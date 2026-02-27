#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nostr Remote Exec — run commands on a remote machine via Nostr NIP-04 DMs.
pip install aiohttp secp256k1 cryptography

SERVER:
    python nostr_rexec.py server [nsec] [--allow <npub>] [--password <secret>]

CLIENT:
    python nostr_rexec.py exec  <server_npub> "cmd" [--verbose on|off] [--password <secret>]
    python nostr_rexec.py shell <server_npub>        [--verbose on|off] [--password <secret>]

Password auth:
    Every exec frame carries  "auth": HMAC-SHA256(password, sid+nonce)
    Server verifies before executing; mismatched password → silent reject.
    The auth token is inside NIP-04 ciphertext so relay operators can't see it.

Frame protocol (NIP-04 encrypted JSON):
  client→server  {"t":"exec","sid":"…","nonce":"…","cmd":"…","auth":"<hex>"}
  server→client  {"t":"out", "sid":"…","nonce":"…","seq":<int>,"d":"<base64>"}
  server→client  {"t":"done","sid":"…","nonce":"…","rc":<int>,"cwd":"<path>"}
  server→client  {"t":"err", "sid":"…","nonce":"…","msg":"<string>"}
"""

import asyncio, base64, hashlib, hmac, json, os, secrets, shlex, ssl, sys, time
from datetime import datetime

for pkg in ["aiohttp","secp256k1","cryptography"]:
    try: __import__(pkg)
    except ImportError: sys.exit(f"❌ pip install {pkg}")

import aiohttp, secp256k1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ── tunables ──────────────────────────────────────────────────────────────────
EXEC_TIMEOUT    = 30
RECV_TIMEOUT    = 60
COALESCE_MS     = 30
MAX_FRAME_BYTES = 12288

# ── password auth ─────────────────────────────────────────────────────────────
def _auth_token(password: str, sid: str, nonce: str) -> str:
    """HMAC-SHA256(password, sid+nonce) — unique per session, not replayable."""
    key = password.encode()
    msg = (sid + nonce).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def _auth_ok(password: str | None, token: str, sid: str, nonce: str) -> bool:
    if password is None:
        return True   # no password configured → open to all authenticated npubs
    expected = _auth_token(password, sid, nonce)
    return hmac.compare_digest(expected, token)

# ── bech32 ────────────────────────────────────────────────────────────────────
_CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CM = {c:i for i,c in enumerate(_CS)}
_GN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]

def _pm(vals):
    c = 1
    for v in vals:
        b = c>>25; c = (c&0x1ffffff)<<5^v
        for i in range(5): c ^= _GN[i] if (b>>i)&1 else 0
    return c

def _hrp(h): return [ord(x)>>5 for x in h]+[0]+[ord(x)&31 for x in h]

def _bits(data,f,t,pad=True):
    a=bits=0; r=[]; mx=(1<<t)-1
    for v in data:
        a=(a<<f)|v; bits+=f
        while bits>=t: bits-=t; r.append((a>>bits)&mx)
    if pad and bits: r.append((a<<(t-bits))&mx)
    return r

def _b32enc(hrp,data):
    d = _bits(data,8,5); p = _pm(_hrp(hrp)+d+[0]*6)^1
    return hrp+"1"+"".join(_CS[x] for x in d+[(p>>5*(5-i))&31 for i in range(6)])

def _b32dec(s):
    s = s.lower(); p = s.rfind("1")
    if p<1 or p+7>len(s): raise ValueError("bad bech32")
    hrp = s[:p]
    try: d = [_CM[c] for c in s[p+1:]]
    except KeyError: raise ValueError("bad char")
    if _pm(_hrp(hrp)+d)!=1: raise ValueError("bad checksum")
    return hrp, bytes(_bits(d[:-6],5,8,pad=False))

def to_npub(h): return _b32enc("npub",bytes.fromhex(h))
def to_nsec(h): return _b32enc("nsec",bytes.fromhex(h))
def npub2hex(s): hrp,b=_b32dec(s); assert hrp=="npub"; return b.hex()
def nsec2hex(s): hrp,b=_b32dec(s); assert hrp=="nsec"; return b.hex()

# ── crypto ────────────────────────────────────────────────────────────────────
def gen_keys():
    b = secrets.token_bytes(32)
    return b.hex(), secp256k1.PrivateKey(b).pubkey.serialize()[1:].hex()

def derive_pub(priv):
    return secp256k1.PrivateKey(bytes.fromhex(priv)).pubkey.serialize()[1:].hex()

def schnorr(eid,priv):
    return secp256k1.PrivateKey(bytes.fromhex(priv)).schnorr_sign(
        bytes.fromhex(eid),None,raw=True).hex()

def _ecdh(priv,pub):
    pk = secp256k1.PublicKey(bytes.fromhex("02"+pub),raw=True)
    return pk.tweak_mul(secp256k1.PrivateKey(bytes.fromhex(priv)).private_key
                        ).serialize(compressed=True)[1:]

def nip04_enc(text,priv,pub):
    key = _ecdh(priv,pub); iv = secrets.token_bytes(16)
    d = text.encode(); pad = 16-len(d)%16; d += bytes([pad]*pad)
    ct = Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend()).encryptor()
    return base64.b64encode(ct.update(d)+ct.finalize()).decode()+"?iv="+base64.b64encode(iv).decode()

def nip04_dec(payload,priv,pub):
    try:
        ct_b64,iv_b64 = payload.split("?iv=")
        key = _ecdh(priv,pub)
        dc = Cipher(algorithms.AES(key),modes.CBC(base64.b64decode(iv_b64)),
                    backend=default_backend()).decryptor()
        d = dc.update(base64.b64decode(ct_b64))+dc.finalize()
        return d[:-d[-1]].decode()
    except Exception: return None

def mkevent(kind,content,priv,pub,tags=None):
    ev = {"pubkey":pub,"created_at":int(time.time()),
          "kind":kind,"tags":tags or[],"content":content}
    s = json.dumps([0,ev["pubkey"],ev["created_at"],ev["kind"],
                    ev["tags"],ev["content"]],separators=(",",":"),ensure_ascii=False)
    ev["id"] = hashlib.sha256(s.encode()).hexdigest()
    ev["sig"] = schnorr(ev["id"],priv)
    return ev

# ── ordered buffer ────────────────────────────────────────────────────────────
class OrderedBuffer:
    def __init__(self):
        self.next_seq = 0; self._buf: dict[int,bytes] = {}

    def push(self,seq,data):
        if seq >= self.next_seq: self._buf[seq] = data

    def drain(self):
        while self.next_seq in self._buf:
            yield self._buf.pop(self.next_seq); self.next_seq += 1

# ── output coalescer ──────────────────────────────────────────────────────────
class Coalescer:
    def __init__(self,flush_cb):
        self._cb = flush_cb; self._buf = bytearray(); self._task = None

    async def write(self,data:bytes):
        self._buf.extend(data)
        if len(self._buf) >= MAX_FRAME_BYTES:
            await self._flush()
        elif self._task is None or self._task.done():
            self._task = asyncio.ensure_future(self._timer())

    async def _timer(self):
        await asyncio.sleep(COALESCE_MS/1000); await self._flush()

    async def _flush(self):
        if self._task and not self._task.done():
            self._task.cancel()
            try: await self._task
            except asyncio.CancelledError: pass
        self._task = None
        if self._buf:
            data = bytes(self._buf); self._buf.clear(); await self._cb(data)

    async def close(self): await self._flush()

# ── relay pool ────────────────────────────────────────────────────────────────
RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.oxtr.dev",
    "wss://relay.primal.net",
    "wss://nostr-pub.wellorder.net",
]
PROXY = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or
         os.environ.get("ALL_PROXY")   or os.environ.get("all_proxy"))
_SSL = ssl.create_default_context()
_SSL.check_hostname = False; _SSL.verify_mode = ssl.CERT_NONE

def _ts(): return datetime.now().strftime("%H:%M:%S")
def _log(tag,msg): print(f"[{_ts()}] {tag} {msg}",flush=True)


class RelayPool:
    def __init__(self,on_event,pub,priv):
        self._ev = on_event; self._pub = pub; self._priv = priv
        self._conns = {}; self._seen = {}; self._tasks = []; self._sess = None
        self._since = int(time.time())

    connected = property(lambda self:len(self._conns))
    def refresh_since(self): self._since = int(time.time())

    async def start(self):
        self._sess = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60,connect=15,sock_read=60))
        for u in RELAYS:
            self._tasks.append(asyncio.create_task(self._connect(u)))

    async def close(self):
        for t in self._tasks: t.cancel()
        await asyncio.gather(*self._tasks,return_exceptions=True)
        for ws in list(self._conns.values()):
            try: await ws.close()
            except Exception: pass
        if self._sess and not self._sess.closed:
            await self._sess.close(); await asyncio.sleep(0.25)

    async def publish(self,ev):
        msg = json.dumps(["EVENT",ev]); ok = 0
        for ws in list(self._conns.values()):
            try: await ws.send_str(msg); ok += 1
            except Exception: pass
        return ok

    async def _connect(self,url):
        bo = 2; kw = {"headers":{"User-Agent":"NostrRexec/1.0"}}
        if PROXY: kw["proxy"] = PROXY
        while True:
            since = self._since
            try:
                async with self._sess.ws_connect(url,ssl=_SSL,**kw) as ws:
                    self._conns[url] = ws; bo = 2
                    sid = secrets.token_hex(8)
                    await ws.send_str(json.dumps(
                        ["REQ",sid,{"kinds":[4],"#p":[self._pub],
                                    "since":since,"limit":0}]))
                    ping = asyncio.create_task(self._ping(ws,url))
                    try:
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                await self._handle(msg.data,url,ws)
                            elif msg.type in (aiohttp.WSMsgType.ERROR,
                                              aiohttp.WSMsgType.CLOSED): break
                    finally:
                        ping.cancel()
                        try: await ping
                        except asyncio.CancelledError: pass
            except asyncio.CancelledError: return
            except Exception: pass
            finally: self._conns.pop(url,None)
            await asyncio.sleep(bo); bo = min(bo*2,60)

    async def _ping(self,ws,url):
        while True:
            await asyncio.sleep(30)
            try: await asyncio.wait_for(ws.ping(),timeout=10)
            except Exception: await ws.close(); break

    async def _handle(self,raw,url,ws):
        try: msg = json.loads(raw)
        except Exception: return
        if not isinstance(msg,list) or not msg: return
        t = msg[0]
        if t == "AUTH" and len(msg) >= 2:
            ev = mkevent(22242,"",self._priv,self._pub,
                         [["relay",url],["challenge",str(msg[1])]])
            await ws.send_str(json.dumps(["AUTH",ev]))
        elif t == "EVENT" and len(msg) >= 3:
            ev = msg[2]; eid = ev.get("id","")
            if eid and eid not in self._seen:
                self._seen[eid] = time.time()
                if len(self._seen) > 5000:
                    cutoff = time.time()-7200
                    for k in [k for k,v in self._seen.items() if v<cutoff]:
                        del self._seen[k]
                await self._ev(ev)

# ══════════════════════════════════════════════════════════════════════════════
# SERVER
# ══════════════════════════════════════════════════════════════════════════════
class ExecServer:
    def __init__(self,priv,allowed_user=None,password=None):
        self._priv = priv; self._pub = derive_pub(priv)
        self._pool = RelayPool(self._on_ev,self._pub,priv)
        self._allowed_user = allowed_user
        self._password = password          # None = no password check
        self._jobs: dict[tuple,asyncio.Task] = {}
        self._cwds: dict[str,str] = {}     # client_pubkey_hex -> cwd

    async def run(self):
        _log("server",f"🔑 npub : {to_npub(self._pub)}")
        _log("server",f"🔑 nsec : {to_nsec(self._priv)}  ← keep secret!")
        if self._allowed_user:
            _log("server",f"🔒 allow npub : {to_npub(self._allowed_user)[:30]}…")
        if self._password:
            _log("server","🔑 password  : set (HMAC-SHA256)")
        else:
            _log("server","⚠️  password  : NOT set (anyone with your npub can connect)")
        _log("server","Ready — waiting for exec requests\n")
        asyncio.create_task(self._pool.start())
        await asyncio.sleep(2)
        _log("server",f"{self._pool.connected}/{len(RELAYS)} relays connected")
        try:
            await asyncio.Event().wait()
        except (KeyboardInterrupt,asyncio.CancelledError): pass
        finally:
            for t in list(self._jobs.values()): t.cancel()
            await self._pool.close()

    async def _on_ev(self,ev):
        if ev.get("kind") != 4: return
        sender = ev.get("pubkey","")
        if sender == self._pub: return
        if self._allowed_user and sender != self._allowed_user:
            _log("server",f"⛔ rejected npub {sender[:12]}… (not in allow list)"); return

        raw = nip04_dec(ev.get("content",""),self._priv,sender)
        if raw is None: return
        try: frame = json.loads(raw)
        except Exception: return

        if frame.get("t") != "exec": return
        sid   = frame.get("sid","")
        nonce = frame.get("nonce","")
        cmd   = frame.get("cmd","")
        token = frame.get("auth","")
        if not sid or not nonce or not cmd: return

        # ── password check ────────────────────────────────────────────────────
        if not _auth_ok(self._password, token, sid, nonce):
            _log("server",f"⛔ rejected {sender[:12]}… (wrong password)"); return

        key = (sid,nonce)
        if key in self._jobs: return   # duplicate delivery

        _log("server",f"[{sid}] ← exec: {cmd!r} from {sender[:12]}…")
        task = asyncio.create_task(self._run(key,cmd,sender))
        self._jobs[key] = task
        task.add_done_callback(lambda _:self._jobs.pop(key,None))

    async def _run(self,key:tuple,cmd:str,client_pub:str):
        sid,nonce = key; seq = 0

        async def send_chunk(data:bytes):
            nonlocal seq
            await self._send(client_pub,{
                "t":"out","sid":sid,"nonce":nonce,
                "seq":seq,"d":base64.b64encode(data).decode()
            }); seq += 1

        coal = Coalescer(send_chunk)
        proc = None
        cwd  = self._cwds.get(client_pub)
        cwd_file = f"/tmp/.nostr_cwd_{sid}"

        if cwd:
            wrapped = (f"cd {shlex.quote(cwd)} && "
                       f"{{ {cmd}; __rc=$?; pwd > {shlex.quote(cwd_file)}; exit $__rc; }}")
        else:
            wrapped = f"{{ {cmd}; __rc=$?; pwd > {shlex.quote(cwd_file)}; exit $__rc; }}"

        try:
            proc = await asyncio.create_subprocess_shell(
                wrapped,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                limit=65536
            )

            async def stream():
                while True:
                    chunk = await proc.stdout.read(4096)
                    if not chunk: break
                    await coal.write(chunk)

            await asyncio.wait_for(stream(),timeout=EXEC_TIMEOUT)
            await asyncio.wait_for(proc.wait(),timeout=5)
            await coal.close()
            rc = proc.returncode if proc.returncode is not None else -1

            new_cwd = cwd or ""
            try:
                with open(cwd_file) as f: new_cwd = f.read().strip()
                os.unlink(cwd_file)
                if new_cwd: self._cwds[client_pub] = new_cwd
            except Exception: pass

            await self._send(client_pub,{
                "t":"done","sid":sid,"nonce":nonce,"rc":rc,"cwd":new_cwd
            })
            _log("server",f"[{sid}] done rc={rc} cwd={new_cwd}")

        except asyncio.TimeoutError:
            await coal.close()
            if proc:
                try: proc.kill()
                except Exception: pass
            try: os.unlink(cwd_file)
            except Exception: pass
            await self._send(client_pub,{
                "t":"err","sid":sid,"nonce":nonce,
                "msg":f"timeout after {EXEC_TIMEOUT}s"
            })
            _log("server",f"[{sid}] killed (timeout)")

        except Exception as e:
            await coal.close()
            try: os.unlink(cwd_file)
            except Exception: pass
            await self._send(client_pub,{"t":"err","sid":sid,"nonce":nonce,"msg":str(e)})
            _log("server",f"[{sid}] error: {e}")

    async def _send(self,peer_pub,frame:dict):
        content = nip04_enc(json.dumps(frame,separators=(",",":")),self._priv,peer_pub)
        ev = mkevent(4,content,self._priv,self._pub,[["p",peer_pub]])
        await self._pool.publish(ev)

# ══════════════════════════════════════════════════════════════════════════════
# CLIENT
# ══════════════════════════════════════════════════════════════════════════════
class ExecClient:
    def __init__(self,priv,server_npub,verbose=True,password=None):
        self._priv = priv; self._pub = derive_pub(priv)
        self._server_pub = npub2hex(server_npub)
        self._pool = RelayPool(self._on_ev,self._pub,priv)
        self._verbose = verbose
        self._password = password          # None = no token sent
        self._jobs: dict[tuple,dict] = {}
        self._cwd = ""

    def _clog(self,msg):
        if self._verbose: _log("client",msg)

    def _prompt(self):
        cwd = self._cwd
        home = os.path.expanduser("~")
        if cwd.startswith(home): cwd = "~" + cwd[len(home):]
        return f"{cwd} $ " if cwd else "$ "

    async def _connect(self):
        asyncio.create_task(self._pool.start())
        for _ in range(40):
            if self._pool.connected: break
            await asyncio.sleep(0.25)
        if not self._pool.connected:
            sys.exit("❌ no relay connected")

    async def exec(self,cmd:str)->int:
        self._pool.refresh_since()
        sid   = secrets.token_hex(8)
        nonce = secrets.token_hex(16)
        key   = (sid,nonce)
        done_ev = asyncio.Event()
        self._jobs[key] = {"buf":OrderedBuffer(),"done":done_ev,"rc":-1,"err":None}

        # build frame — include auth token if password is set
        frame: dict = {"t":"exec","sid":sid,"nonce":nonce,"cmd":cmd}
        if self._password:
            frame["auth"] = _auth_token(self._password, sid, nonce)

        await self._send(frame)
        self._clog(f"[{sid}] → exec: {cmd!r}")
        try:
            await asyncio.wait_for(done_ev.wait(),timeout=RECV_TIMEOUT)
        except asyncio.TimeoutError:
            self._clog(f"[{sid}] timed out waiting for response")
            self._jobs.pop(key,None); return 1

        job = self._jobs.pop(key,{})
        if job.get("err"):
            print(f"\n❌ server error: {job['err']}",flush=True)
            return 1

        rc = job.get("rc",0)
        self._clog(f"[{sid}] rc={rc}")
        return rc

    async def shell(self):
        print(f"⚡ Nostr Remote Shell → {to_npub(self._server_pub)[:30]}…")
        print("   type a command and press Enter  |  Ctrl-C or 'exit' to quit\n")
        loop = asyncio.get_event_loop()
        q: asyncio.Queue = asyncio.Queue()
        loop.add_reader(sys.stdin.fileno(),lambda:q.put_nowait(sys.stdin.readline()))
        try:
            while True:
                print(self._prompt(),end="",flush=True)
                try: line = (await q.get()).rstrip("\n")
                except asyncio.CancelledError: break
                if not line: continue
                if line in ("/quit","exit","quit"): break
                await self.exec(line)
        except (KeyboardInterrupt,asyncio.CancelledError): pass
        finally:
            loop.remove_reader(sys.stdin.fileno())
            print("\n👋 bye")

    async def _on_ev(self,ev):
        if ev.get("kind") != 4: return
        if ev.get("pubkey","") != self._server_pub: return
        raw = nip04_dec(ev.get("content",""),self._priv,self._server_pub)
        if raw is None: return
        try: frame = json.loads(raw)
        except Exception: return

        t     = frame.get("t")
        sid   = frame.get("sid","")
        nonce = frame.get("nonce","")
        job   = self._jobs.get((sid,nonce))
        if not job: return

        if t == "out":
            seq = frame.get("seq")
            if seq is None: return
            try: data = base64.b64decode(frame.get("d",""))
            except Exception: return
            job["buf"].push(seq,data)
            for chunk in job["buf"].drain():
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()

        elif t == "done":
            job["rc"] = frame.get("rc",0)
            cwd = frame.get("cwd","")
            if cwd: self._cwd = cwd
            job["done"].set()

        elif t == "err":
            job["err"] = frame.get("msg","unknown error")
            job["done"].set()

    async def _send(self,frame:dict):
        content = nip04_enc(json.dumps(frame,separators=(",",":")),
                            self._priv,self._server_pub)
        ev = mkevent(4,content,self._priv,self._pub,[["p",self._server_pub]])
        await self._pool.publish(ev)

# ── client entrypoints ────────────────────────────────────────────────────────
async def run_exec(priv,server_npub,cmd,verbose,password):
    c = ExecClient(priv,server_npub,verbose,password)
    await c._connect()
    rc = await c.exec(cmd)
    await c._pool.close()
    sys.exit(rc)

async def run_shell(priv,server_npub,verbose,password):
    c = ExecClient(priv,server_npub,verbose,password)
    await c._connect()
    await c.shell()
    await c._pool.close()

# ══════════════════════════════════════════════════════════════════════════════
# KEY STORAGE
# ══════════════════════════════════════════════════════════════════════════════
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),".nostr_key")

def load_or_gen(arg=None):
    if arg:
        try:
            priv = nsec2hex(arg) if arg.startswith("nsec1") else (arg if len(arg)==64 else None)
            if not priv: raise ValueError
            pub = derive_pub(priv)
            with open(KEY_FILE,"w") as f:
                json.dump({"nsec":to_nsec(priv),"npub":to_npub(pub)},f)
            return priv
        except Exception:
            _log("keys","⚠ bad key arg, using stored key")
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE) as f: d = json.load(f)
            return nsec2hex(d["nsec"])
        except Exception: pass
    priv,pub = gen_keys()
    with open(KEY_FILE,"w") as f:
        json.dump({"nsec":to_nsec(priv),"npub":to_npub(pub)},f)
    _log("keys",f"🆕 npub: {to_npub(pub)}")
    _log("keys",f"   nsec: {to_nsec(priv)}  ← BACK THIS UP")
    return priv

# ══════════════════════════════════════════════════════════════════════════════
# ENTRY
# ══════════════════════════════════════════════════════════════════════════════
USAGE = """
Usage:
  python nostr_rexec.py server  [nsec]  [--allow <npub>] [--password <secret>]
  python nostr_rexec.py exec    <server_npub> "cmd" [nsec] [--verbose on|off] [--password <secret>]
  python nostr_rexec.py shell   <server_npub>       [nsec] [--verbose on|off] [--password <secret>]

  --password   shared secret; client and server must use identical value.
               Token is HMAC-SHA256(password, sid+nonce), sent inside NIP-04
               ciphertext — relay operators cannot see it.
               If server sets --password, clients without it are silently rejected.

Examples:
  python nostr_rexec.py server --password hunter2
  python nostr_rexec.py exec   npub1abc… "df -h" --password hunter2
  python nostr_rexec.py shell  npub1abc… --password hunter2 --verbose off
"""

def _arg(args,flag,default):
    try: i = args.index(flag); v = args[i+1]
    except (ValueError,IndexError): return default
    if default is None: return v
    return type(default)(v)

def _strip_flags(args,flags):
    result = []; skip = False
    for a in args:
        if skip: skip = False; continue
        if a in flags: skip = True; continue
        if not a.startswith("-"): result.append(a)
    return result

def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h","--help"): sys.exit(USAGE)
    mode = args[0].lower()
    known_flags = {"--verbose","--allow","--password"}

    if mode == "server":
        positional   = _strip_flags(args[1:],known_flags)
        nsec_arg     = next((a for a in positional if a.startswith("nsec1") or len(a)==64),None)
        allow_npub   = _arg(args,"--allow",None)
        allowed_hex  = npub2hex(allow_npub) if allow_npub else None
        password     = _arg(args,"--password",None)
        priv = load_or_gen(nsec_arg)
        try: asyncio.run(ExecServer(priv,allowed_hex,password).run())
        except KeyboardInterrupt: pass

    elif mode == "exec":
        positional  = _strip_flags(args[1:],known_flags)
        if len(positional) < 2: sys.exit("❌ usage: exec <server_npub> \"command\"\n"+USAGE)
        server_npub = positional[0]; cmd = positional[1]
        nsec_arg    = positional[2] if len(positional) > 2 else None
        verbose     = _arg(args,"--verbose","on") != "off"
        password    = _arg(args,"--password",None)
        priv = load_or_gen(nsec_arg)
        try: asyncio.run(run_exec(priv,server_npub,cmd,verbose,password))
        except KeyboardInterrupt: pass

    elif mode == "shell":
        positional  = _strip_flags(args[1:],known_flags)
        if not positional: sys.exit("❌ usage: shell <server_npub>\n"+USAGE)
        server_npub = positional[0]
        nsec_arg    = positional[1] if len(positional) > 1 else None
        verbose     = _arg(args,"--verbose","on") != "off"
        password    = _arg(args,"--password",None)
        priv = load_or_gen(nsec_arg)
        try: asyncio.run(run_shell(priv,server_npub,verbose,password))
        except KeyboardInterrupt: pass

    else:
        sys.exit(f"❌ unknown mode '{mode}'\n{USAGE}")

if __name__ == "__main__": main()