# Shell Over Nostr

[中文文档](README_zh.md)

Execute shell commands on a remote machine via Nostr NIP-04 encrypted Direct Messages.

This tool enables secure remote command execution through the decentralized Nostr network, using end-to-end encryption to protect your commands and their output from relay operators and other third parties.

## Features

- **Decentralized Communication**: Uses Nostr relays instead of centralized servers
- **End-to-End Encryption**: All messages are encrypted using NIP-04 (AES-256-CBC)
- **Password Authentication**: Optional HMAC-SHA256 based password protection
- **Access Control**: Restrict access to specific Nostr public keys
- **Session Persistence**: Maintains working directory across commands in shell mode
- **Multi-Relay Support**: Connects to multiple relays for redundancy
- **Proxy Support**: Works with HTTPS/SOCKS proxies via environment variables

## Requirements

- Python 3.10+
- Dependencies: `aiohttp`, `secp256k1`, `cryptography`

```bash
pip install aiohttp secp256k1 cryptography
```

## Architecture

```
┌─────────────┐                    ┌─────────────┐
│   CLIENT    │                    │   SERVER    │
│ (your PC)   │                    │ (remote PC) │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  NIP-04 Encrypted DM (kind: 4)   │
       │  ┌────────────────────────────┐  │
       └──┤    ┌──────────────────┐    ├──┘
          │    │   NOSTR RELAYS   │    │
          │    │  (relay.damus.io)│    │
          │    │  (nos.lol)       │    │
          │    │  (relay.primal)  │    │
          │    └──────────────────┘    │
          └────────────────────────────┘
```

## Usage

### Server Mode

Run this on the remote machine you want to control:

```bash
python main.py server [nsec] [OPTIONS]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `nsec` | Optional | Server's private key (nsec1... or 64-char hex). If not provided, a new key will be generated and saved to `.nostr_key` |
| `--allow <npub>` | Optional | Only allow connections from this Nostr public key |
| `--password <secret>` | Optional | Shared password for authentication. Clients must provide the same password |

**Examples:**

```bash
# Start server with auto-generated keys
python main.py server

# Start server with a specific private key
python main.py server nsec1...

# Start server with password protection
python main.py server --password mySecretPassword123

# Start server restricted to a specific client
python main.py server --allow npub1abc123... --password mySecretPassword123
```

### Client Mode - Single Command (exec)

Execute a single command on the remote server:

```bash
python main.py exec <server_npub> "command" [nsec] [OPTIONS]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<server_npub>` | Yes | Server's public key (npub1...) |
| `"command"` | Yes | Shell command to execute (quote it!) |
| `nsec` | Optional | Client's private key. If not provided, uses stored key or generates new one |
| `--verbose on\|off` | Optional | Show debug logs (default: `on`) |
| `--password <secret>` | Optional | Password for authentication (must match server's password) |

**Examples:**

```bash
# Execute a simple command
python main.py exec npub1server123... "ls -la"

# Execute with password authentication
python main.py exec npub1server123... "df -h" --password mySecretPassword123

# Execute with verbose output disabled
python main.py exec npub1server123... "cat /etc/os-release" --verbose off --password mySecretPassword123

# Execute with specific client key
python main.py exec npub1server123... "uptime" nsec1client...
```

### Client Mode - Interactive Shell (shell)

Start an interactive shell session:

```bash
python main.py shell <server_npub> [nsec] [OPTIONS]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `<server_npub>` | Yes | Server's public key (npub1...) |
| `nsec` | Optional | Client's private key. If not provided, uses stored key or generates new one |
| `--verbose on\|off` | Optional | Show debug logs (default: `on`) |
| `--password <secret>` | Optional | Password for authentication (must match server's password) |

**Examples:**

```bash
# Start interactive shell
python main.py shell npub1server123...

# Start shell with password
python main.py shell npub1server123... --password mySecretPassword123

# Start shell with verbose disabled
python main.py shell npub1server123... --verbose off --password mySecretPassword123
```

## Key Management

### How Keys Work

1. **First Run (no key provided)**: A new keypair is automatically generated and saved to `.nostr_key` file in the same directory as the script.

2. **With Key Argument**: If you provide an `nsec` (private key), it will be saved to `.nostr_key` and used for subsequent runs.

3. **Subsequent Runs**: If `.nostr_key` exists, the stored key is used automatically.

### Key File Format

The `.nostr_key` file contains JSON:

```json
{
  "nsec": "nsec1...",
  "npub": "npub1..."
}
```

### Important Security Notes

- **Backup your keys!** If you lose your private key (nsec), you lose your identity.
- **Keep nsec secret!** Never share your private key.
- **Share npub only!** Your public key (npub) is safe to share - it's how others identify you.

## Authentication

### Password Authentication

When `--password` is set on the server:

1. Client computes: `HMAC-SHA256(password, sid + nonce)`
2. The auth token is included in the encrypted NIP-04 payload
3. Server verifies the token before executing commands
4. Wrong password = silent rejection (no error message to attacker)

**Benefits:**
- Token is encrypted end-to-end (relay operators cannot see it)
- Each session uses unique `sid` and `nonce` (prevents replay attacks)
- Even if someone knows your npub, they can't connect without the password

### Allow List

When `--allow <npub>` is set on the server:

- Only the specified npub can execute commands
- All other connection attempts are silently rejected
- Combined with `--password` for maximum security

## Configuration Parameters

The following constants can be modified in the source code:

| Constant | Default | Description |
|----------|---------|-------------|
| `EXEC_TIMEOUT` | 30 | Maximum execution time per command (seconds) |
| `RECV_TIMEOUT` | 60 | Maximum wait time for server response (seconds) |
| `COALESCE_MS` | 30 | Output coalescing delay (milliseconds) |
| `MAX_FRAME_BYTES` | 12288 | Maximum bytes per output frame |

### Relay List

Default relays (modify `RELAYS` list in source):

```python
RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.oxtr.dev",
    "wss://relay.primal.net",
    "wss://nostr-pub.wellorder.net",
]
```

### Proxy Configuration

Set environment variables for proxy support:

```bash
export HTTPS_PROXY="http://127.0.0.1:7890"
# or
export https_proxy="socks5://127.0.0.1:1080"
# or
export ALL_PROXY="http://proxy.example.com:8080"
```

## Protocol Details

### Frame Format (NIP-04 encrypted JSON)

**Client -> Server (exec request):**
```json
{
  "t": "exec",
  "sid": "<session_id>",
  "nonce": "<random_nonce>",
  "cmd": "<shell_command>",
  "auth": "<hmac_token>"
}
```

**Server -> Client (output chunk):**
```json
{
  "t": "out",
  "sid": "<session_id>",
  "nonce": "<random_nonce>",
  "seq": <sequence_number>,
  "d": "<base64_output>"
}
```

**Server -> Client (command complete):**
```json
{
  "t": "done",
  "sid": "<session_id>",
  "nonce": "<random_nonce>",
  "rc": <return_code>,
  "cwd": "<current_directory>"
}
```

**Server -> Client (error):**
```json
{
  "t": "err",
  "sid": "<session_id>",
  "nonce": "<random_nonce>",
  "msg": "<error_message>"
}
```

### Security Features

1. **End-to-End Encryption**: All communication uses NIP-04 (AES-256-CBC with ECDH key derivation)
2. **Schnorr Signatures**: Events are signed with Schnorr signatures for authenticity
3. **Replay Protection**: Unique `sid` + `nonce` per command prevents replay attacks
4. **Ordered Output**: Sequence numbers ensure output chunks arrive in order
5. **Deduplication**: Server tracks seen event IDs to prevent duplicate execution

## Quick Start Guide

### Step 1: Install Dependencies

```bash
pip install aiohttp secp256k1 cryptography
```

### Step 2: Start Server (on remote machine)

```bash
python main.py server --password MySecurePassword
```

Note the `npub` displayed in the output - you'll need it for the client.

### Step 3: Execute Commands (on your local machine)

```bash
# Single command
python main.py exec npub1... "ls -la" --password MySecurePassword

# Interactive shell
python main.py shell npub1... --password MySecurePassword
```

## Troubleshooting

### "no relay connected"

- Check your internet connection
- Try setting a proxy if you're behind a firewall
- Some relays may be temporarily unavailable - wait and retry

### Command times out

- The command may be running longer than `EXEC_TIMEOUT` (30s default)
- Check if the command requires user input

### "rejected (wrong password)"

- Ensure the password matches exactly between client and server
- Passwords are case-sensitive

### "rejected npub ... (not in allow list)"

- The client's npub is not in the server's allow list
- Use the `--allow` option on the server with the correct client npub

## License

[MIT](LICENSE)
