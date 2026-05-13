# AI Firewall

A blazing-fast, local-first proxy and CLI wrapper designed to prevent autonomous AI agents (like Claude Code, Cursor, and Gemini CLI) from leaking your company secrets and API keys.

Built in Rust, it acts as a "Pre-Flight Safety Check" for your prompts. It seamlessly intercepts HTTPS traffic, dynamically decrypts and scans the payload for secrets, redacts them on the fly, and fires a native desktop alert—all without breaking your workflow.

## Features

- **Blazing Fast Regex Engine:** Catches standard secrets (AWS, GitHub, Stripe, Slack, JWTs) in milliseconds.
- **Context-Preserving Redaction:** Instead of blocking your AI agent and crashing your flow, it dynamically replaces secrets (e.g., swapping your real key with `[REDACTED_AWS_KEY]`) so the AI can still provide helpful answers.
- **Bring Your Own Context (`index`):** Explicitly scan your local `.env` files and add custom company jargon or passwords to your blocklist with a single command.
- **Transparent CLI Wrapper (`run`):** No need to mess with global proxy variables or certificates. Just prepend `ai-firewall run` to your favorite CLI tool.
- **Dynamic HTTPS MITM:** Automatically generates a local Certificate Authority (CA) to inspect encrypted traffic to OpenAI, Anthropic, etc.
- **Native Desktop Alerts:** Get real-time macOS notifications when an agent tries to leak a secret behind your back.

## Installation

You will need [Rust and Cargo](https://rustup.rs/) installed.

```bash
git clone https://github.com/jsmestad/ai-firewall.git
cd ai-firewall
cargo build --release
```

*(You can move the compiled binary from `target/release/ai-firewall` to your `/usr/local/bin` to use it globally).*

## Usage

### 1. Start the Proxy Daemon
In a background terminal tab, start the firewall proxy. This will automatically generate a local CA certificate at `/tmp/ai-firewall-ca.pem` and listen on `http://127.0.0.1:8080`.

```bash
ai-firewall
```

### 2. Wrap your AI Tools
In your active terminal, run any CLI tool through the firewall. The wrapper automatically injects the proxy environment variables and the required CA certificates into the child process.

```bash
# Example with Claude Code
ai-firewall run claude

# Example with a raw curl request
ai-firewall run curl -s -X POST https://example.com -d "My secret is xoxb-1234567890-1234567890"
```

### 3. Add Custom Company Context
To teach the firewall your specific passwords or internal project codenames, use the `index` command on a `.env` file. It will show you what it found and ask for permission before saving it to a local `.dlp-proxy.toml` file.

```bash
ai-firewall index .env
```

## How it works (The MITM Flow)

1. The wrapper injects `HTTP_PROXY`, `HTTPS_PROXY`, and `NODE_EXTRA_CA_CERTS`.
2. Your AI tool sends an HTTP `CONNECT` request to the proxy to establish an HTTPS tunnel.
3. The firewall dynamically mints an SSL certificate for the destination domain signed by your Local CA.
4. The payload is decrypted, scanned, and any secrets are redacted.
5. A desktop notification is triggered.
6. The redacted payload is re-encrypted and forwarded to the LLM provider.

## Security & Privacy Guarantee
**Zero data leaves your machine.** The parsing, redaction, and `.dlp-proxy.toml` blocklists are entirely local. We do not use external APIs or NLP models to detect secrets. 
