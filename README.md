<img width="3168" height="1344" alt="bloodyf4lcon" src="https://github.com/user-attachments/assets/2683095d-634b-4d3b-9c3c-1a321b9e48bf" />

🦅 BLOODY-F4LCON

Terminal-first OSINT recon for usernames. Red/Black vibe, production-hardening: rate limiting, cache (RAM/opt-in disk), configurable providers, headless JSON mode.

## ✨ Features
- Live provider checks (GitHub, Reddit, Steam, Twitter, PSNProfiles by default)
- Rate limiting + backoff, cache with TTL (RAM by default; optional disk)
- Configurable providers/user-agent/disk-cache via TOML or flags
- TUI with active targets, intel feed, colored states, logs
- Headless mode (`--no-tui`) for scripting (JSON output)
- Tracing to stdout + `data/falcon.log`

## 📦 Install
**From repo**
```bash
cargo install --path . --force
```

**Direct from Git (SSH)**
```bash
cargo install --git ssh://git@github.com/ind4skylivey/bloody-f4lcon.git --force
```

## 🚀 Quick Start
```bash
# Scan "shadow" with defaults
bloody-f4lcon shadow

# Limit to GitHub + Reddit
bloody-f4lcon shadow --providers github,reddit

# Disable RAM cache
bloody-f4lcon shadow --no-cache

# Enable disk cache (opt-in) at default path
bloody-f4lcon shadow --disk-cache

# Custom config
bloody-f4lcon shadow --config config/bloodyf4lcon.toml

# Headless JSON (no TUI)
bloody-f4lcon shadow --no-tui > result.json
```

## 🎮 TUI Controls
- ENTER → Scan current target (or add if input filled)
- TAB → Switch target
- q → Exit
- Backspace → Delete input

Panels:
- Header: version + platform count + hint strip
- Active Targets: index, id, hits, status
- Intel Feed: status, hits, platforms (green), restricted (yellow), rate-limited (magenta), failed (red), optional label
- Scan Engine: progress gauge or prompt
- System Logs: rolling feed

## ⚙️ Configuration
File: `config/bloodyf4lcon.toml`
```toml
timeout_ms = 5000
max_concurrent_requests = 5
cache_ttl_seconds = 600
user_agent = "bloody-f4lcon/1.0 (+https://github.com/ind4skylivey/bloody-f4lcon)"
disk_cache_enabled = false
disk_cache_path = "data/cache.json"

[[providers]]
name = "github"
enabled = true
base_url = "https://github.com/{username}"
# ... add more providers as needed
```
Flags override pieces:
- `--config <path>` load alternate file
- `--providers a,b,c` enable subset (case-insensitive)
- `--no-cache` disable in-memory cache
- `--disk-cache` enable disk cache (path from config or `--disk-cache-path`)
- `--disk-cache-path <path>` override disk cache location
- `--verbose` (repeat for debug/trace)
- `--log-file <path>` change log destination
- `--no-tui` headless JSON
- `--label <text>` label for initial target

## 🧪 Development
- Format: `cargo fmt`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Test: `cargo test`

CI: GitHub Actions runs fmt + clippy + tests on push/PR; tag `v*` builds a release binary (Linux x86_64 artifact).

## 🗂️ Releases
- Local release build: `cargo build --release` → `target/release/bloody-f4lcon`
- CI tagged release: push tag `vX.Y.Z` → workflow builds and uploads Linux binary artifact.

## 🔒 Privacy & Data Handling
- Data minimization: cache stores only username, timestamp, provider states (hit/restricted/rate-limited/failed). No raw HTTP bodies stored or logged.
- Disk cache is **opt-in** (`--disk-cache` or config `disk_cache_enabled = true`).
- Clear cache: `rm -f data/cache.json data/falcon.log` (and any custom path).
- Respect platform ToS and legal boundaries; OSINT only where authorized.

## 📸 Visual
![demo](docs/screenshot.png)

