<img width="3168" height="1344" alt="bloodyf4lcon" src="https://github.com/user-attachments/assets/2683095d-634b-4d3b-9c3c-1a321b9e48bf" />

🦅 BLOODY-F4LCON

Terminal-first OSINT recon for usernames. Red/Black vibe, production-hardening: rate limiting, cache (RAM/opt-in disk), configurable providers, headless signals output.

## ✨ Features
- Live provider checks (GitHub, Reddit, Steam, Twitter, PSNProfiles by default)
- Rate limiting + backoff, cache with TTL (RAM by default; optional disk)
- Configurable providers/user-agent/disk-cache via TOML or flags
- TUI with active targets, intel feed, colored states, logs
- Headless mode (`--no-tui`) for scripting; emits signals (JSONL/SARIF/Markdown) and stores history in SQLite
- Signal sources: username hits, typosquat + RDAP age, keyboard/homoglyph variants, CT logs, GitHub code keyword leaks (optional `GITHUB_TOKEN`), paste search (optional `PASTE_TOKEN`)
- Tracing to stdout + `data/falcon.log`
- Client scope files (`client.toml`) define brand terms/domains; without scope tool runs in demo mode

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

# Headless signals (no TUI) with scope, JSONL output
bloody-f4lcon shadow --no-tui --scope config/client.demo.toml --format jsonl --output data/signals.jsonl

# Headless with digest + webhook alerts
bloody-f4lcon shadow --no-tui --scope config/client.demo.toml --format jsonl --digest --alert-webhook https://hooks.slack.com/...

# Headless with GitHub leak search (requires token)
GITHUB_TOKEN=ghp_xxx bloody-f4lcon shadow --no-tui --scope config/client.demo.toml --format sarif

# Headless including paste search (requires PASTE_TOKEN)
PASTE_TOKEN=psb_xxx bloody-f4lcon shadow --no-tui --scope config/client.demo.toml --format jsonl

# Paste + GitHub gist fallback (optional both tokens)
GITHUB_TOKEN=ghp_xxx PASTE_TOKEN=psb_xxx bloody-f4lcon shadow --no-tui --scope config/client.demo.toml --format jsonl
```

## 🎮 TUI Controls
- ENTER → Scan current target (or add if input filled)
- TAB → Switch target
- q → Exit
- Backspace → Delete input
- [ / ] → Cycle signals
- s → Toggle signal detail popup
- f → Cycle severity filter (High/Medium/Low/All)
- t → Cycle tag filter (paste/code-leak/typosquat/All)
- ↑/↓ → Scroll signal details

Panels:
- Header: version + platform count + hint strip
- Active Targets: index, id, hits, status
- Intel Feed: status, hits, platforms (green), restricted (yellow), rate-limited (magenta), failed (red), optional label
- Signals: latest normalized signals with severity color and tags
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
Client scope: `config/client.demo.toml`
```toml
brand_terms = ["acme", "acme corp"]
domains = ["acme.example"]
watchlists = ["invoice", "password reset"]
allowed_sources = ["typosquat", "ct-logs", "leak-keywords", "paste"]
typosquat_locale = "us"
typosquat_distance_weight = 10

[rate_limits]
paste_min_interval_ms = 800
github_min_interval_ms = 1000
```
Flags override pieces:
- `--config <path>` load alternate file
- `--providers a,b,c` enable subset (case-insensitive)
- `--no-cache` disable in-memory cache
- `--disk-cache` enable disk cache (path from config or `--disk-cache-path`)
- `--disk-cache-path <path>` override disk cache location
- `--verbose` (repeat for debug/trace)
- `--log-file <path>` change log destination
- `--no-tui` headless mode (signals)
- `--scope <client.toml>` load client scope (required unless `--demo`)
- `--format <jsonl|sarif|md>` output format for signals (headless)
- `--output <path>` output file path for signals (headless)
- `--db-path <path>` SQLite file for signal history/deltas
- `--digest` write last-24h digest to `--digest-dir` (default data/digests)
- `--digest-new-only` include only new signals in digest (default true; set false to include last 24h)
- `--alert-webhook <url>` send immediate alerts (respect scope alert policy)
- `--alerts-new-only` alert only on newly created signals (default true)
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
