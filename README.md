<img width="3168" height="1344" alt="bloodyf4lcon" src="https://github.com/user-attachments/assets/2683095d-634b-4d3b-9c3c-1a321b9e48bf" />

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-black?logo=rust&label=toolchain)](#) [![CLI](https://img.shields.io/badge/Mode-defensive%20OSINT-red?logo=target)](#) [![Outputs](https://img.shields.io/badge/output-jsonl%20%7C%20md%20%7C%20sarif-blue)](#) [![Storage](https://img.shields.io/badge/store-SQLite%20%7C%20JSONL-8A2BE2)](#) [![License](https://img.shields.io/badge/license-TBD-lightgrey)](#)

─── ▓▓▓ ░░░ ───

## ⚔ OPERATION OVERVIEW
BloodyFalcon is a defensive OSINT radar. It ingests scoped, public signals, normalizes them into deterministic IDs, and emits auditable evidence plus explainable findings for SOC workflows. No exploitation, no bypassing controls—only disciplined reconnaissance inside explicitly authorized scope files.

```text
</> BLOODY-F4LCON // live feed
[#######-------] signal normalization    68%
[██████░░░░░░░] policy gates & decay     54%
channel: scope=clients/example.toml | mode=demo-safe | output=out/
telemetry: evidence=hashes | manifest=stable | TUI=read-only
```

## 🚀 QUICKSTART (CHECKLIST)
- [ ] Install Rust toolchain (`rustup` ≥ 1.75).
- [ ] Copy `clients/example.toml` → your scoped file (keep it private).
- [ ] Run `bloodyfalcon scan --scope clients/example.toml --format jsonl --output out/`.
- [ ] Generate a human report: `bloodyfalcon report --output out/report.md`.
- [ ] Review in the read-only TUI: `bloodyfalcon tui --output out/` (`q` to exit).

## 🛰 FEATURES
- **Deterministic pipeline**: stable signal IDs, evidence refs, dedupe keys, and run manifests hashed with scope/config.
- **Policy & noise discipline**: negative-keyword suppression, typosquat generic-token downgrades, temporal decay, and digest preferences tuned by scope.
- **Evidence hygiene**: redaction toggle (`privacy.store_raw=false`) removes URLs/notes from `evidence.jsonl`; retention enforced on SQLite store.
- **Multi-format outputs**: JSON/JSONL/Markdown/SARIF/CSV plus manifests and trend reports.
- **Storage + replay**: runs can persist to `data/falcon.db`; `replay` fixtures guarantee identical outputs for the same inputs.
- **Read-only TUI**: filter by severity/disposition/tag, inspect rationale, and export the current view without mutating data.
- **Current detector**: offline typosquat generator (domain permutations with scoring and suppression). Additional CT/paste/leak collectors live in `src/modules/detections.rs` and are queued for hardening before joining the default run.

## 🛠 INSTALL / USAGE
```bash
# Build
cargo build --release

# Scan with scope (refuses to run without scope unless --demo-safe)
bloodyfalcon scan --scope clients/example.toml --format jsonl --output out/

# Fixture replay (deterministic, offline)
bloodyfalcon replay --scope clients/example.toml --fixture fixtures/run-alert-2025-01-02.jsonl --output out_alert/

# Report & trend from latest stored run
bloodyfalcon report --output out/report.md
bloodyfalcon trend --window 7d --output out/trend.md

# Read-only terminal viewer
bloodyfalcon tui --output out/

# Demo-safe sandbox (no scope, offline fixtures only)
bloodyfalcon scan --demo-safe --format jsonl --output out_demo/
```

### Operating Modes
- `--scope` / `--client`: loads a TOML scope; enforces allowed sources/detectors.
- `--demo-safe`: bypasses scope requirement; forces offline-only detectors.
- `--no-network`: forbids detectors that need the network (current detector is offline-safe).
- `--detectors`, `--sources`: extra allowlists applied on top of scope.

## ⚙ CONFIGURATION
- **Scope files** (`clients/*.toml`): brand terms, domains, official handles, `allowed_sources`, `allowed_detectors`, watch/negative keywords, privacy rules, policy thresholds, rate limits, typosquat locale/distance weight.
- **App config** (`config/bloodyf4lcon.toml`): provider list for username presence checks, timeouts, concurrency, UA string, optional disk cache path.
- **Privacy**: when `store_raw=false`, evidence URLs/notes are stripped and indicators are redacted via regex patterns.
- **Retention**: SQLite runs live in `data/falcon.db`; `max_evidence_retention_days` purges old runs automatically.

## 🎯 EXAMPLES
```bash
# Generate typosquat candidates for scoped domains
bloodyfalcon scan --scope clients/example.toml --format jsonl --output out/
cat out/signals.jsonl | head

# Replay an alert fixture to see explainability in the report
bloodyfalcon replay --scope clients/example.toml --fixture fixtures/run-alert-2025-01-02.jsonl --output out_alert/
bloodyfalcon report --output out_alert/report.md

# Trend view (7-day window)
bloodyfalcon trend --window 7d --output out/trend.md

# Inspect stored signals safely
bloodyfalcon tui --output out/
```

## 🧭 ARCHITECTURE SNAPSHOT
- Collector → Normalizer → Scorer → Correlator → Escalator → Reporter.
- Outputs: `evidence.jsonl`, `signals.{json|jsonl|md|sarif|csv}`, `manifest.json`, optional SQLite history.
- Manifests embed scope hash, config hash, detector list, evidence/output hashes, and time window for reproducibility.

## 📡 PLANNED OPERATIONS
- Wire CT log, paste intel, and GitHub leak collectors (already prototyped) into the default pipeline with safe rate limits.
- Expose the username recon engine (config-driven providers) as a hardened CLI command.
- Correlation rules beyond typosquat (multi-signal corroboration, feed matches, mention spikes).
- CI hardening: release artifacts plus signed checksums.

## 🤝 CONTRIBUTING
- Rust style: `cargo fmt && cargo test` before sending patches.
- Do not commit real client scopes, secrets, outputs, or databases. Use fixtures and `clients/example.toml` instead.
- Keep docs and code in English; favor deterministic behavior and privacy-safe defaults.
- If you add detectors/sources, ensure they respect `--no-network`, scope allowlists, and redaction paths.

## 🔒 SECURITY & ETHICS
- For authorized monitoring only; no exploitation, no intrusive collection.
- Scope-first: the binary refuses to run without a scope unless `--demo-safe`.
- Privacy-first: redaction + retention controls; prefer silence over noisy or unjustified alerts.
- Preserve manifests/evidence for audit; sanitize when sharing.

─── ▓▓▓ ░░░ ───
