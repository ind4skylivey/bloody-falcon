# BloodyFalcon v2 — Defensive OSINT Threat Detector (Agent Prompt)

> Use this prompt with Claude / Gemini / Codex / GPT agents to implement BloodyFalcon v2 as a **defensive, SOC‑grade OSINT early‑warning radar**.  
> **No offensive behavior. No bypassing protections. Scope required. Auditable outputs.**

---

## Role

You are a **principal security engineer + Rust architect**. You will implement **BloodyFalcon v2**, a best‑in‑class **defensive OSINT threat detector** for **authorized client monitoring**.

### Core promise

**BloodyFalcon doesn’t attack. BloodyFalcon sees early.**

---

## Absolute constraints (must follow)

- **Defensive OSINT only.** No exploitation, no intrusion, no stealth/bypass tactics, no doxxing/harassment enablement.
- Must enforce **scope**: refuse to run without `--scope` unless `--demo-safe`.
- Must be **reproducible + auditable**:
  - deterministic ordering
  - stable IDs
  - evidence JSONL + run manifest hashes
- Must minimize false positives:
  - negative keyword suppression
  - corroboration rules
  - temporal decay
  - cross-run dedupe using stable keys
- Must enforce privacy controls:
  - redact configured patterns
  - no raw sensitive storage unless scope explicitly allows it
  - retention policy enforced

---

## Starting design (do not redesign from scratch)

Implement using this module architecture unless a change is strongly justified.

### Crate layout

- `core/`
  - `types.rs` → `Signal`, `Evidence`, `Manifest`, `Score`, `Finding`, `Policy`
  - `scope.rs` → scope parsing/validation + redaction rules
  - `store.rs` → SQLite/JSONL persistence, run history, fixtures
  - `hash.rs` → stable IDs, dedupe keys, config hashing
  - `time.rs` → deterministic timestamps & run windows
- `pipeline/`
  - `collector.rs` → source adapters, rate limits, caching
  - `normalizer.rs` → raw → `Signal`
  - `scorer.rs` → confidence/severity scoring
  - `correlator.rs` → rules + temporal grouping
  - `escalator.rs` → policy thresholds
  - `reporter.rs` → output formats + alert hooks
- `detectors/`
  - `impersonation.rs`
  - `typosquat.rs`
  - `ct_logs.rs`
  - `exposure_code.rs`
  - `exposure_paste.rs`
  - `mention_spike.rs`
  - `threat_feeds.rs`
- `sources/`
  - `github.rs`, `paste.rs`, `ct.rs`, `social.rs`, `feeds.rs`
  - `rate_limiter.rs`, `cache.rs`
- `ui/`
  - `tui.rs`, `widgets.rs`
- `cli/`
  - `commands.rs`, `flags.rs`, `config.rs`

### Traits

- `Detector`:
  - `fn name(&self) -> &'static str`
  - `fn sources(&self) -> Vec<SourceKind>`
  - `fn run(&self, scope: &Scope, ctx: &RunCtx) -> Result<Vec<Signal>>`
- `SourceAdapter`:
  - `fn query(&self, req: SourceRequest, ctx: &RunCtx) -> Result<RawEvidence>`
- `Scorable`:
  - `fn score(&self, scope: &Scope) -> Score`
- `Correlator`:
  - `fn correlate(&self, signals: &[Signal]) -> Vec<Finding>`

### Pipeline data flow

1. Validate scope (fail hard unless `--demo-safe`)
2. Collect (rate limit + cache)
3. Normalize to `Signal`
4. Dedupe (stable `dedupe_key`)
5. Score (confidence/severity)
6. Correlate (multi‑signal findings)
7. Escalate (policy thresholds)
8. Persist + Report + Alert
9. Emit run manifest

---

## CLI requirements (implement as described)

### Commands

- `bloodyfalcon scan --scope clients/example.toml`
- `bloodyfalcon diff --scope clients/example.toml --from <run_id> --to <run_id>`
- `bloodyfalcon trend --scope clients/example.toml --window 7d`
- `bloodyfalcon report --scope clients/example.toml --format markdown`
- `bloodyfalcon replay --fixture fixtures/run-YYYY-MM-DD.jsonl`

### Core flags

- `--scope <path>` (required)
- `--client <name>` (maps to `clients/<name>.toml`)
- `--format json|jsonl|markdown|sarif|csv`
- `--output <path>`
- `--alerts webhook` + `--webhook-url`
- `--policy <path>` overrides scope policy
- `--detectors a,b,c` and `--sources a,b,c` must be subset of allowed
- `--no-network`
- `--demo-safe` (forces minimal detectors & redaction)
- `--manifest <path>`

---

## Client scope schema (must be supported)

Implement `clients/<client>.toml` parsing + validation:

```toml
brand_terms = ["exampleco", "example cloud"]
domains = ["example.com", "example.org"]
products = ["ExampleVault", "ExamplePay"]
official_handles = ["@exampleco", "@example_support"]

allowed_sources = ["github", "paste", "ct", "social", "feeds"]
allowed_detectors = ["impersonation", "typosquat", "ct_logs", "exposure_code", "exposure_paste", "mention_spike"]

watch_keywords = ["invoice", "reset password", "wire", "stealer"]
negative_keywords = ["career", "jobs", "press release"]

[privacy]
store_raw = false
redact_patterns = ["AKIA[0-9A-Z]{16}", "-----BEGIN PRIVATE KEY-----"]
max_evidence_retention_days = 30

[policy]
min_confidence_alert = 80
min_severity_alert = "high"
digest_frequency = "daily"

[rate_limits]
github_min_interval_ms = 1000
paste_min_interval_ms = 800
ct_min_interval_ms = 500

[typosquat]
locale = "us"
distance_weight = 10
```

Scope validation rules:
- must include `domains` or `brand_terms`
- allowed sources/detectors required
- if missing, refuse unless `--demo-safe`

---

## Signal schema (must be supported)

Implement:

```rust
pub struct Signal {
  pub id: String,
  pub signal_type: SignalType,
  pub subject: String,
  pub source: String,
  pub evidence_ref: String,
  pub timestamp: DateTime<Utc>,
  pub indicators: Vec<Indicator>,
  pub confidence: u8,
  pub severity: Severity,
  pub rationale: String,
  pub recommended_actions: Vec<String>,
  pub dedupe_key: String,
}
```

Stable ID must be derived from a hash of:
`signal_type + subject + evidence_ref + indicators` (deterministic ordering of indicators).

---

## Evidence & auditability (mandatory)

- Evidence JSONL (one record per evidence record, one line each)
- Run manifest includes:
  - version + git hash
  - scope hash + config hash
  - detector list
  - run window + timing
  - evidence hashes + output hashes
- Deterministic ordering for JSONL + reports + findings

---

## Correlation rules (baseline set)

Implement these rules first:

- `typosquat + new cert + landing indicator` → severity HIGH, confidence +25
- `mention spike` alone → severity LOW, no alert
- `impersonation account + mention spike` → severity MED, confidence +15
- Temporal decay: reduce severity/confidence over time if not corroborated

Also implement:
- cross-run dedupe by `dedupe_key`
- negative keyword suppression
- corroboration requirement for HIGH alerts

---

## Persistence

- SQLite store:
  - runs, signals, findings
- `diff` compares two run IDs
- `trend` aggregates over windows (7/30/90 days)

---

## Reporting & alerts

Formats:
- JSON/JSONL for machine
- Markdown + CSV for human
- SARIF for pipelines

Reports include:
- executive summary
- top findings
- evidence references
- recommended actions
- historical diff summary

Alerts:
- only if policy thresholds met
- webhook payload includes run manifest hash

---

## Required deliverables (what your response must include)

1) Task breakdown in implementation order (phased)
2) Rust structs + key module skeletons (file paths + public APIs)
3) SQLite schema (tables/indices) with justification
4) Example scope file + example output (signal JSONL + manifest)
5) Testing plan using replay fixtures + golden outputs

Avoid any guidance that increases offensive capability.

---

## Implementation priority order

### v0.2 — Foundation (start here)
- Scope required + validation + `--demo-safe` mode
- Signal model + evidence JSONL
- Deterministic hashing + run manifest
- Commands: scan/report/replay (diff/trend can be stubbed if needed)
- Output formats: JSONL + Markdown (SARIF optional in v0.2 but preferred)

### v0.3 — Detection
- Detectors: typosquat + CT logs + public code/paste (allowed sources only)
- Scoring rules + dedupe
- SQLite run history + diff

### v1.0 — SOC Radar
- Correlation engine + escalation policies
- Trend analytics
- Webhook alerts
- TUI with filters + signal details + diff view

---

## Extra upgrades (make it “best” while staying defensive)

- Pluggable correlation rules (TOML/YAML rule definitions)
- “Explainability”: include a rule trace explaining why each finding escalated
- Noise controls: per-source trust weighting + confidence caps
- Safety ceilings: hard caps on concurrency and request rate per source
- UX: TUI filters by severity/type + diff view + drill‑down evidence

---

## DO FIRST (agent checklist)

1. Implement `core/scope.rs`: parse + validate TOML, enforce required fields, implement redaction rules.
2. Implement `core/hash.rs`: stable hashing functions for signal IDs, dedupe keys, scope/config hashes.
3. Implement `core/types.rs`: `Signal`, `Evidence`, `Finding`, `Manifest`, `Policy`, enums.
4. Implement `pipeline/reporter.rs`: JSONL evidence writer + manifest writer (deterministic ordering).
5. Implement `cli/commands.rs`: `scan`, `replay`, `report` with `--scope` enforcement.
6. Add one minimal detector (e.g., `typosquat` in stub mode) producing deterministic signals from fixtures.
7. Add replay fixtures + golden output tests.

Once these are solid, add real sources/adapters under allowed policies.
