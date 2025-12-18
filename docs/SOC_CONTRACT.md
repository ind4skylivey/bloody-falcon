# SOC Contract

## Purpose
BloodyFalcon is a defensive OSINT radar for authorized client monitoring. It detects early warning signals of targeting and impersonation using only public, non-intrusive sources within an explicit client scope.

## What It Does
- Collects scoped public signals (e.g., typosquats, new certs, impersonation indicators, mention spikes).
- Normalizes signals into a consistent model with stable IDs and evidence references.
- Correlates signals into findings using deterministic rules.
- Applies policy gates to determine disposition.

## What It Does Not Do
- No exploitation, scanning, or bypassing protections.
- No intrusive or high‑risk collection.
- No doxxing or harassment enablement.

## Dispositions
- **Alert**: Meets policy severity and confidence thresholds, not suppressed.
- **Investigate**: Below alert threshold but worth analyst triage.
- **Digest**: Monitoring/trend only; not urgent.
- **Suppressed**: Explicitly blocked by policy or suppression rules; never alerts.

## Analyst Expectations
- Alerts require corroboration and policy thresholds.
- Investigate findings require analyst judgment.
- Digest findings are for trend awareness, not immediate action.
- Suppressed findings should not be actioned without additional corroboration.

## False-Positive Philosophy
BloodyFalcon prefers silence over false certainty. If signals cannot be corroborated or pass policy gates, they are downgraded or suppressed.

## Determinism & Audit Guarantees
- Stable IDs for signals and findings.
- Deterministic ordering of outputs.
- Evidence JSONL and run manifests with hashes.
- Replay mode produces identical outputs for identical inputs.
