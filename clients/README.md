# Client Scopes

This directory contains **example configuration templates only**.

Real client scopes **must never be committed to git**.

Use `example.toml` as a starting point and store real scopes
outside of the repository (local filesystem, secret manager, etc.).

BloodyFalcon enforces scope at runtime, but git hygiene is required
to prevent accidental data leakage.

This:
- educates
- protects
- reduces liability
