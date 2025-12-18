# Security Data Handling

- Data generated: signals, evidence references, run manifests, and optional SQLite history.
- Storage locations: `data/` for runtime state, `out*/` for reports, and `data/falcon.db` for SQLite.
- Never version: real client scopes, outputs, caches, logs, tokens, or any secret material.
- Data deletion: remove `data/` and `out*/` directories and delete `data/falcon.db` for full cleanup.
- Demo-safe mode: run with `--demo-safe` to restrict sources/detectors to offline fixtures only.
