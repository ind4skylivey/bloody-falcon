# 🦅 **BLOODY-FALCON**

**OSINT Terminal Framework**  
*Red/Black aesthetic. Minimal noise. Maximum signal.*

```
[SYSTEM] BLOODY-FALCON v1.0 BOOT
[SYSTEM] THIRD-EYE PROTOCOL ACTIVE
[SYSTEM] 348 PLATFORMS MAPPED
[SYSTEM] AWAITING TARGET IDENTIFIER
```

Keep fingers on the keys. Paint the terminal red.

---

## ⚡ Why Use It
- Razor-fast TUI: zero mouse, zero distractions.
- Live target stack: switch with `TAB`, scan with `ENTER`.
- Synth wave log rail: rolling system feed stays visible.
- Ready for modules: recon, breach, crosslink stubs already wired.
- Pure Rust + Tokio + Ratatui + Crossterm.

## 🚀 Install & Run
```bash
cargo install --path .
bloody-falcon
```

> Runs locally; ships with simulated hits for demo safety.

## 🎮 Controls
- `ENTER` → Scan current target (or add if input filled)
- `TAB`   → Switch target
- `q`     → Exit
- `Backspace` → Delete input char

## 🖥️ Screen Layout
- Header: BLOODY-FALCON | platform count | hint strip.
- Targets: indexed list with status + hit counter.
- Intel Feed: status, hit count, harvested emails, platform list.
- Scan Engine: progress gauge while running, prompt when idle.
- Input & Logs: target input left, rolling log rail right.

## 📦 Project Map
```
src/
  main.rs          # TUI runtime + app state
  ui/              # UI composition stubs
  core/            # engine/logger stubs
  modules/         # recon | breach | crosslink stubs
assets/            # ascii + theme hooks
docs/              # screenshots, docs
tests/             # future integration tests
```

## 🔧 Dev Notes
- Language: English only. No co-author trailers.
- Keep SOLID/DRY; avoid `.unwrap()` in production paths.
- Add real module logic under `src/modules/` (keep demo data synthetic).

## 🗺️ Roadmap (shortlist)
- Plug real recon providers behind async traits.
- Theme pack loader (assets/themes).
- Config file in `config/` with profile switching.
- Export scan results to JSON/NDJSON.

## 📸 Visual
![demo](docs/screenshot.png)
