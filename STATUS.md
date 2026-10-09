# Scan4Me — Repair Status (2026-10-08)

## Round 1: repair + verify — DONE
Scope: all 11 approved fixes + new tests. CLI `--new-*` flags now imply strict.

### Fixes
1. `cmd_check`: fail-closed `scope_match` (exact / `*.base` / glued-`*`, apex
   excluded). Was substring match — proven authorizing `evil8x8.com` pre-fix.
2. `sync`: git pull failure falls back to cache; Immunefi/Sherlock gated on
   `refresh` (true `--offline`).
3. Required feed files only for enabled platforms.
4. `open()` with `encoding="utf-8"` + `with` blocks; narrowed PD `except`.
5. `export --clean` uses `clean_asset_identifier` (exact prefix strip).
6. Dead code dropped (`program_start` recompute); `re`/`base64` hoisted to top;
   unused `sys`/`timedelta` removed.
7. `cmd_filter` uses passed config for display limit (was second `load_config()`).
8. Added `--no-show-assets` (old `--show-assets default=True` was a dead flag).
9. Bandit: `shutil.which("git")`, explicit `shell=False`, 12 precise `nosec`s,
   Bugcrowd `detail_url` path guard.
10. `black` reformat + `.flake8` (`max-line-length = 120`).
11. README config sample synced to code values.

### Verification (observed)
- `pytest tests/`: 17 passed (15 failed pre-fix on missing helpers).
- `black --check` clean; `flake8` clean; `bandit` 0 issues (12 nosec);
  `mypy` clean; `pylint` 9.72 (was 9.57); `vulture`: 1 known FP (`row_factory`).
- Live CLI: `evil8x8.com` + `8x8.com.evil.com` → NOT IN SCOPE;
  `foo.8x8.com` → AUTHORIZED via `*.8x8.com`; radar/export/strict/`--no-show-assets` OK.

### How to run tests on this machine
Plain `python3 -m pytest` crashes here: AI_DRIVE `.pth` entries plus an EIO-bad
dir (`.../CodeCrusher/robotruth/robotruth/src`) kill any full `sys.path` walk.
Prune first (Scan4Me needs stdlib only):

```bash
cd Scan4Me && python3 -c "import sys; sys.path=[p for p in sys.path if 'AI_DRIVE' not in p]; import pytest; raise SystemExit(pytest.main(['tests/','-q']))"
```

Same prune needed for direct CLI runs (see `/tmp/s4m.py` wrapper pattern).
Environment issue, not a code issue. Drive health check recommended (`dmesg`).

### Deferred (known, not this round)
- pylint `too-many-*`: split `sync_data` / `evaluate_targets` / `cmd_filter` / `main`.
- Per-program N+1 asset-count queries.
- `radar --new-*` with zero matches prints bare "Top 0" (could be friendlier).

### Snapshots
- BEFORE: `scan4me_BEFORE_20261008.tar.gz`
- AFTER: `scan4me_AFTER_20261008.tar.gz`
