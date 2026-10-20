# Scan4Me — Status (2026-10-20)

## Current state

- **Tests:** `python3 -m pytest tests/ -q` → **121 passed** (plain run; no wrapper needed).
- **Live DB (2026-10-19 sync):** 2,027 live programs / 48,699 live assets; 303 contests
  tracked separately (Sherlock 259 + CodeHawks 44) and excluded from the program radar.
- **Platforms:** HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi, Sherlock
  (bounties + contests), PDPrograms, plus listing-only discovery feeds (Bugbase,
  HackenProof, Cantina, Patchstack, Huntr, CodeHawks). Listing-only rows carry
  **zero fabricated assets**. Federacy off by default; Hats excluded.
- **Ranking (standalone):** payout 0.35 / surface 0.30 / freshness 0.20 / speed 0.15.
  Under Oracle, `triage.yaml` overlays this config (payout becomes a gate) — see README.
- **Lint/type gates are report-only in CI** (`|| true`); pytest + coverage is the hard
  gate. Do not read older "clean" claims below as current.

## Since Round 1 (2026-10-08)

- Withdrawn-program tombstones + fail-closed export (`d804b6c`).
- Packaging + hardened CI pytest gate (`424e641`).
- Multi-platform ranking repair + listing coverage (`078c37a`).
- Bugcrowd payout sync repair (`programs.max_payout`) + fail-safe bad-data parsing (`a77984e`).
- Deferred item closed: per-program N+1 asset-count queries replaced with batched GROUP BY.

## Still deferred

- pylint `too-many-*`: split `sync_data` / `evaluate_targets` / `cmd_filter` / `main`.
- `radar --new-*` with zero matches prints bare "Top 0" (could be friendlier).
- Bare `float()` remains in a few pre-existing authenticated fetchers (Bugcrowd/Intigriti/
  YesWeHack) and `_normalize_weights`; listing/public paths are fail-safe.

---

## Round 1: repair + verify — DONE (2026-10-08, historical)

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

### Deferred (known, not this round)
- pylint `too-many-*`: split `sync_data` / `evaluate_targets` / `cmd_filter` / `main`.
- Per-program N+1 asset-count queries.
- `radar --new-*` with zero matches prints bare "Top 0" (could be friendlier).

### Snapshots
- (2026-10-08 tarballs referenced at the time are no longer in this repo.)
