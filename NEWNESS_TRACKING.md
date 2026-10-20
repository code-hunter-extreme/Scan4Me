# Scan4Me Newness Tracking & Filtering

## Overview
Scan4Me now enriches Bugcrowd programs from their public metadata endpoints with official start dates, dated scope history, rewarded-vulnerability totals, average payout, and validation time. Other platforms still use the normalized feed only and are excluded from official-date filters rather than guessed. A rewarded-vulnerability total is a historical competition proxy, not a count of open or resolved reports.

## Features Added

### 1. Database Schema Extensions
- **programs table**: Added `first_seen_timestamp` and `last_updated_timestamp` (Unix epoch seconds)
- **assets table**: Added `first_seen_timestamp` (Unix epoch seconds)
- **Indexes**: Created `idx_program_first_seen` and `idx_asset_first_seen` for fast filtering

### 2. Config-Driven Filtering
In `config.json`, the `freshness_and_competition` section now includes:
```json
{
  "prefer_new_companies": true,
  "new_company_days": 90,
  "strict_new_companies": false,
  "prefer_new_assets": true,
  "new_asset_days": 30,
  "strict_new_assets": false,
  "max_rewarded_vulnerabilities": 150
}
```

Prioritization vs hard filtering are different switches:
- `prefer_new_companies` / `prefer_new_assets: true` → **scoring boost only** (freshness bonus), no exclusion
- `strict_new_companies` / `strict_new_assets: true` → **hard filter** to Bugcrowd programs whose official start date / dated scope-history asset additions fall within N days. Strict gates require `platform = 'Bugcrowd'` official dates; listing feeds may store `official_start_timestamp` for badge/freshness scoring, but strict remains Bugcrowd-only
- `new_company_days`: Threshold for "new" classification (default: 90 days)
- `new_asset_days`: Threshold for asset freshness (default: 30 days)

### 3. CLI Flags (Radar & Export Commands)

#### Radar Command
```bash
python3 scan4me.py radar --limit 20 [--new-companies] [--new-company-days 90]
                                     [--new-assets] [--new-asset-days 30]
```

Examples:
```bash
# Show top targets, all platforms
python3 scan4me.py radar --limit 20

# Show Bugcrowd programs officially started in the last 90 days
python3 scan4me.py radar --limit 20 --new-companies

# Show only Bugcrowd targets officially started in the last 30 days
python3 scan4me.py radar --limit 20 --new-companies --new-company-days 30

# Show Bugcrowd programs with officially added assets in the last 30 days
python3 scan4me.py radar --limit 20 --new-assets
```

#### Export Command
```bash
python3 scan4me.py export --top 30 [--new-companies] [--new-company-days 90]
                                    [--new-assets] [--new-asset-days 30]
                                    [--max-validation-days N]
                                    [--max-rewarded-vulnerabilities N]
                                    [--wildcards-only] [--clean]
```

Examples:
```bash
# Export assets from new companies, cleaned for httpx/subfinder
python3 scan4me.py export --top 50 --new-companies --wildcards-only --clean

# Export all assets with newness filter applied
python3 scan4me.py export --top 100 --new-companies --new-company-days 60
```

### 4. Radar Display Enhancements
- **🆕 NEW PROGRAM Badge**: Displayed only when the program's **official** start date (`official_start_ts`) falls within the configured window. Feed first-observation alone never earns the badge.
- **✨ New Assets Count**: Counts assets whose `official_first_seen_timestamp` (falling back to feed `first_seen_timestamp`) falls within N days — for **all** platforms, not only Bugcrowd scope history. The display line still labels every platform "(Bugcrowd history)" (a known label imprecision in code; only the strict gates are Bugcrowd-official-only).
- (Earlier editions of this doc showed a `[HackerOne] … 🆕 NEW` example "first observed since baseline" — that output is impossible under current code and has been removed.)

### 5. Official Bugcrowd Metadata
- Run `python3 scan4me.py enrich --limit 30` to fetch public program history and statistics for top-paying Bugcrowd programs.
- An individual program can be refreshed with `python3 scan4me.py enrich --handle t-mobile`.
- Bugcrowd program-start and per-asset addition dates come from published official history.
- Rewarded vulnerability totals and validation/average payout statistics are displayed as the platform labels them; they are not guarantees or report-count totals.

### 6. Feed Sync Behavior
- `python3 scan4me.py sync` refreshes the upstream feed before ingestion; `--offline` uses the cached snapshot.
- The first successful sync establishes a baseline and marks existing programs/assets as unknown/not-new.
- Later additions receive first-observed feed timestamps; unchanged entries retain their timestamp.
- Removed assets are **tombstoned** (`deleted_timestamp`) during reconciliation, not deleted; live queries filter tombstones out.

## Workflow: Fast Money Triage

1. **Discover New Opportunities**
   ```bash
   python3 scan4me.py radar --limit 50 --new-companies --new-company-days 30
   ```
   → Identifies high-value targets added in the last 30 days

2. **Extract Scope for Reconnaissance**
   ```bash
   python3 scan4me.py export --top 50 --new-companies --new-company-days 30 \
     --wildcards-only --clean | sort -u > new_targets.txt
   ```
   → Prepares scope for subfinder, httpx, or other recon tools

3. **Prioritize by Asset Freshness**
   ```bash
   python3 scan4me.py radar --limit 20 --new-assets --new-asset-days 30
   ```
   → Focuses on companies with the most recently discovered scope

4. Confirm every candidate against its live program policy before any testing. Strict gates and the badge use official Bugcrowd dates; feed `first_seen` timestamps are only a scoring fallback and never prove launch/addition dates on their own.

## Database Backward Compatibility
- If an existing `scan4me.db` lacks timestamp columns, `migrate_db()` automatically adds them
- Existing data is treated as the baseline on the first sync after this update; it is intentionally not called new.
- Newness filters become useful after a later feed snapshot adds a previously unseen program or asset.
- No report-count filter is available from the imported feeds.

## Future Enhancements
- [ ] Webhook integration: Alert on newly discovered high-payout programs
- [ ] Ranking boost: Programs with high-value new assets rank higher
- [ ] Report saturation: Track report count per program over time
- [ ] Asset rotation: Alert when scope changes significantly
- [ ] OmniCLI integration: Auto-feed new targets for verification

## Testing
```bash
# Verify CLI flags work
python3 scan4me.py radar --help
python3 scan4me.py export --help

# Test newness filtering
python3 scan4me.py radar --limit 5 --new-companies
python3 scan4me.py export --top 10 --new-companies --clean

# Check database timestamps (baseline rows read 0 = observed before tracking; that is expected, not missing data)
sqlite3 scan4me.db "SELECT name, first_seen_timestamp FROM programs LIMIT 5;"
```
