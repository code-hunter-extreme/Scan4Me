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
  "prefer_new_companies": false,
  "new_company_days": 90,
  "prefer_new_assets": false,
  "new_asset_days": 30
}
```

Toggle these to prioritize newly discovered opportunities:
- `prefer_new_companies: true` → filters to Bugcrowd programs with an official start date within N days
- `prefer_new_assets: true` → filters to Bugcrowd programs with an asset first listed in dated scope history within N days
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

# Show only targets added in last 30 days
python3 scan4me.py radar --limit 20 --new-companies --new-company-days 30

# Show Bugcrowd programs with officially added assets in the last 30 days
python3 scan4me.py radar --limit 20 --new-assets
```

#### Export Command
```bash
python3 scan4me.py export --top 30 [--new-companies] [--new-company-days 90]
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
- **🆕 NEW TO FEED Badge**: Displayed for programs first observed within the configured window
- **✨ New Assets Count**: Shows count of newly discovered assets when `--new-assets` is active
- Example:
  ```
  [01] ★ SCORE: 92.8/100 | 🔥 MASSIVE SURFACE | [HackerOne] TikTok 🆕 NEW
       ✨ New Assets (30d): 5 first observed since baseline
  ```

### 5. Official Bugcrowd Metadata
- Run `python3 scan4me.py enrich --limit 30` to fetch public program history and statistics for top-paying Bugcrowd programs.
- An individual program can be refreshed with `python3 scan4me.py enrich --handle t-mobile`.
- Bugcrowd program-start and per-asset addition dates come from published official history.
- Rewarded vulnerability totals and validation/average payout statistics are displayed as the platform labels them; they are not guarantees or report-count totals.

### 6. Feed Sync Behavior
- `python3 scan4me.py sync` refreshes the upstream feed before ingestion; `--offline` uses the cached snapshot.
- The first successful sync establishes a baseline and marks existing programs/assets as unknown/not-new.
- Later additions receive first-observed feed timestamps; unchanged entries retain their timestamp.
- Removed assets are removed from the current scope during reconciliation.

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

4. Confirm every candidate against its live program policy before any testing. Scan4Me's newness timestamps reflect feed observation, not official launch/history dates.

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

# Check database timestamps
sqlite3 scan4me.db "SELECT name, first_seen_timestamp FROM programs LIMIT 5;"
```
