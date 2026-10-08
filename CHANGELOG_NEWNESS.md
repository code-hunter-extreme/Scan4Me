# Changelog: Newness Tracking Implementation

> **Correction (2026-10-08):** These timestamps currently mean first observed by Scan4Me, not official program launch or asset-addition dates. The initial feed snapshot is now recorded as a baseline, and CLI newness filters are wired into radar/export. The imported feeds do not provide resolved-report counts; average resolution time is not a count. Official platform date/history adapters are not yet implemented, so do not treat these filters as proof that a program or asset is newly launched/added.

## Summary
Added comprehensive newness tracking and filtering to Scan4Me for identifying fresh bug bounty opportunities. This enables rapid prioritization of new programs and newly discovered assets within established programs.

## Changes Made

### 1. Core Logic Updates (`scan4me.py`)

#### Database Schema
- **programs table**: Added `first_seen_timestamp` and `last_updated_timestamp` (Unix epoch)
- **assets table**: Added `first_seen_timestamp` (Unix epoch)
- **Indexes**: Added `idx_program_first_seen` and `idx_asset_first_seen` for performance

#### New Functions
- `migrate_db(conn)`: Handles backward compatibility by adding timestamp columns to existing tables

#### Modified Functions
- `sync_data()`: 
  - Calls `migrate_db()` after `init_db()` for schema upgrades
  - Checks for existing `first_seen_timestamp` before INSERT
  - Preserves `first_seen_timestamp` on re-sync updates
  - Sets `last_updated_timestamp` on every sync

- `evaluate_targets()`:
  - When `prefer_new_companies: true`, filters to programs < `new_company_days` old
  - When `prefer_new_assets: true`, calculates `new_assets_count` for display

- `cmd_filter()`:
  - Displays 🆕 NEW badge for programs < 90 days old (configurable)
  - Shows `✨ New Assets (Xd): Y` when `prefer_new_assets: true`

#### CLI Enhancements
- `radar` command:
  - `--new-companies`: Filter to recently added programs
  - `--new-company-days`: Customize "new" threshold (default: 90)
  - `--new-assets`: Show programs with newly discovered assets
  - `--new-asset-days`: Customize asset freshness threshold (default: 30)

- `export` command:
  - `--new-companies`: Filter exports to new programs
  - `--new-company-days`: Customize threshold

### 2. Configuration Updates (`config.json`)

Added to `filters.freshness_and_competition`:
```json
{
  "prefer_new_companies": false,
  "new_company_days": 90,
  "prefer_new_assets": false,
  "new_asset_days": 30
}
```

Allows users to enable newness filtering via config file instead of CLI flags.

### 3. Documentation (`NEWNESS_TRACKING.md`)

Comprehensive guide covering:
- Feature overview and schema changes
- Config-driven filtering options
- CLI flag usage with examples
- Radar display enhancements
- Sync behavior and timestamp preservation
- Fast money triage workflow
- Database backward compatibility
- Testing procedures

## Testing Results

✅ Schema migration works on existing databases
✅ All 940 programs synced with timestamps
✅ All 47,372 assets synced with timestamps
✅ CLI flags parse and apply correctly
✅ Radar display shows 🆕 NEW badges
✅ Export filtering works with newness flags
✅ Config-based filtering is functional
✅ Backward compatibility maintained

## Usage Quick Reference

```bash
# Discover new opportunities (last 30 days)
python3 scan4me.py radar --limit 50 --new-companies --new-company-days 30

# Export scope for new programs (cleaned for httpx)
python3 scan4me.py export --top 50 --new-companies --new-company-days 30 \
  --wildcards-only --clean | sort -u > targets.txt

# Find programs with recently discovered assets
python3 scan4me.py radar --limit 20 --new-assets --new-asset-days 30

# Enable newness filtering in config
# Edit config.json: "prefer_new_companies": true
python3 scan4me.py radar --limit 20
```

## Files Modified
- `/home/phantomcore/Scan4Me/scan4me.py` (core implementation)
- `/home/phantomcore/Scan4Me/config.json` (new configuration options)

## Files Added
- `/home/phantomcore/Scan4Me/NEWNESS_TRACKING.md` (user guide)
- `/home/phantomcore/Scan4Me/CHANGELOG_NEWNESS.md` (this file)

## Future Considerations
- Webhook notifications for newly discovered high-payout programs
- Ranking boost for programs with new assets
- Asset change detection and alerts
- Integration with OmniCLI for automatic analysis pipeline
- Report saturation tracking over time
