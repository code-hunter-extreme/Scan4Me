# 🎯 Scan4Me: Precision Bug Bounty Intelligence & Scope Targeter

**Scan4Me** is an automated bug bounty target selection engine designed for white-hat hackers who prioritize **fast triage response times**, **low report duplication**, **fresh assets**, and **high-payout bounty programs (fast cash)**.

It aggregates and normalizes targets across **HackerOne**, **Bugcrowd**, **Intigriti**, and **YesWeHack**, indexing over **47,000+ assets** into a local SQLite database that can be queried in milliseconds offline.

---

## ⚡ Key Features

- **Triage Speed Filtering**: Filter programs where internal security teams respond in `< 24h` or `< 48h` with high efficiency (>80%), so your reports get validated without waiting months.
- **Fast-Money Scoring**: Algorithmic scoring balancing:
  - ⚡ Triage response speed (40%)
  - 🌿 Asset freshness & low report saturation (35%)
  - 💰 Payout tier & bounty viability (25%)
- **Customizable Configuration (`config.json`)**: Easily tune filters, thresholds, platform preferences, and scoring weights.
- **Instant Legal Scope Checker**: Verify whether a given URL, domain, or IP is authorized before testing.
- **Recon Pipeline Feeder**: Export filtered in-scope domains and wildcards directly formatted for `subfinder`, `httpx`, and `nuclei`.

---

## 🚀 Quick Start

### 1. Initial Sync
Populate or update your local intelligence database with live feeds:
```bash
python3 scan4me.py sync
```

### 2. Run Precision Target Radar
Display the top programs matching your fast-cash criteria:
```bash
python3 scan4me.py radar --limit 15
```

### 3. Legal Scope Verification
Check if an asset is authorized under a known public bounty program:
```bash
python3 scan4me.py check api.tesla.com
```

### 4. Export Filtered Targets for Recon
Feed clean targets directly into your reconnaissance tools:
```bash
python3 scan4me.py export --top 25 --wildcards-only --clean | subfinder -silent | httpx -title -status-code
```

---

## ⚙️ Configuration (`config.json`)

Customize your hunting criteria:

```json
{
  "filters": {
    "paid_bounties_only": true,
    "fast_triage": {
      "enabled": true,
      "max_first_response_hours": 48.0,
      "min_response_efficiency_pct": 80.0,
      "prefer_managed_triage": true,
      "max_time_to_bounty_awarded_hours": 720.0
    },
    "freshness_and_competition": {
      "prefer_fresh_programs": true,
      "low_report_saturation": true,
      "min_in_scope_assets": 1,
      "require_wildcards": false
    },
    "payouts": {
      "min_max_payout_usd": 1000.0,
      "prioritize_fast_cash": true
    }
  },
  "platforms": {
    "hackerone": true,
    "bugcrowd": true,
    "intigriti": true,
    "yeswehack": true
  },
  "ranking_weights": {
    "triage_speed": 0.40,
    "freshness_and_low_saturation": 0.35,
    "payout_size": 0.25
  }
}
```

---

## 🛡️ Responsible Disclosure & Legal Notice

This tool is strictly intended for authorized security research, bug bounty hunting, and educational purposes. Always verify individual program policy pages and adhere to safe harbor guidelines before initiating any security assessment.
