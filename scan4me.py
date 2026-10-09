#!/usr/bin/env python3
"""
Scan4Me: Precision Bug Bounty Intelligence & Scope Targeter
Filters 47,000+ assets across HackerOne, Bugcrowd, Intigriti, and YesWeHack
for paid program discovery, scope size, available response-time measurements,
and first-observed changes in the imported feeds.
"""

import argparse
import base64
import json
import os
import re
import shutil
import sqlite3
import subprocess  # nosec B404
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
DB_PATH = REPO_ROOT / "scan4me.db"
CONFIG_PATH = REPO_ROOT / "config.json"
CONFIG_EXAMPLE_PATH = REPO_ROOT / "config.example.json"
CACHE_DATA_DIR = REPO_ROOT / "data_cache"

UPSTREAM_REPO = "https://github.com/arkadiyt/bounty-targets-data.git"
# Secondary feed: projectdiscovery/public-bugbounty-programs (machine-readable scope JSON)
PD_PROGRAMS_REPO = "https://github.com/projectdiscovery/public-bugbounty-programs.git"
# Immunefi: no stable public JSON API exists — fetcher always soft-fails gracefully.
# Set to None to skip without a network attempt; point to a community mirror when one emerges.
IMMUNEFI_API_URL = None
# Sherlock audit contest API (Web3 smart contract audit contests — confirmed public, paginated)
SHERLOCK_API_URL = "https://audits.sherlock.xyz/api/contests"

# ── Authenticated API endpoints ───────────────────────────────────────────────
# Used when an api_key is configured for the platform; falls back to public feed.
H1_API_BASE = "https://api.hackerone.com/v1"
BUGCROWD_API_BASE = "https://api.bugcrowd.com"
INTIGRITI_API_BASE = "https://api.intigriti.com/core"
YESWEHACK_API_BASE = "https://api.yeswehack.com"


# ─────────────────────────────────────────────────────────────────────────────
# Credential loader
# Priority: environment variable > config.json api_keys > None
# Never store real keys in config.json when using git — use env vars instead.
# ─────────────────────────────────────────────────────────────────────────────


def load_credentials(config=None):
    """Return a dict of per-platform credential dicts.

    For each platform the returned dict has whatever keys that platform needs
    (e.g. {'username': '...', 'api_token': '...'} for HackerOne).
    A key is absent or None when not configured — callers must check before use.

    Env var names follow the pattern documented in config.json api_keys._env.
    Env vars always override config.json values so real secrets stay out of files.
    """
    cfg_keys = (config or {}).get("api_keys", {})

    def _get(platform, field, env_var):
        """env var > config.json > None"""
        env_val = os.environ.get(env_var, "").strip()
        if env_val:
            return env_val
        return (cfg_keys.get(platform) or {}).get(field) or None

    return {
        "hackerone": {
            "username": _get("hackerone", "username", "HACKERONE_USERNAME"),
            "api_token": _get("hackerone", "api_token", "HACKERONE_API_TOKEN"),
        },
        "bugcrowd": {
            "api_token": _get("bugcrowd", "api_token", "BUGCROWD_API_TOKEN"),
        },
        "intigriti": {
            "api_token": _get("intigriti", "api_token", "INTIGRITI_API_TOKEN"),
        },
        "yeswehack": {
            "api_token": _get("yeswehack", "api_token", "YESWEHACK_API_TOKEN"),
        },
        # Slots for platforms that don't have APIs yet — ready when they do
        "federacy": {"api_token": _get("federacy", "api_token", "FEDERACY_API_TOKEN")},
        "immunefi": {"api_token": _get("immunefi", "api_token", "IMMUNEFI_API_TOKEN")},
        "sherlock": {"api_token": _get("sherlock", "api_token", "SHERLOCK_API_TOKEN")},
        "hackenproof": {
            "api_token": _get("hackenproof", "api_token", "HACKENPROOF_API_TOKEN")
        },
        "bugbase": {"api_token": _get("bugbase", "api_token", "BUGBASE_API_TOKEN")},
        "pd_programs": {
            "api_token": _get("pd_programs", "api_token", "PD_PROGRAMS_API_TOKEN")
        },
    }


def _api_request(
    url, *, auth_basic=None, bearer=None, token_header=None, method="GET", timeout=30
):
    """Make an authenticated HTTP request, return parsed JSON or raise.

    auth_basic   : (username, password/token) tuple → HTTP Basic Authorization
    bearer       : string → Authorization: Bearer <token>
    token_header : string → Authorization: Token <token>
    """
    req = urllib.request.Request(url, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "Scan4Me authenticated sync/1.0")
    if auth_basic:
        creds = base64.b64encode(f"{auth_basic[0]}:{auth_basic[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")
    elif bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    elif token_header:
        req.add_header("Authorization", f"Token {token_header}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        return json.load(resp)


# ─────────────────────────────────────────────────────────────────────────────
# Authenticated program fetchers
# Each returns a list of normalized program dicts identical to the public feed
# schema so sync_data can use them as a drop-in replacement.
# ─────────────────────────────────────────────────────────────────────────────


def _fetch_h1_authenticated(username, api_token):
    """Fetch your full HackerOne program list via the authenticated API.

    Returns private + public programs you have access to.
    Endpoint: GET /v1/hackers/programs (paginated, 100/page).
    Auth: HTTP Basic username:api_token.
    """
    programs = []
    page = 1
    while True:
        try:
            data = _api_request(
                f"{H1_API_BASE}/hackers/programs"
                f"?page%5Bnumber%5D={page}&page%5Bsize%5D=100"
                f"&sort=name&filter%5Bsubmission_state%5D%5B%5D=open",
                auth_basic=(username, api_token),
            )
        except Exception as e:
            if page == 1:
                print(f"[!] HackerOne authenticated fetch failed: {e}")
            break

        items = data.get("data", [])
        for item in items:
            attrs = item.get("attributes", {})
            handle = attrs.get("handle", "")
            programs.append(
                {
                    "handle": handle,
                    "name": attrs.get("name") or handle,
                    "url": f"https://hackerone.com/{handle}",
                    "website": attrs.get("profile", {}).get("website") or "",
                    "offers_bounties": bool(attrs.get("offers_bounties")),
                    "managed_program": bool(attrs.get("managed_program")),
                    "average_time_to_first_program_response": attrs.get(
                        "average_time_to_first_program_response"
                    ),
                    "average_time_to_bounty_awarded": attrs.get(
                        "average_time_to_bounty_awarded"
                    ),
                    "average_time_to_report_resolved": attrs.get(
                        "average_time_to_report_resolved"
                    ),
                    "response_efficiency_percentage": attrs.get(
                        "response_efficiency_percentage"
                    ),
                    "targets": {
                        "in_scope": [
                            {
                                "asset_identifier": s.get("asset_identifier", ""),
                                "asset_type": s.get("asset_type", "URL"),
                            }
                            for s in attrs.get("structured_scopes", [])
                            if s.get("eligible_for_submission")
                        ]
                    },
                }
            )

        links = data.get("links", {})
        if not links.get("next"):
            break
        page += 1

    print(
        f"[+] HackerOne authenticated: {len(programs)} programs (including private invites)."
    )
    return programs


def _fetch_bugcrowd_authenticated(api_token):
    """Fetch your Bugcrowd program list via the authenticated API.

    Endpoint: GET /engagements (paginated).
    Auth: Authorization: Token <api_token>.
    """
    programs = []
    page = 1
    while True:
        try:
            data = _api_request(
                f"{BUGCROWD_API_BASE}/engagements?page={page}&sort=name",
                token_header=api_token,
            )
        except Exception as e:
            if page == 1:
                print(f"[!] Bugcrowd authenticated fetch failed: {e}")
            break

        items = data.get("data", data if isinstance(data, list) else [])
        if not items:
            break
        for item in items:
            attrs = item.get("attributes", item)
            name = attrs.get("name", "Unknown")
            handle = attrs.get("code", name.lower().replace(" ", "-"))
            url = attrs.get("url", "") or f"https://bugcrowd.com/{handle}"
            if url.startswith("/"):
                url = f"https://bugcrowd.com{url}"
            max_p = float(attrs.get("max_payout", 0) or 0)
            programs.append(
                {
                    "name": name,
                    "url": url,
                    "max_payout": max_p,
                    "managed_by_bugcrowd": bool(attrs.get("managed_by_bugcrowd")),
                    "safe_harbor": attrs.get("safe_harbor", "Standard"),
                    "targets": {
                        "in_scope": [
                            {
                                "target": s.get("target", ""),
                                "type": s.get("type", "website"),
                            }
                            for s in attrs.get("targets", {}).get("in_scope", [])
                        ]
                    },
                }
            )

        if len(items) < 25:
            break
        page += 1

    print(f"[+] Bugcrowd authenticated: {len(programs)} programs (including private).")
    return programs


def _fetch_intigriti_authenticated(api_token):
    """Fetch your Intigriti program list via the authenticated API.

    Endpoint: GET /core/researcher/programs (paginated).
    Auth: Authorization: Bearer <api_token>.
    """
    programs = []
    page = 1
    while True:
        try:
            data = _api_request(
                f"{INTIGRITI_API_BASE}/researcher/programs"
                f"?offset={(page-1)*20}&limit=20&status=open",
                bearer=api_token,
            )
        except Exception as e:
            if page == 1:
                print(f"[!] Intigriti authenticated fetch failed: {e}")
            break

        records = data.get("records", data if isinstance(data, list) else [])
        if not records:
            break
        for item in records:
            handle = item.get("handle") or str(item.get("id", ""))
            max_b = item.get("maxBounty") or item.get("max_bounty") or {}
            max_val = float((max_b.get("value") or 0) if isinstance(max_b, dict) else 0)
            curr = max_b.get("currency", "EUR") if isinstance(max_b, dict) else "EUR"
            programs.append(
                {
                    "handle": handle,
                    "name": item.get("name", handle),
                    "url": item.get(
                        "url", f"https://app.intigriti.com/programs/{handle}"
                    ),
                    "max_bounty": {"value": max_val, "currency": curr},
                    "targets": {
                        "in_scope": [
                            {
                                "endpoint": s.get("endpoint", ""),
                                "type": s.get("type", "url"),
                            }
                            for s in item.get(
                                "domains", item.get("targets", {}).get("in_scope", [])
                            )
                        ]
                    },
                }
            )

        total = data.get("total", data.get("maxCount", 0))
        if page * 20 >= total or len(records) < 20:
            break
        page += 1

    print(f"[+] Intigriti authenticated: {len(programs)} programs (including private).")
    return programs


def _fetch_yeswehack_authenticated(api_token):
    """Fetch your YesWeHack program list via the authenticated API.

    Endpoint: GET /programs (paginated, includes private programs).
    Auth: Authorization: Bearer <api_token>.
    """
    programs = []
    page = 1
    while True:
        try:
            data = _api_request(
                f"{YESWEHACK_API_BASE}/programs?page={page}&perPage=50",
                bearer=api_token,
            )
        except Exception as e:
            if page == 1:
                print(f"[!] YesWeHack authenticated fetch failed: {e}")
            break

        items = data.get("items", data if isinstance(data, list) else [])
        if not items:
            break
        for item in items:
            programs.append(
                {
                    "id": item.get("id", item.get("slug", "")),
                    "name": item.get("title", item.get("name", "")),
                    "max_bounty": item.get("maxBounty", item.get("max_bounty", 0)),
                    "managed": bool(item.get("managed")),
                    "targets": {
                        "in_scope": [
                            {
                                "target": s.get("target", s.get("scope", "")),
                                "target_type": s.get("type", "web"),
                            }
                            for s in item.get(
                                "scope", item.get("targets", {}).get("in_scope", [])
                            )
                        ]
                    },
                }
            )

        pagination = data.get("pagination", {})
        if page >= pagination.get("nb_pages", 1):
            break
        page += 1

    print(f"[+] YesWeHack authenticated: {len(programs)} programs (including private).")
    return programs


DEFAULT_CONFIG = {
    "filters": {
        "paid_bounties_only": True,
        "fast_triage": {
            "enabled": True,
            "max_first_response_hours": 24.0,
            "min_response_efficiency_pct": 90.0,
            "prefer_managed_triage": True,
            "max_time_to_bounty_awarded_hours": 336.0,
            "require_measured_response_time": False,
            "max_validation_days": 14,
            "strict_validation_days": False,
        },
        "attack_surface_and_scope": {
            "prefer_large_attack_surface": True,
            "min_in_scope_assets": 1,
            "prioritize_wildcards": True,
            "wildcard_multiplier": 2.5,
        },
        "freshness_and_competition": {
            "prefer_fresh_programs": True,
            "low_report_saturation": True,
            "prefer_new_companies": True,
            "new_company_days": 90,
            "strict_new_companies": False,
            "prefer_new_assets": True,
            "new_asset_days": 30,
            "strict_new_assets": False,
            "max_rewarded_vulnerabilities": 150,
        },
        "payouts": {"min_max_payout_usd": 1000.0, "prioritize_fast_cash": True},
        "program_kind": {"web2": True, "web3": True},
    },
    "platforms": {
        "hackerone": True,
        "bugcrowd": True,
        "intigriti": True,
        "yeswehack": True,
        "federacy": True,
        "immunefi": True,
        "sherlock": True,
        "pd_programs": True,
    },
    "ranking_weights": {
        "triage_speed": 0.40,
        "attack_surface_size": 0.20,
        "freshness_and_low_saturation": 0.25,
        "payout_size": 0.15,
    },
    "display": {"limit": 25, "show_company_profile": True, "show_assets_sample": True},
}


def load_config():
    # Priority: config.json (local, git-ignored) → config.example.json → DEFAULT_CONFIG
    for path in (CONFIG_PATH, CONFIG_EXAMPLE_PATH):
        if path.exists():
            try:
                with open(path, encoding="utf-8") as f:
                    cfg = json.load(f)
                if path == CONFIG_EXAMPLE_PATH:
                    print(
                        f"[*] config.json not found — using {path.name} (template). "
                        "Copy it to config.json and set your API keys."
                    )
                return cfg
            except Exception as e:
                print(f"[!] Warning: Failed to load {path.name} ({e}), trying next.")
    return DEFAULT_CONFIG


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    """Initialize database schema if tables don't exist."""
    cur = conn.cursor()

    # Check if programs table exists
    result = cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='programs'"
    ).fetchone()
    if result is None:
        with conn:
            conn.executescript(
                """
            CREATE TABLE programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                name TEXT NOT NULL,
                handle TEXT,
                url TEXT,
                website TEXT,
                offers_bounties BOOLEAN DEFAULT 0,
                managed_triage BOOLEAN DEFAULT 0,
                first_response_hours REAL,
                bounty_awarded_hours REAL,
                report_resolved_hours REAL,
                response_efficiency REAL,
                max_payout REAL DEFAULT 0,
                currency TEXT DEFAULT 'USD',
                safe_harbor TEXT,
                first_seen_timestamp INTEGER DEFAULT 0,
                last_updated_timestamp INTEGER DEFAULT 0,
                official_start_timestamp INTEGER,
                official_scope_updated_timestamp INTEGER,
                rewarded_vulnerabilities INTEGER,
                validation_days REAL,
                average_payout REAL,
                official_metadata_checked_timestamp INTEGER,
                program_kind TEXT DEFAULT 'web2',
                UNIQUE(platform, handle)
            );

            CREATE TABLE assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER,
                asset_identifier TEXT NOT NULL,
                asset_type TEXT,
                is_wildcard BOOLEAN DEFAULT 0,
                first_seen_timestamp INTEGER DEFAULT 0,
                FOREIGN KEY (program_id) REFERENCES programs(id)
            );

            CREATE INDEX idx_asset_identifier ON assets(asset_identifier);
            CREATE INDEX idx_program_platform ON programs(platform);
            CREATE INDEX idx_program_bounty ON programs(offers_bounties);
            CREATE INDEX idx_program_first_seen ON programs(first_seen_timestamp);
            CREATE INDEX idx_asset_first_seen ON assets(first_seen_timestamp);
            CREATE TABLE sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
            )
    else:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """
        )
        conn.commit()


def migrate_db(conn):
    """Add timestamp columns if they don't exist (for backward compatibility)."""
    cur = conn.cursor()

    # Check if programs table has first_seen_timestamp column
    prog_cols = [row[1] for row in cur.execute("PRAGMA table_info(programs)")]
    if "first_seen_timestamp" not in prog_cols:
        print(
            "[*] Migrating programs table: adding first_seen_timestamp, last_updated_timestamp..."
        )
        cur.execute(
            "ALTER TABLE programs ADD COLUMN first_seen_timestamp INTEGER DEFAULT 0"
        )
    if "last_updated_timestamp" not in prog_cols:
        cur.execute(
            "ALTER TABLE programs ADD COLUMN last_updated_timestamp INTEGER DEFAULT 0"
        )
    for column, definition in (
        ("official_start_timestamp", "INTEGER"),
        ("official_scope_updated_timestamp", "INTEGER"),
        ("rewarded_vulnerabilities", "INTEGER"),
        ("validation_days", "REAL"),
        ("average_payout", "REAL"),
        ("official_metadata_checked_timestamp", "INTEGER"),
        ("program_kind", "TEXT DEFAULT 'web2'"),
    ):
        if column not in prog_cols:
            cur.execute(f"ALTER TABLE programs ADD COLUMN {column} {definition}")

    # Check if assets table has first_seen_timestamp column
    asset_cols = [row[1] for row in cur.execute("PRAGMA table_info(assets)")]
    if "first_seen_timestamp" not in asset_cols:
        print("[*] Migrating assets table: adding first_seen_timestamp...")
        cur.execute(
            "ALTER TABLE assets ADD COLUMN first_seen_timestamp INTEGER DEFAULT 0"
        )
    if "official_first_seen_timestamp" not in asset_cols:
        cur.execute(
            "ALTER TABLE assets ADD COLUMN official_first_seen_timestamp INTEGER"
        )

    conn.commit()


def sync_assets(cur, program_id, targets, identifier_key, type_key, now_ts):
    """Reconcile a program's current scope while retaining first-observed times."""
    current_assets = {}
    for target in targets:
        identifier = str(target.get(identifier_key) or "").strip()
        target_name = str(target.get("name") or "").strip().lower()
        if (
            "temporarily out of scope" in identifier.lower()
            or "temporarily out of scope" in target_name
        ):
            continue
        if identifier:
            current_assets[identifier] = target.get(type_key, "URL")

    existing_assets = {
        row["asset_identifier"]: row
        for row in cur.execute(
            "SELECT id, asset_identifier, first_seen_timestamp FROM assets WHERE program_id=?",
            (program_id,),
        ).fetchall()
    }
    for identifier, asset_type in current_assets.items():
        is_wildcard = int("*" in identifier)
        existing = existing_assets.get(identifier)
        if existing:
            cur.execute(
                "UPDATE assets SET asset_type=?, is_wildcard=? WHERE id=?",
                (asset_type, is_wildcard, existing["id"]),
            )
        else:
            cur.execute(
                """INSERT INTO assets
                   (program_id, asset_identifier, asset_type, is_wildcard, first_seen_timestamp)
                   VALUES (?, ?, ?, ?, ?)""",
                (program_id, identifier, asset_type, is_wildcard, now_ts),
            )

    stale_ids = [
        row["id"]
        for identifier, row in existing_assets.items()
        if identifier not in current_assets
    ]
    if stale_ids:
        cur.executemany(
            "DELETE FROM assets WHERE id=?", ((asset_id,) for asset_id in stale_ids)
        )


def fetch_public_json(url):
    request = urllib.request.Request(
        url, headers={"User-Agent": "Scan4Me public bug-bounty metadata sync"}
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
        return json.load(response)


def parse_public_timestamp(value):
    if not value:
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except (AttributeError, TypeError, ValueError):
        return None


def bugcrowd_scope_aliases(scope):
    aliases = set()
    for group in scope or []:
        if not group.get("inScope", True):
            continue
        for target in group.get("targets", []):
            if "temporarily out of scope" in str(target.get("name") or "").lower():
                continue
            for field in ("uri", "name"):
                value = target.get(field)
                if value:
                    aliases.add(str(value).strip().rstrip("/").lower())
    return aliases


def enrich_bugcrowd_program(conn, program_id, handle, now_ts=None):
    """Store public Bugcrowd program dates, scope history, and aggregate statistics."""
    now_ts = now_ts or int(time.time())
    base_url = f"https://bugcrowd.com/engagements/{urllib.parse.quote(handle, safe='')}"
    changelog_index = fetch_public_json(f"{base_url}/changelog.json")
    entries = changelog_index.get("changelogs", [])

    program_start = None
    scope_history = []
    for entry in entries:
        version_timestamp = parse_public_timestamp(entry.get("publishedAt"))
        if not version_timestamp:
            continue
        if "targets" in (entry.get("tags") or "").split(","):
            detail_url = entry.get("changelogShowUrl")
            if not detail_url or not detail_url.startswith("/"):
                continue
            detail = fetch_public_json(f"https://bugcrowd.com{detail_url}.json")
            data = detail.get("data", {})
            start = parse_public_timestamp(data.get("engagement", {}).get("startsAt"))
            if start:
                program_start = start
            scope_history.append(
                (version_timestamp, bugcrowd_scope_aliases(data.get("scope")))
            )

    stats = fetch_public_json(f"{base_url}/statistics")
    rewarded = stats.get("rewardedVulnerabilities")
    validation_text = stats.get("validationWithin")
    validation_days = None
    if isinstance(validation_text, str):
        match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s+days?\s*", validation_text)
        if match:
            validation_days = float(match.group(1))
    average_payout = None
    average_text = stats.get("averagePayout")
    if isinstance(average_text, str):
        match = re.fullmatch(r"\s*\$([\d,]+(?:\.\d{1,2})?)\s*", average_text)
        if match:
            average_payout = float(match.group(1).replace(",", ""))

    cur = conn.cursor()
    asset_rows = cur.execute(
        "SELECT id, asset_identifier FROM assets WHERE program_id=?", (program_id,)
    ).fetchall()
    first_added = {}
    for version_timestamp, aliases in sorted(scope_history):
        for asset in asset_rows:
            key = asset["asset_identifier"].strip().rstrip("/").lower()
            if key in aliases and asset["id"] not in first_added:
                first_added[asset["id"]] = version_timestamp

    with conn:
        cur.execute(
            """UPDATE programs
               SET official_start_timestamp=?,
                   official_scope_updated_timestamp=?,
                   rewarded_vulnerabilities=?,
                   validation_days=?,
                   average_payout=?,
                   official_metadata_checked_timestamp=?
               WHERE id=?""",
            (
                program_start,
                max((timestamp for timestamp, _ in scope_history), default=None),
                rewarded if isinstance(rewarded, int) else None,
                validation_days,
                average_payout,
                now_ts,
                program_id,
            ),
        )
        for asset_id, timestamp in first_added.items():
            cur.execute(
                "UPDATE assets SET official_first_seen_timestamp=? WHERE id=?",
                (timestamp, asset_id),
            )
        if asset_rows:
            reset_holders = ",".join("?" for _ in first_added) or "NULL"
            reset_sql = (
                "UPDATE assets SET official_first_seen_timestamp=NULL "  # nosec B608
                "WHERE program_id=? AND id NOT IN (" + reset_holders + ")"
            )
            cur.execute(reset_sql, (program_id, *first_added.keys()))
    return {
        "program_start": program_start,
        "scope_versions": len(scope_history),
        "assets_with_official_dates": len(first_added),
        "rewarded_vulnerabilities": rewarded if isinstance(rewarded, int) else None,
        "validation_days": validation_days,
        "average_payout": average_payout,
    }


def _fetch_immunefi_programs():
    """Fetch Immunefi bug bounty program list from their public JSON feed.

    Immunefi has no stable public JSON API — IMMUNEFI_API_URL is None until a
    reliable community mirror is identified.  Always returns [] gracefully.
    """
    if not IMMUNEFI_API_URL:
        print("[*] Immunefi: no public JSON API available — skipping.")
        return []
    try:
        req = urllib.request.Request(
            IMMUNEFI_API_URL,
            headers={"User-Agent": "Scan4Me public bug-bounty metadata sync"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
            data = json.load(resp)
    except Exception as e:
        print(f"[!] Immunefi fetch skipped: {e}")
        return []

    if isinstance(data, dict):
        data = data.get("bounties", data.get("data", []))
    if not isinstance(data, list):
        return []

    programs = []
    for item in data:
        name = item.get("project") or item.get("name") or ""
        if not name:
            continue
        handle = name.lower().replace(" ", "-").replace(".", "-")
        url = item.get("url") or f"https://immunefi.com/bounty/{handle}/"
        raw_max = (
            item.get("maximumReward")
            or item.get("maxBounty")
            or item.get("max_payout")
            or 0
        )
        try:
            max_p = float(str(raw_max).replace(",", "").replace("$", "").strip() or 0)
        except (ValueError, TypeError):
            max_p = 0.0
        offers_bounty = max_p > 0 or bool(item.get("active", True))
        raw_assets = item.get("assets") or item.get("scope") or []
        asset_ids = []
        if isinstance(raw_assets, list):
            for a in raw_assets:
                if isinstance(a, dict):
                    ident = a.get("address") or a.get("url") or a.get("target") or ""
                elif isinstance(a, str):
                    ident = a
                else:
                    ident = ""
                ident = ident.strip()
                if ident:
                    asset_ids.append(ident)
        elif isinstance(raw_assets, str) and raw_assets.strip():
            asset_ids.append(raw_assets.strip())
        programs.append(
            {
                "name": name,
                "handle": handle,
                "url": url,
                "max_payout": max_p,
                "currency": "USD",
                "offers_bounties": offers_bounty,
                "assets": asset_ids,
            }
        )
    return programs


def _fetch_sherlock_contests():
    """Fetch Sherlock audit contest list from their public paginated API.

    Returns a list of normalized dicts: name, handle, url, max_payout, currency,
    offers_bounties, starts_at, ends_at, status.
    Sherlock contests are Web3 smart-contract audit competitions with prize pools
    in USD/USDC. Active/upcoming contests have status in ('JUDGING','OPEN','UPCOMING').
    Returns [] on any fetch/parse failure.
    """
    programs = []
    page = 1
    while True:
        try:
            req = urllib.request.Request(
                f"{SHERLOCK_API_URL}?page={page}",
                headers={
                    "User-Agent": "Scan4Me public bug-bounty metadata sync",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
                data = json.load(resp)
        except Exception as e:
            if page == 1:
                print(f"[!] Sherlock fetch skipped: {e}")
            break

        items = data.get("items", [])
        for item in items:
            title = item.get("title", "")
            if not title:
                continue
            handle = f"sherlock-{item.get('id', title.lower().replace(' ', '-'))}"
            url = f"https://audits.sherlock.xyz/contests/{item.get('id', '')}"
            prize_pool = item.get("prize_pool") or item.get("rewards") or 0
            try:
                max_p = float(str(prize_pool).replace(",", "").strip() or 0)
            except (ValueError, TypeError):
                max_p = 0.0
            # Only include public, non-private contests
            if item.get("private", False):
                continue
            status = item.get("status", "")
            offers_bounty = max_p > 0
            programs.append(
                {
                    "name": title,
                    "handle": handle,
                    "url": url,
                    "max_payout": max_p,
                    "currency": item.get("token", "USDC"),
                    "offers_bounties": offers_bounty,
                    "status": status,
                    "starts_at": item.get("starts_at"),
                    "ends_at": item.get("ends_at"),
                    "description": (item.get("short_description") or "")[:200],
                }
            )

        if not data.get("has_next", False):
            break
        page += 1

    return programs


def sync_data(refresh=True, platforms_cfg=None, config=None):
    """Sync all enabled feed sources into the local SQLite database.

    When api_keys are configured (config.json or env vars) the authenticated API
    is used instead of the public feed — gives access to private/invite programs.
    Falls back to the public arkadiyt feed automatically when no key is present.

    Core feeds (arkadiyt/bounty-targets-data, public fallback):
      HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy

    Authenticated feeds (when api_key configured):
      HackerOne  — api.hackerone.com/v1/hackers/programs  (Basic username:token)
      Bugcrowd   — api.bugcrowd.com/engagements           (Token header)
      Intigriti  — api.intigriti.com/core/researcher/...  (Bearer token)
      YesWeHack  — api.yeswehack.com/programs             (Bearer token)

    Optional live feeds (fetched directly, no auth needed):
      Immunefi  — no public API yet; skipped gracefully
      Sherlock  — paginated audit contest API (web3)

    Supplemental feed (projectdiscovery/public-bugbounty-programs):
      Machine-readable scope JSON for 800+ programs across many platforms.
      Indexed as platform='PDPrograms'.  Skipped when unavailable.
    """
    platforms_cfg = platforms_cfg or {}
    creds = load_credentials(config or load_config())
    CACHE_DATA_DIR.mkdir(parents=True, exist_ok=True)
    repo_dir = CACHE_DATA_DIR / "repo"
    cached_repo_data = repo_dir / "data"
    local_data_dir = (
        cached_repo_data if cached_repo_data.is_dir() else CACHE_DATA_DIR / "data"
    )

    git_bin = shutil.which("git")
    if refresh:
        if not git_bin:
            raise FileNotFoundError("`git` not found on PATH; cannot refresh feeds.")
        if (repo_dir / ".git").exists():
            try:
                subprocess.run(
                    [git_bin, "-C", str(repo_dir), "pull", "--ff-only"],
                    check=True,
                    shell=False,  # nosec B603
                )
            except subprocess.CalledProcessError as e:
                print(f"[!] Feed repo pull failed ({e}) — using cached snapshot.")
        else:
            subprocess.run(
                [git_bin, "clone", "--depth", "1", UPSTREAM_REPO, str(repo_dir)],
                check=True,
                shell=False,  # nosec B603
            )
        local_data_dir = repo_dir / "data"
    elif not local_data_dir.exists():
        raise FileNotFoundError(
            f"Offline feed cache not found at {local_data_dir}; run `sync` once with network access."
        )

    # Core feeds are required only when their platform is enabled.
    feed_for_platform = (
        ("hackerone", "hackerone_data.json"),
        ("bugcrowd", "bugcrowd_data.json"),
        ("intigriti", "intigriti_data.json"),
        ("yeswehack", "yeswehack_data.json"),
    )
    required_feeds = tuple(
        name for plat, name in feed_for_platform if platforms_cfg.get(plat, True)
    )
    missing_feeds = [
        name for name in required_feeds if not (local_data_dir / name).is_file()
    ]
    if missing_feeds:
        raise FileNotFoundError(
            f"Missing feed files in {local_data_dir}: {', '.join(missing_feeds)}"
        )

    conn = get_db()
    init_db(conn)
    migrate_db(conn)

    cur = conn.cursor()
    baseline_complete = cur.execute(
        "SELECT value FROM sync_metadata WHERE key='baseline_complete'"
    ).fetchone()
    is_baseline_sync = baseline_complete is None

    print(f"[*] Ingesting and normalizing targets from {local_data_dir}...")
    now_ts = int(time.time())

    # 1. HackerOne — authenticated API when keys present, public feed fallback
    h1_creds = creds.get("hackerone", {})
    h1_username = h1_creds.get("username")
    h1_token = h1_creds.get("api_token")
    if h1_username and h1_token and platforms_cfg.get("hackerone", True):
        print(
            "[*] HackerOne: API key found — using authenticated feed (includes private invites)."
        )
        h1_data = _fetch_h1_authenticated(h1_username, h1_token)
    else:
        if h1_username or h1_token:
            print(
                "[!] HackerOne: partial credentials (need both username + api_token) — using public feed."
            )
        h1_file = local_data_dir / "hackerone_data.json"
        if h1_file.exists():
            with open(h1_file, encoding="utf-8") as f:
                h1_data = json.load(f)
        else:
            h1_data = []

    if h1_data and platforms_cfg.get("hackerone", True):
        with conn:
            for p in h1_data:
                handle = p.get("handle")
                name = p.get("name") or handle
                url = p.get("url") or f"https://hackerone.com/{handle}"
                website = p.get("website") or ""
                offers_bounty = bool(p.get("offers_bounties"))
                managed = bool(p.get("managed_program"))
                resp_time = p.get("average_time_to_first_program_response")
                bounty_time = p.get("average_time_to_bounty_awarded")
                resolved_time = p.get("average_time_to_report_resolved")
                efficiency = p.get("response_efficiency_percentage")

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                    ("HackerOne", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        first_response_hours, bounty_awarded_hours, report_resolved_hours,
                        response_efficiency, currency, first_seen_timestamp, last_updated_timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'USD', ?, ?)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url, website=excluded.website,
                        offers_bounties=excluded.offers_bounties,
                        managed_triage=excluded.managed_triage,
                        first_response_hours=excluded.first_response_hours,
                        bounty_awarded_hours=excluded.bounty_awarded_hours,
                        report_resolved_hours=excluded.report_resolved_hours,
                        response_efficiency=excluded.response_efficiency,
                        currency=excluded.currency,
                        last_updated_timestamp=excluded.last_updated_timestamp
                """,
                    (
                        "HackerOne",
                        name,
                        handle,
                        url,
                        website,
                        offers_bounty,
                        managed,
                        resp_time,
                        bounty_time,
                        resolved_time,
                        efficiency,
                        first_seen,
                        now_ts,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("HackerOne", handle),
                ).fetchone()[0]
                sync_assets(
                    cur,
                    prog_id,
                    p.get("targets", {}).get("in_scope", []),
                    "asset_identifier",
                    "asset_type",
                    now_ts,
                )
        print(f"[+] HackerOne indexed: {len(h1_data)} programs.")

    # 2. Bugcrowd — authenticated API when key present, public feed fallback
    bc_token = creds.get("bugcrowd", {}).get("api_token")
    if bc_token and platforms_cfg.get("bugcrowd", True):
        print(
            "[*] Bugcrowd: API key found — using authenticated feed (includes private programs)."
        )
        bc_data = _fetch_bugcrowd_authenticated(bc_token)
    else:
        bc_file = local_data_dir / "bugcrowd_data.json"
        if bc_file.exists():
            with open(bc_file, encoding="utf-8") as f:
                bc_data = json.load(f)
        else:
            bc_data = []

    if bc_data and platforms_cfg.get("bugcrowd", True):
        with conn:
            for p in bc_data:
                name = p.get("name", "Unknown")
                url = p.get("url", "")
                if url.startswith("/"):
                    url = f"https://bugcrowd.com{url}"
                handle = url.rstrip("/").split("/")[-1]
                max_p = float(p.get("max_payout", 0) or 0)
                offers_bounty = max_p > 0
                managed = bool(p.get("managed_by_bugcrowd"))
                safe = p.get("safe_harbor", "Standard")

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                    ("Bugcrowd", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, currency, safe_harbor, first_seen_timestamp, last_updated_timestamp
                    ) VALUES (?, ?, ?, ?, '', ?, ?, ?, 'USD', ?, ?, ?)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url,
                        offers_bounties=excluded.offers_bounties,
                        managed_triage=excluded.managed_triage,
                        max_payout=excluded.max_payout, currency=excluded.currency,
                        safe_harbor=excluded.safe_harbor,
                        last_updated_timestamp=excluded.last_updated_timestamp
                """,
                    (
                        "Bugcrowd",
                        name,
                        handle,
                        url,
                        offers_bounty,
                        managed,
                        max_p,
                        safe,
                        first_seen,
                        now_ts,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("Bugcrowd", handle),
                ).fetchone()[0]
                sync_assets(
                    cur,
                    prog_id,
                    p.get("targets", {}).get("in_scope", []),
                    "target",
                    "type",
                    now_ts,
                )
        print(f"[+] Bugcrowd indexed: {len(bc_data)} programs.")

    # 3. Intigriti — authenticated API when key present, public feed fallback
    inti_token = creds.get("intigriti", {}).get("api_token")
    if inti_token and platforms_cfg.get("intigriti", True):
        print(
            "[*] Intigriti: API key found — using authenticated feed (includes private programs)."
        )
        inti_data = _fetch_intigriti_authenticated(inti_token)
    else:
        inti_file = local_data_dir / "intigriti_data.json"
        if inti_file.exists():
            with open(inti_file, encoding="utf-8") as f:
                inti_data = json.load(f)
        else:
            inti_data = []

    if inti_data and platforms_cfg.get("intigriti", True):
        with conn:
            for p in inti_data:
                name = p.get("name", "Unknown")
                handle = p.get("handle") or str(p.get("id"))
                url = p.get("url", "")
                max_b = p.get("max_bounty", {})
                max_val = (
                    float(max_b.get("value", 0) or 0) if isinstance(max_b, dict) else 0
                )
                curr = (
                    max_b.get("currency", "EUR") if isinstance(max_b, dict) else "EUR"
                )
                offers_bounty = max_val > 0

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                    ("Intigriti", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, currency, first_seen_timestamp, last_updated_timestamp
                    ) VALUES (?, ?, ?, ?, '', ?, 1, ?, ?, ?, ?)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url,
                        offers_bounties=excluded.offers_bounties,
                        managed_triage=excluded.managed_triage,
                        max_payout=excluded.max_payout, currency=excluded.currency,
                        last_updated_timestamp=excluded.last_updated_timestamp
                """,
                    (
                        "Intigriti",
                        name,
                        handle,
                        url,
                        offers_bounty,
                        max_val,
                        curr,
                        first_seen,
                        now_ts,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("Intigriti", handle),
                ).fetchone()[0]
                sync_assets(
                    cur,
                    prog_id,
                    p.get("targets", {}).get("in_scope", []),
                    "endpoint",
                    "type",
                    now_ts,
                )
        print(f"[+] Intigriti indexed: {len(inti_data)} programs.")

    # 4. YesWeHack — authenticated API when key present, public feed fallback
    ywh_token = creds.get("yeswehack", {}).get("api_token")
    if ywh_token and platforms_cfg.get("yeswehack", True):
        print(
            "[*] YesWeHack: API key found — using authenticated feed (includes private programs)."
        )
        ywh_data = _fetch_yeswehack_authenticated(ywh_token)
    else:
        ywh_file = local_data_dir / "yeswehack_data.json"
        if ywh_file.exists():
            with open(ywh_file, encoding="utf-8") as f:
                ywh_data = json.load(f)
        else:
            ywh_data = []

    if ywh_data and platforms_cfg.get("yeswehack", True):
        with conn:
            for p in ywh_data:
                name = p.get("name", "Unknown")
                handle = str(p.get("id"))
                max_val = float(p.get("max_bounty", 0) or 0)
                offers_bounty = max_val > 0
                managed = bool(p.get("managed"))

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                    ("YesWeHack", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, currency, first_seen_timestamp, last_updated_timestamp
                    ) VALUES (?, ?, ?, ?, '', ?, ?, ?, 'EUR', ?, ?)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url,
                        offers_bounties=excluded.offers_bounties,
                        managed_triage=excluded.managed_triage,
                        max_payout=excluded.max_payout, currency=excluded.currency,
                        last_updated_timestamp=excluded.last_updated_timestamp
                """,
                    (
                        "YesWeHack",
                        name,
                        handle,
                        f"https://yeswehack.com/programs/{handle}",
                        offers_bounty,
                        managed,
                        max_val,
                        first_seen,
                        now_ts,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("YesWeHack", handle),
                ).fetchone()[0]
                sync_assets(
                    cur,
                    prog_id,
                    p.get("targets", {}).get("in_scope", []),
                    "target",
                    "target_type",
                    now_ts,
                )
        print(f"[+] YesWeHack indexed: {len(ywh_data)} programs.")

    # 5. Federacy (optional — present in arkadiyt repo but tiny; skip when absent)
    fed_file = local_data_dir / "federacy_data.json"
    if fed_file.exists() and platforms_cfg.get("federacy", True):
        with open(fed_file, encoding="utf-8") as f:
            fed_data = json.load(f)
        with conn:
            for p in fed_data:
                name = p.get("name", "Unknown")
                handle = str(p.get("id") or name.lower().replace(" ", "-"))
                url = p.get("url", "")
                offers_bounty = bool(p.get("offers_awards", False))

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                    ("Federacy", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, currency, program_kind, first_seen_timestamp, last_updated_timestamp
                    ) VALUES (?, ?, ?, ?, '', ?, 0, 0, 'USD', 'web2', ?, ?)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url,
                        offers_bounties=excluded.offers_bounties,
                        last_updated_timestamp=excluded.last_updated_timestamp
                """,
                    ("Federacy", name, handle, url, offers_bounty, first_seen, now_ts),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("Federacy", handle),
                ).fetchone()[0]
                sync_assets(
                    cur,
                    prog_id,
                    p.get("targets", {}).get("in_scope", []),
                    "target",
                    "type",
                    now_ts,
                )
        print(f"[+] Federacy indexed: {len(fed_data)} programs.")
    elif not fed_file.exists():
        print("[*] Federacy feed not found in repo — skipping.")

    # 6. Immunefi (live fetch — Web3/DeFi; optional, skip on network failure)
    if refresh and platforms_cfg.get("immunefi", True):
        print("[*] Fetching Immunefi programs (Web3/DeFi live feed)...")
        immunefi_programs = _fetch_immunefi_programs()
        if immunefi_programs:
            with conn:
                for p in immunefi_programs:
                    handle = p["handle"]
                    existing = cur.execute(
                        "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                        ("Immunefi", handle),
                    ).fetchone()
                    first_seen = existing[1] if existing else now_ts

                    cur.execute(
                        """
                        INSERT INTO programs (
                            platform, name, handle, url, website, offers_bounties, managed_triage,
                            max_payout, currency, program_kind, first_seen_timestamp, last_updated_timestamp
                        ) VALUES (?, ?, ?, ?, '', ?, 0, ?, 'USD', 'web3', ?, ?)
                        ON CONFLICT(platform, handle) DO UPDATE SET
                            name=excluded.name, url=excluded.url,
                            offers_bounties=excluded.offers_bounties,
                            max_payout=excluded.max_payout,
                            last_updated_timestamp=excluded.last_updated_timestamp
                    """,
                        (
                            "Immunefi",
                            p["name"],
                            handle,
                            p["url"],
                            p["offers_bounties"],
                            p["max_payout"],
                            first_seen,
                            now_ts,
                        ),
                    )

                    prog_id = cur.execute(
                        "SELECT id FROM programs WHERE platform=? AND handle=?",
                        ("Immunefi", handle),
                    ).fetchone()[0]
                    # Immunefi assets are smart contract addresses / URLs — treat as non-wildcard
                    asset_targets = [
                        {"addr": a, "kind": "SmartContract"} for a in p["assets"]
                    ]
                    sync_assets(cur, prog_id, asset_targets, "addr", "kind", now_ts)
            print(f"[+] Immunefi indexed: {len(immunefi_programs)} programs.")
        else:
            print(
                "[*] Immunefi: no data returned (network unavailable or feed format changed)."
            )

    # 7. Sherlock audit contests (live fetch — Web3 smart-contract; optional, soft-fail)
    if refresh and platforms_cfg.get("sherlock", True):
        print(
            "[*] Fetching Sherlock audit contests (Web3 smart-contract competitions)..."
        )
        sherlock_contests = _fetch_sherlock_contests()
        if sherlock_contests:
            with conn:
                for p in sherlock_contests:
                    handle = p["handle"]
                    existing = cur.execute(
                        "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                        ("Sherlock", handle),
                    ).fetchone()
                    first_seen = existing[1] if existing else now_ts

                    cur.execute(
                        """
                        INSERT INTO programs (
                            platform, name, handle, url, website, offers_bounties, managed_triage,
                            max_payout, currency, program_kind, first_seen_timestamp, last_updated_timestamp
                        ) VALUES (?, ?, ?, ?, '', ?, 0, ?, ?, 'web3', ?, ?)
                        ON CONFLICT(platform, handle) DO UPDATE SET
                            name=excluded.name, url=excluded.url,
                            offers_bounties=excluded.offers_bounties,
                            max_payout=excluded.max_payout,
                            currency=excluded.currency,
                            last_updated_timestamp=excluded.last_updated_timestamp
                    """,
                        (
                            "Sherlock",
                            p["name"],
                            handle,
                            p["url"],
                            p["offers_bounties"],
                            p["max_payout"],
                            p["currency"],
                            first_seen,
                            now_ts,
                        ),
                    )
                    # Sherlock scopes are the contest URL itself — no sub-assets to enumerate
            print(f"[+] Sherlock indexed: {len(sherlock_contests)} contests.")
        else:
            print("[*] Sherlock: no contest data returned.")

    # 8. ProjectDiscovery public-bugbounty-programs (supplemental; soft-fail)
    if refresh and platforms_cfg.get("pd_programs", True):
        pd_repo_dir = CACHE_DATA_DIR / "pd_programs_repo"
        try:
            if (pd_repo_dir / ".git").exists():
                subprocess.run(
                    [git_bin, "-C", str(pd_repo_dir), "pull", "--ff-only"],
                    check=True,
                    shell=False,  # nosec B603
                    capture_output=True,
                )
            else:
                subprocess.run(
                    [
                        git_bin,
                        "clone",
                        "--depth",
                        "1",
                        PD_PROGRAMS_REPO,
                        str(pd_repo_dir),
                    ],
                    check=True,
                    shell=False,  # nosec B603
                    capture_output=True,
                )
        except subprocess.CalledProcessError as e:
            print(f"[!] ProjectDiscovery repo sync failed — skipping: {e}")
            pd_repo_dir = None

        if pd_repo_dir and pd_repo_dir.exists():
            pd_file = pd_repo_dir / "chaos-bugbounty-list.json"
            if pd_file.exists():
                try:
                    with open(pd_file, encoding="utf-8") as f:
                        pd_raw = json.load(f)
                    pd_programs_list = (
                        pd_raw
                        if isinstance(pd_raw, list)
                        else pd_raw.get("programs", [])
                    )
                    count = 0
                    with conn:
                        for p in pd_programs_list:
                            name = p.get("name", "")
                            if not name:
                                continue
                            handle = name.lower().replace(" ", "-")[:80]
                            url = p.get("url") or p.get("bounty_url") or ""
                            domains = p.get("domains") or []
                            offers_bounty = bool(p.get("bounty", False))

                            existing = cur.execute(
                                "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                                ("PDPrograms", handle),
                            ).fetchone()
                            first_seen = existing[1] if existing else now_ts

                            cur.execute(
                                """
                                INSERT INTO programs (
                                    platform, name, handle, url, website, offers_bounties,
                                    managed_triage, max_payout, currency, program_kind,
                                    first_seen_timestamp, last_updated_timestamp
                                ) VALUES (?, ?, ?, ?, '', ?, 0, 0, 'USD', 'web2', ?, ?)
                                ON CONFLICT(platform, handle) DO UPDATE SET
                                    name=excluded.name, url=excluded.url,
                                    offers_bounties=excluded.offers_bounties,
                                    last_updated_timestamp=excluded.last_updated_timestamp
                            """,
                                (
                                    "PDPrograms",
                                    name,
                                    handle,
                                    url,
                                    offers_bounty,
                                    first_seen,
                                    now_ts,
                                ),
                            )

                            prog_id = cur.execute(
                                "SELECT id FROM programs WHERE platform=? AND handle=?",
                                ("PDPrograms", handle),
                            ).fetchone()[0]
                            domain_targets = [
                                {"d": d, "t": "URL"} for d in domains if d
                            ]
                            sync_assets(cur, prog_id, domain_targets, "d", "t", now_ts)
                            count += 1
                    print(f"[+] ProjectDiscovery programs indexed: {count} programs.")
                except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
                    print(f"[!] ProjectDiscovery feed parse error — skipping: {e}")
            else:
                print(
                    "[*] ProjectDiscovery: chaos-bugbounty-list.json not found in cloned repo."
                )

    if is_baseline_sync:
        cur.execute("UPDATE programs SET first_seen_timestamp=0")
        cur.execute("UPDATE assets SET first_seen_timestamp=0")
        cur.execute(
            "INSERT INTO sync_metadata(key, value) VALUES('baseline_complete', ?) ",
            (str(now_ts),),
        )
        print("[*] Initial feed baseline recorded; current entries are not marked new.")
    conn.commit()

    total_progs = cur.execute("SELECT count(*) FROM programs").fetchone()[0]
    total_assets = cur.execute("SELECT count(*) FROM assets").fetchone()[0]
    total_wild = cur.execute(
        "SELECT count(*) FROM assets WHERE is_wildcard=1"
    ).fetchone()[0]
    print(
        f"\n[✓] Scan4Me Sync Complete: {total_progs} programs, {total_assets} assets ({total_wild} wildcards)."
    )


def cmd_enrich(args):
    conn = get_db()
    cur = conn.cursor()
    if args.handle:
        programs = cur.execute(
            """SELECT id, handle, name FROM programs
               WHERE platform='Bugcrowd' AND handle=?""",
            (args.handle,),
        ).fetchall()
        if not programs:
            raise ValueError(f"No Bugcrowd program found for handle {args.handle!r}")
    else:
        programs = cur.execute(
            """SELECT id, handle, name FROM programs
               WHERE platform='Bugcrowd'
               ORDER BY max_payout DESC
               LIMIT ?""",
            (args.limit,),
        ).fetchall()
    for index, program in enumerate(programs):
        try:
            result = enrich_bugcrowd_program(conn, program["id"], program["handle"])
        except (
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
            ValueError,
        ) as error:
            print(
                f"[!] {program['name']}: public Bugcrowd metadata unavailable: {error}"
            )
            continue
        start = (
            datetime.fromtimestamp(result["program_start"]).date()
            if result["program_start"]
            else "unknown"
        )
        print(
            f"[+] {program['name']}: started {start}; "
            f"{result['scope_versions']} scope versions; "
            f"{result['assets_with_official_dates']} assets dated; "
            f"{result['rewarded_vulnerabilities']} rewarded; "
            f"{result['validation_days']} validation days; "
            f"average payout ${result['average_payout']}"
        )
        if args.delay and index + 1 < len(programs):
            time.sleep(args.delay)


def evaluate_targets(config=None):
    config = config or load_config()
    conn = get_db()
    cur = conn.cursor()

    filters = config.get("filters", {})
    fast_triage = filters.get("fast_triage", {})
    surface_cfg = filters.get("attack_surface_and_scope", {})
    fresh_cfg = filters.get("freshness_and_competition", {})
    plat_cfg = config.get("platforms", {})
    weights = config.get(
        "ranking_weights",
        {
            "triage_speed": 0.35,
            "attack_surface_size": 0.30,
            "freshness_and_low_saturation": 0.20,
            "payout_size": 0.15,
        },
    )

    kind_cfg = filters.get("program_kind", {"web2": True, "web3": True})
    allowed_kinds = [k for k, v in kind_cfg.items() if v]

    enabled_plats = [p for p, enabled in plat_cfg.items() if enabled]
    plat_map = {
        "hackerone": "HackerOne",
        "bugcrowd": "Bugcrowd",
        "intigriti": "Intigriti",
        "yeswehack": "YesWeHack",
        "federacy": "Federacy",
        "immunefi": "Immunefi",
        "sherlock": "Sherlock",
        "pd_programs": "PDPrograms",
    }
    target_plats = [plat_map[p] for p in enabled_plats if p in plat_map]
    if not target_plats:
        return []

    plat_holders = ",".join("?" * len(target_plats))
    # ?-holders only; values stay bound parameters (B608 false positive).
    query = (
        "SELECT p.*, count(a.id) as asset_count, sum(a.is_wildcard) as wildcard_count "  # nosec B608
        "FROM programs p "
        "LEFT JOIN assets a ON p.id = a.program_id "
        "WHERE p.platform IN (" + plat_holders + ")"
    )
    params = list(target_plats)

    if filters.get("paid_bounties_only", True):
        query += " AND p.offers_bounties = 1"

    # Filter by program kind (web2 / web3) when not both enabled
    if allowed_kinds and len(allowed_kinds) < 2:
        query += " AND p.program_kind IN ({})".format(
            ",".join("?" * len(allowed_kinds))
        )
        params.extend(allowed_kinds)

    # prefer_new_companies: Bugcrowd uses official_start_timestamp; all other platforms
    # use first_seen_timestamp as a universal feed-observation proxy.
    # This is a SCORING signal, not a hard gate — the SQL here only applies the cutoff
    # when strict_new_companies is explicitly true.
    if fresh_cfg.get("strict_new_companies", False):
        new_company_days = fresh_cfg.get("new_company_days", 90)
        cutoff_ts = int(time.time()) - (new_company_days * 86400)
        # Bugcrowd: use official start date; others: use feed first-seen timestamp
        query += (
            " AND (("
            "  p.platform='Bugcrowd' AND p.official_start_timestamp IS NOT NULL"
            "  AND p.official_start_timestamp > ?"
            ") OR ("
            "  p.platform!='Bugcrowd' AND p.first_seen_timestamp > ?"
            "))"
        )
        params.extend([cutoff_ts, cutoff_ts])

    query += " GROUP BY p.id"
    rows = cur.execute(query, params).fetchall()

    now_ts = int(time.time())
    scored_programs = []
    max_first_resp = fast_triage.get("max_first_response_hours", 48.0)
    min_efficiency = fast_triage.get("min_response_efficiency_pct", 80.0)
    wildcard_mult = surface_cfg.get("wildcard_multiplier", 2.5)
    new_asset_days = fresh_cfg.get("new_asset_days", 30)
    new_company_days_score = fresh_cfg.get("new_company_days", 90)
    new_asset_cutoff = now_ts - (new_asset_days * 86400)
    new_company_cutoff = now_ts - (new_company_days_score * 86400)

    for r in rows:
        # ── Triage speed hard filters (HackerOne only — only platform with the data) ──
        if fast_triage.get("enabled", True) and r["platform"] == "HackerOne":
            if (
                r["first_response_hours"] is not None
                and r["first_response_hours"] > max_first_resp
            ):
                continue
            if (
                r["response_efficiency"] is not None
                and r["response_efficiency"] < min_efficiency
            ):
                continue

        # require_measured_response_time: hard gate — only passes HackerOne programs with
        # response data or Bugcrowd programs with published validation_days.
        if (
            fast_triage.get("enabled", True)
            and fast_triage.get("require_measured_response_time", False)
            and r["first_response_hours"] is None
            and not (r["platform"] == "Bugcrowd" and r["validation_days"] is not None)
        ):
            continue

        # max_validation_days: only hard-gate Bugcrowd programs that have the data.
        # Non-Bugcrowd platforms (no validation_days field) always pass through.
        max_validation_days = fast_triage.get("max_validation_days")
        if max_validation_days is not None and r["platform"] == "Bugcrowd":
            if (
                r["validation_days"] is not None
                and r["validation_days"] > max_validation_days
            ):
                continue
            # Bugcrowd programs without enrichment data pass through (data unknown ≠ slow)

        # max_rewarded_vulnerabilities: only hard-gate Bugcrowd programs with the data.
        # Non-Bugcrowd platforms always pass through (incomparable metric).
        max_rewarded = fresh_cfg.get("max_rewarded_vulnerabilities")
        if max_rewarded is not None and r["platform"] == "Bugcrowd":
            if (
                r["rewarded_vulnerabilities"] is not None
                and r["rewarded_vulnerabilities"] > max_rewarded
            ):
                continue

        asset_count = r["asset_count"] or 0
        wild_count = r["wildcard_count"] or 0

        # Scope filters
        if asset_count < surface_cfg.get("min_in_scope_assets", 1):
            continue

        # New assets: count official Bugcrowd-dated scope changes; for other platforms
        # fall back to counting assets first-seen within the window from the feed.
        # This is a SCORING signal — programs with no new assets still appear but score lower.
        new_assets_count = 0
        if fresh_cfg.get("prefer_new_assets", False):
            new_assets_count = cur.execute(
                """SELECT count(*) FROM assets WHERE program_id=?
                   AND (
                     (official_first_seen_timestamp IS NOT NULL AND official_first_seen_timestamp > ?)
                     OR
                     (official_first_seen_timestamp IS NULL AND first_seen_timestamp > ?)
                   )""",
                (r["id"], new_asset_cutoff, new_asset_cutoff),
            ).fetchone()[0]
            # Only hard-exclude if strict_new_assets is set AND this is a Bugcrowd program
            # with enrichment data that actually shows no new scope. All other platforms pass.
            if (
                fresh_cfg.get("strict_new_assets", False)
                and r["platform"] == "Bugcrowd"
                and cur.execute(
                    "SELECT count(*) FROM assets WHERE program_id=? AND official_first_seen_timestamp IS NOT NULL",
                    (r["id"],),
                ).fetchone()[0]
                > 0
                and new_assets_count == 0
            ):
                continue

        # 1. Triage Speed Score (0-100)
        # HackerOne: first_response_hours drives the base (lower = faster = higher score).
        # Bonus: bounty_awarded_hours <= 168h (1 week) = +15 pts; <= 336h (2 weeks) = +8 pts.
        # Bugcrowd: validation_days <= 7 = +20 pts; <= 14 = +10 pts (fast-cash proxy).
        # Other platforms default to 50 (no published measurement).
        speed_score = 50.0
        if r["platform"] == "HackerOne":
            if r["first_response_hours"] is not None:
                speed_score = max(0, 100 - (r["first_response_hours"] * 1.5))
            if r["bounty_awarded_hours"] is not None:
                if r["bounty_awarded_hours"] <= 168:
                    speed_score = min(100.0, speed_score + 15)
                elif r["bounty_awarded_hours"] <= 336:
                    speed_score = min(100.0, speed_score + 8)
        elif r["platform"] == "Bugcrowd" and r["validation_days"] is not None:
            if r["validation_days"] <= 7:
                speed_score = min(100.0, speed_score + 20)
            elif r["validation_days"] <= 14:
                speed_score = min(100.0, speed_score + 10)
        speed_score = min(100.0, speed_score)

        # 2. Attack Surface Score (0-100) - "More Assets is Better, More Surface Area"
        # Each asset gives 1.5 pts, each wildcard gives (1.5 * wildcard_mult) ~ 3.75 pts
        effective_surface = asset_count + (wild_count * wildcard_mult)
        if effective_surface >= 40:
            surface_score = 100.0
        elif effective_surface >= 20:
            surface_score = 85.0
        elif effective_surface >= 10:
            surface_score = 70.0
        elif effective_surface >= 5:
            surface_score = 50.0
        else:
            surface_score = 25.0

        # Tier labeling
        if wild_count >= 10 or asset_count >= 30:
            surface_tier = "🔥 MASSIVE SURFACE"
        elif wild_count >= 3 or asset_count >= 10:
            surface_tier = "⚡ WIDE SURFACE"
        elif wild_count >= 1 or asset_count >= 3:
            surface_tier = "🎯 MODERATE"
        else:
            surface_tier = "🔍 NARROW/FOCUSED"

        # 3. Freshness / Competition Score (0-100)
        # Priority: Bugcrowd official_start_timestamp → feed first_seen_timestamp → default 50.
        # Bonuses for:
        #   - program appears new (within new_company_days window)
        #   - has new scope assets (within new_asset_days window)
        #   - Bugcrowd: low rewarded_vulnerabilities (low competition proxy)
        #   - Bugcrowd: low validation_days (fast cash signal, also in speed but echoed here)
        effective_start_ts = (
            r["official_start_timestamp"] or r["first_seen_timestamp"] or 0
        )
        if effective_start_ts <= 0:
            fresh_score = 50.0
        elif effective_start_ts > new_company_cutoff:
            fresh_score = 100.0
        else:
            # Still a reasonable program; small bump if seen recently in feed
            first_seen_ts = r["first_seen_timestamp"] or 0
            if first_seen_ts > now_ts - 90 * 86400:
                fresh_score = 65.0
            else:
                fresh_score = 50.0

        # Bonus: program has recently-added in-scope assets (new attack surface)
        if new_assets_count > 0:
            fresh_score = min(100.0, fresh_score + 15)

        # Bonus: prefer_new_companies signal — any platform where we can see it's new
        if (
            fresh_cfg.get("prefer_new_companies", False)
            and effective_start_ts > new_company_cutoff
        ):
            fresh_score = min(100.0, fresh_score + 10)

        # Bonus: low competition (Bugcrowd rewarded_vulnerabilities as proxy)
        rewarded = r["rewarded_vulnerabilities"]
        if rewarded is not None:
            if rewarded <= 25:
                fresh_score = min(100.0, fresh_score + 20)
            elif rewarded <= 75:
                fresh_score = min(100.0, fresh_score + 12)
            elif rewarded <= 150:
                fresh_score = min(100.0, fresh_score + 5)

        # 4. Payout Score (0-100)
        # Base from max_payout band. Bugcrowd average_payout adds a real-money bonus
        # when it confirms high actual payouts even on modest max_payout ceilings.
        payout_score = 50.0
        max_p = r["max_payout"] or 0
        if max_p > 0:
            if max_p >= 100000:
                payout_score = 100.0
            elif max_p >= 20000:
                payout_score = 85.0
            elif max_p >= 5000:
                payout_score = 70.0
            else:
                payout_score = 55.0
        elif r["offers_bounties"]:
            payout_score = 65.0
        avg_p = r["average_payout"] or 0
        if avg_p >= 2000:
            payout_score = min(100.0, payout_score + 10)
        elif avg_p >= 500:
            payout_score = min(100.0, payout_score + 5)

        # Composite Fast-Money & Surface Area Score
        total_score = (
            (speed_score * weights["triage_speed"])
            + (surface_score * weights["attack_surface_size"])
            + (fresh_score * weights["freshness_and_low_saturation"])
            + (payout_score * weights["payout_size"])
        )

        scored_programs.append(
            {
                "name": r["name"],
                "platform": r["platform"],
                "url": r["url"],
                "website": r["website"],
                "safe_harbor": r["safe_harbor"] or "Standard",
                "score": round(total_score, 1),
                "speed_score": round(speed_score, 1),
                "surface_score": round(surface_score, 1),
                "fresh_score": round(fresh_score, 1),
                "payout_score": round(payout_score, 1),
                "surface_tier": surface_tier,
                "max_payout": r["max_payout"],
                "currency": r["currency"],
                "first_resp": r["first_response_hours"],
                "efficiency": r["response_efficiency"],
                "managed": bool(r["managed_triage"]),
                "response_time_known": r["first_response_hours"] is not None,
                "report_resolved_hours": r["report_resolved_hours"],
                "official_start_ts": r["official_start_timestamp"],
                "official_scope_updated_ts": r["official_scope_updated_timestamp"],
                "rewarded_vulnerabilities": r["rewarded_vulnerabilities"],
                "validation_days": r["validation_days"],
                "average_payout": r["average_payout"],
                "assets": asset_count,
                "wildcards": wild_count,
                "new_assets": new_assets_count,
                "first_seen_ts": r["first_seen_timestamp"],
                "program_kind": (
                    r["program_kind"] if "program_kind" in r.keys() else None
                )
                or "web2",
                "id": r["id"],
            }
        )

    scored_programs.sort(key=lambda x: x["score"], reverse=True)
    return scored_programs


def cmd_filter(args, config):
    results = evaluate_targets(config)
    limit = args.limit or config.get("display", {}).get("limit", 20)
    fresh_cfg = config.get("filters", {}).get("freshness_and_competition", {})
    new_company_days = fresh_cfg.get("new_company_days", 90)
    new_asset_days = fresh_cfg.get("new_asset_days", 30)

    print("\n" + "=" * 88)
    print(
        "🔥 SCAN4ME PRECISION TARGET RADAR (FAST TRIAGE • MASSIVE ATTACK SURFACE • FAST CASH)"
    )
    print("=" * 88)
    if fresh_cfg.get("prefer_new_companies"):
        print(
            "[*] New program filter uses Bugcrowd's published program start date; unsupported platforms are excluded."
        )
    if fresh_cfg.get("prefer_new_assets"):
        print(
            "[*] New asset filter uses Bugcrowd's dated scope history; unsupported/undated assets are excluded."
        )
    if fresh_cfg.get("low_report_saturation"):
        print(
            "[!] Report counts are not included in these feeds; low/no resolved reports cannot be verified."
        )
    print(
        f"[*] Displaying Top {min(limit, len(results))} Target Companies (Ranked by Surface & Speed):\n"
    )

    conn = get_db()
    for i, p in enumerate(results[:limit], 1):
        if p["response_time_known"]:
            triage_info = f"{p['first_resp']}h avg first response (HackerOne feed)"
            if p["efficiency"] is not None:
                triage_info += f", {p['efficiency']}% efficiency"
        elif p["platform"] == "Bugcrowd" and p["validation_days"] is not None:
            triage_info = f"{p['validation_days']:g}d validation time (Bugcrowd)"
        elif p["managed"]:
            triage_info = "Managed triage (response time not published)"
        else:
            triage_info = "Response time not published"
        kind_badge = " 🌐 Web3" if p.get("program_kind") == "web3" else ""
        payout_str = (
            f"Max: {p['max_payout']:,.0f} {p['currency']}"
            if (p["max_payout"] and p["max_payout"] > 0)
            else "Paid BBP"
        )

        days_seen = (
            (int(time.time()) - p["official_start_ts"]) // 86400
            if p["official_start_ts"]
            else None
        )
        new_indicator = (
            " 🆕 NEW PROGRAM"
            if days_seen is not None and days_seen < new_company_days
            else ""
        )

        print(
            f"[{i:02d}] ★ SCORE: {p['score']}/100 | {p['surface_tier']}"
            f"{kind_badge} | [{p['platform']}] {p['name']}{new_indicator}"
        )
        print(f"     🏢 Company Info : Policy: {p['url']}")
        if p["website"]:
            print(f"                       Website: {p['website']}")
        print(f"     ⚡ Triage Speed  : {triage_info} | 💰 Payout: {payout_str}")
        print(
            f"     🌐 Surface Scope : {p['assets']} In-Scope Assets ({p['wildcards']} Wildcards)"
            f" | Harbor: {p['safe_harbor']}"
        )
        if p["official_start_ts"]:
            started = datetime.fromtimestamp(p["official_start_ts"]).date()
            print(f"     🗓️ Program Start : {started} (official Bugcrowd metadata)")
        if p["new_assets"] > 0:
            print(
                f"     ✨ New Assets   : {p['new_assets']} in scope changes within "
                f"{new_asset_days} days (Bugcrowd history)"
            )
        if p["report_resolved_hours"] is not None:
            print(
                f"     📊 Report Metric: {p['report_resolved_hours']}h avg resolution (not report count)"
            )
        if p["rewarded_vulnerabilities"] is not None:
            print(
                f"     📊 Competition  : {p['rewarded_vulnerabilities']}"
                f" rewarded vulnerabilities (Bugcrowd lifetime total)"
            )
        if p["average_payout"] is not None:
            print(
                f"     💵 Avg Payout   : ${p['average_payout']:,.2f} historically (Bugcrowd)"
            )
        if p["official_scope_updated_ts"]:
            changed = datetime.fromtimestamp(p["official_scope_updated_ts"]).date()
            print(f"     🗓️ Scope Update : {changed} (Bugcrowd published history)")

        if args.show_assets:
            cur = conn.cursor()
            wildcard_samples = cur.execute(
                "SELECT asset_identifier FROM assets WHERE program_id=? AND is_wildcard=1 LIMIT 3",
                (p["id"],),
            ).fetchall()
            other_samples = cur.execute(
                "SELECT asset_identifier FROM assets WHERE program_id=? AND is_wildcard=0 LIMIT 3",
                (p["id"],),
            ).fetchall()

            samples = [w[0] for w in wildcard_samples] + [o[0] for o in other_samples]
            if samples:
                print(f"     🔎 Target Sample : {', '.join(samples[:4])}")
        print("-" * 88)


def scope_match(target, asset_identifier, is_wildcard):
    """Fail-closed scope match: True only when target is provably in scope.

    Non-wildcard assets require an exact (case-insensitive) match.
    '*.base' wildcards match proper subdomains of base only — never the apex
    itself and never lookalike suffixes ('evilexample.com' is NOT in scope).
    Glued wildcards ('*-prefix.host') match targets ending in the literal rest.
    Anything else (mid-string '*', empty inputs) returns False.
    """
    t = (target or "").strip().lower().rstrip(".")
    a = (asset_identifier or "").strip().lower().rstrip(".")
    if not t or not a:
        return False
    if not is_wildcard:
        return t == a
    if a.startswith("*."):
        base = a[2:]
        if not base or "*" in base:
            return False
        return t.endswith("." + base)
    if a.startswith("*"):
        rest = a[1:]
        if not rest or "*" in rest:
            return False
        return t.endswith(rest)
    return False


def clean_asset_identifier(value):
    """Strip one wildcard prefix and URL cruft for recon-tool piping."""
    val = (value or "").strip()
    if val.startswith("*."):
        val = val[2:]
    elif val.startswith("*"):
        val = val[1:]
    return val.lstrip(".").rstrip("/")


def cmd_check(args):
    conn = get_db()
    target = (args.domain or "").strip().lower()
    cur = conn.cursor()

    candidates = cur.execute(
        """
        SELECT p.platform, p.name, p.url, p.website, p.offers_bounties,
               a.asset_identifier, a.is_wildcard
        FROM assets a
        JOIN programs p ON a.program_id = p.id
    """
    ).fetchall()
    matches = [
        m
        for m in candidates
        if scope_match(target, m["asset_identifier"], m["is_wildcard"])
    ][:10]

    if matches:
        print(
            f"\n✅ [AUTHORIZED IN-SCOPE] '{target}' matches {len(matches)} program(s):"
        )
        for m in matches:
            bbp = "Paid BBP" if m["offers_bounties"] else "VDP"
            wild = "(Wildcard Match)" if m["is_wildcard"] else "(Direct Match)"
            print(f"  • [{m['platform']}] {m['name']} ({bbp})")
            print(f"    Asset Rule  : {m['asset_identifier']} {wild}")
            print(f"    Policy URL  : {m['url']}")
            if m["website"]:
                print(f"    Company Web : {m['website']}")
        print()
    else:
        print(
            f"\n❌ [NOT IN KNOWN SCOPE] '{target}' was not found in active public program scopes."
        )
        print("   CAUTION: Do not probe without explicit authorization!\n")


def cmd_export(args, config):
    results = evaluate_targets(config)
    limit = args.top or 30
    target_ids = [p["id"] for p in results[:limit]]

    conn = get_db()
    cur = conn.cursor()
    if not target_ids:
        return
    placeholders = ",".join("?" * len(target_ids))
    sql = (
        "SELECT DISTINCT asset_identifier FROM assets WHERE program_id IN ("  # nosec B608
        + placeholders
        + ")"
    )
    if args.wildcards_only:
        sql += " AND is_wildcard = 1"

    rows = cur.execute(sql, target_ids).fetchall()
    for r in rows:
        val = r[0].strip()
        if args.clean:
            val = clean_asset_identifier(val)
        print(val)


def apply_cli_overrides(config, args):
    """Apply CLI flags onto the loaded config (mutates and returns config).

    --new-companies / --new-assets imply their strict counterparts so the
    flags actually filter, as their help text promises.
    """
    fresh_cfg = config.setdefault("filters", {}).setdefault(
        "freshness_and_competition", {}
    )
    if getattr(args, "new_companies", False):
        fresh_cfg["prefer_new_companies"] = True
        fresh_cfg["strict_new_companies"] = True
        fresh_cfg["new_company_days"] = args.new_company_days
    if getattr(args, "new_assets", False):
        fresh_cfg["prefer_new_assets"] = True
        fresh_cfg["strict_new_assets"] = True
        fresh_cfg["new_asset_days"] = args.new_asset_days
    if getattr(args, "max_validation_days", None) is not None:
        config.setdefault("filters", {}).setdefault("fast_triage", {})[
            "max_validation_days"
        ] = args.max_validation_days
    if getattr(args, "max_rewarded_vulnerabilities", None) is not None:
        fresh_cfg["max_rewarded_vulnerabilities"] = args.max_rewarded_vulnerabilities
    if getattr(args, "require_measured_triage", False):
        config.setdefault("filters", {}).setdefault("fast_triage", {})[
            "require_measured_response_time"
        ] = True
    return config


def main():
    parser = argparse.ArgumentParser(
        description="Scan4Me: Precision Bug Bounty Target Engine"
    )
    sub = parser.add_subparsers(dest="command")

    p_sync = sub.add_parser("sync", help="Sync latest dataset from upstream feeds")
    p_sync.add_argument(
        "--offline",
        action="store_true",
        help="Use the last cached feed snapshot instead of refreshing it",
    )
    p_sync.add_argument(
        "--no-immunefi", action="store_true", help="Skip Immunefi live fetch"
    )
    p_sync.add_argument(
        "--no-sherlock",
        action="store_true",
        help="Skip Sherlock audit contests live fetch",
    )
    p_sync.add_argument(
        "--no-pd-programs",
        action="store_true",
        help="Skip ProjectDiscovery supplemental repo",
    )
    p_sync.add_argument("--no-federacy", action="store_true", help="Skip Federacy feed")

    p_enrich = sub.add_parser(
        "enrich",
        help="Fetch official Bugcrowd dates and public competition/validation metrics",
    )
    p_enrich.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Highest-paying Bugcrowd programs to enrich",
    )
    p_enrich.add_argument(
        "--delay", type=float, default=0.25, help="Seconds between program requests"
    )
    p_enrich.add_argument(
        "--handle", help="Enrich one Bugcrowd program by its public handle"
    )

    p_radar = sub.add_parser(
        "radar", help="List top targets filtered by surface area, speed, and cash"
    )
    p_radar.add_argument("--limit", type=int, default=20)
    p_radar.add_argument("--show-assets", action="store_true", default=True)
    p_radar.add_argument(
        "--no-show-assets",
        dest="show_assets",
        action="store_false",
        help="Hide per-program asset samples",
    )
    p_radar.add_argument(
        "--new-companies",
        action="store_true",
        help="Filter to Bugcrowd programs officially started recently",
    )
    p_radar.add_argument(
        "--new-company-days",
        type=int,
        default=90,
        help="Maximum age of official program start",
    )
    p_radar.add_argument(
        "--new-assets",
        action="store_true",
        help="Filter to Bugcrowd programs with recently added in-scope assets",
    )
    p_radar.add_argument(
        "--new-asset-days",
        type=int,
        default=30,
        help="Maximum age of official scope additions",
    )
    p_radar.add_argument(
        "--require-measured-triage",
        action="store_true",
        help="Exclude programs without a published response-time metric",
    )
    p_radar.add_argument(
        "--max-validation-days",
        type=float,
        help="Bugcrowd validation-time ceiling; requires public metadata",
    )
    p_radar.add_argument(
        "--max-rewarded-vulnerabilities",
        type=int,
        help="Bugcrowd historical reward-count ceiling (competition proxy, not open report count)",
    )

    sub.add_parser("keys", help="Show which API keys are configured (values masked)")

    p_check = sub.add_parser(
        "check", help="Verify if target is in authorized legal scope"
    )
    p_check.add_argument("domain", help="Target domain, e.g. api.target.com")

    p_export = sub.add_parser(
        "export",
        help="Export clean target list for httpx/subfinder from filtered programs",
    )
    p_export.add_argument("--top", type=int, default=30)
    p_export.add_argument("--wildcards-only", action="store_true")
    p_export.add_argument("--clean", action="store_true")
    p_export.add_argument(
        "--new-companies",
        action="store_true",
        help="Filter to Bugcrowd programs officially started recently",
    )
    p_export.add_argument(
        "--new-company-days",
        type=int,
        default=90,
        help="Maximum age of official program start",
    )
    p_export.add_argument(
        "--new-assets",
        action="store_true",
        help="Filter to Bugcrowd programs with recently added in-scope assets",
    )
    p_export.add_argument("--new-asset-days", type=int, default=30)
    p_export.add_argument(
        "--max-validation-days", type=float, help="Bugcrowd validation-time ceiling"
    )
    p_export.add_argument(
        "--max-rewarded-vulnerabilities",
        type=int,
        help="Bugcrowd competition-proxy ceiling",
    )

    args = parser.parse_args()

    config = load_config()
    apply_cli_overrides(config, args)

    if args.command == "sync":
        plat_override = {}
        if getattr(args, "no_immunefi", False):
            plat_override["immunefi"] = False
        if getattr(args, "no_sherlock", False):
            plat_override["sherlock"] = False
        if getattr(args, "no_pd_programs", False):
            plat_override["pd_programs"] = False
        if getattr(args, "no_federacy", False):
            plat_override["federacy"] = False
        merged_plat_cfg = {**config.get("platforms", {}), **plat_override}
        sync_data(
            refresh=not args.offline, platforms_cfg=merged_plat_cfg, config=config
        )
    elif args.command == "keys":
        creds = load_credentials(config)
        print("\n=== Scan4Me API Key Status ===\n")
        STATUS = {
            "hackerone": ("username", "api_token"),
            "bugcrowd": ("api_token",),
            "intigriti": ("api_token",),
            "yeswehack": ("api_token",),
            "federacy": ("api_token",),
            "immunefi": ("api_token",),
            "sherlock": ("api_token",),
            "hackenproof": ("api_token",),
            "bugbase": ("api_token",),
            "pd_programs": ("api_token",),
        }
        API_NOTES = {
            "hackerone": "✅ Active API (Basic auth)",
            "bugcrowd": "✅ Active API (Token header)",
            "intigriti": "✅ Active API (Bearer token)",
            "yeswehack": "✅ Active API (Bearer token)",
            "federacy": "⏳ No API yet — slot reserved",
            "immunefi": "⏳ No public API yet — slot reserved",
            "sherlock": "🌐 Public API (no auth needed)",
            "hackenproof": "⏳ No API detected — slot reserved",
            "bugbase": "⏳ No API yet — slot reserved",
            "pd_programs": "🌐 Public GitHub repo (no auth needed)",
        }
        for plat, fields in STATUS.items():
            plat_creds = creds.get(plat, {})
            configured = all(plat_creds.get(f) for f in fields)
            parts = []
            for f in fields:
                v = plat_creds.get(f)
                if v:
                    masked = v[:4] + "****" + v[-2:] if len(v) > 6 else "****"
                    parts.append(f"{f}={masked}")
                else:
                    parts.append(f"{f}=NOT SET")
            status_icon = "🔑" if configured else "○"
            note = API_NOTES.get(plat, "")
            print(f"  {status_icon} {plat:<12} {', '.join(parts)}")
            print(f"               {note}")
        print()
        print("Set keys in config.json api_keys section OR as env vars:")
        print("  HACKERONE_USERNAME, HACKERONE_API_TOKEN")
        print("  BUGCROWD_API_TOKEN, INTIGRITI_API_TOKEN, YESWEHACK_API_TOKEN")
        print("  (env vars take priority over config.json — never commit real keys)\n")
    elif args.command == "enrich":
        cmd_enrich(args)
    elif args.command == "radar":
        cmd_filter(args, config)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "export":
        cmd_export(args, config)
    else:
        p_radar.print_help()


if __name__ == "__main__":
    main()
