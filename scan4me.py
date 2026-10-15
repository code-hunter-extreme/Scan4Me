#!/usr/bin/env python3
"""
Scan4Me: Precision Bug Bounty Intelligence & Scope Targeter
Filters 47,000+ assets across HackerOne, Bugcrowd, Intigriti, and YesWeHack
for paid program discovery, scope size, available response-time measurements,
and first-observed changes in the imported feeds.
"""

import argparse
import base64
import ipaddress
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
# Immunefi: no public JSON API — but the bug-bounty board page embeds the full
# bounty list as escaped JSON (verified 2026-10-12: 169 bounties). No auth needed.
IMMUNEFI_BOUNTIES_URL = "https://immunefi.com/bug-bounty/"
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
# Priority: environment variable > config.json api_keys > trio central > None
# Never store real keys in config.json when using git — use env vars instead.
# New shared keys go in the trio central store, never in this repo.
# ─────────────────────────────────────────────────────────────────────────────
TRIO_KEYS_FILE = os.path.join(
    os.path.expanduser("~"), ".config", "trio", "keys.env"
)


def _read_trio_keys():
    """Read the trio central key store. Missing/unreadable → {}."""
    out = {}
    try:
        with open(TRIO_KEYS_FILE, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    if k and k not in out:
                        out[k] = v.strip().strip("\"'")
    except OSError:
        pass
    return out


def load_credentials(config=None):
    """Return a dict of per-platform credential dicts.

    For each platform the returned dict has whatever keys that platform needs
    (e.g. {'username': '...', 'api_token': '...'} for HackerOne).
    A key is absent or None when not configured — callers must check before use.

    Env var names follow the pattern documented in config.json api_keys._env.
    Env vars always override config.json values so real secrets stay out of files.
    """
    cfg_keys = (config or {}).get("api_keys", {})
    trio_keys = _read_trio_keys()

    def _get(platform, field, env_var):
        """env var > config.json > trio central > None"""
        env_val = os.environ.get(env_var, "").strip()
        if env_val:
            return env_val
        cfg_val = (cfg_keys.get(platform) or {}).get(field)
        if cfg_val:
            import warnings
            warnings.warn(
                f"API key for {platform}.{field} loaded from config.json — "
                "never commit config.json with real keys (git-tracked secret risk).",
                stacklevel=3,
            )
            return cfg_val
        return trio_keys.get(env_var) or None

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


def _h1_in_scope(structured_scopes):
    """Submission-eligible HackerOne scopes, preserving the eligibility and
    restriction fields (#15). Dropping eligible_for_bounty/instruction/
    max_severity here makes _eligibility_of default them to eligible, so a
    submit-but-no-bounty asset would wrongly enter the paid target list and
    its restrictions would vanish. Keep them alongside identifier + type.
    """
    out = []
    for s in structured_scopes or []:
        if not s.get("eligible_for_submission"):
            continue
        out.append(
            {
                "asset_identifier": s.get("asset_identifier", ""),
                "asset_type": s.get("asset_type", "URL"),
                "eligible_for_bounty": s.get("eligible_for_bounty", True),
                "eligible_for_submission": s.get("eligible_for_submission", True),
                "instruction": s.get("instruction") or "",
                "max_severity": s.get("max_severity") or "",
            }
        )
    return out


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
                        "in_scope": _h1_in_scope(attrs.get("structured_scopes", []))
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
                                "type": s.get("type", "web"),
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
        "triage_speed": 0.35,
        "attack_surface_size": 0.30,
        "freshness_and_low_saturation": 0.20,
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
                eligible_for_bounty INTEGER DEFAULT 1,
                eligible_for_submission INTEGER DEFAULT 1,
                instruction TEXT DEFAULT '',
                max_severity TEXT DEFAULT '',
                first_seen_timestamp INTEGER DEFAULT 0,
                deleted_timestamp INTEGER DEFAULT 0,
                FOREIGN KEY (program_id) REFERENCES programs(id)
            );

            CREATE TABLE oos_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER,
                asset_identifier TEXT NOT NULL,
                asset_type TEXT,
                is_wildcard BOOLEAN DEFAULT 0,
                first_seen_timestamp INTEGER DEFAULT 0,
                deleted_timestamp INTEGER DEFAULT 0,
                FOREIGN KEY (program_id) REFERENCES programs(id)
            );

            CREATE TABLE contests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                name TEXT NOT NULL,
                handle TEXT,
                url TEXT,
                offers_bounties BOOLEAN DEFAULT 0,
                max_payout REAL DEFAULT 0,
                currency TEXT DEFAULT 'USD',
                status TEXT,
                starts_at TEXT,
                ends_at TEXT,
                description TEXT,
                first_seen_timestamp INTEGER DEFAULT 0,
                last_updated_timestamp INTEGER DEFAULT 0,
                UNIQUE(platform, handle)
            );

            CREATE INDEX idx_asset_identifier ON assets(asset_identifier);
            CREATE INDEX idx_asset_program_live ON assets(program_id, deleted_timestamp);
            CREATE INDEX idx_oos_program_live ON oos_assets(program_id, deleted_timestamp);
            CREATE INDEX idx_contest_platform ON contests(platform);
            CREATE INDEX idx_contest_first_seen ON contests(first_seen_timestamp);
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
    for column, definition in (
        ("eligible_for_bounty", "INTEGER DEFAULT 1"),
        ("eligible_for_submission", "INTEGER DEFAULT 1"),
        ("instruction", "TEXT DEFAULT ''"),
        ("max_severity", "TEXT DEFAULT ''"),
        ("deleted_timestamp", "INTEGER DEFAULT 0"),
    ):
        if column not in asset_cols:
            cur.execute(f"ALTER TABLE assets ADD COLUMN {column} {definition}")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS oos_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id INTEGER,
            asset_identifier TEXT NOT NULL,
            asset_type TEXT,
            is_wildcard BOOLEAN DEFAULT 0,
            first_seen_timestamp INTEGER DEFAULT 0,
            deleted_timestamp INTEGER DEFAULT 0,
            FOREIGN KEY (program_id) REFERENCES programs(id)
        )
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_program_live "
        "ON assets(program_id, deleted_timestamp)"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_oos_program_live "
        "ON oos_assets(program_id, deleted_timestamp)"
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS contests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT NOT NULL,
            name TEXT NOT NULL,
            handle TEXT,
            url TEXT,
            offers_bounties BOOLEAN DEFAULT 0,
            max_payout REAL DEFAULT 0,
            currency TEXT DEFAULT 'USD',
            status TEXT,
            starts_at TEXT,
            ends_at TEXT,
            description TEXT,
            first_seen_timestamp INTEGER DEFAULT 0,
            last_updated_timestamp INTEGER DEFAULT 0,
            UNIQUE(platform, handle)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_contest_platform ON contests(platform)")
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_contest_first_seen "
        "ON contests(first_seen_timestamp)"
    )

    # P6: Sherlock audit contests are not bug-bounty programs. Move any legacy
    # contest rows out of programs into contests. Idempotent: once moved, no
    # platform='Sherlock' rows remain in programs and this is a no-op.
    for row in cur.execute(
        """SELECT name, handle, url, offers_bounties, max_payout, currency,
           first_seen_timestamp, last_updated_timestamp
           FROM programs WHERE platform='Sherlock'"""
    ).fetchall():
        cur.execute(
            """
            INSERT INTO contests (
                platform, name, handle, url, offers_bounties, max_payout,
                currency, first_seen_timestamp, last_updated_timestamp
            ) VALUES ('Sherlock', ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(platform, handle) DO UPDATE SET
                name=excluded.name, url=excluded.url,
                offers_bounties=excluded.offers_bounties,
                max_payout=excluded.max_payout,
                currency=excluded.currency,
                last_updated_timestamp=excluded.last_updated_timestamp
            """,
            tuple(row),
        )
    cur.execute("DELETE FROM programs WHERE platform='Sherlock'")

    conn.commit()


def ensure_schema(conn):
    """Idempotent: create + migrate schema so read paths see new columns.

    Write paths (sync) already init+migrate; read paths (radar/check/export)
    call this so tombstone/eligibility filters never hit a stale schema.
    """
    init_db(conn)
    migrate_db(conn)


def _eligibility_of(target):
    """(bounty, submission, instruction, severity) for an asset dict.

    Feeds without eligibility keys (Bugcrowd/Intigriti/YWH/...) default to
    eligible — unknown means "no signal", never "forbidden".
    """
    bounty = target.get("eligible_for_bounty", True)
    submission = target.get("eligible_for_submission", True)
    instruction = target.get("instruction") or ""
    severity = target.get("max_severity") or ""
    return (
        0 if bounty is False or bounty == 0 else 1,
        0 if submission is False or submission == 0 else 1,
        str(instruction),
        str(severity),
    )


# ── Asset normalizer (#4): canonical types + identifiers at ingest ──────────────
# Raw feeds use 15+ case/source-variant type strings and verbatim identifiers
# (scheme-prefixed wildcards, free-text sentences, bare words like "all").
# Everything is canonicalized here, once, before storage; match-time code
# (scope_match, clean_asset_identifier, the Oracle bridge) applies the same
# host-stripping so old verbatim rows still match until the next sync.
CANON_ASSET_TYPES = frozenset(
    {
        "url",
        "wildcard",
        "cidr",
        "api",
        "ios_app",
        "android_app",
        "smart_contract",
        "source_code",
        "executable",
        "other",
    }
)

_CANON_TYPE_ALIASES = {
    # url-ish
    "url": "url",
    "website": "url",
    "web": "url",
    "web_application": "url",
    "webapplication": "url",
    "web_app": "url",
    "webapp": "url",
    "domain": "url",
    "subdomain": "url",
    "host": "url",
    # wildcard
    "wildcard": "wildcard",
    # ip-ish (single literals and ranges both ride as cidr: non-DNS scope)
    "cidr": "cidr",
    "ip": "cidr",
    "ip_address": "cidr",
    "ipaddress": "cidr",
    "iprange": "cidr",
    "ip_range": "cidr",
    "network": "cidr",
    # api
    "api": "api",
    # mobile
    "android": "android_app",
    "android_app": "android_app",
    "google_play": "android_app",
    "google_play_app_id": "android_app",
    "googleplay_app_id": "android_app",
    "ios": "ios_app",
    "ios_app": "ios_app",
    "apple": "ios_app",
    "apple_store_app_id": "ios_app",
    "applestore_app_id": "ios_app",
    "mobile": "other",
    # web3
    "smartcontract": "smart_contract",
    "smart_contract": "smart_contract",
    "contract": "smart_contract",
    "blockchain": "smart_contract",
    # source
    "source_code": "source_code",
    "sourcecode": "source_code",
    "github": "source_code",
    "repository": "source_code",
    "repo": "source_code",
    "git": "source_code",
    # binaries
    "executable": "executable",
    "downloadable_executables": "executable",
    "downloadable": "executable",
    "binary": "executable",
    "download": "executable",
    # fallback
    "other": "other",
    "unknown": "other",
    "": "other",
}


def canonicalize_asset_type(raw_type):
    """Map any raw feed type string to the canonical enum (default: other)."""
    key = str(raw_type or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _CANON_TYPE_ALIASES.get(key, "other")


def _strip_host(value):
    """Lowercased bare host from a URL-ish identifier (no scheme/path/port)."""
    text = (value or "").strip().lower().rstrip(".")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/")[0].split("@")[-1].strip().rstrip(".")
    if text.startswith("[") and "]" in text:  # IPv6 literal
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1 and "*" not in text:  # host:port
        text = text.split(":")[0]
    return text.strip().rstrip(".")


def canonicalize_asset(identifier, raw_type):
    """Canonicalize one scope identifier + type.

    Returns ``(identifier, asset_type, is_wildcard, ok)``. ``ok`` is False
    for non-host junk (free-text sentences, bare words like Intigriti's
    ``"all"`` endpoint) which callers must reject, never store as scope.
    CIDRs, IPs and app IDs are kept verbatim (lowercased) with their enum
    type — they are scope, just not DNS scope.
    """
    raw = (identifier or "").strip()
    if not raw:
        return "", "other", 0, False
    atype = canonicalize_asset_type(raw_type)
    lowered = raw.lower().rstrip(".")

    # IP literals / ranges: scope, not DNS — keep verbatim, never host-strip.
    # A "/" alone is not a CIDR (URLs have paths): require ipaddress to agree.
    token = raw.split()[0] if raw.split() else ""
    if " " in raw:
        return "", "other", 0, False
    if "/" in token or atype == "cidr":
        try:
            return str(ipaddress.ip_address(token)), "cidr", 0, True
        except ValueError:
            pass
        try:
            return str(ipaddress.ip_network(token, strict=False)), "cidr", 0, True
        except ValueError:
            pass
        if "/" in token:
            pass  # URL path, not a range — fall through to host stripping.
        elif atype == "cidr":
            return "", "other", 0, False  # feed claims CIDR, value unparseable.
    # App IDs / package names / store numerics: keep verbatim.
    if atype in ("ios_app", "android_app"):
        if " " in raw:
            return "", "other", 0, False
        return lowered, atype, 0, True

    host = _strip_host(raw)
    if not host or " " in host:
        return "", "other", 0, False
    is_wildcard = 0
    if "*" in host:
        star, _, rest = host.partition("*")
        # Only leading-star forms are matchable scope (*.base, *-glued).
        if star not in ("",):
            return "", "other", 0, False
        rest = rest.lstrip(".")
        if not rest or "*" in rest or " " in rest:
            return "", "other", 0, False
        # Glued form (*-prefix.host) keeps its literal post-star shape.
        host = "*." + rest if not rest.startswith("-") else "*" + rest
        is_wildcard = 1
        atype = "wildcard"
    else:
        # DNS-ish scope needs a dot (rejects "all" and other bare words);
        # localhost is the one legitimate single-label host.
        if "." not in host and host != "localhost":
            return "", "other", 0, False
    if atype == "wildcard" and not is_wildcard:
        # Feed claims wildcard but the identifier has no star: typeless host.
        atype = "url"
    return host, atype, is_wildcard, True


def sync_assets(cur, program_id, targets, identifier_key, type_key, now_ts, stats=None):
    """Reconcile a program's current scope while retaining first-observed times.

    Vanished assets are TOMBSTONED (deleted_timestamp set), never hard-DELETEd:
    a truncated feed or upstream schema change degrades to stale scope instead
    of destroying first-seen evidence, and reappearing assets resurrect with
    their original first_seen_timestamp intact. Live-scope queries must filter
    ``deleted_timestamp=0``. Per-asset eligibility flags are stored verbatim.
    Identifiers + types are canonicalized at ingest (#4); rejected junk is
    counted into ``stats["rejected"]`` when a stats dict is passed.
    """
    current_assets = {}
    for target in targets:
        if not isinstance(target, dict):
            continue
        raw_identifier = str(target.get(identifier_key) or "").strip()
        target_name = str(target.get("name") or "").strip().lower()
        if (
            "temporarily out of scope" in raw_identifier.lower()
            or "temporarily out of scope" in target_name
        ):
            continue
        identifier, asset_type, is_wildcard, ok = canonicalize_asset(
            raw_identifier, target.get(type_key, "URL")
        )
        if not ok or not identifier:
            if stats is not None:
                stats["rejected"] = stats.get("rejected", 0) + 1
            continue
        current_assets[identifier] = (
            asset_type,
            is_wildcard,
            *_eligibility_of(target),
        )

    # Case-insensitive lookup: the canonicalizer lowercases, so verbatim
    # legacy rows still match and keep their original first_seen evidence.
    existing_assets = {}
    for row in cur.execute(
        "SELECT id, asset_identifier, first_seen_timestamp, deleted_timestamp"
        " FROM assets WHERE program_id=?",
        (program_id,),
    ).fetchall():
        existing_assets.setdefault(
            (row["asset_identifier"] or "").strip().lower(), row
        )
    for identifier, spec in current_assets.items():
        asset_type, is_wildcard, bounty, submission, instruction, severity = spec
        existing = existing_assets.get(identifier.strip().lower())
        if existing:
            cur.execute(
                """UPDATE assets SET asset_identifier=?, asset_type=?, is_wildcard=?,
                   eligible_for_bounty=?, eligible_for_submission=?,
                   instruction=?, max_severity=?, deleted_timestamp=0 WHERE id=?""",
                (
                    identifier,
                    asset_type,
                    is_wildcard,
                    bounty,
                    submission,
                    instruction,
                    severity,
                    existing["id"],
                ),
            )
        else:
            cur.execute(
                """INSERT INTO assets
                   (program_id, asset_identifier, asset_type, is_wildcard,
                    eligible_for_bounty, eligible_for_submission,
                    instruction, max_severity,
                    first_seen_timestamp, deleted_timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                (
                    program_id,
                    identifier,
                    asset_type,
                    is_wildcard,
                    bounty,
                    submission,
                    instruction,
                    severity,
                    now_ts,
                ),
            )

    current_lower = {identifier.strip().lower() for identifier in current_assets}
    stale_ids = [
        row["id"]
        for lowered, row in existing_assets.items()
        if lowered not in current_lower and not (row["deleted_timestamp"] or 0)
    ]
    if stale_ids:
        cur.executemany(
            "UPDATE assets SET deleted_timestamp=? WHERE id=?",
            ((now_ts, asset_id) for asset_id in stale_ids),
        )


def sync_oos_assets(cur, program_id, targets, identifier_key, type_key, now_ts, stats=None):
    """Reconcile a program's OUT-OF-SCOPE identifiers (tombstoned, like scope).

    Only call when the feed entry actually carries out-of-scope data — feeds
    without the key must leave previously synced OOS rows untouched.
    Canonicalized at ingest like scope (#4); rejects counted into stats.
    """
    current_oos = {}
    for target in targets:
        if not isinstance(target, dict):
            continue
        raw_identifier = str(target.get(identifier_key) or "").strip()
        identifier, asset_type, is_wildcard, ok = canonicalize_asset(
            raw_identifier, target.get(type_key, "URL")
        )
        if not ok or not identifier:
            if stats is not None:
                stats["rejected"] = stats.get("rejected", 0) + 1
            continue
        current_oos[identifier] = (asset_type, is_wildcard)

    existing_oos = {}
    for row in cur.execute(
        "SELECT id, asset_identifier, first_seen_timestamp, deleted_timestamp"
        " FROM oos_assets WHERE program_id=?",
        (program_id,),
    ).fetchall():
        existing_oos.setdefault((row["asset_identifier"] or "").strip().lower(), row)
    for identifier, (asset_type, is_wildcard) in current_oos.items():
        existing = existing_oos.get(identifier.strip().lower())
        if existing:
            cur.execute(
                """UPDATE oos_assets SET asset_identifier=?, asset_type=?, is_wildcard=?,
                   deleted_timestamp=0 WHERE id=?""",
                (identifier, asset_type, is_wildcard, existing["id"]),
            )
        else:
            cur.execute(
                """INSERT INTO oos_assets
                   (program_id, asset_identifier, asset_type, is_wildcard,
                    first_seen_timestamp, deleted_timestamp)
                   VALUES (?, ?, ?, ?, ?, 0)""",
                (program_id, identifier, asset_type, is_wildcard, now_ts),
            )

    current_lower = {identifier.strip().lower() for identifier in current_oos}
    stale_ids = [
        row["id"]
        for lowered, row in existing_oos.items()
        if lowered not in current_lower and not (row["deleted_timestamp"] or 0)
    ]
    if stale_ids:
        cur.executemany(
            "UPDATE oos_assets SET deleted_timestamp=? WHERE id=?",
            ((now_ts, asset_id) for asset_id in stale_ids),
        )


def _sync_program_scope(
    cur, prog_id, entry, identifier_key, type_key, now_ts, stats=None
):
    """Sync in-scope + out-of-scope targets for one feed entry.

    Each side syncs only when its key is present: feeds that structurally
    omit out-of-scope (e.g. authenticated fetchers) must not wipe previously
    synced OOS rows, and a malformed entry missing scope must not wipe scope.
    Absent sides are left untouched; present-but-empty sides tombstone.
    Normalizer rejects accumulate into ``stats`` when passed.
    """
    targets = entry.get("targets") if isinstance(entry, dict) else None
    if not isinstance(targets, dict):
        return
    if "in_scope" in targets:
        sync_assets(
            cur,
            prog_id,
            targets.get("in_scope") or [],
            identifier_key,
            type_key,
            now_ts,
            stats=stats,
        )
    if "out_of_scope" in targets:
        sync_oos_assets(
            cur,
            prog_id,
            targets.get("out_of_scope") or [],
            identifier_key,
            type_key,
            now_ts,
            stats=stats,
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
        "SELECT id, asset_identifier FROM assets"
        " WHERE program_id=? AND deleted_timestamp=0",
        (program_id,)
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


def _js_unescape_once(text):
    """Decode one layer of JS string escapes (\\", \\\\, \\n, \\/, \\uXXXX)."""
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "n":
                out.append("\n")
                i += 2
            elif nxt == "t":
                out.append("\t")
                i += 2
            elif nxt == "r":
                out.append("\r")
                i += 2
            elif nxt in '"\\/':
                out.append(nxt)
                i += 2
            elif nxt == "u" and i + 5 < len(text):
                hex_start = i + 2
                hex_end = i + 6
                try:
                    out.append(chr(int(text[hex_start:hex_end], 16)))
                    i += 6
                except ValueError:
                    out.append(ch)
                    i += 1
            else:
                out.append(ch)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _extract_bracketed_array(text, start):
    """Return the raw [...] slice starting at index start (escape-aware).

    Returns None when no balanced closing bracket is found.
    """
    depth = 0
    in_str = False
    esc = False
    for j in range(start, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                end = j + 1
                return text[start:end]
    return None


def _parse_immunefi_page(html):
    """Extract the embedded bounty list from the Immunefi board page.

    The page embeds React Flight data containing `"bounties":[...]` with one
    record per program (project, slug, url, maxBounty, pausedAt, inviteOnly).
    Returns the raw record list, or [] when the payload is absent/unparseable.
    """
    key = '"bounties\\":['
    at = html.find(key)
    if at < 0:
        return []
    raw = _extract_bracketed_array(html, at + len(key) - 1)
    if not raw:
        return []
    try:
        decoded = _js_unescape_once(_js_unescape_once(raw))
        records, _ = json.JSONDecoder().raw_decode(decoded)
    except ValueError:
        return []
    return records if isinstance(records, list) else []


def _normalize_immunefi_record(item):
    """Normalize one embedded Immunefi bounty record to the program schema.

    Returns None when the record has no usable project name. Paused and
    invite-only programs are kept but marked offers_bounties=False since they
    are not actionable for a public hunter. Per-program scope lives on the
    detail pages, so assets is always [] (see P5 live-sync recipe).
    """
    name = item.get("project") or item.get("name") or ""
    if not name:
        return None
    slug = item.get("slug") or ""
    handle = slug or name.lower().replace(" ", "-").replace(".", "-")
    path = item.get("url") or f"/bug-bounty/{handle}/"
    url = path if path.startswith("http") else f"https://immunefi.com{path}"
    try:
        max_p = float(item.get("maxBounty") or 0)
    except (ValueError, TypeError):
        max_p = 0.0
    actionable = item.get("pausedAt") is None and not item.get("inviteOnly", False)
    return {
        "name": name,
        "handle": handle,
        "url": url,
        "max_payout": max_p,
        "currency": "USD",
        "offers_bounties": bool(max_p > 0 and actionable),
        "assets": [],
    }


def _fetch_immunefi_programs(url=None):
    """Fetch the Immunefi bug bounty list from their public board page.

    The board embeds the full bounty list as escaped JSON — no API key needed.
    Returns [] on any fetch/parse failure (soft-fail, like other live feeds).
    """
    url = url or IMMUNEFI_BOUNTIES_URL
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Scan4Me public bug-bounty metadata sync"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
            html = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Immunefi fetch skipped: {e}")
        return []

    programs = []
    for item in _parse_immunefi_page(html):
        if not isinstance(item, dict):
            continue
        norm = _normalize_immunefi_record(item)
        if norm:
            programs.append(norm)
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


def _contest_ts(value):
    """Normalize a Sherlock contest timestamp for TEXT storage (int/ISO/None)."""
    if value is None or isinstance(value, str):
        return value
    return str(value)


def _load_pd_programs(repo_dir):
    """Load the program list from a projectdiscovery/public-bugbounty-programs checkout.

    Prefers the generated dist/data.json; falls back to src/data.yaml.
    Returns [] when neither exists or neither parses (soft-fail).
    """
    repo_dir = Path(repo_dir)
    json_file = repo_dir / "dist" / "data.json"
    if json_file.is_file():
        try:
            with open(json_file, encoding="utf-8") as f:
                raw = json.load(f)
            programs = raw if isinstance(raw, list) else raw.get("programs", [])
            return programs if isinstance(programs, list) else []
        except (OSError, UnicodeDecodeError, ValueError) as e:
            print(f"[!] ProjectDiscovery dist/data.json parse error: {e}")
    yaml_file = repo_dir / "src" / "data.yaml"
    if yaml_file.is_file():
        try:
            import yaml  # type: ignore[import-untyped]  # lazy: optional dep
        except ImportError:
            print("[*] ProjectDiscovery: PyYAML missing, cannot read src/data.yaml.")
            return []
        try:
            with open(yaml_file, encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            programs = raw if isinstance(raw, list) else (raw or {}).get("programs", [])
            return programs if isinstance(programs, list) else []
        except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as e:
            print(f"[!] ProjectDiscovery src/data.yaml parse error: {e}")
    return []


def _upstream_sha(git_bin, repo_dir):
    """Short upstream commit hash, or an explicit unknown marker (never fake)."""
    if not git_bin or not (repo_dir / ".git").exists():
        return "unknown (no upstream checkout)"
    try:
        proc = subprocess.run(
            [git_bin, "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
            check=True,
            shell=False,  # nosec B603
            capture_output=True,
            text=True,
        )
        sha = (proc.stdout or "").strip()
        return sha or "unknown (rev-parse empty)"
    except (subprocess.CalledProcessError, OSError) as e:
        return f"unknown (rev-parse failed: {e})"


def _set_meta(cur, key, value):
    cur.execute(
        "INSERT INTO sync_metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def _row_last_updated(existing, now_ts, refresh_ok):
    """last_updated for an upsert: new rows stamp now; on a failed refresh
    existing rows keep their stamp (no freshness bump on stale data)."""
    if existing is None:
        return now_ts
    if refresh_ok:
        return now_ts
    try:
        return existing[2] if existing[2] is not None else now_ts
    except (IndexError, TypeError):
        return now_ts


def _platform_status(enabled, data, source, auth_used=False):
    """sync_metadata status entry for one platform feed (a staleness tripwire)."""
    if not enabled:
        return {"status": "skipped", "count": 0, "source": None}
    if not data:
        if auth_used:
            return {
                "status": "auth_empty",
                "count": 0,
                "source": source,
                "note": "authenticated fetch returned no rows;"
                " old rows left untouched",
            }
        return {"status": "empty", "count": 0, "source": source}
    return {"status": "ok", "count": len(data), "source": source}


def _tombstone_withdrawn_programs(cur, platform, seen_handles, now_ts):
    """Tombstone the live assets of ``platform`` programs absent from a feed.

    When a program disappears from a complete, successful fetch it has closed
    or withdrawn its scope; its still-live assets must stop being treated as
    authorized (checks/exports/ranking all filter on ``deleted_timestamp=0``).
    The caller must invoke this ONLY after a complete successful fetch — never
    on a failed, partial, or empty one — so a transient outage cannot wipe
    scope. Returns the number of programs tombstoned.
    """
    withdrawn = [
        row["id"]
        for row in cur.execute(
            "SELECT id, handle FROM programs WHERE platform=?", (platform,)
        ).fetchall()
        if (row["handle"] or "") not in seen_handles
    ]
    for pid in withdrawn:
        cur.execute(
            "UPDATE assets SET deleted_timestamp=? "
            "WHERE program_id=? AND deleted_timestamp=0",
            (now_ts, pid),
        )
        cur.execute(
            "UPDATE oos_assets SET deleted_timestamp=? "
            "WHERE program_id=? AND deleted_timestamp=0",
            (now_ts, pid),
        )
    return len(withdrawn)


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
      Immunefi  — bug-bounty board page (embedded JSON, web3)
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
    refresh_ok = True
    refresh_error = ""
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
                refresh_ok = False
                refresh_error = str(e)
                print(f"[!] Feed repo pull failed ({e}) — using cached snapshot.")
                print(
                    "[!] Stale snapshot: existing rows keep their"
                    " last_updated_timestamp (no freshness bump)."
                )
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
    upstream_sha = _upstream_sha(git_bin, repo_dir)

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
    ensure_schema(conn)

    cur = conn.cursor()
    baseline_complete = cur.execute(
        "SELECT value FROM sync_metadata WHERE key='baseline_complete'"
    ).fetchone()
    is_baseline_sync = baseline_complete is None

    print(f"[*] Ingesting and normalizing targets from {local_data_dir}...")
    now_ts = int(time.time())

    platform_status = {}
    ingest_stats = {}  # per-platform normalizer reject counts (tripwire)

    # 1. HackerOne — authenticated API when keys present, public feed fallback
    # NOTE: there is NO fallback from a failed authenticated fetch to the
    # public feed — an auth failure yields an empty list and old rows linger
    # untouched (recorded as auth_empty in sync_metadata below).
    h1_creds = creds.get("hackerone", {})
    h1_username = h1_creds.get("username")
    h1_token = h1_creds.get("api_token")
    # `refresh` gates every network call: an offline run (refresh=False) must
    # use cached feed data only and never hit an authenticated API, matching the
    # immunefi/sherlock/pd_programs `*_attempted` flags below.
    h1_auth_used = bool(
        refresh and h1_username and h1_token and platforms_cfg.get("hackerone", True)
    )
    if h1_auth_used:
        print(
            "[*] HackerOne: API key found — using authenticated feed (includes private invites)."
        )
        h1_data = _fetch_h1_authenticated(h1_username, h1_token)
        h1_source = "authenticated"
    else:
        if bool(h1_username) != bool(h1_token):
            # Exactly one of username/token supplied — genuinely incomplete.
            print(
                "[!] HackerOne: partial credentials (need both username + api_token) — using public feed."
            )
        elif h1_username and h1_token and not refresh:
            # Complete credentials, skipped only because this is an offline run —
            # not a credential problem; don't send the user chasing one.
            print(
                "[*] HackerOne: offline mode — authenticated fetch skipped, using cached public feed."
            )
        h1_file = local_data_dir / "hackerone_data.json"
        if h1_file.exists():
            with open(h1_file, encoding="utf-8") as f:
                h1_data = json.load(f)
        else:
            h1_data = []
        h1_source = "public-file"

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
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("HackerOne", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

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
                        last_upd,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("HackerOne", handle),
                ).fetchone()[0]
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "asset_identifier",
                    "asset_type",
                    now_ts,
                    stats=ingest_stats.setdefault("hackerone", {}),
                )
        # Withdrawn-program reconciliation: only after a complete
        # successful fetch (refresh and refresh_ok). Programs absent from
        # this full feed have closed/withdrawn scope -> tombstone their assets.
        if refresh and refresh_ok:
            _seen = {row.get("handle") for row in h1_data if row.get("handle")}
            with conn:
                _tombstone_withdrawn_programs(cur, "HackerOne", _seen, now_ts)
        print(f"[+] HackerOne indexed: {len(h1_data)} programs.")
    platform_status["hackerone"] = _platform_status(
        platforms_cfg.get("hackerone", True), h1_data, h1_source, h1_auth_used
    )

    # 2. Bugcrowd — authenticated API when key present, public feed fallback
    bc_token = creds.get("bugcrowd", {}).get("api_token")
    bc_auth_used = bool(refresh and bc_token and platforms_cfg.get("bugcrowd", True))
    if bc_auth_used:
        print(
            "[*] Bugcrowd: API key found — using authenticated feed (includes private programs)."
        )
        bc_data = _fetch_bugcrowd_authenticated(bc_token)
        bc_source = "authenticated"
    else:
        bc_file = local_data_dir / "bugcrowd_data.json"
        if bc_file.exists():
            with open(bc_file, encoding="utf-8") as f:
                bc_data = json.load(f)
        else:
            bc_data = []
        bc_source = "public-file"

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
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("Bugcrowd", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

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
                        last_upd,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("Bugcrowd", handle),
                ).fetchone()[0]
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "target",
                    "type",
                    now_ts,
                    stats=ingest_stats.setdefault("bugcrowd", {}),
                )
        # Withdrawn-program reconciliation: only after a complete
        # successful fetch (refresh and refresh_ok). Programs absent from
        # this full feed have closed/withdrawn scope -> tombstone their assets.
        if refresh and refresh_ok:
            _seen = {row.get("handle") for row in bc_data if row.get("handle")}
            with conn:
                _tombstone_withdrawn_programs(cur, "Bugcrowd", _seen, now_ts)
        print(f"[+] Bugcrowd indexed: {len(bc_data)} programs.")
    platform_status["bugcrowd"] = _platform_status(
        platforms_cfg.get("bugcrowd", True), bc_data, bc_source, bc_auth_used
    )

    # 3. Intigriti — authenticated API when key present, public feed fallback
    inti_token = creds.get("intigriti", {}).get("api_token")
    inti_auth_used = bool(refresh and inti_token and platforms_cfg.get("intigriti", True))
    if inti_auth_used:
        print(
            "[*] Intigriti: API key found — using authenticated feed (includes private programs)."
        )
        inti_data = _fetch_intigriti_authenticated(inti_token)
        inti_source = "authenticated"
    else:
        inti_file = local_data_dir / "intigriti_data.json"
        if inti_file.exists():
            with open(inti_file, encoding="utf-8") as f:
                inti_data = json.load(f)
        else:
            inti_data = []
        inti_source = "public-file"

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
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("Intigriti", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

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
                        last_upd,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("Intigriti", handle),
                ).fetchone()[0]
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "endpoint",
                    "type",
                    now_ts,
                    stats=ingest_stats.setdefault("intigriti", {}),
                )
        # Withdrawn-program reconciliation: only after a complete
        # successful fetch (refresh and refresh_ok). Programs absent from
        # this full feed have closed/withdrawn scope -> tombstone their assets.
        if refresh and refresh_ok:
            _seen = {row.get("handle") for row in inti_data if row.get("handle")}
            with conn:
                _tombstone_withdrawn_programs(cur, "Intigriti", _seen, now_ts)
        print(f"[+] Intigriti indexed: {len(inti_data)} programs.")
    platform_status["intigriti"] = _platform_status(
        platforms_cfg.get("intigriti", True), inti_data, inti_source, inti_auth_used
    )

    # 4. YesWeHack — authenticated API when key present, public feed fallback
    ywh_token = creds.get("yeswehack", {}).get("api_token")
    ywh_auth_used = bool(refresh and ywh_token and platforms_cfg.get("yeswehack", True))
    if ywh_auth_used:
        print(
            "[*] YesWeHack: API key found — using authenticated feed (includes private programs)."
        )
        ywh_data = _fetch_yeswehack_authenticated(ywh_token)
        ywh_source = "authenticated"
    else:
        ywh_file = local_data_dir / "yeswehack_data.json"
        if ywh_file.exists():
            with open(ywh_file, encoding="utf-8") as f:
                ywh_data = json.load(f)
        else:
            ywh_data = []
        ywh_source = "public-file"

    if ywh_data and platforms_cfg.get("yeswehack", True):
        with conn:
            for p in ywh_data:
                name = p.get("name", "Unknown")
                handle = str(p.get("id"))
                max_val = float(p.get("max_bounty", 0) or 0)
                offers_bounty = max_val > 0
                managed = bool(p.get("managed"))

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("YesWeHack", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

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
                        last_upd,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("YesWeHack", handle),
                ).fetchone()[0]
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "target",
                    "type",
                    now_ts,
                    stats=ingest_stats.setdefault("yeswehack", {}),
                )
        # Withdrawn-program reconciliation: only after a complete
        # successful fetch (refresh and refresh_ok). Programs absent from
        # this full feed have closed/withdrawn scope -> tombstone their assets.
        if refresh and refresh_ok:
            _seen = {row.get("handle") for row in ywh_data if row.get("handle")}
            with conn:
                _tombstone_withdrawn_programs(cur, "YesWeHack", _seen, now_ts)
        print(f"[+] YesWeHack indexed: {len(ywh_data)} programs.")
    platform_status["yeswehack"] = _platform_status(
        platforms_cfg.get("yeswehack", True), ywh_data, ywh_source, ywh_auth_used
    )

    # 5. Federacy (optional — present in arkadiyt repo but tiny; skip when absent)
    fed_file = local_data_dir / "federacy_data.json"
    fed_data = []
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
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("Federacy", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

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
                    ("Federacy", name, handle, url, offers_bounty, first_seen, last_upd),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("Federacy", handle),
                ).fetchone()[0]
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "target",
                    "type",
                    now_ts,
                    stats=ingest_stats.setdefault("federacy", {}),
                )
        print(f"[+] Federacy indexed: {len(fed_data)} programs.")
    elif not fed_file.exists():
        print("[*] Federacy feed not found in repo — skipping.")
    platform_status["federacy"] = _platform_status(
        platforms_cfg.get("federacy", True) and fed_file.exists(),
        fed_data,
        "public-file",
    )

    # 6. Immunefi (live fetch — Web3/DeFi; optional, skip on network failure)
    immunefi_programs = []
    immunefi_attempted = bool(refresh and platforms_cfg.get("immunefi", True))
    if immunefi_attempted:
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
    platform_status["immunefi"] = _platform_status(
        immunefi_attempted, immunefi_programs, "live-board"
    )

    # 7. Sherlock audit contests (live fetch — Web3 smart-contract; optional, soft-fail)
    sherlock_contests = []
    sherlock_attempted = bool(refresh and platforms_cfg.get("sherlock", True))
    if sherlock_attempted:
        print(
            "[*] Fetching Sherlock audit contests (Web3 smart-contract competitions)..."
        )
        sherlock_contests = _fetch_sherlock_contests()
        if sherlock_contests:
            with conn:
                for p in sherlock_contests:
                    handle = p["handle"]
                    existing = cur.execute(
                        "SELECT id, first_seen_timestamp FROM contests WHERE platform=? AND handle=?",
                        ("Sherlock", handle),
                    ).fetchone()
                    first_seen = existing[1] if existing else now_ts

                    cur.execute(
                        """
                        INSERT INTO contests (
                            platform, name, handle, url, offers_bounties, max_payout,
                            currency, status, starts_at, ends_at, description,
                            first_seen_timestamp, last_updated_timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(platform, handle) DO UPDATE SET
                            name=excluded.name, url=excluded.url,
                            offers_bounties=excluded.offers_bounties,
                            max_payout=excluded.max_payout,
                            currency=excluded.currency,
                            status=excluded.status,
                            starts_at=excluded.starts_at,
                            ends_at=excluded.ends_at,
                            description=excluded.description,
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
                            p.get("status"),
                            _contest_ts(p.get("starts_at")),
                            _contest_ts(p.get("ends_at")),
                            p.get("description"),
                            first_seen,
                            now_ts,
                        ),
                    )
                    # Sherlock scopes are the contest URL itself — no sub-assets to enumerate
            print(f"[+] Sherlock indexed: {len(sherlock_contests)} contests.")
        else:
            print("[*] Sherlock: no contest data returned.")
    platform_status["sherlock"] = _platform_status(
        sherlock_attempted, sherlock_contests, "live-api"
    )

    # 8. ProjectDiscovery public-bugbounty-programs (supplemental; soft-fail)
    pd_programs_list = []
    pd_attempted = bool(refresh and platforms_cfg.get("pd_programs", True))
    pd_clone_failed = ""
    if pd_attempted:
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
            pd_clone_failed = str(e)
            pd_repo_dir = None

        if pd_repo_dir and pd_repo_dir.exists():
            pd_programs_list = _load_pd_programs(pd_repo_dir)
            if pd_programs_list:
                try:
                    count = 0
                    with conn:
                        for p in pd_programs_list:
                            if not isinstance(p, dict):
                                continue
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
                except sqlite3.Error as e:
                    print(f"[!] ProjectDiscovery DB index error — skipping: {e}")
            else:
                print(
                    "[*] ProjectDiscovery: no programs loaded"
                    " (dist/data.json + src/data.yaml missing or unparseable)."
                )
    if pd_clone_failed:
        platform_status["pd_programs"] = {
            "status": "clone_failed",
            "count": 0,
            "source": "pd-repo",
            "note": pd_clone_failed,
        }
    else:
        platform_status["pd_programs"] = _platform_status(
            pd_attempted, pd_programs_list, "pd-repo"
        )

    for _plat, _st in ingest_stats.items():
        if _plat in platform_status and _st.get("rejected"):
            platform_status[_plat]["rejected_assets"] = _st["rejected"]
    _set_meta(cur, "upstream_sha", upstream_sha)
    _set_meta(cur, "last_sync_ts", str(now_ts))
    _set_meta(cur, "last_refresh_ok", "1" if refresh_ok else "0")
    # Feed-age anchor: only a real, successful network refresh counts. Offline
    # imports (refresh=False) and failed fetches must not reset feed age (#9).
    if refresh and refresh_ok:
        _set_meta(cur, "last_successful_sync_ts", str(now_ts))
    if refresh_error:
        _set_meta(cur, "last_refresh_error", refresh_error)
    _set_meta(cur, "platform_status", json.dumps(platform_status, sort_keys=True))

    if is_baseline_sync:
        cur.execute("UPDATE programs SET first_seen_timestamp=0")
        cur.execute("UPDATE assets SET first_seen_timestamp=0")
        cur.execute("UPDATE contests SET first_seen_timestamp=0")
        cur.execute(
            "INSERT INTO sync_metadata(key, value) VALUES('baseline_complete', ?) ",
            (str(now_ts),),
        )
        print("[*] Initial feed baseline recorded; current entries are not marked new.")
    conn.commit()

    total_progs = cur.execute("SELECT count(*) FROM programs").fetchone()[0]
    total_assets = cur.execute(
        "SELECT count(*) FROM assets WHERE deleted_timestamp=0"
    ).fetchone()[0]
    total_wild = cur.execute(
        "SELECT count(*) FROM assets WHERE is_wildcard=1 AND deleted_timestamp=0"
    ).fetchone()[0]
    total_tombstoned = cur.execute(
        "SELECT count(*) FROM assets WHERE deleted_timestamp!=0"
    ).fetchone()[0]
    print(
        f"\n[✓] Scan4Me Sync Complete: {total_progs} programs, {total_assets} assets"
        f" ({total_wild} wildcards, {total_tombstoned} tombstoned)."
    )
    total_contests = cur.execute("SELECT count(*) FROM contests").fetchone()[0]
    if total_contests:
        print(
            f"[*] Sherlock contests tracked separately: {total_contests} (not counted as programs)."
        )


def cmd_enrich(args):
    conn = get_db()
    ensure_schema(conn)
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


def score_payout_velocity(prog):
    """Expected payout-per-triage-hour rank for a scored program dict.

    Returns ``(payout_per_hour_usd_or_None, velocity_score_0_100, estimated)``.

    Method (documented heuristic, not calibrated economics):
      expected payout = average_payout when published, else 5% of the max
      ceiling as a severity-discounted proxy (most reports pay far under max);
      triage hours = first_response_hours when known, else validation_days*24.
      payout/hour = expected / triage_hours; the 0-100 score is
      20*log10(pph+1) so $10/h ≈ 21, $100/h ≈ 40, $1000/h ≈ 60.
    When payout or triage time is unknown there is no honest $/h number:
    pph is None and the score falls back to (payout+speed)/4, flagged
    estimated=True so callers can sort measured ranks above guesses.
    """
    import math

    avg_p = prog.get("average_payout") or 0
    max_p = prog.get("max_payout") or 0
    if avg_p > 0:
        expected = float(avg_p)
    elif max_p > 0:
        expected = float(max_p) * 0.05
    else:
        expected = 0.0
    triage_hours = None
    if prog.get("first_resp") is not None:
        try:
            triage_hours = float(prog["first_resp"])
        except (TypeError, ValueError):
            triage_hours = None
    if triage_hours is None and prog.get("validation_days") is not None:
        try:
            triage_hours = float(prog["validation_days"]) * 24.0
        except (TypeError, ValueError):
            triage_hours = None
    if expected > 0 and triage_hours is not None and triage_hours > 0:
        pph = expected / triage_hours
        score = round(min(100.0, max(0.0, 20.0 * math.log10(pph + 1.0))), 1)
        return round(pph, 2), score, False
    fallback = round(
        ((prog.get("payout_score") or 0) + (prog.get("speed_score") or 0)) / 4.0, 1
    )
    return None, fallback, True


def evaluate_targets(config=None):
    config = config or load_config()
    conn = get_db()
    # No ensure_schema here: this library function is query-count-tested and
    # already hard-references migrated columns (official_first_seen_timestamp).
    # Callers on a stale DB must sync (which migrates) first.
    cur = conn.cursor()

    filters = config.get("filters", {})
    fast_triage = filters.get("fast_triage", {})
    surface_cfg = filters.get("attack_surface_and_scope", {})
    fresh_cfg = filters.get("freshness_and_competition", {})
    payout_cfg = filters.get("payouts", {})
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
        # P6: Sherlock contests live in the contests table, not programs —
        # enabling "sherlock" controls contest sync only, never radar rows.
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
        "AND a.deleted_timestamp=0 "
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
    if not surface_cfg.get("prioritize_wildcards", True):
        wildcard_mult = 1.0
    min_max_payout = payout_cfg.get("min_max_payout_usd")
    fast_cash = payout_cfg.get("prioritize_fast_cash", True)
    prefer_large_surface = surface_cfg.get("prefer_large_attack_surface", True)
    prefer_fresh = fresh_cfg.get("prefer_fresh_programs", True)
    low_saturation = fresh_cfg.get("low_report_saturation", True)
    prefer_managed = fast_triage.get("prefer_managed_triage", False)
    award_tier2 = fast_triage.get("max_time_to_bounty_awarded_hours", 336.0) or 336.0
    award_tier1 = award_tier2 / 2.0
    new_asset_days = fresh_cfg.get("new_asset_days", 30)
    new_company_days_score = fresh_cfg.get("new_company_days", 90)
    new_asset_cutoff = now_ts - (new_asset_days * 86400)
    new_company_cutoff = now_ts - (new_company_days_score * 86400)

    # P6: batch the new-asset signals (one GROUP BY each) instead of one query
    # per program. Counts are identical to the former per-program loop.
    new_asset_counts = {}
    enriched_program_ids = set()
    if fresh_cfg.get("prefer_new_assets", False) and rows:
        batched_ids = [r["id"] for r in rows]
        batched_holders = ",".join("?" * len(batched_ids))
        # ?-holders only; values stay bound parameters (B608 false positive).
        for program_id, cnt in cur.execute(
            "SELECT program_id, count(*) FROM assets WHERE program_id IN ("  # nosec B608
            + batched_holders
            + ") AND deleted_timestamp=0 AND ("
            "(official_first_seen_timestamp IS NOT NULL"
            " AND official_first_seen_timestamp > ?)"
            " OR (official_first_seen_timestamp IS NULL"
            " AND first_seen_timestamp > ?)"
            ") GROUP BY program_id",
            (*batched_ids, new_asset_cutoff, new_asset_cutoff),
        ).fetchall():
            new_asset_counts[program_id] = cnt
        if fresh_cfg.get("strict_new_assets", False):
            for (enriched_id,) in cur.execute(
                "SELECT DISTINCT program_id FROM assets WHERE program_id IN ("  # nosec B608
                + batched_holders
                + ") AND deleted_timestamp=0"
                " AND official_first_seen_timestamp IS NOT NULL",
                batched_ids,
            ).fetchall():
                enriched_program_ids.add(enriched_id)

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
        # strict_validation_days: Bugcrowd programs WITHOUT the data are out.
        if (
            fast_triage.get("strict_validation_days", False)
            and r["platform"] == "Bugcrowd"
            and r["validation_days"] is None
        ):
            continue

        # min_max_payout_usd: drop programs whose KNOWN ceiling is below the
        # floor. Unknown ceilings (max_payout NULL/0, e.g. all of HackerOne)
        # pass through — unknown ≠ cheap.
        if min_max_payout is not None:
            _ceiling = r["max_payout"] or 0
            if _ceiling > 0 and _ceiling < min_max_payout:
                continue

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
            new_assets_count = new_asset_counts.get(r["id"], 0)
            # Only hard-exclude if strict_new_assets is set AND this is a Bugcrowd program
            # with enrichment data that actually shows no new scope. All other platforms pass.
            if (
                fresh_cfg.get("strict_new_assets", False)
                and r["platform"] == "Bugcrowd"
                and r["id"] in enriched_program_ids
                and new_assets_count == 0
            ):
                continue

        # 1. Triage Speed Score (0-100)
        # HackerOne: first_response_hours drives the base (lower = faster = higher score).
        # Bonus tiers come from max_time_to_bounty_awarded_hours (default 336h:
        # <=168h = +15 pts; <=336h = +8 pts); gated by prioritize_fast_cash.
        # Bugcrowd: validation_days <= 7 = +20 pts; <= 14 = +10 pts (fast-cash proxy).
        # Managed triage earns +5 when prefer_managed_triage is set.
        # Other platforms default to 50 (no published measurement).
        speed_score = 50.0
        if r["platform"] == "HackerOne":
            if r["first_response_hours"] is not None:
                speed_score = max(0, 100 - (r["first_response_hours"] * 1.5))
            if fast_cash and r["bounty_awarded_hours"] is not None:
                if r["bounty_awarded_hours"] <= award_tier1:
                    speed_score = min(100.0, speed_score + 15)
                elif r["bounty_awarded_hours"] <= award_tier2:
                    speed_score = min(100.0, speed_score + 8)
        elif (
            fast_cash
            and r["platform"] == "Bugcrowd"
            and r["validation_days"] is not None
        ):
            if r["validation_days"] <= 7:
                speed_score = min(100.0, speed_score + 20)
            elif r["validation_days"] <= 14:
                speed_score = min(100.0, speed_score + 10)
        if prefer_managed and r["managed_triage"]:
            speed_score = min(100.0, speed_score + 5)
        speed_score = min(100.0, speed_score)

        # 2. Attack Surface Score (0-100) - "More Assets is Better, More Surface Area"
        # Each asset gives 1.5 pts, each wildcard gives (1.5 * wildcard_mult) ~ 3.75 pts
        # prefer_large_attack_surface=False flattens every program to neutral 50.
        if not prefer_large_surface:
            surface_score = 50.0
        else:
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

        # Freshness bonuses apply only when prefer_fresh_programs is set;
        # the low-competition proxy is additionally gated by low_report_saturation.
        if prefer_fresh:
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
            if low_saturation and rewarded is not None:
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
        if fast_cash:
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

        _pph, _velocity, _vest = score_payout_velocity(
            {
                "average_payout": r["average_payout"],
                "max_payout": r["max_payout"],
                "first_resp": r["first_response_hours"],
                "validation_days": r["validation_days"],
                "payout_score": payout_score,
                "speed_score": speed_score,
            }
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
                "payout_per_hour_usd": _pph,
                "velocity_score": _velocity,
                "velocity_estimated": _vest,
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


STALE_AFTER_HOURS = 48


def feed_provenance(conn=None):
    """Feed provenance stamp for radar/prescan/report artifacts (#5/#9).

    Returns upstream SHA + per-platform fetch status + live row counts +
    feed age + the explicit degraded-mode coverage gaps. Every claim is
    computed from sync_metadata and live tables — never asserted statically.
    Unknowns are reported as unknown, not as zeros.
    """
    own = conn is None
    if own:
        conn = get_db()
    try:
        cur = conn.cursor()
        try:
            meta = {
                r["key"]: r["value"]
                for r in cur.execute("SELECT key, value FROM sync_metadata").fetchall()
            }
        except Exception:
            meta = {}
        try:
            plat_status = json.loads(meta.get("platform_status", "{}") or "{}")
        except (TypeError, ValueError):
            plat_status = {}
        try:
            n_programs = cur.execute("SELECT count(*) FROM programs").fetchone()[0]
        except Exception:
            n_programs = None
        try:
            n_assets = cur.execute(
                "SELECT count(*) FROM assets WHERE deleted_timestamp=0"
            ).fetchone()[0]
        except Exception:
            try:
                n_assets = cur.execute("SELECT count(*) FROM assets").fetchone()[0]
            except Exception:
                n_assets = None
        try:
            n_contests = cur.execute("SELECT count(*) FROM contests").fetchone()[0]
        except Exception:
            n_contests = None
        try:
            h1_total, h1_paid = cur.execute(
                "SELECT count(*), sum(CASE WHEN max_payout > 0 THEN 1 ELSE 0 END)"
                " FROM programs WHERE platform='HackerOne'"
            ).fetchone()
        except Exception:
            h1_total, h1_paid = None, None
        try:
            im_programs = cur.execute(
                "SELECT count(*) FROM programs WHERE platform='Immunefi'"
            ).fetchone()[0]
            im_assets = cur.execute(
                "SELECT count(*) FROM assets a JOIN programs p ON a.program_id=p.id"
                " WHERE p.platform='Immunefi' AND a.deleted_timestamp=0"
            ).fetchone()[0]
        except Exception:
            im_programs, im_assets = None, None
    finally:
        if own:
            conn.close()

    now_ts = int(time.time())

    def _meta_int(key: str) -> int:
        try:
            return int(meta.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    sync_ts = _meta_int("last_sync_ts")
    # Feed age is measured from the last SUCCESSFUL network refresh, never from
    # the last time sync_data merely ran: an offline import or a failed fetch
    # stamps last_sync_ts=now but must not make a stale snapshot look fresh (#9).
    succ_ts = _meta_int("last_successful_sync_ts")
    if not succ_ts and meta.get("last_refresh_ok") != "0":
        # Pre-fix DB whose last run did not fail: fall back to last_sync_ts.
        succ_ts = sync_ts
    age_hours = round((now_ts - succ_ts) / 3600.0, 1) if succ_ts else None

    gaps = [
        # Structural: no feed carries rules/policy text, so Oracle's verify
        # leg 3 can only pass via downgrade-to-advisory, never via data.
        "rules/policy text: carried by no feed — verify leg 3 has no data leg"
    ]
    if h1_total:
        gaps.append(
            f"HackerOne payouts: {h1_paid or 0}/{h1_total} programs carry a"
            " ceiling — the rest cannot pass exact payout verification"
        )
    if im_programs is not None:
        gaps.append(
            f"Immunefi: {im_programs} programs, {im_assets or 0} scope rows"
            " (programs-only until detail-page scope fetch lands)"
        )
    for plat in sorted(plat_status):
        entry = plat_status[plat] or {}
        status = entry.get("status", "unknown")
        if status != "ok":
            gaps.append(
                f"platform {plat}: last sync status={status}"
                f" (rows={entry.get('count', 0)})"
            )
    return {
        "upstream_sha": meta.get("upstream_sha") or "unknown",
        "last_sync_ts": sync_ts or None,
        "last_successful_sync_ts": succ_ts or None,
        "age_hours": age_hours,
        "stale": age_hours is not None and age_hours > STALE_AFTER_HOURS,
        "refresh_ok": meta.get("last_refresh_ok") != "0",
        "platforms": plat_status,
        "row_counts": {
            "programs": n_programs,
            "live_assets": n_assets,
            "contests": n_contests,
        },
        "coverage_gaps": gaps,
    }


def cmd_filter(args, config):
    # Migrate the DB before ranking: evaluate_targets references migrated
    # columns and does not call ensure_schema itself (query-count contract),
    # so an older DB would raise mid-ranking without this.
    _schema_conn = get_db()
    ensure_schema(_schema_conn)
    _schema_conn.close()
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
    _prov = feed_provenance()
    _counts = _prov["row_counts"]
    _age = (
        f"{_prov['age_hours']}h old"
        if _prov["age_hours"] is not None
        else "age unknown (never synced?)"
    )
    print(
        f"[*] Provenance: upstream={str(_prov['upstream_sha'])[:12]}"
        f" | {_age}"
        + (" [STALE]" if _prov["stale"] else "")
        + f" | programs={_counts['programs']} live_assets={_counts['live_assets']}"
        f" contests={_counts['contests']}"
    )
    _bad = sorted(
        p
        for p, e in (_prov["platforms"] or {}).items()
        if (e or {}).get("status", "unknown") != "ok"
    )
    if _bad:
        print(f"[!] Degraded feeds: {', '.join(_bad)} (see coverage gaps below)")
    for _gap in _prov["coverage_gaps"]:
        print(f"[!] Coverage gap: {_gap}")
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
            "[*] Low-saturation bonus uses Bugcrowd rewarded counts only; other"
            " platforms carry no resolved-report signal."
        )
    print(
        f"[*] Displaying Top {min(limit, len(results))} Target Companies (Ranked by Surface & Speed):\n"
    )

    conn = get_db()
    ensure_schema(conn)
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
                "SELECT asset_identifier FROM assets WHERE program_id=?"
                " AND is_wildcard=1 AND deleted_timestamp=0 LIMIT 3",
                (p["id"],),
            ).fetchall()
            other_samples = cur.execute(
                "SELECT asset_identifier FROM assets WHERE program_id=?"
                " AND is_wildcard=0 AND deleted_timestamp=0 LIMIT 3",
                (p["id"],),
            ).fetchall()

            samples = [w[0] for w in wildcard_samples] + [o[0] for o in other_samples]
            if samples:
                print(f"     🔎 Target Sample : {', '.join(samples[:4])}")
        print("-" * 88)


def scope_match(target, asset_identifier, is_wildcard):
    """Fail-closed scope match: True only when target is provably in scope.

    The rule is canonicalized at match time (#4), so legacy verbatim rows
    (scheme-prefixed wildcards like 'http://*.x') match until the next sync
    rewrites them. Non-wildcard assets require an exact (case-insensitive)
    host match. '*.base' wildcards match proper subdomains of base only —
    never the apex itself and never lookalike suffixes ('evilexample.com'
    is NOT in scope). Glued wildcards ('*-prefix.host') match targets
    ending in the literal rest. Anything else returns False.
    """
    t = _strip_host(target)
    rule, _, rule_wild, ok = canonicalize_asset(
        asset_identifier, "wildcard" if is_wildcard else "url"
    )
    if not t or not ok or not rule:
        return False
    if not (is_wildcard or rule_wild):
        return t == rule
    if rule.startswith("*."):
        base = rule[2:]
        if not base or "*" in base:
            return False
        return t.endswith("." + base)
    if rule.startswith("*"):
        rest = rule[1:]
        if not rest or "*" in rest:
            return False
        return t.endswith(rest)
    return False


def _ip_matches_rule(target, rule_identifier) -> bool:
    """True when ``target`` is an IP address contained in ``rule_identifier``.

    ``rule_identifier`` may be a CIDR ('10.0.0.0/8') or a bare IP ('10.1.2.3').
    Used for out-of-scope exclusions: ``scope_match`` compares hosts as strings,
    so a CIDR exclusion would never catch an individual address inside it and
    that address would be wrongly reported as authorized. Returns False for any
    non-IP target or unparseable rule — it only ever adds an exclusion, never
    removes one.
    """
    try:
        ip = ipaddress.ip_address((target or "").strip())
    except ValueError:
        return False
    rule = (rule_identifier or "").strip()
    try:
        return ip in ipaddress.ip_network(rule, strict=False)
    except ValueError:
        try:
            return ip == ipaddress.ip_address(rule)
        except ValueError:
            return False


def clean_asset_identifier(value):
    """Bare host for recon-tool piping: no scheme, path, port, or star."""
    host, _, _, ok = canonicalize_asset(value, "url")
    if ok and host and "*" not in host:
        return host
    # Wildcards / non-DNS: best-effort strip of scheme + star only.
    val = _strip_host(value)
    if val.startswith("*."):
        val = val[2:]
    elif val.startswith("*"):
        val = val[1:]
    return val.lstrip(".").rstrip("/")


def cmd_check(args):
    conn = get_db()
    ensure_schema(conn)
    target = (args.domain or "").strip().lower()
    cur = conn.cursor()

    # Only submission-eligible assets can be authorized targets: an asset the
    # program will not accept reports on must not print as [AUTHORIZED IN-SCOPE].
    candidates = cur.execute(
        """
        SELECT p.id AS program_id, p.platform, p.name, p.url, p.website,
               p.offers_bounties, a.asset_identifier, a.is_wildcard
        FROM assets a
        JOIN programs p ON a.program_id = p.id
        WHERE a.deleted_timestamp=0 AND a.eligible_for_submission=1
    """
    ).fetchall()
    in_scope = [
        m
        for m in candidates
        if scope_match(target, m["asset_identifier"], m["is_wildcard"])
    ]

    # Live out-of-scope exclusions win over an in-scope wildcard: a target that
    # matches an explicit oos_assets rule for the same program is NOT authorized.
    # Cache the verdict per program_id — several in-scope assets can belong to
    # one program, and the exclusion set is identical for all of them.
    oos_cache = {}

    def _is_oos(program_id) -> bool:
        if program_id in oos_cache:
            return oos_cache[program_id]
        verdict = False
        for row in cur.execute(
            "SELECT asset_identifier, is_wildcard FROM oos_assets "
            "WHERE program_id=? AND deleted_timestamp=0",
            (program_id,),
        ).fetchall():
            if scope_match(target, row["asset_identifier"], row["is_wildcard"]) or (
                _ip_matches_rule(target, row["asset_identifier"])
            ):
                verdict = True
                break
        oos_cache[program_id] = verdict
        return verdict

    # Keep the first ten authorized matches; stop scanning once we have them.
    matches = []
    for m in in_scope:
        if _is_oos(m["program_id"]):
            continue
        matches.append(m)
        if len(matches) >= 10:
            break

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
    # Migrate before ranking (see cmd_filter): evaluate_targets hits migrated
    # columns, so ensure_schema must run first on an older DB.
    conn = get_db()
    ensure_schema(conn)
    results = evaluate_targets(config)
    limit = args.top or 30
    target_ids = [p["id"] for p in results[:limit]]

    cur = conn.cursor()
    if not target_ids:
        return
    placeholders = ",".join("?" * len(target_ids))
    # Export only submission-eligible assets; for paid programs also require
    # bounty eligibility, so a bounty-ineligible asset never enters the paid
    # target list. VDP (offers_bounties=0) programs need only submission.
    sql = (
        "SELECT DISTINCT a.asset_identifier FROM assets a"  # nosec B608
        " JOIN programs p ON a.program_id = p.id"
        " WHERE a.deleted_timestamp=0 AND a.eligible_for_submission=1"
        " AND (p.offers_bounties=0 OR a.eligible_for_bounty=1)"
        " AND a.program_id IN (" + placeholders + ")"
    )
    if args.wildcards_only:
        sql += " AND a.is_wildcard = 1"

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
            "immunefi": "🌐 Public board page (no auth needed)",
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
