"""Focused regression tests for Scan4Me repairs.

Covers: scope matching (fail-closed), export cleaning, CLI override wiring,
asset reconciliation, and offline sync feed requirements.

Run:  python3 -m pytest tests/ -q   (from the Scan4Me directory)
"""

import json
import sqlite3
import sys
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scan4me  # noqa: E402 - import requires the sys.path insert above


# ── scope_match: exact (non-wildcard) ─────────────────────────────────────────


def test_scope_match_exact():
    assert scan4me.scope_match("api.example.com", "api.example.com", False) is True


def test_scope_match_exact_case_and_dot_insensitive():
    assert scan4me.scope_match("API.Example.COM.", "api.example.com", False) is True


def test_scope_match_exact_rejects_substring():
    # Substring containment must NOT count as in-scope (the reported bug).
    assert scan4me.scope_match("evilexample.com", "example.com", False) is False
    assert scan4me.scope_match("example.com.evil.com", "example.com", False) is False


# ── scope_match: *.base wildcards ─────────────────────────────────────────────


def test_scope_match_dot_wildcard_subdomain():
    assert scan4me.scope_match("api.example.com", "*.example.com", True) is True
    assert scan4me.scope_match("a.b.example.com", "*.example.com", True) is True


def test_scope_match_dot_wildcard_rejects_apex():
    # *.example.com does not cover the apex itself — fail closed.
    assert scan4me.scope_match("example.com", "*.example.com", True) is False


def test_scope_match_dot_wildcard_rejects_lookalikes():
    assert scan4me.scope_match("evilexample.com", "*.example.com", True) is False
    assert scan4me.scope_match("example.com.evil.com", "*.example.com", True) is False
    assert scan4me.scope_match("example.com", "*.example.com", True) is False


# ── scope_match: glued wildcards (*-prefix.host) ──────────────────────────────


def test_scope_match_glued_wildcard():
    assert scan4me.scope_match("a-vpn.8x8.com", "*-vpn.8x8.com", True) is True


def test_scope_match_glued_wildcard_rejects():
    assert scan4me.scope_match("vpn.8x8.com", "*-vpn.8x8.com", True) is False
    assert scan4me.scope_match("badvpn.8x8.com", "*-vpn.8x8.com", True) is False
    assert scan4me.scope_match("-vpn.8x8.com.evil.com", "*-vpn.8x8.com", True) is False


def test_scope_match_mid_string_wildcard_fails_closed():
    assert scan4me.scope_match("a.example.com", "foo.*.com", True) is False


def test_scope_match_empty_inputs():
    assert scan4me.scope_match("", "*.example.com", True) is False
    assert scan4me.scope_match("a.example.com", "", True) is False


# ── clean_asset_identifier ────────────────────────────────────────────────────


def test_clean_asset_identifier():
    assert scan4me.clean_asset_identifier("*.example.com") == "example.com"
    assert scan4me.clean_asset_identifier("example.com/") == "example.com"
    assert scan4me.clean_asset_identifier("*-vpn.8x8.com") == "-vpn.8x8.com"
    assert scan4me.clean_asset_identifier("  *.Example.COM/ ") == "Example.COM"


# ── apply_cli_overrides ───────────────────────────────────────────────────────


def _namespace(**kwargs):
    defaults = {
        "new_companies": False,
        "new_company_days": 90,
        "new_assets": False,
        "new_asset_days": 30,
        "max_validation_days": None,
        "max_rewarded_vulnerabilities": None,
        "require_measured_triage": False,
    }
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


def test_cli_new_companies_implies_strict():
    config = {"filters": {}}
    scan4me.apply_cli_overrides(
        config, _namespace(new_companies=True, new_company_days=30)
    )
    fresh = config["filters"]["freshness_and_competition"]
    assert fresh["prefer_new_companies"] is True
    assert fresh["strict_new_companies"] is True
    assert fresh["new_company_days"] == 30


def test_cli_new_assets_implies_strict():
    config = {"filters": {}}
    scan4me.apply_cli_overrides(config, _namespace(new_assets=True, new_asset_days=7))
    fresh = config["filters"]["freshness_and_competition"]
    assert fresh["prefer_new_assets"] is True
    assert fresh["strict_new_assets"] is True
    assert fresh["new_asset_days"] == 7


def test_cli_no_flags_leaves_config_untouched():
    config = {"filters": {"freshness_and_competition": {"prefer_new_companies": False}}}
    scan4me.apply_cli_overrides(config, _namespace())
    fresh = config["filters"]["freshness_and_competition"]
    assert fresh["prefer_new_companies"] is False
    assert "strict_new_companies" not in fresh


# ── sync_assets reconciliation ────────────────────────────────────────────────


def _temp_db(path):
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    scan4me.init_db(conn)
    scan4me.migrate_db(conn)
    return conn


def test_sync_assets_reconciles_and_preserves_first_seen(tmp_path):
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO programs (platform, name, handle) VALUES (?, ?, ?)",
        ("HackerOne", "Example", "example"),
    )
    program_id = cur.lastrowid
    conn.commit()

    scan4me.sync_assets(
        cur,
        program_id,
        [
            {"asset_identifier": "*.example.com", "asset_type": "URL"},
            {"asset_identifier": "old.example.com", "asset_type": "URL"},
        ],
        "asset_identifier",
        "asset_type",
        1000,
    )
    conn.commit()
    rows = {
        r["asset_identifier"]: r["first_seen_timestamp"]
        for r in cur.execute(
            "SELECT asset_identifier, first_seen_timestamp FROM assets"
        )
    }
    assert rows == {"*.example.com": 1000, "old.example.com": 1000}

    # Resync: one kept (timestamp preserved), one added, one stale (deleted).
    scan4me.sync_assets(
        cur,
        program_id,
        [
            {"asset_identifier": "*.example.com", "asset_type": "URL"},
            {"asset_identifier": "new.example.com", "asset_type": "URL"},
        ],
        "asset_identifier",
        "asset_type",
        2000,
    )
    conn.commit()
    rows = {
        r["asset_identifier"]: r["first_seen_timestamp"]
        for r in cur.execute(
            "SELECT asset_identifier, first_seen_timestamp FROM assets"
        )
    }
    assert rows == {"*.example.com": 1000, "new.example.com": 2000}
    conn.close()


# ── offline sync feed requirements ────────────────────────────────────────────


def _write_feed(data_dir, name, payload):
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / name).write_text(json.dumps(payload), encoding="utf-8")


def test_sync_offline_all_core_disabled_needs_no_feeds(tmp_path, monkeypatch):
    monkeypatch.setattr(scan4me, "CACHE_DATA_DIR", tmp_path / "cache")
    monkeypatch.setattr(scan4me, "DB_PATH", tmp_path / "t.db")
    (tmp_path / "cache" / "data").mkdir(parents=True)
    cfg = {
        "hackerone": False,
        "bugcrowd": False,
        "intigriti": False,
        "yeswehack": False,
        "federacy": False,
        "immunefi": False,
        "sherlock": False,
        "pd_programs": False,
    }
    scan4me.sync_data(refresh=False, platforms_cfg=cfg, config={})
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    assert conn.execute("SELECT count(*) FROM programs").fetchone()[0] == 0
    conn.close()


def test_sync_offline_missing_required_feed_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(scan4me, "CACHE_DATA_DIR", tmp_path / "cache")
    monkeypatch.setattr(scan4me, "DB_PATH", tmp_path / "t.db")
    _write_feed(tmp_path / "cache" / "data", "hackerone_data.json", [])
    cfg = {
        "hackerone": True,
        "bugcrowd": False,
        "intigriti": False,
        "yeswehack": False,
        "federacy": False,
        "immunefi": False,
        "sherlock": False,
        "pd_programs": False,
    }
    # bugcrowd/intigriti/yeswehack disabled → not required, but the cache dir
    # must still exist for offline mode; missing hackerone feed must raise.
    (tmp_path / "cache" / "data" / "hackerone_data.json").unlink()
    with pytest.raises(FileNotFoundError):
        scan4me.sync_data(refresh=False, platforms_cfg=cfg, config={})


# ── trio central key store ────────────────────────────────────────────────


def test_trio_central_fills_gaps(tmp_path, monkeypatch):
    central = tmp_path / "keys.env"
    central.write_text("HACKERONE_API_TOKEN=from-central\n")
    monkeypatch.setattr(scan4me, "TRIO_KEYS_FILE", str(central))
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    creds = scan4me.load_credentials(config={})
    assert creds["hackerone"]["api_token"] == "from-central"


def test_env_beats_trio_central(tmp_path, monkeypatch):
    central = tmp_path / "keys.env"
    central.write_text("HACKERONE_API_TOKEN=from-central\n")
    monkeypatch.setattr(scan4me, "TRIO_KEYS_FILE", str(central))
    monkeypatch.setenv("HACKERONE_API_TOKEN", "from-process")
    creds = scan4me.load_credentials(config={})
    assert creds["hackerone"]["api_token"] == "from-process"


# ── P6: Sherlock contests separated from programs ─────────────────────────────


def test_p6_contest_migration_drops_exactly_contest_rows(tmp_path):
    """Baseline mirror: 1200 rows in programs including 259 Sherlock contests.

    After migrate_db, programs must drop by exactly the 259 contest rows
    (1200 -> 941) with contests preserved 1:1 in the contests table and
    assets/wildcards untouched.
    """
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    cur.executemany(
        """INSERT INTO programs (platform, handle, name, offers_bounties,
           max_payout, first_seen_timestamp)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [
            ("HackerOne", f"prog-{i}", f"Program {i}", 1, 0, 1000 - i)
            for i in range(941)
        ],
    )
    cur.executemany(
        """INSERT INTO programs (platform, handle, name, offers_bounties,
           max_payout, first_seen_timestamp)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [
            ("Sherlock", f"sherlock-{i}", f"Contest {i}", 1, 5000.0, 2000 + i)
            for i in range(259)
        ],
    )
    prog_id = cur.execute("SELECT id FROM programs WHERE handle='prog-0'").fetchone()[0]
    cur.execute(
        """INSERT INTO assets (program_id, asset_identifier, asset_type,
           is_wildcard, first_seen_timestamp)
           VALUES (?, '*.example.com', 'URL', 1, 100)""",
        (prog_id,),
    )
    cur.execute(
        """INSERT INTO assets (program_id, asset_identifier, asset_type,
           is_wildcard, first_seen_timestamp)
           VALUES (?, 'api.example.com', 'URL', 0, 100)""",
        (prog_id,),
    )
    conn.commit()
    assert cur.execute("SELECT count(*) FROM programs").fetchone()[0] == 1200

    scan4me.migrate_db(conn)

    assert cur.execute("SELECT count(*) FROM programs").fetchone()[0] == 941
    assert cur.execute("SELECT count(*) FROM contests").fetchone()[0] == 259
    assert (
        cur.execute(
            "SELECT count(*) FROM programs WHERE platform='Sherlock'"
        ).fetchone()[0]
        == 0
    )
    assert cur.execute("SELECT count(*) FROM assets").fetchone()[0] == 2
    assert (
        cur.execute("SELECT count(*) FROM assets WHERE is_wildcard=1").fetchone()[0]
        == 1
    )
    row = cur.execute(
        "SELECT name, max_payout, first_seen_timestamp FROM contests"
        " WHERE handle='sherlock-7'"
    ).fetchone()
    assert tuple(row) == ("Contest 7", 5000.0, 2007)

    # Idempotent: a second run changes nothing.
    scan4me.migrate_db(conn)
    assert cur.execute("SELECT count(*) FROM programs").fetchone()[0] == 941
    assert cur.execute("SELECT count(*) FROM contests").fetchone()[0] == 259
    conn.close()


def _eval_config(**platforms):
    base = {
        "hackerone": False,
        "bugcrowd": False,
        "intigriti": False,
        "yeswehack": False,
        "federacy": False,
        "immunefi": False,
        "sherlock": False,
        "pd_programs": False,
    }
    base.update(platforms)
    return {
        "platforms": base,
        "filters": {
            "paid_bounties_only": True,
            "fast_triage": {"enabled": True},
            "attack_surface_and_scope": {
                "min_in_scope_assets": 1,
                "wildcard_multiplier": 2.5,
            },
            "freshness_and_competition": {"prefer_new_assets": False},
            "program_kind": {"web2": True, "web3": True},
        },
    }


def test_p6_evaluate_excludes_contests(tmp_path, monkeypatch):
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO programs (platform, name, handle, offers_bounties,
           max_payout, first_seen_timestamp)
           VALUES ('HackerOne', 'Real Program', 'real-program', 1, 1000, 100)"""
    )
    prog_id = cur.lastrowid
    cur.execute(
        """INSERT INTO assets (program_id, asset_identifier, asset_type,
           is_wildcard, first_seen_timestamp)
           VALUES (?, 'a.example.com', 'URL', 0, 100)""",
        (prog_id,),
    )
    cur.execute(
        """INSERT INTO contests (platform, name, handle, url, offers_bounties,
           max_payout, first_seen_timestamp, last_updated_timestamp)
           VALUES ('Sherlock', 'Contest', 'sherlock-1',
           'https://audits.sherlock.xyz/contests/1', 1, 999999, 100, 100)"""
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)

    both = scan4me.evaluate_targets(_eval_config(hackerone=True, sherlock=True))
    assert [p["name"] for p in both] == ["Real Program"]

    sherlock_only = scan4me.evaluate_targets(_eval_config(sherlock=True))
    assert sherlock_only == []


# ── P6: batched new-asset queries (N+1 fix) ───────────────────────────────────


class _CountingCursor:
    """Proxy cursor that counts execute() calls."""

    def __init__(self, cursor, counter):
        self._cursor = cursor
        self._counter = counter

    def execute(self, sql, params=()):
        self._counter[0] += 1
        return self._cursor.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class _CountingConn:
    """Proxy connection handing out counting cursors."""

    def __init__(self, conn, counter):
        self._conn = conn
        self._counter = counter

    def cursor(self):
        return _CountingCursor(self._conn.cursor(), self._counter)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def test_p6_new_asset_queries_batched(tmp_path, monkeypatch):
    """8 Bugcrowd programs with strict new-asset scoring on.

    Pre-fix this issued 1 + 8 + 8 = 17 queries (per-program loop, twice).
    Post-fix: 1 main + 1 batched new-asset + 1 batched enrichment = 3.
    """
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    now = int(time.time())
    for i in range(8):
        cur.execute(
            """INSERT INTO programs (platform, name, handle, offers_bounties,
               max_payout, first_seen_timestamp)
               VALUES ('Bugcrowd', ?, ?, 1, 1000, ?)""",
            (f"Program {i}", f"prog-{i}", now - 200 * 86400),
        )
        cur.execute(
            """INSERT INTO assets (program_id, asset_identifier, asset_type,
               is_wildcard, first_seen_timestamp,
               official_first_seen_timestamp)
               VALUES (?, ?, 'URL', 0, ?, ?)""",
            (
                cur.lastrowid,
                f"new{i}.example.com",
                now - 200 * 86400,
                now - 2 * 86400,
            ),
        )
    conn.commit()
    conn.close()
    real_conn = sqlite3.connect(str(db_path))
    real_conn.row_factory = sqlite3.Row
    counter = [0]

    def _counting_db():
        return _CountingConn(real_conn, counter)

    monkeypatch.setattr(scan4me, "get_db", _counting_db)
    cfg = _eval_config(bugcrowd=True)
    cfg["filters"]["freshness_and_competition"] = {
        "prefer_new_assets": True,
        "strict_new_assets": True,
        "new_asset_days": 30,
    }
    results = scan4me.evaluate_targets(cfg)
    real_conn.close()

    assert len(results) == 8
    assert all(p["new_assets"] == 1 for p in results)
    assert counter[0] == 3


# ── P6: scoring composite unchanged ───────────────────────────────────────────


def _seed_scoring_fixture(cur, now):
    day = 86400
    cur.execute(
        """INSERT INTO programs (platform, name, handle, url, offers_bounties,
           managed_triage, first_response_hours, bounty_awarded_hours,
           response_efficiency, max_payout, currency, first_seen_timestamp,
           last_updated_timestamp, program_kind)
           VALUES ('HackerOne', 'Fast Corp', 'fast-corp',
           'https://hackerone.com/fast-corp', 1, 1, 10.0, 100.0, 90.0,
           50000, 'USD', ?, ?, 'web2')""",
        (now - 200 * day, now),
    )
    h1 = cur.lastrowid
    for i in range(20):
        cur.execute(
            """INSERT INTO assets (program_id, asset_identifier, asset_type,
               is_wildcard, first_seen_timestamp)
               VALUES (?, ?, 'URL', 0, ?)""",
            (h1, f"host{i}.fast.example.com", now - 200 * day),
        )
    for i in range(5):
        cur.execute(
            """INSERT INTO assets (program_id, asset_identifier, asset_type,
               is_wildcard, first_seen_timestamp)
               VALUES (?, ?, 'URL', 1, ?)""",
            (h1, f"*.wild{i}.fast.example.com", now - 200 * day),
        )
    for i in range(2):
        cur.execute(
            """INSERT INTO assets (program_id, asset_identifier, asset_type,
               is_wildcard, first_seen_timestamp)
               VALUES (?, ?, 'URL', 0, ?)""",
            (h1, f"new{i}.fast.example.com", now - 5 * day),
        )

    cur.execute(
        """INSERT INTO programs (platform, name, handle, url, offers_bounties,
           max_payout, currency, first_seen_timestamp, last_updated_timestamp,
           official_start_timestamp, rewarded_vulnerabilities, validation_days,
           average_payout, program_kind)
           VALUES ('Bugcrowd', 'Enriched Inc', 'enriched-inc',
           'https://bugcrowd.com/enriched-inc', 1, 10000, 'USD', ?, ?, ?,
           10, 5.0, 1000.0, 'web2')""",
        (now - 200 * day, now, now - 10 * day),
    )
    bc = cur.lastrowid
    for i in range(6):
        cur.execute(
            """INSERT INTO assets (program_id, asset_identifier, asset_type,
               is_wildcard, first_seen_timestamp)
               VALUES (?, ?, 'URL', 0, ?)""",
            (bc, f"app{i}.enriched.example.com", now - 200 * day),
        )
    for i in range(2):
        cur.execute(
            """INSERT INTO assets (program_id, asset_identifier, asset_type,
               is_wildcard, first_seen_timestamp)
               VALUES (?, ?, 'URL', 1, ?)""",
            (bc, f"*.w{i}.enriched.example.com", now - 200 * day),
        )
    cur.execute(
        """INSERT INTO assets (program_id, asset_identifier, asset_type,
           is_wildcard, first_seen_timestamp, official_first_seen_timestamp)
           VALUES (?, 'fresh.enriched.example.com', 'URL', 0, ?, ?)""",
        (bc, now - 200 * day, now - 3 * day),
    )

    cur.execute(
        """INSERT INTO programs (platform, name, handle, url, offers_bounties,
           max_payout, currency, first_seen_timestamp, last_updated_timestamp,
           program_kind)
           VALUES ('Intigriti', 'Small Shop', 'small-shop',
           'https://intigriti.com/small-shop', 1, 0, 'USD', ?, ?, 'web2')""",
        (now - 400 * day, now),
    )
    iw = cur.lastrowid
    for i in range(2):
        cur.execute(
            """INSERT INTO assets (program_id, asset_identifier, asset_type,
               is_wildcard, first_seen_timestamp)
               VALUES (?, ?, 'URL', 0, ?)""",
            (iw, f"srv{i}.small.example.com", now - 400 * day),
        )


def test_p6_scoring_composite_unchanged(tmp_path, monkeypatch):
    """Composite scores pinned to values captured before the P6 batching edit.

    Any change to the scoring math or the batched new-asset counts breaks this.
    """
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    _seed_scoring_fixture(conn.cursor(), int(time.time()))
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)

    cfg = _eval_config(hackerone=True, bugcrowd=True, intigriti=True)
    cfg["filters"]["freshness_and_competition"] = {
        "prefer_new_assets": True,
        "new_asset_days": 30,
        "prefer_new_companies": True,
        "new_company_days": 90,
    }
    results = scan4me.evaluate_targets(cfg)

    got = [
        (
            p["name"],
            p["platform"],
            p["score"],
            p["speed_score"],
            p["surface_score"],
            p["fresh_score"],
            p["payout_score"],
            p["assets"],
            p["wildcards"],
            p["new_assets"],
            p["surface_tier"],
        )
        for p in results
    ]
    assert got == [
        (
            "Fast Corp",
            "HackerOne",
            86.2,
            100.0,
            85.0,
            65.0,
            85.0,
            27,
            5,
            2,
            "⚡ WIDE SURFACE",
        ),
        (
            "Enriched Inc",
            "Bugcrowd",
            76.8,
            70.0,
            70.0,
            100.0,
            75.0,
            9,
            2,
            1,
            "🎯 MODERATE",
        ),
        (
            "Small Shop",
            "Intigriti",
            44.8,
            50.0,
            25.0,
            50.0,
            65.0,
            2,
            0,
            0,
            "🔍 NARROW/FOCUSED",
        ),
    ]
