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
    # #4: output is canonicalized (lowercased, scheme/path/port stripped).
    assert scan4me.clean_asset_identifier("  *.Example.COM/ ") == "example.com"
    assert scan4me.clean_asset_identifier("https://Sub.X.com:8443/a?b=1") == "sub.x.com"
    assert scan4me.clean_asset_identifier("http://*.innov8.work") == "innov8.work"


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

    # Resync: one kept (timestamp preserved), one added, one stale
    # (TOMBSTONED — retained with deleted_timestamp, hidden from live scope).
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
    live_rows = {
        r["asset_identifier"]: r["first_seen_timestamp"]
        for r in cur.execute(
            "SELECT asset_identifier, first_seen_timestamp FROM assets"
            " WHERE deleted_timestamp=0"
        )
    }
    assert live_rows == {"*.example.com": 1000, "new.example.com": 2000}
    tomb = cur.execute(
        "SELECT asset_identifier, first_seen_timestamp, deleted_timestamp"
        " FROM assets WHERE asset_identifier='old.example.com'"
    ).fetchone()
    assert tomb is not None  # not hard-deleted
    assert tomb["first_seen_timestamp"] == 1000  # first-seen evidence kept
    assert tomb["deleted_timestamp"] == 2000  # tombstone stamped
    conn.close()


def test_sync_truncation_tombstones_and_resurrects(tmp_path):
    """Hole #11 truncation-safety: a truncated feed tombstones scope instead of
    wiping it, and a restored feed resurrects rows with first-seen intact."""
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO programs (platform, name, handle) VALUES (?, ?, ?)",
        ("HackerOne", "Example", "example"),
    )
    program_id = cur.lastrowid
    conn.commit()

    full = [
        {"asset_identifier": "a.example.com", "asset_type": "URL"},
        {"asset_identifier": "b.example.com", "asset_type": "URL"},
    ]
    scan4me.sync_assets(cur, program_id, full, "asset_identifier", "asset_type", 1000)
    conn.commit()

    # Truncated feed: only one asset survives.
    scan4me.sync_assets(
        cur,
        program_id,
        [{"asset_identifier": "a.example.com", "asset_type": "URL"}],
        "asset_identifier",
        "asset_type",
        2000,
    )
    conn.commit()
    live = [
        r["asset_identifier"]
        for r in cur.execute(
            "SELECT asset_identifier FROM assets WHERE deleted_timestamp=0"
        )
    ]
    assert live == ["a.example.com"]
    tomb = cur.execute(
        "SELECT first_seen_timestamp, deleted_timestamp FROM assets"
        " WHERE asset_identifier='b.example.com'"
    ).fetchone()
    assert (tomb["first_seen_timestamp"], tomb["deleted_timestamp"]) == (1000, 2000)

    # Feed restored: resurrection keeps the ORIGINAL first-seen.
    scan4me.sync_assets(cur, program_id, full, "asset_identifier", "asset_type", 3000)
    conn.commit()
    rows = {
        r["asset_identifier"]: (
            r["first_seen_timestamp"],
            r["deleted_timestamp"],
        )
        for r in cur.execute("SELECT * FROM assets")
    }
    assert rows == {
        "a.example.com": (1000, 0),
        "b.example.com": (1000, 0),
    }
    conn.close()


def test_sync_assets_stores_eligibility_flags(tmp_path):
    """Hole #3: H1-style eligibility flags stored verbatim; feeds without the
    keys default to eligible (unknown != forbidden)."""
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
            {
                "asset_identifier": "ok.example.com",
                "asset_type": "URL",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "instruction": "",
                "max_severity": "critical",
            },
            {
                "asset_identifier": "nope.example.com",
                "asset_type": "URL",
                "eligible_for_bounty": False,
                "eligible_for_submission": False,
                "instruction": "Do not test",
                "max_severity": "none",
            },
            # No eligibility keys (Bugcrowd-style) -> defaults to eligible.
            {"asset_identifier": "plain.example.com", "asset_type": "URL"},
        ],
        "asset_identifier",
        "asset_type",
        1000,
    )
    conn.commit()
    rows = {
        r["asset_identifier"]: r
        for r in cur.execute(
            "SELECT asset_identifier, eligible_for_bounty,"
            " eligible_for_submission, instruction, max_severity FROM assets"
            " WHERE deleted_timestamp=0"
        )
    }
    assert rows["ok.example.com"]["eligible_for_bounty"] == 1
    assert rows["ok.example.com"]["eligible_for_submission"] == 1
    assert rows["ok.example.com"]["max_severity"] == "critical"
    assert rows["nope.example.com"]["eligible_for_bounty"] == 0
    assert rows["nope.example.com"]["eligible_for_submission"] == 0
    assert rows["nope.example.com"]["instruction"] == "Do not test"
    assert rows["plain.example.com"]["eligible_for_bounty"] == 1
    assert rows["plain.example.com"]["eligible_for_submission"] == 1
    conn.close()


def test_sync_oos_assets_stored_and_tombstoned(tmp_path):
    """Hole #3: out-of-scope identifiers persist (tombstoned, never deleted)."""
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO programs (platform, name, handle) VALUES (?, ?, ?)",
        ("Bugcrowd", "Example", "example"),
    )
    program_id = cur.lastrowid
    conn.commit()

    scan4me.sync_oos_assets(
        cur,
        program_id,
        [
            {"target": "oos1.example.com", "type": "website"},
            {"target": "oos2.example.com", "type": "website"},
        ],
        "target",
        "type",
        1000,
    )
    conn.commit()
    live = [
        r["asset_identifier"]
        for r in cur.execute(
            "SELECT asset_identifier FROM oos_assets WHERE deleted_timestamp=0"
        )
    ]
    assert sorted(live) == ["oos1.example.com", "oos2.example.com"]

    scan4me.sync_oos_assets(
        cur,
        program_id,
        [{"target": "oos1.example.com", "type": "website"}],
        "target",
        "type",
        2000,
    )
    conn.commit()
    live = [
        r["asset_identifier"]
        for r in cur.execute(
            "SELECT asset_identifier FROM oos_assets WHERE deleted_timestamp=0"
        )
    ]
    assert live == ["oos1.example.com"]
    tomb = cur.execute(
        "SELECT first_seen_timestamp, deleted_timestamp FROM oos_assets"
        " WHERE asset_identifier='oos2.example.com'"
    ).fetchone()
    assert (tomb["first_seen_timestamp"], tomb["deleted_timestamp"]) == (1000, 2000)
    conn.close()


def test_sync_program_scope_skips_absent_sides(tmp_path):
    """Feeds omitting out_of_scope (auth fetchers) must not wipe OOS rows;
    entries missing scope entirely must not wipe scope."""
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO programs (platform, name, handle) VALUES (?, ?, ?)",
        ("HackerOne", "Example", "example"),
    )
    program_id = cur.lastrowid
    conn.commit()

    entry = {
        "targets": {
            "in_scope": [{"asset_identifier": "a.example.com", "asset_type": "URL"}],
            "out_of_scope": [
                {"asset_identifier": "oos.example.com", "asset_type": "URL"}
            ],
        }
    }
    scan4me._sync_program_scope(
        cur, program_id, entry, "asset_identifier", "asset_type", 1000
    )
    conn.commit()

    # Auth-style entry: in_scope only -> OOS rows untouched.
    scan4me._sync_program_scope(
        cur,
        program_id,
        {"targets": {"in_scope": []}},
        "asset_identifier",
        "asset_type",
        2000,
    )
    conn.commit()
    assert (
        cur.execute(
            "SELECT count(*) FROM oos_assets WHERE deleted_timestamp=0"
        ).fetchone()[0]
        == 1
    )
    # Malformed entry: no targets at all -> scope untouched (tombstones nothing).
    scan4me._sync_program_scope(
        cur, program_id, {"handle": "example"}, "asset_identifier", "asset_type", 3000
    )
    conn.commit()
    assert (
        cur.execute(
            "SELECT count(*) FROM assets WHERE deleted_timestamp=0"
        ).fetchone()[0]
        == 0  # in_scope [] tombstoned the 1 asset above; malformed adds nothing
    )
    assert cur.execute("SELECT count(*) FROM assets").fetchone()[0] == 1
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


def _no_auth(monkeypatch, tmp_path):
    """Force the public-feed path: no env keys, no trio central keys."""
    for var in (
        "HACKERONE_USERNAME",
        "HACKERONE_API_TOKEN",
        "BUGCROWD_API_TOKEN",
        "INTIGRITI_API_TOKEN",
        "YESWEHACK_API_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(scan4me, "TRIO_KEYS_FILE", str(tmp_path / "no-keys.env"))


def _h1_entry(handle="acme"):
    return {
        "handle": handle,
        "name": "Acme",
        "url": f"https://hackerone.com/{handle}",
        "website": "https://acme.com",
        "offers_bounties": True,
        "managed_program": True,
        "targets": {
            "in_scope": [
                {
                    "asset_identifier": "app.acme.com",
                    "asset_type": "URL",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                    "instruction": "",
                    "max_severity": "critical",
                },
                {
                    "asset_identifier": "legacy.acme.com",
                    "asset_type": "URL",
                    "eligible_for_bounty": False,
                    "eligible_for_submission": False,
                    "instruction": "Out of scope soon",
                    "max_severity": "none",
                },
            ],
            "out_of_scope": [
                {"asset_identifier": "evil.acme.com", "asset_type": "URL"}
            ],
        },
    }


def _file_only_cfg(**overrides):
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
    cfg.update(overrides)
    return cfg


def test_sync_records_metadata_and_eligibility(tmp_path, monkeypatch):
    """Hole #5/#3 end of sync_data: upstream SHA + per-platform status land in
    sync_metadata; eligibility flags + OOS identifiers land in the DB."""
    _no_auth(monkeypatch, tmp_path)
    monkeypatch.setattr(scan4me, "CACHE_DATA_DIR", tmp_path / "cache")
    monkeypatch.setattr(scan4me, "DB_PATH", tmp_path / "t.db")
    _write_feed(tmp_path / "cache" / "data", "hackerone_data.json", [_h1_entry()])
    scan4me.sync_data(
        refresh=False, platforms_cfg=_file_only_cfg(hackerone=True), config={}
    )

    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    try:
        meta = {
            r["key"]: r["value"]
            for r in conn.execute("SELECT key, value FROM sync_metadata")
        }
        assert meta["upstream_sha"].startswith("unknown (no upstream checkout)")
        assert meta["last_refresh_ok"] == "1"
        assert int(meta["last_sync_ts"]) > 0
        status = json.loads(meta["platform_status"])
        assert status["hackerone"]["status"] == "ok"
        assert status["hackerone"]["count"] == 1
        assert status["hackerone"]["source"] == "public-file"
        assert status["bugcrowd"]["status"] == "skipped"
        assert status["pd_programs"]["status"] == "skipped"

        flags = {
            r["asset_identifier"]: (
                r["eligible_for_bounty"],
                r["eligible_for_submission"],
            )
            for r in conn.execute(
                "SELECT asset_identifier, eligible_for_bounty,"
                " eligible_for_submission FROM assets WHERE deleted_timestamp=0"
            )
        }
        assert flags == {"app.acme.com": (1, 1), "legacy.acme.com": (0, 0)}
        oos = [
            r["asset_identifier"]
            for r in conn.execute(
                "SELECT asset_identifier FROM oos_assets WHERE deleted_timestamp=0"
            )
        ]
        assert oos == ["evil.acme.com"]
    finally:
        conn.close()


def test_failed_refresh_keeps_timestamps(tmp_path, monkeypatch):
    """Hole #5: a failed `git pull` uses the cached snapshot WITHOUT bumping
    last_updated_timestamp, and records the failure in sync_metadata."""
    import subprocess as _sp

    _no_auth(monkeypatch, tmp_path)
    monkeypatch.setattr(scan4me, "CACHE_DATA_DIR", tmp_path / "cache")
    monkeypatch.setattr(scan4me, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(scan4me.shutil, "which", lambda _b: "/usr/bin/git")

    repo_data = tmp_path / "cache" / "repo" / "data"
    _write_feed(repo_data, "hackerone_data.json", [_h1_entry()])
    (tmp_path / "cache" / "repo" / ".git").mkdir(parents=True)

    def _fake_run(cmd, **kwargs):
        if "rev-parse" in cmd:
            return types.SimpleNamespace(stdout="abc1234\n", stderr="", returncode=0)
        raise _sp.CalledProcessError(128, cmd, output="", stderr="pull failed")

    monkeypatch.setattr(scan4me.subprocess, "run", _fake_run)

    # Seed one existing program with an old stamp (past baseline so the
    # baseline pass doesn't rewrite first_seen).
    conn = _temp_db(tmp_path / "t.db")
    conn.execute(
        "INSERT INTO programs (platform, name, handle, first_seen_timestamp,"
        " last_updated_timestamp) VALUES (?, ?, ?, ?, ?)",
        ("HackerOne", "Acme", "acme", 500, 1000),
    )
    conn.execute(
        "INSERT INTO sync_metadata(key, value) VALUES('baseline_complete', '1')"
    )
    conn.commit()
    conn.close()

    scan4me.sync_data(
        refresh=True, platforms_cfg=_file_only_cfg(hackerone=True), config={}
    )

    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT first_seen_timestamp, last_updated_timestamp FROM programs"
            " WHERE platform='HackerOne' AND handle='acme'"
        ).fetchone()
        assert row["first_seen_timestamp"] == 500
        assert row["last_updated_timestamp"] == 1000  # NOT bumped on stale data
        meta = {
            r["key"]: r["value"]
            for r in conn.execute("SELECT key, value FROM sync_metadata")
        }
        assert meta["last_refresh_ok"] == "0"
        assert meta["upstream_sha"] == "abc1234"
        assert "non-zero exit status 128" in meta["last_refresh_error"]
    finally:
        conn.close()


def test_platform_status_and_row_stamp_units():
    assert scan4me._platform_status(False, [1], "x")["status"] == "skipped"
    assert scan4me._platform_status(True, [], "authenticated", True)["status"] \
        == "auth_empty"
    assert scan4me._platform_status(True, [], "public-file")["status"] == "empty"
    ok = scan4me._platform_status(True, [1, 2], "public-file")
    assert (ok["status"], ok["count"]) == ("ok", 2)
    assert scan4me._row_last_updated(None, 2000, False) == 2000
    assert scan4me._row_last_updated((7, 500, 1000), 2000, True) == 2000
    assert scan4me._row_last_updated((7, 500, 1000), 2000, False) == 1000


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


# ── P5: Immunefi + PDPrograms feed repair ─────────────────────────────────────

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_p5_immunefi_parse_fixture():
    """Fixture (3 records cut from the live board page) parses exactly."""
    html = (FIXTURES / "immunefi_page_excerpt.html").read_text(encoding="utf-8")
    records = scan4me._parse_immunefi_page(html)
    assert [r["project"] for r in records] == [
        "LayerZero",
        "Paused Project",
        "Invite Only Project",
    ]
    programs = [scan4me._normalize_immunefi_record(r) for r in records]
    assert programs[0] == {
        "name": "LayerZero",
        "handle": "layerzero",
        "url": "https://immunefi.com/bug-bounty/layerzero/information/",
        "max_payout": 15000000.0,
        "currency": "USD",
        "offers_bounties": True,
        "assets": [],
    }
    # Paused and invite-only programs are kept but not actionable.
    assert programs[1]["offers_bounties"] is False
    assert programs[2]["offers_bounties"] is False
    assert scan4me._normalize_immunefi_record({"slug": "x"}) is None


def test_p5_immunefi_parse_garbage_returns_empty():
    assert scan4me._parse_immunefi_page("<html>no payload here</html>") == []
    assert scan4me._parse_immunefi_page('"bounties\\":[') == []
    assert scan4me._parse_immunefi_page('"bounties\\":[not json') == []


class _FakeHTTPResp:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_p5_immunefi_fetch_uses_board_url(monkeypatch):
    """Fetcher hits IMMUNEFI_BOUNTIES_URL and normalizes the payload."""
    html = (FIXTURES / "immunefi_page_excerpt.html").read_bytes()
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["ua"] = req.get_header("User-agent")
        return _FakeHTTPResp(html)

    monkeypatch.setattr(scan4me.urllib.request, "urlopen", fake_urlopen)
    programs = scan4me._fetch_immunefi_programs()
    assert seen["url"] == scan4me.IMMUNEFI_BOUNTIES_URL
    assert seen["ua"] == "Scan4Me public bug-bounty metadata sync"
    assert len(programs) == 3
    assert programs[0]["handle"] == "layerzero"


def test_p5_immunefi_fetch_network_failure_soft_fails(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("network down")

    monkeypatch.setattr(scan4me.urllib.request, "urlopen", boom)
    assert scan4me._fetch_immunefi_programs() == []


def test_p5_pd_load_prefers_dist_json(tmp_path):
    repo = tmp_path / "pd"
    (repo / "dist").mkdir(parents=True)
    (repo / "dist" / "data.json").write_text(
        json.dumps(
            {
                "programs": [
                    {
                        "name": "Json Corp",
                        "url": "https://example.com/sec",
                        "bounty": True,
                        "domains": ["example.com"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    # A stale yaml must NOT shadow dist/data.json.
    (repo / "src").mkdir()
    (repo / "src" / "data.yaml").write_text(
        "programs:\n  - name: Yaml Corp\n", encoding="utf-8"
    )
    programs = scan4me._load_pd_programs(repo)
    assert [p["name"] for p in programs] == ["Json Corp"]


def test_p5_pd_load_yaml_fallback(tmp_path):
    repo = tmp_path / "pd"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "data.yaml").write_text(
        "programs:\n"
        "  - name: Yaml Corp\n"
        "    url: https://example.com/sec\n"
        "    bounty: false\n"
        "    domains:\n"
        "      - example.com\n",
        encoding="utf-8",
    )
    programs = scan4me._load_pd_programs(repo)
    assert [p["name"] for p in programs] == ["Yaml Corp"]


def test_p5_pd_load_missing_returns_empty(tmp_path):
    assert scan4me._load_pd_programs(tmp_path / "empty") == []


def test_p5_sync_indexes_immunefi_and_pd(tmp_path, monkeypatch):
    """End-to-end sync wiring: Immunefi page + PD checkout → program rows."""
    cache = tmp_path / "cache"
    (cache / "repo" / "data").mkdir(parents=True)
    pd_repo = cache / "pd_programs_repo"
    (pd_repo / ".git").mkdir(parents=True)
    (pd_repo / "dist").mkdir(parents=True)
    (pd_repo / "dist" / "data.json").write_text(
        json.dumps(
            {
                "programs": [
                    {
                        "name": "PD Corp",
                        "url": "https://hackerone.com/pdcorp",
                        "bounty": True,
                        "domains": ["pdcorp.com", "*.pdcorp.com"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(scan4me, "CACHE_DATA_DIR", cache)
    monkeypatch.setattr(scan4me, "DB_PATH", tmp_path / "t.db")
    monkeypatch.setattr(
        scan4me.subprocess, "run", lambda *a, **k: None
    )  # git pull/clone → no-op
    html = (FIXTURES / "immunefi_page_excerpt.html").read_bytes()
    monkeypatch.setattr(
        scan4me.urllib.request,
        "urlopen",
        lambda req, timeout=None: _FakeHTTPResp(html),
    )
    cfg = {
        "hackerone": False,
        "bugcrowd": False,
        "intigriti": False,
        "yeswehack": False,
        "federacy": False,
        "immunefi": True,
        "sherlock": False,
        "pd_programs": True,
    }
    scan4me.sync_data(refresh=True, platforms_cfg=cfg, config={})
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.row_factory = sqlite3.Row
    try:
        imm = conn.execute(
            "SELECT handle, max_payout, offers_bounties FROM programs"
            " WHERE platform='Immunefi' ORDER BY handle"
        ).fetchall()
        assert [tuple(r) for r in imm] == [
            ("invite-only-project", 15000000.0, 0),
            ("layerzero", 15000000.0, 1),
            ("paused-project", 15000000.0, 0),
        ]
        pd = conn.execute(
            "SELECT name, offers_bounties FROM programs WHERE platform='PDPrograms'"
        ).fetchall()
        assert [tuple(r) for r in pd] == [("PD Corp", 1)]
        assets = conn.execute(
            "SELECT asset_identifier, is_wildcard FROM assets ORDER BY asset_identifier"
        ).fetchall()
        assert [tuple(r) for r in assets] == [
            ("*.pdcorp.com", 1),
            ("pdcorp.com", 0),
        ]
    finally:
        conn.close()


# ── P5: authenticated API paths (mocked transport, recorded contract) ─────────
# Live-run recipe (keys + expected counts) lives in P5_LIVE_SYNC_RECIPE.md.


def test_p5_h1_authenticated_pagination_and_auth(monkeypatch):
    calls = []

    def fake_api(url, **kw):
        calls.append((url, kw))
        if "number%5D=1" in url:
            return {
                "data": [
                    {
                        "attributes": {
                            "handle": "acme",
                            "name": "Acme",
                            "offers_bounties": True,
                            "structured_scopes": [
                                {
                                    "asset_identifier": "acme.com",
                                    "asset_type": "URL",
                                    "eligible_for_submission": True,
                                },
                                {
                                    "asset_identifier": "internal.acme.com",
                                    "asset_type": "URL",
                                    "eligible_for_submission": False,
                                },
                            ],
                        }
                    }
                ],
                "links": {
                    "next": "https://api.hackerone.com/v1/hackers/programs?page=2"
                },
            }
        return {"data": [{"attributes": {"handle": "beta"}}], "links": {}}

    monkeypatch.setattr(scan4me, "_api_request", fake_api)
    programs = scan4me._fetch_h1_authenticated("user", "tok")
    assert len(calls) == 2  # followed the `next` link exactly once
    assert all(kw["auth_basic"] == ("user", "tok") for _, kw in calls)
    assert calls[0][0].startswith(f"{scan4me.H1_API_BASE}/hackers/programs")
    assert programs[0]["handle"] == "acme"
    assert programs[0]["url"] == "https://hackerone.com/acme"
    # Only eligible scopes become targets.
    assert programs[0]["targets"]["in_scope"] == [
        {"asset_identifier": "acme.com", "asset_type": "URL"}
    ]
    assert programs[1]["handle"] == "beta"


def test_p5_h1_authenticated_failure_soft_fails(monkeypatch):
    def boom(url, **kw):
        raise OSError("bad credentials")

    monkeypatch.setattr(scan4me, "_api_request", boom)
    assert scan4me._fetch_h1_authenticated("user", "bad") == []


def test_p5_bugcrowd_authenticated(monkeypatch):
    calls = []

    def fake_api(url, **kw):
        calls.append((url, kw))
        return {
            "data": [
                {
                    "attributes": {
                        "name": "BC Corp",
                        "code": "bccorp",
                        "url": "/bccorp",
                        "max_payout": 5000,
                        "targets": {
                            "in_scope": [{"target": "bccorp.com", "type": "website"}]
                        },
                    }
                }
            ]
        }

    monkeypatch.setattr(scan4me, "_api_request", fake_api)
    programs = scan4me._fetch_bugcrowd_authenticated("tok")
    assert len(calls) == 1  # <25 items → single page
    assert calls[0][0].startswith(f"{scan4me.BUGCROWD_API_BASE}/engagements")
    assert calls[0][1]["token_header"] == "tok"
    assert programs[0]["url"] == "https://bugcrowd.com/bccorp"
    assert programs[0]["max_payout"] == 5000.0


def test_p5_intigriti_authenticated(monkeypatch):
    calls = []

    def fake_api(url, **kw):
        calls.append((url, kw))
        return {
            "records": [
                {
                    "handle": "inticorp",
                    "name": "Inti Corp",
                    "maxBounty": {"value": 10000, "currency": "EUR"},
                    "domains": [{"endpoint": "inticorp.com", "type": "url"}],
                }
            ],
            "total": 1,
        }

    monkeypatch.setattr(scan4me, "_api_request", fake_api)
    programs = scan4me._fetch_intigriti_authenticated("tok")
    assert len(calls) == 1
    assert "/researcher/programs" in calls[0][0]
    assert calls[0][1]["bearer"] == "tok"
    assert programs[0]["max_bounty"] == {"value": 10000.0, "currency": "EUR"}
    assert programs[0]["targets"]["in_scope"] == [
        {"endpoint": "inticorp.com", "type": "url"}
    ]


def test_p5_yeswehack_authenticated(monkeypatch):
    calls = []

    def fake_api(url, **kw):
        calls.append((url, kw))
        return {
            "items": [
                {
                    "slug": "ywhcorp",
                    "title": "YWH Corp",
                    "scope": [{"scope": "ywhcorp.com", "type": "web"}],
                }
            ],
            "pagination": {"nb_pages": 1},
        }

    monkeypatch.setattr(scan4me, "_api_request", fake_api)
    programs = scan4me._fetch_yeswehack_authenticated("tok")
    assert len(calls) == 1
    assert calls[0][0].startswith(f"{scan4me.YESWEHACK_API_BASE}/programs")
    assert calls[0][1]["bearer"] == "tok"
    # Auth normalizer emits the same target/type keys as the public feed (#4).
    assert programs[0]["targets"]["in_scope"] == [
        {"target": "ywhcorp.com", "type": "web"}
    ]


def test_p5_api_request_auth_headers(monkeypatch):
    seen = {}

    class _JsonResp:
        def read(self):
            return '{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        seen["auth"] = req.get_header("Authorization")
        return _JsonResp()

    monkeypatch.setattr(scan4me.urllib.request, "urlopen", fake_urlopen)
    scan4me._api_request("https://x.test", auth_basic=("u", "t"))
    import base64

    assert seen["auth"] == "Basic " + base64.b64encode(b"u:t").decode()
    scan4me._api_request("https://x.test", bearer="tok")
    assert seen["auth"] == "Bearer tok"
    scan4me._api_request("https://x.test", token_header="tok")
    assert seen["auth"] == "Token tok"


# ── #4 feed normalizer ──────────────────────────────────────────────────────


def test_normalizer_canonicalizes_types():
    cases = {
        "URL": "url",
        "url": "url",
        "website": "url",
        "WILDCARD": "wildcard",
        "wildcard": "wildcard",
        "OTHER": "other",
        "other": "other",
        "api": "api",
        "API": "api",
        "android": "android_app",
        "GOOGLE_PLAY_APP_ID": "android_app",
        "ios": "ios_app",
        "APPLE_STORE_APP_ID": "ios_app",
        "IP_ADDRESS": "cidr",
        "iprange": "cidr",
        "CIDR": "cidr",
        "web-application": "url",
        "SmartContract": "smart_contract",
        "SOURCE_CODE": "source_code",
        "DOWNLOADABLE_EXECUTABLES": "executable",
        "bogus-type": "other",
        "": "other",
        None: "other",
    }
    for raw, want in cases.items():
        assert scan4me.canonicalize_asset_type(raw) == want, raw


def test_normalizer_strips_scheme_path_port():
    ident, atype, wild, ok = scan4me.canonicalize_asset(
        "https://Sub.X.com:8443/a?b=1", "website"
    )
    assert (ident, atype, wild, ok) == ("sub.x.com", "url", 0, True)
    ident, atype, wild, ok = scan4me.canonicalize_asset(
        "http://*.innov8.work", "WILDCARD"
    )
    assert (ident, atype, wild, ok) == ("*.innov8.work", "wildcard", 1, True)
    ident, atype, wild, ok = scan4me.canonicalize_asset("*-vpn.8x8.com", "wildcard")
    assert (ident, atype, wild, ok) == ("*-vpn.8x8.com", "wildcard", 1, True)


def test_normalizer_rejects_non_hosts():
    assert scan4me.canonicalize_asset("all", "url")[3] is False
    assert scan4me.canonicalize_asset("Any resource created by the hunter", "other")[3] is False
    assert scan4me.canonicalize_asset("", "url")[3] is False
    assert scan4me.canonicalize_asset("mid*dle.com", "url")[3] is False
    assert scan4me.canonicalize_asset("not a cidr", "CIDR")[3] is False


def test_normalizer_keeps_cidr_and_app_ids():
    assert scan4me.canonicalize_asset("10.0.0.0/8", "iprange") == (
        "10.0.0.0/8", "cidr", 0, True,
    )
    assert scan4me.canonicalize_asset("1.2.3.4", "IP_ADDRESS") == (
        "1.2.3.4", "cidr", 0, True,
    )
    ident, atype, wild, ok = scan4me.canonicalize_asset(
        "com.example.app", "GOOGLE_PLAY_APP_ID"
    )
    assert (ident, atype, wild, ok) == ("com.example.app", "android_app", 0, True)


def test_scope_match_scheme_prefixed_wildcard():
    assert scan4me.scope_match("a.innov8.work", "http://*.innov8.work", True) is True
    assert scan4me.scope_match("innov8.work", "http://*.innov8.work", True) is False
    assert scan4me.scope_match("x.evilinnov8.work", "http://*.innov8.work", True) is False
    assert scan4me.scope_match("sub.x.com", "https://sub.x.com/login", 0) is True


def test_sync_assets_normalizes_and_counts_rejects(tmp_path):
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO programs (platform, name, handle) VALUES (?, ?, ?)",
        ("YesWeHack", "YWH", "ywh"),
    )
    program_id = cur.lastrowid
    conn.commit()
    stats = {}
    scan4me.sync_assets(
        cur,
        program_id,
        [
            {"target": "https://cockpit.outscale.com/", "type": "web-application"},
            {"target": "Any resource created by the hunter", "type": "other"},
            {"target": "all", "type": "url"},
            {"target": "10.1.0.0/16", "type": "iprange"},
        ],
        "target",
        "type",
        1000,
        stats=stats,
    )
    conn.commit()
    rows = cur.execute(
        "SELECT asset_identifier, asset_type FROM assets WHERE program_id=?",
        (program_id,),
    ).fetchall()
    got = sorted((r["asset_identifier"], r["asset_type"]) for r in rows)
    assert got == [
        ("10.1.0.0/16", "cidr"),
        ("cockpit.outscale.com", "url"),
    ]
    assert stats["rejected"] == 2


# ── #10 dead flags wired + velocity scorer ───────────────────────────────────


def _scored_names(cfg, db_path, monkeypatch):
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)
    return scan4me.evaluate_targets(cfg)


def _flag_db(tmp_path):
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    _seed_scoring_fixture(conn.cursor(), int(time.time()))
    conn.commit()
    conn.close()
    return db_path


def test_min_max_payout_usd_filters_known_ceilings(tmp_path, monkeypatch):
    db_path = _flag_db(tmp_path)
    cfg = _eval_config(hackerone=True, bugcrowd=True)
    cfg["filters"]["payouts"] = {"min_max_payout_usd": 20000.0}
    names = [p["name"] for p in _scored_names(cfg, db_path, monkeypatch)]
    # Fast Corp ($50k) stays; Enriched Inc ($10k) drops.
    assert "Fast Corp" in names
    assert "Enriched Inc" not in names


def test_min_max_payout_usd_ignores_unknown_ceilings(tmp_path, monkeypatch):
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    now = int(time.time())
    cur.execute(
        "INSERT INTO programs (platform, name, handle, offers_bounties,"
        " max_payout, first_seen_timestamp, program_kind)"
        " VALUES ('HackerOne', 'Unknown Pay', 'unknown-pay', 1, 0, ?, 'web2')",
        (now,),
    )
    pid = cur.lastrowid
    cur.execute(
        "INSERT INTO assets (program_id, asset_identifier, asset_type,"
        " is_wildcard, first_seen_timestamp) VALUES (?, 'u.example.com', 'url', 0, ?)",
        (pid, now),
    )
    conn.commit()
    conn.close()
    cfg = _eval_config(hackerone=True)
    cfg["filters"]["payouts"] = {"min_max_payout_usd": 1000000.0}
    names = [p["name"] for p in _scored_names(cfg, db_path, monkeypatch)]
    assert names == ["Unknown Pay"]


def test_prefer_managed_triage_bonus(tmp_path, monkeypatch):
    db_path = _flag_db(tmp_path)
    base = _eval_config(hackerone=True)
    # Suppress the +15 bounty bonus (would cap at 100 and hide the +5).
    base["filters"]["payouts"] = {"prioritize_fast_cash": False}
    plain = {p["name"]: p["speed_score"] for p in _scored_names(base, db_path, monkeypatch)}
    cfg = _eval_config(hackerone=True)
    cfg["filters"]["payouts"] = {"prioritize_fast_cash": False}
    cfg["filters"]["fast_triage"]["prefer_managed_triage"] = True
    bonus = {p["name"]: p["speed_score"] for p in _scored_names(cfg, db_path, monkeypatch)}
    # Fast Corp is managed → +5; others unchanged.
    assert bonus["Fast Corp"] == plain["Fast Corp"] + 5


def test_bounty_award_tiers_follow_config(tmp_path, monkeypatch):
    db_path = _flag_db(tmp_path)
    cfg = _eval_config(hackerone=True)
    cfg["filters"]["fast_triage"]["max_time_to_bounty_awarded_hours"] = 100.0
    got = {p["name"]: p["speed_score"] for p in _scored_names(cfg, db_path, monkeypatch)}
    # Fast Corp bounty_awarded_hours=100: old tiers (168/336) gave +15;
    # configured tiers (50/100) give +8 (100 <= 100, tier 2).
    assert got["Fast Corp"] == 100 - 10.0 * 1.5 + 8


def test_prioritize_fast_cash_gates_bonuses(tmp_path, monkeypatch):
    db_path = _flag_db(tmp_path)
    cfg = _eval_config(hackerone=True, bugcrowd=True)
    cfg["filters"]["payouts"] = {"prioritize_fast_cash": False}
    got = {p["name"]: p for p in _scored_names(cfg, db_path, monkeypatch)}
    assert got["Fast Corp"]["speed_score"] == 100 - 10.0 * 1.5  # no +15
    assert got["Enriched Inc"]["speed_score"] == 50.0  # no validation bonus
    assert got["Enriched Inc"]["payout_score"] == 70.0  # no avg-payout +5


def test_prioritize_wildcards_and_surface_flags(tmp_path, monkeypatch):
    db_path = _flag_db(tmp_path)
    cfg = _eval_config(hackerone=True)
    cfg["filters"]["attack_surface_and_scope"]["prioritize_wildcards"] = False
    got = {p["name"]: p["surface_score"] for p in _scored_names(cfg, db_path, monkeypatch)}
    # Fast Corp: 22 assets + 5 wildcards × 1.0 = 27 → 85.0 band.
    assert got["Fast Corp"] == 85.0
    cfg["filters"]["attack_surface_and_scope"]["prefer_large_attack_surface"] = False
    got = {p["name"]: p["surface_score"] for p in _scored_names(cfg, db_path, monkeypatch)}
    assert got["Fast Corp"] == 50.0


def test_freshness_flags_gate_bonuses(tmp_path, monkeypatch):
    db_path = _flag_db(tmp_path)
    cfg = _eval_config(bugcrowd=True)
    cfg["filters"]["freshness_and_competition"] = {
        "prefer_new_assets": True,
        "new_asset_days": 30,
        "prefer_new_companies": True,
        "new_company_days": 90,
        "prefer_fresh_programs": False,
    }
    got = {p["name"]: p["fresh_score"] for p in _scored_names(cfg, db_path, monkeypatch)}
    # Enriched Inc started 10d ago → base 100, no +20 rewarded bonus.
    assert got["Enriched Inc"] == 100.0
    cfg["filters"]["freshness_and_competition"]["prefer_fresh_programs"] = True
    cfg["filters"]["freshness_and_competition"]["low_report_saturation"] = False
    got = {p["name"]: p["fresh_score"] for p in _scored_names(cfg, db_path, monkeypatch)}
    assert got["Enriched Inc"] == 100.0  # capped; rewarded +20 suppressed
    # Saturation gate visible on an old program: seed one without newness.
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    now = int(time.time())
    cur.execute(
        "INSERT INTO programs (platform, name, handle, offers_bounties,"
        " max_payout, first_seen_timestamp, rewarded_vulnerabilities, program_kind)"
        " VALUES ('Bugcrowd', 'Old Corp', 'old-corp', 1, 5000, ?, 10, 'web2')",
        (now - 200 * 86400,),
    )
    pid = cur.lastrowid
    cur.execute(
        "INSERT INTO assets (program_id, asset_identifier, asset_type,"
        " is_wildcard, first_seen_timestamp) VALUES (?, 'o.example.com', 'url', 0, ?)",
        (pid, now - 200 * 86400),
    )
    conn.commit()
    conn.close()
    sat_cfg = _eval_config(bugcrowd=True)
    sat_cfg["filters"]["freshness_and_competition"] = {"low_report_saturation": True}
    on = {p["name"]: p["fresh_score"] for p in _scored_names(sat_cfg, db_path, monkeypatch)}
    sat_cfg["filters"]["freshness_and_competition"]["low_report_saturation"] = False
    off = {p["name"]: p["fresh_score"] for p in _scored_names(sat_cfg, db_path, monkeypatch)}
    assert on["Old Corp"] - off["Old Corp"] == 20


def test_strict_validation_days_excludes_undated(tmp_path, monkeypatch):
    db_path = _flag_db(tmp_path)
    cfg = _eval_config(bugcrowd=True)
    cfg["filters"]["fast_triage"]["strict_validation_days"] = True
    names = [p["name"] for p in _scored_names(cfg, db_path, monkeypatch)]
    # Enriched Inc has validation_days=5 → stays; undated Bugcrowd rows drop.
    assert "Enriched Inc" in names


def test_velocity_scorer_measured_and_estimated():
    pph, score, est = scan4me.score_payout_velocity(
        {
            "average_payout": 1000.0,
            "max_payout": 10000,
            "first_resp": 10.0,
            "validation_days": None,
            "payout_score": 70.0,
            "speed_score": 85.0,
        }
    )
    assert pph == 100.0
    assert est is False
    assert score == round(min(100.0, 20.0 * __import__("math").log10(101.0)), 1)
    pph, score, est = scan4me.score_payout_velocity(
        {
            "average_payout": 0,
            "max_payout": 0,
            "first_resp": None,
            "validation_days": None,
            "payout_score": 65.0,
            "speed_score": 50.0,
        }
    )
    assert pph is None
    assert est is True
    assert score == round((65.0 + 50.0) / 4.0, 1)


def test_evaluate_targets_emits_velocity_fields(tmp_path, monkeypatch):
    db_path = _flag_db(tmp_path)
    got = {p["name"]: p for p in _scored_names(_eval_config(hackerone=True), db_path, monkeypatch)}
    fast = got["Fast Corp"]
    assert fast["payout_per_hour_usd"] == 250.0  # 5% of $50k / 10h
    assert fast["velocity_estimated"] is False
    assert fast["velocity_score"] > 0


# ── #5/#9 provenance stamp ──────────────────────────────────────────────────


def test_feed_provenance_reports_sha_age_counts_gaps(tmp_path):
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    now = int(time.time())
    cur.execute(
        "INSERT INTO programs (platform, name, handle, offers_bounties,"
        " max_payout, first_seen_timestamp, program_kind)"
        " VALUES ('HackerOne', 'H', 'h', 1, 0, ?, 'web2')",
        (now,),
    )
    pid = cur.lastrowid
    cur.execute(
        "INSERT INTO assets (program_id, asset_identifier, asset_type,"
        " is_wildcard, first_seen_timestamp) VALUES (?, 'h.example.com', 'url', 0, ?)",
        (pid, now),
    )
    cur.execute(
        "INSERT INTO sync_metadata(key, value) VALUES('upstream_sha', 'abc123')"
    )
    cur.execute(
        "INSERT INTO sync_metadata(key, value) VALUES('last_sync_ts', ?)",
        (str(now - 10 * 3600),),
    )
    cur.execute(
        "INSERT INTO sync_metadata(key, value) VALUES('platform_status', ?)",
        (json.dumps({"hackerone": {"status": "ok", "count": 1},
                      "immunefi": {"status": "empty", "count": 0}}),),
    )
    conn.commit()
    prov = scan4me.feed_provenance(conn)
    conn.close()
    assert prov["upstream_sha"] == "abc123"
    assert prov["age_hours"] == 10.0
    assert prov["stale"] is False
    assert prov["row_counts"]["programs"] == 1
    assert prov["row_counts"]["live_assets"] == 1
    assert any("HackerOne payouts: 0/1" in g for g in prov["coverage_gaps"])
    assert any("rules/policy text" in g for g in prov["coverage_gaps"])
    assert any("immunefi" in g for g in prov["coverage_gaps"])


def test_feed_provenance_marks_stale_and_unknown(tmp_path):
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sync_metadata(key, value) VALUES('last_sync_ts', ?)",
        (str(int(time.time()) - 100 * 3600),),
    )
    conn.commit()
    prov = scan4me.feed_provenance(conn)
    conn.close()
    assert prov["upstream_sha"] == "unknown"
    assert prov["stale"] is True
    assert prov["age_hours"] == 100.0


# ── cmd_check: out-of-scope exclusion (Greptile PR#2 regression) ──────────────


def _seed_program(conn, platform, name, handle, offers_bounties=1):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO programs(platform, name, handle, url, offers_bounties) "
        "VALUES(?,?,?,?,?)",
        (platform, name, handle, f"https://example/{handle}", offers_bounties),
    )
    return cur.lastrowid


def _add_asset(
    conn, program_id, identifier, is_wildcard=0, deleted=0,
    eligible_for_submission=1, eligible_for_bounty=1,
):
    conn.execute(
        "INSERT INTO assets(program_id, asset_identifier, is_wildcard, deleted_timestamp, "
        "eligible_for_submission, eligible_for_bounty) VALUES(?,?,?,?,?,?)",
        (program_id, identifier, is_wildcard, deleted,
         eligible_for_submission, eligible_for_bounty),
    )


def _add_oos(conn, program_id, identifier, is_wildcard=0, deleted=0):
    conn.execute(
        "INSERT INTO oos_assets(program_id, asset_identifier, is_wildcard, deleted_timestamp) "
        "VALUES(?,?,?,?)",
        (program_id, identifier, is_wildcard, deleted),
    )


def _run_check(tmp_path, monkeypatch, capsys, conn, domain):
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", str(tmp_path / "t.db"))
    scan4me.cmd_check(types.SimpleNamespace(domain=domain))
    return capsys.readouterr().out


def test_cmd_check_excludes_ip_inside_cidr_exclusion(tmp_path, monkeypatch, capsys):
    """An IP that matches an in-scope asset but falls inside a CIDR exclusion
    must NOT be reported as authorized (string compare never caught this)."""
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Acme", "acme")
    _add_asset(conn, pid, "10.1.2.3")
    _add_oos(conn, pid, "10.0.0.0/8")
    out = _run_check(tmp_path, monkeypatch, capsys, conn, "10.1.2.3")
    assert "NOT IN KNOWN SCOPE" in out
    assert "AUTHORIZED IN-SCOPE" not in out


def test_cmd_check_deleted_exclusion_does_not_apply(tmp_path, monkeypatch, capsys):
    """A tombstoned (deleted) exclusion must not suppress an authorized match."""
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Acme", "acme")
    _add_asset(conn, pid, "10.1.2.3")
    _add_oos(conn, pid, "10.0.0.0/8", deleted=1)
    out = _run_check(tmp_path, monkeypatch, capsys, conn, "10.1.2.3")
    assert "AUTHORIZED IN-SCOPE" in out


def test_cmd_check_exclusion_is_scoped_to_its_own_program(tmp_path, monkeypatch, capsys):
    """An exclusion in program A must not suppress a match in program B."""
    conn = _temp_db(tmp_path / "t.db")
    pa = _seed_program(conn, "hackerone", "Acme", "acme")
    pb = _seed_program(conn, "bugcrowd", "Beta", "beta")
    _add_oos(conn, pa, "10.0.0.0/8")   # exclusion belongs to A only
    _add_asset(conn, pb, "10.1.2.3")   # authorized asset in B
    out = _run_check(tmp_path, monkeypatch, capsys, conn, "10.1.2.3")
    assert "AUTHORIZED IN-SCOPE" in out
    assert "Beta" in out


def test_cmd_check_caps_at_ten_matches(tmp_path, monkeypatch, capsys):
    """Authorized output is capped at ten programs."""
    conn = _temp_db(tmp_path / "t.db")
    for i in range(13):
        pid = _seed_program(conn, "hackerone", f"Prog{i}", f"prog{i}")
        _add_asset(conn, pid, "shared.example.com")
    out = _run_check(tmp_path, monkeypatch, capsys, conn, "shared.example.com")
    assert "matches 10 program(s)" in out


# ── cmd_check / cmd_export: eligibility flags (Greptile PR#2 issue 3) ──────────


def test_cmd_check_rejects_submission_ineligible_asset(tmp_path, monkeypatch, capsys):
    """A target whose only matching asset is submission-ineligible is NOT authorized."""
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Acme", "acme")
    _add_asset(conn, pid, "api.acme.com", eligible_for_submission=0)
    out = _run_check(tmp_path, monkeypatch, capsys, conn, "api.acme.com")
    assert "NOT IN KNOWN SCOPE" in out
    assert "AUTHORIZED IN-SCOPE" not in out


def test_cmd_check_allows_submission_eligible_asset(tmp_path, monkeypatch, capsys):
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Acme", "acme")
    _add_asset(conn, pid, "api.acme.com", eligible_for_submission=1)
    out = _run_check(tmp_path, monkeypatch, capsys, conn, "api.acme.com")
    assert "AUTHORIZED IN-SCOPE" in out


def _run_export(tmp_path, monkeypatch, capsys, conn, program_ids, **argkw):
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(scan4me, "evaluate_targets", lambda config=None: [{"id": i} for i in program_ids])
    args = types.SimpleNamespace(top=30, wildcards_only=False, clean=False)
    for k, v in argkw.items():
        setattr(args, k, v)
    scan4me.cmd_export(args, {})
    return [ln.strip() for ln in capsys.readouterr().out.splitlines() if ln.strip()]


def test_cmd_export_excludes_submission_ineligible(tmp_path, monkeypatch, capsys):
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Acme", "acme")
    _add_asset(conn, pid, "ok.acme.com", eligible_for_submission=1)
    _add_asset(conn, pid, "no.acme.com", eligible_for_submission=0)
    out = _run_export(tmp_path, monkeypatch, capsys, conn, [pid])
    assert "ok.acme.com" in out
    assert "no.acme.com" not in out


def test_cmd_export_paid_program_requires_bounty_eligibility(tmp_path, monkeypatch, capsys):
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Paid", "paid", offers_bounties=1)
    _add_asset(conn, pid, "paid-ok.com", eligible_for_bounty=1)
    _add_asset(conn, pid, "paid-nobounty.com", eligible_for_bounty=0)
    out = _run_export(tmp_path, monkeypatch, capsys, conn, [pid])
    assert "paid-ok.com" in out
    assert "paid-nobounty.com" not in out  # bounty-ineligible excluded from paid list


def test_cmd_export_vdp_program_keeps_bounty_ineligible(tmp_path, monkeypatch, capsys):
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Vdp", "vdp", offers_bounties=0)
    _add_asset(conn, pid, "vdp-asset.com", eligible_for_bounty=0, eligible_for_submission=1)
    out = _run_export(tmp_path, monkeypatch, capsys, conn, [pid])
    assert "vdp-asset.com" in out  # VDP needs only submission eligibility


# ── offline must not hit authenticated APIs (Greptile issue 6) ────────────────


def test_sync_offline_does_not_call_authenticated_apis(tmp_path, monkeypatch, capsys):
    """With refresh=False, configured credentials must NOT trigger network calls,
    and complete credentials must NOT be mislabeled as 'partial'."""
    monkeypatch.setattr(scan4me, "CACHE_DATA_DIR", tmp_path / "cache")
    monkeypatch.setattr(scan4me, "DB_PATH", tmp_path / "t.db")
    data_dir = tmp_path / "cache" / "data"
    data_dir.mkdir(parents=True)
    for feed in ("hackerone_data.json", "bugcrowd_data.json",
                 "intigriti_data.json", "yeswehack_data.json"):
        (data_dir / feed).write_text("[]", encoding="utf-8")
    # Credentials present for all four authenticated platforms.
    monkeypatch.setattr(scan4me, "load_credentials", lambda config=None: {
        "hackerone": {"username": "u", "api_token": "t"},
        "bugcrowd": {"api_token": "t"},
        "intigriti": {"api_token": "t"},
        "yeswehack": {"api_token": "t"},
    })
    # Any authenticated fetch is a failure when offline.
    for fn in ("_fetch_h1_authenticated", "_fetch_bugcrowd_authenticated",
               "_fetch_intigriti_authenticated", "_fetch_yeswehack_authenticated"):
        monkeypatch.setattr(scan4me, fn, lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("offline run made an authenticated network call")))
    cfg = {"hackerone": True, "bugcrowd": True, "intigriti": True, "yeswehack": True,
           "federacy": False, "immunefi": False, "sherlock": False, "pd_programs": False}
    # Must complete without calling any authenticated fetcher.
    scan4me.sync_data(refresh=False, platforms_cfg=cfg, config={})
    out = capsys.readouterr().out
    # Complete credentials skipped for being offline must NOT be called "partial".
    assert "partial credentials" not in out
    assert "offline mode" in out


# ── schema migrated before ranking (Greptile issue 8) ─────────────────────────


def _record_schema_then_eval(monkeypatch):
    calls = []

    class _DummyConn:
        def cursor(self):
            class _C:
                def execute(self, *a, **k):
                    return self
                def fetchall(self):
                    return []
            return _C()
        def close(self):
            pass

    monkeypatch.setattr(scan4me, "get_db", lambda: _DummyConn())
    monkeypatch.setattr(scan4me, "ensure_schema", lambda conn: calls.append("schema"))
    monkeypatch.setattr(scan4me, "evaluate_targets", lambda config=None: calls.append("eval") or [])
    import collections as _c
    monkeypatch.setattr(scan4me, "feed_provenance", lambda *a, **k: {
        "upstream_sha": "x", "age_hours": 1.0, "stale": False,
        "row_counts": _c.defaultdict(int), "coverage_gaps": [], "platforms": {},
    })
    return calls


def test_cmd_filter_migrates_before_ranking(tmp_path, monkeypatch, capsys):
    calls = _record_schema_then_eval(monkeypatch)
    scan4me.cmd_filter(types.SimpleNamespace(limit=20), {"display": {"limit": 20}})
    assert calls and calls[0] == "schema", calls
    assert "eval" in calls and calls.index("schema") < calls.index("eval")


def test_cmd_export_migrates_before_ranking(tmp_path, monkeypatch, capsys):
    calls = _record_schema_then_eval(monkeypatch)
    scan4me.cmd_export(types.SimpleNamespace(top=30, wildcards_only=False, clean=False), {})
    assert calls == ["schema", "eval"], calls
