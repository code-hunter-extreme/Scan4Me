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


def test_runtime_paths_are_checkout_relative(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert scan4me.DB_PATH == scan4me.REPO_ROOT / "scan4me.db"
    assert scan4me.CONFIG_PATH == scan4me.REPO_ROOT / "config.json"
    assert scan4me.CACHE_DATA_DIR == scan4me.REPO_ROOT / "data_cache"


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
    """Composite scores pinned exactly (re-pinned 2026-10 for the
    low-confidence-unknown and wildcard-surface scoring revisions).

    Any further change to the scoring math or the batched new-asset
    counts breaks this.
    """
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    _seed_scoring_fixture(conn.cursor(), int(time.time()))
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)

    cfg = _eval_config(hackerone=True, bugcrowd=True, intigriti=True)
    cfg["ranking_weights"] = {
        "triage_speed": 0.35,
        "attack_surface_size": 0.30,
        "freshness_and_low_saturation": 0.20,
        "payout_size": 0.15,
    }
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
            # Freshness: known-old base 25 + new-assets bonus 15 = 40.
            81.2,
            100.0,
            85.0,
            40.0,
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
            # Unknown speed/freshness/payout are low-confidence (30/25/30),
            # never average-or-better free points.
            27.5,
            30.0,
            25.0,
            25.0,
            30.0,
            2,
            0,
            0,
            "🔍 NARROW/FOCUSED",
        ),
    ]


def test_to_usd_converts_known_currencies_and_rejects_unknown():
    assert scan4me._to_usd(100, "USD") == 100.0
    assert scan4me._to_usd(100, "USDC") == 100.0
    assert scan4me._to_usd(100, "EUR") > 100.0
    assert scan4me._to_usd(100, "GBP") > scan4me._to_usd(100, "EUR")
    assert scan4me._to_usd(100, "XYZ") == 0.0
    assert scan4me._to_usd(0, "EUR") == 0.0


def test_evaluate_payout_band_uses_usd(tmp_path, monkeypatch):
    """EUR 19,000 converts above the USD 20,000 band edge (85, not 70)."""
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "Intigriti", "EuroCo", "euroco")
    _add_asset(conn, pid, "api.euroco.eu")
    conn.execute(
        "UPDATE programs SET max_payout=19000, currency='EUR' WHERE id=?", (pid,)
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", tmp_path / "t.db")
    results = scan4me.evaluate_targets(scan4me.load_config())
    euro = [r for r in results if r["id"] == pid]
    assert euro and euro[0]["payout_score"] == 85.0


def test_evaluate_excludes_ineligible_only_program(tmp_path, monkeypatch):
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "Intigriti", "NoSubmit", "nosubmit")
    _add_asset(conn, pid, "api.nosubmit.eu", eligible_for_submission=0)
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", tmp_path / "t.db")
    ids = {r["id"] for r in scan4me.evaluate_targets(scan4me.load_config())}
    assert pid not in ids


def test_load_config_deep_merges_and_normalizes_weights(tmp_path, monkeypatch):
    partial = tmp_path / "config.json"
    partial.write_text(
        json.dumps({"ranking_weights": {"triage_speed": 2.0}}), encoding="utf-8"
    )
    monkeypatch.setattr(scan4me, "CONFIG_PATH", partial)
    cfg = scan4me.load_config()
    assert set(cfg["ranking_weights"]) == {
        "triage_speed", "attack_surface_size",
        "freshness_and_low_saturation", "payout_size",
    }
    assert abs(sum(cfg["ranking_weights"].values()) - 1.0) < 1e-9
    assert cfg["display"]["limit"] == 25


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
    # Only eligible scopes become targets, and eligibility/restriction fields
    # are preserved (defaults when the feed omits them) — not dropped (#15).
    assert programs[0]["targets"]["in_scope"] == [
        {
            "asset_identifier": "acme.com",
            "asset_type": "URL",
            "eligible_for_bounty": True,
            "eligible_for_submission": True,
            "instruction": "",
            "max_severity": "",
        }
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
    assert got["Enriched Inc"]["speed_score"] == 30.0  # unknown base, no bonus
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


# ── withdrawn-program reconciliation (Greptile issue 4) ───────────────────────


def test_cmd_check_tombstoned_program_not_authorized(tmp_path, monkeypatch, capsys):
    """A program tombstoned by reconciliation (deleted_timestamp set) must
    never authorize a target, even though its assets remain stored."""
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "DeadCo", "deadco")
    _add_asset(conn, pid, "api.deadco.com")
    conn.execute("UPDATE programs SET deleted_timestamp=999 WHERE id=?", (pid,))
    out = _run_check(tmp_path, monkeypatch, capsys, conn, "api.deadco.com")
    assert "AUTHORIZED IN-SCOPE" not in out
    assert "NOT IN KNOWN SCOPE" in out


def test_cmd_export_excludes_tombstoned_program_assets(tmp_path, monkeypatch, capsys):
    conn = _temp_db(tmp_path / "t.db")
    live = _seed_program(conn, "hackerone", "LiveCo", "liveco")
    dead = _seed_program(conn, "hackerone", "DeadCo", "deadco")
    _add_asset(conn, live, "api.liveco.com")
    _add_asset(conn, dead, "api.deadco.com")
    conn.execute("UPDATE programs SET deleted_timestamp=999 WHERE id=?", (dead,))
    out = _run_export(tmp_path, monkeypatch, capsys, conn, [live, dead])
    assert "api.liveco.com" in out
    assert "api.deadco.com" not in out


def test_evaluate_targets_excludes_tombstoned_programs(tmp_path, monkeypatch):
    conn = _temp_db(tmp_path / "t.db")
    live = _seed_program(conn, "HackerOne", "LiveCo", "liveco")
    dead = _seed_program(conn, "HackerOne", "DeadCo", "deadco")
    _add_asset(conn, live, "api.liveco.com")
    _add_asset(conn, dead, "api.deadco.com")
    conn.execute("UPDATE programs SET deleted_timestamp=999 WHERE id=?", (dead,))
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", str(tmp_path / "t.db"))
    cfg = scan4me.load_config()
    ids = {row["id"] for row in scan4me.evaluate_targets(cfg)}
    assert live in ids
    assert dead not in ids


def test_reconcile_tombstones_vanished_but_not_on_truncated_feed(tmp_path):
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    keep = _seed_program(conn, "HackerOne", "KeepCo", "keepco")
    gone = _seed_program(conn, "HackerOne", "GoneCo", "goneco")
    conn.commit()
    # Complete feed: vanishing one of two must NOT tombstone (below-half
    # truncation guard also covers small platforms).
    n = scan4me._reconcile_platform_programs(cur, "HackerOne", {"keepco"}, 999)
    assert n == 0
    # Empty feed must never tombstone.
    assert scan4me._reconcile_platform_programs(cur, "HackerOne", set(), 999) == 0
    # Healthy feed (>half present): the one vanished program IS tombstoned.
    for h in ("alpha", "beta", "gamma", "delta"):
        _seed_program(conn, "Bugcrowd", h.title(), h)
    conn.commit()
    n = scan4me._reconcile_platform_programs(
        cur, "Bugcrowd", {"alpha", "beta", "gamma"}, 999
    )
    assert n == 1
    dead = conn.execute(
        "SELECT deleted_timestamp FROM programs WHERE handle='delta'"
    ).fetchone()[0]
    assert dead == 999
    conn.close()
    assert keep and gone


def test_cmd_export_excludes_exact_oos_asset(tmp_path, monkeypatch, capsys):
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Acme", "acme")
    _add_asset(conn, pid, "ok.acme.com")
    _add_asset(conn, pid, "admin.acme.com")
    _add_oos(conn, pid, "admin.acme.com")
    out = _run_export(tmp_path, monkeypatch, capsys, conn, [pid])
    assert "ok.acme.com" in out
    assert "admin.acme.com" not in out


def test_cmd_export_suppresses_wildcard_touched_by_oos(tmp_path, monkeypatch, capsys):
    """Fail-closed plain export: a wildcard pattern partially carved by an
    OOS exclusion cannot be represented safely, so it must not be emitted."""
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Acme", "acme")
    _add_asset(conn, pid, "*.acme.com", is_wildcard=1)
    _add_asset(conn, pid, "ok.other.com")
    _add_oos(conn, pid, "admin.acme.com")
    out = _run_export(tmp_path, monkeypatch, capsys, conn, [pid])
    assert "ok.other.com" in out
    assert not any("acme.com" in line for line in out)



def test_feed_age_uses_last_successful_refresh_not_last_run(tmp_path):
    """A failed/offline sync stamps last_sync_ts=now but must NOT make a stale
    snapshot look fresh — age is measured from the last successful refresh (#9)."""
    conn = _temp_db(tmp_path / "t.db")
    old = int(time.time()) - 100 * 3600          # last good refresh: 100h ago
    cur = conn.cursor()
    cur.executemany(
        "INSERT INTO sync_metadata(key, value) VALUES(?, ?)",
        [
            ("last_successful_sync_ts", str(old)),
            ("last_sync_ts", str(int(time.time()))),  # a just-now failed/offline run
            ("last_refresh_ok", "0"),
        ],
    )
    conn.commit()
    prov = scan4me.feed_provenance(conn)
    conn.close()
    assert prov["age_hours"] == 100.0          # from the successful refresh, not ~0
    assert prov["stale"] is True
    assert prov["refresh_ok"] is False


def test_h1_in_scope_preserves_eligibility_and_restrictions():
    """HackerOne fetch must keep eligible_for_bounty/instruction/max_severity
    (and filter to submission-eligible) so no-bounty assets aren't defaulted
    to bounty-eligible and restrictions aren't lost (#15)."""
    scopes = [
        {"asset_identifier": "a.com", "asset_type": "URL",
         "eligible_for_submission": True, "eligible_for_bounty": False,
         "instruction": "staging only", "max_severity": "medium"},
        {"asset_identifier": "b.com", "asset_type": "URL",
         "eligible_for_submission": False, "eligible_for_bounty": True},
    ]
    out = scan4me._h1_in_scope(scopes)
    assert len(out) == 1  # submission-ineligible b.com dropped
    a = out[0]
    assert a["asset_identifier"] == "a.com"
    assert a["eligible_for_bounty"] is False   # preserved, not defaulted to True
    assert a["instruction"] == "staging only"
    assert a["max_severity"] == "medium"
    # and _eligibility_of now reads the real values
    bounty, submission, instruction, severity = scan4me._eligibility_of(a)
    assert bounty == 0 and submission == 1 and instruction == "staging only"


def test_strict_new_companies_requires_bugcrowd_official_date(tmp_path, monkeypatch):
    """STRICT new-companies must require Bugcrowd + a recent OFFICIAL start date;
    a non-Bugcrowd program fresh only by feed-observation date must NOT satisfy
    the strict gate (#7). Without strict, both still appear (scoring signal)."""
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    now = int(time.time())
    recent = now - 10 * 86400
    # A: Bugcrowd with a recent OFFICIAL start date → qualifies under strict.
    cur.execute(
        """INSERT INTO programs (platform, name, handle, offers_bounties, max_payout,
           first_response_hours, response_efficiency, first_seen_timestamp,
           official_start_timestamp)
           VALUES ('Bugcrowd','BC New','bc-new',1,5000,5.0,95.0,?,?)""",
        (now - 300 * 86400, recent),
    )
    cur.execute("INSERT INTO assets (program_id, asset_identifier, asset_type) "
                "VALUES (?, 'a.bc.com', 'URL')", (cur.lastrowid,))
    # B: HackerOne, fresh only by feed first-seen (observation), no official date.
    cur.execute(
        """INSERT INTO programs (platform, name, handle, offers_bounties, max_payout,
           first_response_hours, response_efficiency, first_seen_timestamp)
           VALUES ('HackerOne','H1 Obs','h1-obs',1,5000,5.0,95.0,?)""",
        (recent,),
    )
    cur.execute("INSERT INTO assets (program_id, asset_identifier, asset_type) "
                "VALUES (?, 'a.h1.com', 'URL')", (cur.lastrowid,))
    conn.commit(); conn.close()

    monkeypatch.setattr(scan4me, "DB_PATH", str(db_path))

    cfg = _eval_config(bugcrowd=True, hackerone=True)
    fresh = cfg["filters"].setdefault("freshness_and_competition", {})

    # Not strict: observation newness is a scoring signal — both appear.
    fresh.update({"prefer_new_companies": True, "strict_new_companies": False,
                  "new_company_days": 90})
    names = {p["name"] for p in scan4me.evaluate_targets(cfg)}
    assert {"BC New", "H1 Obs"} <= names, names

    # Strict: only the Bugcrowd program with an official date qualifies.
    fresh["strict_new_companies"] = True
    strict_names = {p["name"] for p in scan4me.evaluate_targets(cfg)}
    assert "BC New" in strict_names
    assert "H1 Obs" not in strict_names, strict_names


# ── New Tests: Multi-platform accuracy, Web3 scope, and SLA baseline ──────────


def test_web3_programs_not_dropped_when_assets_empty(tmp_path, monkeypatch):
    """Web3 / Immunefi programs with empty DNS asset tables must not be dropped by min_in_scope_assets."""
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO programs (platform, name, handle, url, offers_bounties,
           max_payout, currency, first_seen_timestamp, last_updated_timestamp,
           program_kind)
           VALUES ('Immunefi', 'Web3 Protocol', 'web3-protocol',
           'https://immunefi.com/bug-bounty/web3-protocol', 1, 1000000.0, 'USD',
           1000, 1000, 'web3')"""
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)

    cfg = _eval_config(immunefi=True)
    results = scan4me.evaluate_targets(cfg)
    assert len(results) == 1
    assert results[0]["name"] == "Web3 Protocol"
    assert results[0]["payout_score"] == 100.0
    assert results[0]["surface_score"] == 50.0


def test_unmeasured_managed_triage_elevates_to_sla_baseline(tmp_path, monkeypatch):
    """Unmeasured programs with managed_triage earn the SLA baseline (70.0) when prefer_managed_triage is set."""
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO programs (platform, name, handle, url, offers_bounties,
           managed_triage, max_payout, currency, first_seen_timestamp,
           last_updated_timestamp, program_kind)
           VALUES ('Intigriti', 'Managed Corp', 'managed-corp',
           'https://intigriti.com/managed-corp', 1, 1, 10000, 'USD', 1000, 1000, 'web2')"""
    )
    pid = cur.lastrowid
    cur.execute(
        "INSERT INTO assets (program_id, asset_identifier, asset_type, is_wildcard) "
        "VALUES (?, 'api.managed.com', 'URL', 0)", (pid,)
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)

    cfg = _eval_config(intigriti=True)
    cfg["filters"]["fast_triage"]["prefer_managed_triage"] = True
    results = scan4me.evaluate_targets(cfg)
    assert len(results) == 1
    assert results[0]["speed_score"] == 70.0


def test_rebalanced_default_ranking_weights():
    """Verify DEFAULT_CONFIG ranks payout magnitude (0.35) higher than triage speed (0.15)."""
    cfg = scan4me.load_config()
    weights = cfg["ranking_weights"]
    assert weights["payout_size"] == 0.35
    assert weights["attack_surface_size"] == 0.30
    assert weights["freshness_and_low_saturation"] == 0.20
    assert weights["triage_speed"] == 0.15


# ── Listing-platform coverage (Bugbase/HackenProof/Cantina/Patchstack/Huntr/CodeHawks/Sherlock BB) ──


def test_listing_defaults_cover_required_platforms():
    plats = scan4me.DEFAULT_CONFIG["platforms"]
    for key in ("bugbase", "hackenproof", "cantina", "codehawks", "patchstack", "huntr"):
        assert plats[key] is True, key
    assert plats["federacy"] is False  # operator: no account, ignore
    assert "hatsfinance" not in plats  # operator: no account, exclude


def test_parse_hackenproof_cards():
    html = """
    <a href="/programs/gate"><span>Gate</span><span>Gate</span>
    <span>Up to:</span><span>$5,000</span><span>Started date:</span>
    <span>14 Jul 2020</span><span>Submissions:</span><span>526</span></a>
    <a href="/programs/coinw"><span>Triaged by HackenProof</span><span>CoinW</span>
    <span>Up to:</span><span>$2,000</span></a>
    """
    progs = scan4me._parse_hackenproof_page(html)
    assert [p["handle"] for p in progs] == ["gate", "coinw"]
    assert progs[0]["name"] == "Gate" and progs[0]["max_payout"] == 5000.0
    assert progs[0]["rewarded_vulnerabilities"] == 526
    assert progs[0]["official_start_timestamp"] is not None
    assert progs[1]["name"] == "CoinW" and progs[1]["managed_triage"] is True


def test_parse_cantina_patchstack_huntr_sherlock_cards():
    cantina = scan4me._parse_cantina_page(
        '<a href="/bounties/abc"><img alt="Euler"><span>Euler-Bounty</span>'
        "<span>7,500,000</span><span>in</span><span>USDC</span><span>Live</span>"
        "<span>Cantina-Triaged</span><span>Started on 21 Aug 2024</span></a>"
    )
    assert cantina[0]["max_payout"] == 7500000.0 and cantina[0]["managed_triage"] is True
    patch = scan4me._parse_patchstack_page(
        '<a href="/database/wordpress/plugin/elementor-pro/vulnerabilities">Plugin Elementor Pro</a>'
    )
    assert patch[0]["handle"] == "elementor-pro" and patch[0]["name"] == "Elementor Pro"
    huntr = scan4me._parse_huntr_page(
        '<a href="/challenges/ABC123/v1/leaderboard" aria-label="View details for Quiet Part challenge">x</a>'
    )
    assert huntr[0]["handle"] == "ABC123" and huntr[0]["name"] == "Quiet Part"
    assert huntr[0]["url"] == "https://huntr.com/challenges/ABC123"
    sher = scan4me._parse_sherlock_bounties_page(
        '<a href="/bug-bounties/56"><img alt="Usual Labs"><span>Usual Labs</span>'
        "<span>Payout</span><span>16,000,000 USDC</span></a>"
    )
    assert sher[0]["handle"] == "sherlock-bb-56" and sher[0]["max_payout"] == 16000000.0


def test_parse_codehawks_and_bugbase_pages():
    hawks = scan4me._parse_codehawks_page(
        '<a href="/c/2026-07-battlechain">BattleChain</a><span>80,000 USDC</span>'
    )
    assert hawks[0]["handle"] == "2026-07-battlechain"
    assert hawks[0]["max_payout"] == 80000.0 and hawks[0]["starts_at"] == "2026-07"
    bug = scan4me._parse_bugbase_page(
        r'{"programName":"boAt","programUsername":"boat-lifestyle",'
        r'"programType":"vdp","isPrivate":false,"isManaged":true,'
        r'"createdAt":"2022-04-01T00:00:00.000Z","isVisible":true,"maxBounty":500}'
    )
    assert bug[0]["handle"] == "boat-lifestyle" and bug[0]["max_payout"] == 500.0
    assert bug[0]["managed_triage"] is True


def test_evaluate_includes_listing_only_zero_asset(tmp_path, monkeypatch):
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO programs (platform, name, handle, url, offers_bounties,"
        " max_payout, program_kind, first_seen_timestamp, last_updated_timestamp)"
        " VALUES ('Patchstack', 'Elementor Pro', 'elementor-pro',"
        " 'https://patchstack.com/database/wordpress/plugin/elementor-pro/vulnerabilities',"
        " 1, 1000, 'web2', 1000, 1000)"
    )
    conn.commit(); conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)
    out = scan4me.evaluate_targets(_eval_config(patchstack=True))
    assert [p["name"] for p in out] == ["Elementor Pro"]
    assert out[0]["surface_score"] == 50.0


def test_sherlock_bounty_rows_survive_migration_and_evaluate(tmp_path, monkeypatch):
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    cur = conn.cursor()
    for handle, name in (("sherlock-1", "Legacy Contest"), ("sherlock-bb-56", "Usual Labs")):
        cur.execute(
            "INSERT INTO programs (platform, name, handle, url, offers_bounties,"
            " max_payout, currency, program_kind, first_seen_timestamp, last_updated_timestamp)"
            " VALUES ('Sherlock', ?, ?, 'https://audits.sherlock.xyz/bug-bounties/56', 1,"
            " 16000000, 'USDC', 'web3', 1000, 1000)",
            (name, handle),
        )
    conn.commit()
    scan4me.migrate_db(conn)
    conn.commit()
    rows = conn.execute("SELECT handle FROM programs WHERE platform='Sherlock'").fetchall()
    assert [r[0] for r in rows] == ["sherlock-bb-56"]
    assert conn.execute("SELECT count(*) FROM contests WHERE handle='sherlock-1'").fetchone()[0] == 1
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)
    out = scan4me.evaluate_targets(_eval_config(sherlock=True))
    assert [p["name"] for p in out] == ["Usual Labs"]


def test_listing_zero_payout_resync_preserves_known(tmp_path):
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    prog = {"name": "Gate", "handle": "gate", "url": "https://x/gate",
            "max_payout": 5000.0, "offers_bounties": True,
            "program_kind": "web3", "managed_triage": False}
    scan4me._sync_listing_programs(cur, "HackenProof", [prog], 1000)
    conn.commit()
    scan4me._sync_listing_programs(cur, "HackenProof", [dict(prog, max_payout=0.0)], 2000)
    conn.commit()
    assert tuple(cur.execute("SELECT max_payout, first_seen_timestamp FROM programs").fetchone()) == (5000.0, 1000)
    contest = {"name": "BattleChain", "handle": "2026-07-battlechain", "url": "https://x/c",
               "max_payout": 80000.0, "currency": "USDC", "offers_bounties": True,
               "status": "LIVE", "starts_at": "2026-07", "ends_at": None, "description": ""}
    scan4me._sync_listing_contests(cur, "CodeHawks", [contest], 1000)
    conn.commit()
    scan4me._sync_listing_contests(cur, "CodeHawks", [dict(contest, max_payout=0.0)], 2000)
    conn.commit()
    assert tuple(cur.execute("SELECT max_payout, first_seen_timestamp FROM contests").fetchone()) == (80000.0, 1000)


def test_listing_parser_bleed_cases():
    # Bugbase: record A has no maxBounty; must not inherit record B's 999.
    bug = scan4me._parse_bugbase_page(
        r'{"programName":"Alpha","programUsername":"alpha","programType":"vdp",'
        r'"isPrivate":false,"isManaged":false,"isVisible":true}'
        r'{"programName":"Beta","programUsername":"beta","programType":"bugbounty",'
        r'"isPrivate":false,"isManaged":false,"isVisible":true,"maxBounty":999}'
    )
    assert [p["max_payout"] for p in bug] == [0.0, 999.0]
    # CodeHawks: prize belongs to second card only.
    hawks = scan4me._parse_codehawks_page(
        '<a href="/c/2026-01-alpha">Alpha</a><span>no prize here</span>'
        '<a href="/c/2026-02-beta">Beta</a><span>80,000 USDC</span>'
    )
    assert [c["max_payout"] for c in hawks] == [0.0, 80000.0]
    # HackenProof single text node (no span splits).
    hp = scan4me._parse_hackenproof_page(
        '<a href="/programs/gate">Gate Up to: $5,000 Started date: 14 Jul 2020 Submissions: 526</a>'
    )
    assert hp[0]["name"] == "Gate" and hp[0]["max_payout"] == 5000.0
    assert hp[0]["rewarded_vulnerabilities"] == 526
    assert hp[0]["official_start_timestamp"] is not None


def test_listing_amount_and_nav_rejection():
    # Cantina: small incidental $ first must not beat the real USDC bounty.
    cantina = scan4me._parse_cantina_page(
        '<a href="/bounties/f9df94db-c7b1-434b-bb06-d1360abdd1be"><img alt="Uni">'
        "<span>Deposit $50</span><span>$1,000,000</span><span>in</span><span>USDC</span>"
        "<span>Live</span></a>"
        '<a href="/bounties/explore">Explore bounties</a>'
    )
    assert len(cantina) == 1 and cantina[0]["max_payout"] == 1000000.0
    # HackenProof: nav anchor without card evidence is skipped.
    hp = scan4me._parse_hackenproof_page('<a href="/programs/all">All programs</a>')
    assert hp == []
    # CodeHawks: undated generic /c/ links are skipped.
    hawks = scan4me._parse_codehawks_page('<a href="/c/leaderboard">Leaderboard</a>')
    assert hawks == []
    # Huntr: generic button text never becomes the challenge name.
    huntr = scan4me._parse_huntr_page(
        '<a href="/challenges/ABC12345/v1/rules"><span>View details</span>'
        "<span>Quiet Part Challenge Card</span></a>"
    )
    assert huntr and huntr[0]["name"] != "View details"


def test_listing_reverification_fixes():
    # CodeHawks: two hrefs per card must not shift prizes to neighbours.
    hawks = scan4me._parse_codehawks_page(
        '<a href="/c/2026-01-alpha">Alpha</a><span>4,000 USDC</span>'
        '<a href="/c/2026-01-alpha">View contest</a>'
        '<a href="/c/2026-02-beta">Beta</a><span>80,000 USDC</span>'
        '<a href="/c/2026-02-beta">View contest</a>'
    )
    by_handle = {c["handle"]: c for c in hawks}
    assert by_handle["2026-01-alpha"]["max_payout"] == 4000.0
    assert by_handle["2026-02-beta"]["max_payout"] == 80000.0
    # Cantina: USDC-adjacent amount beats a larger non-bounty $ figure.
    cantina = scan4me._parse_cantina_page(
        '<a href="/bounties/abc"><img alt="Euler"><span>$7,500,000 TVL</span>'
        "<span>50,000</span><span>in</span><span>USDC</span><span>Live</span></a>"
    )
    assert cantina[0]["max_payout"] == 50000.0
    small = scan4me._parse_cantina_page(
        '<a href="/bounties/abc"><img alt="Euler"><span>500 USDC</span><span>Live</span></a>'
    )
    assert small[0]["max_payout"] == 500.0


def test_listing_preservation_and_usdc_prefix(tmp_path):
    # USDC-prefixed amount form parses.
    cantina = scan4me._parse_cantina_page(
        '<a href="/bounties/abc"><img alt="Euler"><span>USDC 7,500,000</span><span>Live</span></a>'
    )
    assert cantina[0]["max_payout"] == 7500000.0
    # Degraded resync preserves offers/managed (programs) and status (contests).
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    prog = {"name": "Gate", "handle": "gate", "url": "https://x/gate",
            "max_payout": 5000.0, "offers_bounties": True,
            "program_kind": "web3", "managed_triage": True}
    scan4me._sync_listing_programs(cur, "HackenProof", [prog], 1000)
    conn.commit()
    degraded = dict(prog, max_payout=0.0, offers_bounties=False, managed_triage=False)
    scan4me._sync_listing_programs(cur, "HackenProof", [degraded], 2000)
    conn.commit()
    assert tuple(cur.execute(
        "SELECT offers_bounties, managed_triage, max_payout FROM programs").fetchone()) == (1, 1, 5000.0)
    contest = {"name": "Beta", "handle": "2026-02-beta", "url": "https://x/c",
               "max_payout": 80000.0, "currency": "USDC", "offers_bounties": True,
               "status": "LIVE", "starts_at": "2026-02", "ends_at": None, "description": ""}
    scan4me._sync_listing_contests(cur, "CodeHawks", [contest], 1000)
    conn.commit()
    scan4me._sync_listing_contests(
        cur, "CodeHawks", [dict(contest, max_payout=0.0, offers_bounties=False, status="")], 2000)
    conn.commit()
    assert tuple(cur.execute(
        "SELECT offers_bounties, max_payout, status FROM contests").fetchone()) == (1, 80000.0, "LIVE")


def test_sherlock_scope_updated_captured():
    sher = scan4me._parse_sherlock_bounties_page(
        '<a href="/bug-bounties/227"><img alt="Usual - Fira"><span>Usual - Fira</span>'
        "<span>Last Updated • Jan 16, 2026</span><span>7,500,000 USDC</span></a>"
    )
    assert sher[0]["official_scope_updated_timestamp"] is not None
    import datetime as _dt
    assert _dt.datetime.fromtimestamp(
        sher[0]["official_scope_updated_timestamp"]).year == 2026


# ── P1 flag contracts (use_auth CLI, limit/top semantics, live counts) ───────


def test_non_negative_int_arg_type():
    import argparse

    assert scan4me._non_negative_int("0") == 0
    assert scan4me._non_negative_int("7") == 7
    with pytest.raises(argparse.ArgumentTypeError):
        scan4me._non_negative_int("-1")
    with pytest.raises(argparse.ArgumentTypeError):
        scan4me._non_negative_int("x")


def test_sync_use_auth_reachable_via_cli(monkeypatch):
    seen = []
    monkeypatch.setattr(scan4me, "sync_data", lambda **k: seen.append(k))
    monkeypatch.setattr(scan4me, "load_config", lambda: {})
    for argv, want in (
        (["scan4me", "sync", "--offline", "--use-auth"], True),
        (["scan4me", "sync", "--offline", "--no-auth"], False),
        (["scan4me", "sync", "--offline"], None),
    ):
        seen.clear()
        monkeypatch.setattr(sys, "argv", argv)
        scan4me.main()
        assert seen and seen[0].get("use_auth") is want, (argv, seen)


def test_cmd_filter_limit_zero_and_negative(monkeypatch, capsys):
    _record_schema_then_eval(monkeypatch)
    # One (incomplete) result row: limit=0 must display none. Under the old
    # `args.limit or 20` bug the loop body ran and blew up on the stub row.
    monkeypatch.setattr(scan4me, "evaluate_targets", lambda config=None: [{}])
    scan4me.cmd_filter(
        types.SimpleNamespace(limit=0), {"display": {"limit": 20}}
    )
    assert "Displaying Top 0" in capsys.readouterr().out
    with pytest.raises(ValueError):
        scan4me.cmd_filter(types.SimpleNamespace(limit=-1), {})


def test_cmd_export_top_zero_and_negative(tmp_path, monkeypatch, capsys):
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "hackerone", "Acme", "acme")
    _add_asset(conn, pid, "ok.acme.com", eligible_for_submission=1)
    out = _run_export(tmp_path, monkeypatch, capsys, conn, [pid], top=0)
    assert "ok.acme.com" not in out
    conn2 = _temp_db(tmp_path / "t.db")
    with pytest.raises(ValueError):
        _run_export(tmp_path, monkeypatch, capsys, conn2, [pid], top=-1)


def test_cmd_enrich_negative_limit_raises():
    with pytest.raises(ValueError):
        scan4me.cmd_enrich(types.SimpleNamespace(limit=-1, handle=None))


def test_feed_provenance_counts_live_programs_only(tmp_path):
    conn = _temp_db(tmp_path / "t.db")
    live = _seed_program(conn, "HackerOne", "LiveCo", "liveco")
    dead = _seed_program(conn, "HackerOne", "DeadCo", "deadco")
    _seed_program(conn, "Immunefi", "GoneFi", "gonefi")
    conn.execute("UPDATE programs SET deleted_timestamp=999 WHERE id=?", (dead,))
    conn.execute(
        "UPDATE programs SET deleted_timestamp=999 WHERE platform='Immunefi'"
    )
    conn.commit()
    prov = scan4me.feed_provenance(conn)
    conn.close()
    assert prov["row_counts"]["programs"] == 1  # only LiveCo is live
    assert not any("Immunefi: 1 programs" in g for g in prov["coverage_gaps"])
    assert live  # silence linters; the seed itself is the fixture


def test_platform_status_count_override_is_indexed_rows():
    st = scan4me._platform_status(True, [1, 2, 3], "live-listing", count=1)
    assert st == {"status": "ok", "count": 1, "source": "live-listing"}
    st2 = scan4me._platform_status(True, [1, 2, 3], "feed")
    assert st2["count"] == 3


# ── falsifier regressions: status honesty, legacy provenance, bool config ───


def test_coerce_bool_quoted_false_never_enables():
    assert scan4me._coerce_bool("false") is False
    assert scan4me._coerce_bool("0") is False
    assert scan4me._coerce_bool("off") is False
    assert scan4me._coerce_bool("true") is True
    assert scan4me._coerce_bool("1") is True
    assert scan4me._coerce_bool(True) is True
    assert scan4me._coerce_bool(None) is False


def test_platform_status_zero_indexed_is_empty_not_ok():
    st = scan4me._platform_status(True, [{"x": 1}], "live-listing", count=0)
    assert st["status"] == "empty"
    assert st["count"] == 0
    with pytest.raises(ValueError):
        scan4me._platform_status(True, [1], "live-listing", count=-1)
    with pytest.raises(ValueError):
        scan4me._platform_status(True, [1], "live-listing", count=1.5)


def test_listing_bad_payout_does_not_abort_sync(tmp_path):
    conn = _temp_db(tmp_path / "t.db")
    cur = conn.cursor()
    seen = scan4me._sync_listing_programs(
        cur,
        "Bugbase",
        [
            {"handle": "bad", "name": "Bad Pay", "url": "https://x", "max_payout": "abc"},
            {"handle": "good", "name": "Good Pay", "url": "https://y", "max_payout": "2500"},
        ],
        123,
    )
    conn.commit()
    rows = cur.execute(
        "SELECT handle, max_payout FROM programs WHERE platform='Bugbase' ORDER BY handle"
    ).fetchall()
    conn.close()
    assert seen == 2
    assert [(r[0], r[1]) for r in rows] == [("bad", 0.0), ("good", 2500.0)]


def test_feed_provenance_legacy_schema_counts_and_gaps(tmp_path):
    conn = sqlite3.connect(str(tmp_path / "legacy.db"))
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE programs (id INTEGER PRIMARY KEY, platform TEXT, max_payout REAL);
        CREATE TABLE assets (id INTEGER PRIMARY KEY, program_id INTEGER);
        CREATE TABLE contests (id INTEGER PRIMARY KEY);
        CREATE TABLE sync_metadata (key TEXT, value TEXT);
        """
    )
    conn.execute("INSERT INTO programs VALUES (1, 'HackerOne', 0)")
    conn.execute("INSERT INTO programs VALUES (2, 'Immunefi', 1000)")
    conn.execute("INSERT INTO assets VALUES (1, 2)")
    conn.commit()
    prov = scan4me.feed_provenance(conn)
    conn.close()
    assert prov["row_counts"]["programs"] == 2
    assert any("HackerOne payouts: 0/1" in g for g in prov["coverage_gaps"])
    assert any("Immunefi: 1 programs, 1 scope rows" in g for g in prov["coverage_gaps"])


def test_feed_provenance_tombstoned_immunefi_assets_excluded(tmp_path):
    conn = _temp_db(tmp_path / "t.db")
    pid = _seed_program(conn, "Immunefi", "GoneFi", "gonefi")
    _add_asset(conn, pid, "app.gonefi.example")
    conn.execute("UPDATE programs SET deleted_timestamp=999 WHERE id=?", (pid,))
    conn.commit()
    prov = scan4me.feed_provenance(conn)
    conn.close()
    assert any("Immunefi: 0 programs, 0 scope rows" in g for g in prov["coverage_gaps"])


def test_cmd_filter_bad_display_config_and_invalid_limit(monkeypatch, capsys):
    _record_schema_then_eval(monkeypatch)
    monkeypatch.setattr(scan4me, "evaluate_targets", lambda config=None: [])
    scan4me.cmd_filter(
        types.SimpleNamespace(limit=None), {"display": None, "filters": None}
    )
    assert "Displaying Top 0" in capsys.readouterr().out
    with pytest.raises(ValueError):
        scan4me.cmd_filter(
            types.SimpleNamespace(limit=None), {"display": {"limit": 2.5}}
        )


def test_non_negative_int_rejects_underscores_and_huge():
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        scan4me._non_negative_int("1_0")
    with pytest.raises(argparse.ArgumentTypeError):
        scan4me._non_negative_int(str(10**30))


def test_cmd_enrich_invalid_limits_raise_before_db():
    with pytest.raises(ValueError):
        scan4me.cmd_enrich(types.SimpleNamespace(limit=10**30, handle=None))
    with pytest.raises(ValueError):
        scan4me.cmd_enrich(types.SimpleNamespace(limit=1.5, handle=None))


def test_bugbase_bad_max_bounty_does_not_abort_page():
    bad = scan4me._parse_bugbase_page(
        r'{"programName":"EvilCo","programUsername":"evilco","maxBounty":1.2.3,"programType":"bugbounty"}'
        r'{"programName":"Dots","programUsername":"dots","maxBounty":...,"programType":"bugbounty"}'
        r'{"programName":"Good","programUsername":"good","maxBounty":2500,"programType":"bugbounty"}'
    )
    assert [p["handle"] for p in bad] == ["evilco", "dots", "good"]
    assert [p["max_payout"] for p in bad] == [0.0, 0.0, 2500.0]


def test_evaluate_targets_bad_filters_real_path(tmp_path, monkeypatch):
    db_path = tmp_path / "t.db"
    conn = _temp_db(db_path)
    conn.close()
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)
    base = {"platforms": {"hackerone": True}}
    for bad_filters in (
        None,
        "junk",
        {"fast_triage": None},
        {"freshness_and_competition": 42},
    ):
        assert scan4me.evaluate_targets({**base, "filters": bad_filters}) == []


def test_sync_bugcrowd_public_file_preserves_known_payout(tmp_path, monkeypatch):
    """Live-sync regression: Bugcrowd upsert must preserve programs.max_payout
    (not reference contests.max_payout) and bad feed payouts must not abort."""
    _no_auth(monkeypatch, tmp_path)
    db_path = tmp_path / "t.db"
    monkeypatch.setattr(scan4me, "CACHE_DATA_DIR", tmp_path / "cache")
    monkeypatch.setattr(scan4me, "DB_PATH", db_path)
    conn = _temp_db(db_path)
    conn.execute(
        "INSERT INTO programs (platform, name, handle, url, offers_bounties,"
        " max_payout, first_seen_timestamp, last_updated_timestamp)"
        " VALUES ('Bugcrowd', 'Old Corp', 'old-corp',"
        " 'https://bugcrowd.com/old-corp', 1, 4321, 500, 1000)"
    )
    conn.execute(
        "INSERT INTO sync_metadata(key, value) VALUES('baseline_complete', '1')"
    )
    conn.commit()
    conn.close()
    _write_feed(
        tmp_path / "cache" / "data",
        "bugcrowd_data.json",
        [
            {
                "name": "Old Corp",
                "url": "/old-corp",
                "max_payout": "abc",
                "targets": {"in_scope": [{"target": "app.old.example", "type": "website"}]},
            },
            {
                "name": "New Corp",
                "url": "/new-corp",
                "max_payout": 2500,
                "targets": {"in_scope": [{"target": "app.new.example", "type": "website"}]},
            },
        ],
    )
    scan4me.sync_data(
        refresh=False,
        platforms_cfg=_file_only_cfg(bugcrowd=True),
        config={},
        use_auth=False,
    )
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT handle, max_payout FROM programs WHERE platform='Bugcrowd' ORDER BY handle"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [("new-corp", 2500.0), ("old-corp", 4321.0)]
