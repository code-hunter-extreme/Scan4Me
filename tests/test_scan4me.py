"""Focused regression tests for Scan4Me repairs.

Covers: scope matching (fail-closed), export cleaning, CLI override wiring,
asset reconciliation, and offline sync feed requirements.

Run:  python3 -m pytest tests/ -q   (from the Scan4Me directory)
"""

import json
import sqlite3
import sys
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
