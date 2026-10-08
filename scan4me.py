#!/usr/bin/env python3
"""
Scan4Me: Precision Bug Bounty Intelligence & Scope Targeter
Filters 47,000+ assets across HackerOne, Bugcrowd, Intigriti, and YesWeHack
specifically for fast triage, massive attack surface (more assets = more bugs),
fresh scope, low report saturation, and fast payouts.
"""

import sys
import os
import json
import sqlite3
import argparse
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
DB_PATH = REPO_ROOT / "scan4me.db"
CONFIG_PATH = REPO_ROOT / "config.json"
CACHE_DATA_DIR = REPO_ROOT / "data_cache"

UPSTREAM_REPO = "https://github.com/arkadiyt/bounty-targets-data.git"

DEFAULT_CONFIG = {
    "filters": {
        "paid_bounties_only": True,
        "fast_triage": {
            "enabled": True,
            "max_first_response_hours": 48.0,
            "min_response_efficiency_pct": 80.0,
            "prefer_managed_triage": True,
            "max_time_to_bounty_awarded_hours": 720.0
        },
        "attack_surface_and_scope": {
            "prefer_large_attack_surface": True,
            "min_in_scope_assets": 1,
            "prioritize_wildcards": True,
            "wildcard_multiplier": 2.5
        },
        "freshness_and_competition": {
            "prefer_fresh_programs": True,
            "low_report_saturation": True
        },
        "payouts": {
            "min_max_payout_usd": 1000.0,
            "prioritize_fast_cash": True
        }
    },
    "platforms": {
        "hackerone": True,
        "bugcrowd": True,
        "intigriti": True,
        "yeswehack": True
    },
    "ranking_weights": {
        "triage_speed": 0.35,
        "attack_surface_size": 0.30,
        "freshness_and_low_saturation": 0.20,
        "payout_size": 0.15
    },
    "display": {
        "limit": 25,
        "show_company_profile": True,
        "show_assets_sample": True
    }
}

def load_config():
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Warning: Failed to load config.json ({e}), using defaults.")
    return DEFAULT_CONFIG

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn):
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS programs (
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
            UNIQUE(platform, handle)
        );

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id INTEGER,
            asset_identifier TEXT NOT NULL,
            asset_type TEXT,
            is_wildcard BOOLEAN DEFAULT 0,
            FOREIGN KEY (program_id) REFERENCES programs(id)
        );

        CREATE INDEX IF NOT EXISTS idx_asset_identifier ON assets(asset_identifier);
        CREATE INDEX IF NOT EXISTS idx_program_platform ON programs(platform);
        CREATE INDEX IF NOT EXISTS idx_program_bounty ON programs(offers_bounties);
        """)

def sync_data(clone_if_missing=True):
    CACHE_DATA_DIR.mkdir(parents=True, exist_ok=True)
    local_data_dir = CACHE_DATA_DIR / "data"

    if not local_data_dir.exists() or not (local_data_dir / "hackerone_data.json").exists():
        shared_scratch = Path("/home/phantomcore/.gemini/antigravity-cli/brain/025773d3-1a4b-4d6a-9674-a58515d9bcd7/scratch/bounty-targets-data/data")
        if shared_scratch.exists():
            print(f"[*] Copying latest datasets from local cache: {shared_scratch}")
            import shutil
            shutil.copytree(shared_scratch, local_data_dir, dirs_exist_ok=True)
        elif clone_if_missing:
            print(f"[*] Cloning latest hourly upstream feed from {UPSTREAM_REPO}...")
            subprocess.run(["git", "clone", "--depth", "1", UPSTREAM_REPO, str(CACHE_DATA_DIR / "repo")], check=True)
            local_data_dir = CACHE_DATA_DIR / "repo" / "data"

    conn = get_db()
    init_db(conn)

    print(f"[*] Ingesting and normalizing targets from {local_data_dir}...")
    cur = conn.cursor()

    # 1. HackerOne
    h1_file = local_data_dir / "hackerone_data.json"
    if h1_file.exists():
        with open(h1_file) as f:
            h1_data = json.load(f)
        with conn:
            for p in h1_data:
                handle = p.get("handle")
                name = p.get("name") or handle
                url = f"https://hackerone.com/{handle}"
                website = p.get("website") or ""
                offers_bounty = bool(p.get("offers_bounties"))
                managed = bool(p.get("managed_program"))
                resp_time = p.get("average_time_to_first_program_response")
                bounty_time = p.get("average_time_to_bounty_awarded")
                resolved_time = p.get("average_time_to_report_resolved")
                efficiency = p.get("response_efficiency_percentage")

                cur.execute("""
                    INSERT OR REPLACE INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        first_response_hours, bounty_awarded_hours, report_resolved_hours,
                        response_efficiency, currency
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'USD')
                """, ("HackerOne", name, handle, url, website, offers_bounty, managed, resp_time, bounty_time, resolved_time, efficiency))
                
                prog_id = cur.lastrowid or conn.execute("SELECT id FROM programs WHERE platform=? AND handle=?", ("HackerOne", handle)).fetchone()[0]
                
                for t in p.get("targets", {}).get("in_scope", []):
                    ident = t.get("asset_identifier", "").strip()
                    if ident:
                        is_w = 1 if ("*" in ident) else 0
                        cur.execute("INSERT INTO assets (program_id, asset_identifier, asset_type, is_wildcard) VALUES (?, ?, ?, ?)",
                                    (prog_id, ident, t.get("asset_type", "URL"), is_w))
        print(f"[+] HackerOne indexed: {len(h1_data)} programs.")

    # 2. Bugcrowd
    bc_file = local_data_dir / "bugcrowd_data.json"
    if bc_file.exists():
        with open(bc_file) as f:
            bc_data = json.load(f)
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

                cur.execute("""
                    INSERT OR REPLACE INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, currency, safe_harbor
                    ) VALUES (?, ?, ?, ?, '', ?, ?, ?, 'USD', ?)
                """, ("Bugcrowd", name, handle, url, offers_bounty, managed, max_p, safe))

                prog_id = cur.lastrowid or conn.execute("SELECT id FROM programs WHERE platform=? AND handle=?", ("Bugcrowd", handle)).fetchone()[0]
                for t in p.get("targets", {}).get("in_scope", []):
                    ident = t.get("target", "").strip()
                    if ident:
                        is_w = 1 if ("*" in ident) else 0
                        cur.execute("INSERT INTO assets (program_id, asset_identifier, asset_type, is_wildcard) VALUES (?, ?, ?, ?)",
                                    (prog_id, ident, t.get("type", "URL"), is_w))
        print(f"[+] Bugcrowd indexed: {len(bc_data)} programs.")

    # 3. Intigriti
    inti_file = local_data_dir / "intigriti_data.json"
    if inti_file.exists():
        with open(inti_file) as f:
            inti_data = json.load(f)
        with conn:
            for p in inti_data:
                name = p.get("name", "Unknown")
                handle = p.get("handle") or str(p.get("id"))
                url = p.get("url", "")
                max_b = p.get("max_bounty", {})
                max_val = float(max_b.get("value", 0) or 0) if isinstance(max_b, dict) else 0
                curr = max_b.get("currency", "EUR") if isinstance(max_b, dict) else "EUR"
                offers_bounty = max_val > 0

                cur.execute("""
                    INSERT OR REPLACE INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, currency
                    ) VALUES (?, ?, ?, ?, '', ?, 1, ?, ?)
                """, ("Intigriti", name, handle, url, offers_bounty, max_val, curr))

                prog_id = cur.lastrowid or conn.execute("SELECT id FROM programs WHERE platform=? AND handle=?", ("Intigriti", handle)).fetchone()[0]
                for t in p.get("targets", {}).get("in_scope", []):
                    ident = t.get("endpoint", "").strip()
                    if ident:
                        is_w = 1 if ("*" in ident) else 0
                        cur.execute("INSERT INTO assets (program_id, asset_identifier, asset_type, is_wildcard) VALUES (?, ?, ?, ?)",
                                    (prog_id, ident, t.get("type", "URL"), is_w))
        print(f"[+] Intigriti indexed: {len(inti_data)} programs.")

    # 4. YesWeHack
    ywh_file = local_data_dir / "yeswehack_data.json"
    if ywh_file.exists():
        with open(ywh_file) as f:
            ywh_data = json.load(f)
        with conn:
            for p in ywh_data:
                name = p.get("name", "Unknown")
                handle = str(p.get("id"))
                max_val = float(p.get("max_bounty", 0) or 0)
                offers_bounty = max_val > 0
                managed = bool(p.get("managed"))

                cur.execute("""
                    INSERT OR REPLACE INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, currency
                    ) VALUES (?, ?, ?, ?, '', ?, ?, ?, 'EUR')
                """, ("YesWeHack", name, handle, f"https://yeswehack.com/programs/{handle}", offers_bounty, managed, max_val))

                prog_id = cur.lastrowid or conn.execute("SELECT id FROM programs WHERE platform=? AND handle=?", ("YesWeHack", handle)).fetchone()[0]
                for t in p.get("targets", {}).get("in_scope", []):
                    ident = t.get("target", "").strip()
                    if ident:
                        is_w = 1 if ("*" in ident) else 0
                        cur.execute("INSERT INTO assets (program_id, asset_identifier, asset_type, is_wildcard) VALUES (?, ?, ?, ?)",
                                    (prog_id, ident, t.get("target_type", "URL"), is_w))
        print(f"[+] YesWeHack indexed: {len(ywh_data)} programs.")

    total_progs = cur.execute("SELECT count(*) FROM programs").fetchone()[0]
    total_assets = cur.execute("SELECT count(*) FROM assets").fetchone()[0]
    total_wild = cur.execute("SELECT count(*) FROM assets WHERE is_wildcard=1").fetchone()[0]
    print(f"\n[✓] Scan4Me Sync Complete: {total_progs} programs, {total_assets} assets ({total_wild} wildcards).")

def evaluate_targets():
    config = load_config()
    conn = get_db()
    cur = conn.cursor()

    filters = config.get("filters", {})
    fast_triage = filters.get("fast_triage", {})
    surface_cfg = filters.get("attack_surface_and_scope", {})
    fresh_cfg = filters.get("freshness_and_competition", {})
    plat_cfg = config.get("platforms", {})
    weights = config.get("ranking_weights", {
        "triage_speed": 0.35,
        "attack_surface_size": 0.30,
        "freshness_and_low_saturation": 0.20,
        "payout_size": 0.15
    })

    enabled_plats = [p for p, enabled in plat_cfg.items() if enabled]
    plat_map = {
        "hackerone": "HackerOne",
        "bugcrowd": "Bugcrowd",
        "intigriti": "Intigriti",
        "yeswehack": "YesWeHack"
    }
    target_plats = [plat_map[p] for p in enabled_plats if p in plat_map]

    query = """
        SELECT p.*, count(a.id) as asset_count, sum(a.is_wildcard) as wildcard_count
        FROM programs p
        LEFT JOIN assets a ON p.id = a.program_id
        WHERE p.platform IN ({})
    """.format(','.join('?' * len(target_plats)))
    params = list(target_plats)

    if filters.get("paid_bounties_only", True):
        query += " AND p.offers_bounties = 1"

    query += " GROUP BY p.id"
    rows = cur.execute(query, params).fetchall()

    scored_programs = []
    max_first_resp = fast_triage.get("max_first_response_hours", 48.0)
    min_efficiency = fast_triage.get("min_response_efficiency_pct", 80.0)
    wildcard_mult = surface_cfg.get("wildcard_multiplier", 2.5)

    for r in rows:
        # Triage speed filters
        if r["platform"] == "HackerOne":
            if r["first_response_hours"] is not None and r["first_response_hours"] > max_first_resp:
                continue
            if r["response_efficiency"] is not None and r["response_efficiency"] < min_efficiency:
                continue

        asset_count = r["asset_count"] or 0
        wild_count = r["wildcard_count"] or 0
        
        # Scope filters
        if asset_count < surface_cfg.get("min_in_scope_assets", 1):
            continue

        # 1. Triage Speed Score (0-100)
        speed_score = 50.0
        if r["platform"] == "HackerOne":
            if r["first_response_hours"] is not None:
                speed_score = max(0, 100 - (r["first_response_hours"] * 1.5))
            if r["managed_triage"]:
                speed_score += 15
        elif r["platform"] in ["Bugcrowd", "Intigriti", "YesWeHack"]:
            speed_score = 85.0 if r["managed_triage"] else 65.0
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

        # 3. Freshness & Low Saturation Score (0-100)
        fresh_score = 60.0
        if r["platform"] == "HackerOne":
            if r["report_resolved_hours"] is None:
                fresh_score = 90.0 # Brand new / low past backlog
            else:
                fresh_score = max(20.0, 80.0 - (r["report_resolved_hours"] / 10.0))
        else:
            fresh_score = 75.0

        # 4. Payout Score (0-100)
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

        # Composite Fast-Money & Surface Area Score
        total_score = (
            (speed_score * weights["triage_speed"]) +
            (surface_score * weights["attack_surface_size"]) +
            (fresh_score * weights["freshness_and_low_saturation"]) +
            (payout_score * weights["payout_size"])
        )

        scored_programs.append({
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
            "assets": asset_count,
            "wildcards": wild_count,
            "id": r["id"]
        })

    scored_programs.sort(key=lambda x: x["score"], reverse=True)
    return scored_programs

def cmd_filter(args):
    results = evaluate_targets()
    limit = args.limit or load_config().get("display", {}).get("limit", 20)
    
    print("\n" + "="*88)
    print("🔥 SCAN4ME PRECISION TARGET RADAR (FAST TRIAGE • MASSIVE ATTACK SURFACE • FAST CASH)")
    print("="*88)
    print(f"[*] Displaying Top {min(limit, len(results))} Target Companies (Ranked by Surface & Speed):\n")

    conn = get_db()
    for i, p in enumerate(results[:limit], 1):
        triage_info = f"{p['first_resp']}h (Eff: {p['efficiency']}%)" if p["first_resp"] is not None else ("Managed Team" if p["managed"] else "Standard")
        payout_str = f"Max: {p['max_payout']:,.0f} {p['currency']}" if (p['max_payout'] and p['max_payout'] > 0) else "Paid BBP"
        
        print(f"[{i:02d}] ★ SCORE: {p['score']}/100 | {p['surface_tier']} | [{p['platform']}] {p['name']}")
        print(f"     🏢 Company Info : Policy: {p['url']}")
        if p["website"]:
            print(f"                       Website: {p['website']}")
        print(f"     ⚡ Triage Speed  : {triage_info} | 💰 Payout: {payout_str}")
        print(f"     🌐 Surface Scope : {p['assets']} In-Scope Assets ({p['wildcards']} Wildcards) | Harbor: {p['safe_harbor']}")

        if args.show_assets:
            cur = conn.cursor()
            wildcard_samples = cur.execute("SELECT asset_identifier FROM assets WHERE program_id=? AND is_wildcard=1 LIMIT 3", (p["id"],)).fetchall()
            other_samples = cur.execute("SELECT asset_identifier FROM assets WHERE program_id=? AND is_wildcard=0 LIMIT 3", (p["id"],)).fetchall()
            
            samples = [w[0] for w in wildcard_samples] + [o[0] for o in other_samples]
            if samples:
                print(f"     🔎 Target Sample : {', '.join(samples[:4])}")
        print("-" * 88)

def cmd_check(args):
    conn = get_db()
    target = args.domain.strip().lower()
    cur = conn.cursor()
    
    matches = cur.execute("""
        SELECT p.platform, p.name, p.url, p.website, p.offers_bounties, a.asset_identifier, a.is_wildcard
        FROM assets a
        JOIN programs p ON a.program_id = p.id
        WHERE a.asset_identifier = ? 
           OR (? LIKE '%' || replace(replace(a.asset_identifier, '*.', ''), '*', '') || '%' AND a.is_wildcard = 1)
        LIMIT 10
    """, (target, target)).fetchall()

    if matches:
        print(f"\n✅ [AUTHORIZED IN-SCOPE] '{target}' matches {len(matches)} program(s):")
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
        print(f"\n❌ [NOT IN KNOWN SCOPE] '{target}' was not found in active public program scopes.")
        print("   CAUTION: Do not probe without explicit authorization!\n")

def cmd_export(args):
    results = evaluate_targets()
    limit = args.top or 30
    target_ids = [p["id"] for p in results[:limit]]

    conn = get_db()
    cur = conn.cursor()
    placeholders = ",".join("?" * len(target_ids))
    sql = f"SELECT DISTINCT asset_identifier FROM assets WHERE program_id IN ({placeholders})"
    if args.wildcards_only:
        sql += " AND is_wildcard = 1"

    rows = cur.execute(sql, target_ids).fetchall()
    for r in rows:
        val = r[0].strip()
        if args.clean:
            val = val.lstrip("*.").rstrip("/")
        print(val)

def main():
    parser = argparse.ArgumentParser(description="Scan4Me: Precision Bug Bounty Target Engine")
    sub = parser.add_subparsers(dest="command")

    p_sync = sub.add_parser("sync", help="Sync latest dataset from upstream feeds")
    
    p_radar = sub.add_parser("radar", help="List top targets filtered by surface area, speed, and cash")
    p_radar.add_argument("--limit", type=int, default=20)
    p_radar.add_argument("--show-assets", action="store_true", default=True)

    p_check = sub.add_parser("check", help="Verify if target is in authorized legal scope")
    p_check.add_argument("domain", help="Target domain, e.g. api.target.com")

    p_export = sub.add_parser("export", help="Export clean target list for httpx/subfinder from filtered programs")
    p_export.add_argument("--top", type=int, default=30)
    p_export.add_argument("--wildcards-only", action="store_true")
    p_export.add_argument("--clean", action="store_true")

    args = parser.parse_args()
    if args.command == "sync":
        sync_data()
    elif args.command == "radar":
        cmd_filter(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "export":
        cmd_export(args)
    else:
        p_radar.print_help()

if __name__ == "__main__":
    main()
