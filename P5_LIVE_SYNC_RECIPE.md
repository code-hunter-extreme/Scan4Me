# P5 Live-Sync Recipe — Immunefi + PDPrograms + Auth Feeds

No live keys were available during P5, so every feed below was proven with
fixtures/mocks (see `tests/test_scan4me.py`, P5 block). This file records
exactly what a live run needs and what it should produce.

## 0. What P5 changed

- **Immunefi** (`_fetch_immunefi_programs`): was hardcoded to `[]`
  (`IMMUNEFI_API_URL = None`). Now parses the bounty list embedded in the
  public board page `https://immunefi.com/bug-bounty/` (no key needed).
  Verified 2026-10-12: page returns 200 and embeds **169 bounties**.
- **PDPrograms** (`_load_pd_programs`, new): was reading the nonexistent file
  `chaos-bugbounty-list.json` (always 0 rows). Now reads the real files in a
  `projectdiscovery/public-bugbounty-programs` checkout: `dist/data.json`
  first, `src/data.yaml` fallback. Local clone holds **802 programs**.
- **Auth feeds** (H1/Bugcrowd/Intigriti/YesWeHack): logic unchanged; now
  covered by mocked-transport tests pinning URL + auth scheme + normalization
  + pagination for each platform.

## 1. Live run — no keys needed (Immunefi + PD + public cores)

```bash
cd /home/phantomcore/Scan4Me
python3 scan4me.py sync
```

Expected console lines (row counts > 0):

```text
[+] Immunefi indexed: ~169 programs.
[+] ProjectDiscovery programs indexed: ~802 programs.
```

Verify in the DB:

```bash
sqlite3 scan4me.db \
  "SELECT platform, COUNT(*) FROM programs WHERE platform IN ('Immunefi','PDPrograms') GROUP BY platform;"
# Immunefi|>0  PDPrograms|>0
sqlite3 scan4me.db \
  "SELECT COUNT(*) FROM programs WHERE platform='Immunefi' AND offers_bounties=1;"
# >0 (≈153 on 2026-10-12; paused/invite-only rows are kept with offers_bounties=0)
```

## 2. Live run — authenticated feeds (private/invite programs)

Keys are read from env vars first (never commit real keys to `config.json`).
Optional shared keys live in the trio central store (`~/.config/trio/keys.env`).

| Platform   | Env vars (both where shown)                              | Where to mint the key                    |
|------------|----------------------------------------------------------|------------------------------------------|
| HackerOne  | `HACKERONE_USERNAME` + `HACKERONE_API_TOKEN`             | hackerone.com → Settings → API Token     |
| Bugcrowd   | `BUGCROWD_API_TOKEN`                                     | bugcrowd.com → Settings → API            |
| Intigriti  | `INTIGRITI_API_TOKEN`                                    | app.intigriti.com → Settings → API Token |
| YesWeHack  | `YESWEHACK_API_TOKEN`                                    | yeswehack.com → Settings → API           |

```bash
cd /home/phantomcore/Scan4Me
export HACKERONE_USERNAME='<you>' HACKERONE_API_TOKEN='<token>'
export BUGCROWD_API_TOKEN='<token>' INTIGRITI_API_TOKEN='<token>' YESWEHACK_API_TOKEN='<token>'
python3 scan4me.py keys    # masked check: all four should show "set"
python3 scan4me.py sync
```

Expected console lines (each > 0 programs when the key is valid):

```text
[+] HackerOne authenticated: N programs (including private invites).
[+] Bugcrowd authenticated: N programs (including private).
[+] Intigriti authenticated: N programs (including private).
[+] YesWeHack authenticated: N programs (including private).
```

A bad/revoked key soft-fails to `[!] <Platform> authenticated fetch failed: ...`
and the platform falls back to its public feed (H1) or an empty list — sync
still completes. That fallback is covered by
`test_p5_h1_authenticated_failure_soft_fails`.

## 3. UNVERIFIED (needs the live runs above)

1. **Auth endpoint shapes.** URLs + auth schemes are pinned by tests, but live
   response shapes were never observed here. If a platform returns extra
   nesting, its `_fetch_*_authenticated` normalizer may yield 0 rows while
   reporting success — compare the `[+]` counts against the web UI.
2. **Immunefi page drift.** The parser keys on the `"bounties":[...]` Flight
   payload. A site redesign returns `[]` gracefully (no crash), but the feed
   then silently goes stale — the `[+] Immunefi indexed:` count is the tripwire.
3. **Immunefi assets are empty by design.** Per-program scope lives on the
   169 detail pages; P5 indexes programs + max payouts only. Fetching detail
   pages per sync is future work, not a bug.
4. **PDPrograms count moves with upstream.** 802 is the 2026-10-12 snapshot;
   expect drift, not an exact match.
