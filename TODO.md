# TODO — Project Continuity & GitHub Sync

Tracker for the handoff tasks requested 2026-10-13. Every task is executed by a
dedicated subagent; the orchestrator ticks items off as each verified result lands.

## Tasks

- [x] 1. Create TODO.md with all tasks and tick items off as they complete
- [x] 2. Create `agent.md` — full project context so a fresh agent can work on this repo without prior history (architecture, deployment topology, credentials model, DB schema, API surface, verification commands, gotchas) — 250 lines, 11 sections, secrets-free (verified)
- [x] 3. Sync all deployed progress/changes from the VPS (`root@<YOUR_VPS_IP>:/opt/observatory`, port 22022) back into this local directory so the repo matches production exactly — 106 deployment files sha256-identical; stray scp artifacts purged from both sides
- [x] 4. Initialize git locally and commit the complete project (GitHub-ready; `.gitignore` already excludes `.env`, `node_modules/`, `dist/`, DuckDB files, runtime data) so a fresh clone reproduces the deployed output — commit `7d82138` on `main`, 118 files, forbidden paths untracked
- [x] 5. Verify everything: VPS↔repo checksum spot-check, git tree completeness, deployed fixes present in tracked files, secrets excluded
- [x] 6. Change IP address color from red to green on the /map page (live feed rows, TOP SOURCE IPS table — match ShardLure's green IP styling) — feed IPs + top-source table now `text-pos` green #40d986
- [x] 7. Live feed must show executed commands like ShardLure's: rows = time-ago · green IP · user (or `?`) · event kind (failed_pa…/client_version/connect/command) · and for command events the actual command text — not "generic bot activity" labels for everything — reference grid rows shipped; feed backfilled with last 14 cowrie events on load; live brute-force session (command/accepted kinds) verified on screen
- [x] 8. Make http://<YOUR_VPS_IP>:8888/map exact like http://100.101.102.100:8080/ (telemetry header box with source/origin/updated + Globe/Intel toggle, panel styling, colors, layout parity) — telemetry box with ticking clock + globe/intel chips (intel → /ssh) live
- [x] 9. Globe arcs hug the sphere and wrap with rotation (no more floating far off the globe; visible over the horizon, per-segment front-hemisphere draw) — arcHeight 0.015–0.045, origin-visibility gate removed
- [x] 10. SSH accepts only ShardLure's default credentials (install/persona/userdb.txt from the reference repo) instead of any password — deployed + verified: root/root ✓ accept, admin/admin ✓ accept, root/wrongpass99 ✗ denied, guest/anything ✓ wildcard, probe strings ✗ denied
- [x] 11. Fix slow dashboard loads (10s+): /network/stats 30-day default → 7 days (30s → 0.17s); DuckDB read-cursor pool (4 long-lived cursors — per-call cursor() cost ~0.5-1s on every query); OBS_GEOIP_ENABLED knob so tests stop downloading 131MB per run; killed stuck ubuntu-release-upgrader that spiked load to 3.4. Page loads now ~1-2.5s (was ~10s)
- [x] 12. Follow-up optimization: move sync `db.fetch_all` calls in routers onto a worker thread (`asyncio.to_thread`) so parallel page requests stop serializing behind the event loop (~2x further win); also consider building web images off-VPS (`docker save | docker load`) — npm ci inside the 1-vCPU/10GB box caused the ENOSPC incidents
- [x] 13. Headroom on the 458MB box: suricata-update classtype filter shipped in `suricata/entrypoint.sh` — keeps attack-relevant classtypes only, 69,071 → ~15k rules, suricata RSS 252MB → 91MB, load 2.8 → 1.2, 8-request parallel wall 19s → 0.88s, page data ready in ~1.2s (was 7-10s+). Remaining option: VPS plan upgrade for more headroom

## Execution notes

- Subagents: sync (task 3) and docs (task 2) run in parallel; git commit (task 4)
  runs after 2+3; verification (task 5) runs last and is independent of the work
  it audits.
- VPS is the running ground truth for deployment files; local-only reference
  material (`shardlure/`, `shardlure_map_page/`, `_ref/`, `scripts/`, `docs/`,
  `TODO.md`, `agent.md`) is intentionally repo-side.
- Pushing to GitHub requires the user's remote URL + credentials (`git remote
  add origin … && git push -u origin main`); everything else is done so the push
  is one command.
