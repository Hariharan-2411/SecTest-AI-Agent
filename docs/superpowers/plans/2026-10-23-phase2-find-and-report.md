# Phase 2 — Find & Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the pipeline reliably *land* a confirmed in-scope finding and turn it into a submittable report — per-risk timeouts + deterministic param-targeting (Part A), then report generation + cross-run dedupe + selectable PoC evidence (Part B).

**Architecture:** Part A tunes the existing agent `runCommand` (per-tool timeout) and the brain's recon loop (a pure `pickInjectionTarget` rewrites an injection tool's target to a discovered param URL before execution). Part B adds orchestrator modules (report, evidence, dedupe) over the existing `reportBuilder.js`/`enrich.js`/`findings.js` + store, an intake `evidenceMode`, and an optional agent-side mitmproxy for Full evidence. Pure logic is `node --test`; the live lab run is the end-to-end check.

**Tech Stack:** Node ≥18 (agent CJS, orchestrator ESM), esbuild (brain bundle), Docker, mitmproxy (Full evidence).

**Spec:** `docs/superpowers/specs/2026-10-23-phase2-find-and-report-design.md`

## Global Constraints

- **Authorization unchanged:** in-scope only, server-side scope on every scan, risk tiers + human approval, non-destructive PoC, **no auto-submit**.
- **Bounded always:** the longer confirmation timeout is still a hard kill — no unbounded runs.
- **Dedupe merges, never drops** — a repeat finding is marked `seen`, a low finding always survives (Phase 1 retain-all rule).
- **Reports/evidence never fabricate** — render only what the tool actually returned; mask secrets (reuse `maskSecret`).
- `tools.js` risk tags still equal `reconAgent.js` `RECON_TOOLS` tags.
- Full-evidence proxy failure degrades to Light; it never breaks the scan.

## Review Focus

- **Confirmation tool runs unbounded** → the ~420s cap must still hard-kill sqlmap/sstimap/commix. *(Task 1.)*
- **Param URL on an out-of-scope host gets substituted** → `pickInjectionTarget` must re-check scope and never retarget outside it. *(Task 2.)*
- **Dedupe drops a finding** → a finding seen in run 2 must be merged + marked `seen`, not removed; count preserved. *(Task 5.)*
- **Report invents evidence** → renders only provided fields; empty where the tool gave nothing. *(Task 4.)*
- **Full-evidence proxy down / TLS distrust** → scan still completes, falls back to Light. *(Task 7.)*

## Per-task pattern

Each task: write the failing test(s) → run (RED) → implement → run (GREEN) → (brain changes: `npm run bundle`) → commit.

---

### Task 1: Per-risk tool timeouts (agent)

**Files:** Modify `agent/lib/tools.js` (add `timeoutMs` to confirmation entries), `agent/lib/tools.js` `runCommand` (honor a passed timeout), `agent/server.js` (pass `def.timeoutMs`); Test: `agent/test/phase2-timeout.test.js`.

**Interfaces:** Produces `TOOLS.sqlmap.timeoutMs` etc.; `runCommand(cmd, { timeoutMs })` already accepts `timeoutMs` — confirm and thread it from the registry.

- [ ] **Step 1: Failing test** — `TOOLS.sqlmap.timeoutMs`/`sstimap`/`commix` ≥ `AGENT_CONFIRM_TIMEOUT_MS` default (~420000); a fake long-running command is killed at a small injected `timeoutMs` (reuse the existing runCommand timeout test style).
- [ ] **Step 2: RED.**
- [ ] **Step 3:** Add `timeoutMs: CONFIRM_TIMEOUT` (env `AGENT_CONFIRM_TIMEOUT_MS`, default 420000) to sqlmap/sstimap/commix; in `/scan`, call `runCommand(cmd, { timeoutMs: def.timeoutMs })`. Non-confirmation tools keep the 120s default.
- [ ] **Step 4: GREEN. Step 5: commit.**

### Task 2: Deterministic param-endpoint targeting (brain)

**Files:** Modify `src/utils/reconLoop.js` (add+export `pickInjectionTarget`, apply before `executeReconTool`); `scripts/brain-entry.mjs` (export it); rebundle. Test: `test/inject-target.test.js` (orchestrator, against the bundle).

**Interfaces:** Produces `pickInjectionTarget(host, surfaceUrls, fallback) -> url` — returns the best `?param=`-bearing in-scope URL for `host`, else `fallback`.

- [ ] **Step 1: Failing test** — given surface urls incl. `http://h/a?x=1` and `http://h/plain`, `pickInjectionTarget('h', urls, 'http://h')` returns the `?x=1` one; with no param URL returns the fallback; a param URL whose host isn't `host` is ignored.
- [ ] **Step 2: RED.**
- [ ] **Step 3:** Implement the pure helper; in `runReconLoop`, for a step whose tool ∈ `{dalfox,sqlmap,sstimap,commix,crlfuzz}` and whose `call.target` has no query string, rewrite `call.target = pickInjectionTarget(host, context.surface.urls, call.target)` (scope already enforced downstream by the agent; helper also filters by host). Rebundle.
- [ ] **Step 4: GREEN. Step 5: commit.**

### Task 3: Intake evidence mode (orchestrator)

**Files:** Modify `lib/intake.js` (add `evidenceMode`), `web/index.html` (radio), `scripts/intake-cli.mjs` (flag). Test: `test/intake.test.js` (extend).

**Interfaces:** `buildEngagement` returns `evidenceMode: 'light' | 'full'` (default `'light'`; anything else → `'light'`).

- [ ] **Step 1: Failing test** — default is `light`; `evidenceMode:'full'` preserved; `evidenceMode:'bogus'` → `light`.
- [ ] **Step 2: RED. Step 3:** implement + dashboard radio + CLI `--evidence full`. **Step 4: GREEN. Step 5: commit.**

### Task 4: Report generator (orchestrator)

**Files:** Create `lib/report.js`; modify `scripts/brain-entry.mjs` (export the report-render fn from `reportBuilder.js` — builder confirms its name), `server.js` (`GET /api/report/:id`), `web/index.html` (Copy-report button). Test: `test/report.test.js`.

**Interfaces:** `renderReport(item) -> markdown` (item = a finding or chain record); `/api/report/:id` looks the id up in findings then chains → 404 if neither.

- [ ] **Step 1: Failing test** — a sample finding renders markdown containing its title, severity/CVSS, and an evidence section; a field the item lacks renders empty, not invented; unknown id → null.
- [ ] **Step 2: RED. Step 3:** implement over `reportBuilder.js`; wire the route. **Step 4: GREEN. Step 5: commit.**

### Task 5: Cross-run dedupe + CVSS (orchestrator)

**Files:** Modify `lib/run.js` (fingerprint persist + merge), `lib/store.js` (a `fingerprints` collection if needed), ensure `enrich.js` CVSS surfaced. Test: `test/dedupe.test.js`.

**Interfaces:** Produces a `markSeen(findings, store) -> findings` step that tags each finding `status:'new'|'seen'` with `firstRun`/`lastRun`, persists fingerprints, and **never removes** a finding.

- [ ] **Step 1: Failing test** — run 1 with finding F → F.status `new`, fingerprint stored; run 2 with the same F (same fingerprint) → F.status `seen`, still present (count unchanged, not dropped); a brand-new G → `new`.
- [ ] **Step 2: RED. Step 3:** implement using `findings.js` fingerprinting; attach `enrich.js` CVSS. **Step 4: GREEN. Step 5: commit.**

### Task 6: PoC evidence — Light (orchestrator)

**Files:** Create `lib/evidence.js`; modify `lib/run.js` (store evidence per finding when `evidenceMode==='light'`), `server.js` (`GET /api/findings/:id/evidence`), `web/index.html` (evidence view). Test: `test/evidence.test.js`.

**Interfaces:** `lightEvidence({ command, raw }) -> { command, excerpt }` with `excerpt` bounded and `maskSecret`-ed.

- [ ] **Step 1: Failing test** — light evidence keeps the command and a bounded excerpt; a secret-looking token in the raw is masked; retrievable by finding id.
- [ ] **Step 2: RED. Step 3:** implement; the agent `/scan` response already carries `command`+`raw` — thread them onto stored findings. **Step 4: GREEN. Step 5: commit.**

### Task 7: PoC evidence — Full via mitmproxy (agent)

**Files:** Modify `agent/Dockerfile` (install `mitmproxy`, trust its CA), `agent/server.js` (when a scan requests `evidence:'full'`, start/reuse `mitmdump`, set `HTTP_PROXY`/`HTTPS_PROXY` for the tool spawn, collect the flow, attach request/response to the response; on proxy error fall back to Light), `agent/lib/tools.js` (runCommand accepts an `env` overlay). Test: `agent/test/phase2-full-evidence.test.js` (unit: env/arg wiring + fallback logic; full capture is exercised in Task 8).

**Interfaces:** `/scan` accepts optional `evidence:'light'|'full'`; response gains `evidence:{mode, request?, response?}`.

- [ ] **Step 1: Failing test** — with `evidence:'full'` the spawn env includes `HTTP(S)_PROXY`; if the proxy is unavailable the result still returns (mode downgraded to `light`), never throws.
- [ ] **Step 2: RED. Step 3:** implement proxy lifecycle + env overlay + capture + fallback; Dockerfile `pip/apt install mitmproxy` and install its CA into the trust store (non-fatal). **Step 4: GREEN. Step 5: commit.**

### Task 8: Live lab E2E (verification)

**Files:** none (uses `scripts/run-lab.sh` + the stack).

- [ ] **Step 1:** `npm run bundle`; `docker compose build`; re-up lab (Juice Shop + WordPress).
- [ ] **Step 2:** Run an engagement (`evidenceMode:light`) and confirm a run reaches a **confirmed `sqli`/`xss` finding on `/rest/products/search?q=`** — i.e. A1 (timeout) + A2 (param targeting) worked.
- [ ] **Step 3:** `GET /api/report/:id` returns a submittable writeup (B1); the finding carries CVSS (B2).
- [ ] **Step 4:** Re-run the same engagement → the finding is marked `seen`, not duplicated (B2).
- [ ] **Step 5:** `GET /api/findings/:id/evidence` returns the Light evidence; run once with `evidenceMode:full` and confirm a request/response flow is captured (or cleanly fell back).
- [ ] **Step 6:** Guardrail re-check: destructive blocked without opt-in; out-of-scope rejected; confirmation tool hard-killed at its cap. Commit any lab-compose tweaks.

## Self-review notes

- **Spec coverage:** A1→Task1, A2/A3→Task2, intake mode→Task3, B1→Task4, B2→Task5, B3 Light→Task6, B3 Full→Task7, verification→Task8.
- **Review Focus:** each of the five lines has an owning task (1,2,5,4,7).
- **Proportion:** per-task bodies omitted; the plan fixes signatures, the retain-all/bounded/scope invariants, and the test assertions — implementer writes idiomatic bodies from the existing modules.
