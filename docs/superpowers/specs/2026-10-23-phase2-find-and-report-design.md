# Iris Orchestrator — Phase 2: Find & Report Design

_Date: 2026-10-23_

## Context / why

Phase 1 shipped the tools and the pipeline, proven live: the two-agent ensemble plans →
critic vets → human-approval gate → tools execute → triage/chain finalize, and it completes
cleanly. But the live lab run exposed the gap between *running tools* and *landing a
reportable bug*:

1. **Injection tools hit the root, not the vulnerable parameter.** The planner targeted
   `http://juiceshop:3000` instead of a param endpoint like `/rest/products/search?q=`, so
   dalfox/sqlmap had nothing to inject → 0 findings.
2. **Confirmation tools are killed too early.** `runCommand` caps every tool at 120s;
   sqlmap/sstimap/commix need minutes of boolean/time-based probing to *confirm*, so they
   returned before detecting.
3. **No path to submission.** Even a confirmed finding has no report, no cross-run dedupe,
   no stored PoC evidence — the trail still ends at a ranked list.

Phase 2 closes both halves: **tuning so the pipeline lands a confirmed finding**, then
**close-the-loop so that finding becomes a submittable report**.

## Authorization posture (unchanged)

Everything in Phase 2 inherits Phase 1's model: authorized in-scope assets only, server-side
scope on every scan, risk-tiered tools with human approval for active/destructive,
non-destructive PoC, **no auto-submit**. Longer timeouts and param-targeting do not change
*what* may run or *where* — only how long a confirmation runs and which URL it targets, both
still scope-gated and approval-gated.

## Goals / Non-goals / Anti-goals

**Goals:** (A) reliably land a *confirmed* finding on an in-scope param endpoint; (B) turn a
finding/chain into a platform-ready report, dedupe findings across runs, and store the PoC
evidence that backs each one.

**Non-goals:** auto-submission; parallelizing the agent's scan queue (stays serial);
destructive exploitation beyond non-destructive confirmation.

**Anti-goals (failure even if it "works"):** a confirmation tool that runs unbounded and
hangs a run; a report that fabricates evidence beyond what the tool actually returned;
dedupe that *drops* a finding instead of merging it (lows must survive — see Phase 1 rule).

## Constraints

- Reuse existing pieces: `reportBuilder.js` (H1/Bugcrowd markdown), `enrich.js` (CVSS 3.1),
  `findings.js` (SHA-256 fingerprint dedupe), the orchestrator store, the agent `runCommand`.
- Keep the agent's serial queue and 120s default; only confirmation tools get a longer, still
  bounded cap.
- Every new timeout/target is still scope- and approval-gated; no new bypass.

---

## Part A — Orchestration tuning (land the confirmed bug)

**A1. Per-risk tool timeouts.** Make `runCommand`'s timeout configurable per tool. Default
stays 120s; confirmation tools (`sqlmap`, `sstimap`, `commix`) get a longer bounded cap
(env `AGENT_CONFIRM_TIMEOUT_MS`, default ~420s). Still hard-killed at the cap — no unbounded
runs (the anti-goal). The tool registry entry carries an optional `timeoutMs`; `runCommand`
honors it.

**A2. Param-endpoint targeting (the key fix) — deterministic, not prompt-only.** Relying on
the LLM to pick the injectable URL is unreliable (it picked the root). Instead add a
deterministic step in the loop/executor: when an injection tool is about to run, if the
chosen target has no query string, **substitute the best discovered param-bearing URL** for
that host from `surface.urls` (prefer URLs with `?k=v`). A small pure helper
`pickInjectionTarget(host, surfaceUrls, fallback)` chooses it; it's unit-testable and
scope-re-checked. The planner prompt still lists discovered endpoints, but correctness no
longer depends on the model choosing well.

**A3. Surface param extraction.** Ensure katana/gau/waybackurls output is retained with its
query strings (today the loop keeps `urls`); add light extraction so param URLs are
first-class in `surface.urls` for A2 to pick from.

## Part B — Close the loop to submission

**B1. Report generator.** `GET /api/report/:id` (finding or chain id) → render via
`reportBuilder.js` into H1/Bugcrowd markdown (title, severity/CVSS, steps, impact,
remediation, evidence). Dashboard gets a "Copy report" button per finding/chain. No
auto-submit; it produces text for the human.

**B2. Cross-run dedupe + CVSS.** Persist each finding's SHA-256 fingerprint in the store.
On a new run, a finding already seen is **merged and marked `seen` (with first/last run
ids)**, a new one marked `new` — never dropped (Phase 1 retain-all rule holds). Surface
`enrich.js` CVSS on every finding and in the report.

**B3. PoC evidence capture — two modes, chosen at intake.** Evidence mode is a new intake
option (asked alongside "enumerate subdomains?" / "allow destructive?" in the dashboard
form + CLI), stored on the engagement as `evidenceMode: 'light' | 'full'` (default `light`):

- **Light:** the exact **tool command + a bounded, masked excerpt of the tool's raw output**
  (+ the `gowitness` screenshot path). What a bounty report's evidence section usually needs;
  cheap, no extra infra.
- **Full:** the agent runs an **HTTP interception proxy** (mitmproxy/`mitmdump`); the tools
  get `HTTP(S)_PROXY` pointed at it (and `--proxy` where a tool needs it explicitly), and the
  proxy records the real **request/response flows**, which are stored per finding. Requires
  the proxy process in the agent container and its CA trusted by the tools (installed into the
  image's trust store; tools that ignore it fall back to Light for that run). Heavier but a
  bounded, standard pattern.

Both store the minimum PoC, masked, never exfiltrated data. Retrievable via
`GET /api/findings/:id/evidence`, shown/linked on the dashboard.

## What's left to the builder

- Exact `AGENT_CONFIRM_TIMEOUT_MS` default and which tools count as "confirmation."
- `pickInjectionTarget` heuristic for ranking param URLs (e.g., prefer more params / known
  sink names) — a reasonable default; not critical to get perfect.
- Report markdown structure beyond what `reportBuilder.js` already emits.
- Evidence size caps and masking rules (reuse the secret-masking helper).

## Verification (end-to-end)

1. Unit: `pickInjectionTarget` picks a param URL over the root and re-checks scope;
   per-risk timeout honored by `runCommand`; cross-run dedupe merges (not drops) a repeat
   finding; report renders required sections from a sample finding.
2. Live lab (re-up Juice Shop + WordPress): a run reaches a **confirmed `sqli`/`xss` finding
   on `/rest/products/search?q=`** (A2 + A1), `GET /api/report/:id` returns a submittable
   writeup (B1), a second run marks that finding `seen` not duplicated (B2), and its
   request/response evidence is retrievable (B3).
3. Guardrails still hold: destructive blocked without opt-in; out-of-scope rejected;
   confirmation tool hard-killed at its cap (no hang).

## Open decisions settled as my call (flagged for override)

- **B3 evidence is user-selectable** (`light` default / `full` via proxy), asked at intake —
  per the user's decision to support both.
- **A2 is deterministic** (a helper picks the param URL), not prompt-only — reliability over
  elegance, since the LLM demonstrably mis-targeted.
- **Serial queue stays**; only the per-tool timeout changes. Parallel scanning is out of scope.
- **Confirmation timeout default ~420s**, hard-killed — long enough for sqlmap, still bounded.
