# Iris Orchestrator — Coverage & Roadmap Design

_Date: 2026-10-22_

## Context / why

The orchestrator drives the companion agent headlessly and already does recon →
scan → triage with human-approved active/destructive steps, a dual-model critic,
and cross-asset chain hypotheses. Two gaps remain:

1. **Finding breadth** — coverage stops at the ProjectDiscovery stack + dalfox/sqlmap,
   so whole vuln classes (SSTI, command injection, CRLF, JWT, WordPress, secrets,
   takeover, cloud) go untested.
2. **The trail ends at a ranked draft** — no report generation, no cross-run dedupe,
   no PoC capture, no continuous monitoring, limited trust/ops plumbing.

This design **locks Phase 1 (tool expansion)** build-ready and **sequences Phases 2–5**
(the user's roadmap) so we ship one phase at a time instead of one big bang.

## Authorization posture (unchanged — load-bearing for every phase)

Authorized, in-scope assets only. Scope is enforced **server-side** by the agent on
every scan (fail-closed). Tools are risk-tagged `safe | active | destructive`:
`safe` auto-runs, `active`/`destructive` require explicit per-run **human approval**,
and `destructive` additionally requires the engagement's `allowDestructive` opt-in +
`AGENT_ALLOW_DESTRUCTIVE=true`. PoCs stay **non-destructive** (confirm, don't exfiltrate).
**No auto-submit.** The critic may only tighten decisions, never loosen. Every new tool
inherits this model unchanged.

## Goals / Non-goals / Anti-goals

**Goals:** broad, high-signal coverage across the kill chain and vuln classes; keep
false positives low by funneling every tool's output through `validate.js` → critic →
chain grounding; deliver in independently-shippable phases.

**Non-goals:** autonomous exploitation beyond non-destructive confirmation; auto-submission;
any action outside the loaded scope.

**Anti-goals (failure even if it "works"):** drowning the user in false positives;
getting the user rate-limited/banned by programs; the agent ever acting outside scope.

## Constraints

- Reuse the existing patterns exactly: agent `tools.js` registry (`{risk, bin, build}`,
  args as an **array**, no shell), `parse.js` normalizer, `reconAgent.js` `RECON_TOOLS`
  risk-mirror, `Dockerfile` install, rebundle brain.
- Multi-arch (builds native on Apple Silicon arm64).
- Keep the agent image lean; defer heavyweight installs.
- Offline-degrade: missing binaries show unavailable in `/health`, never crash.
- API-key tools are optional and degrade when the key is absent.

---

## Phase 1 — Tool expansion (BUILD-READY)

### 1.1 Tools to add

**Core (cheap Go/Python binaries — include now):**

| Tool | Stage / class | Risk | bin | Install | Parser `kind` |
|---|---|---|---|---|---|
| assetfinder | subdomains (passive) | safe | assetfinder | go install | subdomains |
| amass | subdomains (passive+active) | active | amass | apt/snap or go | subdomains |
| arjun | parameter discovery | active | arjun | pipx | urls |
| subzy | subdomain takeover | active | subzy | go install | findings |
| s3scanner | cloud buckets | active | s3scanner | pipx | findings |
| trufflehog | secrets (JS/content) | safe | trufflehog | go install | findings |
| gitleaks | secrets (repos/content) | safe | gitleaks | go install | findings |
| wafw00f | WAF detection | safe | wafw00f | pipx | info |
| crlfuzz | CRLF injection | active | crlfuzz | go install | findings |
| jwt_tool | JWT attacks | active | jwt_tool | pipx | findings |
| wpscan | WordPress | active¹ | wpscan | gem install | findings |
| cvemap | CVE mapping | safe¹ | cvemap | go install | findings |
| SSTImap | SSTI | **destructive** | sstimap | pipx | findings |
| commix | command injection | **destructive** | commix | pipx | findings |
| gowitness | screenshots (visual triage) | active | gowitness | go + chromium | findings(info) |
| puredns | subdomains (DNS brute) | active | puredns | go + massdns | subdomains |
| _SecLists_ | wordlists for ffuf/feroxbuster | n/a | — | git clone | — |

**Heavier — included in Phase 1 per user decision (accept the image growth):**
`gowitness` needs **headless Chromium** (apt `chromium`), adding a few hundred MB — gives
fast visual triage of many hosts. `puredns` needs **massdns** + a trusted resolver list
(bundled in the image) for reliable DNS brute-forcing without false resolves. **SecLists**
is cloned into the image (`/usr/share/seclists`) to back ffuf/feroxbuster; if full clone
proves too large at build time, fall back to the high-value subset (discovery + dns +
common) — builder's call at build time.

¹ API-key tools: `wpscan` (WPScan API token for its vuln DB), `cvemap`/`chaos`
(ProjectDiscovery PDCP key). Optional — degrade to no-key behavior if unset, same
`.env` pattern as the LLM keys.

**Not adding dedicated tools** (nuclei templates + the brain already cover these at high
signal; a dedicated scanner would only add noise): open redirect, LFI/path traversal,
XXE, SSRF *detection*, SPF/DMARC, git/.env exposure, exposed panels/CVEs/takeover
templates, CORS, GraphQL, headers/cookies. Ensure the brain's `headers.js`/`graphql.js`
analyzers run server-side; SSRF/RCE blind confirmation uses the existing `oob.js` catcher.

### 1.2 Work per tool (the repeating pattern)

For each tool, five mechanical steps mirroring the existing code:
1. `agent/lib/tools.js` — registry entry `{risk, bin, build:(host,url,profile)=>args[]}`,
   args as an array, host/url the only variables. Destructive tools get **detection-only,
   bounded** flags (no data dump / shell / file R-W), like today's `sqlmap` entry.
2. `agent/lib/parse.js` — a `case` normalizing stdout to `{kind, items, count, raw}`.
3. `src/utils/reconAgent.js` — add `{risk}` to `RECON_TOOLS` (must match tools.js).
4. `agent/Dockerfile` — install the binary in the right stage (go stage / apt / pipx /
   gem), **non-fatal** (`|| true`) so an offline build still succeeds.
5. Rebundle the brain (`npm run bundle`); `/health` then reports availability.

### 1.3 New finding types & false-positive handling

New normalized finding `type`s: `secrets`, `takeover`, `s3-exposure`, `ssti`,
`cmd-injection`, `crlf`, `jwt`, `waf`(informational). They flow into `validate.js` which
scores/bands them (unknown types fall back to `unknownBase` — acceptable for v1; bespoke
scoring rules are an optional follow-up). The dual-model critic and chain grounding apply
unchanged. **Cross-run dedupe is explicitly Phase 2**, not here.

> **Secrets-tool wiring (my call):** `trufflehog`/`gitleaks` are not host-target tools
> like the others — they scan content, not a URL. The agent fetches in-scope JS/responses
> (reusing what `katana`/`httpx` already pull) into a temp dir and runs them in
> `filesystem` mode over it, then cleans up. So the "secrets" stage is fetch-then-scan,
> wired in the executor rather than a plain `build(host,url)` arg set.

### 1.4 Risk-tier summary

- **destructive** (opt-in + approval + `AGENT_ALLOW_DESTRUCTIVE`): SSTImap, commix
  (joining dalfox, sqlmap).
- **active** (approval): amass, arjun, subzy, s3scanner, crlfuzz, jwt_tool, wpscan, gowitness, puredns.
- **safe** (auto): assetfinder, trufflehog, gitleaks, wafw00f, cvemap.

### 1.5 Phase-1 verification

Per-tool unit tests (`node --test`): correct risk tag; destructive tools assert **no**
`--dump`/`--os-shell`/file-RW flags; parser produces the expected `kind`. `/health` lists
each tool's availability. Local-lab E2E (Juice Shop for injection/secrets + a throwaway WordPress container for
wpscan — I'll add both to `docker-compose.lab.yml`) shows new
finding types appearing and flowing through the FP filter. Scope negative test still holds.

---

## Phases 2–5 (outline — sequenced, not yet build-ready)

**Phase 2 — Close the loop to submission** (highest leverage):
- Report generator: wire existing `reportBuilder.js` (H1/Bugcrowd Markdown) into a
  `GET /api/report/:findingOrChainId` + dashboard "Copy report" button.
- Cross-run dedupe + CVSS: persist finding SHA-fingerprints in the store; on re-scan,
  merge instead of piling up; surface `enrich.js` CVSS on each.
- PoC evidence capture: store the request/response that backs each finding; screenshots
  when `gowitness` is added.

**Phase 3 — Continuous monitoring:**
- Orchestrator-level scheduler over the agent's existing `watches.js` + `recondiff.js`;
  alert (bot) only on **new** subdomains/endpoints/findings since last run.
- Persistent asset-inventory store collection across engagements.

**Phase 4 — Trust & operability:**
- Append-only audit log (store collection) of every plan decision, critic verdict, and
  approve/deny (who/when/why).
- Global pause / kill-switch endpoint + a guard checked in the loop; per-engagement rate
  limit (agent already has `AGENT_RATE_MAX`).
- Approve-with-reason (extend the broker); dashboard run-detail view + findings search.

**Phase 5 — Plumbing:**
- SSE dashboard (replace polling); Slack notifier (add to `bot.js`; `notify.js` already
  formats Slack); LLM cost/token tracking + model fallback in `llm.js`; import scope
  directly from HackerOne/Bugcrowd scope APIs.

## What's left to the builder

- Exact current-version flags per tool in 1.1 (sketched here; verify against each tool's
  current release at build time).
- Whether any new finding `type` earns a bespoke `validate.js` scoring rule vs.
  `unknownBase` (default: `unknownBase` for v1).
- Dockerfile layer ordering to keep the image lean (group pipx installs, cache go builds).

## Open decisions settled as my call (flagged for override)

- **Full coverage (user decision, 2026-10-22):** `gowitness`/Chromium, `puredns`/massdns,
  and SecLists are **included in Phase 1**. The image grows by several hundred MB — accepted
  for maximum coverage.
- **API-key tools included but optional:** wpscan/cvemap ship in the image and simply
  degrade without a key.
- **No bespoke scoring** for new finding types in Phase 1 (`unknownBase` fallback).
