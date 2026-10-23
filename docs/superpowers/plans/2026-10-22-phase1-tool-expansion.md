# Phase 1 — Tool Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 16 new security tools (+ SecLists) to the companion agent so the orchestrator covers far more vuln classes, all risk-tagged into the existing scope/approval gates and feeding the validate→critic→chain false-positive filter.

**Architecture:** Each tool follows the established agent pattern — a `tools.js` registry entry (`{risk, bin, build}` with args as an array, never a shell string), a `parse.js` normalizer to `{kind, items, count}`, a `reconAgent.js` `RECON_TOOLS` risk-mirror (then rebundle the orchestrator brain), and a `Dockerfile` install. Pure logic (arg builders, parsers) is unit-tested with `node --test` without Docker; tool availability + the local-lab run are verified once at the end after a single image build.

**Tech Stack:** Node ≥18 (agent, CommonJS), Go/Python/Ruby tool binaries, Docker (multi-arch/arm64), esbuild (brain bundle).

**Spec:** `docs/superpowers/specs/2026-10-22-coverage-and-roadmap-design.md`

## Global Constraints

- **Authorization model is unchanged and load-bearing.** Scope enforced server-side on every `/scan` (fail-closed). Risk tiers: `safe` auto-runs, `active`/`destructive` require per-run human approval, `destructive` also needs `AGENT_ALLOW_DESTRUCTIVE=true` + engagement `allowDestructive`.
- **Args are always an array passed to `spawn` — never a shell string.** The target host/URL is the only variable; no user input is interpolated into a flag.
- **Destructive tools are detection-only and bounded** — no data dump, no shell, no file read/write (mirror the existing `sqlmap` entry's flag discipline).
- **`tools.js` risk tags MUST equal `reconAgent.js` `RECON_TOOLS` tags** for every tool.
- **Offline-degrade:** a missing binary shows unavailable in `/health` and returns `tool_not_installed` from `/scan`; the build is non-fatal (`|| true`) on download failure.
- **API-key tools (wpscan, cvemap) ship and degrade** without a key — never crash.
- Multi-arch; builds native on arm64. Image growth from Chromium + massdns + SecLists is accepted.

## The repeating per-tool pattern (referenced by every task)

For each tool, one TDD cycle:
1. **Write failing unit test(s)** in `agent/test/<group>.test.js`: (a) `TOOLS[name].risk` equals the spec tier; (b) `buildCommand(name, '<sample target>')` returns an **array** with the target as a single element and the tool's bounded flags (destructive: assert **absence** of `--dump`/`--os-shell`/file-RW/tamper); (c) `parseOutput(name, '<sample stdout>')` returns the expected `kind` and item shape.
2. **Run** `node --test agent/test/<group>.test.js` → FAIL.
3. **Implement** the `tools.js` registry entry + `parse.js` case + `reconAgent.js` `RECON_TOOLS` mirror; add the `Dockerfile` install line (declared now, built in Task 7).
4. **Run** the tests → PASS.
5. **Rebundle** the brain (`cd iris-orchestrator && npm run bundle`) and **commit**.

## Review Focus

- **Destructive tool reaches a target without the gate** → SSTImap/commix must be tagged `destructive` so the server blocks them unless `AGENT_ALLOW_DESTRUCTIVE` + approval. *(Test in Task 5.)*
- **Malicious target injects a flag/command** → every URL-based tool must keep the target as one array element; `;`/space/flag payloads land inert. *(Test in each task that adds a URL tool; canonical test in Task 3.)*
- **API-key tool with no key** → wpscan/cvemap must run or no-op gracefully, never crash the agent. *(Test in Task 4 / Task 1.)*
- **Missing binary at runtime** → `/scan` returns `tool_not_installed`, `/health` shows unavailable, for every new tool. *(Smoke in Task 7.)*
- **Secrets fetch-then-scan leaks or hangs** → the temp content dir is bounded and removed; a large JS file can't exceed the run timeout/maxBuffer. *(Test in Task 2.)*

---

### Task 1: Safe standalone tools — assetfinder, wafw00f, cvemap

**Files:**
- Modify: `agent/lib/tools.js` (registry), `agent/lib/parse.js` (cases), `agent/Dockerfile` (installs)
- Modify: `src/utils/reconAgent.js` (`RECON_TOOLS`)
- Test: `agent/test/phase1-safe.test.js`

**Interfaces:**
- Consumes: existing `buildCommand`, `targetEndpoint`, `parseOutput`.
- Produces: `TOOLS.assetfinder|wafw00f|cvemap` (risk `safe`); parser kinds `subdomains` (assetfinder), `info` (wafw00f), `findings` (cvemap).

- [ ] **Step 1: Write failing tests** — risk `safe` for all three; `buildCommand('assetfinder','example.com')` → `['--subs-only','example.com']`-style array; `buildCommand('wafw00f', url)` targets the endpoint; `parseOutput('assetfinder','a.example.com\nb.example.com')` → `kind:'subdomains', count:2`; `parseOutput('wafw00f', '<sample>')` → `kind:'info'`; `parseOutput('cvemap', '<jsonl>')` → `kind:'findings'`.
- [ ] **Step 2: Run** `node --test agent/test/phase1-safe.test.js` → FAIL.
- [ ] **Step 3: Implement** registry entries + parser cases + `RECON_TOOLS` mirror. Arg sketches (builder verifies against current versions): assetfinder `['--subs-only', host]`; wafw00f `[url, '-o', '-', '-f', 'json']`; cvemap `['-silent', '-json']` (cvemap reads CVE ids/stdin — wire as an enrichment call; **no key → it still runs with public data, degrade quietly**). Dockerfile: `go install github.com/tomnomnom/assetfinder@latest`, `go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest`, `pipx install wafw00f` (or apt).
- [ ] **Step 4: Run** tests → PASS.
- [ ] **Step 5: Rebundle brain + commit.**

### Task 2: Secrets (fetch-then-scan) — trufflehog + gitleaks + fetch helper

**Files:**
- Create: `agent/lib/fetchContent.js` (pull in-scope URL + its linked JS to a temp dir, bounded)
- Modify: `agent/lib/tools.js`, `agent/lib/parse.js`, `agent/Dockerfile`, `src/utils/reconAgent.js`
- Modify: `agent/server.js` `/scan` handler — route `trufflehog`/`gitleaks` through the content runner instead of a plain `buildCommand`
- Test: `agent/test/phase1-secrets.test.js`

**Interfaces:**
- Consumes: `evaluateTarget`/scope, `runCommand`.
- Produces: `fetchToTempDir(url, {maxBytes, maxFiles, timeoutMs}) -> {dir, files, cleanup}`; `TOOLS.trufflehog|gitleaks` (risk `safe`, `mode:'content'`); parser kind `findings` (type `secrets`, value **masked**).

- [ ] **Step 1: Write failing tests** — `fetchToTempDir` caps total bytes and file count and returns a `cleanup()` that removes the dir; a planted canary secret in a fixture dir is found by the gitleaks/trufflehog parser → `kind:'findings', type:'secrets'` with the secret **masked** (shape only); a >maxBytes input is truncated, not unbounded. (Scanning runs over a fixture dir, no network in the unit test.)
- [ ] **Step 2: Run** `node --test agent/test/phase1-secrets.test.js` → FAIL.
- [ ] **Step 3: Implement** `fetchContent.js` (scope-checked fetch of the URL + `<script src>` JS, bounded by maxBytes/maxFiles/timeout, temp dir); `tools.js` entries with `mode:'content'` and args `['filesystem', '<dir>', '--json']` (trufflehog) / `['detect','--source','<dir>','--no-git','-f','json','--report-path','-']` (gitleaks); `server.js` routes `mode:'content'` tools through fetch→scan→cleanup; `parse.js` normalizes each tool's JSON to masked `secrets` findings; `RECON_TOOLS` mirror. Dockerfile: `go install github.com/trufflesecurity/trufflehog/v3@latest`, `go install github.com/gitleaks/gitleaks/v8@latest`.
- [ ] **Step 4: Run** tests → PASS.
- [ ] **Step 5: Rebundle brain + commit.**

### Task 3: Active recon breadth — amass, puredns, arjun, subzy, s3scanner (+ SecLists & resolvers infra)

**Files:**
- Modify: `agent/lib/tools.js`, `agent/lib/parse.js`, `agent/Dockerfile` (tools + SecLists clone + massdns + `/resolvers.txt`), `src/utils/reconAgent.js`
- Test: `agent/test/phase1-active-recon.test.js`

**Interfaces:**
- Produces: `TOOLS.amass|puredns|arjun|subzy|s3scanner` (risk `active`); parser kinds `subdomains` (amass, puredns), `urls` (arjun params), `findings` (subzy takeover, s3scanner buckets).

- [ ] **Step 1: Write failing tests** — risk `active` for all five; **flag-injection test (canonical):** `buildCommand('arjun','https://x.example.com/;curl evil')` keeps the endpoint as one element and emits no `;`/`curl` token; arg sketches present (amass `['enum','-passive','-d',host,'-silent']`; puredns `['bruteforce','<wordlist>',host,'-r','/resolvers.txt','--quiet']`; arjun `['-u',url,'-oJ','/dev/stdout']`; subzy `['run','--target',url,'--hide_fails']`; s3scanner `['-bucket', host-derived]`); parsers: `parseOutput('subzy', '<sample vulnerable line>')` → `kind:'findings', type:'takeover'`; `parseOutput('s3scanner','<open bucket>')` → `type:'s3-exposure'`; amass/puredns → `kind:'subdomains'`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** entries + parsers + mirror. Dockerfile: `go install .../amass`, `go install .../puredns` + `go install .../massdns` (or apt) + write a small trusted `/resolvers.txt`, `pipx install arjun`, `go install .../subzy`, `pipx install s3scanner`, and `git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists` (builder may use the discovery+dns subset if the full clone is too large). Point `AGENT_WORDLIST` default at a SecLists list.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Rebundle brain + commit.**

### Task 4: Active injection-adjacent & CMS — crlfuzz, jwt_tool, wpscan

**Files:** `agent/lib/tools.js`, `agent/lib/parse.js`, `agent/Dockerfile`, `src/utils/reconAgent.js`; Test: `agent/test/phase1-active-inj.test.js`

**Interfaces:** Produces `TOOLS.crlfuzz|jwt_tool|wpscan` (risk `active`); parser kind `findings` with types `crlf`, `jwt`, and WordPress findings.

- [ ] **Step 1: Write failing tests** — risk `active`; `buildCommand('wpscan', url)` contains **no** `--api-token` unless one is configured, and the entry runs without a key (degrade); arg sketches: crlfuzz `['-u', url, '-s']`, jwt_tool `[url-or-token, '-M','at']` (keep to non-destructive checks), wpscan `['--url', url, '--format','json','--no-banner', ...(apiTokenIfPresent)]`; parsers map to `kind:'findings'` with types `crlf`/`jwt`/`wordpress`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** entries (wpscan reads `WPSCAN_API_TOKEN` from env, appends `--api-token` only if set) + parsers + mirror. Dockerfile: `go install .../crlfuzz`, `pipx install jwt_tool` (or git), `gem install wpscan`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Rebundle brain + commit.**

### Task 5: Destructive injection — SSTImap, commix

**Files:** `agent/lib/tools.js`, `agent/lib/parse.js`, `agent/Dockerfile`, `src/utils/reconAgent.js`; Test: `agent/test/phase1-destructive.test.js`

**Interfaces:** Produces `TOOLS.sstimap|commix` (risk `destructive`); parser kind `findings`, types `ssti`, `cmd-injection`.

- [ ] **Step 1: Write failing tests** — risk `destructive` for both; **detection-only assertion:** args contain no `--os-shell`/`--os-cmd`/`--file-write`/`--file-read`/eval-exec flags (commix `['-u', url, '--batch', '--technique=classic', '--level','1']`; sstimap `['-u', url, '--batch']`); parser maps confirmed injection → `type:'ssti'|'cmd-injection'`, else no finding; a `TOOLS.sstimap.risk === 'destructive'` guard so the server gate (existing `riskPermitted`) blocks it without `AGENT_ALLOW_DESTRUCTIVE`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** bounded entries + parsers + mirror. Dockerfile: `pipx install sstimap` (or git clone the maintained fork), `pipx install commix` (or git).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Rebundle brain + commit.**

### Task 6: Screenshots — gowitness (+ Chromium)

**Files:** `agent/lib/tools.js`, `agent/lib/parse.js`, `agent/Dockerfile`, `src/utils/reconAgent.js`; Test: `agent/test/phase1-gowitness.test.js`

**Interfaces:** Produces `TOOLS.gowitness` (risk `active`); parser kind `findings` (informational — a screenshot artifact path per host).

- [ ] **Step 1: Write failing tests** — risk `active`; `buildCommand('gowitness', url)` targets the endpoint and writes to a fixed screenshot dir (sketch: `['scan','single','--url', url,'--screenshot-path','/tmp/iris-shots']`, builder verifies v3 syntax); `parseOutput('gowitness','<sample>')` → `kind:'findings'` carrying the artifact path, `type:'screenshot'`, severity informational.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** entry + parser + mirror. Dockerfile: `apt-get install -y --no-install-recommends chromium` and `go install github.com/sensepost/gowitness@latest`; set a chromium path env if gowitness needs it.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Rebundle brain + commit.**

### Task 7: Image build, availability smoke, WordPress lab, local-lab E2E

**Files:** Modify `iris-orchestrator/docker-compose.lab.yml` (add a WordPress container on the `iris` network); no agent code changes.

**Interfaces:** Consumes everything above.

- [ ] **Step 1:** Add a `wordpress` service (+ its `db`) to `docker-compose.lab.yml` on the `iris` network for wpscan testing, alongside Juice Shop.
- [ ] **Step 2: Build** the agent image: `docker compose build agent`. Expected: success (non-fatal tool downloads may warn).
- [ ] **Step 3: Availability smoke** — run the agent image and assert every new binary resolves: `docker run --rm --entrypoint sh <agent-image> -lc 'for t in assetfinder amass puredns arjun subzy s3scanner trufflehog gitleaks wafw00f crlfuzz jwt_tool wpscan cvemap sstimap commix gowitness; do command -v $t || echo MISSING:$t; done'`. Expected: no `MISSING`.
- [ ] **Step 4: Gate smoke** — with `AGENT_ALLOW_DESTRUCTIVE` unset, `POST /scan {tool:'commix', target:<in-scope>}` → 403 `destructive_disabled`; a `safe` tool on an out-of-scope host → 403 `out_of_scope`.
- [ ] **Step 5: Local-lab E2E** — `scripts/run-lab.sh` (Juice Shop + WordPress) with an LLM key; confirm new finding types (`secrets`, `takeover`, `wordpress`, etc.) appear, active/destructive steps raise approval prompts, and everything flows through the validate→critic→chain filter to the dashboard.
- [ ] **Step 6: Commit** the lab-compose change and a short `CHANGELOG`/README note of the added tools.

## Self-Review notes

- **Spec coverage:** every tool in spec §1.1 (core + heavy trio) maps to Tasks 1–6; "ship-and-degrade" API-key tools → Tasks 1 & 4; SecLists/resolvers infra → Task 3; new finding types → each owning task's parser; E2E incl. WordPress → Task 7. Classes left to nuclei/brain are intentionally no-ops here (spec §1.1 "Not adding").
- **Review Focus:** each of the five lines has an owning test (Tasks 5, 3, 4/1, 7, 2).
- **Proportion:** per-tool bodies are intentionally omitted — the implementer writes idiomatic entries from the arg sketch + the existing `sqlmap`/`nuclei` entries as templates; the plan fixes only risk tiers, arg bounds, parser kinds, and test assertions.
