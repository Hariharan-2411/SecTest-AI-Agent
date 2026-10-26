# Iris Orchestrator

A standalone, Dockerized bug-bounty **recon/triage orchestrator**. It drives the Iris
companion agent (the tool-runner) headlessly so you don't need your laptop or browser on:
give it target URLs + the program's rules, it runs recon/scanning on its own, and it
**asks you to approve** any active/destructive step remotely (Telegram + web dashboard)
before it runs. Nothing is auto-submitted — output is a ranked triage draft for you.

> **Authorized testing only.** Use solely on assets explicitly in-scope for a program you
> are authorized to test. Scope is enforced server-side by the agent on every scan;
> active/destructive tools require explicit per-action human approval; PoCs stay
> non-destructive. You own validation and submission.

## How it reuses the Iris extension (one source of truth)

The analysis brain lives in the extension repo (`Extension/chrome-boiler/src/utils/`).
Rather than copy it, `npm run bundle` compiles the exact functions we wire into a
self-contained `vendor/brain.mjs` via esbuild (the modules use ESM syntax in a non-ESM
package, so a tiny build step is required; the browser/Supabase-coupled `aiProvider` is
stubbed because the orchestrator injects its own LLM `chat`). Point `IRIS_SRC` at the
extension repo (default `../Extension/chrome-boiler`). Re-run `npm run bundle` to pick up
extension changes.

**Standalone:** the built `vendor/brain.mjs` is **committed to this repo**, so a fresh
clone runs with no access to the extension — `npm run bundle` detects the missing source
and keeps the committed brain instead of failing. The extension stays the single source of
truth: to ship a brain update you edit it there, re-run `npm run bundle` here (which
rebuilds from `IRIS_SRC`), and commit the refreshed `vendor/brain.mjs`.

## Architecture

```
intake (URLs + rules) ─► fail-closed scope+policy ─► runReconLoop (bundled brain)
                                                        │  safe → auto-run
                                                        │  active/destructive → approval broker
                                                        ▼
                      Telegram bot + web dashboard ◄── approve/deny (from your phone)
                                                        │
                                            HTTP (x-agent-token) ─► companion agent (subfinder/httpx/nuclei/…)
                                                                     scope re-checked server-side on every /scan
```

## Quick start (local, no Docker)

```bash
cp .env.example .env            # set AGENT_TOKEN, LLM_API_KEY, (optional) Telegram
npm install
npm run bundle                  # build vendor/brain.mjs from IRIS_SRC
# start the companion agent separately (see Extension/chrome-boiler/agent)
npm start                       # dashboard on http://localhost:8790
```

## Docker (both services)

```bash
npm run bundle                  # MUST run on host first — image copies vendor/brain.mjs
cp .env.example .env            # set AGENT_TOKEN + LLM creds
docker compose up --build       # brings up agent + orchestrator; dashboard on 127.0.0.1:8790
```

> **Upgrading from a pre-hardening (root) build?** The images now run as non-root `node`.
> A data volume first created by the old root container stays root-owned, so the non-root
> process can't write it (`EACCES`). Recreate the volumes once: `docker compose down -v`
> then `docker compose up -d` (fresh volumes initialize with `node` ownership). This clears
> local run history; it's dev/test data.

### Keeping the images patched (manual)

Both images use a digest-pinned `node:22-trixie-slim` base, `apt upgrade`, and install
tools at `@latest`, and both run as a non-root `node` user. To pull newly-released
patches you must bypass the layer cache — a plain rebuild reuses the cached
`apt upgrade`/`@latest` layers and gets nothing new:

```bash
# Orchestrator
cd iris-orchestrator && npm run bundle
docker build --no-cache -t iris-orchestrator-orchestrator:latest .

# Agent (its 16+ tools reinstall at @latest → picks up upstream security fixes)
cd ../Extension/chrome-boiler/agent
docker build --no-cache -t iris-orchestrator-agent:latest .
```

Patching costs no runtime performance. Residual CVEs in the agent are inside the
security tools' own dependencies + chromium (gowitness) — they clear only as the
tool authors / Debian ship fixes, which a `--no-cache` rebuild then pulls in. To also
move to a newer base, re-pull `node:22-trixie-slim`, take its new digest, and bump the
`FROM` line. Scan anytime with `docker scout quickview <image>`.

## Dual-model planner / critic (optional)

A second model can review every planned step before it runs. Set the `CRITIC_*`
env vars (they fall back to the `LLM_*` proposer config for anything unset) — e.g.
proposer on OpenRouter, **critic on Groq**. The critic returns a verdict per step and
the recon loop merges it with a hard invariant:

> **The critic can only TIGHTEN, never loosen** — it may downgrade
> `allow → needs_approval → deny` or drop a step, but can never turn a `deny` into
> `allow` or escalate a tool's risk. If the critic errors or returns garbage, the
> planner's original decision stands (fail-safe).

So a second opinion cuts noise, over-eager scans, and false positives without ever
becoming a way around scope or the human-approval gate. Leave `CRITIC_*` blank for
single-model operation. `GET /health` reports the active critic provider (or `false`).

## Chain hypotheses (depth & impact across in-scope assets)

After each scan the orchestrator asks the LLM to propose exploit **chains** across the
findings it collected — including **across multiple in-scope subdomains** (a token leaked
on `a.example.com` that works on `b.example.com`). It's grounded and scope-gated:

- every chain step must reference a **real finding**; a chain with <2 grounded steps is dropped;
- **each step's host is re-checked against scope** — a step on an out-of-scope host is rejected,
  so chaining never wanders outside what the program authorizes;
- severity is derived deterministically; **nothing executes** — you get a ranked hypothesis to verify.

Chains show on the dashboard and at `GET /api/chains`; high/critical ones also ping the bot.
This is the "path to impact" feature — the AI reasons, you confirm and report.

## LLM backends (provider-agnostic)

Set in `.env`:
- **Groq** (default): `LLM_PROVIDER=groq`, `LLM_API_KEY=…`
- **Claude**: `LLM_PROVIDER=anthropic`, `LLM_API_KEY=…`, `LLM_MODEL=claude-opus-4-8`
- **Self-hosted / EC2 / vLLM / Ollama / AWS Bedrock** (OpenAI-compatible):
  `LLM_PROVIDER=openai-compatible`, `LLM_BASE_URL=http://your-ec2:8000/v1`, `LLM_MODEL=…`

`LLM_PARSE_MODEL` optionally routes high-volume parsing to a cheaper model.

## Remote approval

Set `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` for two-way Approve/Deny from your phone
(long-polling — no public URL needed). `DISCORD_WEBHOOK_URL` and `SLACK_WEBHOOK_URL` get
one-way alerts (new findings + an approval heads-up; decide those from the dashboard).
The dashboard also lists pending approvals with Approve/Deny buttons, and **updates live**
over Server-Sent Events (`GET /api/events`) — a header shows `● live` — falling back to a
slow poll if the stream drops.

## Passive / recon-only mode

Tick **"Passive / recon-only"** at intake (or `POST /api/engagements {"passive":true,...}`) to run
**OSINT only** — `subfinder`, `assetfinder` (subdomains) + `gau`, `waybackurls` (historical URLs).
These query third-party sources (passive DNS, cert logs, Wayback, CommonCrawl) and send **no
traffic to the target**, so it's the one mode safe to point at a program whose rules forbid
automated scanning: it reads public data to build a map you then test **by hand**. It bypasses
the LLM loop and never runs any target-contacting tool by construction. Results (deduped
subdomains + URLs) show on the dashboard's **Passive recon map** and at `GET /api/recon`.

> Even passive recon: only enumerate assets you're authorized to research, and do your actual
> testing within each program's rules.

## Scope import

`POST /api/scope/import {"text":"…"}` parses a program's scope into the arrays intake
consumes — no run is started, it's a preview. It sniffs the format:

- **HackerOne** structured scopes (`data[].attributes`, `structured_scopes[]`, or a bare
  array of `asset_identifier`/`asset_type`) — `eligible_for_submission:false` entries go
  out-of-scope.
- **Bugcrowd** `{in_scope:[…], out_of_scope:[…]}` / `targets[]` (strings or `{target,category}`).
- **Plain text** scope blocks with "In scope" / "Out of scope" headers, markdown bullets
  and backticks.

Wildcards (`*.example.com`) become the bare host **plus** auto-enabled subdomain
enumeration. Non-web assets (mobile app ids, source repos, CIDR ranges, hardware) are
dropped with a warning — this is a web recon tool. The dashboard has a "Paste scope →
Parse & fill" box that populates the engagement form.

## Scope & policy (fail closed)

Intake turns URLs + rules text into `{inScope, outOfScope}` + a policy. Active tools are
enabled **only** when the rules permit automation **and** you tick "I confirm this policy";
destructive tools need an additional explicit opt-in. Anything unclear ⇒ safe tools only.

**Destructive tier (injection scanners).** `dalfox` (XSS) and `sqlmap` (SQLi) are registered
in the agent as `destructive` with **detection-only, bounded flags** (no `sqlmap --dump`/
`--os-shell` etc. — a hit is a non-destructive PoC). They are triple-gated: the agent runs
them only with `AGENT_ALLOW_DESTRUCTIVE=true` (default **off**), the engagement policy must
opt in (confirm + "allow destructive"), and the orchestrator still asks you to **approve each
run**. With any of those missing, the brain `deny`s them before they are ever requested.

## Unattended operation (continuous monitoring · kill-switch · audit)

Built for running on its own and being driven from a phone:

- **Continuous monitoring** — `POST /api/monitors` (same body as an engagement plus
  `intervalMs`) schedules a recon re-run on an interval. Cross-run dedupe means the bot
  pings you **only when a finding is new** — a quiet monitor means nothing changed.
  `GET /api/monitors` lists active ones; `POST /api/monitors/:id/stop` ends one. Monitors
  are durable and `resume()` re-arms them after a restart. The dashboard has "Start +
  monitor" and an Active-monitors panel.
- **Kill-switch** — `POST /api/killswitch {"action":"engage","reason":"…"}` halts
  everything: new engagements are refused (`503`), the in-flight loop throws at its next
  scan, scheduled monitors skip their cycles, and all pending approvals are auto-denied.
  The flag is **durable and fail-safe** — a restart stays halted until
  `{"action":"clear"}`. `GET /api/killswitch` reports state; the dashboard shows a
  Live/HALTED banner with a one-click toggle.
- **Audit log** — every consequential action and decision (intake, scan dispatch, each
  approval request/approve/deny/timeout, new findings, kill-switch and monitor changes) is
  recorded append-only. `GET /api/audit?tail=N`; shown on the dashboard.

## Test

```bash
npm test                        # node --test: approvals, intake, llm, run, audit, killswitch, monitor, …
```

See the local-lab E2E in `Extension/chrome-boiler/test-targets.sh` (Juice Shop / DVWA /
WebGoat) to exercise the full flow against authorized targets.

## Layout

- `server.js` — HTTP: health, intake API, approvals, runs/findings, dashboard
- `lib/llm.js` — provider-agnostic LLM client (+ safety preamble)
- `lib/approvals.js` — approval broker (suspend-until-human, timeout = deny)
- `lib/intake.js` — URLs + rules → fail-closed scope + policy
- `lib/scopeImport.js` — HackerOne/Bugcrowd/text scope → engagement fields
- `lib/run.js` — wires the bundled brain's `runReconLoop`
- `lib/bot.js` — Telegram long-poll + Discord/Slack webhooks
- `lib/events.js` — in-process event bus → live dashboard (SSE `GET /api/events`)
- `lib/monitor.js` — scheduled recurring runs (new-only alerts, durable, kill-switch-aware)
- `lib/killswitch.js` — durable fail-safe emergency halt
- `lib/audit.js` — append-only action/decision log
- `lib/store.js` — atomic JSON persistence
- `scripts/bundle-brain.mjs` — esbuild bundle of the extension brain
- `web/index.html` — single-file dashboard
