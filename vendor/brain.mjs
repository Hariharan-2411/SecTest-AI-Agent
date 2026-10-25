// ../Extension/chrome-boiler/src/utils/scope.js
var EMPTY_SCOPE = { inScope: [], outOfScope: [] };
function hostFromUrl(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (_) {
    return "";
  }
}
function normalizePattern(raw) {
  if (!raw || typeof raw !== "string") return "";
  let s = raw.trim();
  if (!s || s.startsWith("#") || s.startsWith("//")) return "";
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  s = s.split("/")[0].split("?")[0].split("#")[0];
  s = s.replace(/:\d+$/, "");
  s = s.trim().toLowerCase().replace(/\.$/, "");
  if (s.startsWith(".")) s = "*" + s;
  return s;
}
function parseScopeText(text) {
  if (!text || typeof text !== "string") return [];
  const out = [];
  const seen = /* @__PURE__ */ new Set();
  for (const token of text.split(/[\n,]/)) {
    const p = normalizePattern(token);
    if (p && !seen.has(p)) {
      seen.add(p);
      out.push(p);
    }
  }
  return out;
}
function matchesPattern(hostname, pattern) {
  if (!hostname || !pattern) return false;
  const host = hostname.toLowerCase();
  const pat = pattern.toLowerCase();
  if (pat === "*") return true;
  if (pat.startsWith("*.")) {
    const base = pat.slice(2);
    return host === base || host.endsWith("." + base);
  }
  return host === pat;
}
function matchesAny(hostname, patterns) {
  return Array.isArray(patterns) && patterns.some((p) => matchesPattern(hostname, p));
}
function evaluateScope(url, scope = EMPTY_SCOPE) {
  const host = hostFromUrl(url);
  if (!host) return { allowed: false, reason: "bad_url", host: "" };
  const inScope = scope && scope.inScope || [];
  const outOfScope = scope && scope.outOfScope || [];
  if (matchesAny(host, outOfScope)) return { allowed: false, reason: "out_of_scope", host };
  if (inScope.length === 0) return { allowed: false, reason: "no_scope", host };
  if (matchesAny(host, inScope)) return { allowed: true, reason: "in_scope", host };
  return { allowed: false, reason: "not_in_scope", host };
}
function isInScope(url, scope = EMPTY_SCOPE) {
  return evaluateScope(url, scope).allowed;
}

// ../Extension/chrome-boiler/src/utils/findings.js
var FINDING_SEVERITIES = ["critical", "high", "medium", "low", "informational"];
function deriveSeverity(constituents) {
  const idxs = (Array.isArray(constituents) ? constituents : []).map((f) => FINDING_SEVERITIES.indexOf(f && f.severity)).filter((i) => i >= 0);
  if (!idxs.length) return "informational";
  const base = Math.min(...idxs);
  return FINDING_SEVERITIES[Math.max(0, base - 1)];
}
function severityRank(sev) {
  const i = FINDING_SEVERITIES.indexOf(sev);
  return i === -1 ? FINDING_SEVERITIES.length : i;
}
function normalizeFinding(f = {}, now = (/* @__PURE__ */ new Date()).toISOString()) {
  const norm = {
    id: f.id || `${f.type || "finding"}:${f.title || ""}`,
    host: f.host || "",
    type: f.type || "finding",
    severity: FINDING_SEVERITIES.includes(f.severity) ? f.severity : "medium",
    confidence: typeof f.confidence === "number" ? f.confidence : null,
    title: f.title || "Finding",
    evidence: f.evidence || "",
    source: f.source || "manual",
    ref: f.ref || "",
    firstSeen: f.firstSeen || now,
    updatedAt: now
  };
  if (f.sink) norm.sink = f.sink;
  if (Array.isArray(f.sources)) norm.sources = f.sources;
  return norm;
}
function dedupeKey(f, { crossHost = false } = {}) {
  const base = f.id || `${f.type}:${f.title}`;
  return crossHost ? String(base) : `${f.host || ""}|${base}`;
}
function dedupeFindings(list, { crossHost = false } = {}) {
  const byKey = /* @__PURE__ */ new Map();
  for (const f of Array.isArray(list) ? list : []) {
    const key = dedupeKey(f, { crossHost });
    const prev = byKey.get(key);
    if (!prev || severityRank(f.severity) < severityRank(prev.severity)) {
      byKey.set(key, f);
    }
  }
  return Array.from(byKey.values());
}
function sortFindings(list) {
  return [...Array.isArray(list) ? list : []].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity) || (b.confidence || 0) - (a.confidence || 0)
  );
}
function summarizeFindings(list) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0, total: 0 };
  for (const f of Array.isArray(list) ? list : []) {
    if (counts[f.severity] != null) counts[f.severity]++;
    counts.total++;
  }
  return counts;
}

// ../Extension/chrome-boiler/src/utils/reconAgent.js
var RECON_TOOLS = {
  subfinder: { risk: "safe" },
  dnsx: { risk: "safe" },
  httpx: { risk: "safe" },
  gau: { risk: "safe" },
  waybackurls: { risk: "safe" },
  naabu: { risk: "active" },
  nmap: { risk: "active" },
  nuclei: { risk: "active" },
  katana: { risk: "active" },
  ffuf: { risk: "active" },
  feroxbuster: { risk: "active" },
  // Injection scanners — fire real payloads. Destructive tier: denied unless the
  // engagement policy opts in, and then still human-approved per run. Must mirror
  // agent/lib/tools.js risk tags.
  dalfox: { risk: "destructive" },
  sqlmap: { risk: "destructive" },
  // Phase 1 — expanded coverage (tags must match agent/lib/tools.js).
  assetfinder: { risk: "safe" },
  wafw00f: { risk: "safe" },
  cvemap: { risk: "safe" },
  trufflehog: { risk: "safe" },
  gitleaks: { risk: "safe" },
  amass: { risk: "active" },
  puredns: { risk: "active" },
  arjun: { risk: "active" },
  subzy: { risk: "active" },
  s3scanner: { risk: "active" },
  crlfuzz: { risk: "active" },
  jwt_tool: { risk: "active" },
  wpscan: { risk: "active" },
  gowitness: { risk: "active" },
  sstimap: { risk: "destructive" },
  commix: { risk: "destructive" }
};
var RECON_PROFILES = ["quick", "top1000", "services", "deep"];
var DEFAULT_PROFILE = "quick";
var RISK_POLICY = {
  safe: "allow",
  active: "needs_approval",
  destructive: "deny"
};
var MAX_RECON_STEPS = 12;
var DEFAULT_RECON_BUDGET = 20;
function str(v) {
  return typeof v === "string" ? v : "";
}
function deny(reason) {
  return { decision: "deny", reason, call: null };
}
function targetUrl(target) {
  const t = str(target).trim();
  if (!t) return "";
  return /^https?:\/\//i.test(t) ? t : `https://${t.replace(/^\/+/, "")}`;
}
function decideByRisk(risk, policy) {
  const action = policy[risk];
  if (action === "allow") return { decision: "allow", reason: "" };
  if (action === "needs_approval")
    return { decision: "needs_approval", reason: `${risk}_tool` };
  return { decision: "deny", reason: `risk_denied:${risk}` };
}
function normalizeToolCall(raw = {}, {
  scope,
  policy = RISK_POLICY,
  budgetUsed = 0,
  budget = DEFAULT_RECON_BUDGET
} = {}) {
  const tool = str(raw.tool);
  const def = RECON_TOOLS[tool];
  if (!def) return deny(`unknown_tool:${tool || "(none)"}`);
  const target = str(raw.target).trim();
  const url = targetUrl(target);
  if (!url) return deny("bad_target");
  const ev = evaluateScope(url, scope || EMPTY_SCOPE);
  if (!ev.allowed) return deny(`out_of_scope:${ev.reason}`);
  if (budgetUsed >= budget) return deny("over_budget");
  const risk = def.risk;
  const profile = RECON_PROFILES.includes(raw.profile) ? raw.profile : DEFAULT_PROFILE;
  const rd = decideByRisk(risk, policy);
  if (rd.decision === "deny")
    return { decision: "deny", reason: rd.reason, call: null };
  return {
    decision: rd.decision,
    reason: rd.reason,
    call: { tool, target, profile, risk }
  };
}
function normalizeReconPlan(rawPlan, opts = {}) {
  const list = Array.isArray(rawPlan) ? rawPlan : Array.isArray(rawPlan && rawPlan.steps) ? rawPlan.steps : Array.isArray(rawPlan && rawPlan.tools) ? rawPlan.tools : [];
  const steps = [];
  const rejected = [];
  for (const raw of list) {
    if (steps.length >= MAX_RECON_STEPS) {
      rejected.push({ raw, reason: "over_cap" });
      continue;
    }
    steps.push(normalizeToolCall(raw, opts));
  }
  return { steps, rejected };
}
function rankTriage(findings) {
  return sortFindings(Array.isArray(findings) ? findings : []).map((f, i) => ({
    ...f,
    rank: i + 1
  }));
}

// ../Extension/chrome-boiler/src/utils/reconExecutor.js
function mapNucleiSeverity(sev) {
  const s = String(sev || "").toLowerCase();
  if (s === "info") return "informational";
  return FINDING_SEVERITIES.includes(s) ? s : "medium";
}
function toFindings(body = {}) {
  if (!body || body.kind !== "findings" || !Array.isArray(body.items))
    return [];
  const host = body.host || "";
  return body.items.map(
    (it) => normalizeFinding({
      type: "nuclei",
      host,
      severity: mapNucleiSeverity(it && it.severity),
      title: it && (it.name || it.templateId) || "nuclei finding",
      evidence: it && it.matched || "",
      ref: it && it.templateId || "",
      source: "nuclei"
    })
  );
}
function fail(tool, target, status, error, host = "") {
  return {
    ok: false,
    tool,
    target,
    host,
    status,
    error,
    kind: null,
    items: [],
    count: 0,
    findings: []
  };
}
async function executeReconTool(call = {}, { agentClient } = {}) {
  const { tool, target, profile } = call;
  if (!agentClient || typeof agentClient.scan !== "function") {
    return fail(tool, target, 0, "no_agent_client");
  }
  let status;
  let body;
  try {
    ({ status, body } = await agentClient.scan({ tool, target, profile }));
  } catch (_) {
    return fail(tool, target, 0, "call_failed");
  }
  body = body || {};
  if (status !== 200) {
    return fail(
      tool,
      target,
      status,
      typeof body.error === "string" && body.error || `status_${status}`,
      body.host || ""
    );
  }
  const items = Array.isArray(body.items) ? body.items : [];
  return {
    ok: true,
    tool,
    target,
    host: body.host || "",
    status,
    error: null,
    kind: body.kind || null,
    items,
    count: typeof body.count === "number" ? body.count : items.length,
    findings: toFindings(body),
    command: body.command || "",
    // for PoC evidence (Light mode)
    raw: String(body.raw || "").slice(0, 4e3),
    evidence: body.evidence || null
    // Full-mode req/resp flows, when present
  };
}
function makeAgentClient({
  baseUrl = "http://localhost:8787",
  token = "",
  evidence,
  fetchImpl
} = {}) {
  const doFetch = fetchImpl || (typeof fetch !== "undefined" ? fetch : null);
  return {
    async scan({ tool, target, profile }) {
      if (!doFetch) throw new Error("no_fetch");
      const res = await doFetch(`${baseUrl}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-agent-token": token },
        body: JSON.stringify({ tool, target, profile, ...evidence ? { evidence } : {} })
      });
      let body = {};
      try {
        body = await res.json();
      } catch (_) {
      }
      return { status: res.status, body };
    }
  };
}

// ../Extension/chrome-boiler/src/utils/escalation.js
var ACTION_VERBS = {
  deep_js: { risk: "safe", targetKind: "none" },
  confirm_reflection: { risk: "safe", targetKind: "none" },
  probe_endpoint: { risk: "safe", targetKind: "url" },
  run_payload: { risk: "active", targetKind: "none" },
  differential_probe: { risk: "active", targetKind: "url" },
  agent_scan: { risk: "active", targetKind: "host" },
  manual: { risk: "none", targetKind: "none" }
};

// ../Extension/chrome-boiler/src/utils/validate.js
var BANDS = { confirmed: 80, likely: 55, tentative: 30, noise: 0 };
var DEFAULT_REPORT_THRESHOLD = BANDS.likely;
var RULES = {
  domXssBase: 30,
  // A runtime canary that reached the sink (domProbe) is strong reachability
  // evidence — additive, still human-verified for actual exploitability.
  probeConfirmedBonus: 25,
  reflection: {
    js: 50,
    "html-body": 45,
    attribute: 15,
    string: -5,
    url: -5,
    rfl: 0,
    none: -35
  },
  taintedSinkBonus: 25,
  injectionBase: 30,
  // Applied by finding type: 'sqli-boolean' (strong) vs 'sqli-time' (noisier).
  oracle: { boolean: 50, time: 35 },
  secretBase: {
    aws_access_key: 78,
    stripe_key: 78,
    github_token: 75,
    google_api_key: 72,
    slack_token: 72,
    private_key: 85,
    jwt: 50
  },
  secretCap: 90,
  // never fully certain — we never USE the key to confirm it's live
  entropyHigh: 4,
  entropyHighBonus: 8,
  entropyLow: 3,
  entropyLowPenalty: -15,
  headersBase: 35,
  headersCap: 45,
  // a missing header is a signal, not a demonstrated vuln
  oobBase: 40,
  oobHitBonus: 55,
  // A nuclei template match is a curated known-vuln signature — high-signal, but
  // still human-verified (nuclei has some false positives).
  nucleiBase: 75,
  unknownBase: 35
};
var SECRET_TYPES = new Set(Object.keys(RULES.secretBase));
function clamp(n, lo = 0, hi = 100) {
  return Math.max(lo, Math.min(hi, n));
}
function bandFor(confidence) {
  if (confidence >= BANDS.confirmed) return "confirmed";
  if (confidence >= BANDS.likely) return "likely";
  if (confidence >= BANDS.tentative) return "tentative";
  return "noise";
}
function hasTaintedSink(f) {
  return !!(f && f.sink && Array.isArray(f.sources) && f.sources.length > 0);
}
function pushVerb(list, verb) {
  if (ACTION_VERBS[verb] && !list.includes(verb)) list.push(verb);
}
function scoreSecret(finding, reasons) {
  const type = finding.type;
  let score = RULES.secretBase[type];
  reasons.push(`secret type "${type}" matched by pattern`);
  if (typeof finding.entropy === "number") {
    if (finding.entropy >= RULES.entropyHigh) {
      score += RULES.entropyHighBonus;
      reasons.push("high Shannon entropy (looks like a live credential)");
    } else if (finding.entropy < RULES.entropyLow) {
      score += RULES.entropyLowPenalty;
      reasons.push("low entropy (likely a placeholder/example value)");
    }
  }
  score = Math.min(score, RULES.secretCap);
  reasons.push("not verified live \u2014 we never use the key to confirm it");
  return score;
}
function scoreDomXss(finding, reasons, needMore) {
  let score = RULES.domXssBase;
  const ctx = finding.reflection;
  const tainted = hasTaintedSink(finding);
  if (ctx && Object.prototype.hasOwnProperty.call(RULES.reflection, ctx)) {
    score += RULES.reflection[ctx];
    reasons.push(`reflection context: ${ctx}`);
    if (ctx !== "js" && ctx !== "html-body")
      pushVerb(needMore, "confirm_reflection");
  } else if (!tainted) {
    reasons.push("no reflection context or tainted sink observed yet");
    pushVerb(needMore, "confirm_reflection");
  }
  if (tainted) {
    score += RULES.taintedSinkBonus;
    reasons.push(`tainted source flows to sink "${finding.sink}"`);
  }
  if (finding.probeConfirmed) {
    score += RULES.probeConfirmedBonus;
    reasons.push("runtime canary reached the sink (confirmed reachability)");
  }
  return score;
}
function scoreInjection(type, reasons, needMore) {
  let score = RULES.injectionBase;
  if (type === "sqli-time") {
    score += RULES.oracle.time;
    reasons.push("time-based blind SQLi signal observed");
    reasons.push("timing can be noisy \u2014 corroborate");
    pushVerb(needMore, "differential_probe");
  } else {
    score += RULES.oracle.boolean;
    reasons.push("boolean-based differential responded to the payload");
  }
  return score;
}
function scoreFinding(finding = {}) {
  const type = finding && typeof finding.type === "string" ? finding.type : "";
  const reasons = [];
  const needMore = [];
  let score;
  if (SECRET_TYPES.has(type)) {
    score = scoreSecret(finding, reasons);
    pushVerb(needMore, "manual");
  } else if (type === "dom-xss") {
    score = scoreDomXss(finding, reasons, needMore);
  } else if (type === "sqli-boolean" || type === "sqli-time") {
    score = scoreInjection(type, reasons, needMore);
  } else if (type === "oob") {
    score = RULES.oobBase;
    if (finding.oobHit) {
      score += RULES.oobHitBonus;
      reasons.push("out-of-band callback received");
    } else {
      reasons.push("no out-of-band callback yet");
      pushVerb(needMore, "manual");
    }
  } else if (type === "header") {
    score = Math.min(RULES.headersBase, RULES.headersCap);
    reasons.push("missing/weak header is a signal, not a demonstrated vuln");
  } else if (type === "nuclei") {
    score = RULES.nucleiBase;
    reasons.push("nuclei template matched (curated known-vuln signature)");
  } else {
    score = RULES.unknownBase;
    reasons.push(
      `unknown finding type "${type || "(none)"}" \u2014 defaulting to tentative`
    );
    pushVerb(needMore, "manual");
  }
  const confidence = clamp(Math.round(score));
  return { confidence, band: bandFor(confidence), reasons, needMore };
}
function validateFinding(finding = {}) {
  const validation = scoreFinding(finding);
  return { ...finding, confidence: validation.confidence, validation };
}
function validateFindings(list) {
  return (Array.isArray(list) ? list : []).map((f) => validateFinding(f));
}
function filterForReport(list, { minConfidence = DEFAULT_REPORT_THRESHOLD } = {}) {
  return (Array.isArray(list) ? list : []).filter(
    (f) => scoreFinding(f).confidence >= minConfidence
  );
}

// ../Extension/chrome-boiler/src/utils/enrich.js
var AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
var AC = { L: 0.77, H: 0.44 };
var UI = { N: 0.85, R: 0.62 };
var CIA = { H: 0.56, L: 0.22, N: 0 };
var PR_UNCHANGED = { N: 0.85, L: 0.62, H: 0.27 };
var PR_CHANGED = { N: 0.85, L: 0.68, H: 0.5 };
function parseVector(vector) {
  if (typeof vector !== "string" || !/^CVSS:3\.[01]\//.test(vector))
    return null;
  const m = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k && v) m[k] = v;
  }
  for (const k of ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]) {
    if (!(k in m)) return null;
  }
  return m;
}
function roundup(input) {
  const i = Math.round(input * 1e5);
  if (i % 1e4 === 0) return i / 1e5;
  return (Math.floor(i / 1e4) + 1) / 10;
}
function cvssBaseScore(vector) {
  const m = parseVector(vector);
  if (!m) return 0;
  const changed = m.S === "C";
  const av = AV[m.AV];
  const ac = AC[m.AC];
  const ui = UI[m.UI];
  const pr = (changed ? PR_CHANGED : PR_UNCHANGED)[m.PR];
  const c = CIA[m.C];
  const i = CIA[m.I];
  const a = CIA[m.A];
  if ([av, ac, ui, pr, c, i, a].some((x) => x == null)) return 0;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss * 0.9731 - 0.02, 13) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const base = changed ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundup(Math.min(base, 10));
}
function cvssSeverity(score) {
  if (score <= 0) return "none";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9) return "high";
  return "critical";
}
var SECRET_META = {
  cwe: "CWE-798",
  cweName: "Use of Hard-coded Credentials",
  vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
};
var CLASS_META = {
  "dom-xss": {
    cwe: "CWE-79",
    cweName: "Cross-site Scripting (XSS)",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
  },
  "sqli-boolean": {
    cwe: "CWE-89",
    cweName: "SQL Injection",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  },
  "sqli-time": {
    cwe: "CWE-89",
    cweName: "SQL Injection (blind, time-based)",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  },
  header: {
    cwe: "CWE-693",
    cweName: "Protection Mechanism Failure",
    vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
  },
  oob: {
    cwe: "CWE-918",
    cweName: "Server-Side Request Forgery (SSRF)",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
  },
  aws_access_key: SECRET_META,
  stripe_key: SECRET_META,
  github_token: SECRET_META,
  google_api_key: SECRET_META,
  slack_token: SECRET_META,
  private_key: SECRET_META,
  jwt: {
    cwe: "CWE-522",
    cweName: "Insufficiently Protected Credentials",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
  },
  "api-spec-exposed": {
    cwe: "CWE-200",
    cweName: "Exposure of Sensitive Information to an Unauthorized Actor",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
  },
  "graphql-introspection": {
    cwe: "CWE-200",
    cweName: "Exposure of Sensitive Information to an Unauthorized Actor",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
  },
  "api-auth": {
    cwe: "CWE-306",
    cweName: "Missing Authentication for Critical Function",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
  },
  "api-idor-candidate": {
    cwe: "CWE-639",
    cweName: "Authorization Bypass Through User-Controlled Key (IDOR)",
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
  },
  "api-injection": {
    cwe: "CWE-74",
    cweName: "Improper Neutralization of Special Elements (Injection)",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
  },
  "ws-cswsh": {
    cwe: "CWE-346",
    cweName: "Origin Validation Error (Cross-Site WebSocket Hijacking)",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"
  },
  "ws-injection": {
    cwe: "CWE-74",
    cweName: "Improper Neutralization of Special Elements (Injection)",
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
  }
};
function enrichFinding(finding = {}) {
  const meta = CLASS_META[finding.type];
  const cvss = meta ? (() => {
    const baseScore = cvssBaseScore(meta.vector);
    return {
      vector: meta.vector,
      baseScore,
      severity: cvssSeverity(baseScore)
    };
  })() : null;
  const cve = typeof finding.cve === "string" && finding.cve ? finding.cve : null;
  const epss = cve && typeof finding.epss === "number" ? finding.epss : null;
  const kev = cve ? finding.kev === true : false;
  return {
    ...finding,
    cwe: meta ? meta.cwe : null,
    cweName: meta ? meta.cweName : null,
    cvss,
    cve,
    epss,
    kev
  };
}
function enrichFindings(list) {
  return (Array.isArray(list) ? list : []).map((f) => enrichFinding(f));
}

// ../Extension/chrome-boiler/src/utils/reconTriage.js
function finalizeTriage(findings, { crossHost = false, minConfidence } = {}) {
  const deduped = dedupeFindings(Array.isArray(findings) ? findings : [], {
    crossHost
  });
  const processed = enrichFindings(validateFindings(deduped));
  const ranked = rankTriage(processed);
  const reportworthy = minConfidence != null ? ranked.filter((f) => (f.confidence || 0) >= minConfidence) : filterForReport(ranked);
  return { ranked, reportworthy, summary: summarizeFindings(ranked) };
}

// stub:stub-aiprovider
var nope = () => {
  throw new Error("aiProvider not available server-side \u2014 inject chat");
};
var chat = nope;

// ../Extension/chrome-boiler/src/utils/reconLoop.js
var MAX_RECON_DEPTH = 6;
var INJECTION_TOOLS = /* @__PURE__ */ new Set(["dalfox", "sqlmap", "sstimap", "commix", "crlfuzz"]);
var INJECTION_PASS_CAP = 6;
function hostOf(t) {
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : "http://" + t).hostname.toLowerCase();
  } catch (_) {
    return "";
  }
}
function pickInjectionTarget(host, surfaceUrls = [], fallback) {
  const h = String(host || "").toLowerCase();
  const cands = [];
  for (const u of Array.isArray(surfaceUrls) ? surfaceUrls : []) {
    if (typeof u !== "string") continue;
    let parsed;
    try {
      parsed = new URL(u);
    } catch (_) {
      continue;
    }
    if (parsed.hostname.toLowerCase() !== h) continue;
    const n = [...parsed.searchParams.keys()].length;
    if (n === 0) continue;
    cands.push({ u, n });
  }
  if (!cands.length) return fallback;
  cands.sort((a, b) => b.n - a.n);
  return cands[0].u;
}
var DECISION_RANK = { allow: 0, needs_approval: 1, deny: 2 };
function stricterDecision(original, critic) {
  const ro = DECISION_RANK[original] ?? 0;
  const rc = DECISION_RANK[critic];
  if (rc === void 0) return original;
  return rc > ro ? critic : original;
}
async function applyCritique(steps, context, critique) {
  if (typeof critique !== "function" || !steps.length) return steps;
  let verdicts;
  try {
    verdicts = await critique(steps, context);
  } catch (_) {
    return steps;
  }
  if (!Array.isArray(verdicts) || verdicts.length !== steps.length) return steps;
  return steps.map((s, i) => {
    const v = verdicts[i];
    const cd = typeof v === "string" ? v : v && v.decision;
    const merged = stricterDecision(s.decision, cd);
    if (merged === s.decision) return s;
    const why = v && typeof v === "object" && v.reason || cd || "tightened";
    return { ...s, decision: merged, reason: `critic:${why}` };
  });
}
var SURFACE_BUCKET = {
  subdomains: "subdomains",
  dns: "subdomains",
  http: "hosts",
  ports: "ports",
  urls: "urls"
};
function safeParse(text) {
  if (typeof text !== "string") return null;
  let t = text.trim();
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) t = fence[1].trim();
  if (!t.startsWith("{") && !t.startsWith("[")) {
    const i = t.indexOf("{");
    const j = t.lastIndexOf("}");
    if (i !== -1 && j > i) t = t.slice(i, j + 1);
  }
  try {
    return JSON.parse(t);
  } catch (_) {
    return null;
  }
}
function buildReconPrompt(context = {}) {
  const scope = context.scope || { inScope: [] };
  const targets = (Array.isArray(scope.inScope) ? scope.inScope : []).slice(
    0,
    20
  );
  const s = context.surface || {};
  const seedUrls = (s.urls || []).slice(0, 15);
  const remaining = Math.max(
    0,
    (context.budget || DEFAULT_RECON_BUDGET) - (context.budgetUsed || 0)
  );
  const done = (Array.isArray(context.executed) ? context.executed : []).filter((e) => e && e.ran).map((e) => `${e.call && e.call.tool}:${e.call && e.call.target}`).slice(0, 30);
  const content = `You are a bug-bounty recon planner. Goal: enumerate in-scope assets and surface known vulnerabilities using ONLY the allowed tools, staying strictly in scope. Allowed tools: ${Object.keys(RECON_TOOLS).join(
    ", "
  )}. Profiles: ${RECON_PROFILES.join(", ")}. In-scope targets: ${targets.join(", ") || "(none)"}. Known endpoints (use these EXACT URLs as the target when scanning, keeping their scheme and port): ${seedUrls.join(", ") || "(none)"}. Already run: ${done.join(", ") || "(none)"}. Discovered so far: ${(s.subdomains || []).length} subdomains, ${(s.hosts || []).length} hosts, ${(s.urls || []).length} urls, ${(s.ports || []).length} ports; ${(context.findings || []).length} findings. Budget remaining: ${remaining} tool runs. STRATEGY: discovery is only the first step \u2014 do NOT spend the whole budget enumerating. As soon as you have endpoints (the Known endpoints above, or once katana/gau/httpx have run), spend most of the remaining budget TESTING those exact endpoint URLs for vulnerabilities with the vuln/injection tools: nuclei, dalfox (XSS), sqlmap (SQLi), crlfuzz (CRLF), sstimap (SSTI), commix (command injection), jwt_tool, subzy (takeover), s3scanner, wpscan. Target the discovered endpoint URLs, not just the root. Propose the next 1-3 recon steps as JSON only: {"steps":[{"tool","target","profile"}],"done":false}. Reference only in-scope targets and allowed tools. Set done:true only when both discovery AND vuln testing of the endpoints are done. JSON only:`;
  return { messages: [{ role: "user", content }] };
}
async function planReconStep(context, { chat: chat2, model } = {}) {
  const call = chat2 || chat;
  try {
    const { messages } = buildReconPrompt(context);
    const reply = await call(messages, model);
    const parsed = safeParse(reply);
    if (!parsed) return { steps: [], done: true };
    return {
      steps: Array.isArray(parsed.steps) ? parsed.steps : [],
      done: !!parsed.done
    };
  } catch (_) {
    return { steps: [], done: true };
  }
}
function mergeResult(context, result) {
  if (!result || !result.ok) return;
  for (const f of result.findings || []) context.findings.push(f);
  const bucket = SURFACE_BUCKET[result.kind];
  if (bucket && Array.isArray(result.items)) {
    const seen = new Set(
      context.surface[bucket].map(
        (x) => typeof x === "string" ? x : JSON.stringify(x)
      )
    );
    for (const it of result.items) {
      const key = typeof it === "string" ? it : JSON.stringify(it);
      if (!seen.has(key)) {
        seen.add(key);
        context.surface[bucket].push(it);
      }
    }
  }
}
async function runReconLoop({
  scope,
  chat: chat2,
  agentClient,
  approve,
  model,
  policy = RISK_POLICY,
  budget = DEFAULT_RECON_BUDGET,
  maxDepth = MAX_RECON_DEPTH,
  seeds = [],
  critique
} = {}) {
  const seedUrls = (Array.isArray(seeds) ? seeds : []).filter(
    (u) => typeof u === "string" && u.trim()
  );
  const context = {
    scope,
    budget,
    budgetUsed: 0,
    executed: [],
    // Seed known endpoints (with scheme/port) so the planner can target them
    // directly — in-scope hosts alone can't carry a non-standard port/scheme.
    surface: { subdomains: [], urls: [...seedUrls], hosts: [], ports: [] },
    findings: []
  };
  const executedKeys = /* @__PURE__ */ new Set();
  const approveFn = typeof approve === "function" ? approve : async () => false;
  let depth = 0;
  try {
    while (depth < maxDepth && context.budgetUsed < budget) {
      depth++;
      const plan = await planReconStep(context, { chat: chat2, model });
      const { steps: proposed } = normalizeReconPlan(plan.steps, {
        scope,
        policy,
        budgetUsed: context.budgetUsed,
        budget
      });
      const steps = await applyCritique(proposed, context, critique);
      let ranAny = false;
      for (const d of steps) {
        if (context.budgetUsed >= budget) break;
        if (d.decision === "deny") {
          context.executed.push({
            decision: "deny",
            reason: d.reason,
            ran: false
          });
          continue;
        }
        let go = d.decision === "allow";
        if (d.decision === "needs_approval") go = !!await approveFn(d.call);
        if (!go) {
          context.executed.push({
            decision: d.decision,
            call: d.call,
            reason: d.reason,
            ran: false
          });
          continue;
        }
        const key = `${d.call.tool}|${d.call.target}|${d.call.profile}`;
        if (executedKeys.has(key)) {
          context.executed.push({
            decision: d.decision,
            call: d.call,
            reason: "already_run",
            ran: false
          });
          continue;
        }
        executedKeys.add(key);
        if (INJECTION_TOOLS.has(d.call.tool) && !/\?.+=/.test(d.call.target || "")) {
          d.call.target = pickInjectionTarget(
            hostOf(d.call.target),
            context.surface.urls,
            d.call.target
          );
        }
        const result = await executeReconTool(d.call, { agentClient });
        context.budgetUsed++;
        ranAny = true;
        mergeResult(context, result);
        context.executed.push({
          decision: d.decision,
          call: d.call,
          ran: true,
          ok: result.ok,
          error: result.error,
          found: (result.findings || []).length,
          command: result.command || "",
          // PoC evidence (Light)
          rawExcerpt: result.raw || "",
          evidence: result.evidence || null
          // PoC evidence (Full: req/resp flows)
        });
      }
      if (plan.done) break;
      if (!ranAny && !steps.length) break;
    }
  } catch (_) {
  }
  try {
    const paramUrls = [...new Set((context.surface.urls || []).filter((u) => /\?.+=/.test(u)))].slice(0, 5);
    let injected = 0;
    for (const tool of ["dalfox", "sqlmap"]) {
      if (!RECON_TOOLS[tool]) continue;
      for (const url of paramUrls) {
        if (injected >= INJECTION_PASS_CAP) break;
        const nd = normalizeToolCall({ tool, target: url }, { scope, policy, budgetUsed: 0, budget: Infinity });
        if (nd.decision === "deny") {
          context.executed.push({ decision: "deny", call: { tool, target: url }, ran: false, reason: nd.reason, pass: "injection" });
          continue;
        }
        const key = `${tool}|${url}|${nd.call.profile}`;
        if (executedKeys.has(key)) continue;
        let go = nd.decision === "allow";
        if (nd.decision === "needs_approval") go = !!await approveFn(nd.call);
        if (!go) {
          context.executed.push({ decision: nd.decision, call: nd.call, ran: false, reason: "not_approved", pass: "injection" });
          continue;
        }
        executedKeys.add(key);
        const result = await executeReconTool(nd.call, { agentClient });
        injected++;
        mergeResult(context, result);
        context.executed.push({ decision: nd.decision, call: nd.call, ran: true, ok: result.ok, error: result.error, found: (result.findings || []).length, command: result.command || "", rawExcerpt: result.raw || "", evidence: result.evidence || null, pass: "injection" });
      }
    }
  } catch (_) {
  }
  const t = finalizeTriage(context.findings);
  return {
    triage: t.ranked,
    reportworthy: t.reportworthy,
    summary: t.summary,
    findings: context.findings,
    surface: context.surface,
    executed: context.executed,
    budgetUsed: context.budgetUsed
  };
}

// ../Extension/chrome-boiler/src/utils/chainPlaybooks.js
var PLAYBOOKS = [
  {
    id: "xss-secret-ato",
    name: "DOM-XSS \u2192 exposed token \u2192 account takeover",
    impact: "Client-side code execution plus a retrievable credential enables session/account takeover.",
    severity: "critical",
    links: [
      { id: "xss", label: "DOM-XSS sink reachable", match: { types: ["dom-xss"] } },
      {
        id: "token",
        label: "Exposed token/secret",
        match: { types: ["jwt", "aws_access_key", "google_api_key", "github_token", "slack_token", "stripe_key", "private_key"] }
      }
    ]
  },
  {
    id: "cors-cookie-theft",
    name: "Permissive CORS + credentialed cookie \u2192 cross-origin data theft",
    impact: "A credentialed wildcard CORS policy lets a malicious origin read authenticated responses.",
    severity: "high",
    links: [
      { id: "cors", label: "Permissive CORS with credentials", match: { types: ["permissive-cors"] } },
      { id: "cookie", label: "Cookie set on the response", match: { types: ["set-cookie"] } }
    ]
  },
  {
    id: "graphql-introspection-idor",
    name: "GraphQL introspection \u2192 surface \u2192 access-control candidate",
    impact: "A fully mapped GraphQL schema plus a missing-authorization candidate points to object-level access-control abuse.",
    severity: "high",
    links: [
      { id: "introspection", label: "Introspection/suggestions enabled", match: { types: ["graphql-introspection", "graphql-suggestions"] } },
      { id: "surface", label: "Query/mutation surface mapped", match: { types: ["graphql-surface"] } },
      { id: "authz", label: "Access-control candidate", match: { types: ["api-idor-candidate", "api-auth"] } }
    ]
  },
  {
    id: "api-injection-idor",
    name: "API/SQL injection + missing-auth/IDOR \u2192 data compromise",
    impact: "An injectable parameter alongside a broken access-control candidate compounds into data compromise.",
    severity: "critical",
    links: [
      { id: "injection", label: "Injection candidate", match: { types: ["api-injection", "sqli-boolean"] } },
      { id: "access", label: "Access-control candidate", match: { types: ["api-idor-candidate", "api-auth"] } }
    ]
  },
  {
    id: "cswsh-ws-injection",
    name: "CSWSH + WebSocket injection \u2192 cross-origin action",
    impact: "A cross-site WebSocket hijack plus an injectable frame lets an attacker drive authenticated socket actions.",
    severity: "high",
    links: [
      { id: "cswsh", label: "Cross-site WebSocket hijack candidate", match: { types: ["ws-cswsh"] } },
      { id: "wsinj", label: "WebSocket frame injection candidate", match: { types: ["ws-injection"] } }
    ]
  },
  {
    id: "spec-injection",
    name: "Exposed API spec \u2192 injectable endpoint",
    impact: "A readable OpenAPI/Swagger spec maps the surface that an injection candidate then exploits.",
    severity: "high",
    links: [
      { id: "spec", label: "Exposed API spec", match: { types: ["api-spec-exposed"] } },
      { id: "injection", label: "Injection/IDOR candidate", match: { types: ["api-injection", "sqli-boolean", "api-idor-candidate"] } }
    ]
  },
  {
    id: "xss-weak-csp",
    name: "DOM-XSS + missing/weak CSP \u2192 reliable exploitation",
    impact: "A weak or absent CSP removes the mitigation that would otherwise blunt the DOM-XSS.",
    severity: "high",
    links: [
      { id: "xss", label: "DOM-XSS sink reachable", match: { types: ["dom-xss"] } },
      { id: "csp", label: "Missing/weak CSP", match: { types: ["missing-csp", "weak-csp"] } }
    ]
  }
];
var SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];
function str2(v) {
  return typeof v === "string" ? v : v == null ? "" : String(v);
}
function getConfidence(f) {
  return typeof f.confidence === "number" ? f.confidence : scoreFinding(f).confidence;
}
function hostInScope(host, scope) {
  if (!scope) return true;
  const h = str2(host).trim();
  if (!h) return true;
  const url = /^https?:\/\//i.test(h) ? h : `https://${h}`;
  return evaluateScope(url, scope).allowed;
}
function isEligible(f, scope) {
  if (!f) return false;
  if (!hostInScope(f.host, scope)) return false;
  return getConfidence(f) >= BANDS.tentative;
}
function linkMatches(link, finding) {
  const types = link && link.match && Array.isArray(link.match.types) ? link.match.types : [];
  return types.includes(finding.type);
}
function matchOne(playbook, eligibleSorted) {
  const links = Array.isArray(playbook.links) ? playbook.links : [];
  const satisfied = [];
  const filledLinkIds = /* @__PURE__ */ new Set();
  const usedFindingIds = /* @__PURE__ */ new Set();
  for (const finding of eligibleSorted) {
    if (usedFindingIds.has(finding.id)) continue;
    for (const link of links) {
      if (filledLinkIds.has(link.id)) continue;
      if (linkMatches(link, finding)) {
        satisfied.push({ linkId: link.id, findingId: finding.id, type: finding.type });
        filledLinkIds.add(link.id);
        usedFindingIds.add(finding.id);
        break;
      }
    }
  }
  const missing = links.filter((l) => !filledLinkIds.has(l.id)).map((l) => ({ linkId: l.id, label: str2(l.label), match: l.match }));
  const constituents = satisfied.map((s) => eligibleSorted.find((f) => f.id === s.findingId));
  return {
    playbookId: playbook.id,
    name: playbook.name,
    satisfied,
    missing,
    completeness: links.length ? satisfied.length / links.length : 0,
    complete: links.length > 0 && satisfied.length === links.length,
    severity: deriveSeverity(constituents)
  };
}
function matchPlaybooks(findings, { scope } = {}) {
  const arr = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const eligibleSorted = sortFindings(arr.filter((f) => isEligible(f, scope)));
  const results = [];
  for (const pb of PLAYBOOKS) {
    const m = matchOne(pb, eligibleSorted);
    if (m.satisfied.length >= 1) results.push(m);
  }
  const sevRank = (s) => {
    const i = SEVERITY_ORDER.indexOf(s);
    return i === -1 ? SEVERITY_ORDER.length : i;
  };
  results.sort(
    (a, b) => Number(b.complete) - Number(a.complete) || b.completeness - a.completeness || sevRank(a.severity) - sevRank(b.severity)
  );
  return results;
}

// ../Extension/chrome-boiler/src/utils/chains.js
var MAX_CHAINS = 8;
var MAX_STEPS = 6;
var MAX_CONTEXT_FINDINGS = 30;
var MAX_RATIONALE = 240;
var _seq = 0;
function chainId() {
  _seq = (_seq + 1) % 1e9;
  return `chn_${Date.now().toString(36)}_${_seq}`;
}
function str3(v) {
  return typeof v === "string" ? v : v == null ? "" : String(v);
}
function clip(s, max) {
  const t = str3(s).replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max) : t;
}
function getConfidence2(f) {
  return typeof f.confidence === "number" ? f.confidence : scoreFinding(f).confidence;
}
function hostInScope2(host, scope) {
  if (!scope) return true;
  const h = str3(host).trim();
  if (!h) return true;
  const url = /^https?:\/\//i.test(h) ? h : `https://${h}`;
  return evaluateScope(url, scope).allowed;
}
function validateCvss(v) {
  const s = str3(v).trim();
  return s && s.length <= 120 && /^CVSS:3\.1\//.test(s) ? s : null;
}
function normalizeChain(raw, { findingsById, scope }) {
  const rawSteps = Array.isArray(raw && raw.steps) ? raw.steps : [];
  const steps = [];
  const constituents = [];
  for (const s of rawSteps.slice(0, MAX_STEPS)) {
    const ref = str3(s && (s.findingId != null ? s.findingId : s.ref));
    const finding = findingsById.get(ref);
    if (!finding) continue;
    if (!hostInScope2(finding.host, scope)) continue;
    if (getConfidence2(finding) < BANDS.tentative) continue;
    steps.push({
      findingId: finding.id,
      type: finding.type,
      note: clip(s && s.note, 200)
    });
    constituents.push(finding);
  }
  if (steps.length < 2)
    return { rejected: { raw, reason: "insufficient_grounded_steps" } };
  return {
    chain: {
      id: chainId(),
      title: clip(raw && raw.title, 120) || steps.map((s) => s.type).join(" \u2192 "),
      steps,
      findingIds: steps.map((s) => s.findingId),
      severity: deriveSeverity(constituents),
      aiCvss: validateCvss(raw && raw.cvss),
      rationale: clip(raw && raw.rationale, MAX_RATIONALE)
    }
  };
}
function normalizeChains(rawPlan, { findings, scope } = {}) {
  const findingsById = /* @__PURE__ */ new Map();
  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f) continue;
    if (f.id != null) findingsById.set(String(f.id), f);
    if (f.ref && !findingsById.has(String(f.ref)))
      findingsById.set(String(f.ref), f);
  }
  const list = Array.isArray(rawPlan) ? rawPlan : Array.isArray(rawPlan && rawPlan.chains) ? rawPlan.chains : [];
  const chains = [];
  const rejected = [];
  for (const raw of list) {
    if (chains.length >= MAX_CHAINS) {
      rejected.push({ raw, reason: "over_cap" });
      continue;
    }
    const res = normalizeChain(raw, { findingsById, scope });
    if (res.chain) chains.push(res.chain);
    else rejected.push(res.rejected);
  }
  return { chains, rejected };
}
function buildChainsPrompt(findings, { playbookMatches } = {}) {
  const top = sortFindings(Array.isArray(findings) ? findings : []).slice(
    0,
    MAX_CONTEXT_FINDINGS
  );
  const lines = top.map(
    (f) => `- id=${str3(f.id)} type=${str3(f.type)} severity=${str3(
      f.severity
    )} confidence=${getConfidence2(f)} host=${str3(f.host)} title=${clip(
      f.title,
      80
    )}`
  );
  const partial = (Array.isArray(playbookMatches) ? playbookMatches : []).filter(
    (m) => m && m.complete === false
  );
  let grounding = "";
  if (partial.length) {
    const pbLines = partial.slice(0, MAX_CHAINS).map(
      (m) => `- ${clip(m.name, 120)}: have [${(m.satisfied || []).map((s) => s.linkId).join(", ")}], missing [${(m.missing || []).map((x) => x.linkId).join(", ")}]`
    );
    grounding = "\n\nKnown chain patterns partially matched (prefer chains that complete the MISSING links):\n" + pbLines.join("\n");
  }
  const content = `You are a web application penetration tester reviewing already-discovered, in-scope findings. Propose plausible EXPLOIT CHAINS that combine two or more of these findings into higher impact (e.g. SSRF -> cloud metadata -> IAM keys; XSS -> cookie theft -> account takeover; IDOR -> privilege escalation). Reference ONLY the finding ids listed below \u2014 do not invent findings. Each chain needs at least two steps. Return JSON only: {"chains":[{"title","steps":[{"findingId","note"}],"cvss","rationale"}]}.

Findings:
${lines.join("\n") || "- (none)"}` + grounding + "\n\nJSON only:";
  return { messages: [{ role: "user", content }] };
}
function safeParse2(text) {
  if (typeof text !== "string") return null;
  let t = text.trim();
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) t = fence[1].trim();
  if (!t.startsWith("{") && !t.startsWith("[")) {
    const i = t.indexOf("{");
    const j = t.lastIndexOf("}");
    if (i !== -1 && j > i) t = t.slice(i, j + 1);
  }
  try {
    return JSON.parse(t);
  } catch (_) {
    return null;
  }
}
function dedupeChains(chains) {
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const c of Array.isArray(chains) ? chains : []) {
    const key = [...Array.isArray(c.findingIds) ? c.findingIds : []].sort().join("|");
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(c);
  }
  return out;
}
async function proposeChains(findings, { chat: chat2, model, scope } = {}) {
  const call = chat2 || chat;
  const validated = validateFindings(findings);
  const matches = matchPlaybooks(validated, { scope });
  const partial = matches.filter((m) => !m.complete);
  const pbById = new Map(PLAYBOOKS.map((p) => [p.id, p]));
  const deterministicRaw = matches.filter((m) => m.complete).map((m) => ({
    title: m.name,
    steps: m.satisfied.map((s) => ({ findingId: s.findingId, note: "" })),
    rationale: (pbById.get(m.playbookId) || {}).impact || "",
    cvss: null
  }));
  let llmOk = false;
  let llmRaw = [];
  try {
    const { messages } = buildChainsPrompt(validated, { playbookMatches: partial });
    const reply = await call(messages, model);
    const parsed = safeParse2(reply);
    if (parsed) {
      llmOk = true;
      llmRaw = Array.isArray(parsed) ? parsed : Array.isArray(parsed.chains) ? parsed.chains : [];
    }
  } catch (_) {
    llmOk = false;
  }
  const { chains, rejected } = normalizeChains([...deterministicRaw, ...llmRaw], {
    findings: validated,
    scope
  });
  const deduped = dedupeChains(chains);
  const source = llmOk ? "llm" : deduped.length ? "playbook" : "error";
  return { chains: deduped, rejected, source };
}

// ../Extension/chrome-boiler/src/utils/reportBuilder.js
var REPORT_PLATFORMS = [
  { id: "hackerone", label: "HackerOne" },
  { id: "bugcrowd", label: "Bugcrowd" },
  { id: "generic", label: "Generic Markdown" }
];
var SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "informational"
];
function normalize(finding = {}) {
  const clean = (v) => typeof v === "string" ? v.trim() : v;
  const lines = (v) => Array.isArray(v) ? v.filter(Boolean) : String(v || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  return {
    title: clean(finding.title) || "Untitled finding",
    target: clean(finding.target) || "",
    program: clean(finding.program) || "",
    ref: clean(finding.ref) || "",
    // WSTG / API / CWE id
    severity: SEVERITIES.includes(finding.severity) ? finding.severity : "medium",
    confidence: typeof finding.confidence === "number" ? finding.confidence : null,
    band: typeof finding.band === "string" ? finding.band : null,
    cwe: typeof finding.cwe === "string" ? finding.cwe : null,
    cvss: finding.cvss && typeof finding.cvss === "object" ? finding.cvss : null,
    summary: clean(finding.summary) || "",
    steps: lines(finding.steps),
    impact: clean(finding.impact) || "",
    remediation: clean(finding.remediation) || "",
    evidence: clean(finding.evidence) || "",
    // raw request/response paste
    references: lines(finding.references)
  };
}
function stepsBlock(steps) {
  if (!steps.length) return "_Add reproduction steps._";
  return steps.map((s, i) => `${i + 1}. ${s}`).join("\n");
}
function evidenceBlock(evidence) {
  if (!evidence) return "";
  return "\n## Evidence\n\n```http\n" + evidence + "\n```\n";
}
function referencesBlock(references, ref) {
  const items = [...references];
  if (ref) items.unshift(`Reference: ${ref}`);
  if (!items.length) return "";
  return "\n## References\n\n" + items.map((r) => `- ${r}`).join("\n") + "\n";
}
function buildReport(finding = {}, platform = "hackerone") {
  const f = normalize(finding);
  const titleLine = f.target ? `# ${f.title} on ${f.target}` : `# ${f.title}`;
  const band = f.band || (f.confidence != null ? bandFor(f.confidence) : null);
  const confidenceLine = f.confidence != null ? `**Confidence:** ${f.confidence}% (${band})` : "";
  const cweLine = f.cwe ? `**CWE:** ${f.cwe}` : "";
  const cvssLine = f.cvss && typeof f.cvss.baseScore === "number" ? `**CVSS:** ${f.cvss.baseScore}${f.cvss.severity ? ` (${f.cvss.severity[0].toUpperCase()}${f.cvss.severity.slice(1)})` : ""}${f.cvss.vector ? ` \u2014 ${f.cvss.vector}` : ""}` : "";
  const metaLine = [
    f.program && `**Program:** ${f.program}`,
    f.target && `**Target:** ${f.target}`,
    `**Severity:** ${f.severity[0].toUpperCase()}${f.severity.slice(1)}`,
    confidenceLine,
    cweLine,
    cvssLine,
    f.ref && `**Class:** ${f.ref}`
  ].filter(Boolean).join("  \n");
  const lowConfidenceBanner = band === "tentative" || band === "noise" ? `
> \u26A0 Low confidence (${f.confidence != null ? f.confidence + "%" : "unscored"}, ${band}) \u2014 verify this finding before drafting a report.` : "";
  const summary = f.summary || "_Briefly describe the vulnerability._";
  const impact = f.impact || "_Describe the real-world impact for this target._";
  if (platform === "bugcrowd") {
    return [
      titleLine,
      metaLine,
      lowConfidenceBanner,
      "\n## Vulnerability Details",
      summary,
      "\n## Steps to Reproduce",
      stepsBlock(f.steps),
      evidenceBlock(f.evidence).trimEnd(),
      "\n## Impact",
      impact,
      f.remediation ? "\n## Recommended Fix\n\n" + f.remediation : "",
      referencesBlock(f.references, f.ref).trimEnd(),
      "\n---\n_Draft generated for review \u2014 verify scope & impact before submitting._"
    ].filter((s) => s !== "").join("\n");
  }
  if (platform === "generic") {
    return [
      titleLine,
      metaLine,
      lowConfidenceBanner,
      "\n## Summary",
      summary,
      "\n## Steps to Reproduce",
      stepsBlock(f.steps),
      evidenceBlock(f.evidence).trimEnd(),
      "\n## Impact",
      impact,
      f.remediation ? "\n## Remediation\n\n" + f.remediation : "",
      referencesBlock(f.references, f.ref).trimEnd()
    ].filter((s) => s !== "").join("\n");
  }
  return [
    titleLine,
    metaLine,
    lowConfidenceBanner,
    "\n## Summary",
    summary,
    "\n## Steps To Reproduce",
    stepsBlock(f.steps),
    evidenceBlock(f.evidence).trimEnd(),
    "\n## Impact",
    impact,
    f.remediation ? "\n## Remediation\n\n" + f.remediation : "",
    referencesBlock(f.references, f.ref).trimEnd(),
    "\n---\n_Draft generated for review \u2014 confirm the finding and its impact before submitting. Never submit unverified or auto-generated reports._"
  ].filter((s) => s !== "").join("\n");
}
export {
  EMPTY_SCOPE,
  REPORT_PLATFORMS,
  buildReport,
  evaluateScope,
  executeReconTool,
  finalizeTriage,
  hostFromUrl,
  isInScope,
  makeAgentClient,
  normalizeFinding,
  parseScopeText,
  pickInjectionTarget,
  planReconStep,
  proposeChains,
  runReconLoop,
  stricterDecision
};
