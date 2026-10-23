// Scope import — paste a program's scope (HackerOne or Bugcrowd structured JSON,
// or a plain-text scope block) and get back the arrays `buildEngagement` already
// consumes: { urls, outOfScopeUrls, enumerateSubdomains }, plus the normalized
// assets, the non-web assets it skipped, and warnings. Pure and format-sniffing;
// it never fetches anything. Fail-closed: nothing recognized → no targets.
//
// Non-web assets (mobile app ids, source repos, CIDR ranges, hardware, …) are
// deliberately dropped with a warning — this is a web recon tool.

const URL_RE = /^https?:\/\/\S+$/i;
const HOST_RE = /^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/i;
const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

const WEB_TYPES = new Set(['URL', 'WILDCARD', 'DOMAIN', 'WEBSITE', 'API', 'IP_ADDRESS', 'IP']);
const NONWEB_TYPES = new Set([
  'CIDR', 'GOOGLE_PLAY_APP_ID', 'APPLE_STORE_APP_ID', 'TESTFLIGHT', 'OTHER_APK',
  'SOURCE_CODE', 'HARDWARE', 'OTHER', 'AI_MODEL', 'DOWNLOADABLE_EXECUTABLES',
  'SMART_CONTRACT', 'ANDROID', 'IOS', 'OTHER_IPA',
]);

function inferType(id) {
  if (URL_RE.test(id)) return 'URL';
  if (id.startsWith('*.')) return 'WILDCARD';
  if (IP_RE.test(id)) return 'IP_ADDRESS';
  return 'DOMAIN';
}

function isWeb(type, id) {
  const T = String(type || '').toUpperCase();
  if (NONWEB_TYPES.has(T)) return false;
  if (WEB_TYPES.has(T)) return true;
  // No usable type → judge the identifier itself.
  return URL_RE.test(id) || HOST_RE.test(id) || IP_RE.test(id);
}

// Pull the first host/URL/wildcard token out of a free-text line (strips
// markdown bullets, backticks, table pipes, trailing punctuation).
function extractToken(line) {
  const cleaned = line.replace(/^[\s>*\-•]+/, '').replace(/`/g, '');
  for (let tok of cleaned.split(/[\s,|]+/)) {
    tok = tok.replace(/^[<([]+/, '').replace(/[>)\].,;:]+$/, '');
    if (!tok) continue;
    if (URL_RE.test(tok) || HOST_RE.test(tok) || IP_RE.test(tok)) return tok;
  }
  return null;
}

// Each parser yields { identifier, type, inScope } rows; this turns rows into the
// engagement arrays.
function fromRows(rows, source) {
  const urls = [];
  const oos = [];
  const skipped = [];
  let wildcardInScope = false;
  for (const row of rows) {
    const id = String(row.identifier || '').trim();
    if (!id) continue;
    const type = row.type || inferType(id);
    if (!isWeb(type, id)) { skipped.push({ identifier: id, type, reason: 'non-web asset' }); continue; }
    let url = id;
    if (id.startsWith('*.')) { url = id.slice(2); if (row.inScope) wildcardInScope = true; }
    (row.inScope ? urls : oos).push(url);
  }
  const warnings = [];
  if (skipped.length) warnings.push(`skipped ${skipped.length} non-web asset(s): ${skipped.map((s) => s.identifier).join(', ')}`);
  const uniqUrls = [...new Set(urls)];
  const uniqOos = [...new Set(oos)];
  if (!uniqUrls.length) warnings.push('no in-scope web targets found in scope — nothing to scan');
  return {
    source,
    urls: uniqUrls,
    outOfScopeUrls: uniqOos,
    enumerateSubdomains: wildcardInScope,
    assets: rows,
    skipped,
    warnings,
  };
}

// --- HackerOne: data[].attributes | structured_scopes[] | [ {asset_identifier} ] ---
function h1Rows(items) {
  return items.map((it) => {
    const a = it.attributes || it;
    return {
      identifier: a.asset_identifier,
      type: a.asset_type,
      inScope: a.eligible_for_submission !== false, // absent → treat as in scope
    };
  });
}

// --- Bugcrowd: {in_scope:[...], out_of_scope:[...]} | [ {target, category} ] ---
function bcRows(obj) {
  const rowify = (list, inScope) => (Array.isArray(list) ? list : []).map((t) => {
    if (typeof t === 'string') return { identifier: t, inScope };
    return { identifier: t.target || t.name || t.asset || t.uri, type: t.type || t.category, inScope };
  });
  return [...rowify(obj.in_scope, true), ...rowify(obj.out_of_scope, false)];
}

function parseJson(obj) {
  // HackerOne
  if (Array.isArray(obj.data) && obj.data.some((d) => (d.attributes || d).asset_identifier)) {
    return fromRows(h1Rows(obj.data), 'hackerone');
  }
  if (Array.isArray(obj.structured_scopes)) {
    return fromRows(h1Rows(obj.structured_scopes), 'hackerone');
  }
  if (Array.isArray(obj) && obj.some((d) => d.asset_identifier)) {
    return fromRows(h1Rows(obj), 'hackerone');
  }
  // Bugcrowd
  if (Array.isArray(obj.in_scope) || Array.isArray(obj.out_of_scope)) {
    return fromRows(bcRows(obj), 'bugcrowd');
  }
  if (Array.isArray(obj.targets)) {
    return fromRows(obj.targets.map((t) => ({ identifier: t.name || t.target, type: t.category || t.type, inScope: t.in_scope !== false })), 'bugcrowd');
  }
  // Generic array of strings/objects
  if (Array.isArray(obj)) {
    return fromRows(obj.map((t) => (typeof t === 'string' ? { identifier: t, inScope: true } : { identifier: t.target || t.name || t.identifier, type: t.type, inScope: t.inScope !== false })), 'json');
  }
  return null;
}

function parseText(text) {
  const rows = [];
  let bucket = true; // true = in scope
  for (const raw of String(text).split(/\r?\n/)) {
    const l = raw.trim();
    if (!l) continue;
    if (/out[\s_-]*of[\s_-]*scope/i.test(l)) bucket = false;
    else if (/\bin[\s_-]*scope\b/i.test(l) && !extractToken(l)) bucket = true;
    const tok = extractToken(l);
    if (tok) rows.push({ identifier: tok, type: inferType(tok), inScope: bucket });
  }
  return fromRows(rows, 'text');
}

export function importScope(input) {
  if (input && typeof input === 'object') {
    return parseJson(input) || fromRows([], 'json');
  }
  const text = String(input == null ? '' : input).trim();
  if (text) {
    try {
      const obj = JSON.parse(text);
      const viaJson = parseJson(obj);
      if (viaJson) return viaJson;
    } catch (_) { /* not JSON → fall through to text */ }
  }
  return parseText(text);
}
