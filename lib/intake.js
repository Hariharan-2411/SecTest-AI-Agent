// Intake — turns an engagement brief (target URLs, subdomain flag, program
// rules text) into a fail-closed scope + policy. Pure: scope helpers injected.
//
// FAIL CLOSED is the whole point: unless the program rules clearly permit
// automated active testing AND a human confirms, the policy allows `safe` tools
// only. Destructive tools are never auto-enabled by text parsing — a human must
// opt in explicitly (confirmed + allowDestructive).

const DENY_SIGNALS = [
  'no automated', 'no automation', 'no scanning', 'no scanners', 'no active scan',
  'do not scan', 'manual only', 'no brute', 'no fuzzing', 'no dos', 'no denial',
  'no automated tools', 'automated tools are prohibited', 'no automated testing',
];
const ALLOW_SIGNALS = [
  'automated scanning is allowed', 'automated testing permitted', 'scanners allowed',
  'active scanning allowed', 'automation allowed', 'nuclei allowed',
];

export function scanRules(rulesText = '') {
  const t = String(rulesText).toLowerCase();
  const denies = DENY_SIGNALS.filter((s) => t.includes(s));
  const allows = ALLOW_SIGNALS.filter((s) => t.includes(s));
  return { denies, allows, hasText: t.trim().length > 0 };
}

export function buildEngagement(
  {
    name = 'engagement',
    urls = [],
    outOfScopeUrls = [],
    enumerateSubdomains = false,
    rulesText = '',
    confirmed = false,       // human reviewed the derived policy
    allowDestructive = false,// explicit human opt-in for destructive tools
    evidenceMode = 'light'   // 'light' (cmd+output excerpt) | 'full' (proxy req/resp)
  } = {},
  { hostFromUrl, parseScopeText } = {}
) {
  if (!hostFromUrl || !parseScopeText) throw new Error('scope helpers required');

  const hosts = [...new Set(urls.map((u) => hostFromUrl(u)).filter(Boolean))];
  const inPatterns = [];
  for (const h of hosts) {
    inPatterns.push(h);
    if (enumerateSubdomains) inPatterns.push(`*.${h}`);
  }
  const outHosts = outOfScopeUrls.map((u) => hostFromUrl(u)).filter(Boolean);

  const scope = {
    inScope: parseScopeText(inPatterns.join('\n')),
    outOfScope: parseScopeText(outHosts.join('\n')),
  };

  const rules = scanRules(rulesText);
  const warnings = [];

  // Fail closed: active allowed only if rules don't deny, rules DO permit, and a
  // human confirmed. Any missing condition → safe-only.
  let allowActive = false;
  if (!confirmed) {
    warnings.push('policy not human-confirmed — safe tools only until confirmed');
  } else if (rules.denies.length) {
    warnings.push(`rules appear to forbid automation: ${rules.denies.join('; ')}`);
  } else if (!rules.allows.length) {
    warnings.push('rules do not explicitly permit automated scanning — safe only');
  } else {
    allowActive = true;
  }

  const policy = {
    allowActive,
    allowDestructive: !!(allowActive && allowDestructive),
    maxRisk: allowActive ? (allowDestructive ? 'destructive' : 'active') : 'safe',
    rateProfile: 'polite',
    ruleSignals: rules,
  };
  if (!scope.inScope.length) warnings.push('no in-scope hosts derived — scan is inert');

  // Seeds = the raw target URLs verbatim, so their scheme/port survive into the
  // recon loop (scope stores bare hosts and cannot carry a port).
  const seeds = [...new Set(urls.map((u) => String(u).trim()).filter(Boolean))];

  const mode = evidenceMode === 'full' ? 'full' : 'light';
  return { name, scope, policy, seeds, evidenceMode: mode, warnings };
}
