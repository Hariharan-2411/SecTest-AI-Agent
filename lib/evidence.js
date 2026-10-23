// PoC evidence (Light mode): the exact tool command + a bounded, masked excerpt
// of the tool's raw output. Minimum PoC — never full exfiltrated data, secrets masked.
const SECRET_RE = /(AKIA[0-9A-Z]{8,}|gsk_[A-Za-z0-9]{10,}|sk-[A-Za-z0-9-]{12,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|xox[baprs]-[A-Za-z0-9-]{8,})/g;

export function mask(s) {
  return String(s || '').replace(SECRET_RE, (m) => m.slice(0, 4) + '***');
}

export function lightEvidence(step = {}, { maxBytes = 2000 } = {}) {
  const call = step.call || {};
  const common = { tool: step.tool || call.tool || '', target: step.target || call.target || '', command: step.command || '' };
  // Full mode: the agent captured real request/response flows — mask + bound them.
  if (step.evidence && step.evidence.mode === 'full' && Array.isArray(step.evidence.flows)) {
    return {
      ...common,
      mode: 'full',
      flows: step.evidence.flows.slice(0, 20).map((fl) => ({
        method: fl.method, url: fl.url, status: fl.status,
        req_body: mask(String(fl.req_body || '').slice(0, maxBytes)),
        res_body: mask(String(fl.res_body || '').slice(0, maxBytes)),
      })),
    };
  }
  return { ...common, mode: 'light', excerpt: mask(String(step.rawExcerpt || step.raw || '').slice(0, maxBytes)) };
}

export function collectEvidence(executed = [], opts) {
  return (Array.isArray(executed) ? executed : [])
    .filter((e) => e && e.ran)
    .map((e) => lightEvidence(e, opts));
}
