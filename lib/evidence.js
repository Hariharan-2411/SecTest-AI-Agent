// PoC evidence (Light mode): the exact tool command + a bounded, masked excerpt
// of the tool's raw output. Minimum PoC — never full exfiltrated data, secrets masked.
const SECRET_RE = /(AKIA[0-9A-Z]{8,}|gsk_[A-Za-z0-9]{10,}|sk-[A-Za-z0-9-]{12,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|xox[baprs]-[A-Za-z0-9-]{8,})/g;

export function mask(s) {
  return String(s || '').replace(SECRET_RE, (m) => m.slice(0, 4) + '***');
}

export function lightEvidence(step = {}, { maxBytes = 2000 } = {}) {
  const call = step.call || {};
  return {
    tool: step.tool || call.tool || '',
    target: step.target || call.target || '',
    command: step.command || '',
    excerpt: mask(String(step.rawExcerpt || step.raw || '').slice(0, maxBytes)),
  };
}

export function collectEvidence(executed = [], opts) {
  return (Array.isArray(executed) ? executed : [])
    .filter((e) => e && e.ran)
    .map((e) => lightEvidence(e, opts));
}
