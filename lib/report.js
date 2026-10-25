// Report generator — turns a finding or a chain into platform-ready markdown via
// the extension's reportBuilder. It only formats what the item carries; it never
// invents evidence.
import * as brain from '../vendor/brain.mjs';

export const PLATFORMS = brain.REPORT_PLATFORMS;

export function renderReport(item, platform = 'hackerone') {
  if (!item) return null;
  // A chain carries `steps`; map it to a finding-shaped object the builder accepts.
  // The builder keys off `title`/`evidence`; our findings carry `name`/`matched`.
  // When the chain has an AI-drafted narrative (summary/impact/remediation — the
  // model narrates, the CODE owns severity), fold it into the report sections.
  const n = item.narrative || {};
  const finding = Array.isArray(item.steps)
    ? {
        title: item.title || 'Exploit chain',
        severity: item.severity,
        summary: n.summary || '',
        impact: n.impact || '',
        remediation: n.remediation || '',
        steps: item.steps.map((s) => s && (s.type || s.title || s.name || s.tool)).filter(Boolean),
        evidence: item.rationale || '',
        target: item.target || '',
      }
    : { ...item, title: item.title || item.name, evidence: item.evidence || item.matched };

  // Findings without reproduction steps get a type-aware PoC scaffold (steps +
  // repro command). Canary/minimal-PoC ethos; pure, never a data dump. Chains
  // already carry their own steps, so only scaffold a bare finding.
  if (!Array.isArray(item.steps) && (!Array.isArray(finding.steps) || !finding.steps.length)) {
    const scaffold = brain.buildPocScaffold(finding);
    finding.steps = [...scaffold.steps, ...(scaffold.repro ? [`Repro: ${scaffold.repro}`] : [])];
  }
  return brain.buildReport(finding, platform);
}
