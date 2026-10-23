// Report generator — turns a finding or a chain into platform-ready markdown via
// the extension's reportBuilder. It only formats what the item carries; it never
// invents evidence.
import * as brain from '../vendor/brain.mjs';

export const PLATFORMS = brain.REPORT_PLATFORMS;

export function renderReport(item, platform = 'hackerone') {
  if (!item) return null;
  // A chain carries `steps`; map it to a finding-shaped object the builder accepts.
  // The builder keys off `title`/`evidence`; our findings carry `name`/`matched`.
  const finding = Array.isArray(item.steps)
    ? {
        title: item.title || 'Exploit chain',
        severity: item.severity,
        evidence: item.rationale || '',
        target: item.target || '',
      }
    : { ...item, title: item.title || item.name, evidence: item.evidence || item.matched };
  return brain.buildReport(finding, platform);
}
