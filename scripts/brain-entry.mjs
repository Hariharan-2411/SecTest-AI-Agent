// Bundle entrypoint — re-exports the pure brain functions the orchestrator wires.
// The path __UTILS__ is rewritten by bundle-brain.mjs to the resolved IRIS_SRC
// utils dir before esbuild runs.
export { runReconLoop, planReconStep, stricterDecision, pickInjectionTarget } from '__UTILS__/reconLoop.js';
export { finalizeTriage } from '__UTILS__/reconTriage.js';
export { proposeChains } from '__UTILS__/chains.js';
export { draftChainNarrative } from '__UTILS__/chainNarrative.js';
export { buildPocScaffold } from '__UTILS__/pocScaffold.js';
export { buildReconDigest, formatReconDigest } from '__UTILS__/reconDigest.js';
export { escalationBudgetFor, BAND_PLAN } from '__UTILS__/escalationBudget.js';
export { buildReport, REPORT_PLATFORMS } from '__UTILS__/reportBuilder.js';
export { makeAgentClient, executeReconTool } from '__UTILS__/reconExecutor.js';
export {
  parseScopeText,
  evaluateScope,
  isInScope,
  EMPTY_SCOPE,
  hostFromUrl,
} from '__UTILS__/scope.js';
export { normalizeFinding } from '__UTILS__/findings.js';
