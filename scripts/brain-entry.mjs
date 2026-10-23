// Bundle entrypoint — re-exports the pure brain functions the orchestrator wires.
// The path __UTILS__ is rewritten by bundle-brain.mjs to the resolved IRIS_SRC
// utils dir before esbuild runs.
export { runReconLoop, planReconStep, stricterDecision, pickInjectionTarget } from '__UTILS__/reconLoop.js';
export { finalizeTriage } from '__UTILS__/reconTriage.js';
export { proposeChains } from '__UTILS__/chains.js';
export { makeAgentClient, executeReconTool } from '__UTILS__/reconExecutor.js';
export {
  parseScopeText,
  evaluateScope,
  isInScope,
  EMPTY_SCOPE,
  hostFromUrl,
} from '__UTILS__/scope.js';
export { normalizeFinding } from '__UTILS__/findings.js';
