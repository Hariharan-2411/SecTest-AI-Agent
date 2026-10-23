// Builds vendor/brain.mjs from the Iris extension's pure src/utils modules.
// Why a build step: those modules use ESM syntax with extensionless imports in a
// package that is NOT type:module, so Node can't import them directly. esbuild
// resolves the graph and the aiProvider stub keeps browser/Supabase coupling out
// (the orchestrator always injects its own `chat`).
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { utilsDir, orchRoot } from '../lib/paths.js';

const here = dirname(fileURLToPath(import.meta.url));
const utils = utilsDir();

// Materialize the entry with the real utils path.
const entrySrc = readFileSync(join(here, 'brain-entry.mjs'), 'utf8').replaceAll(
  '__UTILS__',
  utils.replaceAll('\\', '/')
);
const tmp = mkdtempSync(join(tmpdir(), 'iris-brain-'));
const entryPath = join(tmp, 'brain-entry.mjs');
writeFileSync(entryPath, entrySrc);

// Replace the browser/Supabase-coupled aiProvider with an inert stub: the
// orchestrator always injects `chat`, so the fallback is never called.
const stubAiProvider = {
  name: 'stub-aiprovider',
  setup(b) {
    b.onResolve({ filter: /aiProvider(\.js)?$/ }, () => ({
      path: 'stub-aiprovider',
      namespace: 'stub',
    }));
    b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({
      contents: `
        const nope = () => { throw new Error('aiProvider not available server-side — inject chat'); };
        export const chat = nope;
        export const generatePayload = nope;
        export const classifyResponse = nope;
        export const draftFinding = nope;
        export const escalateFinding = nope;
        export const listModels = async () => [];
        export const checkReachable = async () => false;
        export const DEFAULT_MODEL = 'injected';
      `,
      loader: 'js',
    }));
  },
};

await build({
  entryPoints: [entryPath],
  outfile: resolve(orchRoot, 'vendor/brain.mjs'),
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node20',
  plugins: [stubAiProvider],
  logLevel: 'info',
});

console.log('✓ bundled brain → vendor/brain.mjs  (from', utils + ')');
