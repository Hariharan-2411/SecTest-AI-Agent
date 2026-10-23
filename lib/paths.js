// Resolves the Iris extension source tree (the reusable brain) from IRIS_SRC.
// Live reference: one source of truth — the brain is bundled from here at build
// time rather than copied. See README.
import { resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const orchRoot = resolve(here, '..');

export function irisSrc() {
  const raw = process.env.IRIS_SRC || '../Extension/chrome-boiler';
  return isAbsolute(raw) ? raw : resolve(orchRoot, raw);
}

export function utilsDir() {
  return resolve(irisSrc(), 'src/utils');
}

export { orchRoot };
