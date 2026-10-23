// Atomic JSON persistence (temp file + rename), mirroring the companion agent's
// store pattern. One file per collection under data/. Safe for a single process.
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = resolve(here, '..', 'data');

function fileFor(name) {
  return resolve(DATA_DIR, `${name}.json`);
}

export function load(name, fallback = []) {
  try {
    return JSON.parse(readFileSync(fileFor(name), 'utf8'));
  } catch (_) {
    return fallback;
  }
}

export function save(name, value) {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
  const f = fileFor(name);
  const tmp = `${f}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 2));
  renameSync(tmp, f);
  return value;
}

// A tiny collection helper: load → mutate → save.
export function collection(name) {
  return {
    all: () => load(name, []),
    upsert(record, key = 'id') {
      const rows = load(name, []);
      const i = rows.findIndex((r) => r[key] === record[key]);
      if (i >= 0) rows[i] = { ...rows[i], ...record };
      else rows.push(record);
      save(name, rows);
      return record;
    },
    get(id, key = 'id') {
      return load(name, []).find((r) => r[key] === id) || null;
    },
  };
}
