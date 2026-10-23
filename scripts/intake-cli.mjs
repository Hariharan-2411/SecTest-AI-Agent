// CLI intake: node scripts/intake-cli.mjs --url https://app.example.com --subs --confirm --rules "Automated scanning is allowed."
import * as brain from '../vendor/brain.mjs';
import { buildEngagement } from '../lib/intake.js';

const args = process.argv.slice(2);
const get = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : undefined; };
const has = (k) => args.includes(k);
const urls = args.filter((a, i) => args[i - 1] === '--url');

const engagement = buildEngagement(
  {
    name: get('--name') || 'cli',
    urls,
    enumerateSubdomains: has('--subs'),
    rulesText: get('--rules') || '',
    confirmed: has('--confirm'),
    allowDestructive: has('--destructive'),
    evidenceMode: has('--evidence-full') ? 'full' : 'light',
  },
  { hostFromUrl: brain.hostFromUrl, parseScopeText: brain.parseScopeText }
);
console.log(JSON.stringify(engagement, null, 2));
if (has('--run')) {
  const base = process.env.ORCH_URL || 'http://localhost:8790';
  const r = await fetch(`${base}/api/engagements`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-dashboard-token': process.env.DASHBOARD_TOKEN || '' },
    body: JSON.stringify({ ...engagement.__input, urls, enumerateSubdomains: has('--subs'), rulesText: get('--rules') || '', confirmed: has('--confirm'), allowDestructive: has('--destructive'),
    evidenceMode: has('--evidence-full') ? 'full' : 'light', name: get('--name') || 'cli' }),
  });
  console.log('submit:', r.status, await r.text());
}
