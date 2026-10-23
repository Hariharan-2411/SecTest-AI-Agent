// Provider-agnostic LLM client. Matches the brain's contract: chat(messages, model)
// → string. Default providers are easy APIs (Groq, Anthropic); `openai-compatible`
// (LLM_BASE_URL) covers self-hosted EC2/vLLM/Ollama/LM Studio and AWS Bedrock's
// OpenAI-compatible endpoint — self-hosting is a config change, not a code change.
//
// Defense-in-depth safety preamble is prepended to every call. The REAL guardrails
// are deterministic (server-side scope in the agent, risk-tags, the approval gate);
// this preamble keeps the model's suggestions in line. Keep it in sync with the
// hardened prompts in Extension/chrome-boiler/supabase/functions/groq-proxy/index.ts.

export const SAFETY_PREAMBLE = [
  'You assist with AUTHORIZED bug-bounty recon on explicitly in-scope assets only.',
  'Propose recon/triage steps as CANDIDATES, never verdicts. A human validates and submits.',
  'Never propose data exfiltration, persistence, lateral movement, account takeover of real',
  'users, or denial-of-service. Proof-of-concept must be non-destructive (read a canary, not',
  'customer data). Never auto-submit. Stay within the provided scope and program rules.',
].join(' ');

function withPreamble(messages) {
  const sys = { role: 'system', content: SAFETY_PREAMBLE };
  return [sys, ...(Array.isArray(messages) ? messages : [])];
}

const LLM_TIMEOUT_MS = Number(process.env.LLM_TIMEOUT_MS || 45000);

// fetch with an abort timeout so a hung/rate-limited provider can't stall the
// whole ensemble (Promise.allSettled would otherwise wait forever).
async function timedFetch(url, opts, timeoutMs = LLM_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function openaiCompatible({ baseUrl, apiKey, model, messages }) {
  const res = await timedFetch(`${baseUrl.replace(/\/$/, '')}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
    },
    body: JSON.stringify({ model, messages, temperature: 0.2 }),
  });
  if (!res.ok) throw new Error(`llm_http_${res.status}`);
  const data = await res.json();
  return data?.choices?.[0]?.message?.content || '';
}

async function anthropic({ apiKey, model, messages }) {
  const system = messages.filter((m) => m.role === 'system').map((m) => m.content).join('\n\n');
  const rest = messages
    .filter((m) => m.role !== 'system')
    .map((m) => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content }));
  const res = await timedFetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({ model, max_tokens: 2048, temperature: 0.2, system, messages: rest }),
  });
  if (!res.ok) throw new Error(`llm_http_${res.status}`);
  const data = await res.json();
  return (data?.content || []).map((b) => b.text || '').join('');
}

// Build a chat client from an explicit config. The returned chat(messages, model)
// returns a string, matching the brain's contract.
export function makeClient({ provider, apiKey, model, baseUrl }) {
  const prov = (provider || 'groq').toLowerCase();
  const bases = {
    groq: 'https://api.groq.com/openai/v1',
    'openai-compatible': baseUrl || '',
  };
  async function chat(messages, overrideModel) {
    const m = overrideModel || model;
    const msgs = withPreamble(messages);
    if (prov === 'anthropic') return anthropic({ apiKey, model: m, messages: msgs });
    const url = bases[prov];
    if (!url) throw new Error(`no base url for provider ${prov}`);
    return openaiCompatible({ baseUrl: url, apiKey, model: m, messages: msgs });
  }
  return { provider: prov, model, chat };
}

// Fallback chain: try each client in order; on error (rate limit, outage, bad
// key) fall through to the next. This is how a role uses BOTH Groq AND OpenRouter.
export function makeChain(clients) {
  const list = clients.filter(Boolean);
  return {
    providers: list.map((c) => `${c.provider}${c.model ? ':' + c.model : ''}`),
    model: list[0] && list[0].model,
    async chat(messages, model) {
      let lastErr;
      for (const c of list) {
        try { return await c.chat(messages, model); } catch (e) { lastErr = e; }
      }
      throw lastErr || new Error('no_llm_clients');
    },
  };
}

export function createLlm(env = process.env) {
  const primary = makeClient({
    provider: env.LLM_PROVIDER || 'groq',
    apiKey: env.LLM_API_KEY || '',
    model: env.LLM_MODEL || '',
    baseUrl: env.LLM_BASE_URL || '',
  });
  const fallback = env.LLM_FALLBACK_PROVIDER
    ? makeClient({
        provider: env.LLM_FALLBACK_PROVIDER,
        apiKey: env.LLM_FALLBACK_API_KEY || '',
        model: env.LLM_FALLBACK_MODEL || '',
        baseUrl: env.LLM_FALLBACK_BASE_URL || '',
      })
    : null;
  const clients = [primary, fallback].filter(Boolean);
  const chain = makeChain(clients);
  const parseModel = env.LLM_PARSE_MODEL || '';
  const parseChat = parseModel ? (messages) => chain.chat(messages, parseModel) : chain.chat;
  return { ...chain, clients, provider: chain.providers.join('+'), parseChat };
}

// Critic client for the dual-model planner/critic. Reads CRITIC_* and falls back
// to the proposer's LLM_* config, so single-model deployments keep working.
export function createCritic(env = process.env) {
  const enabled = !!(env.CRITIC_PROVIDER || env.CRITIC_MODEL || env.CRITIC_API_KEY || env.CRITIC_BASE_URL);
  const primary = makeClient({
    provider: env.CRITIC_PROVIDER || env.LLM_PROVIDER || 'groq',
    apiKey: env.CRITIC_API_KEY || env.LLM_API_KEY || '',
    model: env.CRITIC_MODEL || env.LLM_MODEL || '',
    baseUrl: env.CRITIC_BASE_URL || env.LLM_BASE_URL || '',
  });
  const fallback = env.CRITIC_FALLBACK_PROVIDER
    ? makeClient({
        provider: env.CRITIC_FALLBACK_PROVIDER,
        apiKey: env.CRITIC_FALLBACK_API_KEY || '',
        model: env.CRITIC_FALLBACK_MODEL || '',
        baseUrl: env.CRITIC_FALLBACK_BASE_URL || '',
      })
    : null;
  const clients = [primary, fallback].filter(Boolean);
  const chain = makeChain(clients);
  return { ...chain, clients, provider: chain.providers.join('+'), enabled };
}

// Plan ensemble: both models propose in parallel; we UNION their steps so neither
// model's blind spot drops a tool (coverage first — the critic + deterministic
// validator decide what actually runs and what ranks high). Returns a single JSON
// plan string, matching what planReconStep expects from `chat`.
export function makePlanEnsemble(clients, { safeParse } = {}) {
  const parse = safeParse || ((t) => { try { return JSON.parse(String(t).replace(/```(?:json)?|```/g, '').trim()); } catch (_) { return null; } });
  const list = (clients || []).filter(Boolean);
  return async function ensembleChat(messages, model) {
    if (!list.length) throw new Error('no_llm_clients');
    const replies = await Promise.allSettled(list.map((c) => c.chat(messages, model)));
    const seen = new Set();
    const steps = [];
    let dones = 0, ok = 0;
    for (const r of replies) {
      if (r.status !== 'fulfilled') continue;
      ok++;
      const p = parse(r.value);
      if (!p) continue;
      if (p.done) dones++;
      for (const st of Array.isArray(p.steps) ? p.steps : []) {
        const key = `${st.tool}|${st.target}|${st.profile || ''}`;
        if (!seen.has(key)) { seen.add(key); steps.push(st); }
      }
    }
    if (!ok) throw new Error('all_llm_clients_failed');
    // Stop only when every responding model agrees there's nothing left.
    return JSON.stringify({ steps, done: dones === ok });
  };
}