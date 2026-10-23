// Remote notification + approval channel. Telegram does two-way Approve/Deny via
// long-polling getUpdates (works behind NAT — no public webhook needed). Discord
// is one-way finding alerts. Both degrade gracefully when unconfigured.
import { createRequire } from 'node:module';

const TG_API = (token) => `https://api.telegram.org/bot${token}`;

async function tgCall(token, method, body) {
  const res = await fetch(`${TG_API(token)}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json().catch(() => ({}));
}

export function createBot({ env = process.env, broker } = {}) {
  const tgToken = env.TELEGRAM_BOT_TOKEN || '';
  const tgChat = env.TELEGRAM_CHAT_ID || '';
  const discord = env.DISCORD_WEBHOOK_URL || '';
  let offset = 0;
  let polling = false;

  async function notifyApproval(record) {
    if (!tgToken || !tgChat) return;
    const c = record.call || {};
    await tgCall(tgToken, 'sendMessage', {
      chat_id: tgChat,
      text: `🛑 Approval needed\nTool: ${c.tool} (${record.risk})\nTarget: ${c.target}\nProfile: ${c.profile || 'quick'}\nID: ${record.id}`,
      reply_markup: {
        inline_keyboard: [[
          { text: '✅ Approve', callback_data: `approve:${record.id}` },
          { text: '⛔ Deny', callback_data: `deny:${record.id}` },
        ]],
      },
    });
  }

  async function notifyFinding(f) {
    const text = `🔎 ${f.severity || 'info'} — ${f.title || f.name || 'finding'}\n${f.target || f.host || ''}`;
    if (tgToken && tgChat) await tgCall(tgToken, 'sendMessage', { chat_id: tgChat, text });
    if (discord) {
      await fetch(discord, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text }),
      }).catch(() => {});
    }
  }

  async function handleCallback(cb) {
    const data = cb.data || '';
    const m = data.match(/^(approve|deny):(.+)$/);
    if (!m || !broker) return;
    const [, action, id] = m;
    const ok = action === 'approve' ? broker.approve(id, 'telegram') : broker.deny(id, 'telegram');
    await tgCall(tgToken, 'answerCallbackQuery', {
      callback_query_id: cb.id,
      text: ok ? `Recorded: ${action}` : 'Already decided / unknown',
    });
  }

  async function pollOnce() {
    const data = await tgCall(tgToken, 'getUpdates', { offset, timeout: 25 });
    for (const u of data.result || []) {
      offset = u.update_id + 1;
      if (u.callback_query) await handleCallback(u.callback_query).catch(() => {});
    }
  }

  async function startPolling() {
    if (!tgToken || polling) return;
    polling = true;
    while (polling) {
      try { await pollOnce(); } catch (_) { await new Promise((r) => setTimeout(r, 3000)); }
    }
  }

  return {
    enabled: { telegram: !!(tgToken && tgChat), discord: !!discord },
    notifyApproval,
    notifyFinding,
    startPolling,
    stop: () => { polling = false; },
    _handleCallback: handleCallback, // exposed for tests
  };
}
