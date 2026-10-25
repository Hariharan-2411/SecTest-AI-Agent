// Remote notification + approval channel. Telegram does two-way Approve/Deny via
// long-polling getUpdates (works behind NAT — no public webhook needed). Discord
// and Slack are one-way alert channels. All degrade gracefully when unconfigured.
const TG_API = (token) => `https://api.telegram.org/bot${token}`;

export function createBot({ env = process.env, broker, fetchImpl = fetch } = {}) {
  const tgToken = env.TELEGRAM_BOT_TOKEN || '';
  const tgChat = env.TELEGRAM_CHAT_ID || '';
  const discord = env.DISCORD_WEBHOOK_URL || '';
  const slack = env.SLACK_WEBHOOK_URL || '';
  let offset = 0;
  let polling = false;

  async function tgCall(token, method, body) {
    const res = await fetchImpl(`${TG_API(token)}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.json().catch(() => ({}));
  }

  // One-way webhook fan-out. Discord wants {content}, Slack wants {text}.
  async function postWebhooks(text) {
    if (discord) await fetchImpl(discord, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content: text }) }).catch(() => {});
    if (slack) await fetchImpl(slack, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) }).catch(() => {});
  }

  async function notifyApproval(record) {
    const c = record.call || {};
    // Telegram carries the interactive Approve/Deny buttons…
    if (tgToken && tgChat) {
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
    // …Discord/Slack get a one-way heads-up (decide from the dashboard).
    await postWebhooks(`🛑 Approval needed: ${c.tool} (${record.risk}) → ${c.target} · ID ${record.id} — decide on the dashboard`);
  }

  async function notifyFinding(f) {
    const text = `🔎 ${f.severity || 'info'} — ${f.title || f.name || 'finding'}\n${f.target || f.host || ''}`;
    if (tgToken && tgChat) await tgCall(tgToken, 'sendMessage', { chat_id: tgChat, text });
    await postWebhooks(text);
  }

  // Send a plain message to every configured channel (e.g. a monitor digest).
  async function notifyText(text) {
    if (!text) return;
    if (tgToken && tgChat) await tgCall(tgToken, 'sendMessage', { chat_id: tgChat, text });
    await postWebhooks(text);
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
    enabled: { telegram: !!(tgToken && tgChat), discord: !!discord, slack: !!slack },
    notifyApproval,
    notifyFinding,
    notifyText,
    startPolling,
    stop: () => { polling = false; },
    _handleCallback: handleCallback, // exposed for tests
  };
}
