(() => {
const $ = (t, a = {}, ...kids) => { const e = document.createElement(t); for (const [k, v] of Object.entries(a)) k === 'class' ? e.className = v : k === 'style' ? e.style.cssText = v : k.startsWith('on') ? e.addEventListener(k.slice(2), v) : e.setAttribute(k, v);
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(String(c))); return e; };   // textContent only: stored data can never inject markup
const inr = p => '₹' + Math.round(p / 100).toLocaleString('en-IN'), num = n => Math.round(n ?? 0).toLocaleString('en-IN');
let token = null, me = null; const app = document.getElementById('app');
const api = async (path, body) => { const r = await fetch('/api' + path, { method: body ? 'POST' : 'GET', headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json(); if (!r.ok) throw new Error(j.error || r.statusText); return j; };
const table = (cols, rows) => $('table', {}, $('thead', {}, $('tr', {}, cols.map(c => $('th', { class: c.n ? 'n' : '' }, c.h)))), $('tbody', {}, rows.map(r => $('tr', {}, cols.map(c => $('td', { class: (c.n ? 'n ' : '') + (c.cls ? c.cls(r) : '') }, c.f(r)))))));
const kpi = (l, v) => $('div', { class: 'card kpi' }, $('div', { class: 'v' }, v), $('div', { class: 'l' }, l));

function login(msg) {
  const u = $('input', { placeholder: 'username', autocomplete: 'username' }), p = $('input', { placeholder: 'password', type: 'password', autocomplete: 'current-password' }),
    o = $('input', { placeholder: 'one-time code (if MFA enabled)', inputmode: 'numeric', autocomplete: 'one-time-code' }), e = $('div', { class: 'err' }, msg || '');
  const go = async () => { try { const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u.value, password: p.value, otp: o.value }) }); const j = await r.json();
      if (!r.ok) { e.textContent = j.error; return; } token = j.token; me = await api('/me'); shell(); } catch (x) { e.textContent = x.message; } };
  [p, o].forEach(i => i.addEventListener('keydown', k => k.key === 'Enter' && go()));
  app.replaceChildren($('div', { class: 'card login' }, $('h2', {}, 'Provenance'), $('p', { class: 'mute' }, 'Revenue assurance & data trust. Demo logins are in data/demo_credentials.txt'), u, p, o, $('button', { class: 'btn primary', onclick: go }, 'Sign in'), e));
}
const TABS = { Overview: ['overview', overview], Reconciliation: ['recon', recon], Cases: ['cases_view', casesTab], Pipeline: ['pipeline_view', pipeline], Security: ['security', security], 'Ask AI': ['ask', ask], Traceability: ['recall', recall], Audit: ['audit', audit], Account: ['account', account] };
function shell(active) {
  const main = $('main'); const names = Object.keys(TABS).filter(n => me.perms.includes(TABS[n][0]));
  active = names.includes(active) ? active : names[0];
  app.replaceChildren($('header', {}, $('div', {}, $('h1', {}, 'Provenance'), $('div', { class: 'sub' }, me.user + ' · ' + me.role)),
    $('nav', {}, names.map(n => $('button', { class: n === active ? 'on' : '', onclick: () => shell(n) }, n)), $('button', { onclick: async () => { try { await api('/logout', {}); } catch (_) {} token = null; login(); } }, 'Sign out'))), main);
  TABS[active][1](main).catch(x => main.replaceChildren($('div', { class: 'err' }, x.message)));
}
async function overview(m) {
  const [o, an] = await Promise.all([api('/overview'), api('/anomalies')]); const k = o.kpis;
  m.append($('div', { class: 'grid' }, kpi('GMV', inr(k.gmv)), kpi('Orders', num(k.orders)), kpi('Revenue leakage found', inr(k.leakage)), kpi('Open exceptions', num(k.exceptions)), kpi('Contribution margin', inr(k.contribution)), kpi('Refunds', inr(k.refunds)), kpi('Open cases', num(o.cases.open_cases)), kpi('Past SLA', num(o.cases.sla_breached)), kpi('Recovered', inr(o.cases.recovered)), kpi('Recovery rate', o.cases.recovery_rate_pct + '%')));
  const max = Math.max(...o.leak_by_reason.map(r => r.leak_paise), 1);
  m.append($('div', { class: 'card' }, $('h2', {}, 'Money at stake by cause (shortfalls to claim + overpayments to recover)'), table([{ h: 'Cause', f: r => r.reason }, { h: 'Orders', n: 1, f: r => r.n }, { h: 'At stake', n: 1, f: r => inr(r.leak_paise) }, { h: '', f: r => $('div', { class: 'bar', style: `width:${100 * r.leak_paise / max}%` }) }], o.leak_by_reason)));
  m.append($('div', { class: 'card' }, $('h2', {}, 'Channel economics'), table([{ h: 'Channel', f: r => r.channel }, { h: 'GMV', n: 1, f: r => inr(r.gmv) }, { h: 'Fees', n: 1, f: r => inr(r.fees) }, { h: 'Leakage', n: 1, f: r => inr(r.leakage), cls: r => r.leakage ? 'bad' : '' },
    { h: 'Margin', n: 1, f: r => inr(r.contribution) }, { h: 'Return %', n: 1, f: r => r.return_pct }, { h: 'Repeat %', n: 1, f: r => r.repeat_pct }], o.by_channel)));
  m.append($('div', { class: 'card' }, $('h2', {}, 'Statistical anomalies (exact Poisson / binomial tail tests)'), an.length ? table([{ h: 'Day', f: r => r.day }, { h: 'Channel', f: r => r.channel }, { h: 'Type', f: r => r.type }, { h: 'Observed', f: r => r.observed }, { h: 'Expected', f: r => r.expected }, { h: 'p', n: 1, f: r => r.p_value.toExponential(1) }], an) : 'None.'));
}
async function recon(m) {
  const sel = $('select', {}, ['', 'MISSING_SETTLEMENT', 'COMMISSION_OVERCHARGE', 'SHORT_PAY', 'DUPLICATE_SETTLEMENT', 'PAYMENT_MISSING'].map(v => $('option', { value: v }, v || 'all causes'))), box = $('div'), brief = $('div');
  const load = async () => { const rows = await api('/recon?limit=60' + (sel.value ? '&reason=' + sel.value : ''));
    box.replaceChildren(table([{ h: 'Order', f: r => me.perms.includes('investigate') ? $('a', { href: '#', onclick: async e => { e.preventDefault(); const j = await api('/investigate?order_id=' + r.order_id); brief.replaceChildren($('div', { class: 'card' }, $('h2', {}, 'Case brief · ' + r.order_id), $('p', {}, j.brief), j.note_withheld ? $('p', { class: 'warn' }, '⚠ Customer note withheld from AI context (prompt-injection patterns).') : null)); } }, r.order_id) : r.order_id },
      { h: 'Channel', f: r => r.channel }, { h: 'Day', f: r => r.day }, { h: 'Cause', f: r => r.recon_reason }, { h: 'Expected', n: 1, f: r => inr(r.expected_net) }, { h: 'Received', n: 1, f: r => inr(r.actual_net) }, { h: 'Variance', n: 1, cls: () => 'bad', f: r => inr(r.variance) }, { h: 'Customer', f: r => r.customer_token }], rows)); };
  sel.addEventListener('change', load); m.append($('div', { class: 'card' }, $('h2', {}, 'Reconciliation exceptions (largest first)'), $('div', { class: 'row' }, sel), box), brief); await load();
}
async function pipeline(m) {
  const p = await api('/pipeline');
  if (me.perms.includes('pipeline_run')) { const msg = $('span', { class: 'mute' }); m.append($('div', { class: 'row' }, $('button', { class: 'btn primary', onclick: async () => { msg.textContent = 'running…'; try { const r = await api('/pipeline/run', {}); msg.textContent = 'done, DQ ' + r.dq_score; setTimeout(() => shell('Pipeline'), 600); } catch (x) { msg.textContent = x.message; } } }, 'Run pipeline'), msg)); }
  if (me.perms.includes('ingest')) {
    const f = $('input', { type: 'file', accept: '.csv,.jsonl' }), run = $('input', { type: 'checkbox', checked: 'checked' }), msg = $('span', { class: 'mute' });
    const up = () => { const file = f.files[0]; if (!file) { msg.textContent = 'choose a file'; return; } const fr = new FileReader();
      fr.onload = async () => { const b64 = btoa(String.fromCharCode(...new Uint8Array(fr.result))); msg.textContent = 'uploading…';
        try { const r = await api('/ingest', { filename: file.name, content_b64: b64, run: run.checked }); msg.textContent = 'stored ' + r.stored + (r.run ? ' · DQ ' + r.run.dq_score : ''); setTimeout(() => shell('Pipeline'), 800); } catch (x) { msg.textContent = x.message; } };
      fr.readAsArrayBuffer(file); };
    m.append($('div', { class: 'card' }, $('h2', {}, 'Connector: drop a partner file'), $('p', { class: 'mute' }, 'Filename must start with a known source prefix (e.g. settlements_<PARTNER>.csv). Partner column layouts are onboarded via mapping profiles, with no code change.'),
      $('div', { class: 'row' }, f, $('label', {}, run, ' run pipeline now'), $('button', { class: 'btn primary', onclick: up }, 'Upload'), msg), p.pending_files.length ? $('p', { class: 'warn' }, 'Awaiting ingestion: ' + p.pending_files.join(', ')) : null));
  }
  m.append($('div', { class: 'grid' }, kpi('Data-quality score', p.score ?? '–'), kpi('Quarantined rows', p.quarantine.length)));
  m.append($('div', { class: 'card' }, $('h2', {}, 'Stage throughput (latest run)'), table([{ h: 'Stage', f: r => r.stage }, { h: 'In', n: 1, f: r => r.rows_in }, { h: 'Out', n: 1, f: r => r.rows_out }, { h: 'Quarantined', n: 1, f: r => r.rows_quarantined }, { h: 'Duplicates dropped', n: 1, f: r => r.rows_duplicate }], p.stages)));
  m.append($('div', { class: 'card' }, $('h2', {}, 'Data-quality checks'), table([{ h: 'Check', f: r => r.check_name }, { h: 'Severity', f: r => r.severity }, { h: 'Failed / total', n: 1, f: r => `${r.failed} / ${r.total}`, cls: r => r.failed ? 'bad' : 'ok' }], p.dq)));
  m.append($('div', { class: 'card' }, $('h2', {}, 'Quarantine (rejected by data contract)'), table([{ h: 'Source', f: r => r.source }, { h: 'Reason', f: r => r.reason }], p.quarantine)));
  m.append($('div', { class: 'card' }, $('h2', {}, 'Lineage'), table([{ h: 'Table', f: r => r.target }, { h: 'Built from', f: r => r.source }, { h: 'Transform', f: r => r.transform }], p.lineage)));
}
async function security(m) {
  const a = await api('/alerts');
  m.append($('div', { class: 'card' }, $('h2', {}, 'Threat & misuse detections'), table([{ h: 'Severity', f: r => r.severity, cls: r => r.severity }, { h: 'Kind', f: r => r.kind }, { h: 'Subject', f: r => r.subject }, { h: 'Evidence', f: r => { const d = JSON.parse(r.detail); return d.why + (d.excerpt ? ' — “' + d.excerpt + '”' : ''); } },
    { h: '', f: r => me.perms.includes('alerts_ack') && r.status === 'open' ? $('button', { class: 'btn', onclick: async () => { await api('/alerts/ack', { id: r.id }); shell('Security'); } }, 'Acknowledge') : r.status }], a)));
}
async function ask(m) {
  const q = $('input', { placeholder: 'e.g. How much did we lose to marketplace payout errors in the last 30 days, by cause?' }), out = $('div');
  const go = async () => { out.replaceChildren('…'); try { const r = await api('/ask', { question: q.value });
    out.replaceChildren(r.blocked ? $('div', { class: 'err' }, '🛡 ' + r.reason) : $('div', { class: 'card' }, $('p', {}, r.answer), r.rows[0]?.k !== undefined ? table([{ h: r.plan.dimension, f: x => x.k }, { h: r.plan.metric, n: 1, f: x => (r.unit === '₹' ? '₹' : '') + num(x.v) + (r.unit === '%' ? '%' : '') }], r.rows.slice(0, 15)) : null,
      $('div', { class: 'mute' }, 'engine: ' + r.engine + ' · governed plan (no free-form SQL): ' + JSON.stringify(r.plan)), $('pre', {}, r.sql))); } catch (x) { out.replaceChildren($('div', { class: 'err' }, x.message)); } };
  q.addEventListener('keydown', k => k.key === 'Enter' && go());
  m.append($('div', { class: 'card' }, $('h2', {}, 'Ask your data'), $('p', { class: 'mute' }, 'The assistant can only select metrics, dimensions and filters from a governed catalog. It cannot write SQL or see customer-level data.'), $('div', { class: 'row' }, q, $('button', { class: 'btn primary', onclick: go }, 'Ask')), out));
}
async function recall(m) {
  const lots = await api('/lots'), sel = $('select', {}, lots.map(l => $('option', { value: l.lot_id }, `${l.lot_id} · ${l.sku} · ${l.supplier}`))), out = $('div');
  const go = async () => { const r = await api('/recall?lot=' + sel.value); out.replaceChildren($('div', { class: 'grid' }, kpi('Orders affected', r.orders), kpi('Customers (tokens)', r.customers), kpi('Units', r.units), kpi('Revenue exposed', inr(r.revenue_paise))),
    table([{ h: 'Channel', f: x => x[0] }, { h: 'Orders', n: 1, f: x => x[1].orders }, { h: 'Units', n: 1, f: x => x[1].units }, { h: 'Revenue', n: 1, f: x => inr(x[1].revenue) }], Object.entries(r.by_channel)), $('p', { class: 'mute' }, r.note)); };
  m.append($('div', { class: 'card' }, $('h2', {}, 'Recall blast-radius: supplier lot → orders → channels → customers'), $('div', { class: 'row' }, sel, $('button', { class: 'btn primary', onclick: go }, 'Trace forward')), out));
}
async function audit(m) {
  const a = await api('/audit'), v = a.verify;
  m.append($('div', { class: 'card' }, $('h2', {}, 'Tamper-evident audit chain'), $('p', { class: v.ok ? 'ok' : 'bad' }, v.ok ? `✔ Chain intact: ${v.entries} entries (head ${v.head})` : `✘ TAMPERING DETECTED at #${v.broken_at}: ${v.reason}`),
    table([{ h: '#', f: r => r.seq }, { h: 'Time', f: r => r.ts }, { h: 'Actor', f: r => r.actor }, { h: 'Role', f: r => r.role }, { h: 'Action', f: r => r.action }, { h: 'Resource', f: r => r.resource }, { h: 'MAC', f: r => r.mac }], a.entries)));
}

const NEXT = { OPEN: ['INVESTIGATING', 'DISPUTED', 'WRITEOFF_REQUESTED'], INVESTIGATING: ['DISPUTED', 'RECOVERED', 'WRITEOFF_REQUESTED'], DISPUTED: ['INVESTIGATING', 'RECOVERED', 'WRITEOFF_REQUESTED'], WRITEOFF_REQUESTED: ['WRITTEN_OFF', 'INVESTIGATING'] };
let pendingCase = null;
async function casesTab(m) {
  const d = await api('/cases'), st = d.stats, detail = $('div'), manage = me.perms.includes('cases_manage');
  m.append($('div', { class: 'grid' }, kpi('Open cases', st.open_cases), kpi('Value at stake', inr(st.open_at_stake)), kpi('Past SLA', st.sla_breached), kpi('Recovered', inr(st.recovered)), kpi('Recovery rate', st.recovery_rate_pct + '%'), kpi('Written off', inr(st.written_off))));
  const open = async id => {
    const c = await api('/case?id=' + id), users = manage ? await api('/users') : [], cs = c.case;
    const comment = $('input', { placeholder: 'comment / justification' }), amt = $('input', { placeholder: 'recovered ₹', type: 'number', min: '0', step: '0.01' }), who = $('select', {}, users.map(x => $('option', { value: x }, x))), msg = $('div', { class: 'err' });
    const act = async (path, body) => { try { await api(path, { id, ...body }); pendingCase = id; shell('Cases'); } catch (x) { msg.textContent = x.message; } };
    detail.replaceChildren($('div', { class: 'card' }, $('h2', {}, `Case #${id} · ${cs.order_id} · ${cs.reason}`), $('p', {}, `${cs.status} · ${cs.priority} priority · at stake ${inr(cs.at_stake)} · due ${cs.due_at.slice(0, 10)} · assignee ${cs.assignee || '–'}` + (cs.requested_by ? ` · write-off requested by ${cs.requested_by}` : '')),
      table([{ h: 'Time', f: r => r.ts }, { h: 'By', f: r => r.actor }, { h: 'Event', f: r => r.kind }, { h: 'Detail', f: r => r.detail }], c.events),
      manage && NEXT[cs.status] ? $('div', { class: 'row' }, comment, amt, NEXT[cs.status].map(t => $('button', { class: 'btn', onclick: () => act('/case/transition', { to: t, comment: comment.value, recovered_paise: amt.value ? Math.round(parseFloat(amt.value) * 100) : null }) }, '→ ' + t))) : null,
      manage && !['RECOVERED', 'WRITTEN_OFF', 'AUTO_RESOLVED'].includes(cs.status) ? $('div', { class: 'row' }, who, $('button', { class: 'btn', onclick: () => act('/case/assign', { assignee: who.value }) }, 'Assign'), $('button', { class: 'btn', onclick: () => act('/case/comment', { text: comment.value }) }, 'Add comment')) : null, msg));
  };
  m.append($('div', { class: 'card' }, $('h2', {}, 'Work queue (priority, then value)'), table([{ h: '#', f: r => $('a', { href: '#', onclick: e => { e.preventDefault(); open(r.case_id); } }, r.case_id) }, { h: 'Order', f: r => r.order_id }, { h: 'Cause', f: r => r.reason }, { h: 'Priority', f: r => r.priority, cls: r => r.priority === 'high' ? 'bad' : '' },
    { h: 'Status', f: r => r.status }, { h: 'Assignee', f: r => r.assignee || '–' }, { h: 'At stake', n: 1, f: r => inr(r.at_stake) }, { h: 'Due', f: r => r.due_at.slice(0, 10) }], d.cases.slice(0, 40))), detail);
  if (pendingCase) { const id = pendingCase; pendingCase = null; await open(id); }
}
async function account(m) {
  const msgP = $('div', { class: 'err' }), old = $('input', { type: 'password', placeholder: 'current password', autocomplete: 'current-password' }), nw = $('input', { type: 'password', placeholder: 'new password (12+ chars, 3 classes)', autocomplete: 'new-password' });
  m.append($('div', { class: 'card' }, $('h2', {}, 'Change password'), $('p', { class: 'mute' }, 'Changing your password signs out every active session.'), $('div', { class: 'row' }, old, nw, $('button', { class: 'btn primary', onclick: async () => { try { await api('/account/password', { old: old.value, new: nw.value }); token = null; login('Password changed. Please sign in again.'); } catch (x) { msgP.textContent = x.message; } } }, 'Change')), msgP));
  const box = $('div'), code = $('input', { placeholder: '6-digit code', inputmode: 'numeric' }), msgM = $('div', { class: 'err' });
  const begin = async () => { try { const r = await api('/account/mfa/begin', {}); box.replaceChildren($('p', {}, 'Add this key to an authenticator app (TOTP, 6 digits, 30 s):'), $('pre', {}, r.secret), $('div', { class: 'row' }, code, $('button', { class: 'btn primary', onclick: async () => { try { await api('/account/mfa/confirm', { code: code.value }); me.mfa = true; shell('Account'); } catch (x) { msgM.textContent = x.message; } } }, 'Confirm'))); } catch (x) { msgM.textContent = x.message; } };
  m.append($('div', { class: 'card' }, $('h2', {}, 'Multi-factor authentication'), me.mfa ? $('p', { class: 'ok' }, '✔ Enabled for this account.') : $('div', {}, $('p', { class: 'mute' }, 'Not enabled.'), $('button', { class: 'btn', onclick: begin }, 'Set up MFA')), box, msgM));
}
login();
})();
