'use strict';
const $ = id => document.getElementById(id), COL = {TCP:'#6c8ef5',UDP:'#4fc4b0',DNS:'#e8b04a',HTTP:'#e07a8c',TLS:'#a98be0',ICMP:'#7fcf6b',ARP:'#d99a5b',ICMPv6:'#7fcf6b',Other:'#8c96ab'};
const col = p => COL[p] || COL.Other, PAGE = 100;
let sid = '', off = 0, total = 0, inspectedPacket = null, attachedPacket = null;
function el(t, c, x) { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; }
const fmtB = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
const api = async (u, o = {}) => { o.headers = { 'X-Requested-With': 'wirelight', ...o.headers }; const r = await fetch(u, o), j = await r.json(); if (!r.ok) throw new Error(j.error || 'Request failed'); return j; };

async function upload(f) {
  $('err').textContent = ''; if (!f) return;
  $('drop').firstElementChild.textContent = 'Uploading ' + f.name + '…';
  $('upload-status').textContent = `Uploading ${fmtB(f.size)}…`;
  try {
    const limits = await api('/api/upload/config');
    if (f.size > limits.max_bytes) throw new Error(`File is ${fmtB(f.size)}, but the server upload limit is ${fmtB(limits.max_bytes)}. Increase MAX_UPLOAD_MB in .env and recreate Docker.`);
    // XHR exposes upload progress; the server processes the file incrementally
    // without buffering it entirely in RAM. There is no client-side timeout.
    const j = await new Promise((resolve, reject) => {
      const req = new XMLHttpRequest();
      req.open('POST', '/api/upload');
      req.setRequestHeader('X-Requested-With', 'wirelight');
      req.setRequestHeader('Content-Type', 'application/octet-stream');
      req.upload.onprogress = e => {
        if (e.lengthComputable) $('upload-status').textContent = `Uploading ${Math.round(e.loaded / e.total * 100)}% · ${fmtB(e.loaded)} / ${fmtB(e.total)}`;
      };
      req.upload.onload = () => { $('upload-status').textContent = 'Upload received. Parsing packets locally…'; };
      req.onload = () => {
        let body = {};
        try { body = JSON.parse(req.responseText); } catch { /* Invalid HTTP response */ }
        if (req.status >= 200 && req.status < 300) resolve(body);
        else reject(new Error(body.error || `Upload failed (HTTP ${req.status})`));
      };
      req.onerror = () => reject(new Error('Connection lost during upload. Check Docker logs for memory pressure or container restarts.'));
      req.onabort = () => reject(new Error('Upload canceled.'));
      req.send(f);
    });
    sid = j.id; $('fname').textContent = f.name + (j.truncated ? ' (first 100,000 packets)' : '');
    $('land').hidden = true; $('dash').hidden = false; $('again').hidden = false;
    $('remote-download').hidden = true; summary(j.stats); $('q').value = ''; search(0); resetAI();
  } catch (e) {
    $('err').textContent = e.message;
    $('drop').firstElementChild.textContent = 'Ask your packet capture a question.';
  } finally { $('upload-status').textContent = ''; }
}

function summary(s) {
  const c = $('cards'); c.replaceChildren();
  [['Packets', s.packets.toLocaleString()], ['Data', fmtB(s.bytes)], ['Duration', s.duration.toFixed(2) + ' s'], ['Started', new Date(s.start * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC']]
    .forEach(([k, v]) => { const d = el('div', 'card'); d.append(el('b', '', v), el('span', '', k)); c.append(d); });
  const svg = $('tl'), mx = Math.max(...s.timeline, 1); svg.replaceChildren();
  s.timeline.forEach((v, i) => { const r = document.createElementNS('http://www.w3.org/2000/svg', 'rect'); const h = v / mx * 78;
    r.setAttribute('x', i * 10 + 1); r.setAttribute('y', 80 - h); r.setAttribute('width', 8); r.setAttribute('height', h); svg.append(r); });
  const bar = $('bar'), lg = $('legend'); bar.replaceChildren(); lg.replaceChildren();
  s.protocols.forEach(([p, n]) => { const b = el('div'); b.style.cssText = `flex:${n};background:${col(p)}`; b.title = p + ': ' + n; bar.append(b);
    const l = el('span', 'lg'); const i = el('i'); i.style.background = col(p); l.append(i, p + ' ' + n.toLocaleString()); l.onclick = () => ask(p.toLowerCase()); lg.append(l); });
  const t = $('talk'); t.replaceChildren();
  [['Sources', s.top_src, 'from '], ['Destinations', s.top_dst, 'to ']].forEach(([h, list, pre]) => { t.append(el('h3', '', h));
    list.slice(0, 4).forEach(([ip, n]) => { const r = el('div', 'tk', ip); r.append(el('span', '', n.toLocaleString())); r.onclick = () => ask(pre + ip); t.append(r); }); });
}
function ask(q) { $('q').value = q; search(0); }
async function search(o) {
  off = o; $('err').textContent = '';
  try {
    const j = await api(`/api/packets?id=${encodeURIComponent(sid)}&q=${encodeURIComponent($('q').value)}&offset=${o}&limit=${PAGE}`); total = j.total;
    const ch = $('chips'); ch.replaceChildren(); j.filters.forEach(f => ch.append(el('span', 'chip', f)));
    $('count').textContent = `${total.toLocaleString()} matching packets` + (total > PAGE ? ` · showing ${o + 1}–${Math.min(total, o + PAGE)}` : '');
    $('prev').disabled = o === 0; $('next').disabled = o + PAGE >= total;
    const tb = $('rows'); tb.replaceChildren();
    j.rows.forEach(r => { const tr = el('tr'); const a = (ip, p) => ip ? ip + (p ? ':' + p : '') : '–';
      [r.n + 1, r.t.toFixed(6), a(r.src, r.sport), a(r.dst, r.dport), r.proto, r.len, r.info].forEach((v, i) => { const td = el('td', '', v); if (i === 4) { td.className = 'pt'; td.style.color = col(r.proto); } tr.append(td); });
      tr.onclick = () => detail(r.n); tb.append(tr); });
    if (!j.rows.length) { const tr = el('tr'), td = el('td', '', 'No packets match. Try a protocol, an IP address, a port, or a quoted word.'); td.colSpan = 7; tr.append(td); tb.append(tr); }
  } catch (e) { $('err').textContent = e.message; }
}
async function detail(n) {
  try {
    const j = await api(`/api/packet?id=${encodeURIComponent(sid)}&n=${n}`), p = j.p;
    inspectedPacket = p.n;
    $('dt').textContent = `Packet ${p.n + 1} · ${p.proto}`;
    const dl = $('dl'); dl.replaceChildren();
    [['Time', new Date(p.ts * 1000).toISOString()], ['Length', p.len + ' bytes'],
      ['Source', p.src + (p.sport ? ':' + p.sport : '')], ['Destination', p.dst + (p.dport ? ':' + p.dport : '')],
      ['Transport', p.tr], ['TCP flags', p.flags || '–'], ['Info', p.info]]
      .forEach(([k, v]) => dl.append(el('dt', '', k), el('dd', '', v)));
    const layers = $('packet-layers'); layers.replaceChildren();
    for (const layer of j.decoded?.layers || []) {
      const details = el('details', 'packet-layer');
      details.open = true;
      details.append(el('summary', '', layer.name));
      const layerFields = el('dl');
      for (const [key, value] of Object.entries(layer.fields)) {
        layerFields.append(el('dt', '', key), el('dd', '', String(value)));
      }
      details.append(layerFields); layers.append(details);
    }
    $('packet-text').textContent = j.decoded?.payload_text || '(No readable application payload in this packet)';
    $('hex').textContent = j.hex;
    $('packet-limit').textContent = j.captured_bytes < p.len
      ? `Only ${j.captured_bytes.toLocaleString()} of ${p.len.toLocaleString()} original bytes were kept for inspection.`
      : j.inspected_bytes < j.captured_bytes
        ? `Previewing first ${j.inspected_bytes} of ${j.captured_bytes} bytes.` : '';
    $('drawer').hidden = false;
  } catch (e) { $('err').textContent = e.message; }
}

$('drop').onclick = () => $('file').click(); $('drop').addEventListener('keydown', e => { if (e.target === $('drop') && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); $('file').click(); } });
$('file').onchange = e => upload(e.target.files[0]);
['dragover', 'dragleave', 'drop'].forEach(t => $('drop').addEventListener(t, e => { e.preventDefault(); $('drop').classList.toggle('over', t === 'dragover'); if (t === 'drop') upload(e.dataTransfer.files[0]); }));
$('f').onsubmit = e => { e.preventDefault(); search(0); };
$('prev').onclick = () => search(Math.max(0, off - PAGE)); $('next').onclick = () => search(off + PAGE);
$('close').onclick = () => $('drawer').hidden = true; document.addEventListener('keydown', e => { if (e.key === 'Escape') $('drawer').hidden = true; });
$('again').onclick = () => { location.reload(); };
['dns queries', 'tcp syn to port 443', 'http from 10.0.0.5', 'larger than 1000 bytes', 'tcp resets', 'first 20 not tls', 'ping'].forEach(q => { const s = el('span', 'ex', q); s.onclick = () => ask(q); $('ex').append(s); });

// ---- remote capture ----
const post = (u, b) => api(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || {}) });
let live = false, timer = 0, tok = '';
// Browser-local convenience only: never store SSH keys or credentials here.
try {
  const saved = JSON.parse(localStorage.getItem('wirelight-last-ssh') || '{}');
  if (typeof saved.host === 'string') $('host').value = saved.host.slice(0, 253);
  if (typeof saved.user === 'string') $('user').value = saved.user.slice(0, 32);
} catch { /* Storage unavailable or invalid */ }
function saveSSH() {
  try { localStorage.setItem('wirelight-last-ssh', JSON.stringify({host:$('host').value.trim(), user:$('user').value.trim()})); }
  catch { /* Browser storage disabled */ }
}
$('host').addEventListener('input', saveSSH);
$('user').addEventListener('input', saveSSH);
const msg = (t, bad) => { const m = $('rmsg'); m.textContent = t; m.className = bad ? 'bad' : ''; };
const guard = fn => async () => { try { await fn(); } catch (e) { msg(e.message, true); } };
$('t1').onclick = $('t2').onclick = e => { const r = e.target.id === 't2'; $('drop').hidden = r; $('remote').hidden = !r; $('t1').classList.toggle('on', !r); $('t2').classList.toggle('on', r); if (r) guard(loadKeys)(); };
async function loadKeys() {
  const j = await api('/api/keys'), s = $('ksel'), cur = s.value; s.replaceChildren();
  j.keys.forEach(k => { const o = el('option', '', k.name); o.value = k.name; o.dataset.pub = k.pub; o.dataset.fp = k.fp; s.append(o); });
  if ([...s.options].some(o => o.value === cur)) s.value = cur; showKey();
}
function showKey() { const o = $('ksel').selectedOptions[0];
  $('kcmd').value = o ? `echo '${o.dataset.pub}' >> ~/.ssh/authorized_keys` : 'Generate a key first.'; $('kfp').textContent = o ? 'Fingerprint ' + o.dataset.fp : ''; }
$('ksel').onchange = showKey;
$('kgen').onclick = guard(async () => { const n = $('kname').value.trim(); await post('/api/keys', { name: n }); await loadKeys(); $('ksel').value = n; showKey(); msg('Key generated. Run the command above on your server.'); });
$('kdel').onclick = guard(async () => { if (!$('ksel').value || !confirm('Delete this key?')) return; await post('/api/keys/delete', { name: $('ksel').value }); await loadKeys(); });
$('kcopy').onclick = () => navigator.clipboard.writeText($('kcmd').value).then(() => msg('Copied.'), () => { $('kcmd').select(); msg('Press Ctrl+C to copy.'); });
const guardHk = fn => async () => { try { await fn(); } catch (e) {
  if (!/host key/i.test(e.message)) return msg(e.message, true);
  try { const j = await verify(); msg(j.trusted ? 'The stored host key does not match this server. If you expect that (e.g. reinstall), click Forget host and verify again; otherwise do not connect.' : 'This host is not trusted yet. Compare the fingerprint below, click Trust this host, then try again.', j.trusted); } catch (x) { msg(x.message, true); } } };
const conn = () => (saveSSH(), { host: $('host').value.trim(), port: +$('port').value || 22, user: $('user').value.trim(), key: $('ksel').value, sudo: $('sudo').checked });
const verify = async () => { msg('Contacting server…'); const j = await post('/api/ssh/hostkey', conn()); tok = j.token; const h = $('hk'); h.replaceChildren();
  j.fingerprints.forEach(f => h.append(el('div', 'tk', f))); $('trust').hidden = j.trusted;
  msg(j.trusted ? 'Host key already trusted.' : 'Compare with the server (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub), then trust it.'); return j; };
$('verify').onclick = guard(() => verify());
$('trust').onclick = guard(async () => { await post('/api/ssh/trust', { token: tok }); $('trust').hidden = true; msg('Host key trusted.'); });
$('forget').onclick = guard(async () => { await post('/api/ssh/forget', conn()); $('hk').replaceChildren(); msg('Host key removed.'); });
$('ifs').onclick = guardHk(async () => { msg('Connecting…'); const j = await post('/api/ssh/interfaces', conn()), s = $('iface'); s.replaceChildren();
  j.interfaces.forEach(i => { const o = el('option', '', i); o.value = i; s.append(o); }); msg(j.interfaces.length - 1 + ' interfaces found.'); });
$('start').onclick = guardHk(async () => { const j = await post('/api/live/start', { ...conn(), iface: $('iface').value, filter: $('bpf').value.trim(), seconds: +$('secs').value || 300 });
  sid = j.id; live = true; $('remote-download').hidden = false; $('land').hidden = true; $('dash').hidden = false; $('again').hidden = false; $('stop').hidden = false; $('q').value = '';
  resetAI(); $('fname').textContent = `● Live · ${$('user').value}@${$('host').value} · ${$('iface').value}`; timer = setInterval(poll, 2000); poll(); });
async function poll() { try { const j = await api('/api/live/status?id=' + encodeURIComponent(sid)); summary(j.stats); await search(off);
  if (!j.running) { clearInterval(timer); live = false; $('stop').hidden = true; $('fname').textContent += j.error ? ' · stopped: ' + j.error : ' · finished'; }
  } catch (e) { clearInterval(timer); $('fname').textContent = e.message; } }
$('stop').onclick = () => post('/api/live/stop', { id: sid });
$('remote-download').onclick = async () => {
  if (!sid) return;
  const button = $('remote-download'); button.disabled = true;
  try {
    const url = `/api/live/download?id=${encodeURIComponent(sid)}`;
    // Navigation download avoids buffering the complete PCAP in JavaScript.
    const req = await fetch(url, {headers:{'X-Requested-With':'wirelight'}});
    if (!req.ok) { const body = await req.json(); throw new Error(body.error || 'Download failed'); }
    // Browser fetch uses a Blob; remote PCAPs are capped server-side to bound memory.
    const blob = await req.blob();
    const address = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = address;
    link.download = `wirelight-remote-${new Date().toISOString().replace(/[:.]/g, '-')}.pcap`;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(address), 10000);
  } catch (e) { alert(e.message); } finally { button.disabled = false; }
};
$('again').onclick = async () => { if (live) await post('/api/live/stop', { id: sid }).catch(() => {}); location.reload(); };

// ---- AI (Mistral cloud or local LM Studio): user-initiated requests only ----
function updatePacketAttachment() {
  const selected = attachedPacket !== null;
  $('ai-packet-attachment').hidden = !selected;
  $('ai-packet-label').textContent = selected
    ? `Packet #${attachedPacket + 1} attached · headers and up to 512 ASCII payload characters will be shared with the AI when you ask.` : '';
}
$('ai-packet-clear').onclick = () => { attachedPacket = null; updatePacketAttachment(); };
$('packet-ask').onclick = () => {
  if (inspectedPacket === null) return;
  attachedPacket = inspectedPacket; updatePacketAttachment();
  $('drawer').hidden = true;
  $('ai-question').value = `Explain packet #${attachedPacket + 1}. What do its headers and readable payload tell us?`;
  $('ai-question').focus();
  $('ai-section').scrollIntoView({behavior:'smooth', block:'start'});
};
let aiReport = null, aiBusy = false, aiAvailable = false, aiProvider = 'mistral';
const aiStatus = (message, error = false) => { $('ai-status').textContent = message; $('ai-status').className = error ? 'bad' : ''; };
function setAIWorking(busy) {
  aiBusy = busy;
  $('ai-run').disabled = busy || !aiAvailable;
  $('ai-ask').disabled = busy || !aiAvailable;
  $('ai-question').disabled = busy || !aiAvailable;
}
function resetAI() {
  aiReport = null;
  $('ai-result').hidden = true; $('ai-json').disabled = true; $('ai-md').disabled = true;
  $('ai-chat').replaceChildren(el('p', 'hint', 'No AI requests have been sent. Ask a question about the loaded capture.'));
  $('ai-question').value = ''; attachedPacket = null; inspectedPacket = null; updatePacketAttachment();
  setAIWorking(false);
  aiStatus('Ready. No AI analysis runs automatically.');
}
async function aiConfiguration() {
  try { const c = await api('/api/ai/config');
    aiProvider = c.provider;
    const provider = c.provider === 'mistral' ? 'Mistral AI (cloud)' : 'LM Studio (local)';
    if (!c.enabled) $('ai-config').textContent = 'AI disabled by server administrator.';
    else if (!c.configured) $('ai-config').textContent = 'Mistral AI is selected, but MISTRAL_API_KEY is not set. Configure your .env file and recreate the container. Mistral API access may require billing activation.';
    else $('ai-config').textContent = `${provider} · model: ${c.model} · timeout: ${c.timeout_seconds}s · ${c.provider === 'mistral' ? 'Your questions and aggregated traffic metadata are sent to Mistral AI. Packet text is sent only when you explicitly attach a packet.' : 'Aggregates and any explicitly selected packet previews are sent to the configured local server.'}`;
    aiAvailable = !!c.enabled && !!c.configured;
    setAIWorking(aiBusy);
  } catch (e) { aiAvailable = false; $('ai-config').textContent = 'AI configuration unavailable: ' + e.message; setAIWorking(false); }
}
// Render Markdown returned by AI without trusting the generated HTML. Markdown is
// parsed by the bundled (offline) Marked library; only explicitly allowed HTML
// elements are recreated as fresh DOM nodes. No event handlers or styles survive.
const MD_TAGS = new Set([
  'P', 'BR', 'STRONG', 'B', 'EM', 'I', 'DEL', 'S', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6',
  'UL', 'OL', 'LI', 'BLOCKQUOTE', 'PRE', 'CODE', 'HR', 'A', 'TABLE', 'THEAD',
  'TBODY', 'TR', 'TH', 'TD'
]);
const MD_DROP = new Set(['SCRIPT', 'STYLE', 'SVG', 'MATH', 'IFRAME', 'OBJECT', 'EMBED',
  'FORM', 'INPUT', 'BUTTON', 'VIDEO', 'AUDIO', 'IMG', 'PICTURE', 'TEMPLATE']);
const escapeMarkdownHTML = text => String(text).replace(/&/g, '&amp;')
  .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
function appendSafeMarkdownNode(parent, node) {
  if (node.nodeType === Node.TEXT_NODE) { parent.append(document.createTextNode(node.textContent)); return; }
  if (node.nodeType !== Node.ELEMENT_NODE) return;
  const tag = node.tagName.toUpperCase();
  if (MD_DROP.has(tag)) return;
  if (!MD_TAGS.has(tag)) {
    for (const child of Array.from(node.childNodes)) appendSafeMarkdownNode(parent, child);
    return;
  }
  const safe = document.createElement(tag.toLowerCase());
  if (tag === 'A') {
    const href = (node.getAttribute('href') || '').trim();
    // Only explicitly written HTTPS/HTTP links are clickable. Prevent javascript:,
    // data:, protocol-relative links, and escape sequences from becoming URLs.
    if (!/^https?:\/\//i.test(href)) {
      for (const child of Array.from(node.childNodes)) appendSafeMarkdownNode(parent, child);
      return;
    }
    try {
      const target = new URL(href);
      if (!['https:', 'http:'].includes(target.protocol)) return;
      safe.href = target.href;
      safe.target = '_blank';
      safe.rel = 'noopener noreferrer nofollow';
    } catch { return; }
  }
  for (const child of Array.from(node.childNodes)) appendSafeMarkdownNode(safe, child);
  parent.append(safe);
}
function renderMarkdown(parent, message) {
  if (typeof marked === 'undefined' || typeof marked.parse !== 'function') {
    parent.append(el('p', '', message));
    return;
  }
  const renderer = new marked.Renderer();
  // Ignore model-provided HTML and remote images; AI answers are text/Markdown.
  renderer.html = raw => escapeMarkdownHTML(raw);
  renderer.image = (_href, _title, alt) => escapeMarkdownHTML(alt);
  const html = marked.parse(String(message), {
    renderer, gfm: true, breaks: true, mangle: false, headerIds: false
  });
  const template = document.createElement('template');
  template.innerHTML = html;
  for (const child of Array.from(template.content.childNodes)) appendSafeMarkdownNode(parent, child);
}
function addChatMessage(role, message) {
  const chat = $('ai-chat');
  if (chat.firstElementChild?.classList.contains('hint')) chat.replaceChildren();
  const bubble = el('div', 'ai-message ' + role);
  const body = el('div', 'ai-message-body');
  if (role === 'assistant') renderMarkdown(body, message);
  else body.append(el('p', '', message));
  bubble.append(el('strong', 'ai-message-role', role === 'user' ? 'You' : 'AI'), body);
  chat.append(bubble);
  chat.scrollTop = chat.scrollHeight;
}
async function askAI(event) {
  event.preventDefault();
  const question = $('ai-question').value.trim();
  if (!sid || !question || aiBusy || !aiAvailable) return;
  $('ai-question').value = '';
  addChatMessage('user', question);
  setAIWorking(true);
  aiStatus(aiProvider === 'mistral' ? 'Asking Mistral AI…' : 'Waiting for local LM Studio model…');
  try {
    const j = await post('/api/ai/ask', { id: sid, question, packet_numbers: attachedPacket === null ? [] : [attachedPacket] });
    addChatMessage('assistant', j.answer);
    aiStatus(`Answer based on ${j.packet_count.toLocaleString()} packets of traffic metadata${attachedPacket === null ? '' : ` and selected packet #${attachedPacket + 1}`}. AI conclusions are not proof of an incident.`);
  } catch (e) {
    $('ai-question').value = question;
    aiStatus('Could not get AI answer: ' + e.message, true);
  } finally { setAIWorking(false); $('ai-question').focus(); }
}
function aiText(parent, tag, value, className='') { const n = el(tag, className, value); parent.append(n); return n; }
function renderAI(report) {
  aiReport = report; $('ai-result').hidden = false; $('ai-json').disabled = false; $('ai-md').disabled = false;
  const overview = $('ai-overview'); overview.replaceChildren();
  aiText(overview, 'strong', `Assessment confidence: ${report.confidence || 'low'}`);
  aiText(overview, 'p', report.summary || 'No summary provided.');
  const grid = $('ai-findings'); grid.replaceChildren();
  const names = { normal:'Normal business activity', suspicious:'Suspicious / anomalous behavior', attack:'Potential attacks', vulnerability:'Possible vulnerabilities' };
  for (const [category, title] of Object.entries(names)) {
    const box = aiText(grid, 'div', '', 'ai-group ' + category);
    aiText(box, 'h3', title);
    const findings = (report.findings || []).filter(x => x.category === category);
    if (!findings.length) aiText(box, 'p', 'No supported findings in this category.', 'ai-empty');
    for (const f of findings) {
      const item = aiText(box, 'div', '', 'ai-item');
      aiText(item, 'strong', f.title);
      aiText(item, 'span', (f.severity || 'info') + ' · AI assessment', 'ai-severity');
      aiText(item, 'p', f.detail);
      if (f.evidence && f.evidence.length) aiText(item, 'small', 'Evidence: ' + f.evidence.join(' · '));
      if (f.recommendation) aiText(item, 'p', 'Next action: ' + f.recommendation);
    }
  }
  $('ai-narrative').textContent = report.narrative || 'No further incident narrative.';
  const steps = $('ai-steps'); steps.replaceChildren();
  for (const step of report.next_steps || []) aiText(steps, 'li', step);
  const l = $('ai-limits'); l.replaceChildren();
  aiText(l, 'p', `${report.assessment_type || 'AI-assisted assessment'} · ${report.generated_utc} · model: ${report.model}`);
  for (const limitation of report.limitations || []) aiText(l, 'p', '• ' + limitation);
  aiText(l, 'p', `Observed packets: ${report.evidence?.packet_count ?? '?'} · duration: ${report.evidence?.duration_seconds ?? '?'} seconds`);
}
async function runAI() {
  if (!sid || aiBusy || !aiAvailable) return;
  setAIWorking(true); aiStatus(aiProvider === 'mistral' ? 'Generating optional report through Mistral AI…' : 'Generating optional report through LM Studio…');
  try {
    const j = await post('/api/ai/analyze', { id: sid });
    if (!j.report) throw new Error('No assessment returned');
    renderAI(j.report);
    aiStatus(`Report completed · ${j.report.evidence.packet_count.toLocaleString()} packets analyzed · ${j.report.generated_utc}`);
  } catch (e) { aiStatus('Could not generate report: ' + e.message + '. Packet dashboard remains functional.', true); }
  finally { setAIWorking(false); }
}
function downloadAI(filename, content, type) {
  const blob = new Blob([content], {type}); const u = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = u; a.download = filename; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(u), 2000);
}
function markdownReport(r) {
  const safe = s => String(s || '').replace(/[\r\n]+/g, ' ').replace(/[<>]/g, '');
  const lines = ['# Wirelight — AI-assisted network assessment', '', `Generated: ${safe(r.generated_utc)}`,
    `Model: ${safe(r.model)}`, `Confidence: ${safe(r.confidence)}`, `Packet count: ${r.evidence.packet_count}`,
    '', '## Executive summary', '', safe(r.summary), '', '## Notes / Findings', ''];
  const names = {normal:'Normal business activity',suspicious:'Suspicious / anomalous behavior',attack:'Potential attacks',vulnerability:'Possible vulnerabilities'};
  for (const [category,title] of Object.entries(names)) {
    lines.push(`### ${title}`, '');
    const fs = r.findings.filter(f => f.category === category);
    if (!fs.length) lines.push('No supported findings.', '');
    for (const f of fs) lines.push(`**${safe(f.title)}** (${safe(f.severity)})`, '', safe(f.detail), '',
      `Evidence: ${safe((f.evidence || []).join('; '))}`, '', `Recommendation: ${safe(f.recommendation)}`, '');
  }
  lines.push('## Incident narrative', '', safe(r.narrative), '', '## Next steps', '', ...r.next_steps.map(x=>'- '+safe(x)),
    '', '## Limitations', '', ...r.limitations.map(x=>'- '+safe(x)), '',
    '## Evidence aggregates (metadata only)', '', '```json', JSON.stringify(r.evidence, null, 2), '```', '');
  return lines.join('\n');
}
$('ai-run').onclick = runAI;
$('ai-form').addEventListener('submit', askAI);
$('ai-json').onclick = () => aiReport && downloadAI('wirelight-assessment.json', JSON.stringify(aiReport, null, 2), 'application/json');
$('ai-md').onclick = () => aiReport && downloadAI('wirelight-assessment.md', markdownReport(aiReport), 'text/markdown');
aiConfiguration();
