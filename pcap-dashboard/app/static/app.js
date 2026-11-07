'use strict';
const $ = id => document.getElementById(id), COL = {TCP:'#6c8ef5',UDP:'#4fc4b0',DNS:'#e8b04a',HTTP:'#e07a8c',TLS:'#a98be0',ICMP:'#7fcf6b',ARP:'#d99a5b',ICMPv6:'#7fcf6b',Other:'#8c96ab'};
const col = p => COL[p] || COL.Other, PAGE = 100;
let sid = '', off = 0, total = 0;
function el(t, c, x) { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; }
const fmtB = n => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB';
const api = async (u, o = {}) => { o.headers = { 'X-Requested-With': 'wirelight', ...o.headers }; const r = await fetch(u, o), j = await r.json(); if (!r.ok) throw new Error(j.error || 'Request failed'); return j; };

async function upload(f) {
  $('err').textContent = ''; if (!f) return;
  $('drop').firstElementChild.textContent = 'Reading ' + f.name + '…';
  try {
    const j = await api('/api/upload', { method: 'POST', body: f, headers: { 'Content-Type': 'application/octet-stream' } });
    sid = j.id; $('fname').textContent = f.name + (j.truncated ? ' (first 100,000 packets)' : '');
    $('land').hidden = true; $('dash').hidden = false; $('again').hidden = false; summary(j.stats); $('q').value = ''; search(0);
  } catch (e) { $('err').textContent = e.message; $('drop').firstElementChild.textContent = 'Ask your packet capture a question.'; }
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
    $('dt').textContent = `Packet ${p.n + 1} · ${p.proto}`; const dl = $('dl'); dl.replaceChildren();
    [['Time', new Date(p.ts * 1000).toISOString()], ['Length', p.len + ' bytes'], ['Source', p.src + (p.sport ? ':' + p.sport : '')], ['Destination', p.dst + (p.dport ? ':' + p.dport : '')], ['Transport', p.tr], ['TCP flags', p.flags || '–'], ['Info', p.info]]
      .forEach(([k, v]) => dl.append(el('dt', '', k), el('dd', '', v)));
    $('hex').textContent = j.hex; $('drawer').hidden = false;
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
const conn = () => ({ host: $('host').value.trim(), port: +$('port').value || 22, user: $('user').value.trim(), key: $('ksel').value, sudo: $('sudo').checked });
const verify = async () => { msg('Contacting server…'); const j = await post('/api/ssh/hostkey', conn()); tok = j.token; const h = $('hk'); h.replaceChildren();
  j.fingerprints.forEach(f => h.append(el('div', 'tk', f))); $('trust').hidden = j.trusted;
  msg(j.trusted ? 'Host key already trusted.' : 'Compare with the server (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub), then trust it.'); return j; };
$('verify').onclick = guard(() => verify());
$('trust').onclick = guard(async () => { await post('/api/ssh/trust', { token: tok }); $('trust').hidden = true; msg('Host key trusted.'); });
$('forget').onclick = guard(async () => { await post('/api/ssh/forget', conn()); $('hk').replaceChildren(); msg('Host key removed.'); });
$('ifs').onclick = guardHk(async () => { msg('Connecting…'); const j = await post('/api/ssh/interfaces', conn()), s = $('iface'); s.replaceChildren();
  j.interfaces.forEach(i => { const o = el('option', '', i); o.value = i; s.append(o); }); msg(j.interfaces.length - 1 + ' interfaces found.'); });
$('start').onclick = guardHk(async () => { const j = await post('/api/live/start', { ...conn(), iface: $('iface').value, filter: $('bpf').value.trim(), seconds: +$('secs').value || 300 });
  sid = j.id; live = true; $('land').hidden = true; $('dash').hidden = false; $('again').hidden = false; $('stop').hidden = false; $('q').value = '';
  $('fname').textContent = `● Live · ${$('user').value}@${$('host').value} · ${$('iface').value}`; timer = setInterval(poll, 2000); poll(); });
async function poll() { try { const j = await api('/api/live/status?id=' + encodeURIComponent(sid)); summary(j.stats); await search(off);
  if (!j.running) { clearInterval(timer); live = false; $('stop').hidden = true; $('fname').textContent += j.error ? ' · stopped: ' + j.error : ' · finished'; }
  } catch (e) { clearInterval(timer); $('fname').textContent = e.message; } }
$('stop').onclick = () => post('/api/live/stop', { id: sid });
$('again').onclick = async () => { if (live) await post('/api/live/stop', { id: sid }).catch(() => {}); location.reload(); };
