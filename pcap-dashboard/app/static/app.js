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
    sid = j.id; $('fname').textContent = f.name;
    $('land').hidden = true; $('dash').hidden = false; $('again').hidden = false;
    $('remote-download').hidden = true; summary(j.stats); clearFilters(false); search(0); resetAI();
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
let searchToken = 0, searchTimer = 0;
function clearFilters(run = true) {
  $('q').value = ''; $('filter-proto').value = ''; $('filter-port').value = '';
  if (run) search(0);
}
function delayedSearch() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => search(0), 450);
}
async function search(o) {
  if (!sid) return;
  const token = ++searchToken;
  off = o; $('err').textContent = '';
  $('count').textContent = 'Filtering packets…';
  const url = new URLSearchParams({id:sid, q:$('q').value, proto:$('filter-proto').value,
    port:$('filter-port').value, offset:String(o), limit:String(PAGE)});
  try {
    const j = await api(`/api/packets?${url}`);
    if (token !== searchToken) return; // Don't let slow queries overwrite newer results.
    total = j.total;
    const ch = $('chips'); ch.replaceChildren();
    j.filters.forEach(f => ch.append(el('span', 'chip', f)));
    if ($('filter-proto').value) ch.append(el('span','chip',`protocol: ${$('filter-proto').value}`));
    if ($('filter-port').value) ch.append(el('span','chip',`port: ${$('filter-port').value}`));
    $('count').textContent = `${total.toLocaleString()} matching packets` + (total > 0 ? ` · showing ${o + 1}–${Math.min(total, o + PAGE)}` : '');
    $('prev').disabled = o === 0; $('next').disabled = o + PAGE >= total;
    const tb = $('rows'); tb.replaceChildren();
    j.rows.forEach(r => { const tr = el('tr'); const a = (ip, p) => ip ? ip + (p ? ':' + p : '') : '–';
      [r.n + 1, r.t.toFixed(6), a(r.src, r.sport), a(r.dst, r.dport), r.proto, r.len, r.info].forEach((v, i) => { const td = el('td', '', v); if (i === 4) { td.className = 'pt'; td.style.color = col(r.proto); } tr.append(td); });
      if (hostLabelText(r.src)) tr.children[2].title = hostLabelText(r.src);
      if (hostLabelText(r.dst)) tr.children[3].title = hostLabelText(r.dst);
      tr.onclick = () => detail(r.n); tb.append(tr); });
    if (!j.rows.length) { const tr = el('tr'), td = el('td', '', 'No matching packets. Try clearing filters, entering an IP, or selecting a protocol.'); td.colSpan = 7; tr.append(td); tb.append(tr); }
  } catch (e) { if (token === searchToken) { $('err').textContent = e.message; $('count').textContent = 'Search failed'; } }
}
async function detail(n) {
  try {
    const j = await api(`/api/packet?id=${encodeURIComponent(sid)}&n=${n}`), p = j.p;
    inspectedPacket = p.n;
    $('dt').textContent = `Packet ${p.n + 1} · ${p.proto}`;
    const dl = $('dl'); dl.replaceChildren();
    [['Time', new Date(p.ts * 1000).toISOString()], ['Length', p.len + ' bytes'],
      ['Source', p.src + (p.sport ? ':' + p.sport : '')], ['Destination', p.dst + (p.dport ? ':' + p.dport : '')],
      ...(hostLabelText(p.src) ? [['Source role', hostLabelText(p.src)]] : []),
      ...(hostLabelText(p.dst) ? [['Destination role', hostLabelText(p.dst)]] : []),
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
$('f').onsubmit = e => { e.preventDefault(); clearTimeout(searchTimer); search(0); };
$('q').addEventListener('input', delayedSearch);
$('filter-proto').addEventListener('change', () => search(0));
$('filter-port').addEventListener('input', delayedSearch);
$('search-clear').onclick = () => { clearTimeout(searchTimer); clearFilters(); $('q').focus(); };
$('q').addEventListener('keydown', e => { if (e.key === 'Escape') { e.preventDefault(); clearFilters(); } });
$('prev').onclick = () => search(Math.max(0, off - PAGE)); $('next').onclick = () => search(off + PAGE);
$('close').onclick = () => $('drawer').hidden = true; document.addEventListener('keydown', e => { if (e.key === 'Escape') $('drawer').hidden = true; });
$('again').onclick = () => { location.reload(); };
['dns queries', 'tcp syn to port 443', 'http from 10.0.0.5', 'larger than 1000 bytes', 'tcp resets', 'first 20 not tls', 'ping'].forEach(q => { const s = el('span', 'ex', q); s.onclick = () => ask(q); $('ex').append(s); });

// ---- user-triggered, persistent Nmap inventory ----
function selectedMapIds() { return [...$('map-context').querySelectorAll('input:checked')].map(c => c.value); }
let networkHostRoles = {}, hostLabelRevision = 0;
async function refreshHostLabels() {
  const revision = ++hostLabelRevision;
  const maps = await Promise.all(selectedMapIds().map(id => api(`/api/maps/detail?id=${encodeURIComponent(id)}`)));
  if (revision !== hostLabelRevision) return;
  networkHostRoles = {};
  for (const {map} of maps) Object.assign(networkHostRoles, map.labels);
  if (sid) search(off); // update host-label tooltips in the displayed PCAP table
  // The inventory is never used to silently override observed packet endpoints.
}
function hostLabelText(ip) {
  const label = networkHostRoles[ip];
  return label ? `${label.role}${label.notes ? ' — ' + label.notes : ''} (operator label)` : '';
}
let mapCache = [], currentMap = '', mapTimer = null, showingMaps = false;
const mapRoles = ['unknown', 'physical server', 'virtual machine', 'lxc container',
  'docker host', 'docker container', 'reverse proxy', 'router', 'firewall',
  'database server', 'application server', 'other'];
for (const name of mapRoles) { const option = el('option', '', name); option.value = name; $('map-manual-role').append(option); }
$('map-manual-host').onsubmit = async event => {
  event.preventDefault(); if (!currentMap) return;
  try {
    const ip = $('map-manual-ip').value.trim();
    await post('/api/maps/host', { id: currentMap, ip, role: $('map-manual-role').value, notes: $('map-manual-notes').value });
    $('map-manual-ip').value = ''; $('map-manual-notes').value = '';
    await loadMapDetail();
    await refreshHostLabels();
    mapNotice(`Saved operator label for ${ip}; it will survive rescans.`);
  } catch (err) { mapNotice(err.message, true); }
};
function mapNotice(text, bad=false) {
  const out = $('maps-message'); out.textContent = text; out.className = bad ? 'bad' : '';
}
function mapScanNotice(text, bad=false) {
  $('map-status').textContent = text; $('map-status').className = bad ? 'bad' : 'hint';
}
function showMapPanel(open) {
  showingMaps = open;
  $('mapper').hidden = !open;
  $('land').hidden = open || !!sid;
  $('dash').hidden = open || !sid;
  $('map-open').hidden = open;
  if (open) { loadMaps().catch(e => mapNotice(e.message, true)); window.scrollTo(0, 0); }
  else window.scrollTo(0, 0);
}
$('map-open').onclick = $('map-manage').onclick = () => showMapPanel(true);
$('maps-back').onclick = () => showMapPanel(false);
async function loadMaps(prefer) {
  const result = await api('/api/maps');
  mapCache = result.maps;
  const combo = $('map-list');
  const last = prefer !== undefined ? prefer : (currentMap || combo.value);
  combo.replaceChildren(el('option', '', 'Select a saved map'));
  combo.options[0].value = '';
  for (const map of mapCache) { const option = el('option', '', `${map.name} · ${map.subnet}`); option.value = map.id; combo.append(option); }
  combo.value = mapCache.some(m => m.id === last) ? last : '';
  currentMap = combo.value;
  const aiSelect = $('map-context'), selected = new Set(selectedMapIds());
  aiSelect.replaceChildren();
  if (!mapCache.length) aiSelect.append(el('span', 'hint', 'No saved maps yet — PCAP only'));
  for (const map of mapCache) {
    const label = el('label', 'map-check'), checkbox = document.createElement('input');
    checkbox.type = 'checkbox'; checkbox.value = map.id;
    checkbox.checked = selected.has(map.id);
    checkbox.onchange = () => {
      if (selectedMapIds().length > 4) {
        checkbox.checked = false; alert('Select at most four network maps per analysis.');
      }
      refreshHostLabels().catch(() => {});
    };
    label.append(checkbox, document.createTextNode(` ${map.name} (${map.subnet})`)); aiSelect.append(label);
  }
  refreshHostLabels().catch(() => {});
  if (currentMap) await loadMapDetail();
  else { $('map-detail').hidden = true; $('map-host-panel').hidden = true; }
}
$('map-list').onchange = async () => { currentMap = $('map-list').value; try {
  if (currentMap) await loadMapDetail();
  else { $('map-detail').hidden = true; $('map-host-panel').hidden = true; }
} catch(e) { mapNotice(e.message, true); } };
$('map-create').onsubmit = async e => {
  e.preventDefault();
  try {
    const j = await post('/api/maps/create', { name: $('map-new-name').value, subnet: $('map-new-subnet').value, notes: $('map-new-notes').value });
    $('map-new-name').value = ''; $('map-new-subnet').value = ''; $('map-new-notes').value = '';
    await loadMaps(j.map.id); mapNotice('Map saved. Click Scan / Rescan to run Nmap (no automatic scanning).');
  } catch (err) { mapNotice(err.message, true); }
};
$('map-edit').onsubmit = async e => { e.preventDefault(); if (!currentMap) return;
  try { await post('/api/maps/update', { id:currentMap, name:$('map-edit-name').value, notes:$('map-edit-notes').value });
    await loadMaps(currentMap); mapNotice('Map description updated.'); }
  catch(err) { mapNotice(err.message, true); }
};
$('map-use').onclick = () => { if (!currentMap) return;
  if (!sid) { mapNotice('Map selected; open a PCAP or remote capture, then choose it in Network inventory context.'); return; }
  const selected = [...$('map-context').querySelectorAll('input:checked')];
  if (!selected.some(c => c.value === currentMap) && selected.length >= 4) {
    mapNotice('Uncheck another map first (four-map limit).', true); return;
  }
  const checkbox = [...$('map-context').querySelectorAll('input')].find(c => c.value === currentMap);
  if (checkbox) checkbox.checked = true;
  refreshHostLabels().catch(() => {});
  mapNotice('Map selected for AI questions and reports on the loaded capture.'); showMapPanel(false);
};
$('map-delete').onclick = async () => { if (!currentMap || !confirm('Permanently delete this saved map and its manual host labels?')) return;
  try { await post('/api/maps/delete', {id: currentMap}); currentMap = ''; await loadMaps(''); mapNotice('Saved map deleted.'); }
  catch(e) { mapNotice(e.message, true); }
};
function hostRow(ip, info, label) {
  const box = el('div', 'map-host'); const head = el('div', 'map-host-head');
  head.append(el('code', '', ip)); head.append(el('span', 'hint', info ? `Nmap: ${info.state}` : 'Not found in latest scan · label retained'));
  box.append(head);
  if (info) {
    const desc = [info.hostnames?.join(', '), info.mac, ...info.ports.map(p => `${p.port}/${p.protocol} ${p.service} ${p.product} ${p.version}`)].filter(Boolean).join(' · ');
    box.append(el('p', 'map-host-ports', desc || 'No open ports identified'));
  }
  const row = el('div', 'map-host-controls'), role = el('select'), notes = el('input'), save = el('button', '', 'Save label');
  notes.placeholder = 'Host notes (e.g. nested Docker/LXC)'; notes.maxLength = 400;
  for (const r of mapRoles) { const opt = el('option', '', r); opt.value = r; role.append(opt); }
  role.value = label?.role || 'unknown'; notes.value = label?.notes || '';
  save.onclick = async () => { save.disabled = true; try {
    await post('/api/maps/host', {id:currentMap, ip, role:role.value, notes:notes.value});
    mapNotice(`Saved role for ${ip}. This is operator-supplied context, not Nmap proof.`);
  } catch(e) { mapNotice(e.message, true); } finally {save.disabled = false;} };
  row.append(role, notes, save); box.append(row); return box;
}
async function loadMapDetail() {
  const id = currentMap;
  const res = await api(`/api/maps/detail?id=${encodeURIComponent(id)}`);
  if (currentMap !== id) return;
  const m = res.map; $('map-detail').hidden = false; $('map-host-panel').hidden = false;
  $('map-edit-name').value = m.name; $('map-edit-notes').value = m.notes;
  $('map-pn').checked = !!m.skip_discovery;
  $('map-meta').textContent = `${m.subnet} · last scanned: ${m.scanned_at || 'never'} · ${m.scan_count} scan(s) · ${m.hosts.length} host(s) in last result`;
  const hosts = $('map-hosts'); hosts.replaceChildren();
  const added = new Set();
  for (const h of m.hosts) { hosts.append(hostRow(h.ip, h, m.labels[h.ip])); added.add(h.ip); }
  for (const [ip, label] of Object.entries(m.labels)) if (!added.has(ip)) hosts.append(hostRow(ip, null, label));
  if (!hosts.childNodes.length) hosts.append(el('p', 'hint', 'No hosts found yet. Scan the subnet to discover devices. You can then label them for AI context.'));
  await checkMapScan(id);
}
async function checkMapScan(id) {
  const j = await api(`/api/maps/status?id=${encodeURIComponent(id)}`);
  if (currentMap !== id) return;
  const running = j.status === 'running';
  $('map-scan').disabled = running;
  mapScanNotice(running ? `Scanning… started ${j.started_at}. Results will be saved when complete.` :
    j.status === 'failed' ? `Scan failed: ${j.error} (previous results preserved)` :
    j.status === 'completed' ? `Scan complete: ${j.host_count} hosts found.` :
    'Ready. Scans run only when you click Scan / Rescan.', j.status === 'failed');
  if (running) {
    clearTimeout(mapTimer);
    mapTimer = setTimeout(async () => {
      try {
        const now = await api(`/api/maps/status?id=${encodeURIComponent(id)}`);
        if (currentMap !== id) return;
        if (now.status === 'running') await checkMapScan(id);
        else { await loadMaps(id); if (now.status === 'completed') mapNotice('Nmap scan finished; saved inventory updated.'); }
      } catch(e) { mapNotice(e.message, true); }
    }, 2500);
  }
}
$('map-scan').onclick = async () => { if (!currentMap) return;
  const id = currentMap;
  $('map-scan').disabled = true;
  try { await post('/api/maps/scan', {id, skip_discovery: $('map-pn').checked});
    mapScanNotice('Starting Nmap scan…'); await checkMapScan(id);
  } catch(e) { mapScanNotice(e.message, true); $('map-scan').disabled = false; }
};
// Maps remain opt-in on every AI request, including generated reports.
loadMaps().catch(() => { /* Network mapping may be unavailable, PCAP viewer continues working. */ });

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
  sid = j.id; live = true; $('remote-download').hidden = false; $('land').hidden = true; $('dash').hidden = false; $('again').hidden = false; $('stop').hidden = false; clearFilters(false);
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
    ? `Packet #${attachedPacket + 1} attached for extra inspection (up to 1600 plaintext characters). Other representative packets are now included automatically.` : '';
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
    else $('ai-config').textContent = `${provider} · model: ${c.model} · timeout: ${c.timeout_seconds}s · ${c.provider === 'mistral' ? `Questions, correlated traffic indicators and up to ${c.context_settings?.max_samples ?? 72} representative packet samples (including plaintext payload excerpts) are sent to Mistral. Large captures are summarized, not transferred wholesale.` : `Correlated indicators and up to ${c.context_settings?.max_samples ?? 72} decoded packet samples are shared with the local model.`}`;
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
    const j = await post('/api/ai/ask', { id: sid, map_ids: selectedMapIds(), question, packet_numbers: attachedPacket === null ? [] : [attachedPacket] });
    addChatMessage('assistant', j.answer);
    aiStatus(`Answer${j.context_scope?.selected_network_maps?.length ? ` + maps: ${j.context_scope.selected_network_maps.join(', ')}` : ''} used statistics across ${j.packet_count.toLocaleString()} packets and ${j.context_scope?.sampled_packets ?? 0} decoded packet samples${attachedPacket === null ? '' : ` plus selected packet #${attachedPacket + 1}`}. Conclusions require corroboration.`);
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
    const j = await post('/api/ai/analyze', { id: sid, map_ids: selectedMapIds() });
    if (!j.report) throw new Error('No assessment returned');
    renderAI(j.report);
    aiStatus(`Report completed${j.context_scope?.selected_network_maps?.length ? ` · maps: ${j.context_scope.selected_network_maps.join(', ')}` : ''} · ${j.report.evidence.packet_count.toLocaleString()} packet records correlated · ${j.context_scope?.sampled_packets ?? 0} packet examples sent · ${j.report.generated_utc}`);
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
    '## Capture evidence (aggregates, correlations, representative packet excerpts)', '', '```json', JSON.stringify(r.evidence, null, 2), '```', '');
  return lines.join('\n');
}
$('ai-run').onclick = runAI;
$('ai-form').addEventListener('submit', askAI);
$('ai-json').onclick = () => aiReport && downloadAI('wirelight-assessment.json', JSON.stringify(aiReport, null, 2), 'application/json');
$('ai-md').onclick = () => aiReport && downloadAI('wirelight-assessment.md', markdownReport(aiReport), 'text/markdown');
aiConfiguration();
