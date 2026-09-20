/**
 * 界面。
 *
 * ★★ 它**只是后端 API 的一个客户端**，和 AI 平起平坐（docs/设计.md「AI 接口」）。
 *   页面上每一个按钮，背后都是调同一个工具 —— 不许在这里算任何东西。
 *   这样「不许有只存在于 API 的能力」是结构上的必然，而不是一条要人记住的规矩。
 */
let API = '';

/** 调一个工具。返回 {ok, verdict, values, note, error} 的统一形状。 */
async function call(tool, args = {}) {
  const r = await fetch(`${API}/tools/${tool}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  });
  const body = await r.json().catch(() => ({}));
  if (body && body.error) return { ok: false, error: body.error, message: body.message || '' };
  /*
   * ★ 工具有两种返回形状，按规范都合法：
   *     判定 {verdict, values, note}   —— 判断出某个状态（ping、探端口…）
   *     清单 {interfaces: [...]}       —— 列一堆东西（网卡、邻居、默认参数…）
   *   界面两种都要认。早先这里只认第一种，于是"网卡列表"整页是空的：
   *   数据明明取回来了（24 块网卡），却被丢在 values 之外 —— 页面不报错，就是空白。
   */
  return {
    ok: true,
    verdict: body.verdict,
    values: body.values || body,
    note: body.note || '',
    raw: body,
  };
}

const $ = (h) => { const d = document.createElement('div'); d.innerHTML = h.trim(); return d.firstElementChild; };
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// ── 页面 ──

const PAGES = [
  { id: 'nic', name: '本机网络', render: renderNIC },
  { id: 'dhcp', name: '开启路由（DHCP）', render: renderDHCP },
  { id: 'probe', name: '连通性', render: renderProbe },
  { id: 'stream', name: '视频流', render: renderStream },
];

let current = 'nic';

function renderNav() {
  const nav = document.getElementById('nav');
  nav.innerHTML = '';
  for (const p of PAGES) {
    const b = document.createElement('button');
    b.textContent = p.name;
    b.className = p.id === current ? 'on' : '';
    b.onclick = () => { current = p.id; renderNav(); show(); };
    nav.appendChild(b);
  }
}

async function show() {
  const main = document.getElementById('main');
  main.innerHTML = '<div class="empty">读取中…</div>';
  const p = PAGES.find((x) => x.id === current);
  main.innerHTML = '';
  await p.render(main);
}

// ── 本机网络 ──

async function renderNIC(root) {
  const r = await call('net.interfaces');
  if (!r.ok) { root.appendChild($(`<div class="card">读取失败：${esc(r.message)}</div>`)); return; }
  // ★ 判定码由界面翻成人话 —— 后端只给码，不给句子（多语种就靠这条）
  const LABEL = {
    'dual-stack': ['双栈正常', 'ok'], 'v4-only': ['只有 IPv4 可用', 'ok'],
    'v6-only': ['只有 IPv6 可用', 'ok'], 'link-local': ['只拿到本地地址', 'warn'],
    'no-address': ['没有 IP 地址', 'bad'], 'no-carrier': ['没插线', 'warn'],
    down: ['已禁用', 'warn'], virtual: ['虚拟网卡', ''], loopback: ['回环', ''],
  };
  for (const n of r.values.interfaces || []) {
    const [text, cls] = LABEL[n.verdict.verdict] || [n.verdict.verdict, ''];
    const addrs = (n.addrs || []).map((a) =>
      `<tr><td><code>${esc(a.cidr)}</code></td><td>${a.family}</td><td>${esc(a.scope)}</td></tr>`).join('');
    root.appendChild($(`<div class="card">
      <h2>${esc(n.name)} <span class="pill ${cls}">${esc(text)}</span></h2>
      <p class="hint">${esc(n.mac || '')}${n.mtu ? ' · MTU ' + n.mtu : ''}</p>
      ${addrs ? `<table><tr><th>地址</th><th>族</th><th>用途</th></tr>${addrs}</table>` : '<div class="empty">没有地址</div>'}
    </div>`));
  }
}

// ── 开启路由（DHCP）──
//
// ★ 这一页是老板那个场景：一堆设备插在交换机上、没人发地址。

let evSeq = 0;
let freshMacs = new Set();
let pollTimer = null;

async function renderDHCP(root) {
  clearInterval(pollTimer);
  const nics = await call('net.interfaces');
  const usable = (nics.values.interfaces || []).filter(
    (n) => !n.loopback && (n.verdict.verdict === 'dual-stack' || n.verdict.verdict === 'v4-only'));

  const state = await call('net.dhcp.leases');
  const serving = state.ok && state.verdict === 'serving';

  if (serving) { root.appendChild(await runningCard(state)); startPolling(root); return; }

  const opts = usable.map((n) => `<option value="${esc(n.name)}">${esc(n.name)}（${esc((n.addrs[0] || {}).cidr || '')}）</option>`).join('');
  const card = $(`<div class="card">
    <h2>把这台电脑变成 DHCP 服务器</h2>
    <p class="hint">设备都插在交换机上、没人自动分 IP 时用它。参数已按本机网段算好，可以直接改。</p>
    <label>在哪块网卡上服务</label>
    <select id="iface">${opts || '<option>没有可用网卡</option>'}</select>
    <div class="row">
      <div><label>地址池起</label><input id="start"></div>
      <div><label>地址池止</label><input id="end"></div>
      <div><label>租期（小时）</label><input id="lease" value="12"></div>
    </div>
    <label>下发网关（可留空）</label>
    <input id="router" placeholder="留空 = 不下发">
    <p class="hint" id="routerNote"></p>
    <div style="margin-top:14px;display:flex;gap:10px">
      <button class="ghost" id="btnProbe">先看看有没有别人在发地址</button>
      <button class="go" id="btnStart">开始发地址</button>
    </div>
    <div class="out" id="out" style="margin-top:12px;display:none"></div>
  </div>`);
  root.appendChild(card);

  const out = card.querySelector('#out');
  const say = (s) => { out.style.display = 'block'; out.textContent = s; };

  async function fillDefaults() {
    const name = card.querySelector('#iface').value;
    if (!name) return;
    const d = await call('net.dhcp.defaults', { iface: name });
    if (!d.ok) { say('算不出默认参数：' + d.message); return; }
    const v = d.values;                    // 清单形状：values 就是它本身
    card.querySelector('#start').value = v.start || '';
    card.querySelector('#end').value = v.end || '';
    card.querySelector('#lease').value = v.leaseHours || 12;
    card.querySelector('#routerNote').textContent = v.routerNote || '';
  }
  card.querySelector('#iface').onchange = fillDefaults;
  await fillDefaults();

  card.querySelector('#btnProbe').onclick = async () => {
    say('正在广播探测…（约 3 秒）');
    const p = await call('net.dhcp.probe', { iface: card.querySelector('#iface').value, waitMs: 3000 });
    if (!p.ok) { say('探测失败：' + p.message); return; }
    say(p.note + '\n\n' + JSON.stringify(p.values.servers || [], null, 2));
  };

  card.querySelector('#btnStart').onclick = async () => {
    say('正在启动…启动前会自动探一遍，确认没有别的 DHCP 在发地址。');
    const r = await call('net.dhcp.serve', {
      iface: card.querySelector('#iface').value,
      start: card.querySelector('#start').value,
      end: card.querySelector('#end').value,
      leaseHours: Number(card.querySelector('#lease').value) || 12,
      router: card.querySelector('#router').value || undefined,
    });
    if (!r.ok) { say('没有启动：' + r.message); return; }
    if (r.verdict === 'dhcp-found') { say('⚠ ' + r.note); return; }
    evSeq = 0; freshMacs = new Set();
    show();
  };
}

async function runningCard(state) {
  const v = state.values;
  const wrap = $(`<div>
    <div class="card">
      <h2>正在发地址 <span class="pill ok">服务中</span></h2>
      <p class="hint">网卡 ${esc(v.iface)} · 池子共 ${v.poolSize} 个地址 · 已发出 <b id="cnt">${v.count}</b> 个</p>
      <button class="ghost danger" id="btnStop">停止服务</button>
    </div>
    <div class="card">
      <h2>已接入的设备</h2>
      <p class="hint">新接入的会高亮显示。想改某台的 IP，直接在它那一行改完点「改地址」——
        设备会在下次续租时换过去，拔插一下网线可立刻生效。</p>
      <div id="leases"></div>
    </div>
  </div>`);
  wrap.querySelector('#btnStop').onclick = async () => {
    const r = await call('net.dhcp.stop');
    if (!r.ok) alert('停不下来：' + r.message);
    show();
  };
  drawLeases(wrap.querySelector('#leases'), state.values.leases || []);
  return wrap;
}

function drawLeases(box, leases) {
  if (!leases.length) { box.innerHTML = '<div class="empty">还没有设备来要地址。把设备插上交换机，它们会陆续出现。</div>'; return; }
  const rows = leases.map((l) => `
    <tr class="${freshMacs.has(l.mac) ? 'fresh' : ''}">
      <td><code>${esc(l.ip)}</code></td>
      <td><code>${esc(l.mac)}</code></td>
      <td>${esc(l.host || '—')}</td>
      <td><input value="${esc(l.ip)}" data-mac="${esc(l.mac)}" data-from="${esc(l.ip)}" style="width:140px"></td>
      <td><button class="ghost" data-act="${esc(l.mac)}">改地址</button></td>
    </tr>`).join('');
  box.innerHTML = `<table><tr><th>IP</th><th>MAC</th><th>设备名</th><th>改成</th><th></th></tr>${rows}</table>`;
  box.querySelectorAll('button[data-act]').forEach((b) => {
    b.onclick = async () => {
      const inp = box.querySelector(`input[data-mac="${b.dataset.act}"]`);
      const r = await call('net.dhcp.setip', { mac: b.dataset.act, to: inp.value });
      alert(r.ok ? r.note : '改不了：' + r.message);
      show();
    };
  });
}

/** ★ 轮询事件：新设备接入要能自己冒出来，不能让人一直点刷新。 */
function startPolling(root) {
  pollTimer = setInterval(async () => {
    const e = await call('net.dhcp.events', { sinceSeq: evSeq });
    if (!e.ok || e.verdict !== 'serving') return;
    evSeq = e.values.lastSeq || evSeq;
    for (const ev of e.values.events || []) if (ev.kind === 'new') freshMacs.add(ev.mac);
    const ls = await call('net.dhcp.leases');
    if (!ls.ok) return;
    const box = root.querySelector('#leases');
    const cnt = root.querySelector('#cnt');
    if (box) drawLeases(box, ls.values.leases || []);
    if (cnt) cnt.textContent = ls.values.count;
  }, 2500);
}

// ── 连通性 ──

async function renderProbe(root) {
  const card = $(`<div class="card">
    <h2>连通性</h2>
    <p class="hint">ping 会区分「对方明确回了不可达」和「完全没回应」——前者说明路是通的、问题在对端。</p>
    <div class="row">
      <div><label>目标地址</label><input id="t" placeholder="192.168.1.1 或 fd00::1"></div>
      <div><label>端口（探端口时填）</label><input id="p" placeholder="554"></div>
    </div>
    <div style="margin-top:12px;display:flex;gap:10px">
      <button class="go" id="bp">ping</button>
      <button class="ghost" id="bt">探端口</button>
    </div>
    <div class="out" id="o" style="margin-top:12px;display:none"></div>
  </div>`);
  root.appendChild(card);
  const o = card.querySelector('#o');
  const say = (s) => { o.style.display = 'block'; o.textContent = s; };
  card.querySelector('#bp').onclick = async () => {
    say('ping 中…');
    const r = await call('net.ping', { addr: card.querySelector('#t').value, count: 4 });
    say(r.ok ? `${r.note}\n\n${JSON.stringify(r.values, null, 2)}` : r.message);
  };
  card.querySelector('#bt').onclick = async () => {
    say('探测中…');
    const r = await call('net.tcp.probe', {
      addr: card.querySelector('#t').value, port: Number(card.querySelector('#p').value) || undefined });
    say(r.ok ? `${r.note}\n\n${JSON.stringify(r.values, null, 2)}` : r.message);
  };
}

// ── 视频流 ──

async function renderStream(root) {
  const card = $(`<div class="card">
    <h2>视频流探测</h2>
    <p class="hint">输入取流地址，直接告诉你编码、**真实分辨率**、帧率。不需要播放器，也不解码。</p>
    <label>RTSP 地址</label>
    <input id="u" placeholder="rtsp://admin:密码@192.168.1.64:554/cam/realmonitor?channel=1&subtype=0">
    <div style="margin-top:12px"><button class="go" id="b">探测</button></div>
    <div class="out" id="o" style="margin-top:12px;display:none"></div>
  </div>`);
  root.appendChild(card);
  const o = card.querySelector('#o');
  card.querySelector('#b').onclick = async () => {
    o.style.display = 'block'; o.textContent = '探测中…';
    const r = await call('media.rtsp.probe', { url: card.querySelector('#u').value });
    o.textContent = r.ok ? `${r.note}\n\n${JSON.stringify(r.values, null, 2)}` : r.message;
  };
}

// ── 起步 ──

(async () => {
  API = await window.netkit.apiBase();
  const c = document.getElementById('conn');
  try {
    const r = await fetch(`${API}/ots`).then((x) => x.json());
    c.textContent = `已连接 · ${r.conformance} · 规范 ${r.specVersion}`;
  } catch { c.textContent = '后端没连上'; }
  renderNav();
  show();
})();
