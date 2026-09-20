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
  { id: 'remote', name: '远程', render: renderRemote },
];

let current = 'nic';

function renderNav() {
  const nav = document.getElementById('nav');
  nav.innerHTML = '';
  for (const p of PAGES) {
    const b = document.createElement('button');
    b.textContent = p.name;
    b.className = p.id === current ? 'btn on' : 'btn';
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
  const all = r.values.interfaces || [];

  /*
   * ★ 这一页原先是「一块网卡一张大卡片」。在 Mac 上一开就是二十几张，
   *   其中二十张是系统自带的虚拟网卡，清一色「没有 IP 地址」——
   *   真正在用的那一块被埋在最上面一行，要滚半天才看得完。
   *   现场要的是**一眼看出哪块能用**，所以：一张表、在用的排前面、
   *   没在用的默认折起来。
   */
  const live = (n) => ['dual-stack', 'v4-only', 'v6-only', 'link-local'].includes(n.verdict.verdict);
  const on = all.filter(live), off = all.filter((n) => !live(n));

  /*
   * ★ 介质类型。后端只给码（wifi / ethernet / …）和**这个结论从哪来**（os / name），
   *   人话在这里渲染 —— 和判定码一样的规矩，多语种就靠这条。
   *
   *   ★★ `kindSrc === 'name'` 时必须加「可能是」。现场是照着这一列去插线的，
   *   把按名字猜出来的东西说得像确定的，比不说还糟。
   */
  const KIND = {
    wifi: ['无线', '📶'], ethernet: ['有线网口', '🔌'], 'usb-lan': ['USB 网卡', '🔌'],
    cellular: ['4G/共享网络', '📡'], bluetooth: ['蓝牙', '🔵'],
    thunderbolt: ['雷雳', '⚡'], virtual: ['虚拟', ''], loopback: ['回环', ''],
  };
  const kindCell = (n) => {
    const [text, icon] = KIND[n.kind] || ['不确定', ''];
    if (!n.kind) return '<span class="dim">不确定</span>';
    const guess = n.kindSrc === 'name';
    return `<span title="${guess ? '按网卡名推测，未经系统确认' : '系统给出的类型'}">`
      + `${icon} ${guess ? '可能是' : ''}${esc(text)}</span>`;
  };

  const row = (n) => {
    const [text, cls] = LABEL[n.verdict.verdict] || [n.verdict.verdict, ''];
    const addrs = (n.addrs || []).map((a) => `<code>${esc(a.cidr)}</code>`).join('<br>') || '—';
    return `<tr>
      <td><b>${esc(n.name)}</b></td>
      <td>${kindCell(n)}</td>
      <td><span class="pill ${cls}">${esc(text)}</span></td>
      <td>${addrs}</td>
      <td class="dim"><code>${esc(n.mac || '—')}</code></td>
      <td class="dim">${n.mtu || '—'}</td>
    </tr>`;
  };
  const head = '<tr><th>网卡</th><th>类型</th><th>状态</th><th>地址</th><th>MAC</th><th>MTU</th></tr>';

  root.appendChild($(`<div class="card">
    <h2>在用的网卡</h2>
    <p class="hint">下面这些拿到了地址，可以用来 ping、探端口、发 DHCP。</p>
    ${on.length ? `<table>${head}${on.map(row).join('')}</table>`
               : '<div class="empty">一块都没有拿到地址。检查网线、交换机，或者用「开启路由」自己发地址。</div>'}
  </div>`));

  if (!off.length) return;
  const rest = $(`<div class="card">
    <h2>没在用的网卡 <span class="pill">${off.length}</span></h2>
    <p class="hint">虚拟网卡、没插线的、被禁用的。排查时一般不用管。</p>
    <button class="btn" id="more">展开</button>
    <div id="offbox" style="display:none;margin-top:10px"></div>
  </div>`);
  root.appendChild(rest);
  const box = rest.querySelector('#offbox');
  rest.querySelector('#more').onclick = (e) => {
    const openNow = box.style.display === 'none';
    box.style.display = openNow ? 'block' : 'none';
    e.target.textContent = openNow ? '收起' : '展开';
    if (openNow && !box.innerHTML) box.innerHTML = `<table>${head}${off.map(row).join('')}</table>`;
  };
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
      <button class="btn" id="btnProbe">先看看有没有别人在发地址</button>
      <button class="btn primary" id="btnStart">开始发地址</button>
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
      <button class="btn danger" id="btnStop">停止服务</button>
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
      <td><button class="btn" data-act="${esc(l.mac)}">改地址</button></td>
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
      <button class="btn primary" id="bp">ping</button>
      <button class="btn" id="bt">探端口</button>
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
    <div style="margin-top:12px"><button class="btn primary" id="b">探测</button></div>
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

// ── 远程 ──
//
// ★ 设备登记、执行命令、传文件、弹消息、开桌面，背后全是同一批工具 ——
//   改系统的操作由后端走批准渠道弹框，UI 不替人做判断。
// ★★ 「对方可见」关成静默时，UI 当场再弹一次责任确认（docs/设计.md 安全第 3 条），
//   这句话必须出现在人点下去之前，不能只藏在后端返回里。

let remoteSel = null;

async function renderRemote(root) {
  const r = await call('remote.device.list');
  if (!r.ok) { root.appendChild($(`<div class="card">远程功能不可用：${esc(r.message)}</div>`)); return; }
  const devices = r.values.devices || [];
  root.appendChild(notifyCard(r.values.notifyTarget !== false));
  root.appendChild(deviceTable(devices));
  root.appendChild(addDeviceCard());
  const sel = devices.find((d) => d.id === remoteSel);
  if (sel) root.appendChild(remoteOps(sel));
  root.appendChild(auditCard());
}

function notifyCard(on) {
  const card = $(`<div class="card">
    <h2>对方可见 <span class="pill ${on ? 'ok' : 'bad'}">${on ? '开（默认）' : '静默'}</span></h2>
    <p class="hint">开着时，远程连接 / 控制 / 连桌面会先在目标机屏幕上提示一声（带「来自 NetKit·谁」的标识）。
      审计日志不受这个开关影响，怎么设都照记。</p>
    <button class="btn ${on ? 'danger' : 'primary'}" id="tog">${on ? '关闭（进入静默）' : '打开'}</button>
  </div>`);
  card.querySelector('#tog').onclick = async () => {
    if (on) {
      // ★ 关静默 = 要被记住的选择：当场弹一次，写明责任归属，人点了才发
      const ok = await confirmModal(
        '关闭「对方可见」，进入静默模式？',
        ['之后远程连接 / 控制这台设备时，<b>目标机屏幕前的人将不会收到任何提示</b>。',
         '请确认场景是无人值守（服务器、机柜一体机、数字标牌）。',
         '<b>由购买方负责在其组织内合规使用并履行告知义务。</b>',
         '审计日志不受影响，照记；这次选择本身也会进审计。'],
        '我已了解，确认关闭');
      if (!ok) return;
    }
    const r = await call('remote.config.set', { notifyTarget: !on });
    if (!r.ok) { alert('改不了：' + r.message); return; }
    show();
  };
  return card;
}

/** 自己画的确认框：责任那段话必须完整摆出来，不用 confirm()（放不下也不体面）。 */
function confirmModal(title, htmlLines, okText) {
  return new Promise((resolve) => {
    const ov = $(`<div class="modal-ov"><div class="modal">
      <h2>${esc(title)}</h2>
      ${htmlLines.map((l) => `<p class="hint">${l}</p>`).join('')}
      <div style="display:flex;gap:10px;margin-top:14px;justify-content:flex-end">
        <button class="btn" id="no">取消</button>
        <button class="btn danger" id="yes">${esc(okText)}</button>
      </div></div></div>`);
    document.body.appendChild(ov);
    const done = (v) => { ov.remove(); resolve(v); };
    ov.querySelector('#no').onclick = () => done(false);
    ov.querySelector('#yes').onclick = () => done(true);
    ov.onclick = (e) => { if (e.target === ov) done(false); };
  });
}

const OS_LABEL = { windows: 'Windows', linux: 'Linux', darwin: 'macOS' };

function deviceTable(devices) {
  const card = $(`<div class="card">
    <h2>登记的设备 <span class="pill">${devices.length}</span></h2>
    <p class="hint">凭据只落盘在本机 0600 的文件里，不出现在这里、也不进日志。点「操作」展开命令行 / 传文件 / 弹消息 / 开桌面。</p>
    <div id="box"></div>
  </div>`);
  const box = card.querySelector('#box');
  if (!devices.length) {
    box.innerHTML = '<div class="empty">还没有登记设备。在下面填地址和账号加一台，SSH 通了就能诊断、传文件、开桌面。</div>';
    return card;
  }
  const row = (d) => {
    const host = d.identity && d.identity.hostname ? ` <span class="dim">（${esc(d.identity.hostname)}）</span>` : '';
    const seen = d.lastSeen ? new Date(d.lastSeen).toLocaleString() : '还没连过';
    return `<tr>
      <td><b>${esc(d.name || d.id)}</b>${d.name ? `<br><code class="dim">${esc(d.id)}</code>` : ''}${host}</td>
      <td>${esc(OS_LABEL[d.os] || '未知')}</td>
      <td class="dim">${esc(d.auth || '')}${d.hostKeyKnown ? '' : '<br><span class="dim">主机密钥未记录</span>'}</td>
      <td class="dim">${esc(seen)}</td>
      <td style="white-space:nowrap">
        <button class="btn primary" data-act="sel" data-id="${esc(d.id)}">${d.id === remoteSel ? '收起' : '操作'}</button>
        <button class="btn" data-act="probe" data-id="${esc(d.id)}">探测</button>
        <button class="btn danger" data-act="rm" data-id="${esc(d.id)}">删除</button>
      </td></tr>`;
  };
  box.innerHTML = `<table><tr><th>设备</th><th>系统</th><th>认证</th><th>最近探测</th><th></th></tr>
    ${devices.map(row).join('')}</table>`;
  box.querySelectorAll('button[data-act]').forEach((b) => {
    b.onclick = async () => {
      const id = b.dataset.id;
      if (b.dataset.act === 'sel') { remoteSel = remoteSel === id ? null : id; show(); return; }
      if (b.dataset.act === 'rm') {
        if (!confirm(`把 ${id} 从登记簿删掉（连同存的凭据）？`)) return;
        await call('remote.device.remove', { device: id });
        if (remoteSel === id) remoteSel = null;
        show(); return;
      }
      b.disabled = true; b.textContent = '连接中…';
      const r = await call('remote.device.probe', { device: id });
      alert(r.ok ? r.note : '探测失败：' + r.message);
      show();
    };
  });
  return card;
}

function addDeviceCard() {
  const card = $(`<div class="card">
    <h2>登记一台设备</h2>
    <p class="hint">走 SSH。能用私钥就别用口令；不确定账号名就先猜一个，连不上时探测会把线索报回来。</p>
    <div class="row">
      <div><label>地址 *</label><input id="host" placeholder="192.168.3.82 或 fe80::1%en0"></div>
      <div style="max-width:110px"><label>端口</label><input id="port" placeholder="22"></div>
      <div><label>账号 *</label><input id="user" placeholder="administrator / root / pc"></div>
      <div><label>备注名</label><input id="name" placeholder="收银台那台"></div>
    </div>
    <div class="row">
      <div><label>口令</label><input id="pw" type="password" placeholder="和私钥二选一"></div>
      <div><label>私钥路径（本机）</label><input id="key" placeholder="/Users/me/.ssh/id_ed25519"></div>
    </div>
    <div style="margin-top:12px"><button class="btn primary" id="add">登记并探测</button></div>
    <div class="out" id="o" style="display:none;margin-top:10px"></div>
  </div>`);
  const g = (s) => card.querySelector(s).value.trim();
  card.querySelector('#add').onclick = async () => {
    const o = card.querySelector('#o');
    const say = (s) => { o.style.display = 'block'; o.textContent = s; };
    if (!g('#host') || !g('#user')) { say('地址和账号是必填的'); return; }
    if (!g('#pw') && !g('#key')) { say('口令和私钥至少给一个 —— 没凭据连不上'); return; }
    const args = { host: g('#host'), user: g('#user'), name: g('#name') || undefined,
      password: g('#pw') || undefined, keyPath: g('#key') || undefined };
    if (g('#port')) args.port = Number(g('#port'));
    const r = await call('remote.device.add', args);
    if (!r.ok) { say('登记失败：' + r.message); return; }
    say('已登记，正在连接探测…');
    const id = r.values.id;
    const p = await call('remote.device.probe', { device: id });
    say(p.ok ? p.note : '登记成功，但探测失败：' + p.message);
    remoteSel = id;
    setTimeout(show, 1200);
  };
  return card;
}

function remoteOps(d) {
  const card = $(`<div class="card">
    <h2>操作 <code>${esc(d.id)}</code> <span class="dim">${esc(OS_LABEL[d.os] || '系统未知，先探测')}</span></h2>
    <p class="hint">下面每一项改系统的操作都会先弹框确认，且全程记入审计。</p>

    <label>执行命令（远程诊断主力：看资源、抓日志、重启服务）</label>
    <div style="display:flex;gap:8px">
      <input id="cmd" placeholder="${d.os === 'windows' ? 'ipconfig /all' : 'systemctl status nginx'}">
      <button class="btn primary" id="bcmd">执行</button>
      <button class="btn" id="bsess">看会话</button>
    </div>
    <div class="out" id="ocmd" style="display:none;margin-top:8px"></div>

    <label>给屏幕发消息（自动带发送方标识）</label>
    <div style="display:flex;gap:8px">
      <input id="msg" placeholder="如：10 分钟后重启收银系统，请保存工作">
      <button class="btn" id="bmsg">发送</button>
    </div>
    <div class="out" id="omsg" style="display:none;margin-top:8px"></div>

    <label>传文件（断点续传 + 整包 SHA256 复核）</label>
    <div class="row">
      <div><label>本机路径</label><input id="flocal" placeholder="/Users/me/升级包.bin"></div>
      <div><label>设备路径</label><input id="fremote" placeholder="${d.os === 'windows' ? 'C:\\\\tmp\\\\升级包.bin' : '/tmp/升级包.bin'}"></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:8px">
      <button class="btn" id="bpush">推到设备 ↑</button>
      <button class="btn" id="bpull">拉回本机 ↓</button>
    </div>
    <div class="out" id="ofile" style="display:none;margin-top:8px"></div>

    <label>远程桌面</label>
    <div style="display:flex;gap:8px">
      <button class="btn" id="bdq">查状态</button>
      <button class="btn primary" id="bdo">打通并连接${d.os === 'windows' ? '（RDP 没开会替它开）' : ''}</button>
    </div>
    <div class="out" id="odesk" style="display:none;margin-top:8px"></div>
  </div>`);
  const out = (id, s) => { const o = card.querySelector(id); o.style.display = 'block'; o.textContent = s; };
  const busy = async (btn, fn) => {
    const b = card.querySelector(btn); const t = b.textContent;
    b.disabled = true; b.textContent = '进行中…';
    try { await fn(); } finally { b.disabled = false; b.textContent = t; }
  };

  card.querySelector('#bcmd').onclick = () => busy('#bcmd', async () => {
    const cmd = card.querySelector('#cmd').value.trim();
    if (!cmd) return;
    out('#ocmd', '执行中…（等待批准）');
    const r = await call('remote.exec', { device: d.id, command: cmd });
    if (!r.ok) { out('#ocmd', '执行失败：' + r.message); return; }
    const v = r.values;
    out('#ocmd', `退出码 ${v.exitCode} · ${v.seconds.toFixed(1)} 秒\n── 输出 ──\n${v.stdout || '(空)'}${v.stderr ? '\n── 错误 ──\n' + v.stderr : ''}`);
  });

  card.querySelector('#bsess').onclick = () => busy('#bsess', async () => {
    const r = await call('remote.sessions', { device: d.id });
    if (!r.ok) { out('#ocmd', '查会话失败：' + r.message); return; }
    const ss = r.values.sessions || [];
    out('#ocmd', ss.length ? ss.map((s) =>
      `#${s.id}  ${s.state}${s.active ? '（有人）' : ''}${s.current ? ' ← SSH 落在这' : ''}  ${s.name}  ${s.user || ''}`).join('\n')
      : '这台机器上没有登录会话');
  });

  card.querySelector('#bmsg').onclick = () => busy('#bmsg', async () => {
    const text = card.querySelector('#msg').value.trim();
    if (!text) return;
    const r = await call('remote.msg.send', { device: d.id, text });
    const LABEL = { sent: '✓ 已发到对方屏幕', 'sent-unconfirmed': '△ 发了，但不保证对方看得见', 'no-session': '✗ 屏幕前没人', 'send-failed': '✗ 发不出去' };
    out('#omsg', r.ok ? `${LABEL[r.verdict] || r.verdict}\n${r.note}` : '失败：' + r.message);
  });

  const transfer = (tool, args) => busy(tool === 'remote.file.push' ? '#bpush' : '#bpull', async () => {
    out('#ofile', '传输中…（等待批准；大文件要一会儿，断了再点一次会续传）');
    const r = await call(tool, args);
    out('#ofile', r.ok ? r.note : '失败：' + r.message);
  });
  card.querySelector('#bpush').onclick = () => {
    const l = card.querySelector('#flocal').value.trim(), rm = card.querySelector('#fremote').value.trim();
    if (!l || !rm) { out('#ofile', '两个路径都要填'); return; }
    transfer('remote.file.push', { device: d.id, local: l, remote: rm });
  };
  card.querySelector('#bpull').onclick = () => {
    const l = card.querySelector('#flocal').value.trim(), rm = card.querySelector('#fremote').value.trim();
    if (!l || !rm) { out('#ofile', '两个路径都要填'); return; }
    transfer('remote.file.pull', { device: d.id, local: l, remote: rm });
  };

  card.querySelector('#bdq').onclick = () => busy('#bdq', async () => {
    const r = await call('remote.desktop.open', { device: d.id });
    out('#odesk', r.ok ? `${r.note}\n判定：${r.verdict}` : '失败：' + r.message);
  });
  card.querySelector('#bdo').onclick = () => busy('#bdo', async () => {
    out('#odesk', '打通中…（等待批准；Windows 目标 RDP 没开时会改对端注册表和防火墙）');
    const r = await call('remote.desktop.open', { device: d.id, enable: true });
    out('#odesk', r.ok ? `${r.note}\n判定：${r.verdict}` : '失败：' + r.message);
  });
  return card;
}

function auditCard() {
  const card = $(`<div class="card">
    <h2>审计日志</h2>
    <p class="hint">谁、何时、对哪台、做了什么、结果如何。静默模式只关屏幕提示，不关这里的留痕。</p>
    <button class="btn" id="load">取最近 50 条</button>
    <div id="box" style="margin-top:10px"></div>
  </div>`);
  card.querySelector('#load').onclick = async () => {
    const box = card.querySelector('#box');
    const r = await call('remote.audit.tail', { n: 50 });
    if (!r.ok) { box.innerHTML = `<div class="empty">${esc(r.message)}</div>`; return; }
    const es = (r.values.entries || []).slice().reverse();
    if (!es.length) { box.innerHTML = '<div class="empty">还没有记录</div>'; return; }
    box.innerHTML = `<table><tr><th>时间</th><th>谁</th><th>动作</th><th>对哪台</th><th>细节</th><th>结果</th></tr>
      ${es.map((e) => `<tr>
        <td class="dim" style="white-space:nowrap">${esc(new Date(e.at).toLocaleString())}</td>
        <td class="dim">${esc(e.actor || '')}</td>
        <td><code>${esc(e.action || '')}</code></td>
        <td>${esc(e.target || '')}</td>
        <td class="dim">${esc(e.detail || '')}</td>
        <td class="${String(e.result).startsWith('failed') || e.result === 'send-failed' ? 'bad' : 'dim'}">${esc(e.result || '')}</td>
      </tr>`).join('')}</table>`;
  };
  return card;
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
