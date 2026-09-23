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
  { id: 'scan', name: '扫描与发现', render: renderScan },
  { id: 'stream', name: '视频流', render: renderStream },
  { id: 'remote', name: '远程', render: renderRemote },
  { id: 'tools', name: '小工具', render: renderTools },
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

/*
 * ★ 介质类型。后端只给码（wifi / ethernet / …）和**这个结论从哪来**（os / name），
 *   人话在这里渲染 —— 和判定码一样的规矩，多语种就靠这条。
 *
 * ★★ `kindSrc === 'name'` 时必须加「可能是」。现场是照着这一列去插线的，
 *   把按名字猜出来的东西说得像确定的，比不说还糟。
 */
const KIND = {
  wifi: ['无线', '📶'], ethernet: ['有线网口', '🔌'], 'usb-lan': ['USB 网卡', '🔌'],
  cellular: ['4G/共享网络', '📡'], bluetooth: ['蓝牙', '🔵'],
  thunderbolt: ['雷雳', '⚡'], virtual: ['虚拟', ''], loopback: ['回环', ''],
};
// kindWord 给下拉框、标题这类只要一个词的地方用；带「可能是」的诚实前缀。
function kindWord(n) {
  if (!n.kind) return '网卡';
  const [text] = KIND[n.kind] || ['网卡'];
  return (n.kindSrc === 'name' ? '可能是' : '') + text;
}

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

  if (off.length) {
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
  // ★ 路由表放在这一页最下面：平时不看，但它回答的是这一页唯一没法从网卡表看出来的
  //   那一问 ——「同一个目的地，本机打算从哪块网卡送出去」。
  root.appendChild(routesCard());
}

// ── 开启路由（DHCP）──
//
// ★ 这一页是老板那个场景：一堆设备插在交换机上、没人发地址。

let evSeq = 0;
let freshMacs = new Set();
let pollTimer = null;

/*
 * ★★ 老板的问题（2026-09-23）：「usb 或者网口连接的网卡怎么没在想开 dhcp 列表里？」
 *
 *   原来这一页只列**已经拿到私网 IPv4** 的网卡（dual-stack / v4-only）。
 *   而现场的真实情况恰恰相反：一块 USB 网卡或有线口插到傻瓜交换机上，
 *   没有路由器发地址，macOS 给自己塞一个 169.254（link-local）——
 *   按老筛选它就被藏起来了。可这正是**最需要在它上面开 DHCP** 的那块网卡。
 *
 *   所以这里改成：物理网卡全列出来，按能不能直接服务分三档——
 *     · 能直接开（有私网 IPv4）：正常预填地址池
 *     · 缺固定 IP（link-local / no-address）：选中后先让它在本页设一个静态地址
 *     · 开不了（没插线 / 已禁用 / 只有 IPv6）：选项置灰，把原因写出来，不让人瞎猜
 */
const DHCP_DISABLED_REASON = {
  'no-carrier': '没插线', down: '已禁用', 'v6-only': '只有 IPv6',
};
function dhcpClass(n) {
  const v = n.verdict.verdict;
  if (v === 'dual-stack' || v === 'v4-only') return 'servable';
  if (v === 'link-local' || v === 'no-address') return 'needsAddr';
  return 'disabled';
}

async function renderDHCP(root) {
  clearInterval(pollTimer);
  const nics = await call('net.interfaces');
  // 物理网卡：滤掉回环和虚拟网卡（虚拟网卡开 DHCP 没意义，还会把列表撑爆）
  const phys = (nics.values.interfaces || []).filter(
    (n) => n.verdict.verdict !== 'loopback' && n.verdict.verdict !== 'virtual');

  const state = await call('net.dhcp.leases');
  const serving = state.ok && state.verdict === 'serving';

  if (serving) { root.appendChild(await runningCard(state)); startPolling(root); return; }

  // 能用的排前面，开不了的沉底，符合现场「一眼找到该插哪块」的需要
  const order = { servable: 0, needsAddr: 1, disabled: 2 };
  const listed = phys.slice().sort((a, b) => order[dhcpClass(a)] - order[dhcpClass(b)]);
  const byName = {};
  listed.forEach((n) => { byName[n.name] = n; });

  const opts = listed.map((n) => {
    const cls = dhcpClass(n);
    const word = kindWord(n);
    let tail;
    if (cls === 'servable') tail = (n.addrs[0] || {}).cidr || '';
    else if (cls === 'needsAddr') tail = '没有固定 IP，选中后先设一个';
    else tail = DHCP_DISABLED_REASON[n.verdict.verdict] || n.verdict.verdict;
    return `<option value="${esc(n.name)}" data-cls="${cls}"${cls === 'disabled' ? ' disabled' : ''}>`
      + `${esc(n.name)}（${esc(word)}）${tail ? ' — ' + esc(tail) : ''}</option>`;
  }).join('');

  const card = $(`<div class="card">
    <h2>把这台电脑变成 DHCP 服务器</h2>
    <p class="hint">设备都插在交换机上、没人自动分 IP 时用它。选好网卡后参数会自动算好，可以直接改。</p>
    <label>在哪块网卡上服务</label>
    <select id="iface">${opts || '<option>没有可用网卡</option>'}</select>

    <div id="addrPanel" style="display:none;margin-top:12px;padding:12px;border-radius:10px;background:var(--panel-2);border:1px solid var(--line)">
      <p class="hint" id="addrWhy"></p>
      <div class="row">
        <div><label>给它设的 IP</label><input id="addrIp" value="192.168.50.1"></div>
        <div><label>掩码位数</label><input id="addrPrefix" value="24"></div>
      </div>
      <button class="btn primary" id="btnSetAddr" style="margin-top:8px">设静态地址</button>
      <p class="hint">设完这块网卡就能发地址了。改系统网络设置需要管理员权限，弹出来就输入开机密码。</p>
    </div>

    <div id="poolPanel">
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
    </div>
    <div class="out" id="out" style="margin-top:12px;display:none"></div>
  </div>`);
  root.appendChild(card);

  const out = card.querySelector('#out');
  const say = (s) => { out.style.display = 'block'; out.textContent = s; };
  const sel = card.querySelector('#iface');
  const addrPanel = card.querySelector('#addrPanel');
  const poolPanel = card.querySelector('#poolPanel');

  async function fillDefaults() {
    const name = sel.value;
    if (!name) return;
    const d = await call('net.dhcp.defaults', { iface: name });
    if (!d.ok) { say('算不出默认参数：' + d.message); return; }
    const v = d.values;                    // 清单形状：values 就是它本身
    card.querySelector('#start').value = v.start || '';
    card.querySelector('#end').value = v.end || '';
    card.querySelector('#lease').value = v.leaseHours || 12;
    card.querySelector('#routerNote').textContent = v.routerNote || '';
  }

  // 选中一块网卡：缺 IP 的走「先设静态地址」，其余正常预填地址池
  function onSelect() {
    out.style.display = 'none';
    const n = byName[sel.value];
    if (!n) return;
    if (dhcpClass(n) === 'needsAddr') {
      addrPanel.style.display = 'block';
      poolPanel.style.display = 'none';
      card.querySelector('#addrWhy').textContent =
        `网卡 ${n.name} 还没有可用的固定 IP，DHCP 服务器得先有一个自己的地址才能发。给它设一个：`;
    } else {
      addrPanel.style.display = 'none';
      poolPanel.style.display = 'block';
      fillDefaults();
    }
  }
  sel.onchange = onSelect;

  card.querySelector('#btnSetAddr').onclick = async () => {
    const btn = card.querySelector('#btnSetAddr');
    btn.disabled = true; say('正在设静态地址…（可能弹出管理员密码框）');
    const r = await call('net.address.set', {
      iface: sel.value,
      ip: card.querySelector('#addrIp').value,
      prefix: Number(card.querySelector('#addrPrefix').value) || 24,
    });
    btn.disabled = false;
    if (!r.ok) { say('没设成：' + r.message); return; }
    // ★ 后端会回去核一眼地址有没有真用上。没插线时配置写进去了但地址不激活，
    //   这时候不能重渲染成「设好了」——把后端的诚实提示原样说出来，让人去查网线。
    if (r.verdict === 'address-set-inactive') { say('⚠ ' + r.note); return; }
    say('设好了，正在重新读取网卡…');
    show();  // 重渲染：这块网卡现在能直接发地址了
  };

  if (!listed.length) { say('这台机器上没有能发地址的物理网卡。'); }
  else { onSelect(); }

  card.querySelector('#btnProbe').onclick = async () => {
    say('正在广播探测…（约 3 秒）');
    const p = await call('net.dhcp.probe', { iface: sel.value, waitMs: 3000 });
    if (!p.ok) { say('探测失败：' + p.message); return; }
    say(p.note + '\n\n' + JSON.stringify(p.values.servers || [], null, 2));
  };

  card.querySelector('#btnStart').onclick = async () => {
    say('正在启动…启动前会自动探一遍，确认没有别的 DHCP 在发地址。');
    const r = await call('net.dhcp.serve', {
      iface: sel.value,
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
  root.appendChild(checkupCard());
  root.appendChild(dualStackCard());
  root.appendChild(traceCard());
  root.appendChild(mtrCard());
  root.appendChild(timeCard());
  root.appendChild(dnsCard());
  root.appendChild(certCard());
  root.appendChild(httpCard());
  const card = $(`<div class="card">
    <h2>ping / 探端口</h2>
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
  root.appendChild(portProcCard());
  root.appendChild(pingWatchCard());
  root.appendChild(udpCard());
  root.appendChild(scanCard());
  root.appendChild(mtuCard());
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

/*
 * ── 双栈体检 ──
 *
 * ★★ 这是 docs/设计.md 点名的招牌功能，替人做的是只有老手才会做的那一串判断：
 *   IPv6 有地址、有默认路由，看着一切正常，却出不了外网 —— 而应用优先走 v6，
 *   于是每次连接先卡几秒再回落 v4。现场表现成「网很慢」而不是「网不通」，
 *   最容易被查错方向。这一页直接指出那一步。
 *
 * ★ 后端只给判定码，码 → 人话全部在这里渲染（多语种靠的就是这条分工）。
 */

// 顶层判定 → [标题, 颜色, 该怎么做]
const DS_TOP = {
  'no-address': ['没拿到地址', 'bad', '两个地址族都没有可用地址、也没有默认路由 —— 这台机器现在基本没网。'],
  'dual-healthy': ['双栈正常', 'ok', 'IPv4 和 IPv6 都能出外网。'],
  'v6-egress-broken': ['IPv6 出不了外网', 'bad',
    'IPv4 正常，但 IPv6 有地址/路由却出不了外网。应用优先走 IPv6，所以每次连接先卡一下再回落到 IPv4 —— 这就是「网很慢」的真身。'
    + '要么修上游的 IPv6，要么先把这台机器的 IPv6 关掉。'],
  'v4-egress-broken': ['IPv4 出不了外网', 'bad', 'IPv6 正常，但 IPv4 出不了外网。'],
  'both-egress-broken': ['两族都出不了外网', 'bad', '两族都有地址，但都出不了外网 —— 多半是纯内网，或上游整个断了。'],
  'v4-only': ['只有 IPv4，正常', 'ok', '只有 IPv4 能出外网（这台机器没启用 IPv6，或 IPv6 没拿到地址）。'],
  'v6-only': ['只有 IPv6，正常', 'ok', '只有 IPv6 能出外网。'],
  'single-no-egress': ['在线，但出不了外网', 'bad', '只有一族在线，而且出不了外网。'],
};
// 出口 / 单地址连接 → 人话。★ 这里和探端口用的是同一批码。
const DS_CONN = {
  'open': ['通', 'ok'], 'closed': ['被拒绝', 'warn'], 'filtered': ['静默丢包', 'bad'],
  'no-route': ['没有默认路由', 'bad'], 'error': ['连不上', 'bad'],
  'skipped': ['未测', ''], 'pending': ['—', ''],
};
const DS_GW = {
  'reachable': ['通', 'ok'], 'no-reply': ['没回应', 'warn'], 'unreachable': ['明确不可达', 'bad'],
  'no-gateway': ['无下一跳', ''], 'skipped': ['未测', ''],
};
const DS_DNS = {
  'ok': ['解析出记录', 'ok'], 'no-record': ['这一族没有记录', 'warn'],
  'error': ['解析失败', 'bad'], 'skipped': ['未测', ''],
};

const pillOf = (map, code) => {
  const [text, cls] = map[code] || [code || '—', ''];
  return `<span class="pill ${cls}">${esc(text)}</span>`;
};
const tCell = (label, cell) => `<tr><td class="dim">${label}</td><td>${cell}</td></tr>`;
const ms = (n) => (n || n === 0 ? `${Math.round(n)}ms` : '');

function familyTable(f) {
  const addrs = (f.addresses || []).length
    ? `<code>${esc((f.addresses || []).join('  '))}</code>`
    : '<span class="dim">没有全局地址</span>';
  const route = f.hasRoute
    ? `<span class="pill ok">有</span>${f.gateway ? ` <code>${esc(f.gateway)}</code> 经 ${esc(f.routeIface)}` : ''}`
      + (f.routeCount > 1 ? ` <span class="dim">（共 ${f.routeCount} 条）</span>` : '')
    : '<span class="pill bad">没有</span>';
  const gw = pillOf(DS_GW, f.gwReachable) + (f.gwRttMs ? ` <span class="dim">${ms(f.gwRttMs)}</span>` : '');
  const egress = pillOf(DS_CONN, f.egress)
    + ` <span class="dim">${esc(f.egressTarget || '')}${f.egressRttMs ? ' ' + ms(f.egressRttMs) : ''}</span>`;
  const dns = pillOf(DS_DNS, f.dns) + ` <span class="dim">${ms(f.dnsRttMs)}</span>`;
  return `<div><table>
    <tr><th colspan="2">${f.family === 'ipv4' ? 'IPv4' : 'IPv6'}</th></tr>
    ${tCell('地址', addrs)}${tCell('默认路由', route)}${tCell('网关', gw)}
    ${tCell('出外网', egress)}${tCell('DNS', dns)}
  </table></div>`;
}

function attemptRow(title, list) {
  if (!list || !list.length) return tCell(title, '<span class="dim">域名没有这类记录</span>');
  const cells = list.map((a) => `<div><code>${esc(a.addr)}</code> ${pillOf(DS_CONN, a.code)}`
    + ` <span class="dim">${a.code === 'open' || a.rttMs ? ms(a.rttMs) : ''}</span></div>`).join('');
  return tCell(title, cells);
}

function eyeballRow(eb) {
  const map = {
    'eyeballs-ok': ['不会卡', 'ok'], 'eyeballs-stall': ['★ 会先卡一下', 'bad'],
    'eyeballs-single': ['只有一族能连，没得选', 'warn'], 'eyeballs-fail': ['这个域名两族都连不上', 'bad'],
  };
  const [text, cls] = map[eb.code] || [eb.code, ''];
  let extra = '';
  if (eb.code === 'eyeballs-stall') {
    extra = ` 应用先试 <b>${esc(eb.preferred)}</b>，${eb.connDelayMs}ms 没连上就并行起 <b>${esc(eb.winner)}</b>：`
      + `守规矩的应用大约卡 <b>${ms(eb.stallMs)}</b>，不守规矩的（串行把 v6 试到超时）最坏卡 <b>${ms(eb.worstMs)}</b>。`;
  } else if (eb.winner) {
    extra = ` 应用会先用 <b>${esc(eb.winner)}</b> 连上这个域名。`;
  }
  return tCell('Happy Eyeballs', `<span class="pill ${cls}">${esc(text)}</span>${extra}`);
}

function dualStackCard() {
  const card = $(`<div class="card">
    <h2>双栈体检 <span id="ds-top"></span></h2>
    <p class="hint">一次测完 IPv4 与 IPv6 各自：有没有地址、有没有默认路由、网关通不通、出不出得了外网、DNS 通不通；
      再对同一个域名的 A 与 AAAA 分别连一次比耗时，按 Happy Eyeballs(RFC 8305) 判断应用会不会先卡一下。
      ★ 专治「有 IPv6 地址却出不了外网，结果上网很慢」这类现场最难查的问题。</p>
    <div class="row">
      <div><label>体检用的域名</label><input id="ds-d" placeholder="默认 www.cloudflare.com"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn primary" id="ds-go">开始体检</button></div>
    </div>
    <div id="ds-out" style="margin-top:14px"></div>
  </div>`);

  const out = card.querySelector('#ds-out');
  const top = card.querySelector('#ds-top');
  card.querySelector('#ds-go').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">体检中…（要发几轮连接，约 5 秒）</div>';
    const domain = card.querySelector('#ds-d').value.trim();
    const r = await call('net.dualstack.check', domain ? { domain } : {});
    if (!r.ok) { out.innerHTML = `<div class="empty">体检失败：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [title, cls, advice] = DS_TOP[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}</div>
      <div class="row" style="margin-top:14px">${familyTable(v.v4)}${familyTable(v.v6)}</div>
      <table style="margin-top:14px">
        <tr><th colspan="2">域名 <code>${esc(v.domain.name)}:${v.domain.port}</code>
          <span class="dim">解析 ${v.domain.lookupMs}ms${v.domain.err ? ' · ' + esc(v.domain.err) : ''}</span></th></tr>
        ${attemptRow('A 记录（v4）', v.domain.a)}
        ${attemptRow('AAAA 记录（v6）', v.domain.aaaa)}
        ${eyeballRow(v.eyeballs)}
      </table>`;
  };
  return card;
}

/*
 * ── 一键体检 ──
 *
 * ★★ 这一栏卖的不是「八个结果」，是**顺序**：八行清单谁都会列，「第一个坏掉的是哪一步」才省时间。
 *   网关在丢包时，DNS 和出口测到的那些「慢」全是链路带出来的 —— 从中间开始查必然查错方向。
 *   所以这里照着后端给的顺序平铺，不许按颜色或耗时重排。
 * ★ 后端只出判定码，码 → 人话全部在这里（多语种靠的就是这条分工）。
 */

// 顶层判定 → [标题, 颜色, 该怎么做]
const CK_TOP = {
  'all-good': ['八项都过', 'ok',
    '有地址、有默认路由、到网关不丢、解析得出、出得了外网、时钟也对得上。'
    + '★ 这只说明「这台机器到公网这一段」没问题 —— 两台设备之间通不通，得拿那两台的地址另问。'],
  'degraded': ['没有硬故障，但有值得看一眼的', 'warn',
    '下面标出来的几项都不会让网断，却常常就是「慢」和「偶尔卡一下」的来源 —— 从标了「先看这一步」的那项开始。'],
  'broken-at-iface': ['坏在本机网卡', 'bad',
    '没有一块「启用、有链路、且有可用地址」的网卡 —— 后面每一项都是在它之上测的，先把这一步解决掉。'],
  'broken-at-route': ['坏在默认路由', 'bad',
    '有地址却没有默认路由，这台机器只会发到本网段：局域网里 ping 得通，外面什么都到不了。'
    + '查 DHCP 有没有发网关，或者静态地址里那个网关填错了。'],
  'broken-at-gateway': ['坏在到网关这一段', 'bad',
    '★ 网关在丢包时，DNS 和出口的「慢」都是链路带出来的，不是那两层自己的毛病 —— 先修它，再回头看后面那些数。'
    + '查线、查 AP、查网关本身；最好另拿一台机器同时发一份对照，才知道是不是只有这台的事。'],
  'broken-at-dns': ['坏在域名解析', 'bad',
    '配了 DNS 服务器却问不出名字（或者根本没配）。出口那几项是拿 IP 直连测的，所以它们正常不代表解析正常 ——'
    + '「网页打不开，但 IP ping 得通」就是这一层。'],
  'broken-at-egress': ['局域网好，出不了外网', 'bad',
    '到网关不丢、名字也问得出，但 TCP 连不上公网 —— 往上查：网关的 NAT、ACL、认证门户，'
    + '或者这条链路本来就只放行内网。'],
  'broken-at-clock': ['本机时钟偏得太多', 'bad',
    '偏差已经大到会出事：TLS 证书校验直接失败、日志时间戳互相对不上、带时间有效性的令牌全部被拒。'
    + '先校时，再回头看别的。'],
};

const CK_STEP = {
  iface: '本机网卡', route: '默认路由', gateway: '到网关', dns: '域名解析',
  egress: '出外网', mtu: '出口 MTU', clock: '本机时钟', proxy: '系统代理',
};

// 每一步自己的坏法。★ tone 空的是「没问」——它不算结论，别渲染成红。
const CK_CODE = {
  iface: {
    'ok': ['在用', 'ok'], 'no-nic': ['没有一块网卡', 'bad'],
    'all-disabled': ['网卡全被禁用了', 'bad'],
    'no-link': ['启用了但没链路（没插线 / 没连上 AP）', 'bad'],
    'no-address': ['没有可用地址', 'bad'],
    'virtual-only': ['只有隧道口有地址', 'warn'],
  },
  route: {
    'ok': ['两族都有', 'ok'], 'v4-only': ['只有 IPv4', 'ok'],
    'v6-only': ['只有 IPv6', 'warn'], 'none': ['没有默认路由', 'bad'],
  },
  gateway: {
    'ok': ['不丢也不抖', 'ok'], 'stable': ['不丢也不抖', 'ok'],
    'jitter': ['偶尔抖一下', 'warn'],
    'loss': ['在丢包', 'bad'], 'no-route': ['包根本发不出去', 'bad'],
    'unreachable': ['明确回了不可达', 'bad'],
    'no-reply': ['不回 ping', 'warn'],
    'no-gateway': ['没有下一跳（点对点链路）', ''],
    'tunnel': ['走隧道口，没问', ''], 'not-asked': ['没问', ''],
  },
  dns: {
    'ok': ['问得出名字', 'ok'], 'no-server': ['系统没配 DNS', 'bad'],
    'error': ['解析失败', 'bad'], 'no-record': ['一条记录都问不出', 'bad'],
    'no-v4-record': ['v4 问空了', 'warn'],
  },
  egress: {
    'ok': ['出得去', 'ok'], 'v6-egress-broken': ['IPv6 出得去一半', 'warn'],
    'v4-egress-broken': ['IPv4 出得去一半', 'warn'],
    'broken': ['出不了外网', 'bad'], 'not-asked': ['没问', ''],
  },
  mtu: {
    'ok': ['正常', 'ok'], 'small': ['偏小', 'warn'],
    'tunnel': ['走隧道口，那样是对的', 'ok'], 'unknown': ['没读到', ''],
  },
  clock: {
    'ok': ['对得上', 'ok'], 'skew': ['有点偏', 'warn'],
    'big-skew': ['偏得太多', 'bad'], 'not-asked': ['没问到', ''],
  },
  proxy: {
    'none': ['没设代理', 'ok'], 'set': ['走了代理', 'warn'],
    'unsupported': ['这台读不到', ''],
  },
};

const ckFam = (f, fn) => ['ipv4', 'ipv6'].filter((k) => f && f[k])
  .map((k) => `<div><b class="dim">${k === 'ipv4' ? 'IPv4' : 'IPv6'}</b> ${fn(f[k])}</div>`).join('');

const ckLoss = (n) => (n || n === 0 ? `丢 ${Math.round(n)}%` : '');

// 事实那一列：只把后端给的数摊开，不在这里下判断。
function ckFacts(step, f) {
  if (!f) return '<span class="dim">—</span>';
  switch (step) {
    case 'iface': {
      const names = f.withAddress || [];
      return `${f.nics || 0} 块网卡 · 启用 ${f.up || 0} · 有链路 ${f.running || 0} · `
        + (names.length ? `有地址：<code>${esc(names.join('、'))}</code>`
                        : '<span class="dim">没有一块网卡有可用地址</span>');
    }
    case 'route':
      return ckFam(f, (x) => (x.hasRoute
        ? `→ <code>${esc(x.gateway || '无下一跳')}</code> 经 ${esc(x.iface || '?')}`
          + (x.count > 1 ? ` <span class="dim">（共 ${x.count} 条）</span>` : '')
        : '<span class="dim">没有默认路由</span>'));
    case 'gateway':
      return ckFam(f, (x) => pillOf(CK_CODE.gateway, x.code)
        + (x.sent
          ? ` 到 <code>${esc(x.gateway)}</code> 发了 ${x.sent} 发 · ${ckLoss(x.lossPercent)}`
            + ` · 中位 ${ms(x.rttMedianMs)} · 抖动 ${ms(x.jitterAvgMs)}`
            + (x.unreachable ? ` · 明确不可达 ${x.unreachable} 发` : '')
          : (x.gateway ? ` 目标 <code>${esc(x.gateway)}</code>` : '')));
    case 'dns': {
      const srv = (f.servers || []).map((s) => `${esc(s.addr)}${s.iface ? '（' + esc(s.iface) + '）' : ''}`).join('、');
      const at = (list) => {
        const cells = (list || []).map((a) => `<code>${esc(a.addr)}</code> ${pillOf(DS_CONN, a.code)}`
          + ` <span class="dim">${ms(a.rttMs)}</span>`).join('　');
        return cells || '<span class="dim">没有</span>';
      };
      return `<div>${srv ? '问 ' + srv : '<span class="dim">系统里没配 DNS 服务器</span>'}
        · <code>${esc(f.domain || '')}</code>${f.lookupMs ? ' 解析 ' + ms(f.lookupMs) : ''}${f.error ? ' · ' + esc(f.error) : ''}</div>
        <div>A：${at(f.v4)}</div><div>AAAA：${at(f.v6)}</div>`;
    }
    case 'egress':
      return ckFam(f, (x) => pillOf(DS_CONN, x.egress)
        + ` <code>${esc(x.target || '')}</code>${x.rttMs ? ' ' + ms(x.rttMs) : ''}`
        + (x.present ? '' : ' <span class="dim">这一族不在场</span>'));
    case 'mtu': {
      const others = (f.nics || []).filter((n) => n.iface !== f.egressIface).slice(0, 5)
        .map((n) => `${n.iface} ${n.mtu}${n.virtual ? '（隧道）' : ''}`).join('、');
      return `出口 <code>${esc(f.egressIface || '未识别')}</code> MTU <b>${f.egressMtu || '—'}</b>`
        + (f.egressKind ? ` <span class="dim">${esc((KIND[f.egressKind] || [f.egressKind])[0])}</span>` : '')
        + (others ? ` <span class="dim">其它：${esc(others)}</span>` : '');
    }
    case 'clock': {
      const off = f.offsetMs;
      const has = off || off === 0;
      return `问 <code>${esc(f.server || '')}</code> · 回了 ${f.answers || 0}/${f.samples || 0} 包`
        + (has ? ` · <b>${off >= 0 ? '本机慢' : '本机快'} ${esc(humanMs(Math.abs(off)))}</b>` : '')
        + (f.rttMs ? ` · 往返 ${ms(f.rttMs)}` : '')
        + (f.serverTime ? `<div class="dim">它说 ${esc(fmtStamp(f.serverTime))} · 本机 ${esc(fmtStamp(f.localTime))}</div>` : '');
    }
    case 'proxy': {
      const e = f.entries || [];
      if (e.length) return e.map((x) => `<code>${esc(x)}</code>`).join('　');
      return f.scutilError ? `<span class="dim">读取代理设置失败：${esc(f.scutilError)}</span>`
                           : '<span class="dim">没读到任何代理条目</span>';
    }
  }
  return '<span class="dim">—</span>';
}

// 一行体检项。★ 「先修 / 先看这一步」只贴在顶层点名的那一步上 ——
// 八行里后面那些坏的是被它带出来的，贴成一样的颜色就等于没给出顺序。
function ckRow(it, i, first) {
  const map = CK_CODE[it.step] || {};
  const [text, tone] = map[it.code] || [it.code || '—', ''];
  const flag = it.step === first && first
    ? `<span class="pill ${it.severity === 'bad' ? 'bad' : 'warn'}">${it.severity === 'bad' ? '先修这一步' : '先看这一步'}</span>`
    : '';
  return `<tr><td class="dim">${i + 1}</td>
    <td>${esc(CK_STEP[it.step] || it.step)} ${flag}</td>
    <td><span class="pill ${tone}">${esc(text)}</span></td>
    <td>${ckFacts(it.step, it.facts)}</td></tr>`;
}

function checkupCard() {
  const card = $(`<div class="card">
    <h2>一键体检 <span id="cku-top"></span></h2>
    <p class="hint">什么都不用填，按老手的排查顺序把这台机器过一遍：网卡 → 默认路由 → 到网关丢不丢 →
      解析 → 出外网 → MTU → 时钟 → 系统代理。<b>八项并行，两三秒出结果</b>，只发少量探测包、不改动任何东西。
      ★ 顶层只说<b>第一个坏掉的是哪一步</b>，因为后面那些数是带着这个毛病测出来的 —— 从中间开始查，一定会查错方向。</p>
    <details style="margin-top:8px"><summary class="dim">高级：换体检用的域名 / NTP 源 / 到网关发几发</summary>
      <div class="row" style="margin-top:10px">
        <div><label>域名（公网不通时换内网里一定解析得到的名字）</label><input id="cku-d" placeholder="默认 www.cloudflare.com"></div>
        <div><label>NTP 源（内网有自己的时钟源就填它）</label><input id="cku-n" placeholder="默认 pool.ntp.org"></div>
        <div style="flex:0 0 150px"><label>到网关发几发</label><input id="cku-p" placeholder="默认 6（3 到 20）"></div>
      </div>
    </details>
    <div style="margin-top:12px"><button class="btn primary" id="cku-go">开始体检</button></div>
    <div id="cku-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#cku-out');
  const top = card.querySelector('#cku-top');
  card.querySelector('#cku-go').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">体检中…（八项并行，约 3 秒）</div>';
    const args = {};
    const d = card.querySelector('#cku-d').value.trim();
    const n = card.querySelector('#cku-n').value.trim();
    const p = Number(card.querySelector('#cku-p').value);
    if (d) args.domain = d;
    if (n) args.ntpServer = n;
    if (p) args.lanProbes = p;
    const r = await call('net.checkup', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">体检失败：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const items = v.items || [];
    const [title, cls, advice] = CK_TOP[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}</div>
      <table style="margin-top:14px">
        <tr><th></th><th>按排查顺序</th><th>判定</th><th>看到的事实</th></tr>
        ${items.map((it, i) => ckRow(it, i, v.first)).join('')}
      </table>
      <p class="hint" style="margin-top:10px">★ 只有 v4/v6 分开给的两项（到网关、出外网）才算得清「有一族出得去一半」——
        那种机器不会断网，但每次连接都慢半拍。</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/*
 * ── 端口占用反查 ──
 *
 * ★★ 「这个端口被谁占了」问的其实是「我要不要动手」，所以四种结论各配一段话：
 *   occupied      —— 要腾口就得停它，但先分清是不是那个服务的守护进程
 *   outbound-only —— 那是本机当客户端连出去留下的临时口，停它等于掐自己的会话
 *   free          —— 真没人用（只对本机成立，别人的用户 / 容器还要管理员权限）
 *   partial       —— 只读到一部分：这一栏最要紧的就是不许被读成 free
 *   判定由后端给，这里只把人话和「下一步」写出来。
 */
const PP_CODE = {
  occupied: ['有人正在听这个口', 'bad',
    '要腾这个口就得停掉列出来的那个进程。★ 停之前先确认它是不是你要起的那个服务的守护进程 —— '
    + '有的服务由 xinetd / launchd 这类父进程拉起，停父的没用，停子的马上又被拉起来。'],
  'outbound-only': ['不是被占着，是本机连出去留下的口', 'warn',
    '这个本地端口上没有任何监听，列出来的是本机当客户端连出去时内核顺手占住的临时端口。'
    + '★ 去停它等于把正在跑的会话掐断，而且你要起的服务照样起不来。'
    + '如果报「地址已在使用」，接着查 IPv6 上的同一个口 —— v6only 和双栈绑定不是一回事。'],
  free: ['这个口没人用', 'ok',
    '本机没有任何进程在听它，也没有本机发起的连接在用它。★ 这一句只对本机成立 —— '
    + '要是服务起不来并报「地址已在使用」，多半是另一个用户或容器命名空间占的口，那要用管理员权限再问一次。'],
  partial: ['只读到一部分，不能下结论', 'bad',
    '看不到那些进程不等于没在听 —— 非管理员读不到别人进程的句柄。'
    + '★ 用管理员权限再问一次才算数，别把这一栏当「没人用」。'],
  listening: ['本机在听这些口', 'ok',
    '这里只列监听，也就是这台机器对外提供的服务；本机连出去占用的临时端口没算进来。'
    + '★ 想看某个口的全部用途，把端口号填进去再问一次。'],
  'no-listener': ['一个监听都没有', 'warn',
    '这台机器现在不对外提供任何服务 —— 从别的机器看过来，它所有端口都是关着的。'],
  unsupported: ['这个平台读不到', '',
    '这个操作系统上没有可靠的「端口 → 进程」读法。★ 读不到不等于没人占用，所以这里不去猜一个答案 —— '
    + '要查请在这台机器上用系统自带的工具。'],
};

function ppRow(u) {
  const fam = u.family === 'ipv6' ? '6' : u.family === 'ipv4' ? '4' : '';
  // ★ 没有 PID 和「有 PID 却看不到名字」是两件事：前者是内核自己占着
  //   （TIME_WAIT 那类，本来就没有主人），后者才是权限不够。
  //   写成一句，会让人白跑一趟 sudo。
  const svc = u.pid ? (u.process ? `<code>${esc(u.process)}</code>`
                                 : '<span class="dim">看不到（权限不够）</span>')
                   : '<span class="dim">内核（连接留下的，还在等时租）</span>';
  // ★ UDP 那条提示只对 UDP 用：TCP 三个读法都给得出状态，真给不出时留空，
  //   别把「不知道」写成一句听着像结论的话。
  const state = u.state ? esc(u.state)
    : (u.proto === 'udp' ? '<span class="dim">绑上了（UDP 没有监听状态）</span>' : '<span class="dim">—</span>');
  const peer = u.foreign ? `<div class="dim">→ ${esc(u.foreign)}</div>` : '';
  return `<tr><td>${esc(u.proto)}${fam}</td>
    <td><code>${esc(u.local || '*')}</code>:<b>${u.port}</b>${peer}</td>
    <td>${state}</td>
    <td>${svc}${u.user ? ` <span class="dim">${esc(u.user)}</span>` : ''}</td>
    <td>${u.pid ? u.pid : '<span class="dim">—</span>'}</td></tr>`;
}

function portProcCard() {
  const card = $(`<div class="card">
    <h2>这个端口被谁占了 <span id="pp-top"></span></h2>
    <p class="hint">读本机内核的端口表，把「有进程在听」「本机连出去留下的临时口」「真没人用」「只读到一部分」
      分开答 —— 这四种的下一步完全不同，而探端口只能从外面看，看不出本机里是谁占着。
      ★ 只给进程名和 PID，不给命令行（命令行里常有口令，而结果会发给 AI）。纯读本机，不发任何包。</p>
    <div class="row">
      <div style="flex:0 0 200px"><label>端口号（留空 = 列出全部在听的）</label><input id="pp-port" placeholder="554"></div>
      <div style="flex:0 0 150px"><label>协议</label><select id="pp-proto">
        <option value="both">TCP 和 UDP</option><option value="tcp">只看 TCP</option>
        <option value="udp">只看 UDP</option></select></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn primary" id="pp-go">查</button></div>
    </div>
    <p class="hint" style="margin-top:8px">★ 查 UDP 要单独选一下：很多服务的口在 TCP 上根本没有，
      而 UDP 没有「监听」这个状态位 —— 绑上就算。</p>
    <div id="pp-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#pp-out');
  const top = card.querySelector('#pp-top');
  card.querySelector('#pp-go').onclick = async () => {
    const args = {};
    const p = Number(card.querySelector('#pp-port').value.trim());
    if (p) args.port = p;
    const proto = card.querySelector('#pp-proto').value;
    if (proto !== 'both') args.proto = proto;
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">读本机端口表…（要扫一遍进程句柄，一两秒）</div>';
    const r = await call('net.port.process', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">查不了：${esc(r.message || r.error)}</div>`; return; }
    const v = r.values;
    const [title, cls, advice] = PP_CODE[r.verdict] || [r.verdict || '没给判定', '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const rows = [...(v.listening || []), ...(v.connections || [])];
    const listed = (v.listening || []).length;
    const total = v.listenerCount || listed;
    // ★ 没读成功（unsupported）时一行计数都不给 —— 那时候任何「在听 0 个」都是假结论。
    const warn = v.partial ? ' · <b>只读到一部分，看不到不等于没有</b>' : '';
    let head = '';
    if (v.port) {
      head = `<p class="hint" style="margin-top:12px">这个口上共 ${v.count} 条记录`
        + `（其中在听的 ${total} 个${v.proto ? `，只看 ${v.proto.toUpperCase()}` : ''}）${warn}</p>`;
    } else if (v.count !== undefined) {
      head = `<p class="hint" style="margin-top:12px">本机在听 ${total} 个端口`
        + (v.truncated ? `，这里只列出前 ${listed} 个（还有 ${total - listed} 个没列，填上端口号再问）` : '')
        + (v.totalRead ? ` · 本机一共在用 ${v.totalRead} 个套接字` : '') + warn + '</p>';
    }
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}</div>
      ${rows.length ? `<table style="margin-top:14px">
        <tr><th>协议</th><th>本机地址</th><th>状态</th><th>进程</th><th>PID</th></tr>
        ${rows.map(ppRow).join('')}</table>${head}` : head}
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

// ★ 每个码带一句「下一步往哪查」—— 这三类问题的处理办法完全不同，
//   只写「解析失败」等于把人送回原地。
const DNS_CODE = {
  resolved: ['解析到记录', 'ok', ''],
  'no-record': ['域名在，但没有这类记录', 'warn',
    '这是 NODATA：域名存在，只是没配你要的这类记录（比如只配了 A、没配 AAAA）。不是故障。'],
  nxdomain: ['域名不存在', 'bad', '服务器明确说这个域名没有 —— 先核对是不是拼错了。'],
  'server-failure': ['服务器自己查不到', 'bad',
    'SERVFAIL 是服务器那一边的问题（它的上游或转发坏了），换一台服务器大概率就能出结果。'],
  refused: ['服务器拒绝查询', 'bad', '这台解析器不给递归查询（常见于只服务内网的 DNS），换一台公共 DNS 再问。'],
  timeout: ['没有任何回应', 'bad',
    '分不清是服务器挂了、53 端口被拦、还是没有路由。换成问 8.8.8.8 或网关，能分清是哪一层。'],
  unreachable: ['连不上这台服务器', 'bad', '连地址都到不了 —— 先确认这台 DNS 在不在本网、有没有路由。'],
  'bad-response': ['回的不是 DNS 报文', 'bad', '这个端口后面大概不是 DNS 服务。'],
};

function dnsCard() {
  const card = $(`<div class="card">
    <h2>DNS 查询 <span id="dqv"></span></h2>
    <p class="hint">点名问一台 DNS 服务器，看它回什么。★ 现场有一大类问题是「网络是好的，就是解析不对」，
      而它又分三种：服务器没回、它说查不到、答案本身不对（劫持 / 配了内网 DNS 却在查公网）—— 处理办法完全不同。</p>
    <div class="row">
      <div><label>域名（查 PTR 就填 IP）</label><input id="dqn" placeholder="www.example.com"></div>
      <div><label>记录类型</label><select id="dqt">
        <option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option>
        <option>TXT</option><option>NS</option><option>SOA</option><option>PTR</option><option>SRV</option>
      </select></div>
      <div><label>问哪台服务器（留空=系统配的）</label><input id="dqs" placeholder="192.168.1.1 或 223.5.5.5"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label><button class="btn primary" id="dqgo">查询</button></div>
    </div>
    <div id="dqout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#dqout');
  const v = card.querySelector('#dqv');
  card.querySelector('#dqgo').onclick = async () => {
    v.innerHTML = '';
    out.innerHTML = '<div class="empty">查询中…</div>';
    const args = { name: card.querySelector('#dqn').value.trim(), type: card.querySelector('#dqt').value };
    const srv = card.querySelector('#dqs').value.trim();
    if (srv) args.server = srv;
    if (!args.name) { out.innerHTML = '<div class="empty">先填要查的域名或 IP。</div>'; return; }
    const r = await call('net.dns.query', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">查不了：${esc(r.message)}</div>`; return; }
    const [text, cls, advice] = DNS_CODE[r.verdict] || [r.verdict, '', ''];
    v.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const val = r.values;
    const sys = (val.systemServers || []).map((s) => `${s.addr}${s.iface ? '（' + s.iface + '）' : ''}`).join('、');
    const rows = (val.answers || []).map((a) => `<tr><td class="dim">${esc(a.type)}</td>
        <td><code>${esc(a.value)}</code></td><td class="dim">TTL ${a.ttl}</td></tr>`).join('');
    const chain = (val.cnameChain || []).map((c) => `<div class="dim"><code>${esc(c)}</code></div>`).join('');
    out.innerHTML = `
      ${advice ? `<p class="hint">${esc(advice)}</p>` : ''}
      <p class="hint">问的 <code>${esc(val.server)}</code>${val.via === 'tcp' ? '（UDP 被截断，改走 TCP）' : ''}
        · 用时 ${val.elapsedMs}ms · rcode ${esc(val.rcode || '')}${sys ? ` · 系统配的 DNS：${esc(sys)}` : ''}</p>
      ${chain ? `<p class="hint">CNAME 链：${chain}</p>` : ''}
      ${rows ? `<table><tr><th>类型</th><th>值</th><th></th></tr>${rows}</table>`
             : '<div class="empty">这台服务器没给任何答案。</div>'}`;
  };
  return card;
}

/*
 * ── 证书检查 ──
 *
 * ★★ 现场有四件事全都长成「打不开 / 不安全」一句话，处理办法却互相冲突：
 *   证书过期、名字和地址不一致、自签没进信任列表、设备只支持 TLS1.0。
 *   浏览器只给一句红字，工程师得自己拆开。这一页替人拆。
 * ★ 后端只出判定码，码 → 人话在这里（多语种靠的就是这条分工）。
 */

const CERT_CODE = {
  'cert-ok': ['证书正常', 'ok', '证书没过期、名字对得上、本机也认这条链 —— 网页打不开的话，原因不在证书上，往服务和网络上查。'],
  'cert-expired': ['证书已过期', 'bad', '必须重新签发一张。过期之后所有客户端都会拒绝，重装应用、清缓存都没用。'],
  'cert-not-yet-valid': ['证书还没到生效时间', 'bad',
    '这条几乎从来不是证书的错，是这台设备的时钟不对（掉电后重置回几年前那种）。先校时，再回来看证书。'],
  'cert-name-mismatch': ['证书上的名字和访问的地址对不上', 'bad',
    '要么改用证书上写着的名字访问，要么按现在这个地址重签一张。浏览器报 ERR_CERT_COMMON_NAME_INVALID 就是这一条。'],
  'cert-self-signed': ['自签证书', 'warn',
    '证书本身没过期，只是本机不认它这个根 —— 内网设备的出厂默认。要么把它的根证书装进本机信任列表，要么换一张正规签发的。'],
  'cert-unknown-authority': ['本机验不过这条链', 'warn',
    '签发者不在信任列表里：常见于设备上只放了叶子证书、缺中间证书，或者本机没装企业/设备的根证书。'],
  'cert-expiring-soon': ['快要到期了', 'warn', '现在换是顺手的事，等到现场发现打不开就是加班的事。'],
  'cert-weak-protocol': ['证书可用，但对方只支持老版本 TLS', 'bad',
    'TLS 1.0/1.1 已被新版浏览器和平台直接拒绝连接。要升级设备侧的 TLS 栈，换证书解决不了。'],
  'not-tls': ['这个端口回的不是 TLS', 'bad', '端口给错了 —— 它后面多半是明文 HTTP 或 RTSP，换对端口再来一次。'],
  'handshake-failed': ['连上了，但 TLS 没谈成', 'bad',
    '常见于双方的协议版本/加密套件没有交集，或者对端根本不是 TLS 服务。细节看 reason。'],
  'no-certificate': ['握手成功却没出示证书', 'warn', '用的是匿名加密套件（没有身份可验证），或者它不是按 HTTPS 出证的。'],
  'name-unresolved': ['域名解析不到地址', 'bad', '还没走到证书这一步 —— 先用上方的 DNS 查询把解析查通。'],
  'closed': ['端口关着', 'bad', '这个端口上没有 TLS 服务（对方明确拒绝，说明主机是在的）。'],
  'filtered': ['没有任何回应', 'bad', '分不清端口是关着还是被防火墙静默丢了。'],
  'unreachable': ['地址到不了', 'bad', '连路由都不通 —— 先确认地址填对了、和它之间有没有路。'],
};

// 逐个地址那行要短 —— 整句标题排成四行就没法看了。
const CERT_SHORT = {
  'closed': '端口关着', 'filtered': '没回应', 'unreachable': '到不了',
  'not-tls': '不是 TLS', 'handshake-failed': '没谈成',
};

function certCard() {
  const card = $(`<div class="card">
    <h2>证书检查 <span id="cv"></span></h2>
    <p class="hint">连一下对方的 TLS，把「打不开 / 连接不安全」拆成具体是哪一个：<b>过期</b> / <b>名字不匹配</b> /
      <b>自签未受信</b> / <b>设备只支持老 TLS</b>。★ 只握手、不读业务数据。用 IP 访问但想按域名核对证书时，把域名填在第三个框里。</p>
    <div class="row">
      <div><label>地址（域名或 IP，可带端口）</label><input id="cu" placeholder="192.168.1.64 或 cam.example.com:8443"></div>
      <div style="flex:0 0 100px"><label>端口</label><input id="cp" placeholder="443"></div>
      <div><label>按哪个名字核对</label><input id="cn" placeholder="证书上写的域名"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label><button class="btn primary" id="cgo">检查</button></div>
    </div>
    <div id="cout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#cout');
  const top = card.querySelector('#cv');
  card.querySelector('#cgo').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">握手中…</div>';
    const addr = card.querySelector('#cu').value.trim();
    if (!addr) { out.innerHTML = '<div class="empty">先填要检查的地址。</div>'; return; }
    const args = { addr };
    const p = Number(card.querySelector('#cp').value);
    const name = card.querySelector('#cn').value.trim();
    if (p) args.port = p;
    if (name) args.serverName = name;
    const r = await call('net.tls.check', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">检查不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = CERT_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    // 三项核对各自的脸色：名字不对是**必须改**的（换证书或换地址），
    // 不受信和自签只是本机没导入 —— 报成红色会把一件顺手的事说成故障。
    const flag = (b, yes, no, okCls = 'ok', badCls = 'bad') =>
      `<span class="pill ${b ? okCls : badCls}">${esc(b ? yes : no)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const names = [].concat(v.san || [], v.sanIP || []);
    const days = v.daysLeft === undefined ? ''
      : v.daysLeft < 0 ? `<span class="pill bad">已过期 ${-v.daysLeft} 天</span>`
        : `还剩 <b>${v.daysLeft}</b> 天`;
    const tries = (v.attempts || []).map((a) => `<div><code>${esc(a.address)}</code>
        <span class="pill ${CERT_CODE[a.code] ? CERT_CODE[a.code][1] : ''}">${esc(CERT_SHORT[a.code] || a.code)}</span>
        <span class="dim">${esc(a.detail || '')}</span></div>`).join('');
    // 没拿到证书的那些判定（端口关、不是 TLS、解析不到）就别摆一张空证书表
    const proto = v.protocol ? tCell('协议 / 套件', `<code>${esc(v.protocol)}</code> ·
        <code>${esc(v.cipherSuite || '—')}</code>${v.weakProtocol ? '<span class="pill bad">版本太老</span>' : ''}`) : '';
    const cert = v.subject ? `
        ${tCell('主体 / 签发者', `${esc(v.subject)} <span class="dim">←</span> ${esc(v.issuer || '—')}`)}
        ${tCell('有效期', `${esc(v.notBefore || '?')} <span class="dim">到</span> ${esc(v.notAfter || '?')} · ${days}`)}
        ${tCell('包括的名字', names.length ? names.map((n) => `<code>${esc(n)}</code>`).join(' ')
          : '<span class="dim">证书里没写备用名字（只有主题那一个）</span>')}
        ${tCell('三项核对', `${flag(v.hostnameMatch, '名字对得上', '名字不对')}
          ${flag(v.trusted, '本机认这条链', '本机不认', 'ok', 'warn')}
          ${flag(!v.selfSigned, '正规签发', '自签', 'ok', 'warn')}`)}
        ${v.chain && v.chain.length ? tCell('证书链',
          v.chain.map((c) => `<code>${esc(c)}</code>`).join(' <span class="dim">←</span> ')) : ''}` : '';
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}${v.reason ? `<div class="dim" style="margin-top:6px">${esc(v.reason)}</div>` : ''}</div>
      <table style="margin-top:14px">
        ${tCell('连到哪', `<code>${esc(v.target || '—')}</code>
          <span class="dim">${esc(v.family || '')}${v.hostname ? ' · 域名 ' + esc(v.hostname) : ''}</span>`)}
        ${proto}
        ${cert}
        ${tries ? tCell('逐个地址', tries) : ''}
      </table>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

// 网页探测的码 → 人话。★ 后端只给码，句子在这儿（多语种靠这条分工）。
const HTTP_CODE = {
  'http-ok': ['通了', 'ok', '状态码是 2xx。慢不慢看下面那行分段耗时 —— 卡在网络还是卡在服务端，处理的人完全不同。'],
  'http-redirect': ['它在跳转，还没到终点', 'warn',
    '全链在下面。★ 现场最常见的两种：http 没跳到 https（内容混拦，浏览器会提示不安全），或者跳到了一个本机到不了的内网地址。'],
  'http-client-error': ['请求本身的事（4xx）', 'warn',
    '服务是活着的、明确回了话，拒的是这个请求：地址不对、没登录、或者方法不让用。往地址和权限上查，别往网络上查。'],
  'http-server-error': ['服务端自己出错了（5xx）', 'bad',
    '网络这一趟是通的（它回话了），问题在它后面：程序异常、上游服务坏了、或者超出负载。'],
  'http-redirect-loop': ['重定向绕圈', 'bad',
    '跳到这一链里已经来过的地址，永远到不了终点。多为反向代理和站点互相把 http 改 https、https 又改回 http。'],
  'http-timeout': ['整条请求超时', 'bad',
    '哪一段没走完看下面的分段：耗时是 0 的那一段就是没走到的那一段。'],
  'not-http': ['这个端口回的不是 HTTP', 'warn',
    '多半是 RTSP、RTMP 或设备自己的私有协议 —— 视频流用「视频流」那一页探。'],
  'wrong-scheme': ['协议前缀写反了', 'warn',
    '★ 这不是故障：把地址开头的 http / https 换成另一个就能通。省得去查一个根本没坏的服务。'],
  'tls-handshake-failed': ['TLS 握手被对方拒了', 'bad',
    '常见于它要求客户端证书，或者双方的协议版本没有交集。细节看原始结果里的 detail。'],
  'name-unresolved': ['域名解析不到地址', 'bad', '还没走到连接这一步 —— 先用上方的 DNS 查询把解析查通。'],
  'closed': ['端口关着', 'bad', '对方明确拒绝：这个端口上没有 HTTP 服务（机器本身是活的）。'],
  'filtered': ['没有任何回应', 'bad', '分不清端口是关着还是被静默丢了 —— 换 net.ping 看主机在不在。'],
  'unreachable': ['地址到不了', 'bad', '连路由都不通，先确认地址填对了、和它之间有没有路。'],
};

// 分段耗时条：四段按各自占比铺颜色，一眼看出长的那截是谁。
// ★ 「慢在网络」和「慢在服务端」的分工就是这一页存在的全部理由，所以非要把比例画出来不可。
function timingBar(tm, answered) {
  const segs = [
    ['解析', tm.lookupMs, 'var(--gold-dim)'],
    ['连接', tm.connectMs, 'var(--green-dim)'],
    ['TLS', tm.tlsMs, 'var(--green-bg)'],
    ['服务端', tm.serverMs, 'var(--red-bg)'],
  ];
  const net = (tm.lookupMs || 0) + (tm.connectMs || 0) + (tm.tlsMs || 0);
  const app = tm.serverMs || 0;
  const rest = Math.max(0, (tm.totalMs || 0) - net - app);
  const parts = segs.concat([['其他', rest, 'var(--panel-2)']]);
  const total = Math.max(1, parts.reduce((s, [, ms]) => s + ms, 0));
  const bar = parts.filter(([, ms]) => ms > 0)
    .map(([name, ms, color]) =>
      `<div title="${esc(name)} ${ms}ms" style="flex:${ms};background:${color};
        display:flex;align-items:center;justify-content:center;font-size:11px;white-space:nowrap;overflow:hidden">
        ${ms >= total * 0.12 ? esc(name) : ''}</div>`).join('');
  const list = parts.filter(([, ms]) => ms > 0)
    .map(([name, ms]) => `${esc(name)} <b>${ms}</b>ms`).join(' <span class="dim">·</span> ');
  // 结论只在差距明显时给：两段差不多时硬要说谁慢，是拿一个 800ms 的样本编故事。
  // ★★ 更要紧的是**只在问到回话时给**：没走到终点的话 serverMs 天生是 0，
  //   这时候说「慢在网络侧」等于把「没回话」编成了一句归因，方向可能完全反了。
  let say = '';
  if (!answered) {
    // ★★ 没走到终点时**不做归因**：端口直接拒、TLS 谈崩、回话回一半超时，
    //   在数字上是同一种形状（后面几段都是 0）。硬说「慢在网络侧」会把人往错方向带，
    //   而上面那个判定条已经把是哪种情况说清楚了。
    say = `<span class="pill bad">没走到终点</span>
      <span class="dim">分段耗时停在哪儿，路就断在哪儿 —— 服务端那一段根本没开始计时，不做归因。</span>`;
  } else if (app >= net * 2 && app > 200) {
    say = `<span class="pill warn">慢在应用侧</span> <span class="dim">网络三段加起来 ${net}ms，服务端自己想 ${app}ms —— 找维护这个服务的人，网络这边没问题。</span>`;
  } else if (net >= app * 2 && net > 200) {
    say = `<span class="pill bad">慢在网络侧</span> <span class="dim">解析+连接+TLS 共 ${net}ms，服务端只想了 ${app}ms —— 往链路、TLS 握手和 DNS 上查。</span>`;
  }
  // 什么都没花到（比如端口直接关着）就别画一条空 bar —— 空条比没有条更像坏了
  const spent = parts.some(([, ms]) => ms > 0);
  if (!spent && !say) return '';
  return `${spent ? `<div style="display:flex;height:18px;border-radius:4px;overflow:hidden;background:var(--panel-2)">${bar}</div>
    <p class="hint" style="margin:8px 0 0">${list} <span class="dim">·</span> 总计 <b>${esc(tm.totalMs)}</b>ms
      ${tm.ttfbMs ? `（首字节 ${tm.ttfbMs}ms）` : ''}</p>` : ''}
    ${say ? `<p class="hint" style="margin:${spent ? '6px' : '0'} 0 0">${say}</p>` : ''}`;
}

function httpCard() {
  const card = $(`<div class="card">
    <h2>网页 / 接口探测 <span id="hv"></span></h2>
    <p class="hint">问一个 HTTP(S) 地址要状态码，并把耗时拆成 <b>解析 / 连接 / TLS / 等回话</b> 四段 ——
      前三段慢是网络的事，最后一段慢是服务端的事。★ 重定向链每一跳都留着（自动跟随会把「它 301 到哪儿」吃掉）。
      证书顺带判一次，但<b>不因证书坏就不给状态码</b>。不下载正文。</p>
    <div class="row">
      <div><label>地址</label><input id="hu" placeholder="192.168.1.64 或 https://cam.example.com/login"></div>
      <div style="flex:0 0 110px"><label>方法</label><select id="hm"><option>GET</option><option>HEAD</option></select></div>
      <div style="flex:0 0 110px"><label>最多跟几跳</label><input id="hr" placeholder="10，填 0 只看第一跳"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label><button class="btn primary" id="hgo">探测</button></div>
    </div>
    <div id="hout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#hout');
  const top = card.querySelector('#hv');
  card.querySelector('#hgo').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">请求中…</div>';
    const args = { url: card.querySelector('#hu').value.trim() };
    if (!args.url) { out.innerHTML = '<div class="empty">先填地址。</div>'; return; }
    const m = card.querySelector('#hm').value;
    if (m === 'HEAD') args.method = 'HEAD';
    const r = Number(card.querySelector('#hr').value);
    if (r >= 0 && card.querySelector('#hr').value.trim() !== '') args.maxRedirects = r;
    const res = await call('net.http.probe', args);
    if (!res.ok) { out.innerHTML = `<div class="empty">探测不了：${esc(res.message)}</div>`; return; }
    const v = res.values;
    const [text, cls, advice] = HTTP_CODE[res.verdict] || [res.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const chain = (v.redirects || []).map((h, i) => `<div>
        <span class="dim">#${i + 1}</span>
        <span class="pill ${h.status >= 200 && h.status < 300 ? 'ok' : h.status >= 500 ? 'bad' : h.status >= 400 ? 'warn' : ''}">${h.status}</span>
        <code>${esc(h.url)}</code>${h.location ? ` <span class="dim">→</span> <code>${esc(h.location)}</code>` : ''}
        <span class="dim">${h.ms}ms</span></div>`).join('');
    const t = v.tls;
    // 证书那块仍然用 CERT_CODE 的文案：同一套码，不在这儿再抄一遍
    const tlsRow = t ? tCell('证书', `<span class="pill ${(CERT_CODE[t.verdict] || ['', ''])[1]}">
        ${esc((CERT_CODE[t.verdict] || [t.verdict])[0])}</span>
      <span class="dim">${esc(t.protocol || '')} · ${esc(t.subject || '')}${
      t.daysLeft === undefined ? '' : t.daysLeft < 0 ? ` · 已过期 ${-t.daysLeft} 天` : ` · 剩 ${t.daysLeft} 天`}</span>`) : '';
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}${v.reason ? `<div class="dim" style="margin-top:6px">${esc(v.reason)}</div>` : ''}
        ${v.detail ? `<div class="dim" style="margin-top:6px"><code>${esc(v.detail)}</code></div>` : ''}</div>
      ${v.timings ? `<div style="margin-top:14px">${timingBar(v.timings, v.status)}</div>` : ''}
      <table style="margin-top:14px">
        ${tCell('结果', `<span class="pill ${cls}">${esc(v.status || text)}</span>
          <code>${esc(v.method || 'GET')} ${esc(v.url)}</code>
          <span class="dim">${esc(v.proto || '')}${v.server ? ' · ' + esc(v.server) : ''}
            ${v.contentType ? ' · ' + esc(v.contentType) : ''}
            ${v.contentLength ? ' · ' + esc(v.contentLength) + ' 字节' : ''}</span>`)}
        ${v.remote ? tCell('实际连到', `<code>${esc(v.remote)}</code>
          <span class="dim">域名两族都有记录时，这一条决定该往 v4 还是 v6 查</span>`) : ''}
      </table>
      ${chain ? `<p class="hint" style="margin:12px 0 4px">重定向链${v.redirectCount ? `（跟了 ${v.redirectCount} 跳）` : ''}</p>
        <div style="font-size:13.5px;line-height:1.9">${chain}</div>` : ''}
      ${tlsRow ? `<table>${tlsRow}</table>` : ''}
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/*
 * ── 路径追踪 ──
 *
 * ★★ 和双栈体检是互补的两件事：体检答「这一族出不出得了外网」，追踪答「出得去的话路有多长、
 *   断在哪一跳」。现场拿到「上不去」之后问的下一句几乎都是这个。
 * ★ 逐跳的 * 一定要画出来：中间丢两跳是常态，只有把「没回」和「回了但很慢」分开摆，
 *   人才看得懂「断在哪」和「这次没看出来」的区别。
 * ★ 后端只出判定码，码 → 人话在这里（多语种靠这条分工）。
 */

const TRACE_CODE = {
  'path-ok': ['这条路走得通', 'ok',
    '每一族的追踪都到了终点。慢不慢看下面逐跳的往返 —— 某一跳突然变大，就是那里。到了终点还上不了服务，那是端口或服务的事，换「网页 / 接口探测」。'],
  'path-partial': ['一族到、另一族断在半路', 'bad',
    '★ 双栈机器上最贵的一种漏报：应用往往优先走 IPv6，就先卡在那条上。下面两族并排，断的那族写着停在哪台设备。'],
  'path-broken': ['两族都没走到终点', 'bad',
    '断在哪一跳、停在哪台设备上，见下面逐跳。先处理写着「本机没路」或「断在中间」的那一族。'],
  'path-incomplete': ['结论不全，别急着查网络', 'warn',
    '有一族没给出结论：可能是这台机器缺追踪命令，也可能只是跳数或时间用完 —— 那两种都该调参数或换机器，而不是去查一条没坏的路。看下面各族自己那一行。'],
  'reached': ['走到了终点', 'ok', ''],
  'stalled': ['断在中间某跳', 'bad',
    '最后一台有回应的设备之后，再没人回过话。停在哪台下面写着。'],
  'no-response': ['第一跳就没回应', 'warn',
    '★ 这**不说明路断了**：路由器不回应 ICMP 超时时，整条路都是这个形状，目标可能好好的。改用 ping / 探端口确认到不到得了终点。'],
  'max-hops': ['跳数用完了', 'warn',
    '一路都有回应、只是没走到终点。该做的是把上面的「最多几跳」调大再看，不是查网络。'],
  'no-route': ['本机这一族没有出路', 'bad',
    '探测包在这台机器上就发不出去 —— v6 被关的招牌表现。查这一族的网卡地址和默认路由，用上方「双栈体检」。'],
  'needs-privilege': ['命令要管理员权限', 'warn',
    '追踪要发原始探测包。以管理员身份再跑一次；Linux 上可换 tracepath，普通用户就能跑。'],
  'trace-timeout': ['整条追踪超时', 'warn',
    '已经走到的跳在下面，并标了「不完整」。哪一族在耗时间，看它有没有跳出第一跳；要更久的话把上面的超时调大。'],
  'no-command': ['这台机器没有可用的追踪命令', 'warn',
    '★ 这是工具没有，不是路上没设备 —— 装 traceroute 或换台机器再追，别去查网络。'],
  'name-unresolved': ['域名解析不到地址', 'bad', '还没走到追路径这一步 —— 先用上方的 DNS 查询把解析查通。'],
};

const TRACE_SHORT = {
  'reached': '到了终点', 'stalled': '断在中间', 'no-response': '没回应',
  'max-hops': '跳数用完', 'no-route': '本机没路', 'needs-privilege': '要权限',
  'trace-timeout': '超时', 'no-command': '没命令',
};

// 逐跳画成一排小方块：丢的跳留灰块，别让它从图上消失 ——
// 只画回了的那些，人就看不出「其实第 3、4 跳根本没吭声」。
function traceRail(hops) {
  const chips = hops.map((h) => {
    const rtt = (h.rttMs || []).length
      ? `${Math.min(...h.rttMs).toFixed(1)}ms` : '不回';
    const bg = h.isGoal ? 'var(--green-bg)' : h.addr ? 'var(--panel-2)' : 'var(--gold-bg)';
    const line = h.isGoal ? 'var(--green-dim)' : h.addr ? 'var(--gold-dim)' : 'var(--red-line)';
    return `<div title="${esc(h.addr || '这一跳没回应')}${h.mark ? ' · ' + esc(h.mark) : ''}"
      style="background:${bg};border:1px solid ${line};border-radius:5px;padding:5px 8px;min-width:96px;font-size:12.5px">
      <span class="dim">#${h.hop}</span>
      <code>${esc(h.addr || '—')}</code>
      <span class="${h.addr ? 'dim' : 'pill warn'}">${esc(rtt)}</span>
      ${h.lost ? `<span class="dim" title="这一跳发了几个、丢了几个">丢${h.lost}</span>` : ''}
      ${h.mark ? `<span class="pill bad">${esc(h.mark)}</span>` : ''}
      ${h.isGoal ? '<span class="pill ok">终点</span>' : ''}</div>`;
  }).join('');
  return `<div style="display:flex;flex-wrap:wrap;gap:6px">${chips}</div>`;
}

function traceFamilyBlock(f) {
  const [text, cls] = TRACE_CODE[f.code] || [f.code, ''];
  const hops = f.hops || [];
  // ★ 没跳的时候怎么说，要按**为什么**没跳分开：
  //   本机没路 / 缺命令 / 要权限时一句「一个跳都没回来」会被读成「这条路是空的」，
  //   而真实情况是压根没开始走 —— 那种情况交给下面那行原因说。
  //   只有真的发出去了、一个都没回（no-response），才需要把「全黑」这件事讲出来。
  const rail = hops.length ? traceRail(hops)
    : f.code === 'no-response'
      ? '<p class="hint"><span class="pill warn">一个都没回</span> <span class="dim">探测发出去了，从第一跳起没人吭声。</span></p>'
      : '';
  const stop = f.lastAddr
    ? `<span class="dim">停在</span> <code>${esc(f.lastAddr)}</code> <span class="dim">第 ${f.hopsSeen} 跳</span>` : '';
  const extra = f.detail || f.tried
    ? `<div class="dim" style="margin-top:6px;font-size:12.5px">${esc([f.detail, f.tried].filter(Boolean).join(' ｜ '))}</div>` : '';
  return `<div style="margin-top:14px">
    <p style="margin:0 0 8px">
      <b>${esc((f.family || '').toUpperCase())}</b>
      <span class="pill ${cls}">${esc(TRACE_SHORT[f.code] || text)}</span>
      ${f.partial ? '<span class="pill warn">不完整</span>' : ''}
      ${stop}
      <span class="dim"> · ${esc(f.command || '')}</span></p>
    ${rail}
    ${extra}</div>`;
}

function traceCard() {
  const card = $(`<div class="card">
    <h2>路径追踪 <span id="tv"></span></h2>
    <p class="hint">走到目标要经过哪几台设备、<b>断在哪一跳</b>。★ 默认 IPv4、IPv6 各追一遍并排给结果 ——
      现场最常见的正是「一族到、另一族断在半路」。中途个别跳不全是常态，卡片不会据此说路断了；
      整条都不回（路由器限速 ICMP）会单独标成「没回应」，而不是「断在第一跳」。用的哪条命令如实写出来。</p>
    <div class="row">
      <div><label>目标（域名或 IP）</label><input id="th" placeholder="192.168.1.1 或 camera.example.com"></div>
      <div style="flex:0 0 110px"><label>地址族</label>
        <select id="tf"><option value="auto">两族都追</option><option value="v4">只追 v4</option><option value="v6">只追 v6</option></select></div>
      <div style="flex:0 0 90px"><label>最多几跳</label><input id="tm" placeholder="30"></div>
      <div style="flex:0 0 90px"><label>每跳几个探测</label><input id="tq" placeholder="1"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label><button class="btn primary" id="tgo">追踪</button></div>
    </div>
    <div id="tout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#tout');
  const top = card.querySelector('#tv');
  card.querySelector('#tgo').onclick = async () => {
    top.innerHTML = '';
    const host = card.querySelector('#th').value.trim();
    if (!host) { out.innerHTML = '<div class="empty">先填目标地址。</div>'; return; }
    out.innerHTML = '<div class="empty">追踪中…（最长 1 分钟，两族各分一半时间）</div>';
    const args = { host, family: card.querySelector('#tf').value };
    const n = Number(card.querySelector('#tm').value);
    const q = Number(card.querySelector('#tq').value);
    if (n > 0) args.maxHops = n;
    if (q > 0) args.perHop = q;
    const r = await call('net.trace', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">追不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = TRACE_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}</div>
      ${(v.traces || []).map(traceFamilyBlock).join('')}
      <p class="hint" style="margin-top:12px"><span class="dim">引擎：${esc(v.engine || '')}</span></p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/*
 * ── 持续路径质量（MTR 式）──
 *
 * ★★ 这一栏存在的理由是：单跑一次 traceroute 全绿，**不能**说这条路没问题。
 *   「画面隔十几秒花一格」「传两分钟断一下」这种主诉，只有把同一批跳连着问几十次才看得见。
 * ★ 光把每一跳的丢包率列出来是没用的，甚至会误导：中间设备普遍对 TTL 超时的 ICMP 做限速，
 *   表上就是一行 100% 丢包，而它后面的每一跳都收得到 —— 那说明被转发的流量它一个都没丢。
 *   所以这一栏把「这一跳丢的是它自己的回应」和「丢包从这里一路延续到终点」用两种颜色分开画。
 * ★ 后端只出判定码和每跳注记，句子在这里（多语种靠这条分工）。
 */

const MTR_CODE = {
  'quality-ok': ['这条路一直很好', 'ok', '每一跳的丢包和往返都在正常范围里。要是还是觉得卡，那多半不是这条路径的事 —— 换「网页 / 接口探测」看服务自己慢不慢。'],
  'quality-silent-loss': ['中间有设备不回探测，但路是通的', 'warn',
    '★ 看着吓人的那一行是**这台设备不爱回话**，不是它丢包：它后面的每一跳都收得到。家用和园区网的路由器普遍给 ICMP 超时做限速。要修的是探测能不能问到自己，不是这条路。'],
  'quality-path-changed': ['同一跳出现过不止一个地址', 'warn',
    '多为等价路径负载分担（本来就这样），或者是路由在翻动。翻动本身不卡人，**每次换到一条更烂的路**才会 —— 对照下面的丢包和往返看。'],
  'quality-latency-jump': ['从某一跳起明显变慢，而且一直到终点都慢', 'bad',
    '抬升起点那一跳就是分界：它之前还是好的，之后一路都带上这份延迟。要查的是那一段链路（或者出口拥塞），不是终点自己。'],
  'quality-target-loss': ['中间的跳都正常，只有终点在丢', 'bad',
    '路是通的（每一跳都替它作证了），丢的是**到终点这最后一段**：终点自己在限速 ICMP、防火墙把它挡了，或者它真的忙不过来。先用 ping / 探端口确认它服不服务。'],
  'quality-loss': ['从某一跳起，丢包一路延续到终点', 'bad',
    '★ 这才是真的拥塞/故障点：下面标了从第几跳开始。中间某跳丢但后面能收到，不算这一条 —— 那种是它不爱回话。'],
  'quality-no-response': ['一个像样的样本都没拿到', 'warn',
    '★ 这**不说明路断了**：第一跳起就不回 ICMP（整条路都被限速）时就是这个形状。改用 ping / 探端口确认终点到不到得了。'],
  'no-route': ['本机这一族没有出路', 'bad', '探测包在这台机器上就发不出去 —— v6 被关的招牌表现。查这一族的地址和默认路由，用上方「双栈体检」。'],
  'needs-privilege': ['命令要管理员权限', 'warn', '持续逐跳探测要发原始包。以管理员身份再跑一次。'],
  'no-command': ['这台机器没有可用的探测命令', 'warn', '★ 这是工具没有，不是路上没设备 —— 装 traceroute 或 mtr，或换台机器再测。'],
  'trace-timeout': ['时间用完，只跑到一部分轮', 'warn', '已完成的轮都在下面。要更准的丢包率就调大「几轮」或超时，别调小。'],
  'name-unresolved': ['域名解析不到地址', 'bad', '还没到探测这一步 —— 先用上方的 DNS 查询把解析查通。'],
  // 两族并排时，有一族没跑成：结论只覆盖跑成的那族
  'path-incomplete': ['结论不全，别急着查网络', 'warn',
    '有一族压根没测成（缺命令或要权限）。跑成的那族结论在下面 —— 没测过的那族既不能说好也不能说坏。'],
};

const MTR_SHORT = {
  'quality-ok': '一直很好', 'quality-silent-loss': '假丢包', 'quality-path-changed': '路径在翻动',
  'quality-latency-jump': '某跳起变慢', 'quality-target-loss': '只有终点丢', 'quality-loss': '一路在丢',
  'quality-no-response': '没样本', 'no-route': '本机没路', 'needs-privilege': '要权限',
  'no-command': '没命令', 'trace-timeout': '时间不够',
};

// 每跳的注记 → 那行的颜色和那一句话。★ 注记是后端给的**判定**，不是样式提示。
const MTR_FLAG = {
  'loss-source': ['bad', '丢包从这里开始，并且一路带到了终点'],
  'target': ['bad', '只有它在丢：中间的跳都收到了'],
  'silent': ['warn', '只丢自己的回应，转发的流量它一个没丢'],
  'latency-start': ['warn', '往返从这里开始抬升，并延续到终点'],
  'path-moved': ['', '这一跳见过不止一个下一跳'],
  'healthy': ['', ''],
};

function mtrLossCell(h) {
  const pct = h.lossPct || 0;
  const cls = (h.flag === 'loss-source' || h.flag === 'target') ? 'bad' : h.flag === 'silent' ? 'warn' : '';
  const color = cls === 'bad' ? 'var(--red-bg)' : cls === 'warn' ? 'var(--gold-bg)' : 'var(--green-dim)';
  const bar = `<div style="height:6px;border-radius:3px;background:var(--panel-2);min-width:56px">
      <div style="height:6px;width:${Math.max(2, Math.min(100, pct))}%;border-radius:3px;background:${color}"></div></div>`;
  // ★ 分母必须露出来：只写「12.5%」，人不知道那是 8 个里丢 1 个还是 80 个里丢 10 个，
  //   而这两种是完全不同的事。
  return `<div style="display:flex;align-items:center;gap:8px">${bar}
    <span class="${cls ? 'pill ' + cls : 'dim'}">${pct}%</span>
    <span class="dim">${h.lost}/${h.snt}</span></div>`;
}

function mtrFamilyBlock(f) {
  const [text, cls] = MTR_CODE[f.code] || [f.code, ''];
  const rows = (f.hops || []).map((h) => {
    const [fcls, fnote] = MTR_FLAG[h.flag] || ['', ''];
    const who = h.addr ? `<code>${esc(h.addr)}</code>` : '<span class="dim">不回</span>';
    const moved = h.addrs && h.addrs.length > 1
      ? `<div class="dim" style="font-size:12px">还见过 ${esc(h.addrs.filter((a) => a !== h.addr).join('、'))}</div>` : '';
    const goal = h.isGoal ? '<span class="pill ok">终点</span>' : '';
    return `<tr${h.flag === 'loss-source' || h.flag === 'target' ? ' class="fresh"' : ''}>
      <td>${h.hop}${goal}</td>
      <td>${who}${moved}</td>
      <td>${mtrLossCell(h)}</td>
      <td>${h.avgMs || h.avgMs === 0 ? esc(h.avgMs) + 'ms' : '—'}</td>
      <td>${h.worstMs ? esc(h.worstMs) + 'ms' : '—'}</td>
      <td class="${fcls === 'bad' ? 'pill bad' : fcls === 'warn' ? 'pill warn' : 'dim'}"
          style="background:none;border:none;padding:0">${esc(fnote)}${h.mark ? ' ' + esc(h.mark) : ''}</td>
    </tr>`;
  }).join('');
  const head = f.detail || f.tried
    ? `<div class="dim" style="margin-top:6px;font-size:12.5px">${esc([f.detail, f.tried].filter(Boolean).join(' ｜ '))}</div>` : '';
  return `<div style="margin-top:14px">
    <p style="margin:0 0 8px">
      <b>${esc((f.family || '').toUpperCase())}</b>
      <span class="pill ${cls}">${esc(MTR_SHORT[f.code] || text)}</span>
      <span class="dim">${f.roundsDone}/${f.rounds} 轮 · ${esc(f.engine || '')}</span>
      ${f.partial ? '<span class="pill warn">不完整</span>' : ''}
      ${f.lossHop ? `<span class="pill bad">丢包起点 第 ${f.lossHop} 跳</span>` : ''}
      ${f.latencyHop ? `<span class="pill warn">变慢起点 第 ${f.latencyHop} 跳</span>` : ''}
      ${!f.goalSeen && f.hops && f.hops.length ? '<span class="pill warn">一次都没走到终点</span>' : ''}</p>
    ${rows ? `<table><tr><th>跳</th><th>设备</th><th>丢包</th><th>平均</th><th>最差</th><th></th></tr>${rows}</table>` :
      '<p class="hint">这一族一个样本都没拿到。</p>'}
    ${head}</div>`;
}

function mtrCard() {
  const card = $(`<div class="card">
    <h2>路径质量（逐跳持续探测）<span id="qo"></span></h2>
    <p class="hint">把「偶尔卡一下 / 隔十几秒花一格」这种主诉查出来：<b>同一批跳连着问几十次</b>，
      每一跳给出丢包率（带分母）、平均和最差往返。★ 中间某跳丢、后面每跳都收得到，会明说是
      「这台设备只丢自己的回应，没丢转发」，不当故障报；从某跳起一路丢到终点才算拥塞点，并点名那一跳。
      装了 mtr 就用它（同样时间样本多一个量级），没装就跑多轮 traceroute，用的是哪个都写出来。</p>
    <div class="row">
      <div><label>目标（域名或 IP）</label><input id="qh" placeholder="192.168.1.1 或 camera.example.com"></div>
      <div style="flex:0 0 110px"><label>地址族</label>
        <select id="qf"><option value="auto">两族都测</option><option value="v4">只测 v4</option><option value="v6">只测 v6</option></select></div>
      <div style="flex:0 0 80px"><label>几轮</label><input id="qn" placeholder="8"></div>
      <div style="flex:0 0 90px"><label>每跳几个</label><input id="qq" placeholder="3"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label><button class="btn primary" id="qgo">开始测量</button></div>
    </div>
    <div id="qout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#qout');
  const top = card.querySelector('#qo');
  card.querySelector('#qgo').onclick = async () => {
    top.innerHTML = '';
    const host = card.querySelector('#qh').value.trim();
    if (!host) { out.innerHTML = '<div class="empty">先填目标地址。</div>'; return; }
    out.innerHTML = '<div class="empty">测量中…（默认 8 轮 × 每跳 3 发，最长 1 分钟）</div>';
    const args = { host, family: card.querySelector('#qf').value };
    const n = Number(card.querySelector('#qn').value);
    const q = Number(card.querySelector('#qq').value);
    if (n > 0) args.rounds = n;
    if (q > 0) args.perHop = q;
    const r = await call('net.mtr', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">测不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = MTR_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}</div>
      ${(v.reports || []).map(mtrFamilyBlock).join('')}
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/**
 * ── 校时检查（net.time.check）──
 *
 * ★ 这一栏存在的原因：时钟不对的症状从来不长在「时间」上 —— 证书报「还没生效」、
 *   日志排不成序、租约被判过期，现场查了半天查的是网络和证书。
 * ★ 「差了多少」和「是谁不对」是两件事：只有一个源答的时候，那 3 年既可能是本机错、
 *   也可能是对方错 —— 所以只有一个源时这一栏只报偏差，不指认谁错。
 */

const TIME_CODE = {
  'time-ok': ['时钟是对的', 'ok', '几个时间源说的都对得上，本机时钟和标准只差几十毫秒以内 —— 证书、租约、日志排序不会因此出问题。要是还在报「证书没生效」，那是别的事。'],
  'time-skewed': ['时钟有偏差', 'warn', '偏差不小，但还没到会把证书和租约判错的程度。★ 只有一个源答的时候，这里只说差多少，不说谁不对 —— 想指认本机，需要多个源互相印证。'],
  'time-way-off': ['时钟差得足以让别的东西出错', 'bad', '这个量级上，证书会被判「还没生效」或「已过期」、租约会被算成早到期、日志时间戳排不进正确的顺序 —— 现场看到的「网有问题」，根在这里。至于是不是本机不对，看下面那行：多个源互相印证过才敢指认。'],
  'time-servers-disagree': ['时间源之间自己就对不上', 'warn', '★ 这时候不能指认本机不对：至少有一个时间源自己就是坏的（或者中间有设备在改写 NTP）。先看下面哪一行和别的不一样，把它从服务器列表里去掉再问一次。'],
  'time-no-response': ['一个时间源都没回', 'warn', '最常见是 UDP 123 被挡（很多出口默认不放）。★ 这只说明「问不到标准时间」，不说明本机的钟是坏的 —— 要判断时钟，先放行 NTP 或者换成内网的时钟源。'],
  'time-kiss-rejected': ['时间源拒答', 'warn', '对方明确回了「不给」：RATE 是问得太密被限速，STEP 是它直说你的钟偏得超过它的容错 —— 后者等于替你确认了「时钟确实不对」。看下面每一行的码分别是哪一种。'],
  'time-bad-response': ['回的不是 NTP', 'bad', '端口上有回应，但内容不是时间戳。多为链路上有设备在冒充/改写 NTP，或者这个端口上挂着别的服务。换一个端口或换一台服务器再问。'],
  'name-unresolved': ['服务器域名解析不出来', 'bad', '还没到问时间这一步 —— 用上方「DNS 查询」把解析查通，或者直接填 IP。'],
};

const TIME_SHORT = {
  'time-ok': '时钟对的', 'time-skewed': '有偏差', 'time-way-off': '差得离谱',
  'time-servers-disagree': '源对不上', 'time-no-response': '问不到',
  'time-kiss-rejected': '被拒答', 'time-bad-response': '回的不是NTP', 'name-unresolved': '解析不出',
  'answered': '答了',
};

// 偏差要给人读成「慢了多少」而不是一个浮点数：几十毫秒和差三年，是两种完全不同的活。
function humanMs(ms) {
  const a = Math.abs(ms);
  if (a < 1000) return a.toFixed(1) + ' 毫秒';
  if (a < 60000) return (a / 1000).toFixed(a < 10000 ? 1 : 0) + ' 秒';
  if (a < 3600000) return Math.floor(a / 60000) + ' 分 ' + Math.round((a % 60000) / 1000) + ' 秒';
  if (a < 86400000) return Math.floor(a / 3600000) + ' 小时 ' + Math.floor((a % 3600000) / 60000) + ' 分';
  return (a / 86400000).toFixed(a < 864000000 ? 1 : 0) + ' 天';
}

// 后端出 RFC3339（带毫秒），界面把它写成能一眼读完的一行。
function fmtStamp(s) {
  return s ? s.replace('T', ' ') : '—';
}

function timeSourceRow(s) {
  const [text, cls] = TIME_CODE[s.code] || [s.code, ''];
  const answered = s.code === 'answered';
  const dir = answered ? (s.offsetMs > 0 ? '本机慢' : '本机快') : '';
  return `<tr>
    <td><code>${esc(s.server)}</code>${s.leap ? `<div class="dim" style="font-size:12px">闰秒预警：${s.leap === 'insert' ? '接下来要插一秒' : '这一分钟删过一秒'}</div>` : ''}</td>
    <td><span class="pill ${answered ? '' : cls}">${esc(TIME_SHORT[s.code] || text)}</span>
        ${s.kiss ? `<span class="pill warn">${esc(s.kiss)}</span>` : ''}</td>
    <td>${answered ? `<b>${humanMs(s.offsetMs)}</b> <span class="dim">${dir}</span>` : '—'}</td>
    <td>${answered && s.rttMs ? esc(s.rttMs) + 'ms' : '—'}</td>
    <td>${answered ? `<span class="dim">stratum ${esc(s.stratum)}${s.refId ? ' ← ' + esc(s.refId) : ''}</span>` : '—'}</td>
    <td class="dim">${esc(s.samples)}/${esc(s.answers)}${s.detail ? `<div style="font-size:12px">${esc(s.detail)}</div>` : ''}</td>
  </tr>`;
}

function timeCard() {
  const card = $(`<div class="card">
    <h2>校时检查 <span id="wv"></span></h2>
    <p class="hint">问一台权威时间源「现在几点」。★ 时钟不对的症状从来不长在时间上 ——
      <b>证书报「还没生效」、日志排不成序、租约被判过期</b>，现场查了半天查的是别的东西。
      这一栏给偏差（带方向和量级）、给「本机说几点 / 标准说几点」，并且<b>只有多个时间源互相印证时</b>
      才说「是本机的钟不对」；只问到一个源时只报差多少、不指认谁错。源之间对不上，会点出有个源自己就坏了。</p>
    <div class="row">
      <div><label>时间源（留空问默认公网源；内网有自己的时钟源就填它的地址）</label>
        <input id="ws" placeholder="192.168.1.1, ntp.internal（逗号分隔）"></div>
      <div style="flex:0 0 90px"><label>端口</label><input id="wp" placeholder="123"></div>
      <div style="flex:0 0 100px"><label>每个源问几次</label><input id="wn" placeholder="3"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label><button class="btn primary" id="wgo">对一下表</button></div>
    </div>
    <div id="wout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#wout');
  const top = card.querySelector('#wv');
  card.querySelector('#wgo').onclick = async () => {
    top.innerHTML = '';
    const args = {};
    const sv = card.querySelector('#ws').value.split(',').map((x) => x.trim()).filter(Boolean);
    if (sv.length) args.servers = sv;
    const p = Number(card.querySelector('#wp').value);
    const n = Number(card.querySelector('#wn').value);
    if (p > 0) args.port = p;
    if (n > 0) args.samples = n;
    out.innerHTML = '<div class="empty">正在问时间源…（各源并行，最长约 10 秒）</div>';
    const r = await call('net.time.check', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">问不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = TIME_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const answered = v.agreeSources > 0;
    // ★ 指认「谁不对」的底气只来自源之间的一致：一个源的时候这句话不能说。
    const blame = v.attribution === 'corroborated'
      ? `<span class="pill ok">${v.agreeSources} 个源说得一致 → 是本机的钟不对</span>` :
      v.attribution === 'conflict' ? '<span class="pill warn">源之间对不上 → 不能指认本机</span>' :
      v.attribution === 'single-source' ? '<span class="pill warn">只问到一个源 → 只报偏差，不说谁错</span>' :
      '<span class="pill warn">没问到任何标准时间 → 无从指认</span>';
    out.innerHTML = `
      ${answered ? `<div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
        <div><label>本机说</label><div><b>${esc(fmtStamp(v.localTime))}</b></div></div>
        <div><label>标准时间（${esc(v.checkedWith || '')}）</label><div><b>${esc(fmtStamp(v.standardTime))}</b></div></div>
        <div><label>差</label><div><span class="pill ${cls}">${esc(humanMs(v.offsetMs))}，本机${v.localSlow ? '慢' : '快'}</span></div></div>
      </div>` : ''}
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}</div>
      <p style="margin:10px 0 0">${blame}
        ${v.spreadMs ? `<span class="dim">源之间最大差 ${esc(humanMs(v.spreadMs))}</span>` : ''}</p>
      <table style="margin-top:10px"><tr><th>时间源</th><th>结果</th><th>偏差</th><th>往返</th><th>它的上游</th><th>问/回</th></tr>
        ${(v.sources || []).map(timeSourceRow).join('')}</table>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/*
 * ── UDP 探测 ──
 *
 * ★ UDP 没有「连上」这回事，所以这里最容易被含混带过去：没人回你，可能是端口开着
 *   但它不答你这句话，也可能是防火墙把包丢了 —— 现场要查的方向完全不同。
 *   后端拿一次对照探测把这两种分开，界面就把四种结果各自说清楚，不许合成一句「不通」。
 */
const UDP_CODE = {
  'udp-responsive': ['有回包', 'ok', '这个端口后面确实有个会答话的服务 —— 不用再猜了。'],
  'udp-closed': ['端口没人监听', 'warn',
    '对方回了 ICMP 端口不可达：主机是活的，只是这个端口没有服务。要么是服务没起来，要么你打错了端口。'],
  'udp-silent-alive': ['端口不出声，机器是活的', 'warn',
    '目标端口没答，但同一台机器的对照端口出声了 —— 至少能排除「整机不对」。剩下的两种还得往下分：'
    + '端口开着但它不答你这一句（换成协议里真实的一条报文再问一次），或者这个端口被单独拦了。'],
  'udp-silent': ['UDP 整段静默', 'bad',
    '目标端口和对照端口都没出声。分不清是机器不在、还是这条路把 UDP 整段丢了 —— '
    + '先用上面的 ping 看机器在不在，再往上查防火墙/交换机。'],
  'unknown': ['判不出来', 'warn', '包根本没发出去（看原始结果里的 detail），这不算端口不通。'],
};

function udpCard() {
  const card = $(`<div class="card">
    <h2>探 UDP 端口 <span id="uv"></span></h2>
    <p class="hint">向一个 UDP 端口发一发看它答不答。<b>多数服务不认识空包</b> ——
      只想知道「5060 上有没有 SIP」，就把 <code>payload</code> 填成协议里真实的一句话（或用
      <code>payloadHex</code> 发二进制报文），否则它不理你，你只能拿到「没反应」。
      对照探测会再打一个肯定没人监听的端口，用它的反应把「这台机器不对」和「只是这个端口的事」分开；
      生产设备上不想到处发包可以关掉。</p>
    <div class="row">
      <div><label>目标地址（只收 IP）</label><input id="ua" placeholder="192.168.1.1"></div>
      <div style="flex:0 0 90px"><label>端口</label><input id="up" placeholder="5060"></div>
      <div><label>发的内容（留空 = 空包）</label><input id="upay" placeholder="OPTIONS sip:1sip:1 SIP/2.0"></div>
      <div style="flex:0 0 130px"><label>或十六进制</label><input id="uphex" placeholder="00010000"></div>
    </div>
    <div class="row" style="margin-top:10px">
      <div style="flex:0 0 130px"><label>对照端口</label><input id="uctl" placeholder="50000"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <label style="display:flex;align-items:center;gap:6px;font-weight:400">
          <input type="checkbox" id="unctlo" style="width:auto"> 不跑对照，只发目标这一发</label></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn primary" id="ugo">探一下</button></div>
    </div>
    <div id="uout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#uout');
  const top = card.querySelector('#uv');
  card.querySelector('#ugo').onclick = async () => {
    top.innerHTML = '';
    const args = { addr: card.querySelector('#ua').value };
    const p = Number(card.querySelector('#up').value);
    const hex = card.querySelector('#uphex').value.trim();
    const ctl = Number(card.querySelector('#uctl').value);
    const pay = card.querySelector('#upay').value;
    if (p > 0) args.port = p;
    if (pay) args.payload = pay;
    if (hex) args.payloadHex = hex;
    if (ctl > 0) args.controlPort = ctl;
    args.noControl = card.querySelector('#unctlo').checked;
    out.innerHTML = '<div class="empty">正在发…（要跑对照的话最坏等两个超时）</div>';
    const r = await call('net.udp.probe', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">探不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = UDP_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const c = v.control;
    out.innerHTML = `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
        <div><label>目标</label><div><b><code>${esc(v.target)}</code></b></div></div>
        <div><label>回包</label><div>${v.answered ? `<b>${esc(v.bytes)} 字节</b>` : '<span class="dim">没有</span>'}</div></div>
        <div><label>等了</label><div>${esc(v.elapsedMs)}ms</div></div>
        <div><label>对照端口</label><div>${c
          ? `<code>:${esc(c.port)}</code> ${c.answered ? '<span class="pill ok">出声了</span>' : '<span class="pill warn">也没出声</span>'}`
          : '<span class="dim">没跑</span>'}</div></div>
      </div>
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}${v.detail ? `<div class="dim" style="margin-top:6px;font-size:12.5px">${esc(v.detail)}</div>` : ''}</div>
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/*
 * ── 端口扫描 ──
 *
 * ★ 这一栏买到的不是「快」，是**形状**：单个端口关着不值一提，一片端口里有一个回了拒绝
 *   就说明主机是活的；反过来一个回执都没有，那连机器在不在都不知道 —— 下一步完全两回事，
 *   所以界面不许把这两种都写成「扫不到」。
 * ★★ 结果超过 200 个端口时后端不给逐端口明细（只给汇总和 openPorts）：
 *   两千条 closed 没有一条是信息，却足以把开着的几个埋掉。这里要把省掉了说清楚。
 */
const SCAN_CODE = {
  'ports-open': ['有端口开着', 'ok',
    '下面列出来的端口连上了。要知道某个服务为什么不通，再用上面的单端口探测看它答得多慢。'],
  'ports-closed': ['没有端口开着，但主机是活的', 'warn',
    '有端口明确回了拒绝 —— 拒绝说明对方收到了包并且答了，所以主机在、路也通，只是这些端口上没有服务。'
    + '★ 别把它当成「机器挂了」去查链路。'],
  'ports-no-response': ['一个都没回话', 'bad',
    '所有端口都静默。这不能说明主机不在：整段被防火墙静默丢、地址根本没人用，都是这个形状。'
    + '先用上面的 ping 看机器在不在，再查对端的防火墙。'],
  'ports-no-route': ['包根本没出去', 'bad',
    '到这个地址没有路 —— 一个包都没发出去，所以这跟对端防不防火没有关系。查自己：网卡起来了吗、'
    + '和它是不是同一个网段（看「本机网络」那一页，和这一页顶部的双栈体检）。'],
};

// 单端口状态沿用 net.tcp.probe 那三个码，界面和体检项因此只有一套词。
const SCAN_STATUS = {
  'open': ['开着', 'ok'],
  'closed': ['关着', 'bad'],
  'filtered': ['没回话', 'warn'],
  'no-route': ['没路', 'bad'],
  'error': ['判不出来', 'warn'],
};

function scanCard() {
  const card = $(`<div class="card">
    <h2>扫一片端口 <span id="sv"></span></h2>
    <p class="hint">对<b>一台</b>主机批量做 TCP 连接探测。端口可以写 <code>22,80,443</code>、区间
      <code>8000-8010</code>、混着写；留空扫一批现场常用端口（含 RTSP / ONVIF / 各厂商 SDK 端口）。
      ★ 一次连太多端口，有些摄像机会当成爆破把这台机器临时锁掉 —— 在生产设备上把并发和端口数都收着点。</p>
    <div class="row">
      <div><label>目标地址（只收 IP）</label><input id="sa" placeholder="192.168.1.64"></div>
      <div><label>端口（留空 = 常用端口集）</label><input id="spts" placeholder="22,80,554,37777 或 8000-8100"></div>
      <div style="flex:0 0 110px"><label>单端口等待 ms</label><input id="stim" placeholder="500"></div>
      <div style="flex:0 0 110px"><label>同时几个</label><input id="scnc" placeholder="32"></div>
    </div>
    <div style="margin-top:12px"><button class="btn primary" id="sgo">开始扫</button></div>
    <div id="sout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#sout');
  const top = card.querySelector('#sv');
  card.querySelector('#sgo').onclick = async () => {
    top.innerHTML = '';
    const args = { addr: card.querySelector('#sa').value };
    const pts = card.querySelector('#spts').value.trim();
    const t = Number(card.querySelector('#stim').value);
    const c = Number(card.querySelector('#scnc').value);
    if (pts) args.ports = pts;
    if (t > 0) args.timeoutMs = t;
    if (c > 0) args.maxConcurrency = c;
    out.innerHTML = '<div class="empty">正在扫…（最坏要等「端口数 ÷ 并发数」轮超时，端口多就慢）</div>';
    const r = await call('net.ports.scan', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">扫不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = SCAN_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const open = (v.openPorts || []).map((p) => `<code>${esc(p)}</code>`).join(' ') || '<span class="dim">无</span>';
    const rows = (v.ports || []).map((p) => {
      const [w, pc] = SCAN_STATUS[p.status] || [p.status, ''];
      return `<tr><td><code>${esc(p.port)}</code></td><td><span class="pill ${pc}">${esc(w)}</span></td>
        <td class="dim">${p.elapsedMs ? esc(p.elapsedMs) + 'ms' : ''}</td>
        <td class="dim">${esc(p.detail || '')}</td></tr>`;
    }).join('');
    out.innerHTML = `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
        <div><label>目标</label><div><b><code>${esc(v.target)}</code></b></div></div>
        <div><label>扫了</label><div>${esc(v.scanned)} 个</div></div>
        <div><label>开着</label><div><b>${esc(v.open)}</b></div></div>
        <div><label>关着</label><div>${esc(v.closed)}</div></div>
        <div><label>没回话</label><div>${esc(v.filtered)}</div></div>
        <div><label>没路</label><div>${esc(v.noRoute || 0)}</div></div>
      </div>
      <div style="margin-bottom:12px"><label>开着的端口</label><div>${open}</div></div>
      ${v.warning === 'many-connections' ? `<div style="background:var(--gold-bg);border:1px solid var(--gold-dim);
        border-radius:6px;padding:9px 12px;margin-bottom:12px;font-size:13px">
        这次连了 ${esc(v.scanned)} 个端口。不少摄像头和录像机把短时间内的批量连接当成爆破，
        会把这台机器临时锁几分钟 —— 扫完发现「突然什么都不通了」，先想到这个。</div>` : ''}
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}</div>
      ${rows ? `<table style="margin-top:14px"><tr><th>端口</th><th>状态</th><th>等了</th><th></th></tr>${rows}</table>`
        : v.portsOmitted ? `<p class="dim" style="margin-top:14px">扫了 ${esc(v.scanned)} 个端口，逐端口的明细就不列了
            —— 一整屏「关着」里没有一条是信息，反而会把真开着的几个埋掉。开着的端口已经在上面列出来了，
            要看某几个的明细，把端口填窄一点再扫一次。</p>` : ''}
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/**
 * net.mtu.path 的六种判定。
 * ★★ 「大包过不去」这件事有两种归属，处理的人完全不同，所以文案必须分开：
 *   mtu-path  → 路上某个环节压小了尺寸，要照这个数设本机网卡（或去查中间那一跳）
 *   mtu-local → 是本机网卡自己装不下，路上根本没测到更小的限制 —— 别去查隧道
 *   mtu-no-response 那一档是这一栏的**安全阀**：对方不回 ICMP 时什么都测不出来，
 *   把它说成「路径 MTU 就是 N」会让人照着设一个错的网卡 MTU。
 */
const MTU_CODE = {
  'mtu-path': ['路上有个更小的限制', 'warn',
    '大包就是在中间某个环节被挡住的：隧道、PPPoE、VPN、或者被人改小过 MTU 的交换机口。'
    + '把这台机器的网卡 MTU 设成上面那个数（或更小）就能过去；要根治就去查中间那一环。'],
  'mtu-local': ['上限是本机网卡，路上没测到更小的限制', 'ok',
    '没撞到比本机网卡更小的尺寸。大包发不出去的话，先查本机这块网卡的 MTU 和分片设置，'
    + '别去翻隧道和路由器 —— 这一趟没看到它们挡过东西。'],
  'mtu-no-limit-found': ['测到上限都没被挡', 'ok',
    '这次的「最大测到」是上面填的那个值，所以只能说到这儿都是通的。想确认更大的尺寸，'
    + '把上限调大再测一次，多花的只是几次二分。'],
  'mtu-no-response': ['对方不回回执，这一栏测不出东西', 'bad',
    '连起手的那个小包都没回执 —— 这台主机不回 ICMP，或者这条路把差错报文挡了。'
    + '★ 这不代表 MTU 有问题：「收不到回执」和「大包真的过不去」长得一模一样。先用上面的 ping 看它在不在。'],
  'mtu-no-route': ['包根本没出去', 'bad',
    '到这个地址没有路，一个包都没发出去，所以跟路径 MTU 无关。查自己：网卡起来了吗、'
    + '和它是不是同一个网段（看「本机网络」那一页，和这一页顶部的双栈体检）。'],
  'mtu-df-unsupported': ['这台机器上测不了', 'bad',
    '这一栏靠的是「不许分片」那个套接字选项；它设不上、或者设上了内核却照旧自己把大包切开时，'
    + '量出来的数会大得离谱。宁可不给结论，也不端一个假的 MTU 出来 —— 那是会照着设进网卡的。'],
};

// 逐个尺寸的探测记录。二分不一定正好测到「第一个过不去」的那个，所以明细要摆出来给人看。
const MTU_OUTCOME = {
  'through': ['过得去', 'ok'],
  'too-big': ['太大被挡', 'bad'],
  'silent': ['没回执', 'warn'],
  'no-route': ['没路', 'bad'],
  'error': ['发不出去', 'warn'],
};

function mtuCard() {
  const card = $(`<div class="card">
    <h2>路径 MTU <span id="mv"></span></h2>
    <p class="hint">查<b>「连得上、小包都好，就是大包过不去」</b>：视频一出来就卡、传文件传到一半断，
      而 ping 和端口探测都正常 —— 因为它们在路上过的包本来就不大。隧道 / VPN / PPPoE /
      被改小过 MTU 的端口都会这样。做法是给一个 UDP 包设「不许分片」，二分地试不同大小，
      看从哪儿开始发不出去。<b>只收 IP。</b></p>
    <div class="row">
      <div><label>目标地址（只收 IP）</label><input id="ma" placeholder="192.168.1.64"></div>
      <div style="flex:0 0 130px"><label>探测端口</label><input id="mp" placeholder="9253（留空即可）"></div>
      <div style="flex:0 0 130px"><label>最大测到</label><input id="mm" placeholder="留空 = 本机网卡 MTU"></div>
      <div style="flex:0 0 110px"><label>单尺寸等待 ms</label><input id="mt" placeholder="700"></div>
    </div>
    <div style="margin-top:12px"><button class="btn primary" id="mgo">开始探</button></div>
    <div id="mout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#mout');
  const top = card.querySelector('#mv');
  card.querySelector('#mgo').onclick = async () => {
    top.innerHTML = '';
    const args = { addr: card.querySelector('#ma').value };
    const p = Number(card.querySelector('#mp').value);
    const m = Number(card.querySelector('#mm').value);
    const t = Number(card.querySelector('#mt').value);
    if (p > 0) args.port = p;
    if (m > 0) args.maxSize = m;
    if (t > 0) args.timeoutMs = t;
    out.innerHTML = '<div class="empty">正在二分探大小…（大约十几步，每步最多等一个超时）</div>';
    const r = await call('net.mtu.path', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">探不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = MTU_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const e = v.egress || {};
    const rows = (v.steps || []).map((s) => {
      const [w, pc] = MTU_OUTCOME[s.outcome] || [s.outcome, ''];
      return `<tr><td><code>${esc(s.size)}</code></td><td><span class="pill ${pc}">${esc(w)}</span></td>
        <td class="dim">${s.elapsedMs ? esc(s.elapsedMs) + 'ms' : ''}</td>
        <td class="dim">${esc(s.detail || '')}</td></tr>`;
    }).join('');
    // 那个「数」是这一栏的全部产出：路径 MTU / 至少能过 / 本机上限，三种说法各配一个数
    const figure = v.pathMtu != null
      ? `<div><label>路径 MTU（IP 包总长）</label><div style="font-size:26px"><b>${esc(v.pathMtu)}</b> 字节</div></div>`
      : v.carriesAtLeast != null
        ? `<div><label>至少能过</label><div style="font-size:26px"><b>${esc(v.carriesAtLeast)}</b> 字节</div></div>`
        : '';
    out.innerHTML = `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
        <div><label>目标</label><div><b><code>${esc(v.target)}</code></b></div></div>
        ${figure}
        <div><label>出口网卡</label><div>${e.mtu ? `<code>${esc(e.iface)}</code> MTU ${esc(e.mtu)}` : '<span class="dim">没读到</span>'}</div></div>
        <div><label>探测端口</label><div>${esc(v.port)}</div></div>
        <div><label>靠哪一层测的</label><div>${esc(v.engine)}</div></div>
      </div>
      ${v.dfVerified === false ? `<div style="background:var(--red-bg);border:1px solid var(--red-line);
        border-radius:6px;padding:9px 12px;margin-bottom:12px;font-size:13px">
        这台机器上「不许分片」设上了却不干活（超过网卡 MTU 的包照发出去，内核自己切开了）。
        这样量出来的任何 MTU 都是假的，所以没有给数。</div>` : ''}
      ${v.warning === 'below-ipv6-min' ? `<div style="background:var(--gold-bg);border:1px solid var(--gold-dim);
        border-radius:6px;padding:9px 12px;margin-bottom:12px;font-size:13px">
        IPv6 链路上按规定至少该能过 1280 字节，这里测出来比它还小 —— 中间有设备不守规矩，
        这个数别当成正常的路径 MTU 用。</div>` : ''}
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}</div>
      ${rows ? `<table style="margin-top:14px"><tr><th>包大小（IP 总长）</th><th>结果</th><th>等了</th><th></th></tr>${rows}</table>` : ''}
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/*
 * ── 连续 ping ──
 *
 * ★★ 现场的原话是「有时候卡一下」。四发的 ping 问不出这个毛病 —— 四发全通，
 *   因为那一下没赶上。所以这一栏按时间连发，把每一发都留在结果里。
 *
 * ★ 图只负责看出形状，**点名的那一发才是产出**：时刻 + 值。
 *   人拿时刻去对现场发生了什么（是不是刚好起流、刚好有人插拔网线），
 *   只给一张图和一句「抖动偏大」等于没答。
 * ★ 丢包那几发在图上必须断线、并在底下留格子 —— 连过去就是把「没回执」画成了「一直很好」。
 */

// 「没回执」有三种，界面不许合成一种说：
// 超时是对方不吭声，不可达是有人明说够不着，error 是包在本机就没出去 —— 三个查的方向不同。
const WATCH_KIND = {
  'no-reply': ['没回执（超时）', 'warn'],
  'unreachable': ['明确不可达', 'bad'],
  'error': ['包没出去（本机）', 'bad'],
};

const WATCH_CODE = {
  'stable': ['稳', 'ok',
    '这一段每一发都有回执、快慢也平 —— 「卡」不是这一台在这段时间的问题，去别的环节找'
    + '（应用自己的超时、DNS、对端的服务）。'],
  'jitter': ['抖', 'warn',
    '没丢包，但快慢差得明显。★ 先看下面点名的那一发是第几秒 —— 无线链路、挤满的 AP、'
    + '对端在干重活都会这样。如果整条线都在晃而挑不出单发，那是链路质量本身在晃，不是谁卡了一下。'],
  'loss': ['丢包', 'bad',
    '有发数没拿到回执。★ 丢和抖是两种病，处理方向不同：丢要查链路（信号、网线、端口协商、环路），'
    + '抖多半是排队。底下写清了丢在第几发、是超时还是明确不可达。'],
  'no-reply': ['一个都没回', 'warn',
    '这一栏分不出「主机不在」和「ICMP 被挡」，所以给不出稳定性结论。先去上面的 ping 确认这台存在。'],
  'unreachable': ['明确不可达', 'bad',
    '每一发都拿到了「到不了」的回执 —— 包出得去、也有人回话，中间的路是通的，'
    + '问题在终点或路由（对端关机、地址没人要、中间设备没路由）。这跟「被防火墙挡了」是两个结论。'],
  'no-route': ['本机没路', 'bad',
    '包根本没出去，跟对端没关系。查自己这边：网卡起没起、地址配没配、是不是同一个网段。'],
};

// 一图一例。★ 纵轴按本图最大值缩放，两条线各画一张，不做双轴 ——
// 把 0.05ms 的对照和 90ms 的目标塞进同一根轴上，对照那条就变成一条贴底的直线，
// 看着像「它稳得像根线」，其实只是被刻度压扁了。
function watchChart(samples, spanMS, tone, spikes) {
  const W = 620, H = 168, P = 16;
  const ok = samples.filter((s) => s.kind === 'reachable');
  if (!ok.length) return '';
  const hi = Math.max(...ok.map((s) => s.rttMs || 0)) * 1.18 || 1;
  const span = Math.max(1, spanMS || ok[ok.length - 1].atMs || 1);
  const X = (at) => P + (at / span) * (W - 2 * P);
  const Y = (r) => H - P - (r / hi) * (H - 2 * P);
  const stroke = tone === 'base' ? 'var(--gold-dim)' : 'var(--green-dim)';
  let prev = null;
  const segs = [], dots = [], holes = [];
  for (const s of samples) {
    if (s.kind !== 'reachable') {
      holes.push(`<line x1="${X(s.atMs)}" y1="${P}" x2="${X(s.atMs)}" y2="${H - P}"
          stroke="var(--red-line)" stroke-dasharray="3 4" opacity=".5"/>
        <rect x="${(X(s.atMs) - 3.5).toFixed(1)}" y="${H - P - 3.5}" width="7" height="7"
          fill="var(--red-bg)" stroke="var(--red-line)"/>`);
      prev = null;
      continue;
    }
    const cx = X(s.atMs), cy = Y(s.rttMs || 0);
    if (prev) segs.push(`<line x1="${prev[0].toFixed(1)}" y1="${prev[1].toFixed(1)}"
        x2="${cx.toFixed(1)}" y2="${cy.toFixed(1)}" stroke="${stroke}" stroke-width="1.7"/>`);
    dots.push(`<circle cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="2.7" fill="${stroke}"/>`);
    prev = [cx, cy];
  }
  const rings = (spikes || []).map((seq) => {
    const s = samples.find((x) => x.seq === seq);
    if (!s || s.kind !== 'reachable') return '';
    return `<circle cx="${X(s.atMs).toFixed(1)}" cy="${Y(s.rttMs || 0).toFixed(1)}" r="6"
      fill="none" stroke="var(--gold-dim)" stroke-width="1.6"/>`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto;display:block" role="img"
      aria-label="每一发的往返时间">
      <line x1="${P}" y1="${H - P}" x2="${W - P}" y2="${H - P}" stroke="var(--line)"/>
      ${holes.join('')}${segs.join('')}${dots.join('')}${rings}
      <text x="${P}" y="${P - 4}" fill="var(--muted)" font-size="10">
        ${esc(hi.toFixed(1))}ms</text>
      <text x="${W - P}" y="${P - 4}" text-anchor="end" fill="var(--muted)" font-size="10">
        ${(span / 1000).toFixed(1)}s</text>
    </svg>`;
}

// prefix 传 'baseline' 时读的是 baselineSent / baselineRttMedianMs 这一批 ——
// ★ 后端把前缀后的首字母大写了（mergeStats 里的 upper1），这里必须按同一个口径拼，
//   拼错不会报错，只会让对照组的八个格子全显示「没测到」。
function watchSummaryRows(v, prefix) {
  const p = prefix || '';
  const key = (k) => (p ? p + k[0].toUpperCase() + k.slice(1) : k);
  const num = (n, unit) => (n == null ? '<span class="dim">没测到</span>' : `<b>${esc(n)}</b>${unit}`);
  return `<div class="row" style="gap:18px;flex-wrap:wrap;margin-top:10px">
    <div><label>发了</label><div>${num(v[key('sent')], '')}</div></div>
    <div><label>回了</label><div>${num(v[key('recv')], '')}</div></div>
    <div><label>明确不可达</label><div>${num(v[key('unreachable')], '')}</div></div>
    <div><label>丢包率</label><div>${num(v[key('lossPercent')], '%')}</div></div>
    <div><label>中位</label><div>${num(v[key('rttMedianMs')], 'ms')}</div></div>
    <div><label>95 分位</label><div>${num(v[key('rttP95Ms')], 'ms')}</div></div>
    <div><label>最慢</label><div>${num(v[key('rttMaxMs')], 'ms')}</div></div>
    <div><label>相邻两发抖动</label><div>${num(v[key('jitterAvgMs')], 'ms')}</div></div>
  </div>`;
}

function pingWatchCard() {
  const card = $(`<div class="card">
    <h2>连续 ping（看抖不抖）<span id="pwv"></span></h2>
    <p class="hint">专查<b>「有时候卡一下」</b>：四发的 ping 问不出这个毛病，因为那一下没赶上。
      这里按时间连发，把每一发都留下 —— 曲线之外还会点出<b>第几发、第几秒、抖成什么样</b>，
      拿那个时刻去对现场发生了什么。可选填一个对照地址（一般是网关），
      用来分「只有这台慢」和「这一整段都在抖」。</p>
    <div class="row">
      <div><label>目标地址</label><input id="pwa" placeholder="192.168.1.64"></div>
      <div style="flex:0 0 130px"><label>间隔 ms</label><input id="pwi" placeholder="500"></div>
      <div style="flex:0 0 130px"><label>看多久 ms</label><input id="pwd" placeholder="10000（最多 60000）"></div>
      <div style="flex:0 0 130px"><label>单发等待 ms</label><input id="pwt" placeholder="1000"></div>
      <div><label>对照地址（可留空）</label><input id="pwb" placeholder="192.168.1.1 网关"></div>
    </div>
    <div style="margin-top:12px"><button class="btn primary" id="pwgo">开始连发</button></div>
    <div id="pwout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#pwout');
  const top = card.querySelector('#pwv');
  card.querySelector('#pwgo').onclick = async () => {
    top.innerHTML = '';
    const args = { addr: card.querySelector('#pwa').value };
    for (const [id, key] of [['#pwi', 'intervalMs'], ['#pwd', 'durationMs'], ['#pwt', 'timeoutMs']]) {
      const n = Number(card.querySelector(id).value);
      if (n > 0) args[key] = n;
    }
    const b = card.querySelector('#pwb').value.trim();
    if (b) args.baseline = b;
    const secs = Math.round((args.durationMs || 10000) / 1000);
    out.innerHTML = `<div class="empty">连发中…（约 ${secs} 秒，两腿一起跑时要再久一点）</div>`;
    const r = await call('net.ping.watch', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">测不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = WATCH_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';

    const spikes = (v.spikes || []).length
      ? `<div style="margin-top:12px"><label>抖在哪一发</label><div style="font-size:13.5px">
          ${(v.spikes || []).map((s) => {
    const one = (v.samples || []).find((x) => x.seq === s) || {};
    return `<span style="background:var(--gold-bg);border:1px solid var(--gold-dim);
              border-radius:5px;padding:3px 8px;margin-right:8px;display:inline-block">
              第 ${esc(s)} 发 · ${esc(((one.atMs || 0) / 1000).toFixed(1))}s · ${esc(Math.round(one.rttMs || 0))}ms
            </span>`;
  }).join('')}</div></div>` : '';

    const lost = (v.lostAt || []).length
      ? `<div style="margin-top:12px"><label>丢在哪几发</label>
          <table><tr><th>第几发</th><th>第几秒</th><th>是哪种没回执</th></tr>
          ${(v.lostAt || []).map((m) => `<tr><td><code>${esc(m.seq)}</code></td>
            <td>${esc(((m.atMs || 0) / 1000).toFixed(1))}s</td>
            <td>${pillOf(WATCH_KIND, m.kind)}</td></tr>`).join('')}
          </table>
          <p class="dim" style="margin:6px 0 0">★ 「明确不可达」和「超时」是两种东西：前者有人回话说够不着，
            后者连句话都没有 —— 前者查路由和终点，后者多半是挡包。</p></div>` : '';

    const baseBlock = v.compare ? `
      <div style="margin-top:16px">
        <label>对照组 ${esc(v.baseline)} <span class="dim">（同一轮里跑的，用来分「谁在抖」）</span></label>
        ${watchChart(v.baselineSamples || [], v.baselineSpanMs || v.spanMs, 'base', [])}
        ${watchSummaryRows(v, 'baseline')}
      </div>` : '';
    const cmp = v.compare ? `
      <div style="margin-top:12px;background:${bg};border:1px solid ${line};border-radius:6px;
        padding:10px 12px;font-size:13.5px">${esc(CMP_TEXT[v.compare] || v.compare)}${
  v.compare === 'both' && v.compareWorse && v.compareWorse !== 'similar'
    ? esc(v.compareWorse === 'target' ? '（更难看的是目标这台）' : '（更难看的是对照组那台）') : ''}</div>` : '';

    out.innerHTML = `
      <div class="row" style="gap:18px;margin-bottom:10px;flex-wrap:wrap">
        <div><label>目标</label><div><b><code>${esc(v.target)}</code></b> ${esc(v.family)}</div></div>
        <div><label>间隔 / 时长</label><div>${esc(v.intervalMs)}ms · ${esc((v.durationMs / 1000).toFixed(0))}s</div></div>
        <div><label>实到</label><div>${esc(((v.spanMs || 0) / 1000).toFixed(1))}s
          ${v.actualIntervalMs && v.actualIntervalMs > v.intervalMs * 1.5
    ? `<span class="pill warn">实际每发 ${esc(v.actualIntervalMs)}ms</span>` : ''}</div></div>
      </div>
      ${watchChart(v.samples || [], v.spanMs, 'target', v.spikes)}
      ${watchSummaryRows(v, '')}
      ${spikes}${lost}${baseBlock}${cmp}
      <div style="margin-top:14px;background:${bg};border:1px solid ${line};border-radius:6px;
        padding:10px 12px;font-size:13.5px">${esc(advice)}</div>
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果（逐发留痕）</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

const CMP_TEXT = {
  'neither': '两条线都干净 —— 目标这一路没毛病。',
  'target-only': '同一轮里对照组是干净的 —— 毛病只在这台，去查它自己（网卡、驱动、它那条链路）。',
  'baseline-only': '同一轮里反倒是对照组不干净，目标这台没问题。',
  'both': '同一轮里对照组也不干净 —— 先查这一段链路（网段、AP、出口），别只盯这一台。',
};

/*
 * ── 扫描与发现 ──
 *
 * ★ 这一页把「这个网段上都有谁」的三样东西放在一起：主动扫一段（net.subnet.scan）、
 *   听 v6 的应答顺便看谁还没配网（net.discover，原来只有 API 没有按钮，不合 [OTS-4.5]）、
 *   以及纯读本机缓存的邻居表（net.neighbors，同样原来没按钮）。
 *
 * ★★ 三张卡的可信度不是一回事，界面必须把这层差别留在脸上：
 *   邻居表是**缓存**（里面没有 ≠ 它不在，而且旧记录可能早就溜了）；
 *   扫网段是**当场问过**（每台都带着凭什么判定它在线）；
 *   发现只听得见应 v6 的那些。混成一张「设备清单」就会让人拿着一个漏了一半的表去现场。
 */

const SUBNET_CODE = {
  'hosts-found': ['问到了设备', 'ok',
    '清单在下面，每台都写着凭什么判定它在线。★ 收到自己的 ping 应答最硬，'
    + '「应了 ARP 但没应 ping」的摄像头很常见（上面有一键禁 ping），别当成不在。'],
  'no-hosts': ['一个信号都没收到', 'warn',
    '这不能读成「这个网段是空的」：整段被静默（交换机端口隔离、防火墙拦 ICMP）'
    + '和「真的没有设备」在结果上长一个样。先确认本机这块网卡真的接在这个网里。'],
};

// 一台设备被判在线的证据，按强弱分档。★ 不写凭什么，人就不敢信这张表。
const EVIDENCE = {
  icmp: ['收到它自己的 ping 应答', 'ok'],
  arp: ['应了 ARP，没应 ping', 'ok'],
  'arp-cache': ['本机缓存里的旧记录', 'warn'],
  tcp: ['端口有应答（连上或被拒）', 'ok'],
};

const DISCOVER_CODE = {
  'found-unconfigured': ['有设备还没配好网络', 'warn',
    '下面标出来的设备只有 IPv6 链路本地地址、没有 IPv4 —— 大概率是刚拆封、还没配网的那台。'
    + '这正是这一栏最值钱的用途：在一大堆设备里把「需要动手的那台」挑出来。'],
  'all-configured': ['应答的设备都已经配好地址', 'ok',
    '没有发现缺 IPv4 地址的设备。★ 这里只听得见应 IPv6 应答的那些，'
    + '纯 v4 的老设备不在这一栏的视野里，要看整段就去扫网段。'],
  'no-responder': ['没人应答', 'warn',
    '一个应答都没收到。可能是这块网卡没插线、不在这个网里，或者上游把 IPv6 邻居发现挡了。'],
  'no-link-local': ['本机喊不出去', 'bad',
    '要用的那块网卡连自己的 IPv6 链路本地地址都没有 —— 这个地址是自动生成的，'
    + '没有它就说明这台的 IPv6 没起来，先去「本机网络」看一眼。'],
};

async function renderScan(root) {
  root.appendChild(subnetScanCard());
  root.appendChild(discoverCard());
  root.appendChild(neighborsCard());
}

function subnetScanCard() {
  const card = $(`<div class="card">
    <h2>扫一个网段 <span id="nv"></span></h2>
    <p class="hint">问一遍<b>某个 IPv4 网段上现在有谁</b>。网段留空就扫本机自己所在的各段。
      ★ 只扫 IPv4：IPv6 一个 /64 有 1.8×10<sup>19</sup> 个地址，逐个问是问不完的，
      v6 那一套在下面「听谁在应答」那张卡里。</p>
    <div class="row">
      <div><label>网段（CIDR，留空 = 本机所在网段）</label><input id="nc" placeholder="192.168.1.0/24"></div>
      <div style="flex:0 0 150px"><label>只扫某块网卡</label><input id="ni" placeholder="en0 / 以太网"></div>
      <div style="flex:0 0 110px"><label>最多问几个</label><input id="nm" placeholder="1024"></div>
      <div style="flex:0 0 110px"><label>每轮等待 ms</label><input id="nw" placeholder="1500"></div>
    </div>
    <div class="row" style="margin-top:10px">
      <div><label>TCP 兜底端口（扫路由过来的网段时填）</label>
        <input id="np" placeholder="留空；或 22,80,554 —— ARP 用不上那段全靠它"></div>
    </div>
    <div style="margin-top:12px"><button class="btn primary" id="ngo">开始扫</button></div>
    <div id="nout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#nout');
  const top = card.querySelector('#nv');
  card.querySelector('#ngo').onclick = async () => {
    top.innerHTML = '';
    const args = {};
    const set = (id, key) => { const s = card.querySelector(id).value.trim(); if (s) args[key] = s; };
    set('#nc', 'cidr'); set('#ni', 'iface'); set('#np', 'tcpPorts');
    const n = Number(card.querySelector('#nm').value);
    const w = Number(card.querySelector('#nw').value);
    if (n > 0) args.maxHosts = n;
    if (w > 0) args.waitMs = w;
    out.innerHTML = '<div class="empty">正在扫…（发一轮再等回执，慢设备或者隔着无线就把等待时间调大）</div>';
    const r = await call('net.subnet.scan', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">扫不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice0] = SUBNET_CODE[r.verdict] || [r.verdict, '', ''];
    const advice = r.verdict === 'no-hosts' && v.onLink === false
      ? '这个网段<b>不是</b>本机所在的链路（是路由过来的）：那里 ARP 永远只有网关一条，'
        + '扫不到人是正常的。带上「TCP 兜底端口」再扫一次才有意义。'
      : advice0;
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const rows = (v.hosts || []).map((h) => {
      const [w2, pc] = EVIDENCE[h.evidence] || [h.evidence, ''];
      return `<tr><td><code>${esc(h.addr)}</code></td><td><code class="dim">${esc(h.mac || '—')}</code></td>
        <td class="dim">${esc(h.iface || '')}</td>
        <td><span class="pill ${pc}">${esc(w2)}</span>${h.detail ? ` <span class="dim">${esc(h.detail)}</span>` : ''}</td>
        <td class="dim">${h.elapsedMs ? esc(h.elapsedMs) + 'ms' : ''}</td></tr>`;
    }).join('');
    out.innerHTML = `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
        <div><label>扫了哪些网段</label><div><b><code>${esc((v.subnets || []).join(' '))}</code></b></div></div>
        <div><label>问过</label><div>${esc(v.asked)} 个地址</div></div>
        <div><label>在线</label><div><b>${esc(v.alive)}</b></div></div>
        <div><label>没信号</label><div>${esc(v.noSignal)}</div></div>
        <div><label>本机链路</label><div>${v.onLink ? '是（ARP 用得上）' : '否（ARP 用不上）'}</div></div>
      </div>
      ${v.skippedSelf ? `<p class="dim" style="margin:0 0 10px">这几个地址是本机自己的，没有列进清单：
        <code>${esc((v.skippedSelf || []).join(' '))}</code>（问自己必然有回执，列出来只会多一行莫名其妙的设备）</p>` : ''}
      ${v.skippedIface && v.skippedIface.length ? `<p class="dim" style="margin:0 0 10px">跳过了：${esc(v.skippedIface.join('；'))}</p>` : ''}
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${advice}</div>
      ${rows ? `<table style="margin-top:14px"><tr><th>地址</th><th>MAC</th><th>网卡</th><th>凭什么判定在线</th><th>等了</th></tr>${rows}</table>` : ''}
      ${v.alive ? `<p class="dim" style="margin-top:10px">「没信号」的那些<b>不是</b>「不在线」的证据 ——
        它们只是没在这轮里吭声。要确认某一台，去「连通性」页单独 ping 它。</p>` : ''}
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

function discoverCard() {
  const card = $(`<div class="card">
    <h2>听谁在应答（找没配网的设备）<span id="dv"></span></h2>
    <p class="hint">往 IPv6 组播喊一声，谁应答就记下来 —— 现场最常用的一招是
      <b>在一堆设备里把刚拆封、还没配 IPv4 地址的那台挑出来</b>。★ 它只能听见应 v6 的设备，
      纯 IPv4 的老设备看不见（那种用上面「扫一个网段」）。</p>
    <div class="row">
      <div style="flex:0 0 200px"><label>只在哪块网卡上听</label><input id="di" placeholder="留空 = 所有网卡"></div>
      <div style="flex:0 0 130px"><label>等待 ms</label><input id="dw" placeholder="1200"></div>
      <div style="flex:1 1 auto;align-self:flex-end"><button class="btn primary" id="dgo">听一次</button></div>
    </div>
    <div id="dout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#dout');
  const top = card.querySelector('#dv');
  card.querySelector('#dgo').onclick = async () => {
    top.innerHTML = '';
    const args = {};
    const i = card.querySelector('#di').value.trim();
    const w = Number(card.querySelector('#dw').value);
    if (i) args.iface = i;
    if (w > 0) args.waitMs = w;
    out.innerHTML = '<div class="empty">正在听…（要等组播应答跑完这一轮）</div>';
    const r = await call('net.discover', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">听不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = DISCOVER_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const rows = (v.devices || []).map((d) => {
      const un = !d.hasIPv4;
      return `<tr${un ? ' style="background:var(--gold-bg)"' : ''}>
        <td><code class="dim">${esc(d.linkLocal || '')}</code></td>
        <td>${un ? '<b>没有 IPv4</b>' : `<code>${esc(d.ipv4)}</code>`}</td>
        <td><code class="dim">${esc(d.mac || '—')}</code></td>
        <td class="dim">${esc(d.iface || '')}</td>
        <td class="dim">${d.rttMs ? esc(Math.round(d.rttMs)) + 'ms' : ''}</td>
        <td class="dim">${d.self ? '本机' : ''}</td></tr>`;
    }).join('');
    out.innerHTML = `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
        <div><label>应答</label><div><b>${esc(v.count)}</b> 台</div></div>
        <div><label>没配好地址</label><div><b>${esc(v.unconfigured || 0)}</b> 台</div></div>
        <div><label>在哪些网卡上听的</label><div>${esc((v.interfaces || []).join('、')) || '—'}</div></div>
      </div>
      ${v.probedV4Networks && v.probedV4Networks.length ? `<p class="dim" style="margin:0 0 10px">
        为了让「没有 IPv4」这个结论站得住，先把这些网段主动问过一遍：
        <code>${esc(v.probedV4Networks.join(' '))}</code>（ARP 只是缓存，光靠它会把活设备读成没配网）</p>` : ''}
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice)}</div>
      ${rows ? `<table style="margin-top:14px"><tr><th>IPv6 链路本地地址</th><th>IPv4</th><th>MAC</th>
        <th>网卡</th><th>等了</th><th></th></tr>${rows}</table>` : ''}
      ${v.skipped && v.skipped.length ? `<p class="dim" style="margin-top:10px">跳过：${esc(v.skipped.join('；'))}</p>` : ''}
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

// ★ 状态这一栏是这张表唯一说人话的地方，而三个平台打的是三套字母：
//   macOS/Linux 的 ndp 用 R/S/T/I/U，Linux 的 ip neigh 用 REACHABLE/STALE/FAILED，
//   Windows 直接打「动态/静态」。认不全的原样带出来就行 —— 那比猜错好。
const NBR_STATE = {
  R: ['可达', 'ok'],
  S: ['缓存里的旧记录', 'warn'],
  T: ['延迟确认', ''],
  I: ['没解析出来', 'warn'],
  U: ['不可达', 'bad'],
  G: ['刚被引用过', ''],
  REACHABLE: ['可达', 'ok'],
  STALE: ['缓存里的旧记录', 'warn'],
  DELAY: ['延迟确认', ''],
  PROBE: ['正在问', ''],
  INCOMPLETE: ['没解析出来', 'warn'],
  FAILED: ['没解析出来', 'warn'],
  '动态': ['刚问过', 'ok'],
  '静态': ['手工写死的', 'warn'],
};
// ★ 这一张不放顶层判定：它读的是本机缓存，没有「结论」可言 ——
//   有意义的是每一条的状态，人自己会判断哪几条算数。
function neighborsCard() {
  const card = $(`<div class="card">
    <h2>本机邻居表</h2>
    <p class="hint">一个包都不发，只读本机现在的邻居表：IPv4 是 ARP 表，IPv6 是 NDP 表，
      两张表一并给出。用它快速回答「这个 MAC 是哪个 IP」「刚才那个地址是谁」。
      ★ 这是<b>缓存</b>：表里没有它，<b>不等于</b>它不在 —— 要问「有谁在场」请用上面那张卡。</p>
    <div class="row">
      <div style="flex:0 0 160px"><label>看哪一族</label><input id="qf" value="both" placeholder="both / ipv4 / ipv6"></div>
      <div style="flex:0 0 200px"><label>只看某块网卡</label><input id="qi" placeholder="留空 = 全部"></div>
      <div style="flex:1 1 auto;align-self:flex-end"><button class="btn" id="qgo">读一次</button></div>
    </div>
    <div id="qout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#qout');
  card.querySelector('#qgo').onclick = async () => {
    out.innerHTML = '<div class="empty">读取中…</div>';
    const args = { family: card.querySelector('#qf').value.trim() || 'both' };
    const i = card.querySelector('#qi').value.trim();
    if (i) args.iface = i;
    const r = await call('net.neighbors', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">读不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const ns = (v.neighbors || []).map((n) => {
      const [w, pc] = NBR_STATE[n.state] || [n.state || '—', ''];
      // 没有 MAC 就是没解析出来 —— 不管状态那一栏是什么字母，都不许给个绿点
      const label = n.mac ? w : '没解析出来';
      const cls = n.mac ? (pc || '') : 'warn';
      return `<tr><td><code>${esc(n.addr)}</code></td>
        <td><code class="dim">${esc(n.mac || '—')}</code></td>
        <td class="dim">${esc(n.iface || '')}</td>
        <td class="dim">${esc(n.family || '')}</td>
        <td><span class="pill ${cls}">${esc(label)}</span></td></tr>`;
    }).join('');
    out.innerHTML = `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
        <div><label>多少条</label><div><b>${esc(v.count)}</b></div></div>
        <div><label>其中没解析出 MAC 的</label><div>${esc((v.neighbors || []).filter((n) => !n.mac).length)}</div></div>
      </div>
      ${ns ? `<table><tr><th>地址</th><th>MAC</th><th>网卡</th><th>族</th><th>状态</th></tr>${ns}</table>`
        : '<div class="empty">表是空的 —— 这台机器最近没跟谁通过话。这不是「网段里没人」的证据。</div>'}
      <p class="dim" style="margin:10px 0 0">「没解析出来」的那几条是内核之前问过、对方没应的占位记录 ——
        表里有这一行不等于设备在场。★ 这一张卡一个包都不发，它只是把本机现在记着什么念出来。</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

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

// ── 小工具 ──

/*
 * ★ 这一页放「不常用、但每次现场都要现查」的东西，所以不挤占前面几页：
 *   排障时人要的是连通性，不是掩码。
 */
async function renderTools(root) {
  root.appendChild(subnetCalcCard());
  root.appendChild(macCard());
  root.appendChild(macRandomCard());
  root.appendChild(codecCard());
  root.appendChild(wolCard());
  root.appendChild(fileshareCard());
}

// ★ 每个码带一句「所以下一步做什么」：这几个码的处置完全不同 ——
//   重叠要改配置，主机地址只是登记时别抄错，跨族是这个问题本身问不成立。
// ★ 有两句要按结果里的字段改口（写成函数）：/31 没有「网络地址不能分给设备」这回事，
//   而显式填了 /32 的人不是「忘填掩码」，说成他没填是在怪错人。
const SC_CODE = {
  'single-address': ['只是一个地址', '', (v) => v.prefixAssum
    ? '掩码没填上，所以按「一个地址」算 —— 没替你猜一个 /24。要算一段，把掩码补上再算一次。'
    : `填的就是 /${v.prefix}：一个地址自成一个段。要算一段，把斜杠后面的数字改小（如 /24）。`],
  'v4-network': ['填的是网段地址', 'ok', (v) => v.pointToPoint
    ? '这是 /31 互联口：这一段的两个地址都能配给设备，没有「减掉网络地址和广播地址」这一步。'
    : '这个可以直接登记。★ 网络地址本身不能分给设备用（它是「这一段」的名字）。'],
  'v4-host-address': ['填的是主机地址', 'warn', '段算得出来（见下），但登记时别把这个地址抄成网段地址。'],
  'v4-broadcast-address': ['填的是广播地址', 'bad', '它不能配在任何设备上 —— 大概率末段该写 0。'],
  'v6-prefix': ['IPv6 段', '', 'v6 没有广播地址、也没有「总数减二」，按下面「地址总数」那一栏读。'],
  'networks-overlap': ['两段重叠', 'bad',
    '这是「有时候连得上有时候连不上」的根因：两条路由都能到一个地址，走哪条看内核当时怎么选。得改掩码或改地址池。'],
  'families-differ': ['两族各自编址', '',
    '这个问法本身不成立 —— v4 段和 v6 段谈不上撞。要说「这台机器两族是不是都通」，去连通性页做双栈体检。'],
};

function subnetCalcCard() {
  const card = $(`<div class="card">
    <h2>子网计算 <span id="sc-top"></span></h2>
    <p class="hint">填什么都认：192.168.1.0/24、192.168.1.0/255.255.255.0（从设备页抄下来的写法）、
      只写地址（按一个地址算，★ 不替你猜 /24）。
      掩码 1 不连续（比如 255.0.255.0）会直接报错 —— 那种掩码不成段，硬算出来的答案是假的。
      纯算术，不发任何包，所以它答不了「这段里有没有人」，那要用网段扫描。</p>
    <div class="row">
      <div style="flex:1 1 260px"><label>要算的段或地址</label>
        <input id="sc-cidr" placeholder="192.168.1.100/255.255.255.0"></div>
      <div style="flex:1 1 260px"><label>对照段（可留空，填了就问撞不撞）</label>
        <input id="sc-peer" placeholder="192.168.1.128/25"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn primary" id="sc-go">算</button></div>
    </div>
    <div id="sc-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#sc-out');
  const top = card.querySelector('#sc-top');
  const run = async () => {
    const args = { cidr: card.querySelector('#sc-cidr').value.trim() };
    const peer = card.querySelector('#sc-peer').value.trim();
    if (peer) args.peer = peer;
    if (!args.cidr) { out.innerHTML = '<div class="empty">先填要算的段或地址。</div>'; return; }
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">计算中…</div>';
    const r = await call('net.subnet.calc', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">算不了：${esc(r.message || r.error)}</div>`; return; }
    const v = r.values;
    const [title, cls, advice] = SC_CODE[r.verdict] || [r.verdict || '没给判定', '', ''];
    const say = typeof advice === 'function' ? advice(v) : advice;
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    // ★ 只列后端真给了的字段：v6 没有掩码/通配码/广播，硬排上去会出现「广播：undefined」
    const items = [
      ['规整网段', v.canonical], ['这个段是', v.network],
      ['掩码', v.mask], ['通配码', v.wildcard],
      ['地址总数', v.size], ['可用主机数', v.usable],
      ['首个可用', v.firstUsable], ['末个可用', v.lastUsable], ['广播地址', v.broadcast],
      ['反向解析区', v.reverseZone],
    ].filter((x) => x[1] !== undefined && x[1] !== '');
    const n6 = v.v6Notes || {};
    if (n6.kind) items.push(['地址性质', ({
      ula: '站内自建（ULA）—— 不该出现在公网', 'link-local': '链路本地 —— 出不了这条链路',
      global: '公网可路由', multicast: '组播地址 —— 不是用来配的', loopback: '本机回环',
    }[n6.kind] || n6.kind)]);
    if (n6.sla64Count) items.push(['可切出的 /64', n6.sla64Count + ' 个（v6 通常一条链路一个 /64）']);
    if (v.pointToPoint) items.push(['点对点段', '两个地址都能用（/31 互联口，没有网络/广播地址）']);
    if (v.peer) items.push(['对照段', v.peer]);
    const rel = [];
    if (v.overlaps === true) {
      rel.push(['怎么撞的', ({
        'identical': '两段完全相同', 'peer-inside': '填的这段把对照段整个包住',
        'peer-contains': '对照段把填的这段整个包住',
      }[v.contains] || v.contains)]);
      if (v.overlapSize) rel.push(['重叠地址数', v.overlapSize]);
    }
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(say)}</div>
      <table style="margin-top:14px"><tr><th></th><th></th></tr>
        ${items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><code>${esc(x)}</code></td></tr>`).join('')}
        ${rel.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><b>${esc(x)}</b></td></tr>`).join('')}</table>
      ${v.prefixAssum ? '<p class="hint">★ 输入的掩码是空的，这一栏按「一个地址」算 —— 没有替你猜一个 /24。</p>' : ''}
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  card.querySelector('#sc-go').onclick = run;
  card.querySelector('#sc-cidr').onkeydown = (e) => { if (e.key === 'Enter') run(); };
  card.querySelector('#sc-peer').onkeydown = (e) => { if (e.key === 'Enter') run(); };
  return card;
}

// ── MAC / OUI 查询 ──

// ★ 每个码带一句「所以下一步做什么」：这一栏真正的分歧不是「认不认识厂商」，
//   而是**这个地址能不能当设备身份** —— 全零要去查网卡，组播不是一台设备，
//   本机管理位置着的会把一台数成好几台。认不出厂商名不影响它是个好身份。
const MA_CODE = {
  'mac-unset': ['没读到 MAC', 'bad',
    '六个字节全零 —— 这不是「厂商库里缺这一条」，是这块网卡根本没把地址交出来'
    + '（MAC 没烧进去、驱动没读上来、或那是个没配地址的虚拟接口）。去查网卡，别换库、别换工具。'],
  'mac-broadcast': ['广播地址', 'bad',
    '全一只能用来发，不许当任何设备的源地址。邻居表里出现它，记下的是协议帧的目的地，不是一台设备。'],
  'protocol-group': ['不是一台设备', '', (v) => v.who
    ? `这是${v.who}，出处 ${v.whoSrc} —— 协议规定的地址。${v.whoWhy || ''}`
    : '第一个字节最低位是 1，说明它是发给「一组地址」的，本来就不对应某一台设备。'],
  'virtual-nic': ['像是虚机 / 容器', 'warn', (v) =>
    `${v.who}（依据 ${v.whoSrc}）。${v.whoWhy || ''}`
    + ' ★ 这是按软件的默认地址段推的，属推测 —— 不是哪里的登记信息。'],
  'locally-administered': ['地址是软件造的', 'warn',
    '本机管理位是置着的：iOS / Android 的私有 Wi-Fi 地址、Windows 的随机 MAC、MAC 克隆都在这里。'
    + '别拿它当设备唯一标识 —— 同一台设备换个网络就可能换一个，用它做统计会把一台数成好几台。'],
  'device-address': ['厂商发的地址', 'ok', (v) => v.who
    ? `厂商多半是 ${v.who}。${v.whoWhy || ''}`
    : '这个地址可以当设备身份用。' + (v.vendorWhy || '')],
};

function macCard() {
  const card = $(`<div class="card">
    <h2>MAC 地址 <span id="ma-top"></span></h2>
    <p class="hint">粘什么写法都认：02:42:ac:11:00:02、02-42-ac-11-00-02、0242.ac11.0002（交换机）、
      0242ac110002（连写）。答的是「这个地址能不能当设备身份」，不只是「它是谁」：
      全零是网卡没交出地址，组播本来就不是一台设备，本机管理位置着的多半是随机地址或虚机网卡。
      ★ 厂商名默认不报 —— IEEE 那张注册表是非商业许可，不打进安装包；
      要这一栏有名字，把后端的环境变量 NETKIT_OUI_FILE 指到你从 ieee.org 下的 oui.txt。
      纯解析，不发任何包。</p>
    <div class="row">
      <div style="flex:1 1 320px"><label>要问的 MAC / 以太网地址</label>
        <input id="ma-mac" placeholder="02:42:ac:11:00:02"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn primary" id="ma-go">查</button></div>
    </div>
    <div id="ma-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#ma-out');
  const top = card.querySelector('#ma-top');
  const run = async () => {
    const args = { mac: card.querySelector('#ma-mac').value.trim() };
    if (!args.mac) { out.innerHTML = '<div class="empty">先填要问的 MAC。</div>'; return; }
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">查中…</div>';
    const r = await call('net.mac.analyze', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">查不了：${esc(r.message || r.error)}</div>`; return; }
    const v = r.values;
    const [title, cls, advice] = MA_CODE[r.verdict] || [r.verdict || '没给判定', '', ''];
    const say = typeof advice === 'function' ? advice(v) : advice;
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    // ★ 只列后端真给了的字段：组播地址不给接口标识，非 Docker 前缀不给反推的 IPv4，
    //   硬排上去就会显示「IPv6 接口标识：undefined」，而那一栏看起来像真的
    const items = [
      ['这个地址', v.canonical], ['交换机写法', v.dotForm], ['连写', v.bareForm],
      ['地址长度', v.family === 'eui-64' ? `${v.octets} 字节（EUI-64）` : `${v.octets} 字节`],
      ['第一个字节', `${v.firstOctet}（二进制 ${v.firstOctetBin}）`],
      // ★ 全零 / 全一不谈「发给谁、哪来的」：那两栏会把人带回「这是台设备的地址」，
      //   而这一档的结论恰恰是它不属于任何设备
      v.special ? ['这种地址', v.special === 'all-zero'
        ? '六个字节全零 —— 不是任何设备的地址' : '六个字节全一 —— 广播，只用于发']
        : ['发给谁', v.group ? '一组地址（组播）' : '一台设备（单播）'],
      !v.special && ['地址哪来的', v.administered === 'local'
        ? '本机管理 —— 不是哪家厂商名下的地址（随机地址、虚机网卡、协议组播都在这里）'
        : '全球唯一 —— 前缀是 IEEE 分给某厂商的'],
      // ★ 「厂商前缀」这个名字只给真在厂商名下的地址用：组播、随机地址、全零 / 全一
      //   的前 3 字节不在任何厂商名下，标成「厂商前缀」就是在编一个没登记的归属
      v.special || v.administered !== 'global' || v.group ? ['前 3 字节', v.oui] : ['厂商前缀', v.oui],
      v.special || v.administered !== 'global' || v.group ? ['其余字节', v.nic] : ['设备位', v.nic],
      ['IPv6 接口标识', v.iid && `${v.iid}（EUI-64，SLAAC 配出来的地址里就是这段）`],
      ['藏着的 IPv4', v.derivedIPv4 && `${v.derivedIPv4}（Docker 把容器地址写进了后四字节）`],
    ].filter((x) => x && x[1] !== undefined && x[1] !== '');
    const bold = [];
    if (v.who) bold.push(['来路', `${v.who}（${v.whoBasis === 'standard' ? '协议规定，是事实'
      : v.whoBasis === 'registry' ? '按你挂的厂商表查的' : '软件约定推的，属推测'}）`]);
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(say)}</div>
      <table style="margin-top:14px"><tr><th></th><th></th></tr>
        ${items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><code>${esc(x)}</code></td></tr>`).join('')}
        ${bold.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><b>${esc(x)}</b></td></tr>`).join('')}</table>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  card.querySelector('#ma-go').onclick = run;
  card.querySelector('#ma-mac').onkeydown = (e) => { if (e.key === 'Enter') run(); };
  return card;
}

// ── 随机 / 克隆 MAC 生成 ──

// ★ 两种模式的差别不是「好不好看」，是**这个地址在谁名下**：
//   纯随机置了本机管理位，不属于任何厂商，随便用；保留厂商前缀就是去别人名下的段里造地址，
//   随机位一算出来只有两千多万，撞上真设备是「几台机器同时时通时不通」，得让人自己决定。
const MR_CODE = {
  'random-generated': ['可以放心用', 'ok',
    '本机管理位是置着的、组播位是清着的：能当设备源地址，也不在任何厂商名下的地址段里。'
    + '随机部分 40 位，局域网里撞不上真设备。★ 这里只是生成了字符串，本机网卡地址没动。'],
  'clone-generated': ['保留了你给的前缀', 'warn', (v) =>
    `前缀 ${v.prefix} 原样保留，随机部分只剩 ${v.randomBits} 位（${v.space} 个组合）。`
    + (v.vendorBlock
      ? '★ 这个前缀是 IEEE 登记给某家厂商的 —— 那一段里的真设备是活着的，撞上就是两台机器同一个 MAC，'
        + '症状是「几台机器同时时通时不通」，比配不上难查得多。确认要再用。'
      : '这个前缀本身是本机管理段，不在任何厂商名下。')],
};

function macRandomCard() {
  const card = $(`<div class="card">
    <h2>随机 MAC <span id="mr-top"></span></h2>
    <p class="hint">生成能直接用的地址：默认把本机管理位置着、组播位清着 —— 少处理一位，
      症状都不是「生成失败」而是配上去收不到回包，或者撞进别人名下的地址段。
      填了前缀就是克隆模式（有些系统的授权看 MAC 前缀），那一档会把随机位还剩多少、
      是不是在厂商名下算给你看。★ 只生成字符串，不改任何网卡设置。</p>
    <div class="row">
      <div style="flex:1 1 200px"><label>生成几个（1~10）</label>
        <input id="mr-count" placeholder="1"></div>
      <div style="flex:1 1 260px"><label>保留的前缀（可留空；也可粘一个完整 MAC）</label>
        <input id="mr-prefix" placeholder="00:1a:2b"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn primary" id="mr-go">生成</button></div>
    </div>
    <div id="mr-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#mr-out');
  const top = card.querySelector('#mr-top');
  const run = async () => {
    const args = {};
    const c = card.querySelector('#mr-count').value.trim();
    // ★ 只 trim 显示、不按 trim 后的空不空来决定发不发：输入框里敲了几个空格就算「给了前缀」，
    //   这里替它丢掉等于偷偷换成纯随机，而人要的是克隆 —— 后端专门拦这一条，界面不许绕过
    const p = card.querySelector('#mr-prefix').value;
    if (c && !/^\d+$/.test(c)) {
      out.innerHTML = '<div class="empty">生成不了：「几个」那一栏要写 1~10 的数字。</div>';
      return;
    }
    if (c) { args.count = Number(c); }
    if (p !== '') { args.prefix = p; }
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">生成中…</div>';
    const r = await call('net.mac.random', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">生成不了：${esc(r.message || r.error)}</div>`; return; }
    const v = r.values;
    const [title, cls, advice] = MR_CODE[r.verdict] || [r.verdict || '没给判定', '', ''];
    const say = typeof advice === 'function' ? advice(v) : advice;
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const f = v.formats || {};
    const items = [
      ['模式', v.mode === 'clone' ? `克隆（保留 ${v.prefix}）` : '纯随机（本机管理 + 单播）'],
      ['随机部分', `${v.randomBits} 位，${v.space} 个组合`],
      ['第一个字节怎么处理', v.firstOctetPolicy],
      ['第一个的其它写法', `${f.dash || ''} / ${f.dot || ''} / ${f.bare || ''}`],
    ].filter((x) => x[1] !== undefined && x[1] !== '');
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(say)}</div>
      <div style="margin-top:12px;display:flex;flex-direction:column;gap:6px">
        ${(v.macs || []).map((m) => `<code class="mono" style="font-size:15px;user-select:all;cursor:pointer" title="点一下整条选中">${esc(m)}</code>`).join('')}
      </div>
      <table style="margin-top:14px"><tr><th></th><th></th></tr>
        ${items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><code>${esc(x)}</code></td></tr>`).join('')}</table>
      <p class="hint">点上面任意一个地址选中后可复制；要看看它会被读成什么，粘到上面那张「MAC 地址」卡里查一次。</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  card.querySelector('#mr-go').onclick = run;
  card.querySelector('#mr-count').onkeydown = (e) => { if (e.key === 'Enter') run(); };
  card.querySelector('#mr-prefix').onkeydown = (e) => { if (e.key === 'Enter') run(); };
  return card;
}

// ★ 编解码这一页的措辞难点在「解出来不是文本」：多数工具在这儿报「失败」，
//   人就换工具、或者去查设备坏没坏 —— 而那两种都不是结论。所以每一档都带下一步。
const CC_CODE = {
  'decoded-text': ['解出来了，是可读文本', 'ok', (v) =>
    (v.shape === 'jwt'
      ? '这是一枚签名令牌，上面已经把头解出来 —— ★ 这里只解码，不验签，所以「解得开」不等于「这枚令牌有效」。载荷里常带账号、内部 IP，别整段贴进工单。'
      : '下面那一栏就是解出来的原文，可以直接复制。') +
    (v.alphabetUnclaimed
      ? ' 这一段里 + 和 / 、- 和 _ 都没出现过，两派 base64 字母表解出来一模一样 —— 指哪一种都不影响结果；' +
        '哪天串里真出现了这一类字符，指错了会被当场拦下来，不会悄悄解成一个错值。'
      : '')],
  'decoded-binary': ['解出来是二进制', 'warn', (v) =>
    v.looksLikeGbk
      ? '这一串既不是合法 UTF-8、也不像随机数据，而是老设备固件里那种 GBK 中文。这里不替你猜字符表 —— 猜出来的中文比乱码更容易被当成事实。要看成人话，得拿转码工具整份转一次。'
      : '★ 解码没有失败：是这些字节本来就不该当文本读。要么它是加密 / 压缩过的数据（那本来就解不出人话），要么它压根不是这一种编码 —— 换一种读法再判一次。'],
  'still-encoded': ['还套着一层编码', 'warn', '解出来一次，里面还剩编码 —— 多半是被编了两遍（常见于把一个链接整个塞进另一个链接的参数里）。再判一次就解到底了。'],
  'ambiguous-encoding': ['几种读法都成立', 'warn', (v) =>
    `几种读法各自解出了不同东西，都列在下面了。多半是 ${CC_ENC[v.mostLikely] || v.mostLikely} —— ${v.why || ''}。★ 没替你挑一个，因为挑错了你会拿着那个结果去对设备。`],
  'plain-text': ['这段没在编码', '', (v) => v.why || '它原样就是它自己。'],
  'not-decodable': ['这一种解不开', 'bad', (v) => v.why || '解不开。'],
  encoded: ['编好了', 'ok', '挑一种贴走。★ base64 不是加密，别拿它藏密码 —— 它一眼就能解回来。'],
};

const CC_ENC = {
  base64: 'Base64（标准字母表）', base64url: 'Base64（URL 安全，带 - 和 _）',
  hex: '十六进制', url: 'URL 百分号转义', unicode: '\\u 转义', jwt: '签名令牌',
};

// ★ 工具替人放宽了什么，必须逐条摆出来：不记下来就等于悄悄改了数据。
const CC_FIX = {
  'outer-whitespace': '去掉了首尾空白',
  'quotes-trimmed': '去掉了成对引号',
  'padding-added': '补上了缺失的填充符 =',
  'url-safe-alphabet': '按 URL 安全字母表读的（认了 - 和 _）',
  'line-wrapped': '去掉了折行带的换行（命令行输出那种每 76 列一段）',
  'inner-whitespace': '去掉了中间的空格 —— ★ 要是这段是从网址里抄的，那个空格原本可能是个加号',
  'hex-0x-prefix': '去掉了开头的 0x',
  'separators-removed': '去掉了字节之间的分隔符',
  'plus-in-url': '串里有加号，按「查询串」和「路径」两种读法分开给了',
};

function codecCard() {
  const card = $(`<div class="card">
    <h2>编解码 <span id="cc-top"></span></h2>
    <p class="hint">整段贴进来：Base64 / Base64URL / 十六进制 / 网址百分号转义 / \\u 转义，认得出是哪种并解开；
      反过来要编进去也行。
      ★ 解出来不是文本时不会报「失败」—— 二进制就是二进制，那是两种不同的下一步。
      几种读法都说得通的串（比如 32 个十六进制字符），两种结果都摆出来让你指一个，不替你猜。
      纯字符串运算：不发任何包，也不碰文件。</p>
    <div class="row">
      <div style="flex:1 1 100%"><label>要判的字符串</label>
        <textarea id="cc-text" rows="3" placeholder="贴 Base64、网址里抄的一段、或者一串十六进制"
          style="width:100%"></textarea></div>
    </div>
    <div class="row">
      <div style="flex:1 1 160px"><label>怎么处理</label>
        <select id="cc-op">
          <option value="auto">自动（判是什么并解开）</option>
          <option value="decode">只要解开</option>
          <option value="encode">只要编进去</option>
        </select></div>
      <div style="flex:1 1 190px"><label>按哪种读法（可留自动）</label>
        <select id="cc-enc">
          <option value="">自动判断</option>
          <option value="base64">Base64</option>
          <option value="base64url">Base64URL</option>
          <option value="hex">十六进制</option>
          <option value="url">URL 转义</option>
          <option value="unicode">\\u 转义</option>
        </select></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn primary" id="cc-go">判一下</button></div>
    </div>
    <div id="cc-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#cc-out');
  const top = card.querySelector('#cc-top');
  const mono = 'user-select:all;cursor:pointer;word-break:break-all';
  const run = async () => {
    const text = card.querySelector('#cc-text').value;
    if (!text.trim()) { top.innerHTML = ''; out.innerHTML = '<div class="empty">先贴一段字符串。</div>'; return; }
    const args = { text, op: card.querySelector('#cc-op').value };
    const enc = card.querySelector('#cc-enc').value;
    if (enc) args.encoding = enc;
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">判一下…</div>';
    const r = await call('net.codec.convert', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">判不了：${esc(r.message || r.error)}</div>`; return; }
    const v = r.values;
    const [title, cls, advice] = CC_CODE[r.verdict] || [r.verdict || '没给判定', '', ''];
    const say = typeof advice === 'function' ? advice(v) : advice;
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const fixes = (v.normalized || []).map((f) => CC_FIX[f] || f);
    // ★ 只列后端真给了的：解出来是二进制就没有 text 那一栏，硬排会出「undefined」
    // ★ 同一个字段在不同判定下说的是两件事：解不开那一档里的 encoding 是「你指的读法」，
    //   不是「我们认出来的」；明文那一档的 byteLen 是贴进来的长度，不是解出来的
    const rejected = r.verdict === 'not-decodable';
    const passthrough = r.verdict === 'plain-text' || r.verdict === 'encoded';
    const items = [
      [rejected ? '你指的读法' : '认出的写法', v.encoding ? (CC_ENC[v.encoding] || v.encoding) : undefined],
      [passthrough ? '这段多少字节' : '解出多少字节',
        v.byteLen !== undefined && r.verdict !== 'encoded' ? String(v.byteLen) : undefined],
      ['是不是合法 UTF-8', v.utf8 === undefined ? undefined : (v.utf8 ? '是' : '不是')],
      ['头（签名令牌）', v.header],
      ['按查询串读', v.plusAmbiguous ? v.asQuery : undefined],
      ['按路径读', v.plusAmbiguous ? v.asPath : undefined],
      ['原文', v.plainText],
      ['Base64', v.base64], ['Base64URL', v.base64url],
      ['十六进制', v.hex],
      ['URL 转义', v.url], ['\\u 转义', v.unicode],
      ['编了多少字节', r.verdict === 'encoded' ? String(v.byteLen) : undefined],
    ].filter((x) => x[1] !== undefined && x[1] !== '');
    const rows = items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
      <td><code style="${mono}">${esc(x)}</code></td></tr>`).join('');
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(say)}</div>
      ${fixes.length ? `<p class="hint" style="margin-top:8px">替你放宽过：${esc(fixes.join('；'))}</p>` : ''}
      ${v.text ? `<div style="margin-top:10px"><label class="dim">解出来</label>
        <pre style="${mono};margin:4px 0 0;white-space:pre-wrap">${esc(v.text)}</pre></div>` : ''}
      ${v.hexDump ? `<div style="margin-top:10px"><label class="dim">按字节看</label>
        <pre style="${mono};margin:4px 0 0;white-space:pre-wrap">${esc(v.hexDump)}</pre></div>` : ''}
      ${v.readings ? `<table style="margin-top:12px"><tr><th>读法</th><th>解出来</th><th>这一种放宽过什么</th></tr>
        ${v.readings.map((x) => `<tr><td class="dim" style="white-space:nowrap">${esc(CC_ENC[x.encoding] || x.encoding)}
          ${x.encoding === v.mostLikely ? '（多半是这种）' : ''}</td>
          <td><code style="${mono}">${esc(x.readable ? x.text : x.hexDump)}</code></td>
          <td class="dim">${esc((x.normalized || []).map((f) => CC_FIX[f] || f).join('；')) || '—'}</td></tr>`).join('')}</table>` : ''}
      ${rows ? `<table style="margin-top:14px"><tr><th></th><th></th></tr>${rows}</table>` : ''}
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  card.querySelector('#cc-go').onclick = run;
  card.querySelector('#cc-text').onkeydown = (e) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) run();
  };
  return card;
}

// ── net.wol：唤醒一台机器 ──
//
// ★★ 这一页的难点不是「怎么发」，是**别把「发出去了」说成「醒了」**。
//   唤醒失败的现场表象永远是同一个：没有人报错。所以每一栏都要说清
//   「这一栏能证明什么」：从哪块网卡发的、发到哪、对方此刻在不在邻居表里。

// 发出去了，但「醒没醒」要另一步验
const WL_SENT = {
  'sent-broadcast': ['已发到本机网段', 'ok'],
  'sent-unicast': ['已发到指定地址', 'ok'],
};
const WL_CODE = {
  'likely-awake': ['它此刻在邻居表里，没发', 'warn'],
};
// 这块网卡是怎么定下来的——现场发错地方，八成在这一步
const WL_FROM = {
  'given': '你指定的',
  'neighbor-table': '这个 MAC 在邻居表里是从这块网卡学到的',
  'default-route': '没有它的记录，按 IPv4 默认路由选了这块',
  'only-usable-v4': '没默认路由，本机只有这一块带可用 IPv4 的网卡',
};
const WL_DST = {
  'directed-broadcast': '本机网段的定向广播地址',
  'forwarded-unicast': '你指定的地址（跨网段）',
};

function wolCard() {
  const card = $(`<div class="card">
    <h2>Wake-on-LAN 唤醒 <span id="wl-top"></span></h2>
    <p class="hint">往目标网卡的 MAC 发一枚魔术帧，把睡着的机器叫起来。
      ★ 这会改变那台机器的状态，所以一次只唤醒一台、要你点头才发，并且留一笔痕迹。
      默认只往指定网卡自己网段的广播地址发（不用全 255 那一发，它从默认路由的网卡出去，
      可能吵醒一整层楼）。网卡留空就自己推：先看这个 MAC 是哪块网卡学到的，再看默认路由。
      ★ 发出去不等于醒了：看结果里「从哪发到哪」和「它在不在邻居表里」两栏，
      最后一步是过一两分钟回来看它回没回来。</p>
    <div class="row">
      <div style="flex:1 1 220px"><label>要唤醒的 MAC（只能一台）</label>
        <input id="wl-mac" placeholder="aa:bb:cc:dd:ee:ff"></div>
      <div style="flex:1 1 140px"><label>从哪块网卡（留空自动选）</label>
        <input id="wl-iface" placeholder="en0 / eth0"></div>
      <div style="flex:1 1 180px"><label>跨网段时发到哪（目标网段广播地址）</label>
        <input id="wl-host" placeholder="留空 = 本机网段"></div>
    </div>
    <div class="row">
      <div style="flex:0 0 110px"><label>端口</label>
        <input id="wl-port" placeholder="9"></div>
      <div style="flex:0 0 110px"><label>连发几枚</label>
        <input id="wl-repeats" placeholder="1"></div>
      <div style="flex:1 1 180px"><label>SecureOn 口令（可留空，不会被记下来）</label>
        <input id="wl-pass" type="password" autocomplete="off" placeholder="4 或 6 字节 hex"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn danger" id="wl-go">唤醒这台</button></div>
    </div>
    <label style="display:flex;gap:6px;align-items:center;margin-top:8px;font-size:13px">
      <input type="checkbox" id="wl-force" style="flex:0 0 auto">
      邻居表里现在还有它（刚才醒着）也照发 —— 部分主机会因此走一次开机流程</label>
    <div id="wl-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#wl-out');
  const top = card.querySelector('#wl-top');
  const run = async () => {
    const mac = card.querySelector('#wl-mac').value.trim();
    if (!mac) {
      out.innerHTML = '<div class="empty">先写要唤醒哪一台：从设备标签、DHCP 租约或邻居表里抄它的 MAC。</div>';
      return;
    }
    const args = { mac };
    const iface = card.querySelector('#wl-iface').value.trim();
    const host = card.querySelector('#wl-host').value.trim();
    const port = card.querySelector('#wl-port').value.trim();
    const rep = card.querySelector('#wl-repeats').value.trim();
    const pass = card.querySelector('#wl-pass').value.trim();
    if (iface) { args.iface = iface; }
    if (host) { args.host = host; }
    if (port) { args.port = Number(port); }
    if (rep) { args.repeats = Number(rep); }
    if (pass) { args.secureOn = pass; }
    if (card.querySelector('#wl-force').checked) { args.force = true; }
    top.innerHTML = '';
    // ★ 等批准：这一发会改变对面那台机器，所以必须有人点头，取消就什么都不发生
    out.innerHTML = '<div class="empty">等你点批准…（取消的话一枚都不发）</div>';
    const r = await call('net.wol', args);
    card.querySelector('#wl-pass').value = '';  // 口令不留在输入框里
    if (!r.ok) {
      out.innerHTML = `<div class="empty">没有发出去：${esc(r.message || r.error)}</div>`;
      return;
    }
    const v = r.values || {};
    const sent = WL_SENT[r.verdict];
    const awake = WL_CODE[r.verdict];
    let title, cls;
    if (sent) { [title, cls] = sent; } else if (awake) { [title, cls] = awake; } else {
      title = r.verdict || '没给判定'; cls = '';
    }
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    let say;
    if (sent) {
      say = `已经发出去的只证明「从这块网卡到了这个地址」，不证明它醒了。`
        + (v.needsRelay
          ? ' ★ 这一发的目标不在本机任何网段里，要经路由器转发 —— '
            + '多数路由器默认丢掉定向广播，没醒先怀疑这一条。'
          : ' 过一两分钟回来看邻居表：它回来了才是真醒了。')
        + (v.seenAt ? ` 发之前邻居表里已经有它（${esc(v.seenAt)}），是你勾了照发才发的。`
          : ' 发之前邻居表里没有它。');
    } else if (awake) {
      say = `没有发。邻居表里现在还有它（${esc(v.seenAt || '没给地址')}），说明它刚才大概率醒着`
        + '。★ 这不是铁证：条目要几分钟才过期。确定它是关着的话勾上下面那个框再发一次。';
    } else {
      say = '后端给了一个这里还没认得的判定，原文在下面展开看。';
    }
    const items = [
      ['唤醒哪台', v.mac],
      ['从哪块网卡', v.iface ? `${v.iface}（${WL_FROM[v.ifaceFrom] || v.ifaceFrom || '没说怎么选的'}`
        + (v.ifaceKind ? `，${v.ifaceKind}` : '') + (v.ifaceVirtual ? '，虚拟/隧道口' : '') + '）' : undefined],
      ['本机地址', v.src ? `${v.src}（${v.subnet}）` : undefined],
      [sent ? '发到哪' : '本来会发到哪',
        v.dst ? `${v.dst}:${v.port}（${WL_DST[v.dstKind] || v.dstKind}）` : undefined],
      ['发了几枚', v.sent === undefined ? undefined
        : v.sent ? `${v.sent} / 要发 ${v.sends}` : `一枚都没发（要发 ${v.sends}）`],
      ['帧', v.frame ? `${v.frameBytes} 字节` : undefined],
      ['口令', v.passwordUsed ? '用过，没写进结果和日志' : undefined],
    ].filter((x) => x[1] !== undefined && x[1] !== '');
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${say}</div>
      ${v.frame ? `<div style="margin-top:10px"><label class="dim">发出去的帧（和别人的工具对拍，口令不在里面）</label>
        <pre class="mono" style="margin:4px 0 0;word-break:break-all;font-size:11.5px">${esc(v.frame)}</pre></div>` : ''}
      <table style="margin-top:14px"><tr><th></th><th></th></tr>
        ${items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><code>${esc(x)}</code></td></tr>`).join('')}</table>
      ${sent ? `<p class="hint">没醒的常规原因，按概率排：设备没在开机卡/电源供电（WoL 要待机取电）、
        固件里这个功能没开、换机器换了网卡所以 MAC 不对、快速启动导致关机后不再监听、
        以及跨网段那一发被路由器丢了。</p>` : ''}
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  card.querySelector('#wl-go').onclick = run;
  card.querySelector('#wl-mac').onkeydown = (e) => { if (e.key === 'Enter') run(); };
  return card;
}

// ── 路由表：去往一个地址，到底从哪块网卡出去 ──
//
// ★★ 这张表是本项目一半结论的地基（wol 说「从哪块网卡发」、dualstack 看「有没有默认
//   路由」、trace 的第一跳就是它），可用户原先没有任何地方能看到它。
//   多网卡工控机上「时通时不通」「换台机器就通」，十有八九就是这张表里有两条在打架。
//
// ★ 界面上只说**该走哪**，一个字都不说「走得到」：这一读纯在本机，一个包都没发。
//   把「按本机规则该走这条路」写成「能通」，是这类工具最常见的越界。

const RT_CODE = {
  'routes-listed': ['已读到本机路由表', ''],
  'route-found': ['出口确定了', 'ok'],
  'no-route': ['没有路可走', 'bad'],
  'route-mismatch': ['按表算的和系统选的不一样', 'warn'],
  'route-split': ['一个名字解出几个地址，走的路不一样', 'warn'],
  'route-local': ['这个地址就是本机自己', 'warn'],
  'multi-default-route': ['同族有多条默认路由', 'bad'],
  'table-unreadable': ['这台机器上读不到路由表', 'bad'],
};
const RT_FROM = {
  os: '系统自己给的',
  table: '按表算的（照这张表做最长前缀匹配）',
};

function routesCard() {
  const card = $(`<div class="card">
    <h2>路由表 <span id="rt-top"></span></h2>
    <p class="hint">本机所有出口的总账，并且能问一句「去往这个地址会从哪块网卡出去」。
      ★ 纯读本机，一个探测包都不发（只有你填的是域名时解析一次）；
      所以它答的是<strong>该走哪</strong>，不是<strong>走不走得到</strong>。
      多网卡机器上「时通时不通」、插了 VPN 之后某个网段上不去，都是这张表里两条在打架。
      表按系统选路的优先级排：越具体的网段越靠前，默认路由压在最后 ——
      按顺序从上往下看第一条盖得住的，就是实际生效的那条。</p>
    <div class="row">
      <div style="flex:1 1 240px"><label>去往哪儿（地址或域名，留空 = 只看表）</label>
        <input id="rt-dest" placeholder="192.168.1.100 / fd00::1 / camera.local"></div>
      <div style="flex:0 0 150px"><label>看哪一族</label>
        <select id="rt-family">
          <option value="">两族都看</option>
          <option value="ipv4">只看 IPv4</option>
          <option value="ipv6">只看 IPv6</option>
        </select></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn primary" id="rt-go">读一下</button></div>
    </div>
    <div id="rt-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#rt-out');
  const top = card.querySelector('#rt-top');

  const destOf = (r) => (r.destination === '0.0.0.0/0' || r.destination === '::/0')
    ? 'default' : r.destination;
  const isDefault = (r) => r.destination === '0.0.0.0/0' || r.destination === '::/0';

  // 一行「该走哪」的答复。并列、问不到、直连，全部要说在明处。
  const decideLine = (d, ties, extra) => {
    const parts = [`去往 <code>${esc(d.addr)}</code> 从 <b>${esc(d.iface || '（没给网卡名）')}</b> 出去`];
    parts.push(d.gateway ? `下一跳 <code>${esc(d.gateway)}</code>`
      : '是本网段直连，不经过网关');
    if (d.from === 'table') {
      // 按表算的答案：把真正生效的那一条指给人看（表里就有这一行，高亮着）
      parts.push(`命中的是 <code>${esc(destOf(d))}</code> 那一行`);
    }
    parts.push(`依据：${RT_FROM[d.from] || d.from}`);
    if (d.metric) parts.push(`度量 ${d.metric}`);
    if (d.src) parts.push(`本机用 <code>${esc(d.src)}</code>`);
    if (ties) {
      parts.push(`★ 还有 ${ties} 条同样匹配，而本机没给可比的依据（表里不带度量），`
        + '这里列的只是其中一条 —— 别把它当成「就这一条路」');
    }
    if (extra) parts.push(extra);
    return parts.join('；') + '。';
  };

  const run = async () => {
    const args = {};
    const dest = card.querySelector('#rt-dest').value.trim();
    const fam = card.querySelector('#rt-family').value;
    if (dest) args.dest = dest;
    if (fam) args.family = fam;
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">读中…</div>';
    const r = await call('net.routes', args);
    if (!r.ok) {
      // ★ 解不开名字这一句必须留着：不写「.local 走 mDNS」，
      //   人会以为那台设备下线了，接着去 ping —— 而 ping 同样解不开这个名字。
      out.innerHTML = `<div class="empty">没读到：${esc(r.message || r.error)}</div>`;
      return;
    }
    const v = r.values || {};
    const [title, cls] = RT_CODE[r.verdict] || [r.verdict || '没给判定', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';

    let say;
    switch (r.verdict) {
      case 'route-found':
        say = decideLine(v.decision || {}, v.ties || 0,
          v.osUnavailable ? '★ 系统那边问不到（这个平台没有「问一句」的命令，或者它没答），所以这一条是照表算的' : '');
        break;
      case 'multi-default-route':
        say = '同一族有两条以上的默认路由。★ 出外网走哪条不看表的顺序，只看度量 —— '
          + '这就是「ping 得通一半」「插了 VPN 某个网段上不去」最常见的来源。'
          + '下面「默认路由」那一栏把每一条挂在哪块网卡都列出来了。'
          + '★ 先按网卡名分一下：多出来的那些如果都挂在 utun / ppp / tun / tap 这类'
          + '隧道口上，那是 VPN 自己在收路线，一般不算故障；'
          + '两块物理网卡（en / eth / WLAN 之类）各带一条默认路由，才是真会时通时不通的那种。';
        break;
      case 'no-route':
        say = v.familyRoutes === 0
          ? `<code>${esc(v.destAddr || v.dest)}</code> 是个 ${v.family === 'ipv6' ? 'IPv6' : 'IPv4'} 地址，`
            + `可这张表里 ${v.family === 'ipv6' ? 'IPv6' : 'IPv4'} 一条路由都没有 —— 这台机器这一族<strong>没启用</strong>。`
            + '★ 不是防火墙拦的，也不是对端不理：先去把这一族开起来，查防火墙是白查。'
          : `表里 ${v.familyRoutes} 条 ${v.family === 'ipv6' ? 'IPv6' : 'IPv4'} 路由，`
            + `没有一条盖得住 <code>${esc(v.destAddr || v.dest)}</code>。`
            + '★ 到不了它是<strong>没路</strong>，不是「对端不理」—— 这两个的下一步完全不同：'
            + '没路要加路由（或换一块有路口的网卡），不理才去查对端和防火墙。';
        break;
      case 'route-mismatch':
        say = '★ 按表算是一个出口，系统自己给的是另一个 —— 这台机器的路由不能靠看表判断。'
          + 'Linux 上多半是策略路由（每块网卡各自一张表，主表那条不算数）。'
          + '以系统给的那一条为准，两个答案都摆在下面。';
        break;
      case 'route-split':
        say = `${esc(v.dest)} 解出 ${v.destAddrs ? v.destAddrs.length : (v.paths || []).length} 个地址，`
          + '而它们走的路不一样。★ 实际走哪条由应用挑哪个地址决定，不由本机决定 —— '
          + '所以这不是配置错误，是必须看见的事实（一个域名同时给 v4/v6、或者轮询解析就是这样）。';
        break;
      case 'route-local':
        say = `<code>${esc(v.destAddr || v.dest)}</code> 是<strong>本机自己的地址</strong> —— `
          + '发往它会走回环，不会出网卡。★ 如果你以为它是另一台设备，那就是两台机器的 IP 撞了'
          + '（现场最常见：设备的固定地址被误配到了本机网卡上）。'
          + '这时候「能 ping 通」恰恰是假象，通的是自己。';
        break;
      case 'table-unreadable':
        say = '这台机器上一条路由都没读到。★ 这<strong>不等于</strong>「这台机器没有路由」—— '
          + '多半是这个平台这里的读取方式还没实现，或者被系统挡住了。'
          + '换成只填一族的 IPv4 / IPv6 再试一次；要查出口请直接用「路径追踪」。';
        break;
      default:
        say = '下面就是本机的路由表。★ 只看了本机，一个包都没发。'
          + '想知道「去往某个地址会从哪块网卡出去」，把地址填上面问一句 —— '
          + '光看表要自己在几十行里做最长前缀匹配，很容易看漏一条压住默认路由的 /24。';
    }

    // ★ 高亮哪一行「就是这一条」：按表算的能精确到行；问系统拿到的只能按
    //   「同一块网卡 + 同一个下一跳」指回去，而直连答案没有下一跳 —— 那样一整片
    //   本网段路由都符合条件。标十行等于说「这十行都是答案」，是假话，所以
    //   指不准就一行都不标。
    const mark = r.verdict === 'route-mismatch' ? v.byTable : v.decision;
    const hits = new Set();
    if (mark) {
      (v.routes || []).forEach((x, i) => {
        const same = mark.from === 'table'
          ? mark.destination === x.destination && mark.iface === x.iface
          : !!mark.gateway && mark.iface === x.iface && mark.gateway === x.gateway;
        if (same) hits.add(i);
      });
      if (mark.from !== 'table' && hits.size !== 1) hits.clear();
    }
    const rows = (v.routes || []).map((x, i) => {
      const hit = hits.has(i);
      return `<tr${hit ? ' style="background:var(--green-bg)"' : ''}>
        <td class="dim">${x.family === 'ipv6' ? 'v6' : 'v4'}</td>
        <td><code>${esc(destOf(x))}</code>${isDefault(x) ? ' <span class="pill">默认</span>' : ''}</td>
        <td>${x.gateway ? `<code>${esc(x.gateway)}</code>` : '<span class="dim">直连（不经网关）</span>'}</td>
        <td><b>${esc(x.iface || '—')}</b></td>
        <td class="dim">${x.metric ? x.metric : '—'}</td>
      </tr>`;
    }).join('');
    const hasMetric = (v.routes || []).some((x) => x.metric);

    const pathRows = (v.paths || []).map((p) => `<tr>
      <td><code>${esc(p.addr)}</code></td>
      <td><b>${esc(p.iface || '—')}</b></td>
      <td>${p.gateway ? `<code>${esc(p.gateway)}</code>` : '<span class="dim">直连</span>'}</td>
      <td class="dim">${esc(destOf(p))}</td>
      <td class="dim">${esc(RT_FROM[p.from] || p.from || '')}</td>
    </tr>`).join('');

    const oneRow = (label, d) => d ? `<tr><td class="dim" style="white-space:nowrap">${esc(label)}</td>
      <td>${d.iface ? `<b>${esc(d.iface)}</b>` : '—'}${d.gateway ? ` · 下一跳 <code>${esc(d.gateway)}</code>` : ' · 直连'}
        ${d.from === 'table' ? `· 命中 <code>${esc(destOf(d))}</code>` : ''}${d.metric ? ` · 度量 ${d.metric}` : ''}
        · <span class="dim">${esc(RT_FROM[d.from] || d.from || '')}</span></td></tr>` : '';

    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${say}</div>
      ${v.defaults && v.defaults.length ? `<p class="hint" style="margin-top:8px">默认路由：${
        v.defaults.map((d) => `${esc(d.iface || '?')}（下一跳 ${esc(d.gateway || '无')}，${d.family}）`).join('；')
      }${v.multiDefault ? ' ★ 同族不止一条' : ''}</p>` : ''}
      ${r.verdict === 'route-mismatch' ? `<table style="margin-top:12px"><tr><th></th><th>答案</th></tr>
        ${oneRow('系统自己选的', v.byOS)}${oneRow('按表算的', v.byTable)}</table>` : ''}
      ${pathRows ? `<table style="margin-top:12px"><tr><th>解出的地址</th><th>出口网卡</th>
        <th>下一跳</th><th>命中</th><th>依据</th></tr>${pathRows}</table>` : ''}
      ${rows ? `<div style="margin-top:12px;max-height:360px;overflow:auto">
        <table><tr><th>族</th><th>目的</th><th>下一跳</th><th>出口网卡</th><th>度量</th></tr>
        ${rows}</table></div>
        ${hasMetric ? '' : `<p class="hint">这张表里一条度量都没给（macOS 的读取方式就不带这一栏）—— `
          + '碰到并列时这里没法替你判谁生效，会照实写在结论里。</p>'}` : ''}
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  card.querySelector('#rt-go').onclick = run;
  card.querySelector('#rt-dest').onkeydown = (e) => { if (e.key === 'Enter') run(); };
  run();  // 只读本机，不要人点头：进页面就把表摆出来
  return card;
}

// ── 文件共享：把本机一个目录开成只读的下载地址 ──
//
// ★★ 这张卡跟别的卡有一点不一样：**开着的每一秒都在把一个目录摊给整个网段**
//   （无鉴权，谁都能读）。所以默认版面必须一眼看见「开着没有、开的哪个目录、
//   绑在哪几个地址」，停掉那颗钮得一直在手边。
//   ★ 后端只接 GET/HEAD：界面上压根没有上传入口，不是「藏起来不给点」。

const FS_CODE = {
  'share-serving': ['正在共享', 'ok'],
  'share-stopped': ['已经停掉了', ''],
  'share-idle': ['没在共享', ''],
};

// ★ 这几种「没成」的处置完全不同，界面不许并成一句「失败」：
//   partial 是设备那头掉了或网断了（重发一次就行），not-found 是文件名填错
//   （去改设备那一页的地址），denied 是有人在试上传或想翻出共享目录。
const FS_TAKE = {
  ok: ['整份取走了', ''],
  head: ['只问了大小', ''],
  range: ['按段取的（断点续传在跑）', ''],
  partial: ['传到一半断了', 'bad'],
  list: ['翻了目录', 'warn'],
  denied: ['被拒（想上传 / 想翻出去）', 'bad'],
  'not-found': ['没有这个文件', 'warn'],
};

// 后端给的是「这块口凭什么选上」的原话，界面翻成人话，并且把风险点一句带上：
// 指定网卡这条路是绕开默认路由的，机器上那块口连着谁，只有现场的人知道。
const FS_WHY = {
  '你指定的网卡': '说的就是你指的那块口 ★ 这一条没照着默认路由挑，确认一下这块口连着谁',
  'IPv4 默认路由走这块': '按 IPv4 默认路由挑的（这台机器往上走的那块口）',
  '本机只有一块带可用 IPv4 的网卡': '自动挑的：本机只有这一块带可用的 IPv4 地址',
};

function fsSize(n) {
  if (typeof n !== 'number') return '—';
  if (n >= 1073741824) return (n / 1073741824).toFixed(1) + ' GB';
  if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
  if (n >= 1024) return Math.round(n / 1024) + ' KB';
  return n + ' 字节';
}

function fsClock(s) {
  const d = new Date(s);
  if (isNaN(d.getTime())) return '—';
  const p = (x) => String(x).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function fsSpan(since) {
  const d = new Date(since);
  if (isNaN(d.getTime())) return '';
  let m = Math.floor((Date.now() - d.getTime()) / 60000);
  if (m < 1) m = 1;
  if (m < 60) return `${m} 分钟`;
  return `${Math.floor(m / 60)} 小时 ${m % 60} 分`;
}

// 台账：现场查「设备说下载失败」就看这一栏 —— 有没有人来取过、
// 取到第几个字节断的，看了就不用猜。
function fsLedger(recent) {
  const list = recent || [];
  if (!list.length) {
    return '<div class="empty">还没有设备来取过文件。它说不行的时候回来看这一栏：'
      + '空着说明根本没来（地址或网不对），有半截的说明传断了。</div>';
  }
  const rows = list.map((t) => {
    const [word, cls] = FS_TAKE[t.status] || [t.status || '—', ''];
    return `<tr>
      <td class="dim">${esc(fsClock(t.at))}</td>
      <td><code>${esc(t.peer || '—')}</code></td>
      <td><code>${esc(t.path || '—')}</code></td>
      <td class="dim">${esc(fsSize(t.bytes))}</td>
      <td class="${cls}">${esc(word)}</td>
    </tr>`;
  }).join('');
  return `<div style="max-height:280px;overflow:auto"><table>
    <tr><th>什么时候</th><th>谁取的</th><th>取了什么</th><th>多少</th><th>结果</th></tr>
    ${rows}</table></div>
    <p class="hint">只留最近 50 笔。「被拒」那一行是分开的：想上传的一律不收，
      文件名写错只算没找到，不混成「有人在攻击」。</p>`;
}

function fsWarn(lines) {
  if (!lines || !lines.length) return '';
  return `<div style="margin-top:10px;padding:10px 12px;border-radius:6px;font-size:13.5px;
      background:var(--gold-bg);border:1px solid var(--gold-dim);color:var(--gold)">★ ${
    lines.map((x) => esc(x)).join('<br>★ ')}</div>`;
}

let fsTimer = null;

function fileshareCard() {
  const card = $(`<div class="card">
    <h2>文件共享（只读） <span id="fs-top"></span></h2>
    <p class="hint">把本机一个目录开成 http 下载地址 —— 设备的升级页面要填一个
      「固件下载地址」，交换机要把配置文件拉回去，都是这一张。
      ★ <strong>只读</strong>：只发不收，同网段谁都改不了、删不了本机任何东西。
      ★ 只绑你挑的那块网卡上的地址，<strong>不绑 0.0.0.0</strong> ——
      多网卡机器上那等于把目录从办公网甚至公网口也开出去。
      ★ 无鉴权：开着的时候同一网段任何设备不必登录就能把这个目录整个读走，
      所以每次开都要你点头，用完请点停掉（停是当场断，正在传的那一发也立刻断）。</p>
    <div class="row">
      <div style="flex:1 1 300px"><label>要共享的目录（只放要发出去的那些文件）</label>
        <input id="fs-root" placeholder="/Users/you/firmware 或 D:\\固件"></div>
      <div style="flex:0 0 150px"><label>开在哪块网卡（留空自动）</label>
        <input id="fs-iface" placeholder="en0 / eth0 / WLAN"></div>
      <div style="flex:0 0 100px"><label>端口</label>
        <input id="fs-port" placeholder="8080"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn danger" id="fs-go">开共享</button></div>
    </div>
    <div class="row">
      <div style="flex:1 1 260px"><label>或者只绑这几个地址（填了就按这个来，覆盖上面那块网卡）</label>
        <input id="fs-addrs" placeholder="192.168.1.20 fd00::1（不许写 0.0.0.0）"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <label style="display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal">
          <input type="checkbox" id="fs-list" checked style="flex:0 0 auto">
          允许翻目录列表</label></div>
    </div>
    <div class="row" style="margin-top:6px">
      <div style="flex:0 0 auto;min-width:0">
        <button class="btn" id="fs-refresh">刷新台账</button>
        <button class="btn danger" id="fs-stop" style="display:none">立刻停掉</button></div>
    </div>
    <div id="fs-out" style="margin-top:14px"></div>
  </div>`);

  const out = card.querySelector('#fs-out');
  const top = card.querySelector('#fs-top');
  const btnStop = card.querySelector('#fs-stop');

  const paint = (verdict, v) => {
    const [title, cls] = FS_CODE[verdict] || [verdict || '没给判定', ''];
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
    btnStop.style.display = verdict === 'share-serving' ? '' : 'none';
    const st = v.status || v;                 // status 卡把台账包在 status 里
    const serving = verdict === 'share-serving';
    // serve 和 status 两个形状都要能画：字段落在哪一层不一样，别看错成 undefined
    const root = v.root || st.root || '';
    const port = v.port || st.port || 0;
    const listing = typeof v.listing === 'boolean' ? v.listing : st.listing;
    const urls = (v.urls && v.urls.length ? v.urls : st.urls) || [];
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--sunken)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--line)';

    let say;
    if (verdict === 'share-idle') {
      say = '现在没开着。开一次就是一次对外暴露，需要时再开、用完就停 —— '
        + '这个共享不鉴权，同网段谁都能读。';
    } else if (verdict === 'share-stopped') {
      // ★ 停掉之后不再摆下载地址：那几条已经读不到东西了，还做成可复制的样子，
      //   人就照旧往设备里粘，然后回来查「为什么下载失败」。
      say = `端口已经放掉，${esc(root)} 不再对外可读。`
        + `这中间一共被取走 ${v.requests || 0} 次、${esc(fsSize(v.bytes || 0))}。`
        + '已经下到设备里的文件不受影响。';
    } else if (serving && v.iface) {
      say = `目录 <code>${esc(root)}</code> 正从网卡 <b>${esc(v.iface)}</b>`
        + `（${esc(FS_WHY[v.ifaceWhy] || v.ifaceWhy || '怎么定的没说')}）发出去，端口 ${port || '—'}。`
        + `只读，不收上传。★ 同一网段的设备不必登录就能读到这个目录里的东西。`;
    } else if (serving) {
      say = `目录 <code>${esc(root)}</code> 正绑在这些地址上：${
        (v.addrs || st.addrInfo || []).map((x) => `<code>${esc(x)}</code>`).join('、')
        }，端口 ${port || '—'}。只读，不收上传。`;
    } else {
      say = '后端给了一个这里还没认得的判定，原文在下面展开看。';
    }

    const facts = [];
    if (serving || verdict === 'share-stopped') {
      if (typeof v.entries === 'number') {
        facts.push(['目录里有多少', `${v.entries} 个文件${v.dirs ? `、${v.dirs} 个子目录` : ''}，共 ${esc(fsSize(v.bytes || 0))}`]);
      }
      if (typeof st.requests === 'number') {
        facts.push(['已被取走', `${st.requests} 次、${esc(fsSize(st.bytes || 0))}`
          // ★ 两个数分开摆：想上传的是有人在试，文件名没对上的是现场抄错了字。
          //   并成一个「失败 N 次」的话，前者会被后者淹掉。
          + (st.denied ? `；<b class="bad">${st.denied} 次被拒</b>（想上传 / 想翻出目录）` : '')
          + (st.notFound ? `；${st.notFound} 次文件名没对上` : '')]);
      }
      if (st.since) facts.push(['开了多久', fsSpan(st.since)]);
      if (serving) {
        // ★ 这一栏在状态刷新后也要留着：关没关列表决定了别人能不能把文件名挨个抄走
        facts.push(['能不能翻目录', listing
          ? '能（同网段谁都能把这个目录的文件名挨个列走）' : '不能（要写对完整文件名才取到走）']);
      }
    }
    const factRows = facts.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
      <td>${x}</td></tr>`).join('');

    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${say}</div>
      ${urls.length && serving ? `<div style="margin-top:12px"><label class="dim">下载地址（贴进设备的升级页面）</label>
        ${urls.map((u) => `<div style="margin-top:4px"><code style="user-select:all;cursor:cell">${esc(u)}</code></div>`).join('')}
        <p class="hint">点一下整条就选中，直接抄。跨网段的设备要用它自己能到的那个地址，
          不是随便挑一条。</p></div>` : ''}
      ${factRows ? `<table style="margin-top:12px"><tr><th></th><th></th></tr>${factRows}</table>` : ''}
      ${fsWarn(v.warnings)}
      ${serving ? `<div style="margin-top:12px"><label class="dim">谁在取、取走了什么（每 3 秒自己刷新）</label>
        <div id="fs-ledger">${fsLedger(st.recent)}</div></div>` : ''}
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };

  const refresh = async (quiet) => {
    const r = await call('net.fileshare.status');
    if (!r.ok) {
      if (!quiet) out.innerHTML = `<div class="empty">看不了状态：${esc(r.message || r.error)}</div>`;
      return;
    }
    paint(r.verdict, r.values || {});
    if (r.verdict === 'share-serving') {
      if (fsTimer) clearInterval(fsTimer);
      fsTimer = setInterval(() => refresh(true), 3000);
    } else if (fsTimer) {
      clearInterval(fsTimer);
      fsTimer = null;
    }
  };

  card.querySelector('#fs-go').onclick = async () => {
    const root = card.querySelector('#fs-root').value.trim();
    if (!root) {
      out.innerHTML = '<div class="empty">先写要共享哪个目录。只放要发出去的那些文件 —— '
        + '别把整个用户目录端出来（里面有 id_rsa、.env 这类东西）。</div>';
      return;
    }
    const args = { root };
    const iface = card.querySelector('#fs-iface').value.trim();
    const port = card.querySelector('#fs-port').value.trim();
    const addrs = card.querySelector('#fs-addrs').value.split(/[\s,、]+/).filter(Boolean);
    if (iface) { args.iface = iface; }
    if (port) { args.port = Number(port); }
    if (addrs.length) { args.addrs = addrs; }
    if (!card.querySelector('#fs-list').checked) { args.listing = false; }
    top.innerHTML = '';
    // ★ 等批准：开这个共享改的是这台机器对外的可见面，必须有人看一眼再开
    out.innerHTML = '<div class="empty">等你点批准…（取消的话一个端口都不开）</div>';
    const r = await call('net.fileshare.serve', args);
    if (!r.ok) {
      out.innerHTML = `<div class="empty">没有开起来：${esc(r.message || r.error)}</div>`;
      return;
    }
    paint(r.verdict, r.values || {});
    if (fsTimer) clearInterval(fsTimer);
    fsTimer = setInterval(() => refresh(true), 3000);
  };
  card.querySelector('#fs-refresh').onclick = () => refresh(true);
  card.querySelector('#fs-stop').onclick = async () => {
    btnStop.disabled = true;
    out.innerHTML = '<div class="empty">等你点批准…（取消就还开着）</div>';
    const r = await call('net.fileshare.stop');
    btnStop.disabled = false;
    if (!r.ok) {
      out.innerHTML = `<div class="empty">停不下来：${esc(r.message || r.error)}</div>`;
      return;
    }
    if (fsTimer) { clearInterval(fsTimer); fsTimer = null; }
    paint(r.verdict, r.values || {});
  };
  card.querySelector('#fs-root').onkeydown = (e) => { if (e.key === 'Enter') card.querySelector('#fs-go').click(); };
  refresh(true);   // 只读一次状态，不动系统：进页面就要看得见「现在开着没有」
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
