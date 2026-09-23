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
  root.appendChild(dualStackCard());
  root.appendChild(traceCard());
  root.appendChild(mtrCard());
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
