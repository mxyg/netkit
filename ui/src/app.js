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

/*
 * ★★ 导航分两层（老板 2026-09-25：「功能太多了，不会用了」）。
 *
 *   工具涨到四十多项之后，八个平铺按钮里有一个「连通性」页堆了十五张卡，
 *   一开到底、滚动半天，谁都找不到自己要的那一个 —— 平铺已经不承担导航了。
 *   所以拆成：**上面一组是「现在要回答的问题」，下面才是那一组里的具体页**。
 *   硬规矩：每组不超过 4 页、每页不超过 5 张卡，再多就继续拆页，不许在页里堆。
 */
const PAGES = [
  { g: '这台机器', id: 'nic', name: '网卡与路由', render: renderNIC },
  { g: '这台机器', id: 'dhcp', name: 'DHCP 分地址', render: renderDHCP },
  { g: '这台机器', id: 'local', name: '本机端口与文件共享', render: renderLocal },

  { g: '通不通', id: 'connect', name: 'ping 与端口', render: renderConnect },
  { g: '通不通', id: 'path', name: '路径与质量', render: renderPath },
  { g: '通不通', id: 'name', name: '域名与时间', render: renderName },
  { g: '通不通', id: 'service', name: '网站与证书', render: renderService },

  { g: '谁在网里', id: 'scan', name: '网段上有哪些地址', render: renderScan },
  { g: '谁在网里', id: 'device', name: '设备是谁', render: renderDevice },
  { g: '谁在网里', id: 'stream', name: '摄像头取流', render: renderStream },
  { g: '谁在网里', id: 'switch', name: '交换机（SNMP）', render: renderSwitch },

  { g: '出问题了', id: 'checkup', name: '一键体检与诊断包', render: renderCheckup },
  { g: '出问题了', id: 'trouble', name: '按症状排查', render: renderTrouble },

  { g: '管别的机器', id: 'remote', name: '远程设备与审计', render: renderRemote },
  { g: '管别的机器', id: 'remote-work', name: '连上去干活', render: renderRemoteWork },

  { g: '工具箱', id: 'tools', name: '算子网 / MAC / 编解码', render: renderTools },
];

const GROUPS = [...new Set(PAGES.map((p) => p.g))];

let group = GROUPS[0];
let current = PAGES[0].id;

function renderNav() {
  const nav = document.getElementById('nav');
  nav.innerHTML = '';
  const rows = [document.createElement('div'), document.createElement('div')];
  rows.forEach((r) => { r.className = 'navrow'; });
  GROUPS.forEach((g) => {
    const b = document.createElement('button');
    b.textContent = g;
    b.className = 'btn grp' + (g === group ? ' on' : '');
    b.onclick = () => {
      if (g === group) return;
      group = g;
      current = PAGES.find((p) => p.g === g).id;
      renderNav(); show();
    };
    rows[0].appendChild(b);
  });
  const subs = PAGES.filter((p) => p.g === group);
  if (subs.length > 1) {
    for (const p of subs) {
      const b = document.createElement('button');
      b.textContent = p.name;
      b.className = 'btn sub' + (p.id === current ? ' on' : '');
      b.onclick = () => {
        if (p.id === current) return;
        current = p.id;
        renderNav(); show();
      };
      rows[1].appendChild(b);
    }
  }
  nav.append(...rows);
}

async function show() {
  const main = document.getElementById('main');
  // ★ DHCP 那页的租约轮询只在停在那一页时才该跑：换页后它还每 2.5 秒发一次请求，
  //   而且往**当前这页**的 #leases 里写 —— 页面拆细了以后这个尾巴更明显，当场断掉。
  clearInterval(pollTimer);
  pollTimer = null;
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

// net.dhcp.probe 的两档。★★ 这一栏的分量在于「问了没有」和「问了没人应」不是一回事：
//   探测本身要占 :68 端口，本机 DHCP 客户端还开着时根本问不出去，
//   那种情况后端直接报错（走「探测失败」），不会冒充「这个网没人发地址」。
const PROBE_DHCP_CODE = {
  'dhcp-found': ['这个网已经有人在发地址', 'bad',
    '★ 别再起第二个。两边同时发地址时，设备拿到哪个看运气，故障是间歇的、而且每台机器不一样 —— 这是现场最难查的一类问题。要看是谁在发，问它下发的网关和 DNS 指向哪。'],
  'no-dhcp': ['这个网里没人发地址', 'ok',
    '可以放心开。★ 这只代表刚才那几秒没人应答；网里随时可能接入一台带 DHCP 的设备（路由器、热点、别的电脑），开之前再点一次问一遍。'],
};

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
    out.style.whiteSpace = 'pre-wrap';
    const p = await call('net.dhcp.probe', { iface: sel.value, waitMs: 3000 });
    if (!p.ok) { say('探测失败：' + p.message); return; }
    const v = p.values || {};
    const servers = v.servers || [];
    const [title, cls, advice] = PROBE_DHCP_CODE[p.verdict] || [p.verdict || '没给判定', '', ''];
    const rows = servers.map((s) => `<tr>
        <td><code>${esc(s.serverId || s.from || '')}</code>${s.serverId && s.from && s.serverId !== s.from
          ? `<br><span class="dim">报文来自 <code>${esc(s.from)}</code></span>` : ''}</td>
        <td>${esc(s.offeredIp || '—')}</td>
        <td>${esc(s.mask || '—')}</td>
        <td>${esc(s.router || '—')}</td>
        <td>${(s.dns || []).length ? esc(s.dns.join('、')) : '—'}</td>
        <td>${s.leaseSeconds ? esc(String(Math.round(s.leaseSeconds / 60))) + ' 分钟' : '—'}</td>
      </tr>`).join('');
    out.style.whiteSpace = 'normal';
    out.innerHTML = `<p><span class="pill ${cls}">${esc(title)}</span></p>
      ${rows ? `<table>
        <tr><th>它自称</th><th>打算发的地址</th><th>掩码</th><th>网关</th><th>DNS</th><th>租期</th></tr>${rows}
      </table>` : ''}
      <p class="dim" style="margin:10px 0 0">${esc(p.note || '')}</p>
      ${advice ? adviceBox(cls, esc(advice)) : ''}`;
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

// ── 通不通 ──
//
// ★ 原来这是「连通性」一页，十五张卡从头滚到底。现在按**问的层次**拆成四页：
//   端口通不通 → 路上几跳 → 名字解析得对不对 → 上层服务答得好不好。
//   顺序也是排查的顺序：下层没通之前，上面的数字都别当准。

async function renderConnect(root) {
  root.appendChild(pingCard());
  root.appendChild(scanCard());
  root.appendChild(udpCard());
}

async function renderPath(root) {
  root.appendChild(traceCard());
  root.appendChild(mtrCard());
  root.appendChild(pingWatchCard());
  root.appendChild(mtuCard());
}

async function renderName(root) {
  root.appendChild(dnsCard());
  root.appendChild(dualStackCard());
  root.appendChild(timeCard());
}

async function renderService(root) {
  root.appendChild(httpCard());
  root.appendChild(certCard());
}

// adviceBox 给一句「所以怎么办」的彩色块。★ 和判定盒同一套配色，不新造颜色。
function adviceBox(cls, text) {
  const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
  const line = cls === 'ok' ? 'var(--green-line)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
  return `<div style="background:${bg};border:1px solid ${line};border-radius:6px;`
    + `padding:10px 12px;margin-top:12px;font-size:13.5px">${text}</div>`;
}

const PING_CODE = {
  'reachable': ['通', 'ok', '往返和丢包在下面。★ 通了只说明 ICMP 过得去，不说明端口开着。'],
  'unreachable': ['回了明确的不可达', 'bad',
    '★ 这个「不通」是有用的：有设备（多半是路由或防火墙）回答了「到不了」，说明「路是通的」，问题在终点或那条路由。去查对端的地址、路由和防火墙，别再 ping 了。'],
  'no-reply': ['完全没回应', 'bad',
    '分不清是机器不在、还是 ICMP 被静默丢掉 —— 这两件事的下一步完全不同：先用「探端口」或网段扫描问一次，能连上就说明机器在。'],
};

const PROBE_CODE = {
  'open': ['端口开着', 'ok', '三次握手成了。★ 这只说明有人在听，服务是不是对的要看它回什么（RTSP、HTTP、SNMP 各有各的卡）。'],
  'closed': ['端口关着（对方回了拒绝）', 'warn',
    '对端明确回了 RST —— ★ 主机是「活着」的，只是这个端口没服务。去看服务起没起、端口号对不对。'],
  'filtered': ['没有任何回应', 'bad',
    '等到超时，一个回包都没有。多半是中间有人静默丢（防火墙/ACL），也可能主机压根不在。'],
};

function pingCard() {
  const card = $(`<div class="card">
    <h2>ping 一个地址 <span id="p-top"></span></h2>
    <p class="hint">只问一次，看它答不答。★ ping 区分「回了明确的不可达」和「完全没回应」——
      前者说明路是通的、问题在终点；后者连机器在不在都说不清。要连着看稳不稳，去「路径与质量」那一页用「连续 ping」。</p>
    <div class="row">
      <div><label>目标地址</label><input id="p-t" placeholder="192.168.1.1 或 fd00::1"></div>
      <div style="flex:0 0 190px"><label>端口（探端口时填）</label><input id="p-p" placeholder="554"></div>
    </div>
    <div style="margin-top:12px;display:flex;gap:10px">
      <button class="btn primary" id="p-bp">ping</button>
      <button class="btn" id="p-bt">探端口</button>
    </div>
    <div id="p-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#p-out');
  const top = card.querySelector('#p-top');
  const say = (html) => { out.innerHTML = html; };
  card.querySelector('#p-bp').onclick = async () => {
    top.innerHTML = '';
    say('<div class="empty">ping 中…</div>');
    const r = await call('net.ping', { addr: card.querySelector('#p-t').value.trim(), count: 4 });
    if (!r.ok) { say(`<div class="empty">问不了：${esc(r.message)}</div>`); return; }
    const [title, cls, advice] = PING_CODE[r.verdict] || [r.verdict, '', ''];
    const v = r.values || {};
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    say(`<table>
        ${tCell('目标', `<code>${esc(v.target || '')}</code> <span class="dim">${esc(v.family || '')}</span>`)}
        ${tCell('发 / 收到', `${v.sent ?? '—'} / ${v.received ?? '—'}`)}
        ${tCell('丢包', v.lossPercent === undefined ? '—' : `${Math.round(v.lossPercent)}%`)}
        ${tCell('往返（最快/平均/最慢）', ms(v.rttMinMs) + ' / ' + ms(v.rttAvgMs) + ' / ' + ms(v.rttMaxMs))}
      </table>${advice ? adviceBox(cls, esc(advice)) : ''}`);
  };
  card.querySelector('#p-bt').onclick = async () => {
    top.innerHTML = '';
    say('<div class="empty">探测中…</div>');
    const port = Number(card.querySelector('#p-p').value);
    const r = await call('net.tcp.probe', {
      addr: card.querySelector('#p-t').value.trim(), port: port || undefined,
    });
    if (!r.ok) { say(`<div class="empty">问不了：${esc(r.message)}</div>`); return; }
    const [title, cls, advice] = PROBE_CODE[r.verdict] || [r.verdict, '', ''];
    const v = r.values || {};
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    say(`<table>
        ${tCell('目标', `<code>${esc(v.target || '')}</code> <span class="dim">${esc(v.family || '')}</span>`)}
        ${tCell('端口', v.port ?? '—')}
        ${tCell('等了多久', ms(v.elapsedMs))}
      </table>${advice ? adviceBox(cls, esc(advice)) : ''}`);
  };
  return card;
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
// Happy Eyeballs 那一步的读数。★ 单独拎出来是因为「按症状排查」走到双栈时，
//   吐的顶层判定就是这一批码 —— 两处共用一份，换一句说法不必改两个地方。
const DS_EYEBALLS = {
  'eyeballs-ok': ['不会卡', 'ok'], 'eyeballs-stall': ['★ 会先卡一下', 'bad'],
  'eyeballs-single': ['只有一族能连，没得选', 'warn'], 'eyeballs-fail': ['这个域名两族都连不上', 'bad'],
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
  const [text, cls] = DS_EYEBALLS[eb.code] || [eb.code, ''];
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
      // ★ 偏差那个数只有在它真答过话时才存在。没答时后端给的 offsetMs 是 0，
      //   照着写成「本机慢 0.0 毫秒」就是把「没问到」伪装成「问了、很准」。
      const asked = f.code === 'answered';
      const off = f.offsetMs;
      const why = {
        'time-no-response': '没回话（内网封 UDP/123 时天天如此）',
        'time-kiss-rejected': '它拒答了（限速，或明说本机钟太离谱）',
        'time-bad-response': '回了，但不是 NTP 的样子',
      }[f.code] || (f.code ? `问不到：${esc(f.code)}` : '没去问');
      return `问 <code>${esc(f.server || '')}</code> · 回了 ${f.answers || 0}/${f.samples || 0} 包`
        + (asked ? ` · <b>${off >= 0 ? '本机慢' : '本机快'} ${esc(humanMs(Math.abs(off)))}</b>`
                 : ` · <span class="dim">${why}</span>`)
        + (asked && f.rttMs ? ` · 往返 ${ms(f.rttMs)}` : '')
        + (asked && f.serverTime
            ? `<div class="dim">它说 ${esc(fmtStamp(f.serverTime))} · 本机 ${esc(fmtStamp(f.localTime))}</div>` : '');
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
 * ── 诊断包导出 ──
 *
 * ★★ 这一栏治的是「截图发群里，对方追问两天」：截图里没有「网关是哪台」「这块卡是
 *   USB 转的还是板载的」「这台被谁改过配置」，于是来回两天。包里给的是每一项读到的
 *   原文，读不到的也带着「为什么读不到」—— 所以界面只把后端给的逐项判定摊开成一行行，
 *   不在这儿替它写结论。
 *
 * ★ 默认只占一行：这是一个「要发给别人才用得上」的动作，不是常看的表。
 */
const DB_TOP = {
  'bundle-written': ['包已写好', 'ok',
    '整个附件发给对方就行。★ 发之前过一眼：包里有内网地址、机器名、网卡名、进程名，'
    + '发出去就等于把这些给了对方。口令、团体名、令牌、私钥在落盘前已经抹掉、键名留着，'
    + '所以「配了但没给你看」和「没配」在包里分得开。'],
  'bundle-partial': ['包写好了，但有几项没读出来', 'warn',
    '缺的那几项也在包里，各自写明为什么读不到 —— 对方不会把「没权限读」看成「这台没配」。'
    + '★ 这一档八成是没给管理员权限：邻居表、本机端口占用、hosts 在非管理员下读不全。'
    + '用管理员权限再导一次才补得齐；只想补那几项，就在高级里单独勾它们。'],
  'bundle-not-written': ['这台写不出来', 'bad',
    '一个文件都没写出来，别去目录里找半截的包。★ 先看用户配置目录还能不能写'
    + '（磁盘满、目录被别的用户占有、路径太深都会这样），或者在高级里只勾几项再导一次。'],
};
const DB_SEC = {
  'section-read': ['在包里', 'ok'],
  // ★ 包没写成时不许说「在包里」：内容确实读到了，但那一页此刻不存在于任何文件里。
  //   说成「在包里」，对方会去解一个根本不存在的 zip。
  'section-read-nopack': ['读到了（没进包）', 'warn'],
  'section-unreadable': ['没读出来', 'bad'],
  'section-skipped': ['按你的要求跳过', 'warn'],
};
// ★ 空壳那一档要单独说：判定码仍然只有 written / partial / not-written 三种，
//   「缺几项」和「一项都没缺出来」是两个说法，但不是两个判定 —— 后者由后端的
//   nothingRead 给（界面不自己数行：数错了就把「有六页内容」的包喊成空壳，反之也一样）。
const DB_ALLBAD = '★ 这一趟一项都没读出来 —— 这个包里全是「为什么读不到」，没有内容。'
  + '别把它当「这台机器干净」发出去：先按上面说的解决权限，再重导一次。';
// 与后端 sectionLabel / sectionOrder 一一对应：勾选项的顺序就是包里的顺序。
const DB_ITEMS = [
  ['system', '系统与时间'], ['nic', '网卡与地址'], ['routes', '路由表'],
  ['neighbors', '邻居表（ARP 与 NDP）'], ['dns', 'DNS 服务器'], ['hosts', 'hosts 文件'],
  ['proxy', '代理设置'], ['ports', '本机端口占用'], ['journal', 'NetKit 改过什么'],
  ['checkup', '连通性体检'],
];

function dbRow(it, packed) {
  const code = it.code === 'section-read' && !packed ? 'section-read-nopack' : it.code;
  const [text, tone] = DB_SEC[code] || [it.code || '—', ''];
  // ★ 判定这一栏只回答「这一页在不在包里」，页名那一栏回答「在哪一页」：
  //   没读出来的那一项，包里那一页写的是为什么读不到 —— 对方指着那一页问时，得能对上名字。
  const file = packed ? esc(it.file || '') : '—';
  // ★ 「为什么」只在没读出来那一档给人看：reason 在别的档里放的是机器码（体检那一项放它自己的顶层判定），
  //   直接把机器码印到这一栏，界面就变成「degraded」这种没人看得懂的字。
  const note = it.code === 'section-unreadable'
    ? `<span class="dim">${esc((it.reason || '').split('\n')[0])}</span>`
    : `<span class="dim">${it.lines || 0} 行</span>`;
  return `<tr><td>${esc(it.label || it.item)}</td>
    <td><span class="pill ${tone}">${esc(text)}</span></td>
    <td><code class="dim">${file}</code></td>
    <td>${note}</td></tr>`;
}

function diagBundleCard() {
  const card = $(`<div class="card">
    <h2>导出诊断包 <span id="db-top"></span></h2>
    <p class="hint">把这台机器的网络现状打成一个 zip：网卡与地址、路由表、邻居表、DNS、hosts、代理、
      本机端口占用、NetKit 改过什么，外加一项按排查顺序跑的连通性体检。★ 每一项都带<b>读到的原文</b>，
      读不到的那一项也留在包里写明为什么 —— 对方不必再回来问「网关是哪台」。
      落盘前统一脱敏（口令 / 团体名 / 令牌 / 私钥抹成 <code>***</code>，键名留着），包内文件名一律 UTF-8。
      只在自己的输出目录里新建这一个文件，不改任何东西。</p>
    <div class="row" style="margin-top:10px">
      <div style="flex:1 1 240px"><label>包名上的现场标签（建议填现场名，可留空）</label>
        <input id="db-label" placeholder="如 金宇建安-盒1"></div>
      <div style="flex:0 0 auto;min-width:0"><label>&nbsp;</label>
        <button class="btn" id="db-go">导出诊断包</button></div>
    </div>
    <details style="margin-top:8px"><summary class="dim">高级：只要其中几项 / 不跑要发包的那一项 / 换体检域名</summary>
      <div class="row" style="margin-top:10px">
        <div style="flex:1 1 240px"><label>体检用哪个域名测 DNS 与出口</label>
          <input id="db-domain" placeholder="默认 www.cloudflare.com；内网填内网一定解析得到的名字"></div>
      </div>
      <label style="display:flex;gap:6px;align-items:center;margin-top:8px">
        <input type="checkbox" id="db-nolive" style="width:auto"> 不跑要发探测包的那一项（只留配置快照）</label>
      <p class="dim" style="margin:10px 0 4px">只要下面勾的这几项（一个都不勾 = 全给）。★ 对方只问了某件事时
        别把不相干的配置一起发出去：</p>
      <div id="db-only" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:4px 12px"></div>
    </details>
    <div id="db-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#db-out');
  const top = card.querySelector('#db-top');
  card.querySelector('#db-only').innerHTML = DB_ITEMS.map(([k, name]) =>
    `<label style="display:flex;gap:6px;align-items:center;font-size:13px">
      <input type="checkbox" class="db-item" value="${k}" style="width:auto"> ${esc(name)}</label>`).join('');
  card.querySelector('#db-go').onclick = async () => {
    const args = {};
    const label = card.querySelector('#db-label').value.trim();
    const domain = card.querySelector('#db-domain').value.trim();
    const only = [...card.querySelectorAll('.db-item')].filter((c) => c.checked).map((c) => c.value);
    if (label) args.label = label;
    if (domain) args.domain = domain;
    if (only.length) args.only = only;
    if (card.querySelector('#db-nolive').checked) args.skipLive = true;
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">正在一项项读…（体检那一项要发少量探测包，约 3 秒）</div>';
    const r = await call('net.diag.bundle', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">导不出来：${esc(r.message || r.error)}</div>`; return; }
    const v = r.values;
    let [title, cls, advice] = DB_TOP[r.verdict] || [r.verdict || '没给判定', '', ''];
    if (v.nothingRead === true) { // 「有几项没读出来」在这一档说轻了
      title = '包写好了，但这一趟什么都没读出来';
      cls = 'bad';
      // ★ 不整段换掉：下面那句「八成是没给管理员权限」正是这一档的下一步，仍然要说。
      advice += '\n' + DB_ALLBAD;
    }
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const items = v.sections || [];
    // 体检那一项自己的顶层判定：包旁边要能直接说出「这一台断在第几步」，
    // 而这套词与上面那张体检卡完全一致（CK_TOP），不许在包里换一套说法。
    const cu = v.checkup && v.checkup.top;
    const [cuName, cuTone] = cu ? (CK_TOP[cu] || [cu, 'warn']) : [];
    const cuPill = cu ? `<span class="pill ${cuTone}">体检：${esc(cuName)}</span>` : '';
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(advice).replace(/\n/g, '<br>')}</div>
      ${v.path ? `<p style="margin:12px 0 0">包：<code>${esc(v.path)}</code><br>
        <span class="dim">${esc(fsSize(v.bytes))} · ${v.entries || 0} 个文件 · 用时 ${ms(v.tookMs)}</span>
        ${cuPill ? '　' + cuPill : ''}
        </p>` : ''}
      ${v.reason ? `<p style="margin:12px 0 0">原因：${esc(v.reason)}${
        v.dir ? `<br><span class="dim">输出目录：<code>${esc(v.dir)}</code></span>` : ''}</p>` : ''}
      ${items.length ? `<table style="margin-top:12px">
        <tr><th>${v.path ? '包里的项' : '读到的项'}</th><th>判定</th><th>哪一页</th><th>行数 / 为什么没读出来</th></tr>
        ${items.map((it) => dbRow(it, !!v.path)).join('')}
      </table>` : ''}
      ${v.redactedHow ? `<p class="dim" style="margin:10px 0 0">脱敏：${esc(v.redactedHow)}</p>` : ''}
      ${(v.truncated || []).length ? `<p class="dim" style="margin:4px 0 0">被截断的页：${
        esc((v.truncated || []).join('、'))} —— 原文太长，要看全文用对应的工具单独再查一次。</p>` : ''}
      <p class="hint" style="margin-top:10px">★ 每一项都带读到的原文：解开后那几页是给别人<b>接着查</b>的，
        不是截图那种「看着像结论」的东西。时钟准不准、v6 出不出得去，在包里「02 连通性」那一页 ——
        界面上要单独再问一次，去「域名与时间」。</p>
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
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
    '多半是 RTSP、RTMP 或设备自己的私有协议 —— 取流用「摄像头取流」那一页探。'],
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
    '每一族的追踪都到了终点。慢不慢看下面逐跳的往返 —— 某一跳突然变大，就是那里。到了终点还上不了服务，那是端口或服务的事，去「网站与证书」那一页问它回什么。'],
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
    '★ 这「不说明路断了」：路由器不回应 ICMP 超时时，整条路都是这个形状，目标可能好好的。改用 ping / 探端口确认到不到得了终点。'],
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
    '★ 看着吓人的那一行是「这台设备不爱回话」，不是它丢包：它后面的每一跳都收得到。家用和园区网的路由器普遍给 ICMP 超时做限速。要修的是探测能不能问到自己，不是这条路。'],
  'quality-path-changed': ['同一跳出现过不止一个地址', 'warn',
    '多为等价路径负载分担（本来就这样），或者是路由在翻动。翻动本身不卡人，「每次换到一条更烂的路」才会 —— 对照下面的丢包和往返看。'],
  'quality-latency-jump': ['从某一跳起明显变慢，而且一直到终点都慢', 'bad',
    '抬升起点那一跳就是分界：它之前还是好的，之后一路都带上这份延迟。要查的是那一段链路（或者出口拥塞），不是终点自己。'],
  'quality-target-loss': ['中间的跳都正常，只有终点在丢', 'bad',
    '路是通的（每一跳都替它作证了），丢的是「到终点这最后一段」：终点自己在限速 ICMP、防火墙把它挡了，或者它真的忙不过来。先用 ping / 探端口确认它服不服务。'],
  'quality-loss': ['从某一跳起，丢包一路延续到终点', 'bad',
    '★ 这才是真的拥塞/故障点：下面标了从第几跳开始。中间某跳丢但后面能收到，不算这一条 —— 那种是它不爱回话。'],
  'quality-no-response': ['一个像样的样本都没拿到', 'warn',
    '★ 这「不说明路断了」：第一跳起就不回 ICMP（整条路都被限速）时就是这个形状。改用 ping / 探端口确认终点到不到得了。'],
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
    + '先用「ping 与端口」那一页问一次它在不在，再查对端的防火墙。'],
  'ports-no-route': ['包根本没出去', 'bad',
    '到这个地址没有路 —— 一个包都没发出去，所以这跟对端防不防火没有关系。查自己：网卡起来了吗、'
    + '和它是不是同一个网段（看「网卡与路由」那一页；两族是不是都通，去「域名与时间」那一页做双栈体检）。'],
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
    + '★ 这不代表 MTU 有问题：「收不到回执」和「大包真的过不去」长得一模一样。先用「ping 与端口」那一页问一次它在不在。'],
  'mtu-no-route': ['包根本没出去', 'bad',
    '到这个地址没有路，一个包都没发出去，所以跟路径 MTU 无关。查自己：网卡起来了吗、'
    + '和它是不是同一个网段（看「网卡与路由」那一页；两族是不是都通，去「域名与时间」那一页做双栈体检）。'],
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
    '这一栏分不出「主机不在」和「ICMP 被挡」，所以给不出稳定性结论。先去「ping 与端口」那一页确认这台存在。'],
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
 * ★ 这一页把「这个网段上都有谁」的四样东西放在一起：主动扫一段（net.subnet.scan）、
 *   问设备自己是谁（net.device.identify）、
 *   听 v6 的应答顺便看谁还没配网（net.discover，原来只有 API 没有按钮，不合 [OTS-4.5]）、
 *   以及纯读本机缓存的邻居表（net.neighbors，同样原来没按钮）。
 *
 * ★★ 四张卡的可信度不是一回事，界面必须把这层差别留在脸上：
 *   邻居表是**缓存**（里面没有 ≠ 它不在，而且旧记录可能早就溜了）；
 *   扫网段是**当场问过**（每台都带着凭什么判定它在线）；
 *   设备识别只放**设备自己说过的话**（没说的一定留空，不猜）；
 *   发现只听得见应 v6 的那些。混成一张「设备清单」就会让人拿着一个漏了一半的表去现场。
 */

const SUBNET_CODE = {
  'hosts-found': ['问到了设备', 'ok',
    '清单在下面，每台都写着凭什么判定它在线。★ 收到自己的 ping 应答最硬，'
    + '「应了 ARP 但没应 ping」的摄像头很常见（不少设备管理页里有一键禁 ping），别当成不在。'],
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

/*
 * ── 设备识别（net.device.identify）的判定话术 ──
 *
 * ★★ 这一张与「网段上有哪些地址」那一页的分工必须在脸上就分得开：扫网段答的是
 *   「这个地址上有没有人」，这一张答的是「它是哪一台」。
 *   所以这里最要紧的一句话是 heard-anonymous —— 有东西应了但没说身份，
 *   它既不是「发现了设备」也不是「没有设备」，混进任何一边都会把人支到错的地方去。
 */
const DEVICE_CODE = {
  'devices-found': ['认出了是谁', 'ok',
    '下面每一台写的都是<b>它自己说过的话</b>（名字、类型、管理地址）。'
    + '★ 空着的那一格意思是「这台没说」，不是「没有」——这一栏宁可留空也不按 MAC 前缀猜厂商：'
    + '猜对九次、错一次，人就顺着错的那一次去机房。'],
  'heard-anonymous': ['有人应，但一句身份都没说', 'warn',
    '这些地址上有东西在答话，可它没说过自己是谁 —— 这<b>不等于没有设备</b>，'
    + '也不等于坏了。最常见的是固件里把发现服务关掉的摄像头，和不开 UPnP 的路由/交换机。'
    + '下一步：拿其中一个地址去「ping 与端口」那一页扫端口，看它开了什么（554 是 RTSP、80/443 是管理页）。'],
  'no-device-answered': ['问过的口径没人应答', 'warn',
    '★ 这一条<b>不能</b>读成「这个网段里没有设备」：设备不喊这几种话、中间隔着一层路由、'
    + '交换机做了组播抑制，三种病在这里长一个样。先在「问几轮」填 3 再问一次'
    + '（UDP 会丢，问两轮的命中率明显高于把一轮拉长），再用「网段上有哪些地址」那一页确认地址上到底有没有人。'],
  'no-interface': ['一块能问的网卡都没有', 'bad',
    '一个都没问出去，所以这份结果里没有任何一栏可以说设备的事。'
    + '先看网线插没插、这块网卡禁没禁用、有没有拿到 IPv4 地址（「网卡与路由」那一页）。'],
  'no-multicast-route': ['组播发不出去', 'bad',
    '本机或路上某台设备把组播挡了 —— 容器里跑、VPN 只给了一个 /32、系统禁了组播，都会卡在这里。'
    + '换一块有 IPv4 的网卡，或者在「点名问哪些地址」里直接填那个 IP：'
    + '★ 点名时我们发的是<b>单播</b>，不靠组播出去，隔着路由也能问到。'],
  'stopped': ['还没问到东西就停了', 'warn',
    '这份只覆盖停之前那一段，<b>不能</b>当成整个网段的答案：'
    + '慢的设备（老摄像头、走 802.11 的笔记本）第二轮才答话是常态。'],
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
    + '没有它就说明这台的 IPv6 没起来，先去「网卡与路由」那一页看一眼。'],
};

/*
 * ── 交换机 / SNMP ──
 *
 * ★★ 这一组卡片买到的东西是「把设备拆开问」。SNMP 的失败特别省 —— 团体名写错、
 *   防火墙丢了、设备压根没开 SNMP，三种病在报文层面是同一个「没回话」。
 *   后端拿对照探测和 error-status 把它们分开，界面就一个码一句话，
 *   不许在这里再拼句子（拼句子的是后端，AI 和界面读同一份）。
 * ★ 团体名这一栏是 password 输入框：界面就一个人用，但截图、投屏、
 *   站在后面看的人是真实存在的。后端也不会把它回传，两边各守一半。
 */
const SNMP_CODE = {
  'snmp-ok': ['SNMP 通，团体名可用', 'ok',
    '这台设备认这个团体名，路也是通的。下面 MAC 表、端口、PoE、LLDP 那几栏都可以问了。'],
  'snmp-no-reply': ['没有回话', 'bad',
    '问了两次（重传）都没一个包回来。这三种病在报文上完全同形，分不开：'
    + '团体名不对（v2c 不报错，直接把你的包丢在地上）、防火墙或设备 ACL 没放行、这台设备没开 SNMP。'
    + '先核团体名，再用「ping 与端口」那一页的「探 UDP 端口」问 161/udp 有没有反应。'],
  'snmp-reply-unmatched': ['有回包，但对不上号', 'warn',
    '路上有东西在回话，只是对不上这次问的 —— 这「不是」没人答。最常见的是设备上把 trap 目标'
    + '配成了这台机器（那 SNMP 本身是通的，把团体名或视图再核一遍），其次是同网段有第二台在答同一个请求。'],
  'snmp-v1-only': ['这台只认 v1', 'warn',
    'v2c 没答、换成 v1 就答了。★ 后面几栏（MAC 表、端口、PoE、LLDP）都要把版本填成 v1，'
    + '不然每一栏都会「没回话」。v1 没有 GETBULK，走表会慢很多。'],
  'snmp-v2c-only': ['这台只认 v2c', 'warn',
    '指定了 v1 没答、换成 v2c 答了 —— 把版本留空或填 v2c 即可。'],
  'snmp-error': ['设备答了，但说「这一栏不给读」', 'warn',
    '设备认这个请求（团体名是对的、SNMP 也开着），只是这一栏不给读或读不了。'
    + '★ 这跟「不通」是两回事：这一条要查的是设备上的视图/权限配置，不是防火墙。'],
  'unknown': ['观测没做成', 'warn', '请求根本没发出去（看原始结果里的 detail），这不算设备不通。'],
};

const SNMP_SYS_LABEL = {
  sysDescr: '说明', sysObjectID: '对象标识符', sysName: '设备名',
  sysLocation: '位置', uptime: '已开机',
};

// 五张 SNMP 卡共用的一段表单。前缀传进来，免得五个 id 打架。
function snmpFormHTML(p) {
  return `
    <div class="row">
      <div><label>设备地址（只收 IP，可带端口）</label><input id="${p}a" placeholder="192.168.1.2 或 192.168.1.2:1161"></div>
      <div style="flex:0 0 90px"><label>端口</label><input id="${p}p" placeholder="161"></div>
      <div><label>读团体名</label><input id="${p}c" type="password" placeholder="必填，没有默认值" autocomplete="off"></div>
      <div style="flex:0 0 110px"><label>版本</label><select id="${p}v">
        <option value="">v2c（默认）</option><option value="v2c">v2c</option><option value="v1">v1</option>
      </select></div>
      <div style="flex:0 0 150px"><label>从哪块网卡出去</label><input id="${p}i" placeholder="en0 / 以太网"></div>
    </div>
    <p class="hint" style="margin:8px 0 0">团体名<b>必填、故意不给默认值</b>：猜一个「public」只会把上面那三种病揉成一种。
      它不会出现在结果里，也不会进日志。多网卡机器上「从哪块网卡出去」常常决定设备答不答
      （管理 VLAN 只放行一个口，或者设备按源地址收口）；解不开这一栏会<b>直接报错</b>，不会退化成「随便哪个口都行」。</p>`;
}

function readSnmpArgs(card, p) {
  const args = { addr: card.querySelector('#' + p + 'a').value.trim() };
  const port = Number(card.querySelector('#' + p + 'p').value);
  const community = card.querySelector('#' + p + 'c').value;
  const version = card.querySelector('#' + p + 'v').value;
  const iface = card.querySelector('#' + p + 'i').value.trim();
  if (port > 0) args.port = port;
  if (community) args.community = community;
  if (version) args.version = version;
  if (iface) args.iface = iface;
  return args;
}

// SNMP 结果顶部那一排共用信息。
function snmpHead(v) {
  // ★ 「回话」那一格先看 matched：有包但对不上号时 answered 也是 true，
  //   这时候给一个绿的「有」等于把这一条最要紧的区别抹平。
  const reply = v.matched === false ? '<span class="pill warn">有包，对不上号</span>'
    : v.answered ? '<span class="pill ok">有</span>' : '<span class="pill bad">没有</span>';
  return `
    <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
      <div><label>目标</label><div><b><code>${esc(v.target)}</code></b></div></div>
      <div><label>版本</label><div>${esc(v.version || '')}
        ${v.askedVersion && v.askedVersion !== v.version ? `<span class="dim">（问的是 ${esc(v.askedVersion)}）</span>` : ''}
        ${v.iface ? `<span class="dim">从 ${esc(v.iface)} 出去</span>` : ''}</div></div>
      <div><label>回话</label><div>${reply}</div></div>
      ${v.elapsedMs !== undefined ? `<div><label>等了</label><div>${esc(v.elapsedMs)}ms</div></div>` : ''}
      ${v.vendor ? `<div><label>厂商</label><div>${esc(v.vendor)}</div></div>` : ''}
    </div>`;
}

function snmpAdviceBox(cls, advice, extra) {
  const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
  const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
  return `<div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
    ${esc(advice)}${extra ? `<div class="dim" style="margin-top:6px;font-size:12.5px">${esc(extra)}</div>` : ''}</div>`;
}

function snmpProbeCard() {
  const card = $(`<div class="card">
    <h2>这台设备 SNMP 通不通 <span id="sv"></span></h2>
    <p class="hint">问一句「你是谁、开机多久了」（系统组那七栏）。这是 SNMP 那几栏的第一步：
      MAC 表、端口、PoE、LLDP 查不出来，先回这张卡确认团体名和路是通的。
      没回话时会自动换另一档版本再问一次（v2c 不通换 v1），用来把「这台只认另一档」从三种病里摘出去。</p>
    ${snmpFormHTML('sw')}
    <div class="row" style="margin-top:10px">
      <div style="flex:0 0 auto;min-width:0">
        <label style="display:flex;align-items:center;gap:6px;font-weight:400">
          <input type="checkbox" id="snover" style="width:auto"> 不做版本对照（只问指定那一档）</label></div>
      <div style="flex:0 0 auto;min-width:0"><button class="btn primary" id="sgo">问一问</button></div>
    </div>
    <div id="sout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#sout');
  const top = card.querySelector('#sv');
  card.querySelector('#sgo').onclick = async () => {
    top.innerHTML = '';
    const args = readSnmpArgs(card, 'sw');
    args.noVersionProbe = card.querySelector('#snover').checked;
    out.innerHTML = '<div class="empty">正在问…（两档都试过的话最坏等四个超时）</div>';
    const r = await call('net.snmp.probe', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">问不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = SNMP_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const extra = [v.detail, v.versionProbe ? `已换成 ${v.versionProbe} 对照过` : '',
      v.otherVersionSilent ? '另一档也没答（版本这一条已经排除了）' : ''].filter(Boolean).join('；');
    const rows = Object.keys(SNMP_SYS_LABEL).filter((k) => v[k] !== undefined && v[k] !== '')
      .map((k) => `<tr><td>${SNMP_SYS_LABEL[k]}</td><td>${k === 'uptime'
        ? `${esc(v.uptime)} <span class="dim">（${esc(v.uptimeSeconds)} 秒）</span>`
        : `<code>${esc(v[k])}</code>`}</td></tr>`).join('');
    out.innerHTML = `
      ${snmpHead(v)}
      ${rows ? `<table><tr><th style="width:110px">系统信息</th><th></th></tr>${rows}</table>` : ''}
      ${v.sysMissing && v.sysMissing.length
        ? `<p class="dim" style="margin:8px 0 0">设备没填这几栏：${esc([].concat(v.sysMissing).join('、'))}
           <span class="dim">（v1 设备上少几栏很常见，不代表它坏了）</span></p>` : ''}
      <div style="margin-top:12px">${snmpAdviceBox(cls, advice, extra)}</div>
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

// MAC 表这一张独有的判定。共用的那些（no-reply / error / 只认另一档）退回 SNMP_CODE 那一份，
// ★ 不在两处各写一遍 —— 写两遍就会有一遍过期。
const SNMP_MAC_CODE = {
  'snmp-ok': ['读到了', 'ok',
    '转发表读回来了。「在哪一个口」这句话的分量，取决于上面写的读了多少、有没有截断。'],
  'snmp-mac-not-found': ['表里没有这个 MAC', 'warn',
    '表读全了，里面确实没有它。★ 这不等于「它不在这台设备上」：这张表只记最近发过帧的源地址，'
    + '终端静默着就不在里面；其次是它可能挂在另一台设备或另一个 VLAN 上。'],
  'snmp-not-walked': ['表没读完，下不了结论', 'warn',
    '读满限量就停了，后面还有什么谁都不知道 —— 这一条给的是下一步，不是结论。'
    + '把「最多读几条」提到能盖住整张表再问一次（留空就是按整张表读）。'],
  'snmp-no-data': ['这台没给出转发表', 'warn',
    '设备答了话（团体名是对的），只是两张转发表都不给内容。要么它不做二层交换'
    + '（三层设备、透明转发），要么链路上确实没流量，要么这张表按 VLAN 分给了别的团体名。'],
};

const FDB_STATUS = {
  dynamic: ['动态学到', 'ok'],
  static: ['手工配死', 'warn'],
  self: ['本机地址', ''],
};

// 一张转发表该有哪些行。★ 端口名问不到的行只写「桥端口 N」，不猜口名 ——
//   猜错的那一次是人照着这句话去机房拔线，拔了别人的链路。
function fdbRowsHTML(es) {
  if (!es || !es.length) return '';
  const withVlan = es.some((e) => e.vlan !== undefined);
  const where = (e) => (e.port
    ? `<code>${esc(e.port)}</code>${e.ifIndex !== undefined ? ` <span class="dim">ifIndex ${esc(e.ifIndex)}</span>` : ''}`
    : `<span class="dim">桥端口 ${esc(e.basePort)}（口名没读到）</span>`);
  const st = (e) => {
    const s = FDB_STATUS[e.status];
    if (!s) return '<span class="dim">设备没给</span>';
    return `<span class="pill ${s[1]}">${esc(s[0])}</span>`;
  };
  return `<table>
    <tr><th>MAC</th>${withVlan ? '<th style="width:80px">VLAN</th>' : ''}
      <th>在哪个口</th><th style="width:110px">怎么进表的</th></tr>
    ${es.map((e) => `<tr><td><code>${esc(e.mac)}</code></td>
      ${withVlan ? `<td>${e.vlan === undefined ? '<span class="dim">—</span>' : esc(e.vlan)}</td>` : ''}
      <td>${where(e)}</td><td>${st(e)}</td></tr>`).join('')}
  </table>`;
}

function snmpMacCard() {
  const card = $(`<div class="card">
    <h2>谁插在哪个口（MAC 地址表） <span id="skstat"></span></h2>
    <p class="hint">读一台设备的转发表。<b>填 MAC 就是反查</b>「这台终端插在交换机的哪个口上」，
      不填读整张表。★ 反查默认把整张表读全（三万条的表要等一会儿）：
      读到一半就说「表里没有」，会让人去查一条本来好好的链路。</p>
    ${snmpFormHTML('sk')}
    <div class="row" style="margin-top:10px">
      <div><label>反查这个 MAC（留空 = 整张表）</label>
        <input id="skmac" placeholder="aa:bb:cc:dd:ee:ff / aa-bb-… / aabb.ccdd.eeff"></div>
      <div style="flex:0 0 110px"><label>只看 VLAN</label><input id="skvlan" placeholder="100"></div>
    </div>
    <details style="margin-top:10px"><summary class="dim">读哪张表、最多读几条（一般不用动）</summary>
      <div class="row" style="margin-top:8px">
        <div style="flex:0 0 220px"><label>读哪张表</label><select id="sktable">
          <option value="">两张都试（默认）</option>
          <option value="qbridge">Q-BRIDGE（带 VLAN）</option>
          <option value="bridge">BRIDGE-MIB（老设备，不带 VLAN）</option>
        </select></div>
        <div style="flex:0 0 150px"><label>最多读几条</label><input id="sklimit" placeholder="整张表"></div>
      </div>
      <p class="hint">交换机有两张转发表：新的是 Q-BRIDGE（带 VLAN），老的是 BRIDGE-MIB（不带 VLAN）。
        默认先读新的、读不到再退老的。点名只读一张，是用来处理
        「这台设备的表结构被厂商改过、读出来是乱的」这种现场。
        ★ 按 VLAN 筛是在<b>读回来之后</b>筛，不减读的量。</p>
    </details>
    <div style="margin-top:12px"><button class="btn primary" id="skgo">读这张表</button></div>
    <div id="skout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#skout');
  const top = card.querySelector('#skstat');
  card.querySelector('#skgo').onclick = async () => {
    top.innerHTML = '';
    const args = readSnmpArgs(card, 'sk');
    const mac = card.querySelector('#skmac').value.trim();
    const vlan = Number(card.querySelector('#skvlan').value);
    const limit = Number(card.querySelector('#sklimit').value);
    const table = card.querySelector('#sktable').value;
    if (mac) args.mac = mac;
    if (vlan > 0) args.vlan = vlan;
    if (limit > 0) args.limit = limit;
    if (table) args.table = table;
    out.innerHTML = `<div class="empty">正在问…${mac
      ? '反查一条 MAC 会把整张表读全，核心交换机上这一步要等几十秒'
      : '表大时要等一会儿'}</div>`;
    const r = await call('net.snmp.mac', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">问不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const [text, cls, advice] = SNMP_MAC_CODE[r.verdict] || SNMP_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const extra = [v.detail,
      v.lookedUp === 'index' ? '这一条是按索引直取的，没读整张表' : '',
      v.portNames === 'unavailable' ? '端口名那一栏问不到（只给了桥端口号）' : '',
      v.unresolved ? `${v.unresolved} 行配不出口名` : '',
      v.skipped ? `${v.skipped} 行索引写法对不上，被跳过` : ''].filter(Boolean).join('；');
    const readOut = v.lookedUp === 'index' ? '<span class="pill ok">按索引直取</span>'
      : `读了 <b>${esc(v.read)}</b> 条`
        + (v.truncated ? ` <span class="pill warn">撞上限量 ${esc(v.readLimit)}，没读完</span>` : ' <span class="pill ok">读全了</span>');
    // ★ 表没读回来（团体名不对、设备不给读）时这三格整排不出现：
    //   留三格空的「读了 条 / 剩下 条」，看着像读回来是 0 条 —— 那是另一种结论。
    const statsRow = v.read === undefined ? '' : `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:10px">
        <div><label>读的表</label><div><code>${esc(v.fdbTable || '')}</code>
          <span class="dim">（试过 ${esc([].concat(v.tablesTried || []).join('、'))}）</span></div></div>
        <div><label>读了多少</label><div>${readOut}</div></div>
        <div><label>筛完剩下</label><div><b>${esc(v.count)}</b> 条
          ${v.vlanFilter ? `<span class="dim">按 VLAN ${esc(v.vlanFilter)} 筛过</span>` : ''}
          ${v.queriedMac ? `<span class="dim">反查 ${esc(v.queriedMac)}</span>` : ''}</div></div>
      </div>`;
    out.innerHTML = `
      ${snmpHead(v)}
      ${statsRow}
      ${fdbRowsHTML(v.entries)}
      <div style="margin-top:12px">${snmpAdviceBox(cls, advice, extra)}</div>
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/**
 * 端口表这一张独有的判定。共用的那些（no-reply / error / 只认另一档）退回 SNMP_CODE 那一份，
 * ★ 不在两处各写一遍 —— 写两遍就会有一遍过期。
 * 「口不行」在这里被拆成三件下一步完全相反的事：有人关着（去问是谁关的）、
 * 链路断了（去查线和对端）、在错包（去查模块和两端速率/双工匹配）。
 */
const SNMP_PORTS_CODE = {
  'snmp-ok': ['读到了', 'ok',
    '表读回来了。★ 这不等于「这些口都还好」：整张表里有口 down 是正常现象（没插线的空口本来就该 down），'
    + '要判断某一个口，把名字或编号填进去点名再问一次，那一次的判定才说得出「断了还是被关着」。'],
  'snmp-port-down': ['链路没起来', 'bad',
    '管理上是开着的、链路上是断的 —— 这一条查物理层：对端开没开机、这根线、对端的口、光模块型号波长对不对。'
    + '★ oper 是「等外部动作」或「下层没起」时别去查线：前者物理层已经好了，在等 802.1X/STP；'
    + '后者是聚合口的成员没起来，要往下看成员口。'],
  'snmp-port-disabled': ['这个口是被关着的', 'warn',
    'admin 本身就是 down —— 有人在设备上 shutdown 了它，不是链路故障，照着「查线」去跑一趟是白跑。'
    + '要恢复得在设备上开回来（本工具只读，一行配置都不改）。'],
  'snmp-port-errors': ['链路能用但在错包', 'warn',
    '口是 up 的，可这一段在错包/丢包：链路活着但在烂。最常见的是线或模块在坏，'
    + '其次是两端速率/双工不匹配（一头自协商一头强制最容易出这个）。'
    + '★ 把「读两遍之间等几秒」调大再问一次，看这几个数是不是在持续涨 —— 涨着才是要动手的那一个。'],
  'snmp-port-not-found': ['没有点名的那个口', 'warn',
    '★ 先分清是哪一种：填 ifIndex 时只问了那一个编号（设备一栏都没给 = 没这个接口号）；'
    + '按名字查且表读全了，才是这台真没有这个名字的口。面板上的「第 5 口」在很多设备上就是不等'
    + '于 ifIndex 5（编号按槽位排、子接口还会插号），先把表列一遍对着 name 认。'],
  'snmp-not-walked': ['表没读全，下不了结论', 'warn',
    '读到「最多列几个」那一档就停了，后面还有什么谁都不知道 —— 此刻「没这个口」和'
    + '「其余口都还好」这两句都不成立。把限量提到能盖住整张表再问一次。'],
  'snmp-no-data': ['这台没给出端口表', 'warn',
    '设备答了话（团体名是对的），只是 ifTable 是空的。要么它不做转发'
    + '（一台主机把 SNMP 服务开着而已），要么这张表被藏进了别的视图 —— 换团体名再问一次 net.snmp.probe。'],
};

// oper 的七个值翻成人话。★ 名字（up/dormant/lowerLayerDown）留在这儿而不是后端：
// 后端给的是设备原文，界面上要的是「所以这一步该查什么」。
const PORT_OPER = {
  up: ['在转发', 'ok'],
  down: ['没链路', 'bad'],
  testing: ['测试模式', 'warn'],
  unknown: ['问不出来', 'warn'],
  dormant: ['等外部动作', 'warn'],
  notPresent: ['不在位', 'warn'],
  lowerLayerDown: ['下层没起', 'warn'],
};

// 顶上一格（判定）。★「链路没起来」只适用于 oper=down：后端把 oper 不是 up 的都归到
// snmp-port-down 这一个代码里，而 dormant / lowerLayerDown / notPresent 的下一步
// 和「查线」完全相反（等放行、看成员口、看模块）。给它们挂一颗红「链路没起来」，
// 等于界面上把后端那句「这两种别去查线」推翻了一遍。
const PORT_DOWN_HINT = {
  down: ['链路没起来', 'bad',
    '管理上是开着的、链路上是断的 —— 这一条查物理层：对端开没开机、这根线、对端的口、光模块型号波长对不对。'],
  dormant: ['物理层好了，还没进转发', 'warn',
    '★ 这一步别去查线：链路上已经起来了，是被上面卡住的 —— 802.1X 没放行、STP 还在监听/学习、或者口没划进 VLAN。'
    + '查那三样，不是查这根线。'],
  lowerLayerDown: ['这个口下面那一层没起', 'warn',
    '★ 别查这个口的线：它是一个聚合口/子接口，它的成员口没起来所以它起不来。'
    + '往下看成员口（把「口名或编号」留空列一遍整张表，看是哪几个成员 down）。'],
  notPresent: ['这个口的部件不在位', 'warn',
    '模块没插、或者这台不支持这个口 —— 不是故障。换一个在位的口再看。'],
  testing: ['口在测试模式', 'warn',
    'admin 是 testing（设备在做线测），这一趟的状态不代表正常转发时的状态。'],
  unknown: ['状态问不出来', 'warn',
    '★ 这一条不能说它是通的还是断的：设备自己答不出这个口的链路状态（驱动/固件没往上送）。'
    + '先换一种问法确认它在不在（整张表列一遍、或者去 ARP 表里看），别照这句话去机房查线。'],
};

// 流量计数器是拿来比大小的，不是拿来精读的：换算成 SI 单位（网络设备上的
// G 本来就是十进制），而且只给三位有效数字 —— 一秒前还在涨的数写成
// 1623456789 反而像个准数。
function humanOctets(n) {
  const unit = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1000 && i < unit.length - 1) { v /= 1000; i += 1; }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(v >= 10 ? 1 : 2)}${unit[i]}`;
}

// 端口表。★ 一格里同时给「现在能不能转发、跑多快、这一段错了多少包、这个状态持续多久」，
// 这几件事在现场是同一趟巡检要一起看的，拆成四张表就没人对着读了。
function portRowsHTML(es) {
  if (!es || !es.length) return '';
  const has = (...ks) => es.some((e) => ks.some((k) => e[k] !== undefined));
  const withRate = has('inMbps', 'outMbps', 'inRateWhy', 'outRateWhy');
  const withTotal = has('inOctets', 'inOctets32', 'outOctets', 'outOctets32');
  const withErr = has('inErrors', 'outErrors', 'inDiscards', 'outDiscards',
    'inErrorsDelta', 'outErrorsDelta', 'inDiscardsDelta', 'outDiscardsDelta');
  const withSince = has('sinceChange');
  const dash = '<span class="dim">—</span>';

  const who = (e) => `
    <div><code>${esc(e.name || e.descr || 'ifIndex ' + e.ifIndex)}</code>
      <span class="dim">#${esc(e.ifIndex)}</span></div>
    ${e.alias ? `<div class="dim">${esc(e.alias)}</div>` : ''}
    ${e.kind && e.kind !== '物理网口' ? `<div class="dim">${esc(e.kind)}</div>` : ''}`;

  // ★ 被关着的口要在这格里同时看得见：只写 oper 会把「有人 shutdown」显示成「断了」。
  const state = (e) => {
    const o = PORT_OPER[e.oper] || ['状态没读到', 'warn'];
    const bits = [`<span class="pill ${o[1]}">${esc(o[0])}</span>`];
    if (e.admin && e.admin !== 'up') bits.push('<span class="pill warn">被关着</span>');
    // 后端那句解释里，开头往往就是这一格已经写过的词（「没链路 / 没链路」）。
    // 重复的那截切掉，只留括号里补充的那半句。
    let m = e.operMeaning || '';
    if (m === o[0]) m = '';
    else if (e.oper !== 'up' && m.startsWith(o[0])) m = m.slice(o[0].length);
    if (m && e.oper !== 'up') bits.push(`<div class="dim">${esc(m)}</div>`);
    return bits.join(' ');
  };

  const speed = (e) => {
    if (e.speedMbps !== undefined) return `${esc(e.speedMbps)}M`;
    // ifSpeed 顶格 = 这一栏问不出准数，只能说「至少」：写成 4294M 是假准数。
    if (e.speedAtLeast !== undefined) return `<span class="pill warn">≥4.29G</span>`;
    return dash;
  };

  // 「这一段速率」这一列只有 110px：后端那句整话（「这台不给读这一向的字节数」）
  // 放进去会把整列顶成三行，谁都读不下去。→ 格子里给短标签 + 悬停给整话，
  // 表下面配一行图例。★ 两种「没有数」不给合成一个词：那是三种下一步相反的病。
  const whyCell = (e, k, why, st) => {
    if (e[k] !== undefined) return esc(e[k]);
    if (e[why] === undefined) return dash;
    // ★ 分档看后端的 inRateStatus / outRateStatus，不去正则那句人话：文案改一个字，
    //   两种下一步相反的病就会被分到同一个标签里。
    const s = e[st] === 'unreliable' ? '算不准' : '不给读';
    return `<span class="dim" title="${esc(e[why])}">${s}</span>`;
  };
  const rate = (e) => `↓ ${whyCell(e, 'inMbps', 'inRateWhy', 'inRateStatus')}`
    + ` ↑ ${whyCell(e, 'outMbps', 'outRateWhy', 'outRateStatus')}<div class="dim">M</div>`;

  const total = (e) => {
    const one = (hc, low) => {
      if (e[hc] !== undefined) return humanOctets(e[hc]);
      // ★ 32 位那一栏单标出来：这一档的数会绕回，不能和 64 位的放一个口径比。
      //   写成 7.65MB³² 界面上看着像「7.65MB32」这个数。
      if (e[low] !== undefined) {
        return `${humanOctets(e[low])}<span class="dim" title="这一栏只有 32 位，千兆口 34 秒就绕回一圈">（32 位）</span>`;
      }
      // 表里有行给了字节数、这一行没给 = 这一向这台不给读，不是 0。
      if (withTotal) return '<span class="dim" title="这一向的字节数设备没给，不是 0">不给读</span>';
      return dash;
    };
    return `↓ ${one('inOctets', 'inOctets32')} ↑ ${one('outOctets', 'outOctets32')}`;
  };

  const counts = (label, dIn, dOut, cIn, cOut) => (e) => {
    const cell = (k) => (e[k] === undefined ? dash : esc(e[k]));
    const got = e[dIn] !== undefined || e[dOut] !== undefined || e[cIn] !== undefined || e[cOut] !== undefined;
    if (!got) return '';
    return `<div>${label} ${cell(dIn)} / ${cell(dOut)}`
      + `<span class="dim"> 共 ${cell(cIn)}/${cell(cOut)}</span></div>`;
  };
  const errCell = counts('错包', 'inErrorsDelta', 'outErrorsDelta', 'inErrors', 'outErrors');
  const discCell = counts('丢包', 'inDiscardsDelta', 'outDiscardsDelta', 'inDiscards', 'outDiscards');

  const since = (e) => (e.sinceChange === undefined ? dash
    : `${esc(e.sinceChange)}<div class="dim">前换的状态</div>`);

  const head = `<tr><th>口</th><th style="width:150px">现在</th><th style="width:70px">线速</th>
    ${withRate ? '<th style="width:110px">这一段速率</th>' : ''}
    ${withTotal ? '<th style="width:150px">一共跑了</th>' : ''}
    ${withErr ? '<th style="width:190px">错包 / 丢包（入/出）</th>' : ''}
    ${withSince ? '<th style="width:110px">这个状态多久了</th>' : ''}</tr>`;

  // ★ 格子里的短标签必须在表下面对回整句话，否则「不给读」和「算不准」看着像
  //   同一个「读不出来」——而它们的下一步相反（换团体名 / 把测量间隔调短）。
  const whySet = new Set();
  for (const e of es) {
    for (const k of ['inRateStatus', 'outRateStatus']) {
      if (e[k] === 'unreliable') whySet.add('算不准');
      else if (e[k] === 'no-counter') whySet.add('不给读');
    }
  }
  if (withTotal && es.some((e) => e.inOctets === undefined && e.inOctets32 === undefined
    && e.outOctets === undefined && e.outOctets32 === undefined)) whySet.add('不给读');
  const legendText = {
    '不给读': '「不给读」= 这一向的字节数这台没给 —— 不是 0，也不是「没流量」',
    '算不准': '「算不准」= 计数器对不上（绕了不止一圈、被重置过，或者两遍用的不是同一档），宁可不给数',
  };
  const legend = whySet.size
    ? `<p class="hint" style="margin:6px 0 0">${[...whySet].map((w) => legendText[w]).join('；')}。`
      + '<span class="dim">（鼠标停在格子上有整句话）</span></p>' : '';

  return `<table>${head}
    ${es.map((e) => `<tr>
      <td>${who(e)}</td>
      <td>${state(e)}${e.mtu ? `<div class="dim">MTU ${esc(e.mtu)}</div>` : ''}</td>
      <td>${speed(e)}</td>
      ${withRate ? `<td>${rate(e)}</td>` : ''}
      ${withTotal ? `<td>${total(e)}</td>` : ''}
      ${withErr ? `<td>${errCell(e)}${discCell(e)}</td>` : ''}
      ${withSince ? `<td>${since(e)}</td>` : ''}
    </tr>`).join('')}
  </table>${legend}`;
}

function snmpPortsCard() {
  const card = $(`<div class="card">
    <h2>这个口到底怎么样（端口表） <span id="spstat"></span></h2>
    <p class="hint">读一台设备的端口表：<b>开着没有、链路起来没有、跑多快、这一段流了多少、有没有在错包丢包</b>。
      ★ 填了「口名或编号」才是点名，那一次的判定才说得出「断了还是被关着」；
      不填只列表 —— 整张表里有口 down 不是故障（空口本来就该 down），所以列表一律给「读到了」。</p>
    ${snmpFormHTML('sp')}
    <div class="row" style="margin-top:10px">
      <div><label>口名或编号（留空 = 整张表）</label>
        <input id="spwho" placeholder="GE1/0/5、Gi1/0/5、Vlanif100，或者备注里的字（如「配线架12」）"></div>
      <div style="flex:0 0 130px"><label>ifIndex</label><input id="spidx" placeholder="点名一个口时填"></div>
      <div style="flex:0 0 130px"><label>只看</label><select id="spstate">
        <option value="">都列</option><option value="up">在转发的</option><option value="down">没起来的</option>
      </select></div>
      <div style="flex:0 0 150px"><label>读两遍之间等几秒</label><input id="spwatch" placeholder="0 = 只读一遍"></div>
    </div>
    <details style="margin-top:10px"><summary class="dim">最多列几个口 / 只问状态（一般不用动）</summary>
      <div class="row" style="margin-top:8px">
        <div style="flex:0 0 150px"><label>最多列几个口</label><input id="splimit" placeholder="512"></div>
        <div style="flex:0 0 auto;min-width:0;padding-top:18px">
          <label style="display:flex;align-items:center;gap:6px;font-weight:400">
            <input type="checkbox" id="spnoc" style="width:auto"> 只问状态，不问流量计数器</label></div>
      </div>
      <p class="hint">★ 筛状态是在<b>读回来之后</b>筛，不减读的量；「一共几个口」记的是筛掉之前有几个。
        几百口的设备上「只问状态」能省掉大半报文，代价是没有速率和错包那几栏。
        撞上限量的那一次不会给「其余口都还好」这种结论。</p>
    </details>
    <p class="hint" style="margin-top:8px">「读两遍之间等几秒」填了才给速率和这段时间内的错包增量。
      ★ 千兆口上 32 位计数器 <b>34 秒</b>就绕一圈（万兆 3.4 秒），间隔越长绕圈的概率越大；
      绕了不止一圈时界面上是「不给读 / 算不准」，不会给一个看着合理的假速率。</p>
    <div style="margin-top:12px"><button class="btn primary" id="spgo">读端口表</button></div>
    <div id="spout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#spout');
  const top = card.querySelector('#spstat');
  card.querySelector('#spgo').onclick = async () => {
    top.innerHTML = '';
    const args = readSnmpArgs(card, 'sp');
    const who = card.querySelector('#spwho').value.trim();
    const idx = Number(card.querySelector('#spidx').value);
    const watch = Number(card.querySelector('#spwatch').value);
    const limit = Number(card.querySelector('#splimit').value);
    const state = card.querySelector('#spstate').value;
    if (who) args.name = who;
    if (idx > 0) args.ifIndex = idx;
    if (watch > 0) args.watchSeconds = watch;
    if (limit > 0) args.limit = limit;
    if (state) args.state = state;
    args.noCounters = card.querySelector('#spnoc').checked;
    out.innerHTML = `<div class="empty">正在问…${watch > 0
      ? `（读了两遍，中间等了 ${esc(watch)} 秒）`
      : '表大时要等一会儿'}</div>`;
    const r = await call('net.snmp.ports', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">问不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const ports = [].concat(v.ports || []);
    const base = SNMP_PORTS_CODE[r.verdict] || SNMP_CODE[r.verdict] || [r.verdict, '', ''];
    // 后端把「oper 不是 up」全归到 snmp-port-down 一个码，可这三种的下一步和查线相反。
    // ★ 顶上一格必须跟着 oper 走，否则界面上一颗红「链路没起来」把后端那句
    //   「这两种别去查线」推翻了一遍。
    const [text, cls, advice] = r.verdict === 'snmp-port-down'
      ? (PORT_DOWN_HINT[ports[0] && ports[0].oper] || base) : base;
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const extra = [v.detail,
      // ★ 三种「没有计数器」分开说：没问、这台不给读、压根没口可读。
      //   合成一句「这台不给读」会让人白换团体名。
      //   counterBits 是短板口径（有一向只有 32 位就报 32），所以这句说的是「最窄的那一档」，
      //   不能写成「计数器 32 位」——满表 64 位的值会被这一句盖掉。
      v.counterBits === 64 ? '字节数两向都是 64 位（不会绕回）'
        : v.counterBits === 32 ? '有向只给到 32 位计数器，千兆口 34 秒就绕一圈（表里那几格已标出）'
          : (args.noCounters ? '这一趟只问了状态，没问流量计数器'
            : (ports.length ? '字节数那一栏这台不给读' : '')),
      // 重启这件事表上面已经有一整段在讲了（连后端那句 rateUnsure 一起），
      // 这里再写一遍只会让人以为除了重启还有另一桩病。
      v.rateUnsure && !v.rebooted ? `速率：${v.rateUnsure}` : '',
      v.sampleAborted ? v.sampleAborted : '',
      v.truncated ? `撞上限量 ${v.readLimit}，这张表没读全` : ''].filter(Boolean).join('；');
    // ★ 列表空着、可表其实读了回来：这一格必须自己说话。不写的话界面只剩一颗
    //   「读到了」加一张空表，看着像「这台一个口都没有」——那是另一种结论。
    //   （没点状态筛而列表空的只有「按名字没找着」那一种，后端那条判定已经说清了。）
    const emptyLine = (ports.length || !v.read || !v.stateFilter) ? '' : `
      <p class="hint">★ 一个口都没列出来，但这不是「这台没有口」：按「${
        esc(v.stateFilter === 'up' ? '在转发的' : '没起来的')}」筛之前，这一趟读了 ${
        esc(v.read)} 个口，没有一个在这个状态上。被筛掉不等于没有。</p>`;
    // ★ 读回来几口 / 筛完剩几口要看得见：只看下面那张表的人会把
    //   「筛过剩下 3 个」读成「这台只有 3 个口」。
    const statsRow = v.read === undefined ? '' : `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:10px">
        <div><label>读了多少</label><div><b>${esc(v.read)}</b> 个口
          ${v.count !== undefined && v.count !== v.read
            ? `<span class="dim">筛完列出 <b>${esc(v.count)}</b> 个</span>` : ''}
          ${v.truncated ? `<span class="pill warn">撞上限量 ${esc(v.readLimit)}</span>` : ''}</div></div>
        ${v.up !== undefined ? `<div><label>在转发 / 没链路 / 被关着</label>
          <div><b>${esc(v.up)}</b> / <b>${esc(v.down)}</b> / <b>${esc(v.adminDown)}</b></div></div>` : ''}
        ${v.sampleSeconds !== undefined ? `<div><label>测了多久</label><div>${esc(v.sampleSeconds)} 秒</div></div>` : ''}
      </div>`;
    out.innerHTML = `
      ${snmpHead(v)}
      ${statsRow}
      ${v.rebooted ? `<p class="hint">★ 这台设备在两次读之间重启过（sysUpTime 倒退），
        所以这一趟<b>没有速率和增量</b> —— 计数器全被清零过，相减得到的是「开机到现在」，
        不是「这一秒跑了多少」。上面的累计值是第二次读到的那一份。</p>` : ''}
      ${emptyLine}
      ${portRowsHTML(v.ports)}
      ${(v.errorPorts && v.errorPorts.length) ? `<p class="hint" style="margin:8px 0 0">
        这一段在错包的口：${esc([].concat(v.errorPorts).join('、'))}</p>` : ''}
      ${(v.recentlyChanged && v.recentlyChanged.length) ? `<p class="hint" style="margin:6px 0 0">
        五分钟内换过状态的口：${esc([].concat(v.recentlyChanged).join('、'))}
        <span class="dim">—— 「偶尔断一下」先看这几个</span></p>` : ''}
      <div style="margin-top:12px">${snmpAdviceBox(cls, advice, extra)}</div>
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/*
 * ── PoE 供电（net.snmp.poe）──
 *
 * ★★ 这一张卡买的是「到底谁不给电」。RFC 3621 把供电分成三层：整台的电源池、
 *   这个口允不允许（adminEnable）、这个口现在在不在供（detectionStatus）。
 *   三层的下一步完全相反（查电源模块 / 去设备上开回来 / 查线和对端设备），
 *   所以这里三样分开摆，绝不合成一栏「供电正常/不正常」。
 * ★ 这一棵树给不出「某个口用了几瓦」—— 只有整台的实测值。不许在界面上造一个每口功率。
 * ★ 判定文案只写「这一格该看什么」，下一步的整句话是后端 note 的事，这里不再拼一遍。
 */
const SNMP_POE_CODE = {
  'snmp-ok': ['读到了', 'ok',
    '电源池和口的状态都读回来了。★ 整张表里有口「在检测」不是故障清单：没插受电设备的空口本来就该在检测。'
    + '要判断某一个口，把组号口号（或 ifIndex）填进去点名再问一次。'],
  'snmp-poe-pse-fault': ['整台的 PoE 电源报故障', 'bad',
    '电源池自己报了 faulty —— 这是电源模块、整机供电的事，不是哪一根线、也不是哪个口的配置。'
    + '★ 这一条压过下面每一行的状态：池子塌了的时候口那一栏写什么都不是那个口的事。'],
  'snmp-poe-off': ['这台的 PoE 电源总开关是关着的', 'bad',
    '整台的电源池 oper=off —— 逐个口去看「有没有供电」是白跑，每一个都只会是「没在供」。'
    + '先确认这是不是有人有意关掉的（本工具只读，不会开回来）。'],
  'snmp-poe-budget': ['PoE 余量紧了', 'warn',
    '这一档说的是「下一个插上来的设备可能被拒绝」，不是「现在哪个口坏了」。'
    + '两条路：按优先级把不重要的口排开（预算不够时设备先断优先级低的那几个），或者减掉一些负载。'],
  'snmp-poe-disabled': ['这个口没在供电', 'warn',
    '★ 先看上面「允不允许」那一格：被人关着的和这台自己不供，下一步完全不一样。'],
  'snmp-poe-searching': ['在检测、没供上电', 'warn',
    '检测状态卡在 searching：没插东西、插上来的东西签名不合规、或者它要的电超了这台给的档。'
    + '★ 把「读两遍之间等几秒」填上再问一次，看「签名不合规」「要电被拒」这两个计数器涨不涨 —— 涨着的那一种才要动手。'],
  'snmp-poe-fault': ['这个口自己报故障', 'bad',
    '口的 detectionStatus 报 fault / otherFault —— 是这一个口（或它下面那根线、那个设备）的事，'
    + '不是电源池的事。先把这个口的线和对端换一次试试，再看「过载」「短路」两个计数器。'],
  'snmp-poe-not-found': ['没有点名的那一行', 'warn',
    '★ 先分清是哪一种：按「组号 + 口号」直取时只问了那一行，本结果没走整张表；'
    + '走表筛过、而且表读全了，才是这台真没有这一行。'
    + '堆叠设备上每一箱都有自己的 5 号口 —— 不填组号时它跟面板上的第 5 口不是一回事。'],
  'snmp-not-walked': ['PoE 表没读全，下不了结论', 'warn',
    '读到「最多列几个」那一档就停了，后面还有什么谁都不知道 —— 此刻「没有这一行」和'
    + '「其余口都还好」这两句都不成立。把限量提到能盖住整张表再问一次。'],
  'snmp-no-data': ['这台没给出 PoE 表', 'warn',
    '设备答了话（团体名是对的），只是 PoE 那棵子树没给出认行用的那一栏。三种下一步相反：'
    + '它不是供电端（不支持 PoE 的交换机、以及受电设备本来就没有这棵树）、这一棵被藏进了别的视图、'
    + '或者它只给了别的栏 —— 下面那句会写明它给了哪几栏。'],
};

// 整张表里报错 ≠ 点名的那一个口报错：顶上一格说错了范围，人就照着去查一个口。
const POE_FAULT_LISTING = ['表里有口在报故障', 'bad',
  '口这一栏报 fault / otherFault —— 是那几个口（或它们下面的线、对端设备）的事，不是电源池的事。'
  + '★ 逐个口把线重做一遍，再看「过载」「短路」两个计数器是不是在涨；整张表读回来了才有这一句。'];

const POE_STATUS = {
  disabled: ['没在供', 'warn'],
  searching: ['在检测', 'warn'],
  deliveringPower: ['在供电', 'ok'],
  fault: ['报故障', 'bad'],
  test: ['测试中', 'warn'],
  otherFault: ['报故障', 'bad'],
};

// 「没在供」这一颗顶栏必须跟着 admin 那一格走：后端把「有人关了」和「这台自己不供」
// 归到同一个码里，可前者的下一步是去设备上开回来、后者是去看电源池预算。
const POE_DISABLED_HINT = {
  disabled: ['这个口的供电被人关着', 'warn',
    'adminEnable=false —— 有人在设备上把这个口的 PoE 关掉了，不是故障，照着「查线」跑一趟是白跑。'],
  enabled: ['允许供电，可这台自己不供', 'warn',
    'admin 是开着的 —— 这不是有人关的：多半它本来就不是 PoE 口，或者电源池不够、设备把它排除了。'
    + '★ 去看上面那一栏的余量，别去问是谁关的。'],
  missing: ['分不清是谁关的', 'warn',
    '使能那一栏这台没给，所以「人关的」和「设备自己排除的」分不开 —— 这两种下一步不一样，'
    + '先确认这一栏在设备的 SNMP 视图里能不能读。'],
};

const PSE_OPER = {
  on: ['开着', 'ok'],
  off: ['关着', 'bad'],
  faulty: ['报故障', 'bad'],
};

const PSE_BUDGET = {
  ok: ['还够', 'ok'],
  tight: ['紧了', 'warn'],
  unknown: ['算不出来', 'warn'],
};

// 五个计数器：格子里给短标签，整句话在下面的图例里对回去。
// ★ 它们是「从开机攒到现在」的次数，不带这一句，「3 次」看着像「刚才 3 次」。
const POE_COUNTER = {
  mpsAbsent: ['掉电', '供着供着掉回去（检测不到受电设备的维持签名）'],
  invalidSignature: ['签名不合规', '插上来的东西签名不对（不是标准 PD，或者线不行）'],
  powerDenied: ['要电被拒', '插上来要电、被这台拒绝了（多半是余量不够）'],
  overLoad: ['过载', '过载保护跳过'],
  shortCircuit: ['短路', '短路保护跳过'],
};

const POE_PRIORITY = { critical: '关键', high: '高', low: '低' };

const POE_MATCHED = {
  'portIndex-equals-ifIndex': '按编号猜的',
  'pethPsePortType-names-the-port': '设备对的口名',
  'both-mappings': '两条都对上',
};

// 电源池那一张小表：整台的额定 / 实测 / 还剩 / 阈值。
// ★ 它排在口的上面，因为池子级的问题（关着、故障、余量紧）压过每一个口的结论。
function pseRowsHTML(es) {
  if (!es || !es.length) return '';
  const dash = '<span class="dim">—</span>';
  const w = (n) => (n === undefined ? dash : `${esc(n)}<span class="dim">W</span>`);
  return `<table>
    <tr><th style="width:70px">电源池</th><th style="width:150px">总开关</th>
      <th style="width:60px">额定</th><th style="width:80px">实测在耗</th>
      <th style="width:56px">已用</th><th style="width:60px">还剩</th>
      <th style="width:52px">阈值</th><th>余量</th></tr>
    ${es.map((e) => {
    const o = PSE_OPER[e.oper];
    const b = PSE_BUDGET[e.budget] || [e.budget, 'warn'];
    // ★ 每一句解释挂在它讲的那一栏下面：operMeaning 讲的是总开关，
    //   挂到「余量」那一格就等于把「电源开着」说成了对余量的结论。
    const why = e.pseInconsistent || e.budgetWhy || e.budgetBasis || '';
    const clip = (s) => (s.length > 34 ? `${s.slice(0, 34)}…` : s);
    return `<tr>
        <td><code>第 ${esc(e.group)} 组</code></td>
        <td>${o ? `<span class="pill ${o[1]}">${esc(o[0])}</span>` : '<span class="dim" title="这一栏这台没给">不给读</span>'}
          ${e.operMeaning && e.oper !== 'on' ? `<div class="dim" title="${esc(e.operMeaning)}">${esc(clip(e.operMeaning))}</div>` : ''}</td>
        <td>${w(e.powerW)}</td>
        <td>${w(e.consumptionW)}</td>
        <td>${e.usedPct === undefined ? dash : `${esc(e.usedPct)}%`}</td>
        <td>${w(e.remainingW)}</td>
        <td>${e.thresholdPct === undefined ? dash : `${esc(e.thresholdPct)}%`}</td>
        <td><span class="pill ${b[1]}">${esc(b[0])}</span>${why
      ? `<div class="dim" title="${esc(why)}">${esc(clip(why))}</div>` : ''}</td>
      </tr>`;
  }).join('')}
  </table>
    <p class="hint" style="margin:6px 0 0">★ 额定和实测这两栏的口径是设备自己定的（RFC 里单位是瓦，可有些设备报的不是瓦）。
      「还剩」是这两个数相减，不是「还能再插几台设备」。</p>`;
}

// PoE 口表：允不允许 / 现在在不在供 / 等级与优先级 / 五个计数器。
// ★ 只列有意义的列：这台没给「线对」就不开那一栏，免得整栏空着像读错了。
function poeRowsHTML(es) {
  if (!es || !es.length) return '';
  const keys = Object.keys(POE_COUNTER);
  const has = (...ks) => es.some((e) => ks.some((k) => e[k] !== undefined));
  const withPairs = has('pairs', 'pairsControllable');
  const withGrade = has('class', 'classUnknown', 'classSkipped', 'priority');
  const withCnt = has(...keys.flatMap((k) => [k, `${k}Delta`]));
  const dash = '<span class="dim">—</span>';

  const who = (e) => `
    <div><code>${esc(e.group)} 组 ${esc(e.port)} 号</code></div>
    ${e.pdType ? `<div class="dim">${esc(e.pdType)}</div>` : ''}
    ${e.matchedBy ? `<div class="dim" title="${esc(e.matchedByWhy)}">${esc(POE_MATCHED[e.matchedBy] || e.matchedBy)}</div>` : ''}`;

  // ★ 允不允许 / 现在怎样 是两栏，不能并成一栏：admin 开着但设备不供、
  //   和 admin 被人关了，界面上看着一样就会有人去查线。
  const allow = (e) => {
    if (e.admin === undefined) return '<span class="dim" title="使能这一栏这台没给">不给读</span>';
    if (e.admin === 'disabled') {
      return `<span class="pill warn" title="${esc(e.adminWhy)}">被关着</span>`;
    }
    return '<span class="pill">允许</span>';
  };
  const now = (e) => {
    if (e.status === undefined) {
      return `<span class="pill warn" title="${esc(e.statusMissing)}">说不清</span>`;
    }
    const s = POE_STATUS[e.status] || [e.status, 'warn'];
    let m = e.statusMeaning || '';
    // ★ 后端那句解释开头常常就是这一格已经写过的词（「在供电 / 正在供电」）：
    //   重复的那截切掉，只留补充的半句，否则一格两行说的是同一句话。
    if (m === s[0] || (m.includes(s[0]) && m.length <= s[0].length + 2)) m = '';
    else if (m.startsWith(s[0])) m = m.slice(s[0].length).replace(/^[，、：]/, '');
    return `<span class="pill ${s[1]}">${esc(s[0])}</span>`
      + (m ? `<div class="dim">${esc(m)}</div>` : '');
  };
  const grade = (e) => {
    const bits = [];
    if (e.class) bits.push(`<div title="${esc(e.classNote)}">等级 ${esc(e.class)}</div>`);
    else if (e.classUnknown !== undefined) {
      bits.push(`<div class="dim" title="${esc(e.classNote)}">等级 ${esc(e.classUnknown)}（不换算成瓦）</div>`);
    } else if (e.classSkipped) {
      bits.push(`<div class="dim" title="${esc(e.classSkipped)}">等级不报</div>`);
    }
    if (e.priority) {
      bits.push(`<div class="dim" title="${esc(e.priorityNote)}">优先级 ${esc(POE_PRIORITY[e.priority] || e.priority)}</div>`);
    }
    return bits.join('') || dash;
  };
  const pairs = (e) => {
    if (e.pairs === undefined) {
      return e.pairsControllable === false
        ? '<span class="dim" title="这台不能切线对">固定</span>' : dash;
    }
    // 设备原文（signal/spare）放进悬停：格子里只留一个中文词，别中英各写一遍。
    return `<div class="dim" title="${esc(e.pairs)} · ${esc(e.pairsNote)}">${
      e.pairs === 'signal' ? '信号线对' : '备用线对'}</div>`;
  };
  const cnt = (e) => {
    const bits = [];
    for (const k of keys) {
      const total = e[k];
      const delta = e[`${k}Delta`];
      if (total === undefined && delta === undefined) continue;
      if (!total && !delta) continue;
      bits.push(`<div>${esc(POE_COUNTER[k][0])} ${total === undefined ? '?' : esc(total)}`
        + (delta ? `<span class="pill bad">+${esc(delta)}</span>` : '') + '</div>');
    }
    if (!bits.length) {
      return keys.some((k) => e[k] !== undefined) ? '<span class="dim">都是 0</span>' : dash;
    }
    if (e.countersUnreliable) {
      bits.push(`<div class="dim" title="${esc(e.countersUnreliable)}">增量算不准</div>`);
    }
    return bits.join('');
  };

  const legend = new Set();
  for (const e of es) for (const k of keys) if (e[k] || e[`${k}Delta`]) legend.add(POE_COUNTER[k][1]);

  return `<table>
    <tr><th style="width:120px">PoE 口</th><th style="width:80px">允不允许</th>
      <th style="width:150px">现在</th>
      ${withGrade ? '<th style="width:118px">等级 / 优先级</th>' : ''}
      ${withPairs ? '<th style="width:80px">线对</th>' : ''}
      ${withCnt ? '<th style="width:150px">这一段 / 累计</th>' : ''}</tr>
    ${es.map((e) => `<tr>
      <td>${who(e)}</td>
      <td>${allow(e)}</td>
      <td>${now(e)}</td>
      ${withGrade ? `<td>${grade(e)}</td>` : ''}
      ${withPairs ? `<td>${pairs(e)}</td>` : ''}
      ${withCnt ? `<td>${cnt(e)}</td>` : ''}
    </tr>`).join('')}
  </table>${legend.size ? `<p class="hint" style="margin:6px 0 0">计数器：${[...legend].join('；')}。`
    + '<span class="dim">（红角标是这次读的两遍之间涨的，那才是要动手的）</span></p>' : ''}`;
}

function snmpPoeCard() {
  const card = $(`<div class="card">
    <h2>这个口给不给电（PoE） <span id="postat"></span></h2>
    <p class="hint">读一台设备的 PoE 供电：<b>整台的电源池够不够、这个口允不允许供电、现在在不在供、
      检测卡在哪一步、掉电/被拒/过载/短路各攒了几次</b>。
      ★ 这一栏<b>给不出「某个口用了几瓦」</b> —— RFC 3621 只有整台的实测值，谁在这里编一个每口功率谁就是在编。
      先跑最上面那张「SNMP 通不通」。</p>
    ${snmpFormHTML('po')}
    <div class="row" style="margin-top:10px">
      <div style="flex:0 0 110px"><label>组号</label><input id="pogroup" placeholder="1，堆叠才有"></div>
      <div style="flex:0 0 110px"><label>口号</label><input id="poport" placeholder="PoE 表里的编号"></div>
      <div style="flex:0 0 110px"><label>ifIndex</label><input id="poidx" placeholder="按接口号问"></div>
      <div><label>或者在备注里找这几个字</label><input id="polabel" placeholder="AP-3F、NVR-12…（很多设备上这栏是空的）"></div>
      <div style="flex:0 0 130px"><label>只看</label><select id="postate">
        <option value="">都列</option><option value="on">在供电的</option><option value="off">没在供电的</option>
      </select></div>
      <div style="flex:0 0 150px"><label>读两遍之间等几秒</label><input id="powatch" placeholder="0 = 只读一遍"></div>
    </div>
    <details style="margin-top:10px"><summary class="dim">最多列几个口 / 只问状态（一般不用动）</summary>
      <div class="row" style="margin-top:8px">
        <div style="flex:0 0 150px"><label>最多列几个口</label><input id="polimit" placeholder="512"></div>
        <div style="flex:0 0 auto;min-width:0;padding-top:18px">
          <label style="display:flex;align-items:center;gap:6px;font-weight:400">
            <input type="checkbox" id="ponoc" style="width:auto"> 只问状态，不问那几个计数器</label></div>
      </div>
      <p class="hint">★ 筛状态是在<b>读回来之后</b>筛，不减读的量；「读了多少」记的是筛掉之前有几个。
        撞上限量的那一次不会给「其余口都还好」这种结论。</p>
    </details>
    <p class="hint" style="margin-top:8px">★ 「口号」既不是面板上的第几口、也不等于 ifIndex：
      堆叠设备里每一箱都有自己的 5 号口，不填组号会把每一组的 5 号都列出来。
      填 ifIndex 时这一条是<b>猜的映射</b>（RFC 3621 没规定两者的关系），结果里每一行都会写明是怎么对上的 ——
      只有设备自己把口名写在 pethPsePortType 那一栏里，那条才算设备给的。</p>
    <div style="margin-top:12px"><button class="btn primary" id="pogo">读 PoE 供电情况</button></div>
    <div id="poout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#poout');
  const top = card.querySelector('#postat');
  card.querySelector('#pogo').onclick = async () => {
    top.innerHTML = '';
    const args = readSnmpArgs(card, 'po');
    const num = (id) => Number(card.querySelector(id).value);
    const group = num('#pogroup');
    const port = num('#poport');
    const idx = num('#poidx');
    const label = card.querySelector('#polabel').value.trim();
    const watch = num('#powatch');
    const limit = num('#polimit');
    const state = card.querySelector('#postate').value;
    if (group > 0) args.groupIndex = group;
    if (port > 0) args.portIndex = port;
    if (idx > 0) args.ifIndex = idx;
    if (label) args.name = label;
    if (watch > 0) args.watchSeconds = watch;
    if (limit > 0) args.limit = limit;
    if (state) args.state = state;
    args.noCounters = card.querySelector('#ponoc').checked;
    out.innerHTML = `<div class="empty">正在问…${watch > 0
      ? `（读了两遍，中间等了 ${esc(watch)} 秒）`
      : '整台加整张 PoE 表，口多时要等一会儿'}</div>`;
    const r = await call('net.snmp.poe', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">问不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const ports = [].concat(v.poePorts || []);
    const base = SNMP_POE_CODE[r.verdict] || SNMP_CODE[r.verdict] || [r.verdict, '', ''];
    // 「这个口没在供电」要跟着 admin 那一格走，否则界面把后端那句
    // 「这两种下一步不一样」推翻成一颗统一的黄灯。
    const ad = ports[0] && ports[0].admin;
    // 整张表那一趟（poeSummary）也会给 snmp-poe-fault，那颗灯不能说「这个口」：
    // ★ v.powering 只有收口那一条会写，点名一个口时没有 —— 用它分范围。
    const listed = r.verdict === 'snmp-poe-fault' && v.powering !== undefined;
    const [text, cls, advice] = listed ? POE_FAULT_LISTING
      : r.verdict === 'snmp-poe-disabled'
        ? (POE_DISABLED_HINT[ad === 'disabled' || ad === 'enabled' ? ad : 'missing'] || base) : base;
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const extra = [v.detail,
      v.countersSince,
      v.labelEmpty,
      v.sampleUnsure,
      v.truncated ? `撞上限量 ${v.readLimit}，这张表没读全` : ''].filter(Boolean).join('；');
    const statsRow = v.read === undefined ? '' : `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:10px">
        <div><label>读了多少</label><div><b>${esc(v.read)}</b> 个 PoE 口
          ${v.count !== undefined && v.count !== v.read
            ? `<span class="dim">筛完列出 <b>${esc(v.count)}</b> 个</span>` : ''}
          ${v.truncated ? `<span class="pill warn">撞上限量 ${esc(v.readLimit)}</span>` : ''}
          ${v.truncated ? '<span class="dim">（读到这一档就停了，一共有几个口没说）</span>'
            : v.countTotal === undefined ? '<span class="dim">（这一条没走整张表，一共有几个口没说）</span>'
              : `<span class="dim">表里一共 ${esc(v.countTotal)} 行</span>`}</div></div>
        ${v.powering === undefined ? '' : `<div><label>在供电 / 在检测 / 没在供 / 报错</label>
          <div><b>${esc(v.powering)}</b> / <b>${esc(v.searching)}</b> / <b>${esc(v.disabled)}</b> / <b>${esc(v.faulty)}</b>
          ${v.adminOff !== undefined ? `<span class="dim">其中 ${esc(v.adminOff)} 个是被关着的</span>` : ''}
          ${v.statusUnknown ? `<span class="dim">另有 ${esc(v.statusUnknown)} 行说不清</span>` : ''}</div></div>`}
        ${v.sampleSeconds !== undefined ? `<div><label>测了多久</label><div>${esc(v.sampleSeconds)} 秒</div></div>` : ''}
      </div>`;
    // ★ 表空的、可其实读回来过：这一格必须自己说话，不然只剩一颗「读到了」加一张空表，
    //   看着像「这台一个 PoE 口都没有」。
    const emptyLine = (ports.length || !v.read || !v.stateFilter) ? '' : `
      <p class="hint">★ 一个口都没列出来，但这不是「这台没有 PoE 口」：按「${
        esc(v.stateFilter === 'on' ? '在供电的' : '没在供电的')}」筛之前读了 ${
        esc(v.read)} 行，没有一行在这个状态上。被筛掉不等于没有。</p>`;
    out.innerHTML = `
      ${snmpHead(v)}
      ${statsRow}
      ${v.rebooted ? `<p class="hint">★ 这台设备在两次读之间重启过（sysUpTime 倒退），计数器被清零了，
        所以这一趟<b>没有增量</b> —— 表里那几个数是累计值，不是「这一会儿涨的」。</p>` : ''}
      ${pseRowsHTML(v.pse)}
      <h2 style="margin-top:16px">口的供电</h2>
      ${emptyLine}
      ${poeRowsHTML(v.poePorts)}
      ${(v.faultPorts && v.faultPorts.length) ? `<p class="hint" style="margin:8px 0 0">
        报故障的口：${esc([].concat(v.faultPorts).join('、'))}</p>` : ''}
      ${(v.powerDeniedPorts && v.powerDeniedPorts.length) ? `<p class="hint" style="margin:6px 0 0">
        攒下「要电被拒」的口：${esc([].concat(v.powerDeniedPorts).join('、'))}
        <span class="dim">—— 插得上、要不到电，先看上面那栏余量</span></p>` : ''}
      <div style="margin-top:12px">${snmpAdviceBox(cls, advice, extra)}</div>
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

const SNMP_LLDP_CODE = {
  'snmp-lldp-unsupported': ['这台没有 LLDP 这一棵', 'warn',
    '设备答了话（团体名是对的），可 LLDP-MIB 那棵子树整个读不到。三种下一步完全相反：'
    + '这台不是网管设备/没开 LLDP、这一棵被藏进了别的视图、或者它只做 CDP 不做 LLDP'
    + '（★ 只发 CDP 的设备在这里就是不存在，读不到邻居不等于对端不存在 —— 那要换 CDP 那一侧去问）。'],
  'snmp-lldp-tx-only': ['这个口的 LLDP 是「只发不收」', 'warn',
    'lldpPortConfigAdminStatus=txOnly：这一档按标准只把自己发出去、不存对端发来的东西，'
    + '所以它的邻居表本来就该是空的。★ 这不是对端没发，是这台自己不存 —— 要互相看得见，'
    + '去设备上把这个口改成收发（本工具只读，不改配置）。'],
  'snmp-lldp-port-off': ['这个口的 LLDP 关着', 'warn',
    'lldpPortConfigAdminStatus=disabled：不发也不存，这个口上永远不会有邻居。'
    + '先去设备上确认这是不是有意关的（本工具只读）。'],
  'snmp-lldp-no-neighbor': ['没有邻居', 'warn',
    '这台有 LLDP 那棵树、这个口也在收，可邻居表里一条都没有。剩下两种病：对端根本没发 LLDP'
    + '（老设备、打印机、IPC 常常只发 CDP 或不发），或者对端发的被中间的东西吞了。'
    + '★ 这一条不是「这根线上没东西」，是「没有东西在向它说 LLDP」—— 线下插着什么还得看 MAC 表那一栏。'],
  'snmp-lldp-not-found': ['点名的那个口没有邻居行', 'warn',
    '★ 别的口有邻居，只有这一个口没有 —— 这一条比「整台没邻居」有用得多。'
    + '先看这一口的 LLDP 开关是不是「只发不收」或关着；是收发、可就是没有，再去查对端发不发。'],
  'snmp-lldp-multi': ['一个口上听见了好几个邻居', 'warn',
    '★ 这不是故障，是拓扑：这个口下面接了台非网管交换机、hub 或者分光器。'
    + '设备不会主动把这件事说出来，要理拓扑就顺着这几个口去现场看一眼。'],
  'snmp-lldp-aging': ['邻居在老化（它会消失）', 'bad',
    '刚才那一段里，某个口上的邻居老化计数涨了：对端停发 LLDP、或者它给的存活时间比自己的发包间隔短、'
    + '或者这条链路在抖。★ 这一条不是「没有邻居」，是「邻居会消失」—— 查对端为什么停发，别查这台没配。'],
  'snmp-not-walked': ['邻居表没读全，下不了结论', 'warn',
    '这张表读到一半停住了（撞上限量，或者设备走着走着不往前走了）。'
    + '★ 这时候「这个口没有邻居」和「其余口都还好」两句都不成立 —— 少读的那几行里'
    + '就可能正好有你要找的那一台。把「最多列几条」提到能盖住整张表再问一次。'],
  'snmp-no-data': ['这台没给出 LLDP 的内容', 'warn',
    '设备答了话（团体名是对的），可 LLDP 那几组一栏都没给。要么这台的 LLDP 服务没开'
    + '（不少设备上不开服务时这棵树就不存在），要么整棵被放进了别的视图 —— 换团体名再问一次 net.snmp.probe。'],
};

const LLDP_ADMIN = {
  txOnly: ['只发不收', 'warn'],
  rxOnly: ['只听不发', 'warn'],
  txAndRx: ['收发', 'ok'],
  disabled: ['关着', 'bad'],
};

const LLDP_ADMIN_LABEL = {
  txAndRx: '收发', txOnly: '只发不收', rxOnly: '只听不发', disabled: '关着', other: '别的值',
};

const LLDP_MATCHED = {
  'dot1dBasePortIfIndex': '设备对的映射',
  'lldpLocPort-names-it': '设备对的口名',
  'portNum-equals-ifIndex': '按编号猜的',
  'both-mappings': '两条都对上',
};

// 邻居表：一个口一行（一个口上几行邻居就几行）。
// ★ 只开有内容的栏 —— 这台没给管理地址就不开那一栏，整栏空着像读错了。
function lldpRowsHTML(es) {
  if (!es || !es.length) return '';
  const has = (...ks) => es.some((e) => e[ks[0]] !== undefined
    || ks.slice(1).some((k) => e[k] !== undefined));
  const withMgmt = has('mgmtAddresses');
  const withAge = has('lastUpdate', 'lastUpdateWhy', 'ageoutsTotal', 'ageoutsDelta');
  const dash = '<span class="dim">—</span>';

  const local = (e) => {
    const a = LLDP_ADMIN[e.localLldpAdmin];
    return `<div><code>口号 ${esc(e.portNum)}</code>${e.remIndex > 1 ? `<span class="dim"> 第 ${esc(e.remIndex)} 行</span>` : ''}</div>
      ${e.localPortName ? `<div><b>${esc(e.localPortName)}</b></div>` : ''}
      ${e.portMatchedBy ? `<div class="dim" title="${esc(e.portMatchWhy)}">${esc(LLDP_MATCHED[e.portMatchedBy] || e.portMatchedBy)}</div>` : ''}
      ${a ? `<span class="pill ${a[1]}" title="${esc(e.localLldpAdminMeaning || '')}">${esc(a[0])}</span>` : ''}`;
  };
  // 「对端是谁」这一格是复制进工单的那一行：名字 + 标识 + 标识按什么翻的。
  const who = (e) => {
    const bits = [];
    if (e.sysName) bits.push(`<div><b>${esc(e.sysName)}</b></div>`);
    if (e.chassisId) {
      bits.push(`<div><code title="${esc(e.chassisIdWhy || '')}">${esc(e.chassisId)}</code></div>`);
    }
    if (e.chassisIdType) bits.push(`<div class="dim">${esc(e.chassisIdType)}</div>`);
    if (!e.sysName && !e.chassisId) bits.push(dash);
    if (e.gone) bits.push('<span class="pill bad">第二遍不见了</span>');
    if (e.newNeighbor) bits.push('<span class="pill warn">这一趟新出现的</span>');
    if (e.missingColumns) {
      // 整句掐到 24 个字会切成「lldpRemPortId / …」这种半截话 —— 按「、」一条一条数，
      // 只展示第一条 + 一共缺几栏，全文留给鼠标提示。
      const list = (e.missingColumns.split('：')[1] || '').split(' —— ')[0];
      const cols = list ? list.split('、').filter(Boolean) : [];
      bits.push(cols.length
        ? `<div class="dim" title="${esc(e.missingColumns)}">缺栏：${esc(cols[0])}${cols.length > 1 ? ` 等 ${cols.length} 栏` : ''}</div>`
        : `<div class="dim" title="${esc(e.missingColumns)}">缺栏：${esc(list || '这一行的栏没列出来')}</div>`);
    }
    return bits.join('');
  };
  const rport = (e) => {
    const bits = [];
    if (e.remotePortId) bits.push(`<div><code title="${esc(e.remotePortIdWhy || '')}">${esc(e.remotePortId)}</code></div>`);
    if (e.remotePortIdType) bits.push(`<div class="dim">${esc(e.remotePortIdType)}</div>`);
    if (e.remotePortDesc) bits.push(`<div class="dim" title="${esc(e.remotePortDesc)}">${esc(e.remotePortDesc)}</div>`);
    return bits.join('') || dash;
  };
  const caps = (e) => {
    const bits = [];
    if (e.capabilities) bits.push(`<div>${esc([].concat(e.capabilities).join('、'))}</div>`);
    if (e.capabilitiesEnabled) {
      bits.push(`<div class="dim" title="enabled 是另一张位图，界面上「对端是什么」按这一张认">已启用：${esc([].concat(e.capabilitiesEnabled).join('、'))}</div>`);
    } else if (e.capabilities) {
      bits.push('<div class="dim">enabled 没给，只按 supported 说</div>');
    }
    if (e.capabilityNote) bits.push(`<div class="dim" title="${esc(e.capabilityNote)}">${esc(e.capabilityNote.replace(/^★\s*/, ''))}</div>`);
    return bits.join('') || dash;
  };
  const fresh = (e) => {
    const bits = [];
    if (e.lastUpdate) {
      const old = e.lastUpdateSeconds > 600;
      bits.push(old
        ? `<span class="pill warn" title="比 LLDP 一般的存活时间老得多：这台只是把第一次听到的东西留着没清">${esc(e.lastUpdate)}前刷新</span>`
        : `<div>${esc(e.lastUpdate)}前刷新</div>`);
    } else if (e.lastUpdateWhy) {
      bits.push(`<div class="dim" title="${esc(e.lastUpdateWhy)}">算不出多久以前</div>`);
    }
    if (e.ageoutsDelta) bits.push(`<span class="pill bad">这一段老化 ${esc(e.ageoutsDelta)} 次</span>`);
    else if (e.ageoutsTotal !== undefined) bits.push(`<div class="dim" title="从开机攒到现在的次数，单看一个数说明不了任何事">累计老化 ${esc(e.ageoutsTotal)}</div>`);
    return bits.join('') || dash;
  };

  return `<table>
    <tr><th style="width:150px">这台这个口</th><th style="width:200px">对端是谁</th>
      <th style="width:160px">对端的口</th><th style="width:150px">它自称</th>
      ${withMgmt ? '<th style="width:150px">它留的管理地址</th>' : ''}
      ${withAge ? '<th style="width:130px">多久没刷新 / 老化</th>' : ''}</tr>
    ${es.map((e) => `<tr>
      <td>${local(e)}</td>
      <td>${who(e)}</td>
      <td>${rport(e)}</td>
      <td>${caps(e)}</td>
      ${withMgmt ? `<td>${e.mgmtAddresses
        ? [].concat(e.mgmtAddresses).map((a) => `<div><code>${esc(a)}</code></div>`).join('') : dash}</td>` : ''}
      ${withAge ? `<td>${fresh(e)}</td>` : ''}</tr>`).join('')}
  </table>`;
}

function lldpStatsHTML(s) {
  if (!s) return '';
  if (s.note && !s.tableInserts && !s.tableDeletes && !s.tableDrops && !s.tableAgeouts
    && !s.ageoutPorts && !s.rxErrorPorts) {
    return `<p class="hint">${esc(s.note)}</p>`;
  }
  const item = (label, v, why) => (v === undefined ? ''
    : `<div><label>${esc(label)}</label><div><b>${esc(v)}</b>${
      why ? `<span class="dim">（${esc(why)}）</span>` : ''}</div></div>`);
  return `<div class="row" style="align-items:flex-end;gap:18px">
    ${item('插入过几条', s.tableInserts)}
    ${item('被清掉几条', s.tableDeletes)}
    ${item('表满丢掉几条', s.tableDrops)}
    ${item('自然老化几条', s.tableAgeouts)}
    ${item('老过化的口', s.ageoutPorts && [].concat(s.ageoutPorts).join('、'))}
    ${item('收包出错的口', s.rxErrorPorts && [].concat(s.rxErrorPorts).join('、'))}
  </div><p class="hint" style="margin:6px 0 0">★ 这几个数是从设备<b>开机攒到现在</b>的，
    单看一个数说明不了任何事 —— 要看「这一段涨没涨」，把上面「读两遍之间等几秒」填一个数再问一次。</p>`;
}

function snmpLldpCard() {
  const card = $(`<div class="card">
    <h2>这根线另一头是谁（LLDP 邻居） <span id="llstat"></span></h2>
    <p class="hint">读一台设备的 LLDP 邻居：<b>哪一个口上听见了对端哪台设备、它在对端的哪个口、
      对端自称是什么、它留下的管理地址</b>，外加每个口的 LLDP 开关和邻居老化次数。
      ★ 这一棵树里<b>没有 CDP</b>：只发 CDP 的老设备、打印机、摄像头在这里就是不存在，
      「读不到邻居」不等于「线上没东西」。先跑最上面那张「SNMP 通不通」。</p>
    ${snmpFormHTML('ll')}
    <div class="row" style="margin-top:10px">
      <div style="flex:0 0 120px"><label>LLDP 口号</label><input id="llport" placeholder="lldpRemLocalPortNum"></div>
      <div style="flex:0 0 120px"><label>ifIndex</label><input id="lridx" placeholder="按接口号问"></div>
      <div><label>或者在口名里找这几个字</label><input id="llname" placeholder="Gi1/0/5、GE1/0/5…"></div>
      <div style="flex:0 0 150px"><label>读两遍之间等几秒</label><input id="llwatch" placeholder="0 = 只读一遍"></div>
    </div>
    <details style="margin-top:10px"><summary class="dim">最多列几行 / 不读统计计数器（一般不用动）</summary>
      <div class="row" style="margin-top:8px">
        <div style="flex:0 0 150px"><label>最多列几行</label><input id="lllimit" placeholder="512"></div>
        <div style="flex:0 0 auto;min-width:0;padding-top:18px">
          <label style="display:flex;align-items:center;gap:6px;font-weight:400">
            <input type="checkbox" id="llnostats" style="width:auto"> 不读那几个统计计数器</label></div>
      </div>
      <p class="hint">★ 不读计数器就看不出「邻居在老化」这一条（邻居本身照读）。
        撞到限量的那一次不会给「其余口都还好」这种结论。</p>
    </details>
    <p class="hint" style="margin-top:8px">★ <b>LLDP 口号既不是面板上的第几口、也不等于 ifIndex</b>：
      MIB 规定桥设备按 dot1dBasePort 编号。填 ifIndex 时结果里每一行都会写明这一条是怎么对上的
      —— 设备的映射（可以当准）、还是「编号正好相等」猜的（要核）；几条路指着不同口号时全列出来，不挑一个。</p>
    <div style="margin-top:12px"><button class="btn primary" id="llgo">读 LLDP 邻居</button></div>
    <div id="llout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#llout');
  const top = card.querySelector('#llstat');
  card.querySelector('#llgo').onclick = async () => {
    top.innerHTML = '';
    const args = readSnmpArgs(card, 'll');
    const num = (id) => Number(card.querySelector(id).value);
    const port = num('#llport');
    const idx = num('#lridx');
    const name = card.querySelector('#llname').value.trim();
    const watch = num('#llwatch');
    const limit = num('#lllimit');
    if (port > 0) args.portNum = port;
    if (idx > 0) args.ifIndex = idx;
    if (name) args.name = name;
    if (watch > 0) args.watchSeconds = watch;
    if (limit > 0) args.limit = limit;
    args.noStats = card.querySelector('#llnostats').checked;
    out.innerHTML = `<div class="empty">正在问…${watch > 0
      ? `（读了两遍，中间等了 ${esc(watch)} 秒）`
      : '整棵邻居子树都要走一遍，口多时要等一会儿'}</div>`;
    const r = await call('net.snmp.lldp', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">问不了：${esc(r.message)}</div>`; return; }
    const v = r.values;
    const rows = [].concat(v.neighbors || []);
    const base = SNMP_LLDP_CODE[r.verdict] || SNMP_CODE[r.verdict] || [r.verdict, '', ''];
    const [text, cls, advice] = base;
    // 共用那句「下面几栏都可以问了」是设备体检那张卡的口径；在这张卡上邻居已经列出来了，
    // 再说一遍等于走错了门，所以这一条换成说眼前这张表。
    const say = r.verdict === 'snmp-ok'
      ? '这台设备认这个团体名，路也是通的。上面这些邻居行就是它直接答的。' : advice;
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const extra = [v.detail, v.answeredEarlier, v.portMapping, v.name,
      v.queriedPorts ? `别的口上有邻居：口号 ${[].concat(v.queriedPorts).join('、')}` : '',
      v.sampleUnsure, v.sampleAborted,
      v.truncated ? `撞上限量 ${v.readLimit}，这张表没读全` : ''].filter(Boolean).join('；');
    const local = v.local || {};
    const localLine = Object.keys(local).length ? `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
        <div><label>这台自称</label><div><b>${esc(local.sysName || '')}</b>
          ${local.chassisId ? `<span class="dim" title="${esc(local.chassisIdType || '')}"><code>${esc(local.chassisId)}</code></span>` : ''}</div></div>
        ${local.capabilities ? `<div><label>它说自己会这些</label><div>${esc([].concat(local.capabilities).join('、'))}
          ${local.capabilitiesEnabled ? `<span class="dim">已启用：${esc([].concat(local.capabilitiesEnabled).join('、'))}</span>` : ''}</div></div>` : ''}
        ${local.sysDesc ? `<div><label>设备说明</label><div class="dim" title="${esc(local.sysDesc)}">${esc(String(local.sysDesc).slice(0, 60))}${String(local.sysDesc).length > 60 ? '…' : ''}</div></div>` : ''}
      </div>${local.capabilityNote ? `<p class="hint">${esc(local.capabilityNote)}</p>` : ''}` : '';
    const counts = v.portAdminCounts
      ? `<div><label>这台的 LLDP 开关</label><div>${Object.entries(v.portAdminCounts)
        .map(([k, n]) => `${esc(LLDP_ADMIN_LABEL[k] || k)} <b>${esc(n)}</b>`)
        .join(' · ')}<span class="dim">（按口数的，只发了一遍开关表）</span></div></div>` : '';
    const statsRow = v.read === undefined ? '' : `
      <div class="row" style="align-items:flex-end;gap:18px;margin-bottom:10px">
        <div><label>读回几条</label><div><b>${esc(v.read)}</b> 行邻居
          ${v.count !== undefined && v.count !== v.read
            ? `<span class="dim">这一趟列出 <b>${esc(v.count)}</b> 行</span>` : ''}
          ${v.truncated ? `<span class="pill warn">撞上限量 ${esc(v.readLimit)}</span>` : ''}
          ${v.countTotal === undefined ? '' : `<span class="dim">表里一共 ${esc(v.countTotal)} 行</span>`}</div></div>
        ${v.ports === undefined ? '' : `<div><label>涉及几个口</label><div><b>${esc(v.ports)}</b>
          ${v.multiNeighborPorts ? `<span class="pill warn">${esc(v.multiNeighborPorts)} 个口上不止一个邻居</span>` : ''}</div></div>`}
        ${counts}
        ${v.uptimeSeconds !== undefined ? `<div><label>这台开了</label><div class="dim">${esc(v.uptime || v.uptimeSeconds + ' 秒')}</div></div>` : ''}
        ${v.sampleSeconds !== undefined ? `<div><label>测了多久</label><div>${esc(v.sampleSeconds)} 秒</div></div>` : ''}
      </div>`;
    out.innerHTML = `
      ${snmpHead(v)}
      ${localLine}
      ${statsRow}
      ${v.portMappingAmbiguous ? `<p class="hint">★ 这一条是靠猜对上的：两条路指着不同的口号，候选的口都问了 —— 别把它们当成同一根线。</p>` : ''}
      ${v.rebooted ? `<p class="hint">★ 这台设备在两次读之间重启过（sysUpTime 倒退），计数器被清零了，
        所以这一趟<b>没有增量</b> —— 只按两遍的行数比了邻居。</p>` : ''}
      ${v.newNeighborRows ? `<p class="hint">★ 这一趟之间多出 ${esc(v.newNeighborRows)} 行邻居（只有第二遍才读到）——
        下面标着「这一趟新出现的」那几行就是它。</p>` : ''}
      <h2 style="margin-top:16px">邻居</h2>
      ${rows.length ? lldpRowsHTML(rows) : `<div class="empty">这一趟一条邻居都没列出来。
        ${v.queriedPorts ? `但别的口上有：口号 ${esc([].concat(v.queriedPorts).join('、'))}` : ''}</div>`}
      ${v.agingPorts ? `<p class="hint" style="margin:8px 0 0">老过化的口：${esc([].concat(v.agingPorts).join('、'))}
        <span class="dim">—— 这一条说的是「邻居会消失」，不是「没有邻居」</span></p>` : ''}
      ${v.stats ? `<div style="margin-top:14px"><h2>邻居表统计</h2>${lldpStatsHTML(v.stats)}</div>` : ''}
      <div style="margin-top:12px">${snmpAdviceBox(cls, say, extra)}</div>
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

async function renderSwitch(root) {
  root.appendChild(snmpProbeCard());
  root.appendChild(snmpMacCard());
  root.appendChild(snmpPortsCard());
  root.appendChild(snmpPoeCard());
  root.appendChild(snmpLldpCard());
}

async function renderScan(root) {
  root.appendChild(subnetScanCard());
  root.appendChild(neighborsCard());
}

// ── 设备是谁 / 摄像头取流 ──
//
// ★ 「视频流」原来自己占一页，孤零零一张卡，看着像给视频软件开的后门。
//   它答的其实是「这个取流地址上到底有没有一路流、以什么规格在播」——
//   问的是现场那台摄像头，所以和识别设备、听广播归在一组（「谁在网里」）。
// ★ 一组里最多四页、一页里最多五张：取流这一叠（ONVIF / RTSP / HLS，
//   后面还有 RTMP 与 GB28181）已经自成一路问题，硬并回「设备是谁」
//   就是第六张卡 —— 那张卡一放，这一页又滚到底找不着北了。

async function renderDevice(root) {
  root.appendChild(deviceIdentifyCard());
  root.appendChild(discoverCard());
  root.appendChild(wolCard());
}

// 三张卡是一条流水线，不是三个并列的工具：
// 只有设备 IP → ONVIF 问出取流地址 → RTSP 验这路流到没到本机 → HLS 问平台那份清单还写着什么。
async function renderStream(root) {
  root.appendChild(onvifCard());
  root.appendChild(rtspCard());
  root.appendChild(hlsCard());
}

// ONVIF 这一张排在「取流探测」前面，不是随手放的：
// ★ 现场手里往往只有这台设备的 IP，取流地址恰恰是要问出来的那一个。
//   ONVIF 把「有几路流、每路什么规格、第一路的 rtsp:// 地址」答得出来，
//   答完直接抄进下面那张卡去验流 —— 「没画面」的排查因此从问出地址开始，不是从猜地址开始。
function onvifCard() {
  const card = $(`<div class="card">
    <h2>问一台 ONVIF 设备 <span id="ov-top"></span></h2>
    <p class="hint">向设备发几问<b>只读</b>的 SOAP：它是谁、它自己说现在几点、服务挂在哪儿、
      有几路码流、第一路的取流地址是多少。<b>不改它任何配置。</b>
      ★ 哪一问没问出去会单独占一行，不会糊成「问了，一切正常」。密码只进请求，不进结果。</p>
    <div class="row">
      <div><label>服务地址（只填 IP 也行，默认 80 端口与设备服务路径）</label>
        <input id="ov-u" placeholder="192.168.1.64 或 http://192.168.1.64:8899/onvif/device_service"></div>
      <div style="flex:0 0 170px"><label>ONVIF 账号</label>
        <input id="ov-a" placeholder="多数相机匿名只回 Fault"></div>
      <div style="flex:0 0 170px"><label>密码</label>
        <input id="ov-w" type="password" autocomplete="new-password"></div>
    </div>
    <div style="margin-top:12px"><button class="btn primary" id="ov-b">问一遍</button></div>
    <div id="ov-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#ov-out');
  const top = card.querySelector('#ov-top');
  card.querySelector('#ov-b').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">正在问…（几问是排着队发的，设备慢或者第一问就要账号时会多等几秒）</div>';
    const args = {};
    const put = (id, key) => { const s = card.querySelector(id).value.trim(); if (s) args[key] = s; };
    put('#ov-u', 'url'); put('#ov-a', 'username'); put('#ov-w', 'password');
    const r = await call('media.onvif.info', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">问不了：${esc(r.message || r.error)}</div>`; return; }
    const v = r.values || {};
    const [title, cls, advice] = ONVIF_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;

    const led = (v.steps || []).map((s) => {
      const st = ONVIF_STEP[s.state] || [s.state || '—', 'bad', ''];
      return `<tr><td>${esc(s.step || '')}</td>`
        + `<td><span class="pill ${st[1]}">${esc(st[0])}</span></td>`
        + `<td>${s.note ? esc(s.note) : '<span class="dim">它照答了</span>'}</td></tr>`;
    }).join('');

    const ps = v.profiles || [];
    const streamRows = ps.length
      ? `<tr><th>码流名</th><th>token（问地址用它）</th><th>编码</th><th>分辨率</th><th>帧率</th><th>上限码率</th><th>音频</th></tr>`
        + ps.map((p) => `<tr><td>${esc(p.name || '—')}</td><td><code>${esc(p.token || '')}</code></td>`
          + `<td>${esc(p.codec || '—')}</td>`
          + `<td>${p.width ? `${p.width}×${p.height}` : '<span class="dim">没报</span>'}</td>`
          + `<td>${esc(p.framerate || '—')}</td>`
          + `<td>${p.bitrateKbps ? esc(p.bitrateKbps) + ' kbps' : '—'}</td>`
          + `<td>${esc(p.audio || '没有')}</td></tr>`).join('')
      : '';

    // 时间那一格答的是「它自己说几点、它靠什么对时」。偏移照给，但注明是相对本机 ——
    // 拿本机那把尺去论设备的对错，本机自己歪的时候就把它的准算成了错。
    const off = typeof v.offsetMsVsLocal === 'number'
      ? `<b>${esc(humanMs(v.offsetMsVsLocal))}</b> <span class="dim">它比本机${v.offsetMsVsLocal > 0 ? '快' : '慢'}（相对本机；本机准不准归「校时检查」判）</span>`
      : '<span class="dim">没换算成偏差 —— 它只报了本地时间，或者这一问没问出去。<b>只给本地时间就不换算</b>：时区一差几小时，会凭空造出一个「它时间不对」。</span>';
    const ntp = (v.ntpServers || []).join(' 、') || (v.ntpFromDHCP ? '由 DHCP 下发' : '');

    // ★ 有内容才现身：第一问就被挡下时，「它是谁 / 几点 / 几路流」四张空表
    //   会把真正那一条信息（问话记录）挤到屏幕外，还看着像「查过了，都没查到」。
    const step = (name) => (v.steps || []).find((x) => x.step === name);
    // 只有「这一问真的问出去了、它答了没有码流」才说它没配 —— 第一问就断掉时
    // 这一问根本没发生，说成「它说没有码流」就是替设备编了一句它没说过的话。
    const mediaAsked = step('问它有几路码流') && step('问它有几路码流').state === 'asked';
    const hasWho = v.manufacturer || v.model || v.firmwareVersion || v.serialNumber || v.hardwareId || v.mediaService;
    const hasClock = v.deviceTime || v.deviceTimeType || typeof v.offsetMsVsLocal === 'number'
      || (v.ntpServers || []).length || v.ntpFromDHCP;
    const secs = [];
    if (v.mediaUri) {
      secs.push(`<h2 style="margin-top:16px">它报的取流地址</h2>
        <table>${tCell('拿这个去验流', `<code>${esc(v.mediaUri)}</code>`)}</table>`);
    }
    if (ps.length) {
      secs.push(`<h2 style="margin-top:16px">它报的码流</h2><table>${streamRows}</table>`);
    } else if (mediaAsked) {
      secs.push(`<h2 style="margin-top:16px">它报的码流</h2>
        <div class="empty">媒体服务答得清清楚楚：这台上一条码流都没配。几路流、什么规格，都得先在设备那侧把码流配出来。</div>`);
    }
    if (hasWho) {
      secs.push(`<h2 style="margin-top:16px">它是谁</h2>
        <table>
          ${tCell('厂商 / 型号', `${esc(v.manufacturer || '它没说')} ${v.model ? '· ' + esc(v.model) : ''}`)}
          ${tCell('固件 / 硬件', `${esc(v.firmwareVersion || '—')}${v.hardwareId ? ' · ' + esc(v.hardwareId) : ''}`)}
          ${tCell('序列号', v.serialNumber ? `<code>${esc(v.serialNumber)}</code>` : '<span class="dim">它没说</span>')}
          ${v.mediaService ? tCell('媒体服务挂在', `<code>${esc(v.mediaService)}</code> <span class="dim">（它自报的路径与端口，主机仍钉在这台）</span>`) : ''}
        </table>`);
    }
    if (hasClock) {
      secs.push(`<h2 style="margin-top:16px">它说现在几点</h2>
        <table>
          ${tCell('它的时刻', v.deviceTime ? `<code>${esc(v.deviceTime)}</code>` : '<span class="dim">这一问没答</span>')}
          ${tCell('和差多少', off)}
          ${tCell('靠什么对时', `${esc(v.deviceTimeType || '它没说')}${v.deviceTimezone ? ' · 时区 ' + esc(v.deviceTimezone) : ''}${v.daylightSavings === true ? ' · 开了夏令时' : ''}`)}
          ${ntp ? tCell('它的时间源', `<code>${esc(ntp)}</code>`) : ''}
        </table>`);
    }
    secs.push(`<h2 style="margin-top:16px">问话记录</h2>
      <table><tr><th>问了什么</th><th>状态</th><th>为什么</th></tr>${led}</table>`);
    out.innerHTML = `${advice ? adviceBox(cls, esc(advice)) : ''}
      ${r.note ? `<p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>` : ''}${secs.join('')}`;
  };
  return card;
}

const ONVIF_STEP = {
  'asked': ['问出去了', 'ok', ''],
  'not-asked': ['没问出去', 'bad',
    '这一步的结论不算它的读数 —— 连问都没问到，就不能说这一项没问题。'],
};

const ONVIF_CODE = {
  'onvif-ok': ['身份与码流都问到了', 'ok',
    '★ 上面那个取流地址直接抄进下面「取流探测」验流。码流表里有几个 token 就是几条流 —— '
    + '主码流 / 子码流是两条不同的 profile，对一下分辨率是不是你要的那一路，再对上下游平台期望的那一路。'],
  'onvif-no-profile': ['它说一条码流都没配', 'bad',
    '★ 媒体服务答得出来、也明确说了没有流 —— 这就不是链路的问题了。去设备自己的通道 / 码流配置看有没有启用'
    + '（多数相机加完通道只开主码流，子码流默认是关的），配好再问一次。'],
  'onvif-partial': ['身份问到了，媒体那一路问不出', 'warn',
    '★ 设备确实是 ONVIF，只是媒体服务没答（那个端口不通、不认这一问、或者这台没实现媒体服务）。'
    + '下面「问话记录」写了是哪一问、为什么。这一段问不出地址，取流地址先回设备网页后台或厂商工具里抄。'],
  'auth-required': ['要账号，或者这个账号被挡', 'warn',
    '★ 先分清是哪一种：账号没填 = 它在要；填了还被挡 = 这个账号不够格。'
    + '很多相机把 ONVIF 账号和 Web 登录账号分开管 —— 要在它自己的用户列表里另加一个，并勾上媒体权限。'
    + '拿「网页能登录」去推「ONVIF 也该能用」，就会一直卡在这一格。'],
  'onvif-fault': ['它回了 Fault，是不接这一问', 'bad',
    '★ Fault 是「问到了、但不这么答」，不是密码不对，别去翻密码。'
    + '看问话记录里那句原因：Action not supported 这类是这台固件没实现这个操作，'
    + '去对一下它的 ONVIF Profile 支持范围（S 只给取流，T 才给云台那一套）。'],
  'not-onvif': ['这个地址不是 ONVIF 服务', 'bad',
    '★ 连得上、也回了话，回的却是网页或别的协议，所以「没回应」这个说法在这儿是错的。'
    + 'ONVIF 常见在 80，也有 8899 / 2020 / 8080；先进设备网页后台确认 ONVIF 开关是开着的。'
    + '那个端口如果是 TLS，地址前缀要写 https://。'],
  'no-response': ['连上了，一声不响', 'bad',
    '★ 端口活着却不答话：服务卡死，或者它只放行白名单里的 IP 发 ONVIF。'
    + '先看这台的网络服务要不要重启，再确认本机地址在不在它的允许列表里。'],
  'unreachable': ['连不上', 'bad',
    '★ 连不上先别改密码 —— 密码错不会导致连不上。去「ping 与端口」那页确认这个端在不在：'
    + '端口不在 = ONVIF 没开、或者中间隔了路由/防火墙；端口在而这里连不上 = 前缀（http / https）写错了。'],
};

function rtspCard() {
  const card = $(`<div class="card">
    <h2>取流探测 <span id="rt-top"></span></h2>
    <p class="hint">问一个 RTSP 地址「这里有一路流吗」。读的是它的应答（SDP），
      ★ 不解码、不放画面、不装任何播放器 —— 所以它答的是「设备肯不肯给流、给的是什么规格」，
      图像本身好不好看不归它管。</p>
    <div style="display:flex;gap:12px;align-items:flex-end">
      <div style="flex:1"><label>取流地址</label>
        <input id="rt-u" placeholder="rtsp://192.168.1.64:554/cam/realmonitor?channel=1&subtype=0"></div>
      <div style="flex:0 0 160px"><label>实收听多久</label><select id="rt-w">
        <option value="3000">三秒（默认）</option>
        <option value="6000">六秒 —— 起流慢的设备</option>
        <option value="10000">十秒 —— 慢到可疑</option>
        <option value="0">不听，只问参数</option>
      </select></div>
    </div>
    <div style="margin-top:12px"><button class="btn primary" id="rt-b">探测</button></div>
    <div id="rt-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#rt-out');
  const top = card.querySelector('#rt-top');
  card.querySelector('#rt-b').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">探测中…</div>';
    const u = card.querySelector('#rt-u').value.trim();
    const w = Number(card.querySelector('#rt-w').value);
    const r = await call('media.rtsp.probe', { url: u, measureMs: w });
    if (!r.ok) { out.innerHTML = `<div class="empty">问不了：${esc(r.message)}</div>`; return; }
    const [title, cls, advice] = RTSP_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const v = r.values || {};
    const rows = (v.tracks || []).map((t) => `<tr><td>${esc(t.kind || '')}</td>`
      + `<td>${esc(t.codec || '—')}</td>`
      + `<td>${t.width ? `${t.width}×${t.height}${t.fps ? ' @' + t.fps + 'fps' : ''}` : '<span class="dim">没给参数集</span>'}</td></tr>`).join('');
    // 有流时 note 就是那几轨的文字版，表格里已经有了，不再重复一行。
    const note = r.note && r.verdict !== 'stream-ok'
      ? `<p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>` : '';
    out.innerHTML = `<table>
      ${tCell('问的地址', `<code>${esc(v.url || u)}</code>`)}
      ${tCell('连的端', `<code>${esc(v.target || '')}</code>${v.status ? ` · 应答 ${v.status}` : ''}`)}
      ${rows ? `<tr><th>轨</th><th>编码</th><th>规格（分辨率 / 帧率）</th></tr>${rows}` : tCell('轨', '<span class="dim">应答里没有媒体描述</span>')}
    </table>${rtpBlock(v)}${note}${advice ? adviceBox(cls, esc(advice)) : ''}`;
  };
  return card;
}

// 实收那一格和上面那张「规格表」是两问：那张是设备**说**它打算发什么，
// 这一格是这几秒里盒子里**真到了**什么。★ 没量到就只留一句为什么，
// 绝不能拿一个 0 顶上去 —— 「没收到」和「收到 0 码率」是两个不同的下一步。
function rtpBlock(v) {
  const r = v.rtp;
  if (!r) {
    const why = v.measureNote || (v.measured === false ? '这一次没收流' : '');
    // 「换了路子」这一句量没量到都得露：只在有读数时才显示，
    // 就把「UDP 没谈成」那一格悄悄抹掉了，而那正是下一步要看的。
    const switched = v.transportNote ? `<p class="dim" style="margin:6px 0 0">${esc(v.transportNote)}</p>` : '';
    return why ? `<p class="dim" style="margin:10px 0 0">实际收到：${esc(why)}</p>${switched}` : '';
  }
  const has = (x) => x !== undefined && x !== null && x !== 0;
  const loss = has(r.lostPackets)
    ? `${r.lostPackets} 包（${r.lossPercent}%）`
    : (r.lossNote ? `<span class="dim">${esc(r.lossNote)}</span>` : '一个没丢');
  const cells = [
    ['收流走的口子', (v.transport === 'udp' ? 'UDP' : 'TCP 交织') + ` · ${r.measuredMs} 毫秒里到了 ${r.packets} 包`],
    ['实际码率', has(r.bitrateKbps) ? `${r.bitrateKbps} kbps（只按载荷字节算）` : '<span class="dim">窗口太短，没算</span>'],
    ['到达帧率', has(r.receivedFps) ? `${r.receivedFps} fps（数的是 marker 位，一帧的最后一包）` : '<span class="dim">没算</span>'],
    ['丢包', loss],
    ['乱序 / 重复', `${r.reordered || 0} / ${r.duplicates || 0}`],
    ['关键帧', has(r.keyframes) ? `${r.keyframes} 张` + (has(r.keyframeEveryMs) ? ` · 隔 ${r.keyframeEveryMs} 毫秒一张` : '')
      : '<span class="dim">这路编码认不出关键帧，只数了包</span>'],
  ];
  const why = (v.measureNote || r.rateNote || '')
    ? `<p class="dim" style="margin:6px 0 0">${esc(v.measureNote || r.rateNote)}</p>` : '';
  const other = (r.measureNotes || []).map((x) => `<p class="dim" style="margin:6px 0 0">${esc(x)}</p>`).join('');
  const switched = v.transportNote ? `<p class="dim" style="margin:6px 0 0">${esc(v.transportNote)}</p>` : '';
  return `<p class="hint" style="margin:14px 0 4px">实际收到 —— 这一段是量出来的，不是设备说的</p>
    <table>${cells.map(([k, val]) => tCell(k, val)).join('')}</table>${why}${switched}${other}`;
}

const RTSP_CODE = {
  'stream-ok': ['有流', 'ok',
    '★ 设备肯给流，上面这些轨就是它能给的全部规格。接进平台前对一下编码和分辨率是不是要的那路码流——主码流/子码流常常只差路径里的一位数字。'],
  'stream-no-media': ['回了 200，但一轨媒体都没有', 'bad',
    '★ 连上、认证都过了，这条路径上却没配出码流 —— 不是下游的问题。去设备那侧看这个通道有没有启用（很多相机加完通道默认不开子码流），再把路径里的通道号 / 码流类型对一遍。'],
  'stream-no-data': ['它答应给流，可一个包都没来', 'bad',
    '★ 轨是有的、账号是过了、PLAY 也回了 200 —— 前面那几步全都对，唯独码流没到本机。'
    + '先确认这台设备让不让第二路取流（多数型号只开一路，平台正在拉流时它就这么答）；'
    + '再分清是哪一路没通：走 UDP 时收流用的是本机一批临时偶数口，'
    + '隔了 NAT 或防火墙只看已知服务口，包就回不来 —— 换 TCP 交织再问一次，'
    + 'TCP 那一路要能收到，就是那批 UDP 口被挡了，不是设备没发。'],
  'auth-required': ['要账号密码', 'warn',
    '★ 401 不是设备坏了，是问到了、只是不让看。先核对账号密码，再确认这个账号有没有该通道的取流权限（NVR 上不同用户开的通道不一样）。'],
  'not-found': ['这个路径没有流', 'bad',
    '★ 设备是好的、账号是好的，只有路径不对。海康是 /Streaming/Channels/101，大华是 /cam/realmonitor?channel=1&subtype=0，通道号和码流类型就在最后那几位。'],
  'no-response': ['连上了没回应', 'bad',
    '端口开着却不回 RTSP，大概率端口号填错了：554 才是 RTSP，80 是 Web，8000 / 8200 是各家私有 SDK 的口子。也可能是设备只放行了指定 IP。'],
  'unreachable': ['连不上', 'bad',
    '★ 连不上先别改密码。去「ping 与端口」那页探一下这个端在不在：端口在而 RTSP 不通，是服务的问题；端口就不在，先确认地址、网段和中间隔没隔路由。'],
};

// hlsCard 排在「取流探测」后面，顺序就是现场的动作顺序：
// 先问设备要地址（ONVIF）→ 验这路流到没到本机（RTSP）→ 最后问平台那份清单此刻还写着什么（这一张）。
function hlsCard() {
  const card = $(`<div class="card">
    <h2>拉一路 HLS（m3u8） <span id="hl-top"></span></h2>
    <p class="hint">问平台<b>这份清单此刻还在不在往前加片子</b>。★ 它和上面那张「取流探测」问的不是同一件事：
      RTSP 量的是码流到没到本机，这一路中间隔着一层平台 —— 盒子说没画面，
      有一种毛病是清单还在、里面的分片却早就不加了。同样不解码、不放画面、不改任何东西。</p>
    <div style="display:flex;gap:12px;align-items:flex-end">
      <div style="flex:1"><label>清单地址</label>
        <input id="hl-u" placeholder="http://192.168.1.20:80/hls/cam1/index.m3u8"></div>
      <div style="flex:0 0 190px"><label>隔多久再看一次清单</label><select id="hl-w">
        <option value="4000">四秒（默认）</option>
        <option value="8000">八秒 —— 切片周期长的平台</option>
        <option value="15000">十五秒 —— 慢到可疑</option>
        <option value="0">不看，只拉一次（点播）</option>
      </select></div>
      <div style="flex:0 0 130px"><label>抽查几片</label><select id="hl-s">
        <option value="2">两片（默认）</option>
        <option value="3">三片</option>
        <option value="1">只看最新那片</option>
        <option value="0">不取分片</option>
      </select></div>
    </div>
    <details style="margin-top:8px"><summary class="dim">这台要账号（Basic）/ 一次请求的超时</summary>
      <div class="row" style="margin-top:8px">
        <div><label>账号</label><input id="hl-usr" autocomplete="off"></div>
        <div><label>口令</label><input id="hl-pw" type="password" autocomplete="off"></div>
        <div style="flex:0 0 160px"><label>单次超时 ms</label><input id="hl-t" placeholder="5000"></div>
      </div>
      <p class="hint" style="margin-top:6px">地址里已经带了账号（http://user:pass@host/…）就别填这两个，
        ★ 口令只进请求头，不进结果、不进日志。</p>
    </details>
    <div style="margin-top:12px"><button class="btn primary" id="hl-b">拉一遍</button></div>
    <div id="hl-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#hl-out');
  const top = card.querySelector('#hl-top');
  card.querySelector('#hl-b').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = '<div class="empty">正在拉清单…（隔几秒再拉一次对照，稍等）</div>';
    const args = { url: card.querySelector('#hl-u').value.trim() };
    const w = Number(card.querySelector('#hl-w').value);
    const s = Number(card.querySelector('#hl-s').value);
    args.watchMs = w;
    args.sampleSegments = s;
    const usr = card.querySelector('#hl-usr').value.trim();
    const pw = card.querySelector('#hl-pw').value;
    if (usr) args.username = usr;
    if (pw) args.password = pw;
    const t = Number(card.querySelector('#hl-t').value);
    if (t) args.timeoutMs = t;
    const r = await call('media.hls.probe', args);
    if (!r.ok) { out.innerHTML = `<div class="empty">问不了：${esc(r.message)}</div>`; return; }
    const d = hlsDisplay(r);
    top.innerHTML = `<span class="pill ${d.cls}">${esc(d.title)}</span>`;
    out.innerHTML = hlsResult(r);
  };
  return card;
}

// hlsDisplay 把「判定码」和「这一次真的问了什么」合成界面要说的那一句。
//
// ★ 顶部那颗胶囊和结果表必须走同一个口径：`hls-ok` 那句「这一路是活的」里含着
//   分片取得到、窗口在往前加两件事 —— 抽查填 0 就一片没碰，观看窗口填 0 就没看第二遍，
//   这时候照码说绿话，等于把我们没问的两格算成没毛病。和后端那句账同一条线（见 hlsOKNote）。
function hlsDisplay(r) {
  const v = r.values || {};
  const raw = HLS_CODE[r.verdict] || [r.verdict, '', ''];
  if (r.verdict !== 'hls-ok') return { title: raw[0], cls: raw[1], advice: raw[2] };
  if (v.isLive === false) {
    return {
      title: '录完的这一段读得到', cls: 'ok',
      advice: '★ 清单末尾写着这一段录完了，所以「窗口在不在往前加」本来就不适用 —— 这一句说的是'
        + '分片取得到、清单点得出的东西都在。播放不到去查别的：清单里的地址、签名有没有过期、播放器那一头。',
    };
  }
  const sawSeg = (v.sampled || []).length > 0;
  const sawWindow = v.windowAdvanced !== undefined;
  if (sawSeg && sawWindow) return { title: raw[0], cls: raw[1], advice: raw[2] };
  const missing = [];
  const tips = [];
  if (!sawSeg) {
    missing.push('一片分片都没取过');
    tips.push('把「抽查几片」换成两片再问一次');
  }
  if (!sawWindow) {
    missing.push('没看第二遍，说不了它在不在往前加');
    tips.push('把「隔多久再看一次清单」换成四秒再问一次');
  }
  return {
    title: '清单读得到，但' + missing.join('、'),
    cls: '',
    advice: '★ 这一句只验到「清单此刻读得到」，上面没说的两格还算没排除：'
      + tips.join('、') + '。',
  };
}

// hlsResult 把一次探测摊开。★ 每一格都留了「为什么没有这一格」的位置：
// 空着和填了 0 是两种结论（没去看窗口 ≠ 看了没动，没取分片 ≠ 分片取不到）。
function hlsResult(r) {
  const v = r.values || {};
  const { cls, advice } = hlsDisplay(r);
  const dim = (x) => `<span class="dim">${x}</span>`;
  const cells = [tCell('问的地址', `<code>${esc(v.url || '')}</code>`
    + (v.finalURL ? ` · ${dim('最后落在')} <code>${esc(v.finalURL)}</code>` : ''))];
  // ★ closed（主机在、这个口没服务）与 filtered（一句都不答）是下一步走两条路的分界，
  //   它连着不上时根本没有状态码 —— 那一格不能跟着状态码一起消失。
  const said = [];
  if (v.httpStatus) said.push(`HTTP ${esc(v.httpStatus)}`);
  if (v.contentType) said.push(esc(v.contentType));
  if (v.looksLike) said.push(dim(`内容看着像 ${esc(v.looksLike)}`));
  if (v.reach) said.push(dim(v.reach === 'closed' ? '端口明确拒绝（主机在，这个口没服务）' : '没有任何回应'));
  if (said.length) cells.push(tCell('它回的', said.join(' · ')));
  if (v.master) {
    const rows = (v.variants || []).map((x) => `<tr><td><code>${esc(x.uri || '')}</code></td>`
      + `<td>${x.bandwidth ? esc((x.bandwidth / 1000).toFixed(0)) + ' kbps' : '—'}</td>`
      + `<td>${esc(x.resolution || '—')}</td><td>${esc(x.codecs || '—')}</td></tr>`).join('');
    cells.push(tCell('这是一份主清单', `里面列了 ${(v.variants || []).length} 路，★ 下面问的是带宽最高的那一路`
      + `<table><tr><th>地址</th><th>带宽</th><th>分辨率</th><th>编码</th></tr>${rows}</table>`
      + (v.variant ? `<div>替你看的是 <code>${esc(v.variant)}</code>${v.variantResolution ? ' · ' + esc(v.variantResolution) : ''}</div>` : '')));
  }
  const kind = v.isLive === undefined ? '' : (v.isLive ? '直播（还在往前加）' : '点播（这一段录完了）');
  if (kind) {
    cells.push(tCell('这份清单', [
      kind,
      `${v.segmentCount ?? 0} 片`,
      v.windowSec ? `窗口共 ${esc(v.windowSec)} 秒` : dim('一片都没有，谈不上窗口'),
      v.mediaSequence ? `序号从 ${esc(v.mediaSequence)} 起` : '',
      v.targetDurationSec ? `写着每片最长 ${esc(v.targetDurationSec)} 秒` : dim('没写每片最长'),
      v.hasInitSegment ? '带初始化段（fMP4 切的）' : '',
      v.discontinuities ? dim(`中间有 ${esc(v.discontinuities)} 处时间戳断点`) : '',
    ].filter(Boolean).join(' · ')));
  }
  if (v.longestSegmentSec) {
    cells.push(tCell('最长的那一片', `${esc(v.longestSegmentSec)} 秒 —— 比清单承诺的长，播放器会在这里缓冲`));
  }
  const sampled = (v.sampled || []).map((x) => {
    // ★ 先读 error 再读状态码：回 200/206 而正文是空的，那一条的毛病写在 error 里，
    //   按状态码显示就成了「回 HTTP 206」—— 数字很好看，毛病却被盖住。
    const got = x.ok ? `${(x.bytes || 0).toLocaleString()} 字节 · ${x.elapsedMs ?? 0} 毫秒`
      : (x.error ? esc(x.error)
        : (x.httpStatus ? `回 HTTP ${esc(x.httpStatus)}` : '没取到'));
    return `<tr><td>${x.initSegment ? '初始化段' : ('第 ' + (x.seq ?? '?') + ' 片')}</td>`
      + `<td>${x.durationSec ? esc(x.durationSec) + ' 秒' : '—'}</td>`
      + `<td>${got}${x.truncated ? dim('（读满上限，没读完）') : ''}${x.byteRange ? dim(' · 段 ' + esc(x.byteRange)) : ''}</td>`
      + `<td><code>${esc(x.uri || '')}</code></td></tr>`;
  }).join('');
  if (sampled) {
    cells.push(tCell('抽查的分片',
      `<table><tr><th>哪一片</th><th>标称时长</th><th>取回的</th><th>地址</th></tr>${sampled}</table>`));
  }
  if (v.missingSegment) {
    cells.push(tCell('取不到的是哪一片', `<code>${esc(v.missingSegment)}</code>`
      + ` ${dim('它回的是什么，写在上面「抽查的分片」那一格里')}`));
  }
  if (v.bitrateKbps) {
    cells.push(tCell('实际码率', `${esc(v.bitrateKbps)} kbps · ${dim(esc(v.bitrateBasis || ''))}`
      + (v.bitrateSkipped ? `<br>${dim(esc(v.bitrateSkipped))}` : '')));
  } else if (v.sampled) {
    cells.push(tCell('实际码率', dim('没算 —— 抽查的片没一片是「整片读完」的')));
  }
  if (v.windowAdvanced !== undefined) {
    cells.push(tCell('窗口挪了没有', (v.windowAdvanced
      ? `<b>挪了</b> · 等了 ${esc(v.watchedMs ?? 0)} 毫秒`
      : `<b>一片没换</b> · 等了 ${esc(v.watchedMs ?? 0)} 毫秒`)
      + (v.stuckOn ? ` · 一直停在 <code>${esc(v.stuckOn)}</code>` : '')
      + (v.lastSegmentNow ? ` · 此刻最后一片是 <code>${esc(v.lastSegmentNow)}</code>` : '')));
  } else if (v.isLive) {
    cells.push(tCell('窗口挪了没有', dim('这一次没看（只拉了一次清单，说不了卡不卡）')));
  }
  if ((v.unknownTags || []).length) {
    cells.push(tCell('认不出的标签', dim(`只留了名字，值没抄：${(v.unknownTags || []).map(esc).join('、')}`)));
  }
  if (typeof v.detail === 'string' && v.detail) cells.push(tCell('原文那一错', dim(esc(v.detail))));
  // 判定本身是好的时候，note 就是那一格读数的复述，不再单占一行。
  const note = r.note && r.verdict !== 'hls-ok'
    ? `<p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>` : '';
  return `<table>${cells.join('')}</table>${note}`
    + (advice ? adviceBox(cls, esc(advice)) : '')
    + `<details style="margin-top:10px"><summary class="dim">原始结果</summary>`
    + `<pre>${esc(JSON.stringify(r.raw || v, null, 2))}</pre></details>`;
}

const HLS_CODE = {
  'hls-ok': ['这一路是活的', 'ok',
    '★ 清单拉得到、抽查的分片取回、窗口还在往前加 —— 平台这一头是好的。画面上还是没东西，'
    + '那就不是源的问题：查播放器到平台之间那一段（它拉的地址是不是这一路、域名解析到哪、账号是谁的）。'],
  'hls-stalled': ['清单还在，可窗口一片没换', 'bad',
    '★ 这是这一路最值钱的一档：地址对、不报错、清单也还写着 —— 唯独不再往前加分片。'
    + '说明推流那一早就不推了，而平台没把这路下线。去找推流端（设备、编码器、推流服务）看它还活不活，'
    + '别在重启平台上绕圈 —— 重启完它还是拿到一份不动的清单。'],
  'hls-segment-missing': ['清单点出来的分片取不到', 'bad',
    '★ 清单和分片对不上号：多半是平台删得比写得快（窗口给播放器留得太短），或者源站和平台之间换了机器。'
    + '分清回的是 404 还是没回话：404 是对不上号，没回话是分片还在写或者那条路被挡了。'],
  'hls-empty-playlist': ['清单是空的', 'bad',
    '★ 里面一片都没有 —— 这一路此刻根本没在推（刚点开播，或者已经掉线）。先确认推流端起来了再问一次；'
    + '如果它一直空着而平台显示「在线」，那是平台的通道状态是假的，不是网络的问题。'],
  'hls-target-over': ['分片比清单承诺的长', 'warn',
    '★ 能播，但播放器会反复缓冲：清单写着每片最长几秒，实际有一片明显超过。'
    + '多半是码率突然冲高，或者编码器的 GOP 比切片周期还长 —— 改切片周期或码率上限，不是改网络。'],
  'hls-auth-required': ['要账号', 'warn',
    '★ 401、403 不是坏了，是问到了、只是不给。注意清单和分片可能用两套凭据（分片走签名地址的那种更常见）：'
    + '先把这份地址原样丢进浏览器看能不能下下来，再核对账号对这条通道有没有权限。'],
  'hls-not-found': ['这个路径上没有清单', 'bad',
    '★ 十有八九是流名写错。各平台是 /hls/流名/index.m3u8、/流名.m3u8、/live/流名/playlist.m3u8 这几套写法，'
    + '回平台把这条通道的播放地址原样抄一遍，别手敲。'],
  'hls-not-hls': ['回的不是清单', 'bad',
    '★ 它答话了，答的不是 HLS：可能是设备自己的网页、一段裸流（FLV、MP4），或者这个口上说的压根不是 HTTP。'
    + '结果里「内容看着像」那一格写了头几个字节认出的形状。RTSP、RTMP 那两路用上面几张卡去问。'],
  'hls-unreachable': ['连不上', 'bad',
    '★ 连不上先别改密码 —— 密码错不会导致连不上。端口明确回了拒绝，说明主机活着、这个口上没有服务，'
    + '去核对端口号和平台进程；什么都没回，先回「ping 与端口」那页确认这台在不在、中间隔没隔路由。'],
  'hls-timeout': ['连上了没回话', 'bad',
    '★ 端口通了却不给清单：多半是平台那边压着一堆请求，或者它只放行内网某几段地址。'
    + '把单次超时放宽到十秒再问一次；还是不通，就看那台服务器的负载和访问日志里有没有这一问 —— '
    + '日志里没有，就是没到这里。'],
};

function subnetScanCard() {
  const card = $(`<div class="card">
    <h2>扫一个网段 <span id="nv"></span></h2>
    <p class="hint">问一遍<b>某个 IPv4 网段上现在有谁</b>。网段留空就扫本机自己所在的各段。
      ★ 只扫 IPv4：IPv6 一个 /64 有 1.8×10<sup>19</sup> 个地址，逐个问是问不完的，
      v6 那一套在「设备是谁」那一页的「听谁在应答」里。</p>
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
        它们只是没在这轮里吭声。要确认某一台，去「ping 与端口」那一页单独 ping 它。</p>` : ''}
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(v, null, 2))}</pre></details>`;
  };
  return card;
}

/*
 * ── 设备识别这一张 ──
 *
 * ★ 默认版面只给「问哪块网卡、等多久、点名问哪个地址」，协议与服务类型的挑选收在高级里：
 *   四种全问是默认，平时那一排勾选不该占地方。
 * ★★ 结果一行要同时答完「它是谁 / 它是什么 / 管理地址 / MAC / 是谁说的 / 从哪块网卡看到的」，
 *   因为抄这一行的人下一步就是拿这些去登录那台设备。
 *   「这台没说」必须显式写出来 —— 空一格和一格「没有」在人眼里是同一件事，
 *   在结论上不是：设备没说，不等于这台不重要。
 */
function deviceIdentifyCard() {
  const PROTOS = [
    ['ssdp', 'SSDP / UPnP', '媒体服务器、智能设备、多数网络摄像头'],
    ['mdns', 'mDNS / DNS-SD', 'NAS、打印机、Mac、AirPlay 与投屏'],
    ['ws-discovery', 'WS-Discovery', '监控设备（ONVIF）、Windows 的网络发现'],
    ['netbios', 'NetBIOS', '老 Windows 与打印机。★ 只有这一路给得出 MAC，它要点名问'],
  ];
  const card = $(`<div class="card">
    <h2>问一遍：这些地址是哪台设备 <span id="xv"></span></h2>
    <p class="hint">上面「扫一个网段」答的是<b>有没有人</b>，这一张答<b>它是哪一台</b>：
      把设备自己喊出来的话摊开 —— 名字、类型、管理地址、MAC。
      ★ 只放设备自己说过的话，没说的留空并写明「这台没说」，一律不按 MAC 前缀猜厂商。</p>
    <div class="row">
      <div style="flex:0 0 190px"><label>只问哪块网卡</label><input id="xi" placeholder="留空 = 插着线的都问"></div>
      <div style="flex:0 0 110px"><label>每轮等几秒</label><input id="xs" placeholder="3"></div>
      <div style="flex:0 0 90px"><label>问几轮</label><input id="xr" placeholder="2"></div>
      <div><label>点名问哪些地址（留空 = 对着网段喊）</label>
        <input id="xa" placeholder="10.0.12.77，或 10.0.12.0/24；空格或逗号分开"></div>
      <div style="flex:0 0 100px;align-self:flex-end"><button class="btn primary" id="xgo">问一遍</button></div>
    </div>
    <details style="margin-top:8px"><summary class="dim">高级：只问某几种自报 / 额外问哪些服务 / 顺带取描述文件</summary>
      <p class="dim" style="margin:10px 0 4px">只勾怀疑的那几种，问得更快、也少打扰别人：</p>
      <div id="xproto" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:4px 12px"></div>
      <div class="row" style="margin-top:10px">
        <div><label>额外问哪些 DNS-SD 服务类型</label>
          <input id="xsvc" placeholder="留空即可；如 _raop._tcp.local、_googlecast._tcp.local"></div>
      </div>
      <label style="display:flex;gap:6px;align-items:center;margin-top:8px">
        <input type="checkbox" id="xdesc" style="width:auto">
        顺着 SSDP 给的管理地址再取一份描述文件（能多问出型号、序列号）</label>
      <p class="hint" style="margin:6px 0 0">★ 这一条是往<b>设备上</b>发一个 HTTP GET：只读，
        但会在那台的访问日志里多一条 —— 有些老设备（门禁、编码器）日志一满就重启，所以默认不取。
        最多取 12 份，只认 http/https。</p>
    </details>
    <div id="xout" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#xout');
  const top = card.querySelector('#xv');
  card.querySelector('#xproto').innerHTML = PROTOS.map(([k, name, note]) =>
    `<label style="display:flex;gap:6px;align-items:center;font-size:13px">
      <input type="checkbox" class="x-proto" value="${k}" style="width:auto"> ${esc(name)}
      <span class="dim">${esc(note)}</span></label>`).join('');
  card.querySelector('#xgo').onclick = async () => {
    top.innerHTML = '';
    const args = {};
    const iface = card.querySelector('#xi').value.trim();
    if (iface) args.iface = iface;
    const secs = Number(card.querySelector('#xs').value);
    const rounds = Number(card.querySelector('#xr').value);
    if (secs > 0) args.seconds = secs;
    if (rounds > 0) args.rounds = rounds;
    const list = (s) => s.split(/[\s,，、]+/).filter(Boolean);
    const addrs = list(card.querySelector('#xa').value);
    if (addrs.length) args.addrs = addrs;
    const svc = list(card.querySelector('#xsvc').value);
    if (svc.length) args.services = svc;
    const picked = [...card.querySelectorAll('.x-proto')].filter((c) => c.checked).map((c) => c.value);
    // 一个都不勾 = 用后端的默认（四种全问）。★ 不许把「没勾」当成「都别问」。
    if (picked.length && picked.length < PROTOS.length) args.protocols = picked;
    if (card.querySelector('#xdesc').checked) args.describe = true;

    out.innerHTML = '<div class="empty">正在问…（先把查询发出去，再在窗口里等各方答话。'
      + '走无线的那块网卡常常慢一拍）</div>';
    const r = await call('net.device.identify', args);
    if (!r.ok) {
      out.innerHTML = `<div class="empty">问不了：${esc(r.message || r.error)}</div>`;
      return;
    }
    const v = r.values;
    const [text, cls, advice] = DEVICE_CODE[r.verdict] || [r.verdict, '', ''];
    const stopPill = v.stopped
      ? `<span class="pill warn">中途停了：只问了 ${esc(v.roundsDone)}/${esc(v.rounds)} 轮</span>` : '';
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span> ${stopPill}`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';

    // 四路各自那一本账：一路没应不代表设备不在，只代表它不说这一种话。
    const tally = (v.protocols || []).map((p) => {
      const askedCell = p.asked
        ? `<span class="dim">${p.protocol === 'netbios'
          ? '点名问过 ' + esc(p.targets) + ' 个地址' : '在 ' + esc(p.targets) + ' 块网卡上问过'}</span>`
        : '<span class="pill">这一路没问</span>';
      return `<tr><td>${esc(p.protocol)}</td><td>${askedCell}</td>
        <td${p.asked && !p.reports ? ' class="dim"' : ''}>${esc(p.reports)} 条</td>
        <td>${esc(p.hosts)} 个地址</td></tr>`;
    }).join('');
    const rows = (v.devices || []).map((d) => {
      const inst = (d.instances || []).filter((s) => s && s !== d.name).slice(0, 3);
      const types = (d.types || []).filter((s) => s && s !== d.kind).slice(0, 3);
      return `<tr${d.identified ? '' : ' style="opacity:.72"'}>
        <td><code>${esc(d.addr)}</code>${d.port ? `<span class="dim">:${esc(d.port)}</span>` : ''}</td>
        <td>${d.name ? `<b>${esc(d.name)}</b>` : '<span class="dim">没说名字</span>'}
          ${inst.length ? `<div class="dim" style="font-size:12px">还报了 ${esc(inst.join('、'))}`
            + `${(d.instances || []).length > 3 ? ' 等' : ''}</div>` : ''}</td>
        <td>${d.kind ? esc(d.kind) : '<span class="dim">没说类型</span>'}
          ${types.length ? `<div class="dim" style="font-size:12px">${esc(types.join('、'))}</div>` : ''}
          ${(d.detail || []).length ? `<div class="dim" style="font-size:12px">${esc(d.detail.join('；'))}</div>` : ''}</td>
        <td>${d.url ? `<code class="dim" style="font-size:12px">${esc(d.url)}</code>`
          : '<span class="dim">没给</span>'}</td>
        <td><code class="dim">${esc(d.mac || '—')}</code></td>
        <td class="dim">${esc((d.protocols || []).join('、'))}</td>
        <td class="dim">${esc(d.iface || '—')}</td></tr>`;
    }).join('');

    // 「一次都没问出去」的那几个判定（没网卡、组播发不出去）没有这几栏可填。
    // ★ 摆一排空统计比不摆更坏：人会读成「问到 0 个」，而实际是「没问」。
    const ran = v.count !== undefined;
    out.innerHTML = `
      ${ran ? `<div class="row" style="align-items:flex-end;gap:18px;margin-bottom:12px">
        <div><label>应了的地址</label><div><b>${esc(v.count)}</b> 个</div></div>
        <div><label>其中报了身份的</label><div><b>${esc(v.identified || 0)}</b> 个</div></div>
        <div><label>收到自报</label><div>${esc(v.reports)} 条</div></div>
        <div><label>问过的网卡</label><div>${esc((v.interfaces || []).join('、')) || '—'}</div></div>
        <div><label>问了几轮</label><div>${esc(v.roundsDone)}/${esc(v.rounds)}</div></div>
        ${v.targets ? `<div><label>点名</label><div>${esc((v.targets || []).length)} 个地址</div></div>` : ''}
      </div>` : ''}
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${advice}${v.reason ? `<div class="dim" style="margin-top:6px">本机报出来的原因：
          <code>${esc(v.reason)}</code> <span class="dim">（这一句是本机自己说的，不是设备上看到的）</span></div>` : ''}</div>
      ${v.count ? `<table style="margin-top:14px"><tr><th>地址</th><th>它是谁</th><th>它是什么</th>
        <th>管理地址（它自己给的）</th><th>MAC</th><th>谁说的</th><th>哪块网卡</th></tr>${rows}</table>
        <p class="dim" style="margin-top:10px">管理地址这一栏是<b>设备自己写的</b>，所以不做成链接：
          抄下来自己核对一眼再打开。「谁说的」那几路里，NetBIOS 是唯一给得出 MAC 的，
          空着就是那台不理 NetBIOS（不是它没 MAC）。</p>` : ''}
      ${tally ? `<h2 style="margin-top:16px">四路各自问到什么</h2>
      <table><tr><th>自报口径</th><th>问的情况</th><th>收到几条</th><th>几个地址答的</th></tr>${tally}</table>` : ''}
      ${v.notAsked ? `<p class="hint" style="margin:10px 0 0">另有 ${esc((v.notAsked || []).length)} 个地址
        <b>一个包都没发出去</b>：<code>${esc([].concat(v.notAsked).join(' '))}</code>
        <span class="dim">—— 问都没问过，不是问了没人答。</span></p>` : ''}
      ${v.skipped ? `<p class="dim" style="margin:10px 0 0">这些没去问：
        ${[].concat(v.skipped).map((s) => esc(s)).join('<br>')}</p>` : ''}
      <p class="dim" style="margin:10px 0 0;white-space:pre-line">${esc(r.note)}</p>
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

// ── 远程：分成「这台机器是谁」和「连上去干活」两页 ──
//
// ★ 原来五张卡挤一页，加体检剧本就超了「每页不超过五张」这条。
//   拆开的分法也正好是人的分法：一页管登记簿和留痕，一页对着某台机器干活。
//
// ★ 设备登记、执行命令、传文件、弹消息、开桌面、跑剧本，背后全是同一批工具 ——
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
  root.appendChild(auditCard());
}

async function renderRemoteWork(root) {
  const r = await call('remote.device.list');
  if (!r.ok) { root.appendChild($(`<div class="card">远程功能不可用：${esc(r.message)}</div>`)); return; }
  const devices = r.values.devices || [];
  const sel = devices.find((d) => d.id === remoteSel) || null;
  root.appendChild(devicePickCard(devices));
  // 有活儿才现身：没挑设备时下面那两张卡除了占地方没有别的用处。
  if (sel) root.appendChild(remoteOps(sel));
  root.appendChild(playbookCard(devices, sel));
}

function devicePickCard(devices) {
  const card = $(`<div class="card">
    <h2>这一页要对哪台干活</h2>
    <p class="hint">登记、删除、看审计在「远程设备与审计」那页。这里只挑一台，下面每一项都会先弹框确认再动。</p>
    <div class="row" style="align-items:flex-end">
      <div style="min-width:280px"><label>设备</label>
        <select id="pick">${devices.length
          ? devices.map((d) => `<option value="${esc(d.id)}" ${d.id === remoteSel ? 'selected' : ''}>${esc(d.name || d.id)} · ${esc(OS_LABEL[d.os] || '系统未知')}</option>`).join('')
          : '<option value="">（还没有登记的设备）</option>'}</select></div>
      <button class="btn primary" id="go"${devices.length ? '' : ' disabled'}>就这台</button>
      <button class="btn" id="clr"${remoteSel ? '' : ' disabled'}>取消选择</button>
    </div>
  </div>`);
  card.querySelector('#go').onclick = () => { remoteSel = card.querySelector('#pick').value; show(); };
  card.querySelector('#clr').onclick = () => { remoteSel = null; show(); };
  return card;
}

// 剧本的状态码 → 界面中文。后端只给码（和判定与账同源的那套规矩一致）。
const PLAYBOOK_STEP = {
  ran: ['问到', 'ok'],
  failed: ['没问到答案', 'bad'],
  timeout: ['没跑完', 'bad'],
  'skipped-platform': ['这台问不出', 'warn'],
  aborted: ['没问到（机器已经不答话）', 'warn'],
};
const PLAYBOOK_VERDICT = {
  'playbook-ok': ['该问的都问到了', 'ok'],
  'playbook-step-failed': ['有几条没问到答案', 'bad'],
  'playbook-platform-skipped': ['这一本在这台机器上一条都没问到', 'warn'],
  'playbook-unreachable': ['问到一半机器不答话了', 'bad'],
  'playbook-empty': ['这本是空的', 'warn'],
};

function playbookCard(devices, sel) {
  const card = $(`<div class="card">
    <h2>体检剧本</h2>
    <p class="hint">把「连上去挨个敲那十几条」录成一本能看、能改、能发给同事的剧本。
      跑之前先看清它要敲什么、有几条会改那台机器的东西 —— 批准框上也会照原样念一遍。</p>
    <div id="body"><div class="empty">读取中…</div></div>
  </div>`);
  const body = card.querySelector('#body');
  // ★ 存完 / 删完的那句话要活得过重绘：不然点下去只看见列表闪了一下，
  //   到底存没存上得靠人去猜。换一本时清掉（那句话说的是上一本）。
  let flash = '';
  // ★ 刚存的那本也要活得过重绘：存完跳回列表第一本，等于没告诉他存到哪了。
  let keepBook = '';

  const load = async () => {
    const r = await call('remote.playbook.list', sel ? { device: sel.id } : {});
    if (!r.ok) { body.innerHTML = `<div class="empty">列不出剧本：${esc(r.message)}</div>`; return; }
    draw(r.values.playbooks || [], r.values);
  };

  const draw = (books, vals) => {
    const known = sel && sel.os && sel.os !== 'unknown';
    body.innerHTML = `
      ${flash ? `<p class="hint" id="flash" style="color:var(--gold)">${esc(flash)}</p>` : ''}
      <div class="row" style="align-items:flex-end">
        <div style="min-width:300px"><label>挑一本</label>
          <select id="book">${books.map((b) => `<option value="${esc(b.id)}"${b.id === keepBook ? ' selected' : ''}>${esc(b.name)} —— ${esc(b.stepCount)} 条，其中 ${esc(b.writeSteps)} 条会改东西${b.builtIn ? '（内置）' : ''}</option>`).join('')}</select></div>
        <div style="max-width:120px"><label>每条等多久</label>
          <select id="wait"><option value="0">按剧本标的</option><option value="30">30 秒</option><option value="60">60 秒 —— 磁盘慢的机器</option></select></div>
        <button class="btn primary" id="run"${sel && known ? '' : ' disabled'}>跑这一本</button>
      </div>
      <p class="dim" style="margin:8px 0 0" id="applies"></p>
      <details style="margin-top:6px"><summary class="dim">这一本要问哪几问、哪几条会改东西</summary>
        <div id="preview" style="margin-top:8px"></div></details>
      ${sel && !known ? '<p class="hint" style="color:var(--gold)">这台机器的系统还没探过 —— 先去「远程设备与审计」那页点一次「探测」。不知道系统就把分系统的条判成「问不出」，那是猜的。</p>' : ''}
      <div class="out" id="result" style="display:none;margin-top:12px"></div>
      <details style="margin-top:12px"><summary class="dim">改这一本 / 另存一本 / 导入同事发来的</summary>
        <div id="editor" style="margin-top:8px"></div></details>`;

    const bookOf = () => books.find((b) => b.id === body.querySelector('#book').value) || books[0];
    const drawBook = () => {
      const b = bookOf();
      if (!b) return;
      const pv = body.querySelector('#preview');
      pv.innerHTML = `${b.note ? `<p class="hint">${esc(b.note)}</p>` : ''}
        <table><tr><th>问什么</th><th>敲什么</th><th>哪种系统</th><th></th></tr>
        ${b.steps.map((s) => `<tr>
          <td>${esc(s.name)}<br><span class="dim">${esc(s.why || '')}</span></td>
          <td><code class="dim">${esc(s.run)}</code></td>
          <td class="dim">${(s.os || []).map((o) => OS_LABEL[o] || o).join(' / ') || '哪都一样'}</td>
          <td>${s.write ? '<span class="pill bad">会改东西</span>' : '<span class="pill">只看</span>'}</td></tr>`).join('')}</table>
        <p class="dim" style="margin:8px 0 0">跑完的每一条都会回到审计日志里（命令和字节数，输出不进审计 —— 里面可能有口令）。</p>`;
      const a = body.querySelector('#applies');
      if (!a) return;
      if (!sel) { a.textContent = '还没挑设备 —— 挑一台才能跑。'; return; }
      if (!known) { a.textContent = ''; return; }
      a.textContent = `在 ${sel.name || sel.id}（${OS_LABEL[sel.os] || sel.os}）上，这本有 ${b.appliesOnDevice}/${b.stepCount} 条问得出去。`;
      drawEditor(b);
    };

    const drawEditor = (b) => {
      const ed = body.querySelector('#editor');
      const json = JSON.stringify({
        id: b.id, name: b.name, note: b.note || '',
        steps: b.steps.map((s) => ({
          name: s.name, run: s.run, why: s.why,
          ...(s.os && s.os.length ? { os: s.os } : {}),
          ...(s.marks && s.marks.length ? { marks: s.marks } : {}),
          ...(s.write ? { write: true } : {}),
          ...(s.timeoutSec ? { timeoutSec: s.timeoutSec } : {}),
        })),
      }, null, 2);
      ed.innerHTML = `
        <p class="hint">这里改的就是那本剧本的原文。<b>改内置那本只能另存成新的一本</b> ——
        内置的那本是「照着官方那本跑」的基准，覆盖了就没人知道你和别人跑的不是同一套。</p>
        <p class="hint">同事发来的那本：把整段 JSON 贴进下面这个框，点「存成新的一本」就进来了。
        不合式的贴法会原样把哪儿不合式说回来，不会存半本进去。</p>
        <textarea id="txt" rows="14" style="width:100%;font-family:ui-monospace,Menlo,monospace">${esc(json)}</textarea>
        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
          <button class="btn primary" id="saveAs">存成新的一本</button>
          <button class="btn" id="saveOver"${b.builtIn ? ' disabled title="内置那本不许覆盖"' : ''}>保存修改这一本</button>
          <button class="btn" id="copy">复制这段（发给同事）</button>
          <button class="btn" id="copyOut">复制最近一次结果</button>
          <button class="btn danger" id="del"${b.builtIn ? ' disabled title="内置那本删不掉"' : ''}>删掉这一本</button>
        </div>
        <div class="out" id="esave" style="display:none;margin-top:8px"></div>`;
      let lastResult = '';
      ed.querySelector('#copy').onclick = async (e) => {
        const t = ed.querySelector('#txt').value;
        try { await navigator.clipboard.writeText(t); e.target.textContent = '已复制，发过去就行'; }
        catch { e.target.textContent = '复制不了，全选框里那段自己拷'; }
      };
      ed.querySelector('#copyOut').onclick = async (e) => {
        const t = lastResult || body.querySelector('#result').innerText;
        try { await navigator.clipboard.writeText(t); e.target.textContent = '已复制'; }
        catch { e.target.textContent = '复制不了'; }
      };
      const save = (replace) => {
        const say = (s) => { const o = ed.querySelector('#esave'); o.style.display = 'block'; o.textContent = s; };
        let book;
        try { book = JSON.parse(ed.querySelector('#txt').value); }
        catch (err) { say('这段不是合法 JSON：' + err.message); return; }
        say(replace ? '保存中…（等待批准）' : '存入中…（等待批准）');
        call('remote.playbook.save', { playbook: book, replace }).then((r) => {
          if (!r.ok) { say('存不下：' + r.message); return; }
          say(r.note);
          flash = r.note;
          keepBook = r.values.playbook;
          setTimeout(load, 800);
        });
      };
      ed.querySelector('#saveAs').onclick = () => save(false);
      ed.querySelector('#saveOver').onclick = () => save(true);
      ed.querySelector('#del').onclick = async () => {
        const cur = bookOf();
        // 删的是本机上那一个文件：万一里面记着「只有这台机器管用」的经验，
        // 删了就没了 —— 所以先给一次把 JSON 拷走的机会，再让点。
        const ok = await confirmModal(
          `删掉剧本「${cur.name}」？`,
          ['只删本机配置目录里那一个文件，<b>设备上跑过的痕迹和审计日志都不动</b>。',
           '内置的那些本删不掉，这里也不会去碰它们。',
           '想留着的话：先点「复制这段（发给同事）」把 JSON 收好，再回来删。'],
          '确认删掉');
        if (!ok) return;
        const r = await call('remote.playbook.delete', { playbook: cur.id });
        const say = (s) => { const o = ed.querySelector('#esave'); o.style.display = 'block'; o.textContent = s; };
        if (!r.ok) { say('删不掉：' + r.message); return; }
        say(r.note);
        flash = r.note;
        setTimeout(load, 800);
      };
      // 跑完一次结果就换一次；另存时给人一个能把结果一起发走的口子
      card.__setResult = (t) => { lastResult = t; };
    };

    body.querySelector('#book').onchange = (e) => {
      // 那句说的是上一本（「已存好 X」），换一本再挂着就是假线索 ——
      // 清变量不够，那行已经在页上了，得当场摘掉。
      flash = ''; keepBook = e.target.value;
      body.querySelector('#flash')?.remove();
      drawBook();
    };
    body.querySelector('#run').onclick = async () => {
      const b = bookOf();
      const o = body.querySelector('#result');
      const wait = Number(body.querySelector('#wait').value) || undefined;
      o.style.display = 'block';
      o.textContent = `正在 ${sel.id} 上跑「${b.name}」…（${b.writeSteps} 条会改东西，批准框上会一条条念给你看）`;
      const args = { device: sel.id, playbook: b.id };
      if (wait) args.timeoutSec = wait;
      const r = await call('remote.playbook.run', args);
      if (!r.ok) { o.textContent = '跑不了：' + r.message; return; }
      o.innerHTML = playbookResult(r);
      if (card.__setResult) card.__setResult(o.innerText);
    };
    drawBook();
  };

  load();
  return card;
}

function playbookResult(r) {
  const v = r.values || {};
  const c = v.counts || {};
  const [label, cls] = PLAYBOOK_VERDICT[r.verdict] || [r.verdict, ''];
  const red = Object.values(v.redacted || {}).reduce((a, b) => a + b, 0);
  const steps = (v.steps || []).map((s) => {
    const [sl, sc] = PLAYBOOK_STEP[s.status] || [s.status, ''];
    const hits = (s.hits || []).filter((h) => h.lines > 0);
    const misses = (s.hits || []).filter((h) => !h.lines);
    return `<div style="border-top:1px solid var(--line);padding:10px 0">
      <div><span class="pill ${sc}">${esc(sl)}</span>
        <b>${esc(s.name)}</b>
        ${s.write ? '<span class="pill bad">改了那台机器的东西</span>' : ''}
        ${s.exitCode ? `<span class="pill warn">退出码 ${esc(s.exitCode)}</span>` : ''}
        <span class="dim">${esc(s.elapsedMs ? (s.elapsedMs / 1000).toFixed(1) + ' 秒' : '')}</span></div>
      ${s.why ? `<p class="dim" style="margin:4px 0">为什么问它：${esc(s.why)}</p>` : ''}
      <p style="margin:4px 0"><code>${esc(s.command)}</code></p>
      ${hits.map((h) => `<div style="border-left:3px solid var(--gold);padding:2px 0 2px 8px;margin:6px 0">
          <b>命中 ${esc(h.lines)} 行</b>
          ${(h.sample || []).map((x) => `<pre class="hit" style="margin:2px 0;white-space:pre-wrap">${esc(x)}</pre>`).join('')}
          <p style="margin:4px 0 0">${esc(h.say)}</p></div>`).join('')}
      ${misses.length ? `<p class="dim" style="margin:6px 0 0">这几样在这段输出里没提到：${misses.map((h) => `「${esc(h.say)}」`).join('、')}
        —— <b>没提到不等于没有</b>，它只说明这本剧本要找的那句话没出现。</p>` : ''}
      ${s.output ? `<pre class="out" style="white-space:pre-wrap;margin:6px 0 0">${esc(s.output)}</pre>` : ''}
      ${s.error ? `<p style="margin:6px 0 0">没问到的原因：${esc(s.error)}</p>` : ''}
      ${s.note ? `<p class="dim" style="margin:6px 0 0">${esc(s.note)}</p>` : ''}
    </div>`;
  }).join('');

  return `<div><span class="pill ${cls}">${esc(label)}</span> <b>${esc(v.verdictNote || r.note || '')}</b></div>
    <p class="dim" style="margin:8px 0">共 ${esc(c.total)} 条：问到 ${esc(c.ran)}、没问到答案 ${esc(c.failed)}、
      没跑完 ${esc(c.timedOut)}、这台问不出 ${esc(c.skippedPlatform)}、没问到（机器断了）${esc(c.aborted)}${c.hitLines ? `；关键词命中 ${esc(c.hitLines)} 处` : ''}</p>
    ${red ? `<p class="hint" style="color:var(--gold)">结果里抹掉了凭据：${esc(v.redactedHow)}。键名留着、值换成掩码 —— 那是「有口令、没给你看」，不是「没配口令」。</p>`
          : `<p class="dim" style="margin:8px 0">凭据核过一遍：${esc(v.redactedHow)}。</p>`}
    ${steps}
    <p style="margin:10px 0 0"><b>下一步：</b>${esc(v.nextStep || '')}
      <span class="dim">（这台 ${esc(v.device)} · 剧本 ${esc(v.playbook)} · 用了 ${esc(v.seconds ? v.seconds.toFixed(1) : '—')} 秒）</span></p>`;
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
}

// ── 这台机器：端口占用与文件共享 ──

async function renderLocal(root) {
  root.appendChild(portProcCard());
  root.appendChild(fileshareCard());
}

// ── 出问题了：先体检，再把整包事实带走 ──
//
// ★ 这两张卡是配套的一对：体检给「第一个坏掉的是哪一步」，诊断包给「连同机器上
//   看得见的一切，打包发给远程的人」。原来它们埋在十五张卡中间，现场找不到。

async function renderCheckup(root) {
  root.appendChild(checkupCard());
  root.appendChild(diagBundleCard());
}

async function renderTrouble(root) {
  root.appendChild(troubleCard());
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
    '这个问法本身不成立 —— v4 段和 v6 段谈不上撞。要说「这台机器两族是不是都通」，去「域名与时间」那一页做双栈体检。'],
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
  denied: ['被拒（想上传 / 想翻出共享目录）', 'bad'],
  'not-found': ['没有这个文件（地址里那个文件名没对上）', 'warn'],
  // TFTP 那一侧独有的三种：处置和上面几种完全不同，不许并回「失败」。
  aborted: ['协商完就没回话（多半这台设备不认 OACK）', 'bad'],
  busy: ['同时传得太多了，这一笔没接', 'warn'],
  'octet-served': ['按原样字节发完了（它要的是 netascii）', ''],
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
      <td class="dim">${esc(['http', 'tftp', 'ftp'].includes(t.proto) ? t.proto : 'http')}</td>
      <td><code>${esc(t.path || '—')}</code></td>
      <td class="dim">${esc(fsSize(t.bytes))}</td>
      <td class="${cls}">${esc(word)}</td>
    </tr>`;
  }).join('');
  return `<div style="max-height:280px;overflow:auto"><table>
    <tr><th>什么时候</th><th>谁取的</th><th>哪个协议</th><th>取了什么</th><th>多少</th><th>结果</th></tr>
    ${rows}</table></div>
    <p class="hint">只留最近 50 笔。「被拒」那一行是分开的：想上传的（http 的 PUT、tftp 的 WRQ、ftp 的 STOR/DELE）一律不收，
      文件名写错只算没找到，不混成「有人在攻击」。协议那一栏看得出设备是从哪个口来取的 ——
      同一台设备换个地址栏就会换一行，开着三种协议时这一栏也是「谁在动这个目录」的清单。</p>`;
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
      ★ 遇到<strong>只认 tftp 的老设备</strong>（填 http 一律「下载失败」），勾上「连 TFTP 一起开」：
      同一个目录、同样只读，只是多开一个 UDP 口。另一批设备/交换机的地址栏只认
      <strong>ftp://</strong>，那就勾「连 FTP 一起开」。
      ★ <strong>只读</strong>：只发不收，同网段谁都改不了、删不了本机任何东西
      （http 只接 GET/HEAD，tftp 的上传请求当场回「不接受上传」，
      ftp 的 STOR/DELE/MKD/RNFR 这些命令压根不认）。
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
      <div style="flex:0 0 110px"><label>TFTP 端口（默认 69）</label>
        <input id="fs-tftpport" placeholder="69"></div>
      <div style="flex:0 0 110px"><label>FTP 端口（默认 21）</label>
        <input id="fs-ftpport" placeholder="21"></div>
    </div>
    <div class="row">
      <label style="display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap">
        <input type="checkbox" id="fs-list" checked style="flex:0 0 auto">
        允许翻目录列表</label>
      <label style="display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap"
        title="老设备的升级页面只认 tftp://，填 http 一律「下载失败」。开了就是多开一个 UDP 口，一样只读、一样不鉴权。">
        <input type="checkbox" id="fs-tftp" style="flex:0 0 auto">
        连 TFTP 一起开（老设备只认它）</label>
      <label style="display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap"
        title="还有一批设备和交换机的地址栏只认 ftp://。开的是只读：上传、删除、改名这些命令当场拒。数据口只绑在这块网卡上。">
        <input type="checkbox" id="fs-ftp" style="flex:0 0 auto">
        连 FTP 一起开（交换机/老设备只认 ftp://）</label>
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
    // serve 和 status 两边都带这几个字段（刷一次状态不能丢掉「多开了哪个协议」这件事）
    const tftp = typeof v.tftp === 'boolean' ? v.tftp : Boolean(st.tftp);
    const tftpPort = v.tftpPort || st.tftpPort || 0;
    const turls = (v.tftpUrls && v.tftpUrls.length ? v.tftpUrls : st.tftpUrls) || [];
    const ftp = typeof v.ftp === 'boolean' ? v.ftp : Boolean(st.ftp);
    const ftpPort = v.ftpPort || st.ftpPort || 0;
    const furls = (v.ftpUrls && v.ftpUrls.length ? v.ftpUrls : st.ftpUrls) || [];
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--sunken)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--line)';

    // 开着哪几种协议说一遍：停掉那一句和状态那一句都要用它，两边各列一份必出错
    const protos = ['http'];
    if (tftp) protos.push('tftp');
    if (ftp) protos.push('ftp');

    let say;
    if (verdict === 'share-idle') {
      say = '现在没开着。开一次就是一次对外暴露，需要时再开、用完就停 —— '
        + '这个共享不鉴权，同网段谁都能读。';
    } else if (verdict === 'share-stopped') {
      // ★ 停掉之后不再摆下载地址：那几条已经读不到东西了，还做成可复制的样子，
      //   人就照旧往设备里粘，然后回来查「为什么下载失败」。
      say = `${protos.join('、')} 的端口都已经放掉，${esc(root)} 不再对外可读。`
        + `这中间一共被取走 ${v.requests || 0} 次、${esc(fsSize(v.bytes || 0))}。`
        + '已经下到设备里的文件不受影响。';
    } else if (serving && v.iface) {
      say = `目录 <code>${esc(root)}</code> 正从网卡 <b>${esc(v.iface)}</b>`
        + `（${esc(FS_WHY[v.ifaceWhy] || v.ifaceWhy || '怎么定的没说')}）发出去，http 端口 ${port || '—'}`
        + (tftp ? `、TFTP 端口 ${tftpPort || '—'}` : '')
        + (ftp ? `、FTP 端口 ${ftpPort || '—'}` : '') + `。`
        + `只读，不收上传。★ 同一网段的设备不必登录就能读到这个目录里的东西。`;
    } else if (serving) {
      say = `目录 <code>${esc(root)}</code> 正绑在这些地址上：${
        (v.addrs || st.addrInfo || []).map((x) => `<code>${esc(x)}</code>`).join('、')
        }，http 端口 ${port || '—'}`
        + (tftp ? `、TFTP 端口 ${tftpPort || '—'}` : '')
        + (ftp ? `、FTP 端口 ${ftpPort || '—'}` : '') + `。只读，不收上传。`;
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
        if (tftp) {
          // ★ 多开的那是一个 UDP 口，也要一直看得见：现场防火墙对 UDP 的默认放行
          //   往往比 TCP 松，只报 http 等于少说了一半。
          facts.push(['TFTP 那一侧', `开着，UDP 端口 ${tftpPort || '—'}；一样只读，上传请求一律回「不接受上传」`]);
        }
        if (ftp) {
          // ★ 这一栏要说的是「它还额外开了什么」：FTP 每传一个文件要临时开一个数据口，
          //   只放行 21 的防火墙会卡在取文件那一步 —— 不说，现场会去怀疑设备。
          facts.push(['FTP 那一侧', `开着，端口 ${ftpPort || '—'}；只读，STOR/DELE/MKD/RNFR 这些命令当场拒`
            + '；每传一个文件临时开一个数据口（只绑这块网卡的地址），防火墙只放行这一个口会卡在取文件那一步']);
        }
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
      ${turls.length && serving ? `<div style="margin-top:12px"><label class="dim">TFTP 地址（设备的升级页面只认 tftp 时用这一条）</label>
        ${turls.map((u) => `<div style="margin-top:4px"><code style="user-select:all;cursor:cell">${esc(u)}</code></div>`).join('')}
        <p class="hint">设备那一栏通常只填「文件名」或「地址 + 文件名」：<code>${esc(turls[0] || '')}固件名.bin</code> 这样接。
          ★ TFTP 没有目录列表，文件名必须写全，写错就是「没有这个文件」。
          69 号口绑不上（要更高权限）时，界面上会让它换一个端口，设备的地址栏能填端口就填上。</p></div>` : ''}
      ${furls.length && serving ? `<div style="margin-top:12px"><label class="dim">FTP 地址（交换机、老设备的配置/固件栏只认 ftp:// 时用这一条）</label>
        ${furls.map((u) => `<div style="margin-top:4px"><code style="user-select:all;cursor:cell">${esc(u)}</code></div>`).join('')}
        <p class="hint">多数设备的 ftp 栏要的是「地址 + 文件名」：<code>${esc(furls[0] || '')}固件名.bin</code> 这样接。
          ★ 要用户名的地方随便填一个就行（这个共享不鉴权），密码同理 —— 别把你别的账号填进去。
          主动模式（PORT）只允许连回它自己连进来的那个地址，隔着 NAT 的设备会取不到文件，那种设备请让它走 PASV。</p></div>` : ''}
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
    if (card.querySelector('#fs-tftp').checked) {
      args.tftp = true;
      const tp = card.querySelector('#fs-tftpport').value.trim();
      // 不填就交给后端按 69 来：这里替它填一个别的号，等于人没同意过的端口
      if (tp) { args.tftpPort = Number(tp); }
    }
    if (card.querySelector('#fs-ftp').checked) {
      args.ftp = true;
      const fp = card.querySelector('#fs-ftpport').value.trim();
      if (fp) { args.ftpPort = Number(fp); }
    }
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

/*
 * ── 按症状排查（net.troubleshoot）──
 *
 * ★★ 和上面那张体检卡的分工写在脸上：体检是「不管三七二十一全过一遍」，给出八项结果，
 *   从哪一条开始看由人判断；这一张是人先说一句症状，按工程师的顺序**只走那一条路**，
 *   停在第一个能解释症状的判定上，并且把「第几步问了什么 / 答了什么 / 所以接下来问什么」
 *   整条留下 —— 那条路径才是拿去跟二线对质的东西，一句「网络没问题」不是。
 *
 * ★★ 每一步的判定话术**这里一份都不重写**。树里每一步就是本页另一张卡用的那个工具，
 *   给的也是它那一批判定码，所以直接查它自己那份字典（TREE_CODE_OF）。
 *   在这儿另写一套，等于给同一件事造两套会各自腐烂的说法 ——
 *   和后端「树不重造判定，只调已有工具」是同一条纪律。
 *
 * ★ 没问出去的步骤必须显式渲染成「没问」，不许留空栏：空栏会被读成「问了，没问题」。
 */

// 六种症状：名字和后端那六个稳定标识一致，中文只活在这里。
const SYMPTOM = {
  'no-internet': ['这台机器上不去网',
    '什么都不用填，这台机器就是主角。★ 要拿某个内网域名当对照组，再填在「目标」里。'],
  'host-down': ['点名一台机器连不上',
    '把连不上的那一台填在「目标」（IP 或域名都收）。★ 不填就只查我们这台到公网那一段，点不到你手上那一台。'],
  'slow': ['通是通，但很慢',
    '填那个慢的地址。要是慢的是某个网页或接口，把完整地址填在高级的「网址」里 —— 只有那样才量得出各段各占了多少。'],
  'flaky': ['偶尔卡一下 / 时好时坏',
    '填那个「时好时坏」的地址。★ 这种病要多发几发才挑得出来，别勾「快一点」。'],
  'cert-error': ['证书报错 / HTTPS 打不开',
    '填报错的那个地址（或者把浏览器地址栏那串贴到高级的「网址」）。★ 这一条会先问时间，再决定是不是证书的锅。'],
  'device-down': ['一台设备不在线 / 没画面',
    '把那台设备的地址填进来。★ 有 rtsp 取流地址就填在高级的「网址」里；没有也行 —— 会先向设备问一次 ONVIF，把地址问出来再去验流。'],
};

// 五种状态。★ 这一列是这张卡最要紧的一列：「没去问」和「问了没有」差一次跑错机房。
const TREE_STATUS = {
  asked: ['问了', '', ''],
  'not-asked': ['没问出去', 'warn', '缺前面的事实，这一步一个包都没发'],
  skipped: ['没问到这一步', '', '停在前面那一步了，按顺序不必问'],
  unreadable: ['问了，但没读出要的那一项', 'bad', '是我们读不到，不是网络没答'],
  failed: ['这一步自己出错了', 'bad', '参数、权限或工具内部的错，不能当成「查过了没问题」'],
};

// 顶层那三种「没定位到根因」的读数。
const TREE_TOP = {
  'no-cause-found': ['这条路每一步都正常', 'warn',
    '★ 这不等于「没毛病」，只等于「毛病不在我们问的这几步里」：症状多半在对端、在应用配置、或者在'
    + '另一块网卡上。看下面哪几步压根没问出去 —— 那几步才是这份结论的边界，也是下一步该补的地方。'],
  stopped: ['时间用完，只走到一半', 'warn',
    '这份路径只到标了状态的那几步，后面全是「没问到」。★ 别把这份当整条结论用：'
    + '在高级里把「最长跑多久」调大，或者勾上「快一点」少发几发，再跑一次。'],
  'nothing-asked': ['一步都没问出去', 'bad',
    '要问的目标信息压根没给够，所以一个探测包都没发。★ 这一档最容易被读成「查过了，都没事」—— '
    + '它什么都没说。把「目标」填上（点名的那台机器 / 那个网址）再来一次。'],
};

// 每一步的判定话术 = 那个工具自己那份字典（可以不止一份：双栈那一步的顶层判定
// 有两种来源，双栈体检自己那批、和 Happy Eyeballs 那一批）。
// ★ 见上面的注释：一份都不重写。
const TREE_CODE_OF = {
  checkup: [CK_TOP], 'route-list': [RT_CODE], 'route-target': [RT_CODE],
  dns: [DNS_CODE], 'dns-multi': [DNS_CODE], dualstack: [DS_TOP, DS_EYEBALLS],
  'gw-watch': [WATCH_CODE], watch: [WATCH_CODE], ping: [PING_CODE],
  trace: [TRACE_CODE], mtr: [MTR_CODE], clock: [TIME_CODE], tcp: [PROBE_CODE],
  ports: [SCAN_CODE], 'on-link': [SUBNET_CODE], tls: [CERT_CODE],
  http: [HTTP_CODE], mtu: [MTU_CODE], stream: [RTSP_CODE], onvif: [ONVIF_CODE],
  hls: [HLS_CODE],
};

// 树里问到的那一步没给出话术时，只回落到码本身 —— 不许在这儿编一句人话顶上：
// 那等于把「我们没译」演成「网络就这么个说法」。测试逐条钉着这批码。
function treeCodePill(step, code) {
  if (!code) return '';
  for (const dict of TREE_CODE_OF[step] || []) {
    const hit = dict[code];
    if (hit) return `<span class="pill ${hit[1]}">${esc(hit[0])}</span>`;
  }
  return `<span class="pill">${esc(code)}</span>`;
}

/*
 * 根因话术。★★ 这里的每一条都是「停在这一点上，接下来去动什么」，
 *   不是对判定的复述 —— 复述那一步的判定在表格里已经有，人要看的是下一步的手。
 */
const TREE_CAUSE = {
  // ── 这台机器上不去网 ──
  'cause-no-interface': ['一块在用的网卡都没有', 'bad',
    '要么全被禁用，要么没有一块拿到可用地址 —— 后面每一步都是在它之上测的，先解决这一步。'
    + '查网卡开关、虚拟口 / VPN 的残留、无线关联上了没有。'],
  'cause-link-down': ['网卡开着，链路却没起来', 'bad',
    '线没插 / 对端那个口没起来 / 没连上 AP。★ 这一条不用查任何配置：先看这块口的灯和对端口，'
    + '是物理层的事。'],
  'cause-no-address': ['链路是好的，但没拿到地址', 'bad',
    'DHCP 没发地址（现场最常见的是那个口被划在另一个 VLAN 里），或者静态地址压根没配。'
    + '去「DHCP 分地址」那一页看有没有应答，再回来看这块口的地址。'],
  'cause-no-default-route': ['有地址，却没有默认路由', 'bad',
    '这台机器只会发到本网段：局域网里什么都通，外面一个都到不了。查 DHCP 有没有发网关、'
    + '静态配置里网关那栏填了没有。'],
  'cause-gateway-loss': ['到网关就在丢包', 'bad',
    '★ 网关在丢包时，解析和外网的「慢」都是它带出来的，不是那几层自己的毛病 —— 先修这一段，'
    + '再回头看后面那些数。查线、查 AP 信号、查那个口的协商速率。'],
  'cause-gateway-unreachable': ['网关明确回了「到不了」', 'bad',
    '有人答了话，说明本机到网关这一路是通的，是网关自己没有出路。'
    + '查它上游那条链路、它自己的默认路由和 NAT。'],
  'cause-gateway-silent': ['网关一个都不回', 'bad',
    '★ 这不能直接读成「网关死了」：它拦 ICMP 时长得一模一样。换个不依赖 ICMP 的办法验一次 —— '
    + '探一个公网 IP（跳过解析），或者另拿一台机器同时测，才知道是不是只有这台的事。'],
  'cause-dns-server-dead': ['配了 DNS 服务器却问不到', 'bad',
    '「网页打不开，但 IP ping 得通」就是这一层。换成问网关或一个公共 DNS 再试一次：'
    + '能出结果说明配的那台不干活，还不行就是 53 端口被拦。'],
  'cause-dns-upstream': ['DNS 服务器自己查不到', 'bad',
    'SERVFAIL 是它那一侧的账（它的上游或转发坏了），改本机没用的方向。'
    + '换一台服务器就能出结果 —— 现场常是内网 DNS 只配了转发、转发目标却不通。'],
  'cause-dns-refused': ['DNS 服务器不给递归查询', 'bad',
    '这台解析器只服务内网（不替你查公网名字）。换一台公共 DNS，'
    + '或者把查询发给你自己搭的那台递归。'],
  'cause-dns-bad-response': ['回来的不是能解的 DNS 报文', 'bad',
    '★ 这多半不是 DNS 坏了，是有设备在冒充 / 改写它（老网关、透明代理、被投毒的缓存）。'
    + '换一个 DNS 服务器或走加密 DNS 再问一次，能分清是谁在动。'],
  'cause-name-missing': ['这个域名不存在', 'bad',
    '服务器明确说没有这个名字。先核对有没有拼错、少带后缀；内网名字要看这台机器有没有走'
    + '那个搜索域 / 那个 hosts 文件。'],
  'cause-v6-egress-broken': ['IPv6 有路却出不了外网', 'bad',
    '★ 这是「网很慢」的真身之一：应用先试 IPv6，等它失败才回落到 IPv4，于是每一次连接都慢半拍，'
    + '而 ping 和体检看着都正常。要么修上游的 IPv6，要么先把这块口的 IPv6 关掉。'],
  'cause-path-stalled': ['路断在中间某一跳', 'bad',
    '最后一台有回应的设备之后，再没人回过话 —— 停在哪台写在那一步的依据里。'
    + '查那一台和它后面那条链路，别再从两头互相 ping 了。'],
  'cause-path-silent': ['第一跳就没回应，说不通路断没断', 'warn',
    '★ 路由器不回应探测包时，「路好好的」和「路断了」是同一个形状。改用探端口或直接连服务确认'
    + '终点到不到得了，再决定查哪一段。'],
  'cause-no-route-to-target': ['本机没有去往那个地址的路由', 'bad',
    '一个包都没发出去，所以跟对端防不防火没有任何关系。查自己：地址和掩码配得对不对、'
    + '是不是根本不在同一个网段、多网卡机器上有没有那块口的路由。'],
  'cause-clock-way-off': ['本机时钟差得足以让别的东西出错', 'bad',
    '这个量级上证书会被判「已过期」或「还没生效」、租约会算成早到期、日志时间戳排不进正确顺序 —— '
    + '现场看到的「网有问题」，根在这里。先校时，再回头看别的。'],
  'cause-clock-skewed': ['时钟有偏差，但还没到出事的地步', 'warn',
    '★ 只有一个时间源答的时候，这里只说差多少、不指认是谁不对。要指认，多配几个源再问一次。'],
  'cause-proxy-in-the-way': ['系统代理指着一台连不上的机器', 'bad',
    '★ 这种机器最骗人：ping、探端口、直连公网全都正常，只有应用打不开 —— 因为应用走代理，'
    + '而体检那一圈里有几项是不走代理的。查代理地址、端口，或者先把系统代理关掉再试。'],

  // ── 点名一台机器 ──
  'cause-target-off-link': ['二层就没有它（同网段没人认它）', 'bad',
    '★ 这一条值得单独一档：扫的是它所在那一段，清单里别的设备都在，只有它一个信号都没发过 —— '
    + '网络配置已经不用查了，去查线、查供电（PoE 那个口给没给功率）、查它是不是关着机。'],
  'cause-target-alive-noicmp': ['它是活的，只是不理 ping', 'warn',
    '同网段那一问里它吭过声（应了 ARP），却不回 ICMP —— 摄像头、NVR 十台九台这样，'
    + '多数还带「一键禁 ping」的开关。★ 别再拿 ping 不通当证据了，直接去问它服务的端口。'],
  'cause-target-unreachable': ['有设备明确回了「到不了这台」', 'bad',
    '这比「没回应」有用得多：包出得去、也有人回话，路是通的，问题在终点或某台设备的路由上。'
    + '查它的地址还在不在、中间那台路由有没有到它的路由。'],
  'cause-target-no-reply': ['一路都没回，也没拿到二层证据', 'bad',
    '★ 这一档故意不给「它挂了」的结论：整段被静默、它自己关机、地址被人改了，全是这个形状。'
    + '要么把「目标」填成它的 IP（跳过解析）再跑一次，要么换一台同网段的机器同时测。'],
  'cause-service-closed': ['机器在，那个端口上没服务', 'bad',
    '端口明确回了拒绝 —— 拒绝说明它收到了包，所以主机活着、路也通。'
    + '去看服务起没起、端口号对不对（摄像头 554 是 RTSP，80 是 Web，8000 / 8200 是各家私有 SDK）。'],
  'cause-service-filtered': ['那个端口一个回包都没有', 'bad',
    '多半是中间有人静默丢（防火墙 / ACL / 端口防护），也可能是主机根本不在。'
    + '★ 这两件事的下一步完全不同，所以先用同网段那一问或探一片端口确认主机在不在。'],
  'cause-host-alive': ['网络和端口都没问题，症状不在这条路上', 'warn',
    '★ 这一条是拿来收口的：它活着、端口也开着，所以「上不去」的账要记到服务里去的'
    + '那一层（账号、通道号、并发满了、它只放行指定 IP）。拿取流那一步去问它回什么。'],

  // ── 通是通，但很慢 ──
  'cause-link-jitter': ['链路本身在抖', 'bad',
    '没丢包，但快慢差得明显。★ 抖和丢是两种病：丢要查链路（线、信号、协商、环路），'
    + '抖多半是排队 —— 查那条链路是不是被某台机器占满了，或者 AP 上挂了太多客户端。'],
  'cause-link-loss': ['链路上有丢包，重传把一切拖慢', 'bad',
    '★ 丢包时的「慢」不该记到应用头上：TCP 每丢一次就要等一次重传超时，'
    + '用户看到的就是「转很久」。先把这一段修干净，再看那些分段耗时还剩多少。'],
  'cause-v6-stall': ['应用先卡在 IPv6 上，再回落', 'bad',
    '双栈机器上「慢」最省事的解释：每一次新建连接先赌 IPv6，赌输了再走 IPv4，'
    + '于是每次多等一截。修上游 v6，或先把这块口的 IPv6 关掉再测一次对比。'],
  'cause-dns-slow': ['慢在解析这一段', 'bad',
    '各段耗时里解析占了大头，说明服务器能答只是答得慢（转发链长、DNS sec 校验、'
    + '或者被限速）。换一台近的 DNS、或者把常用名字做成本地解析，效果立竿见影。'],
  'cause-connect-slow': ['慢在 TCP 握手这一段', 'bad',
    '网络往返本身就慢或第一跳 SYN 被丢了一次 —— 查路由距离、对端 backlog，'
    + '以及中间有没有在改写连接。★ 服务端处理慢不是这一条。'],
  'cause-tls-slow': ['慢在 TLS 那一段', 'bad',
    '常见于设备证书链太长、要现场补中间证书，或者双方的套件要来回试几轮才谈成。'
    + '把证书链配齐（配上中间证书）能省掉这一段的大半。'],
  'cause-app-slow': ['网络各段都利索，慢在服务自己想', 'bad',
    '★ 这条的作用是把人从网络侧叫回来：包没丢、往返没抬升、握手也快，账全在服务器处理时间里。'
    + '去查那个服务的日志、数据库和上游，别再翻交换机了。'],
  'cause-path-latency': ['从某一跳起往返抬升，并一路带到终点', 'bad',
    '抬升起点那一跳就是分界：它之前还是好的。要查的是那一段链路（或那个出口在拥塞），'
    + '不是终点机器 —— 它只是替前面所有环节把账付了。'],
  'cause-mtu-too-small': ['路上有一个更小的包长限制', 'bad',
    '大包就是在中间某一环被挡住或被迫分片：隧道、VPN、PPPoE、被人改小过的交换机口。'
    + '★ 这条专门治「连得上、ping 得通，视频一出来就卡 / 传文件传到一半断」——'
    + '因为别的探测发的是小包。把本机网卡 MTU 设成那一步给的建议值就能先绕过去。'],

  // ── 偶尔卡一下 ──
  'cause-intermittent-loss': ['有一段在突发丢包', 'bad',
    '★ 「一直不丢」和「偶尔丢」是两个查法：一直丢能立刻定位，突发丢要么有规律（定时任务、'
    + '无线信道跳频、某台机器周期发广播），要么是被偶发拥塞。连续 ping 和逐跳质量里都写了第几轮、'
    + '第几发丢的，拿那个时间点对它的日志。'],
  'cause-path-moved': ['等价路径在翻动', 'warn',
    '同一跳出现过不止一个下一跳：负载分担本来就这样，不算故障。★ 只有当每次翻到一条更烂的路时才卡人 —— '
    + '对照那一步的丢包和往返看，别看它翻没翻。'],
  'cause-multi-default': ['同族有多条默认路由，选路在换', 'bad',
    '多网卡、或者插了 VPN 之后最典型的病：两条一样的路优先级接近，内核在它们之间换 —— '
    + '换到那条不通的就卡一下。★ 这是本机的事，留一条默认路由，或者给另一条降优先级 / '
    + '改成只走指定网段。'],
  'cause-round-robin-bad': ['一个名字解出几台，其中一台是坏的', 'bad',
    'DNS 轮询里混了一台下线或半死的机器：解到它就通、解到它就不通，看上去完全是随机。'
    + '★ 这一条要拿那个名字的完整清单去看，哪一台连不上就先从解析里摘掉。'],
  'cause-clock-disagree': ['两台机器的钟不一致，日志对不上号', 'bad',
    '★ 这时候不能指认谁不对：至少有一个时间源自己就是坏的（或者中间有设备在改写 NTP）。'
    + '先把对不上的那一个从服务器列表里去掉再问一次，剩下的才可信。'],

  // ── 证书 ──
  'cause-cert-expired': ['证书确实过期了', 'bad',
    '时间也对得上，所以是证书自己的账。必须重新签发一张 —— 过期之后所有客户端都会拒绝，'
    + '重装应用、清缓存、换浏览器都没用。'],
  'cause-cert-not-yet-valid': ['证书确实还没到生效时间', 'bad',
    '★ 走到这一条，本机那个钟已经对过了、是好的（偏到足以冤枉证书的那种会单独报出来），'
    + '所以「还没生效」是证书自己说的实话：要么这张证书刚签、还没到它写的生效时刻，'
    + '要么签它的那台机器钟超前，把生效时间签到了未来。去签发的那一头对时刻。'],
  'cause-cert-name-mismatch': ['证书上的名字和访问的地址对不上', 'bad',
    '要么改用证书上写着的名字访问，要么按现在这个地址重签一张。'
    + '★ 用 IP 访问内网设备最常撞这一条（设备证书一般只写名字，不写 IP）。'],
  'cause-cert-untrusted': ['证书本身没坏，是本机不认这条链', 'warn',
    '自签、缺中间证书、或者本机没装那个根 —— 内网设备的出厂默认。'
    + '把它的根证书装进本机信任列表，或者让设备出示完整的链。'],
  'cause-cert-weak-protocol': ['对方只肯谈老版本 TLS', 'bad',
    'TLS 1.0 / 1.1 已被新版浏览器和平台直接拒绝连接。★ 要升级的是设备侧的 TLS 栈，'
    + '换证书解决不了 —— 老固件的设备只能换固件或者放在只走专网的位置上。'],
  'cause-clock-made-cert-bad': ['证书是被本机时钟冤枉的', 'bad',
    '★★ 这一条是这张树里最值钱的一档：证书没过期，是这台机器的钟偏得把它推出了有效期窗口。'
    + '没有「先问时间」这一步，现场就会白跑一趟 CA，而毛病在自己主机的任务栏上。先校时，'
    + '再看那个报错还在不在。'],
  'cause-not-tls': ['那个端口回的不是 TLS', 'bad',
    '地址写成了 https，端口后面却是明文服务（或者反过来）。★ 改个前缀就好，'
    + '不用查证书也不用查网络 —— 这一条单独占一档就是为了别让人去装证书。'],

  // ── 一台设备不在线 / 没画面 ──
  'cause-device-off-link': ['二层就没有这台设备', 'bad',
    '★ 同网段那一问里别的设备都在，只有它一个信号没发过：网络配置不用查了。'
    + '去查线、查那个 PoE 口给没给功率、查它是不是关着机或被人搬走了。'],
  'cause-device-no-icmp': ['设备活着，只是不理 ping', 'warn',
    '它应了 ARP 却不回 ICMP —— 这是摄像头的常态，不是毛病。★ 别拿「ping 不通」写进报告里说设备离线，'
    + '去问它的服务端口（554 / 80 / 私有 SDK 口）。'],
  'cause-device-no-service': ['设备在，但那些服务口一个都没开', 'bad',
    '端口明确回了拒绝，说明主机活着。★ 那就不是链路的事：查取流服务开没开、'
    + '通道号对不对、这个账号有没有该通道的权限（NVR 上不同用户开的通道不一样）。'],
  // ── 「向设备问取流地址」那一步的七种落点 ──
  // ★ 这一批的共同点：地址问不出来，下一步就没东西可验 —— 所以话术全都在说
  //   「那这一格怎么补」，而不是复述 ONVIF 回了什么。
  'cause-onvif-auth': ['设备要账号才肯说取流地址', 'warn',
    '401 是它答了、只是不放行，不是设备坏了。★ 很多相机把 ONVIF 账号和 Web 登录账号分开管，'
    + '拿后台密码来问 ONVIF 问不通是常态 —— 去它自己的「用户 / ONVIF 设置」里单加一个。'],
  'cause-port-not-onvif': ['那个端口上不是 ONVIF', 'warn',
    '连得上、也回了话，可回的不是 ONVIF 应答。★ 先照上面那一步自己那句话办：它要是说「那个端口说的是 HTTPS」，'
    + '把地址前缀改成 https:// 再问一次就好，这不是故障；它回的是一页网页，那地址就得去后台的「取流 / 网络」页里抄。'],
  'cause-onvif-unsupported': ['这台不接 ONVIF 的这一问', 'warn',
    '包它认、账号也过了，可它回一句「不会这一问」。ONVIF 是分档实现的（S / T / M），'
    + '只做设备档的就没有媒体服务。★ 这不必去翻密码，要确认的是这台到底支持到哪一档。'],
  'cause-onvif-no-media': ['身份问到了，可说 RTSP 的那一路没问出来', 'warn',
    '它肯报自己是哪台，但几路流、地址在哪这一路没答上来（媒体服务没起、挂在别的端口上，'
    + '或者它只给了 http 那一路 —— 下一步只会说 RTSP）。★ 这路地址我们问不出来：'
    + '去设备后台抄一条填在高级的「网址」里，这一步就接着往下问。'],
  'cause-onvif-no-profile': ['设备自己说它一条码流都没配', 'bad',
    '媒体服务答得清清楚楚：0 路。这就不是链路、也不是账号的事 —— 是那个通道没出码流。'
    + '去设备上把主 / 子码流建出来，配好再问一次地址。'],
  'cause-onvif-silent': ['端口开着，可它不回 ONVIF 这一问', 'bad',
    '连上了一个字都没回 —— 和「连不上」是两种病，这一种多半是那个服务卡住了，'
    + '或者它压根不在这端口上应答。★ 先看设备的 Web 后台打得开吗，再对端口号。'],
  'cause-onvif-unreachable': ['ONVIF 那一问连都连不出去', 'warn',
    '默认 80 没人应 —— 各家会把 ONVIF 挪到 8899 / 2020 / 8080，或者只在 https 上。'
    + '★ 先进后台确认它开了 ONVIF、端口是多少；有取流地址的话直接填到高级的「网址」里，这一步就绕过去了。'],
  // ── 「拉平台那份清单」那一步的十种落点（手里那一路是平台给的 m3u8）──
  // ★ 这一批和上面那批的区别只有一句话：中间隔着一层平台。
  //   设备肯给流 ≠ 平台这份清单还在往前挪，所以话术全在说「这一步查谁」。
  'cause-hls-ok': ['平台这一路是活的，「没画面」在播放那一侧', 'warn',
    '★ 清单在往前挪、抽查的分片取得到、码率也量得出来 —— 推流和平台这两段都没事。'
    + '去查客户端：编码是 H.265 的话浏览器基本不放（换 H.264 那一路）、'
    + '播放器切没切到这一路、平台到客户端那一段（CDN / 反向代理）有没有换地址。'],
  'cause-hls-stalled': ['清单还写着，可窗口一片没往前挪', 'bad',
    '★ 这一档最坑人：地址对、不报错、页面上看着一切正常，可连着两次拉的清单里'
    + '那几片一模一样 —— 源头早就不往前推了，平台只是照着旧清单继续发。'
    + '别在平台日志里找错，去推流那侧看编码器的码率曲线（多数已经掉到 0）；'
    + '顺带确认这台是不是只有被人看时才出流（按需取流的设备一断观看就停推）。'],
  'cause-hls-segment-missing': ['清单点名的分片，源上取不到', 'bad',
    '清单是新的、分片却回 404 / 403 —— 平台内部对不上号。★ 多是清理策略与窗口对不齐：'
    + '留的片数比清单承诺的少，或者分片落在多台节点上而存储没共享（问到 A 节点、'
    + '清单是 B 节点写的）。先在平台上换一路地址再问一次，只有一路这样就是这一路的配置。'],
  'cause-hls-empty': ['清单是空的，一条分片都没点', 'bad',
    '★ 这一路此刻没有内容 —— 要么刚点开播还没推上来，要么设备到平台那一段断了。'
    + '过十几秒再问一次：仍然空就去查推流端（它有没有在发），'
    + '不空就是刚起来那一下没画面，不用改任何东西。'],
  'cause-hls-target-over': ['能播，但每一片都比承诺的长', 'warn',
    '清单写着「一片最多 N 秒」，实测那片比这还长。★ 起播没问题，'
    + '播放器会反复缓冲、画面越播越往后拖 —— 现场读成「卡」而不是「坏」。'
    + '这是编码端的 GOP / 切片间隔改了而平台没跟着改承诺值，两边对一遍。'],
  'cause-hls-auth': ['平台要账号才给这份清单', 'warn',
    '★ 401 / 403 是它答了、只是不放行，不是这一路坏了。'
    + '清单地址常常带着有时效的签名参数（token 过期就是这一档）：地址要从页面上现抄，'
    + '别把昨天那条存成书签。用固定账号访问就在本卡的高级里填，口令不进结果。'],
  'cause-hls-not-found': ['这个路径上没有这路清单', 'bad',
    '平台在、这个应用名下没有这条流。★ 流名 / 应用名对不上是主因，'
    + '再确认这一路在平台上起没起（很多平台只在有人订阅时才生成清单，那是空清单不是 404）。'],
  'cause-hls-not-hls': ['它答话了，答的不是清单', 'warn',
    '★ 拿回来的东西认不出是 m3u8 —— 那个地址多半是网页、裸流（FLV / MP4）或别的服务，'
    + '结果里 looksLike 那一栏说了它像什么。对上是 FLV 就去问 RTSP 或 HTTP-FLV 那一路，'
    + '是一页网页说明抄地址抄到了后台页面上。'],
  'cause-hls-unreach': ['连不上平台的那个口', 'bad',
    '★ 先看结果里 reach 那一栏：closed 是机器在、这个口上没服务（端口或前缀错了）；'
    + 'filtered 是它一句都不答（防火墙只放行了白名单）。这两种下一步完全不同，别并成「网络不通」。'],
  'cause-hls-timeout': ['连上了，可它到点没回话', 'bad',
    'TCP 是建起来了，问一句清单过去半天不回。★ 平台的清单接口挂住了：'
    + '它自己在等上游、或者后端取流慢把接口一起拖死。换个时段再问一次，'
    + '同时问一段平台上别的路 —— 别的路也这样就是平台，只有这一路就是这路。'],
  'cause-stream-auth': ['问到了，只是不让看', 'warn',
    '★ 401 不是设备坏了，是它答了并且认得这个请求。核对账号密码，再确认这个账号'
    + '对该通道有取流权限 —— 现场十次有八次是权限而不是密码。'],
  'cause-port-not-rtsp': ['那个口接了 TCP，却不说 RTSP', 'bad',
    '★ 端口是开的、连接也建了，但对面不认 RTSP 这句话 —— 多半是端口号填错了：'
    + '554 才是 RTSP，80 是 Web 管理页，8000 / 8200 是各家私有 SDK 的口子。'
    + '对着「扫一片端口」那一行看它到底开的是哪个口，再改地址里的端口。'],
  'cause-stream-missing': ['设备答了，但这个通道上没有这路流', 'bad',
    '设备是好的、账号是好的，只有路径不对。★ 海康是 /Streaming/Channels/101，'
    + '大华是 /cam/realmonitor?channel=1&subtype=0 —— 通道号和主/子码流就差最后那几位。'],
  'cause-stream-broken': ['设备应了，但这路流没配出媒体轨', 'bad',
    '连上、认证都过了，DESCRIBE 的应答里一条媒体轨都没有 —— 这不是「拉不到画面」，'
    + '是设备上那一通道根本没出码流。去设备那侧确认通道已启用、码流（主/子）已配置，'
    + '再换一条路径问一次。'],
  'cause-stream-no-data': ['它答应给流，可一个包都没来', 'bad',
    '★ 轨有、账号过、PLAY 也回了 200 —— 前面几步全对，唯独码流没到本机。'
    + '先确认这台让不让第二路取流（多数型号只开一路，平台正在拉时它就这么答）；'
    + '再分清是哪一路没通：走 UDP 时收流用的是本机一批临时偶数口，'
    + '隔了 NAT 或防火墙只看已知服务口，包就回不来 —— 换 TCP 交织再问一次，'
    + 'TCP 收得到就是那批 UDP 口被挡，不是设备没发。'],
  'cause-stream-ok': ['流在播，「没画面」是那头的显示侧', 'warn',
    '★ 这一条的作用是把人从设备前叫走：它肯给流、编码和分辨率都对。'
    + '查客户端的解码能力、播放器那边收没收到、或者平台有没有把这路转发出去。'],
  'cause-egress-blocked': ['路到得了出口那台机器，却连不上它那个口', 'bad',
    '局域网好、解析也正常、路径也追到了，就是连不上那个端口 —— 拦在中间或出口那一段：'
    + 'NAT 没做、ACL 只放行了内网、或者认证门户还没过。★ 这一档不该去查终端设备。'],
  'cause-wrong-scheme': ['协议前缀写反了', 'warn',
    '明文口写成 https（或反过来）。★ 这不是慢，是先撞一次再重试 —— 所以症状看着像「慢」，'
    + '改个前缀就消失。取流地址用 rtsp://，别用 http://。'],
};

// 每一步给人看的那几项取值。★ 后端按 shows 挑好了给人看的字段，这里只负责说清是什么。
const TREE_FACT = {
  first: '先坏在', count: '一共几条', multiDefault: '同族默认路由',
  iface: '出口网卡', destination: '目的', direct: '是不是直连', from: '这个结论从哪来',
  sent: '发出', recv: '收到', received: '收到', lossPercent: '丢包率',
  jitterAvgMs: '抖动', rttMaxMs: '最大往返', rttAvgMs: '平均往返', spikes: '尖峰在第几发',
  lostAt: '丢在第几发',
  rcode: '应答码', server: '问的是哪台服务器', elapsedMs: '用时', eyeballs: '两族谁先连上',
  family: '地址族', hopsSeen: '见到几跳', engine: '用什么测的',
  lossHop: '丢包从第几跳起', latencyHop: '变慢从第几跳起', goalSeen: '见到终点',
  roundsDone: '跑完几轮', target: '问的是', open: '开着的口', closed: '关着的口',
  transport: '收流走的口子', bitrateKbps: '实际码率',
  filtered: '一个都没回', scanned: '扫了几个口', openPorts: '开着的端口清单',
  subnets: '扫的网段', alive: '在有几台', asked: '问了几个地址', hosts: '清单',
  notAfter: '到期时间', notBefore: '生效时间', issuer: '签发者', subject: '证书上的名字',
  protocol: '谈成的协议版本', daysLeft: '还剩几天', status: '状态', timings: '各段耗时',
  url: '地址', offsetMs: '差了多少', checkedWith: '问的是哪台时间源',
  agreeSources: '互相印证的源', attribution: '是谁不对', codec: '编码',
  width: '宽', height: '高', trackCount: '有几路轨', answers: '解出来的地址',
  manufacturer: '它自报是哪台', model: '型号', profileCount: '它自报几路码流',
  mediaUri: '问出来的取流地址',
  // 平台清单那一步（media.hls.probe）给人看的几项
  httpStatus: '它回的', segmentCount: '清单里有几片', windowSec: '窗口多长',
  windowAdvanced: '窗口往前挪了', mediaSequence: '序号起点',
  pathMtu: '路上允许的包长', suggestion: '建议设成', mtu: '这块口的 MTU',
  lossAt: '丢在第几发',
  // 双栈那一步里 Happy Eyeballs 那几项
  code: '读数', preferred: '先试', winner: '连上的是', stallMs: '要卡',
  worstMs: '最坏卡', connDelayMs: '多久回落', willStall: '会不会先卡',
  // 网页探测那一步的分段耗时
  lookupMs: '解析', connectMs: '建连', tlsMs: 'TLS', serverMs: '服务端', totalMs: '合计',
};

// 布尔值在人话里必须带上「是谁给的」：direct=true 是「按表算着像直连」，不是「一定直连」。
const TREE_YESNO = { direct: ['算直连', '不算直连'], goalSeen: ['见到了', '没见到'],
  // 清单窗口那一格：★「一动不动」和「没问」是两件事，没问时后端根本不给这一栏。
  windowAdvanced: ['往前挪了', '一片没换'] };

function treeFactWord(k, v) {
  if (typeof v === 'boolean') {
    // 布尔值也要有个名字：直接印 true/false 等于没译。
    const t = TREE_YESNO[k] || ['是', '否'];
    return v ? t[0] : t[1];
  }
  if (typeof v === 'number') return /Ms$/.test(k) ? ms(v) : `${v}`;
  return esc(v);
}

function treeFactVal(k, v) {
  if (v === null || v === undefined || v === '') return '<span class="dim">—</span>';
  if (k === 'first') return esc(CK_STEP[v] || v); // 体检那一步说「先坏在」哪一项，用同一套词
  // 套在事实里的小判定（双栈那一步的 eyeballs 读数）用同一张字典，别露英文码。
  if (k === 'code' && DS_EYEBALLS[v]) return esc(DS_EYEBALLS[v][0]);
  if (Array.isArray(v)) {
    if (!v.length) return '<span class="dim">一条都没有</span>';
    const items = v.slice(0, 4).map((x) => {
      if (x && typeof x === 'object') {
        // 主机 / 解析结果那一类：优先给地址，再给它凭什么在线。
        const addr = x.addr || x.ip || x.address || x.name || x.value || '';
        const ev = x.evidence ? `（${esc(EVIDENCE[x.evidence] ? EVIDENCE[x.evidence][0] : x.evidence)}）` : '';
        const mac = x.mac ? `<span class="dim"> ${esc(x.mac)}</span>` : '';
        if (addr) return `${esc(addr)}${ev}${mac}`;
        return esc(Object.entries(x).slice(0, 2).map(([kk, vv]) => treeFactWord(kk, vv)).join(' '));
      }
      return esc(String(x));
    });
    const more = v.length > 4 ? `<span class="dim"> 等 ${v.length} 条</span>` : '';
    return `${items.join('、')}${more}`;
  }
  if (typeof v === 'object') {
    return Object.entries(v)
      .map(([kk, vv]) => `<span class="dim">${esc(TREE_FACT[kk] || kk)}</span> ${treeFactVal(kk, vv)}`)
      .join('　');
  }
  return treeFactWord(k, v);
}

function treeFacts(f) {
  const e = Object.entries(f || {});
  if (!e.length) return '<span class="dim">—</span>';
  return e.map(([k, v]) => `<span class="dim">${esc(TREE_FACT[k] || k)}</span> ${treeFactVal(k, v)}`)
    .join('<br>');
}

function treeArgs(a) {
  const e = Object.entries(a || {});
  if (!e.length) return '<span class="dim">—（这一步不带参数）</span>';
  // ★ 后端已经把口令和团体名换成占位词了；这里只是别把它们摊成一大片。
  return e.map(([k, v]) => `<code>${esc(k)}=${esc(treeArgWord(k, v))}</code>`).join(' ');
}

function treeArgWord(k, v) {
  if (typeof v === 'boolean') return v ? '是' : '否';
  if (typeof v === 'object') return JSON.stringify(v);
  return v;
}

function treeStepRow(s, i) {
  const st = TREE_STATUS[s.status] || [s.status || '—', 'bad', ''];
  const codePill = s.code === 'tool-missing'
    // ★ 这一条不是网络的读数，是我们那张表写错了 —— 必须说成我们的锅。
    ? '<span class="pill bad">路线里写着它，可它没注册</span>'
    : treeCodePill(s.step, s.code);
  const why = s.note || s.toolNote || st[2];
  return `<tr>
    <td class="dim">${i + 1}</td>
    <td>${esc(s.stepName || s.step)}<div class="dim"><code>${esc(s.tool)}</code></div></td>
    <td>${treeArgs(s.args)}</td>
    <td><span class="pill ${st[1]}">${esc(st[0])}</span></td>
    <td>${codePill || '<span class="dim">没有判定</span>'}${why ? `<div class="dim" style="margin-top:3px">${esc(why)}</div>` : ''}</td>
    <td>${treeFacts(s.facts)}</td>
  </tr>`;
}

function troubleCard() {
  const card = $(`<div class="card">
    <h2>按症状排查 <span id="tr-top"></span></h2>
    <p class="hint">上面那张体检是「全过一遍」，这一张是<b>你说一句症状，我按工程师的顺序只走那一条路</b>，
      停在第一个能解释它的判定上。★ 每一步都写明「问了什么工具、答了什么、所以接下来问什么」，
      没问出去的那几步也留着 —— 那份推理路径可以直接拿去跟二线对质，比一句「网络没问题」有用。
      全程只读、不发多余的包、不改任何东西。</p>
    <div class="row">
      <div style="flex:0 0 250px"><label>哪一句症状</label>
        <select id="tr-s">${Object.entries(SYMPTOM).map(([k, v]) =>
          `<option value="${k}">${esc(v[0])}</option>`).join('')}</select></div>
      <div><label>目标（地址或域名）</label>
        <input id="tr-t" placeholder="192.168.1.64 或 cam.example.com"></div>
      <div style="flex:0 0 110px"><label>端口</label><input id="tr-p" placeholder="554 / 443"></div>
    </div>
    <p class="hint" id="tr-hint" style="margin-top:8px"></p>
    <div id="tr-auth" style="display:none;margin-top:10px">
      <div class="row">
        <div><label>账号（问设备取流时用）</label><input id="tr-u" autocomplete="off"></div>
        <div><label>口令</label><input id="tr-w" type="password" autocomplete="off"></div>
        <div><label>SNMP 团体名</label><input id="tr-c" autocomplete="off"></div>
      </div>
      <p class="dim" style="margin-top:6px">★ 填在这里的口令和团体名<b>不会</b>出现在结果、推理路径或诊断包里
        —— 路径上只留「给了、但没写出来」，所以「配了但没给你看」和「没配」在结果里分得开。</p>
    </div>
    <details style="margin-top:8px"><summary class="dim">高级：换网址 / 多个端口 / 只在哪块网卡上找 / 跑多久</summary>
      <div class="row" style="margin-top:10px">
        <div><label>网址（慢、证书报错时给具体地址；取流给 rtsp://）</label>
          <input id="tr-x" placeholder="https://192.168.1.20 或 rtsp://..."></div>
        <div style="flex:0 0 170px"><label>要看好几个端口</label><input id="tr-ps" placeholder="554,80,8000"></div>
      </div>
      <div class="row" style="margin-top:10px">
        <div style="flex:0 0 190px"><label>只在这块网卡上找</label><input id="tr-i" placeholder="en0 / eth0"></div>
        <div style="flex:0 0 120px"><label>单发等待 ms</label><input id="tr-to" placeholder="默认 2000"></div>
        <div style="flex:0 0 130px"><label>这棵树最长跑几秒</label><input id="tr-ms" placeholder="默认 120"></div>
        <div style="flex:0 0 150px"><label>&nbsp;</label>
          <label class="dim"><input type="checkbox" id="tr-q"> 快一点（少发几发，先要个方向）</label></div>
      </div>
    </details>
    <div style="margin-top:12px"><button class="btn primary" id="tr-go">开始排查</button></div>
    <div id="tr-out" style="margin-top:14px"></div>
  </div>`);
  const out = card.querySelector('#tr-out');
  const top = card.querySelector('#tr-top');
  const pick = card.querySelector('#tr-s');
  const hint = card.querySelector('#tr-hint');
  const auth = card.querySelector('#tr-auth');
  const sync = () => {
    hint.textContent = SYMPTOM[pick.value][1];
    // ★ 凭据那一栏只在会用得着它的那一句症状下现身。
    auth.style.display = pick.value === 'device-down' ? '' : 'none';
  };
  pick.onchange = sync;
  sync();

  card.querySelector('#tr-go').onclick = async () => {
    top.innerHTML = '';
    const args = { symptom: pick.value };
    const put = (id, key, asNumber) => {
      const x = card.querySelector('#' + id).value.trim();
      if (!x) return;
      args[key] = asNumber ? Number(x) : x;
    };
    put('tr-t', 'target'); put('tr-p', 'port', true); put('tr-ps', 'ports');
    put('tr-x', 'url'); put('tr-i', 'iface'); put('tr-to', 'timeoutMs', true);
    put('tr-ms', 'maxSeconds', true);
    put('tr-u', 'username'); put('tr-w', 'password'); put('tr-c', 'community');
    if (card.querySelector('#tr-q').checked) args.quick = true;
    out.innerHTML = `<div class="empty">排查中…（按顺序只走那一条路，最长 ${args.maxSeconds || 120} 秒 ——
      逐跳和连续 ping 那几步要多发几发，稍等）</div>`;
    const r = await call('net.troubleshoot', args);
    if (!r.ok) {
      top.innerHTML = '';
      out.innerHTML = `<div class="empty">没跑起来：${esc(r.message || r.error)}</div>`;
      return;
    }
    const v = r.values || {};
    const steps = v.steps || [];
    const [tTitle, tCls, tAdvice] = TREE_CAUSE[r.verdict] || TREE_TOP[r.verdict]
      || [r.verdict, 'warn', ''];
    top.innerHTML = `<span class="pill ${tCls}">${esc(tTitle)}</span>`;
    const idx = steps.findIndex((s) => s.step === v.causeStep);
    const bg = tCls === 'ok' ? 'var(--green-bg)' : tCls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = tCls === 'ok' ? 'var(--green-dim)' : tCls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const causeFacts = treeFacts(v.causeFacts);
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(tAdvice)}
        ${idx >= 0 ? `<div class="dim" style="margin-top:6px">定位在第 ${idx + 1} 步（${
          esc(v.causeName || v.causeStep)}）—— 那一步的依据：${causeFacts}</div>` : ''}
      </div>
      <p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>
      <table style="margin-top:12px">
        <tr><th></th><th>按排查顺序</th><th>问了什么</th><th>状态</th><th>判定</th><th>依据</th></tr>
        ${steps.map(treeStepRow).join('')}
      </table>
      <p class="hint" style="margin-top:10px">★ 一共问了 ${v.asked || 0} 步。状态写成「没问出去」或「没问到这一步」的那些，
        就是这份结论的边界 —— 想让它们也问出结果，把「目标」填实，或者去高级里把时间调够。</p>
      <p class="hint" style="margin-top:6px">每一步的判定用的就是那一页同一个工具的判定，话术一份都没有重写。
        想单独把某一步问细，去下面「出问题了」以外的对应页。</p>
      <details style="margin-top:10px"><summary class="dim">原始结果</summary>
        <pre class="dim">${esc(JSON.stringify(r.raw, null, 2))}</pre></details>`;
  };
  card.querySelector('#tr-t').onkeydown = (e) => { if (e.key === 'Enter') card.querySelector('#tr-go').click(); };
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
