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
  noteCall(current, tool, body && body.verdict);
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
 * ★★ 导航：一栏全露出（老板 2026-09-30：「想用什么功能还找不到」「新用户完全用不明白」）。
 *
 *   上一版是两层平铺按钮（八个组一排 + 组内几页一排），2026-09-25 那次是为了治
 *   「十五张卡堆在一页」，但它换来一个新问题：**进哪一组要先猜对问题的归类**。
 *   「摄像头没画面」属于「谁在网里」还是「出问题了」？猜错一次，整排按钮重画一遍，
 *   人就在八组里来回点。量到的另一条更硬：冷启动从 localStorage 恢复到的页
 *   如果在别的组，第一行高亮与第二行页签全是第一组的 —— 页面已经是抓包，
 *   导航还指着「网卡与路由」，等于每次开机先撒一句谎。
 *
 *   现在：左侧一栏把 23 页一次全露出（组名只当小节标题），顶部一颗搜索钮
 *   把「打一个字就跳到位」补上，页头那一条写清「这一页回答什么」。
 *   硬规矩不变：每组不超过 4 页、每页不超过 5 张卡，再多就继续拆页，不许在页里堆。
 *
 * ★ 卡片与工具的对应关系**不在这里手抄** —— 那份事实本来就在下面各 render 函数里，
 *   由 scripts/page-index.cjs 用 AST 量出来生成 page-index.js，--check 钉住不漂。
 *   再抄一份映射表就是第四副本，历史上「界面说没做、后端其实做了」就是这么来的。
 */
const PAGES = [
  { g: '', pin: true, id: 'home', name: t('总览'), render: renderHome },

  { g: t('这台机器'), id: 'nic', name: t('网卡与路由'), render: renderNIC },
  { g: t('这台机器'), id: 'dhcp', name: t('DHCP 分地址'), render: renderDHCP },
  { g: t('这台机器'), id: 'local', name: t('本机端口与文件共享'), render: renderLocal },

  { g: t('通不通'), id: 'connect', name: t('ping 与端口'), render: renderConnect },
  { g: t('通不通'), id: 'path', name: t('路径与质量'), render: renderPath },
  { g: t('通不通'), id: 'name', name: t('域名与时间'), render: renderName },
  { g: t('通不通'), id: 'service', name: t('网站与证书'), render: renderService },

  { g: t('快不快'), id: 'thru', name: t('两台机器对测'), render: renderThru },
  { g: t('快不快'), id: 'speed', name: t('出去公网有多快'), render: renderSpeed },
  { g: t('快不快'), id: 'quality', name: t('盯一段时间'), render: renderQuality },
  { g: t('快不快'), id: 'bandwidth', name: t('谁在吃流量'), render: renderBandwidth },

  { g: t('谁在网里'), id: 'scan', name: t('网段上有哪些地址'), render: renderScan },
  { g: t('谁在网里'), id: 'device', name: t('设备是谁'), render: renderDevice },
  { g: t('谁在网里'), id: 'stream', name: t('摄像头取流'), render: renderStream },
  { g: t('谁在网里'), id: 'switch', name: t('交换机（SNMP）'), render: renderSwitch },

  { g: t('网长什么样'), id: 'topo', name: t('拓扑图'), render: renderTopo },

  { g: t('出问题了'), id: 'checkup', name: t('一键体检与诊断包'), render: renderCheckup },
  { g: t('出问题了'), id: 'trouble', name: t('按症状排查'), render: renderTrouble },
  { g: t('出问题了'), id: 'capture', name: t('抓包看内容'), render: renderCapture },

  { g: t('管别的机器'), id: 'remote', name: t('远程设备与审计'), render: renderRemote },
  { g: t('管别的机器'), id: 'remote-work', name: t('连上去干活'), render: renderRemoteWork },
  { g: t('管别的机器'), id: 'mobile', name: t('手机互联与投屏'), render: renderMobile },

  { g: t('工具箱'), id: 'tools', name: t('算子网 / MAC / 编解码'), render: renderTools },
];

/*
 * ★ 每一页开头那一句「这一页回答什么」。页名是名词（网卡与路由），
 *   现场的人要的是一问（我到底在问它什么）—— 上一版这句写在卡片里，
 *   五张卡五种写法，滚到底才看得见；现在它钉在页头，跟着标题走。
 */
const PAGE_ASK = {
  home: t('先说这台机器现在怎么样，再把全部功能摊开给你看'),
  nic: t('我这块网卡拿到了什么地址、走哪条路出去'),
  dhcp: t('让这台电脑给交换机上的设备分 IP，并盯住谁拿到了地址'),
  local: t('本机哪个端口被人占着、哪个目录正被人取走'),
  connect: t('这个地址答不答、这个端口开不开、这个网段上有没有它'),
  path: t('中间走了几跳、哪一跳开始丢、大包能不能过'),
  name: t('域名解析成什么、v4 与 v6 是不是都能出、本机时钟准不准'),
  service: t('这个网址通不通、慢在哪一段、证书还剩几天'),
  thru: t('两台机器之间此刻能吃下多少带宽'),
  speed: t('出去公网有多快，v4 与 v6 各算一本账'),
  quality: t('连着盯一段时间，把「有时候卡一下」问成一本能翻的账'),
  bandwidth: t('这几十秒本机的带宽被哪个进程、哪块网卡吃了'),
  scan: t('这个网段上现在有谁、它们各自凭什么证据被判在线'),
  device: t('这个地址是哪台设备、有没有还没配 IP 的盒子、叫得醒谁'),
  stream: t('这一路取流取不到，是断在地址、认证、信令还是媒体'),
  switch: t('谁插在哪个口、口跑多快、给没给电、丢包了没有'),
  topo: t('把这些探测合成一张图：这台机器眼里的网长什么样'),
  checkup: t('什么都不用填，先问一遍哪里坏了，再打包发给不在现场的人'),
  trouble: t('给一个症状，按工程师的顺序只走那一条排查路'),
  capture: t('里面到底跑了什么：抓下来，按流聚合成一张能对账的表'),
  remote: t('登记过的设备、刚才对哪台做过什么、对方屏幕上有没有提示'),
  'remote-work': t('连上一台干活：敲命令、传文件、发消息、开桌面、跑剧本'),
  mobile: t('手机扫码进来传文件、投屏，不装任何东西'),
  tools: t('算网段、看 MAC 来路、解编码 —— 不用开终端'),
};

// 卡片都是小表单的页才并排成两栏；带表格的一律单栏（并排是为了密度，不是为了好看）。
const GRID = new Set(['connect', 'name', 'service', 'tools', 'speed', 'bandwidth', 'scan', 'device']);

const GROUPS = [...new Set(PAGES.filter((p) => !p.pin).map((p) => p.g))];

// ★ 换语言是整页重跑（i18n.js 的 setLang 里写了为什么必须重跑）。既然要重跑，
//   就得把「人在哪一页」留住 —— 不然点一下语言钮，人就被扔回第一页，
//   而他刚才是停在抓包那一页上等结果的。存这一格比让 setLang 就地重画便宜得多：
//   就地重画省不下任何东西（结果本来就是重建成空白的），却换不来那三十多张码表换语言。
const PAGE_KEY = 'netkit.page';
let current = (() => {
  try {
    const id = localStorage.getItem(PAGE_KEY);
    return id && PAGES.some((p) => p.id === id) ? id : 'home';
  } catch (_) { return 'home'; }
})();
// 组不再是状态 —— 它永远等于「当前那一页所在的组」。上一版把它单独存了一份，
// 于是冷启动恢复别的组的页时，导航和内容的这一格先对不上一次。
let group = (PAGES.find((p) => p.id === current) || PAGES[0]).g;

// ★ 画具的代号：每重画一屏就 +1。页里的异步结果回来时先对一代，
//   代不对就是人已经换页了 —— 那一趟的活作废，不许往已经拆掉的节点里写。
let gen = 0;

function navBtn(p) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'navp' + (p.id === current ? ' on' : '');
  b.textContent = p.name;
  b.title = PAGE_ASK[p.id] || '';
  b.onclick = () => goto(p.id);
  return b;
}

function renderNav() {
  const nav = document.getElementById('nav');
  nav.innerHTML = '';
  const top = document.createElement('div');
  top.className = 'navtop';
  for (const p of PAGES) if (p.pin) top.appendChild(navBtn(p));
  nav.appendChild(top);
  for (const g of GROUPS) {
    const sec = document.createElement('div');
    sec.className = 'navgrp';
    const h = document.createElement('div');
    h.className = 'navgh';
    h.textContent = g;
    sec.appendChild(h);
    for (const p of PAGES) if (p.g === g) sec.appendChild(navBtn(p));
    nav.appendChild(sec);
  }
}

/** 跳去某一页；opts.card / opts.ent 到了那一页再生效（见 applyPending）。 */
let pending = null;
function goto(id, opts) {
  const p = PAGES.find((x) => x.id === id);
  if (!p) return;
  pending = opts || null;
  if (id === current) { show(); return; }
  current = id;
  group = p.g;
  renderNav();
  show();
}

/** 换页要断掉的轮询。★ 少断一个，就是拿别人的屏幕当轮询靶子（下面逐条写了为什么）。 */
function stopAllTimers() {
  // ★ DHCP 那页的租约轮询只在停在那一页时才该跑：换页后它还每 2.5 秒发一次请求，
  //   而且往**当前这页**的 #leases 里写
  clearInterval(pollTimer); pollTimer = null;
  // ★ 对测口那本台账每 3 秒问一次
  clearInterval(thruTimer); thruTimer = null;
  // ★ 监测状态每 3 秒问一次
  clearInterval(qualityTimer); qualityTimer = null;
  qualityPick = null;
  // ★ 抓包那一路的计数每 3 秒问一次；capPick 留着会让流表上的
  //   「看这一条」在换页之后仍往已经拆掉的明细卡里写
  clearInterval(capTimer); capTimer = null;
  capPick = null;
  // ★ 对端那一路也一样：换页之后还每 3 秒发一次 net.capture.peer.status，
  //   而每一次都要开一条 SSH 去问别人家的机器 —— 那不为本页服务的请求不该留
  clearInterval(peerCapTimer); peerCapTimer = null;
  // ★★ 下面这两扇是上一版漏掉的：文件共享的取用台账、手机门户的状态，
  //   都只在「自己那一页点了停止」时才关，换页不关。
  //   症状不是报错，是**换到别的页还在每 3 秒往已经拆掉的节点里写**。
  clearInterval(fsTimer); fsTimer = null;
  clearInterval(portalTimer); portalTimer = null;
}

async function show() {
  const main = document.getElementById('main');
  stopAllTimers();
  const p = PAGES.find((x) => x.id === current) || PAGES[0];
  current = p.id;
  group = p.g;
  try { localStorage.setItem(PAGE_KEY, String(p.id)); } catch (_) { /* 存不上就这一趟不回页 */ }
  main.className = GRID.has(p.id) ? 'grid' : '';
  main.innerHTML = '';
  if (p.id !== 'home') main.appendChild(pageHead(p));
  try {
    await p.render(main);
  } catch (e) {
    main.appendChild($(t('<div class=\"card\">这一页没画出来：{0}</div>', [esc(String(e && e.message || e))])));
  }
  bindEnts(main);
  decorate(main);
  renderRail(p);
  applyPending();
}

/** 页头那一块：页名 + 这一页回答什么 + 相关页（相关页是从源码正文里量出来的，不是手配的）。 */
function pageHead(p) {
  const el = document.createElement('div');
  el.className = 'pagehead';
  const ask = PAGE_ASK[p.id];
  el.innerHTML = `<h2>${esc(p.name)}</h2>` + (ask ? `<p class="ask">${esc(ask)}</p>` : '');
  const refs = ((typeof PAGE_INDEX === 'object' ? PAGE_INDEX[p.id] : null) || {}).refs || [];
  if (refs.length) {
    const row = document.createElement('div');
    row.className = 'rel';
    const lbl = document.createElement('span');
    lbl.className = 'lbl';
    lbl.textContent = t('相关页');
    row.appendChild(lbl);
    for (const id of refs) {
      const q = PAGES.find((x) => x.id === id);
      if (!q) continue;
      const b = document.createElement('button');
      b.className = 'btn';
      b.type = 'button';
      b.style.cssText = 'font-size:12.5px;padding:2px 9px';
      b.textContent = q.name;
      b.onclick = () => goto(q.id);
      row.appendChild(b);
    }
    el.appendChild(row);
  }
  return el;
}


// ── 壳层的五件事：能力表 / 装饰层 / 上下文栏 / 搜索 / 此刻在跑 ──

/*
 * ★ 这一节里没有任何「功能」—— 功能全在后端的 95 个工具里。
 *   这一节只回答一个问题：**人怎么知道自己可以问什么**。
 *   所以它不许自己攒任何清单：页与页的关系、页与工具的关系，
 *   一律从 page-index.js（由源码量出来的）和 GET /tools（后端活报的）来。
 */

const PIDX = (typeof PAGE_INDEX === 'object' && PAGE_INDEX) || {};

// 工具名 → {page, card}。一个工具被几处用就取头一处（跳转只要落得准）。
// ★ 总览那一页要排除：它确实调了 net.checkup，但它是「索引」，不是这张工具的归属地 ——
//   算进来会让「net.checkup 用在哪」答成「总览」，人点了却落在一张没有表单的第一屏上。
const PINNED = new Set(PAGES.filter((p) => p.pin).map((p) => p.id));
let HOST = {};
function buildHost() {
  HOST = {};
  for (const [pid, rec] of Object.entries(PIDX)) {
    if (PINNED.has(pid)) continue;
    for (const c of (rec.cards || [])) {
      for (const tn of (c.tools || [])) if (!HOST[tn]) HOST[tn] = { page: pid, card: c.t };
    }
    for (const tn of (rec.tools || [])) if (!HOST[tn]) HOST[tn] = { page: pid, card: '' };
  }
}

// ★ 能力表从后端活读：界面上任何「一共多少项」的说法都由它现算。
//   写死一个数就是埋一颗雷 —— 加一个工具那天起，屏上那句话开始撒谎。
let TOOLS = [];
async function loadTools() {
  try {
    const r = await fetch(`${API}/tools`);
    const j = await r.json();
    TOOLS = Array.isArray(j.tools) ? j.tools : [];
  } catch (_) { TOOLS = []; }
  buildHost();
}
const toolOf = (n) => TOOLS.find((x) => x.name === n);
const isMut = (n) => (toolOf(n) || {}).class === 'mutate';

/* ── 问过什么（只记工具名与判定码，绝不记参数 —— 参数里有凭据） ── */

const HIST_KEY = 'netkit.history';
let HIST = (() => {
  try { return JSON.parse(localStorage.getItem(HIST_KEY) || '[]') || []; } catch (_) { return []; }
})();
function noteCall(page, tool, verdict) {
  if (!page || !tool) return;
  HIST.unshift({ at: Date.now(), page, tool, verdict: typeof verdict === 'string' ? verdict : '' });
  if (HIST.length > 120) HIST.length = 120;
  try { localStorage.setItem(HIST_KEY, JSON.stringify(HIST)); } catch (_) { /* 存不上就只活在这一趟 */ }
}
const histFor = (page) => HIST.filter((h) => h.page === page).slice(0, 7);
const stampOf = (ms) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

/* ── 装饰层：结果里出现的地址、页名、原始结果，都该是入口而不是文字 ──
 *
 * ★★ 为什么用 MutationObserver 而不是「渲染完扫一遍」：
 *   这一屏上最该点的东西**几乎都是点完按钮之后才出现的** —— 扫出来的表里那些 IP、
 *   流表里那些地址。只在切页时扫一次，等于给了一张空表做装饰，结果全在装饰之外。
 */
const decoSeen = new WeakSet();
let decoQueued = new Set();
let decoObs = null;
let decoTimer = null;

function decorate(root) {
  if (!decoObs) {
    decoObs = new MutationObserver((recs) => {
      // ★ 这里不能「正在刷就跳过」—— 跳掉的那一批是页面刚 append 的结果，
      //   正好是最该点得动的东西。自己插进去的节点会被 decoSeen 记住，不会再刷一遍，
      //   而按钮／链接里的文字 textNodes 本来就不收，所以也不会自循环。
      for (const r of recs) r.addedNodes.forEach((n) => { if (n.nodeType === 1) queueDeco(n); });
    });
    decoObs.observe(root, { childList: true, subtree: true });
  }
  queueDeco(root);
}

function queueDeco(el) {
  if (decoSeen.has(el)) return;
  decoSeen.add(el);
  decoQueued.add(el);
  // ★ 不用 requestAnimationFrame：窗口最小化 / 后台时 rAF 根本不排，
  //   装饰就整批积压 —— 屏上那些地址一直是死的，直到人把窗口调回来才亮。
  //   定时器在后台只是被压慢，不会停。
  if (decoTimer) return;
  decoTimer = setTimeout(() => { decoTimer = null; flushDeco(); }, 16);
}

function flushDeco() {
  const batch = [...decoQueued];
  decoQueued.clear();
  for (const el of batch) {
    if (!el.isConnected) continue;
    bindEnts(el);
    linkifyRefs(el);
    markEntities(el);
    markRaw(el);
  }
}

const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const normT = (s) => String(s || '').replace(/\s+/g, ' ').trim();
// 屏上有没有汉字：有 → 直接子串匹配；没有（英日韩俄）→ 前后不许再接字母数字，
// 否则英文页名 "Device identity" 会把正文里普通句子也咬一口。
const hasCJK = (s) => /[㐀-鿿぀-ヿ가-힯]/.test(s);

function refRe() {
  const alts = [];
  for (const p of PAGES) {
    if (p.pin) continue;
    alts.push({ text: p.name, id: p.id });
  }
  for (const g of GROUPS) alts.push({ text: g, id: (PAGES.find((p) => p.g === g) || {}).id });
  const uniq = [...new Map(alts.map((a) => [a.text, a])).values()].sort((a, b) => b.text.length - a.text.length);
  const src = uniq.map((a) => {
    const e = escRe(a.text);
    return hasCJK(e) ? e : `(?<![A-Za-z0-9])${e}(?![A-Za-z0-9])`;
  });
  return { uniq, re: new RegExp(src.join('|'), 'g'), test: new RegExp(src.join('|')) };
}

/** 把正文里「去『路径与质量』那一页」这类点名变成真链接（页名取运行时的当页语言，四本词典自动跟上）。 */
function linkifyRefs(root) {
  const { uniq, re, test } = refRe();
  if (!uniq.length) return;
  const byText = new Map(uniq.map((a) => [a.text, a.id]));
  for (const node of textNodes(root, test)) {
    re.lastIndex = 0;
    const frag = document.createDocumentFragment();
    let last = 0;
    let m;
    while ((m = re.exec(node.data))) {
      if (m.index > last) frag.appendChild(document.createTextNode(node.data.slice(last, m.index)));
      frag.appendChild(pageLink(m[0], byText.get(m[0])));
      last = m.index + m[0].length;
    }
    if (!last) continue;
    if (last < node.data.length) frag.appendChild(document.createTextNode(node.data.slice(last)));
    node.parentNode.replaceChild(frag, node);
  }
}

function pageLink(text, id) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'ent pagelink';
  b.textContent = text;
  b.title = t('跳到这一页');
  b.onclick = (e) => { e.stopPropagation(); if (id) goto(id); };
  return b;
}

/** 只收「可以点的地方之外」的文本节点：按钮、链接、输入框里不再嵌一层。 */
function textNodes(root, test) {
  const out = [];
  if (!root || !test) return out;
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(n) {
      if (!n.data || !n.data.trim()) return NodeFilter.FILTER_REJECT;
      const p = n.parentElement;
      if (!p || p.closest('button, a, input, select, textarea, script, style, .pop, .pagehead')) {
        return NodeFilter.FILTER_REJECT;
      }
      return test.test(n.data) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    },
  });
  let n;
  while ((n = w.nextNode())) out.push(n);
  return out;
}

/* ── 实体钮：地址 / MAC 一律点得动 ──
 *
 * ★ 现场的人手里永远有一个「数」—— 扫出来的地址、表里的 MAC、流表里的端点。
 *   上一版这个数只能看：想拿它去 ping，得选中、复制、换页、粘贴。
 *   现在点它，动作直接摆出来。
 */
const ENT_RE = new RegExp([
  '(?:\\d{1,3}\\.){3}\\d{1,3}(?:/\\d{1,2})?(?::\\d{1,5})?',
  '[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){1,7}(?:%[A-Za-z0-9._-]+)?(?:/\\d{1,3})?',
  '(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',
].join('|'), 'g');
const ENT_TEST = new RegExp(ENT_RE.source);

function entKind(tok) {
  if (/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(tok)) return 'mac';
  const v4 = tok.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/\d{1,2})?(?::\d{1,5})?$/);
  if (v4) return 'addr';
  const core = tok.replace(/\/\d{1,3}$/, '').split('%')[0];
  if (!core.includes(':')) return '';
  const groups = core.split(':').filter(Boolean);
  // 时间是 10:32:44 这种三段的纯数字 —— 不许当地址；缩写形式（含 ::）或段里带 a~f 才算。
  if (groups.length < 2) return '';
  if (core.includes('::') || /[a-f]/i.test(core) || groups.length >= 5) return 'addr';
  return '';
}

function markEntities(root) {
  for (const node of textNodes(root, ENT_TEST)) {
    ENT_RE.lastIndex = 0;
    const frag = document.createDocumentFragment();
    let last = 0;
    let m;
    while ((m = ENT_RE.exec(node.data))) {
      const kind = entKind(m[0]);
      if (!kind) continue;
      if (m.index > last) frag.appendChild(document.createTextNode(node.data.slice(last, m.index)));
      frag.appendChild(entBtn(kind, m[0]));
      last = m.index + m[0].length;
    }
    if (!last) continue;
    if (last < node.data.length) frag.appendChild(document.createTextNode(node.data.slice(last)));
    node.parentNode.replaceChild(frag, node);
  }
}

function entBtn(kind, value) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'ent';
  b.dataset.entKind = kind;
  b.dataset.entVal = value;
  b.textContent = value;
  b.title = t('点它问这个地址');
  b.onclick = (e) => { e.stopPropagation(); showEntPop(b, kind, value); };
  return b;
}

const bare = (v) => v.replace(/\/\d{1,3}$/, '').replace(/:\d{1,5}$/, '').split('%')[0];

/** 一个数能问出什么。★ 卡片名用中文原文当 key（跳过去之后再按当页语言找那张卡的 h2）。 */
function entActions(kind, value) {
  const ip = bare(value);
  if (kind === 'mac') {
    return [
      [t('查这个 MAC 的来路'), { page: 'tools', card: 'MAC 地址', kind: 'mac', value }],
      [t('把它叫醒（Wake-on-LAN）'), { page: 'device', card: 'Wake-on-LAN 唤醒', kind: 'mac', value }],
      [t('只抓它的包'), { page: 'capture', card: '这一张流表', kind: 'filter', value }],
    ];
  }
  if (kind === 'addr') {
    return [
      [t('ping 它'), { page: 'connect', card: 'ping 一个地址', kind: 'addr', value: ip }],
      [t('探它的端口'), { page: 'connect', card: '扫一片端口', kind: 'addr', value: ip }],
      [t('看它中间走几跳'), { page: 'path', card: '路径追踪', kind: 'addr', value: ip }],
      [t('它是哪台设备'), { page: 'device', card: '问一遍：这些地址是哪台设备', kind: 'addr', value: ip }],
      [t('去它走哪块网卡'), { page: 'nic', card: '路由表', kind: 'addr', value: ip }],
      [t('当网站问一次'), { page: 'service', card: '网页 / 接口探测', kind: 'url', value: `http://${ip}/` }],
      [t('只抓它的包'), { page: 'capture', card: '这一张流表', kind: 'filter', value: ip }],
    ];
  }
  return [];
}

let popEl = null;
function closePop() { if (popEl) { popEl.remove(); popEl = null; } }
function showEntPop(anchor, kind, value) {
  closePop();
  const pop = document.createElement('div');
  pop.className = 'pop';
  const head = document.createElement('div');
  head.className = 'popv';
  head.textContent = value;
  pop.appendChild(head);
  const add = (label, run) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = label;
    b.onclick = () => { closePop(); run(); };
    pop.appendChild(b);
  };
  add(t('复制这个'), () => copyText(value));
  for (const [label, spec] of entActions(kind, value)) {
    add(label, () => {
      if (spec.page === current) { fillEnt(spec); return; }
      goto(spec.page, { ent: spec });
    });
  }
  document.body.appendChild(pop);
  const r = anchor.getBoundingClientRect();
  const w = pop.offsetWidth || 220;
  const h = pop.offsetHeight || 160;
  pop.style.left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8)) + 'px';
  pop.style.top = (r.bottom + h > window.innerHeight - 8 ? Math.max(8, r.top - h - 4) : r.bottom + 4) + 'px';
}

document.addEventListener('click', (e) => { if (popEl && !e.target.closest('.pop')) closePop(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closePop(); });

/** 原始结果 / 输出块：给一个复制口，别让人用鼠标去框三段 JSON。 */
function markRaw(root) {
  for (const d of root.matches('details') ? [root] : [...root.querySelectorAll('details')]) {
    if (d.classList.contains('raw')) continue;
    const sum = d.querySelector('summary');
    const pre = d.querySelector('pre');
    // 只在「这是一坨原文」时挂复制钮 —— 折叠块里翻正文的那种不该长出一个复制空字符串的钮。
    if (!sum || !pre) continue;
    d.classList.add('raw');
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'copy';
    b.textContent = t('复制');
    b.onclick = (e) => { e.preventDefault(); e.stopPropagation(); copyText(pre.textContent); };
    sum.appendChild(b);
  }
}

function copyText(s) {
  const v = String(s ?? '');
  const done = () => toast(t('已复制'));
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(v).then(done, () => fallbackCopy(v, done));
  } else fallbackCopy(v, done);
}
function fallbackCopy(v, done) {
  const ta = document.createElement('textarea');
  ta.value = v;
  ta.style.cssText = 'position:fixed;top:-1000px';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); done(); } catch (_) { /* 复制不上就是不复制，不编成功 */ }
  ta.remove();
}

let toastEl = null;
function toast(text) {
  if (!toastEl) {
    toastEl = document.createElement('div');
    toastEl.className = 'toast';
    document.body.appendChild(toastEl);
  }
  toastEl.textContent = text;
  toastEl.classList.add('on');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => toastEl.classList.remove('on'), 1600);
}

/* ── 跳到那一页之后：把该填的填上、该看的滚过来 ── */

function cardEl(title) {
  const want = normT(title);
  return [...document.querySelectorAll('#main .card')]
    .find((c) => { const h = c.querySelector('h2'); return h && normT(h.textContent).startsWith(want); });
}

function focusCard(card, title) {
  if (!card) return;
  card.scrollIntoView({ block: 'start', behavior: 'smooth' });
  card.classList.remove('flash');
  void card.offsetWidth;
  card.classList.add('flash');
  if (title) card.title = t('从搜索里跳来的这一张');
}

/*
 * ★★ 谁接得住哪种数，全写在这一张表里，而不是加进各卡片那段 HTML：
 *   那五十多段字符串是词典的 key，往里面加一个属性就得重译四本、还会动 HTML 骨架判据。
 *   集中一份还有第二个好处 —— 「屏上哪些框接得住地址」一眼数得完；
 *   散在二十张卡里，漏绑哪一张都不会有人发现。
 *   格式：[输入框 id, 收的实体, 填完点哪颗按钮]
 */
const ENT_BIND = [
  ['p-t', 'addr', 'p-bp'],          // ping 一个地址
  ['sa', 'addr', 'sgo'],            // 扫一片端口
  ['th', 'addr', 'tgo'],            // 路径追踪
  ['xa', 'addr', 'xgo'],            // 问一遍：这些地址是哪台设备
  ['rt-dest', 'addr', 'rt-go'],     // 路由表：去它走哪块网卡
  ['hu', 'url', 'hgo'],             // 网页 / 接口探测
  ['ma-mac', 'mac', 'ma-go'],       // MAC 地址（查来路）
  ['wl-mac', 'mac', 'wl-go'],       // Wake-on-LAN
  ['cf-host', 'filter', 'cap-flows-go'], // 流表按端点收
];
function bindEnts(root) {
  for (const [id, kind, go] of ENT_BIND) {
    const inp = root.querySelector('#' + id);
    if (inp && !inp.dataset.ent) inp.dataset.ent = kind;
    const btn = root.querySelector('#' + go);
    if (btn && !btn.dataset.entRun) btn.dataset.entRun = kind;
  }
}

/** 把实体值填进那一页标了 data-ent 的输入框，并按 data-ent-run 点一下那颗按钮。 */
function fillEnt(spec) {
  const scope = (spec.card && cardEl(t(spec.card))) || document.getElementById('main');
  const inp = scope && scope.querySelector(`[data-ent~="${spec.kind}"]`);
  if (!inp) { toast(t('这一页没有接得住它的输入框')); return; }
  inp.value = spec.value;
  inp.dispatchEvent(new Event('input', { bubbles: true }));
  inp.dispatchEvent(new Event('change', { bubbles: true }));
  const card = inp.closest('.card') || scope;
  const go = card.querySelector(`[data-ent-run~="${spec.kind}"]`);
  focusCard(card, spec.card);
  if (go && !go.disabled) go.click();
}

function applyPending() {
  const q = pending;
  pending = null;
  if (!q) return;
  if (q.ent) { fillEnt(q.ent); return; }
  if (q.card) {
    const el = cardEl(t(q.card));
    if (el) focusCard(el, q.card);
  }
}

/* ── 右侧上下文栏 ── */

function renderRail(p) {
  const rail = document.getElementById('rail');
  if (!rail) return;
  rail.innerHTML = '';
  const rec = PIDX[p.id] || { tools: [], cards: [] };

  const sec1 = document.createElement('div');
  sec1.className = 'railsec';
  sec1.appendChild(railHead(t('这一页问的这几件事')));
  const list = document.createElement('div');
  list.className = 'railist';
  for (const tn of rec.tools || []) {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'railrow' + (isMut(tn) ? ' mut' : '');
    row.title = (toolOf(tn) || {}).summary || tn;
    const c = HOST[tn] && HOST[tn].page === p.id ? HOST[tn].card : '';
    row.innerHTML = `<code>${esc(tn)}</code>` + (c ? `<div class="cls">${esc(t(c))}</div>` : '');
    const host = cardEl(t(c));
    row.onclick = () => { if (host) focusCard(host, c); };
    list.appendChild(row);
  }
  if (!(rec.tools || []).length) {
    const e = document.createElement('div');
    e.className = 'dim';
    e.style.fontSize = '12.5px';
    e.textContent = t('这一页不直接问后端，它把别处问到的合成起来');
    list.appendChild(e);
  }
  sec1.appendChild(list);
  rail.appendChild(sec1);

  const hist = histFor(p.id);
  const sec2 = document.createElement('div');
  sec2.className = 'railsec';
  sec2.appendChild(railHead(t('这一页最近问过')));
  if (hist.length) {
    const box = document.createElement('div');
    box.className = 'railist';
    for (const h of hist) {
      const row = document.createElement('div');
      row.className = 'railrow';
      row.style.cursor = 'default';
      row.innerHTML = `<code>${esc(h.tool)}</code><div class="cls">${esc(stampOf(h.at))}${h.verdict ? ' · ' + esc(h.verdict) : ''}</div>`;
      box.appendChild(row);
    }
    sec2.appendChild(box);
  } else {
    const e = document.createElement('div');
    e.className = 'dim';
    e.style.fontSize = '12.5px';
    e.textContent = t('还没有。这一页只留工具名和判定码，填过的地址不在这儿。');
    sec2.appendChild(e);
  }
  rail.appendChild(sec2);
}

function railHead(text) {
  const h = document.createElement('div');
  h.className = 'railh';
  h.textContent = text;
  return h;
}

/* ── 搜索（命令面板）：想用什么，打一个字 ──
 *
 * ★ 侧栏解决「一眼看全」，搜索解决「我知道有个什么但叫不出名字」。
 *   两者都要：只有侧栏的话，六十来张卡还是要靠翻；只有搜索的话，新用户不知道该搜什么。
 */

// 顶栏那颗钮和三步上手都要点这颗键的名字 —— 苹果和其余键盘不是一套键，写死 ⌘K
// 在 Windows 上就是教人按一个按了没反应的组合。
const FIND_KEY = (/Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent) ? '⌘K' : 'Ctrl K');

function findItems() {
  const items = [];
  for (const p of PAGES) {
    if (p.pin) continue;
    items.push({ kind: 'page', page: p.id, title: p.name, sub: PAGE_ASK[p.id] || p.g, g: p.g });
  }
  for (const [pid, rec] of Object.entries(PIDX)) {
    const page = PAGES.find((x) => x.id === pid);
    if (!page) continue;
    for (const c of rec.cards || []) {
      items.push({ kind: 'card', page: pid, card: c.t, title: t(c.t), sub: page.name });
    }
  }
  for (const tool of TOOLS) {
    const h = HOST[tool.name];
    items.push({
      kind: 'tool', tool: tool.name, title: tool.name,
      // ★ 后端那句 summary 是给 AI 看的说明书，也是中文写死的 —— 它进 title 属性，
      //   不进正文：正文里印一句没译的话，比不印更容易让人以为自己看漏了什么。
      sub: h ? t('用在') + ' ' + t(h.card || '') + ' · ' + ((PAGES.find((p) => p.id === h.page) || {}).name || '')
             : t('后端有这一项，界面里还没给它入口'),
      hay: tool.summary || '',
    });
  }
  return items;
}

function score(it, q) {
  const t1 = it.title.toLowerCase(), sub = (it.sub || '').toLowerCase(), hay = (it.hay || '').toLowerCase();
  const s = q.toLowerCase();
  let n = -1;
  if (t1 === s) n = 100;
  else if (t1.startsWith(s)) n = 70;
  else if (t1.includes(s)) n = 50;
  else if (sub.includes(s)) n = 30;
  else if (hay.includes(s)) n = 12;
  if (n < 0) return -1;
  return n + (it.kind === 'page' ? 6 : it.kind === 'card' ? 3 : 0);
}

let findOpen = false;
function openFind(seed) {
  if (findOpen) return;
  findOpen = true;
  const ov = document.createElement('div');
  ov.className = 'find-ov';
  const box = document.createElement('div');
  box.className = 'find-box';
  const head = document.createElement('div');
  head.className = 'find-in';
  const inp = document.createElement('input');
  inp.type = 'text';
  inp.placeholder = t('要做什么？打页名、卡片名或工具名');
  inp.value = seed || '';
  const hint = document.createElement('span');
  hint.className = 'find-foot';
  hint.style.cssText = 'border:0;padding:0';
  hint.textContent = t('共 {0} 项能力', [TOOLS.length || '—']);
  head.appendChild(inp);
  head.appendChild(hint);
  const list = document.createElement('div');
  list.className = 'find-list';
  const foot = document.createElement('div');
  foot.className = 'find-foot';
  foot.textContent = t('↑↓ 选 · Enter 跳 · Esc 关');
  box.append(head, list, foot);
  ov.appendChild(box);
  document.body.appendChild(ov);

  const items = findItems();
  let hits = [];
  let sel = 0;

  const paint = () => {
    list.innerHTML = '';
    if (!hits.length) {
      const e = document.createElement('div');
      e.className = 'find-empty';
      e.textContent = t('没有对得上的。换个词，或者看总览页的能力清单。');
      list.appendChild(e);
      return;
    }
    let lastGrp = '';
    hits.forEach((h, i) => {
      const gname = h.it.kind === 'page' ? t('页面') : h.it.kind === 'card' ? t('卡片') : t('工具');
      if (gname !== lastGrp) {
        lastGrp = gname;
        const g = document.createElement('div');
        g.className = 'find-grp';
        g.textContent = gname;
        list.appendChild(g);
      }
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'find-it' + (i === sel ? ' on' : '');
      const t1 = document.createElement('span');
      t1.className = 't1';
      t1.innerHTML = highlight(h.it.title, inp.value.trim());
      const t2 = document.createElement('span');
      t2.className = 't2';
      t2.textContent = h.it.sub || '';
      b.append(t1, t2);
      if (h.it.tool) { const c = document.createElement('code'); c.style.display = 'none'; b.appendChild(c); }
      b.onmousemove = () => { sel = i; paint(); };
      b.onclick = () => pick(h.it);
      list.appendChild(b);
    });
    const on = list.querySelector('.find-it.on');
    if (on) on.scrollIntoView({ block: 'nearest' });
  };

  const search = () => {
    const q = inp.value.trim();
    const scored = items.map((it) => ({ it, n: q ? score(it, q) : (it.kind === 'page' ? 1 : -1) }))
      .filter((x) => x.n >= 0)
      .sort((a, b) => b.n - a.n || a.it.title.length - b.it.title.length);
    hits = scored.slice(0, 60);
    sel = 0;
    paint();
  };

  const close = () => { findOpen = false; ov.remove(); };
  const pick = (it) => {
    close();
    if (it.kind === 'page') goto(it.page);
    else if (it.kind === 'card') { if (it.page === current) { focusCard(cardEl(t(it.card)), it.card); } else goto(it.page, { card: it.card }); }
    else if (it.tool && HOST[it.tool]) {
      const h = HOST[it.tool];
      if (h.page === current) focusCard(cardEl(t(h.card)), h.card);
      else goto(h.page, { card: h.card });
    } else if (it.tool) toast(t('后端有这一项，界面里还没给它入口'));
  };

  inp.oninput = search;
  inp.onkeydown = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(sel + 1, hits.length - 1); paint(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(sel - 1, 0); paint(); }
    else if (e.key === 'Enter') { e.preventDefault(); if (hits[sel]) pick(hits[sel].it); }
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
  };
  ov.onclick = (e) => { if (e.target === ov) close(); };
  search();
  inp.focus();
  inp.select();
}

function highlight(text, q) {
  const e = esc(text);
  if (!q) return e;
  const i = text.toLowerCase().indexOf(q.toLowerCase());
  if (i < 0) return e;
  return esc(text.slice(0, i)) + '<mark>' + esc(text.slice(i, i + q.length)) + '</mark>' + esc(text.slice(i + q.length));
}

/* ── 此刻在跑：顶栏那一排 ──
 *
 * ★★ 这一排存在的理由不是好看。后台跑着的东西在上一版是**看不见的**：
 *   一路抓包开着、一个 DHCP 在服务、对测口开着，人换到别的页就什么都看不出来，
 *   于是「我这台机器现在还在给别人发地址」这种事实要靠记忆来维护。
 *   只认后端给的判定码，不在界面里猜。
 */
const RUN_CHECKS = [
  { tool: 'net.capture.status', page: 'capture', word: t('本机抓包'), on: ['capture-running', 'capture-running-lossy'] },
  { tool: 'net.capture.peer.status', page: 'capture', word: t('对端抓包'), on: ['capture-peer-running', 'capture-peer-stopping'] },
  { tool: 'net.dhcp.leases', page: 'dhcp', word: t('在给设备分地址'), on: ['serving'] },
  { tool: 'net.quality.status', page: 'quality', word: t('在盯质量'), on: ['quality-running'] },
  { tool: 'net.throughput.status', page: 'thru', word: t('对测口开着'), on: ['thru-serving'] },
  { tool: 'net.fileshare.status', page: 'local', word: t('文件共享开着'), on: ['share-serving'] },
  { tool: 'net.portal.status', page: 'mobile', word: t('手机门户开着'), on: ['portal-serving'] },
];
let runTimer = null;

async function refreshRunning() {
  if (document.hidden) return;
  const found = [];
  await Promise.all(RUN_CHECKS.map(async (c) => {
    try {
      const r = await fetch(`${API}/tools/${c.tool}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
      });
      const j = await r.json();
      if (j && c.on.includes(j.verdict)) found.push(c);
    } catch (_) { /* 问不到就当没在跑？不行 —— 所以这里什么都不加：
                     下一轮再问，这一排宁可少说一条，也不许把「问不到」画成「没在跑」。 */ }
  }));
  const host = document.getElementById('runstate');
  if (!host) return;
  host.innerHTML = '';
  for (const c of found) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'runchip';
    b.textContent = c.word;
    b.title = t('这一项正在跑，点过去看');
    b.onclick = () => goto(c.page);
    host.appendChild(b);
  }
}
function startRunWatch() {
  refreshRunning();
  clearInterval(runTimer);
  runTimer = setInterval(refreshRunning, 5000);
}

/*
 * ── 总览：新用户的第一屏 ──
 *
 * ★★ 这一页不许自己攒清单 —— 四块内容全部是**现量出来的**：
 *   · 此刻的结论：net.checkup 给的判定码（人话用 CK_TOP，和体检页同一套词，不在这里另编一套）；
 *   · 按问题找：PAGES + PAGE_ASK，卡片名从 page-index.js 来（那份是由各 render 函数的源码量出来的）；
 *   · 能力清单：GET /tools 此刻报的那一张表，并如实标出哪一项界面里还没有入口。
 *   历史上「界面说后端没做、其实后端做了」就是手抄清单抄出来的；这里一个数都不抄，
 *   所有「多少页 / 多少卡 / 多少项」都由这几个数组当场算。
 */
async function renderHome(root) {
  root.appendChild(homeHero());
  root.appendChild(homeSteps());
  root.appendChild(homeQuestions());
  root.appendChild(homeCapabilities());
  const h = homeHistory();
  if (h) root.appendChild(h);
}

/** 第一块：这台机器此刻怎么样。进来就自动问一遍 —— 新用户不知道该点哪儿，先给他一个结论。 */
function homeHero() {
  const card = document.createElement('div');
  card.className = 'card hero';
  const say = document.createElement('div');
  say.className = 'say';
  const verdict = document.createElement('p');
  verdict.className = 'verdict';
  const body = document.createElement('div');
  say.append(verdict, body);

  const again = document.createElement('button');
  again.type = 'button';
  again.className = 'btn primary';
  again.textContent = t('再问一遍');
  const detail = document.createElement('button');
  detail.type = 'button';
  detail.className = 'btn';
  detail.textContent = t('逐项看');
  detail.onclick = () => goto('checkup');
  card.append(say, again, detail);

  // 换页不停在这里，这一趟回来的结果就不该再画到屏上 —— 记一代，回来先对代。
  const myGen = ++gen;
  const run = async () => {
    if (myGen !== gen) return;   // ★ 换页（或重问）之后这一趟的活就作废，别再往已经拆掉的节点里写
    again.disabled = true;
    verdict.textContent = t('正在按老手的排查顺序问这一台机器…');
    body.innerHTML = '';
    const r = await call('net.checkup', {});
    if (myGen !== gen) return;
    again.disabled = false;
    if (!r.ok) {
      verdict.textContent = t('这一刻问不出结论');
      body.innerHTML = adviceBox('bad', esc(t('后端没答上这一问：{0}', [esc(r.message || '')])));
      return;
    }
    const v = r.values || {};
    const [title, cls, advice] = CK_TOP[r.verdict] || [r.verdict || '—', '', ''];
    verdict.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    body.innerHTML = advice ? adviceBox(cls, esc(advice)) : '';
    if (v.first) {
      const line = document.createElement('p');
      line.className = 'hint';
      line.style.marginTop = '10px';
      line.textContent = t('顺序是从这一步开始的：{0}', [CK_STEP[v.first] || v.first]);
      body.appendChild(line);
    }
    const go = document.createElement('button');
    go.type = 'button';
    go.className = 'btn';
    go.textContent = t('照这个症状排下去');
    go.onclick = () => goto('trouble');
    body.appendChild(go);
  };
  again.onclick = run;
  run();
  return card;
}

const CARD_COUNT = () => Object.values(PIDX).reduce((n, rec) => n + ((rec.cards || []).length), 0);
const PAGE_COUNT = () => PAGES.filter((p) => !p.pin).length;

function homeSteps() {
  const card = document.createElement('div');
  card.className = 'card';
  const items = [
    [t('先说症状，别先说工具'),
      t('「网页打不开」「摄像头没画面」这种话，「按症状排查」那一页已经替工程师排好了顺序 —— 从那条路进去，别自己凑工具。')],
    [t('手里有一个地址或 MAC，就点它'),
      t('扫出来的表、流表、设备列表里那些数是入口：ping 它、探它的端口、只抓它的包、查它的来路，点一下直接摆出来，不用复制粘贴换页。')],
    [t('叫不出名字就打一个字'),
      t('顶栏那颗搜索（{0}）把 {1} 个页面、{2} 张卡片和后端此刻报出的能力一起搜，结果上写明每一项在哪个页的哪张卡。',
        [FIND_KEY, PAGE_COUNT(), CARD_COUNT()])],
  ];
  const ol = document.createElement('ol');
  ol.className = 'steps';
  for (const [b, s] of items) {
    const li = document.createElement('li');
    const strong = document.createElement('b');
    strong.textContent = b;
    const span = document.createElement('span');
    span.textContent = s;
    li.append(strong, span);
    ol.appendChild(li);
  }
  const h = document.createElement('h2');
  h.textContent = t('这个软件怎么用：三步');
  card.append(h, ol);
  return card;
}

/** 按问题找：把 8 个组当成 8 类问题摊开，每张卡一个直达落点。 */
function homeQuestions() {
  const card = document.createElement('div');
  card.className = 'card';
  const h = document.createElement('h2');
  h.textContent = t('按你现在想问的那件事找');
  const hint = document.createElement('p');
  hint.className = 'hint';
  hint.textContent = t('左边一栏是全的（{0} 个页面），这里按「问题的归类」重排一遍 —— 点下面的卡片名直接落到那张卡。', [PAGE_COUNT()]);
  const grid = document.createElement('div');
  grid.className = 'qgrid';
  for (const g of GROUPS) {
    for (const p of PAGES.filter((x) => x.g === g)) {
      const tile = document.createElement('div');
      tile.className = 'qtile';
      const t3 = document.createElement('h3');
      t3.textContent = p.name;
      const ask = document.createElement('p');
      ask.className = 'ask';
      ask.textContent = PAGE_ASK[p.id] || '';
      const ul = document.createElement('ul');
      const cards = (PIDX[p.id] || {}).cards || [];
      for (const c of cards.slice(0, 4)) {
        const li = document.createElement('li');
        const b = document.createElement('button');
        b.type = 'button';
        b.textContent = t(c.t);
        b.onclick = () => { if (p.id === current) focusCard(cardEl(t(c.t)), c.t); else goto(p.id, { card: c.t }); };
        li.appendChild(b);
        ul.appendChild(li);
      }
      if (cards.length > 4) {
        const li = document.createElement('li');
        const b = document.createElement('button');
        b.type = 'button';
        b.textContent = t('还有 {0} 张', [cards.length - 4]);
        b.onclick = () => goto(p.id);
        li.appendChild(b);
        ul.appendChild(li);
      }
      const grp = document.createElement('div');
      grp.className = 'railh';
      grp.textContent = g;
      tile.append(grp, t3, ask, ul);
      grid.appendChild(tile);
    }
  }
  card.append(h, hint, grid);
  return card;
}

/** 全部能力：后端此刻报的那一张表。★ 没有入口的那几项如实标出来，不藏。 */
function homeCapabilities() {
  const card = document.createElement('div');
  card.className = 'card';
  const h = document.createElement('h2');
  h.textContent = t('这台机器能问的全部事情');
  const hostCount = TOOLS.filter((x) => HOST[x.name]).length;
  const hint = document.createElement('p');
  hint.className = 'hint';
  hint.textContent = TOOLS.length
    ? t('后端此刻报出 {0} 项，界面里 {1} 项有入口 —— 点一行跳到用它的那张卡。', [TOOLS.length, hostCount])
    : t('后端没报出能力表（{0} 打不通 /tools）—— 这里宁可空着，也不替它编一份。', [FIND_KEY]);
  card.append(h, hint);

  const order = new Map(PAGES.map((p, i) => [p.id, i]));
  const byPage = new Map();
  for (const tool of TOOLS) {
    const h2 = HOST[tool.name];
    const key = h2 ? h2.page : '';
    if (!byPage.has(key)) byPage.set(key, []);
    byPage.get(key).push(tool);
  }
  const keys = [...byPage.keys()].sort((a, b) => (order.get(a) ?? 99) - (order.get(b) ?? 99));
  for (const key of keys) {
    const page = PAGES.find((p) => p.id === key);
    const sec = document.createElement('div');
    const lbl = document.createElement('div');
    lbl.className = 'railh';
    lbl.textContent = page ? page.name : t('界面里还没有入口的');
    sec.appendChild(lbl);
    const list = document.createElement('div');
    list.className = 'caplist';
    for (const tool of byPage.get(key).sort((a, b) => a.name.localeCompare(b.name))) {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'caprow' + (HOST[tool.name] ? '' : ' orphan') + (tool.class === 'mutate' ? ' mut' : '');
      // ★ 后端那句 summary 是给 AI 看的说明书，也是中文写死的 —— 进 title，不进正文。
      row.title = tool.summary || '';
      const code = document.createElement('code');
      code.textContent = tool.name;
      const sum = document.createElement('span');
      sum.className = 'sum';
      const host = HOST[tool.name];
      sum.textContent = host
        ? [t('用在'), page ? page.name : '', t('的'), (host.card && t(host.card)) || ''].filter(Boolean).join(' ')
          + (tool.class === 'mutate' ? ' ' + t('（会改动，要点确认）') : '')
        : t('后端有这一项，界面里还没给它入口');
      row.append(code, sum);
      if (host) row.onclick = () => { if (host.page === current) focusCard(cardEl(t(host.card)), host.card); else goto(host.page, { card: host.card }); };
      list.appendChild(row);
    }
    sec.appendChild(list);
    card.appendChild(sec);
  }
  return card;
}

/** 今天问过什么（只有工具名、判定码和时间 —— 参数里有凭据，一份都不存）。 */
function homeHistory() {
  if (!HIST.length) return null;
  const card = document.createElement('div');
  card.className = 'card';
  const h = document.createElement('h2');
  h.textContent = t('这台机器最近问过的那些（这一台电脑上）');
  const hint = document.createElement('p');
  hint.className = 'hint';
  hint.textContent = t('只留工具名、判定码和钟点 —— 填过的地址、口令一概不存。点一行回到那一页。');
  const list = document.createElement('div');
  list.className = 'caplist';
  for (const rec of HIST.slice(0, 10)) {
    const page = PAGES.find((p) => p.id === rec.page);
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'caprow';
    row.onclick = () => goto(rec.page);
    const code = document.createElement('code');
    code.textContent = rec.tool;
    const sum = document.createElement('span');
    sum.className = 'sum';
    sum.textContent = [stampOf(rec.at), page ? page.name : rec.page, rec.verdict].filter(Boolean).join(' · ');
    row.append(code, sum);
    list.appendChild(row);
  }
  card.append(h, hint, list);
  return card;
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
  wifi: [t('无线'), '📶'], ethernet: [t('有线网口'), '🔌'], 'usb-lan': [t('USB 网卡'), '🔌'],
  cellular: [t('4G/共享网络'), '📡'], bluetooth: [t('蓝牙'), '🔵'],
  thunderbolt: [t('雷雳'), '⚡'], virtual: [t('虚拟'), ''], loopback: [t('回环'), ''],
};
// kindWord 给下拉框、标题这类只要一个词的地方用；带「可能是」的诚实前缀。
function kindWord(n) {
  if (!n.kind) return t('网卡');
  const [text] = KIND[n.kind] || [t('网卡')];
  return (n.kindSrc === 'name' ? t('可能是') : '') + text;
}

async function renderNIC(root) {
  const r = await call('net.interfaces');
  if (!r.ok) { root.appendChild($(t('<div class=\"card\">读取失败：{0}</div>', [esc(r.message)]))); return; }
  // ★ 判定码由界面翻成人话 —— 后端只给码，不给句子（多语种就靠这条）
  const LABEL = {
    'dual-stack': [t('双栈正常'), 'ok'], 'v4-only': [t('只有 IPv4 可用'), 'ok'],
    'v6-only': [t('只有 IPv6 可用'), 'ok'], 'link-local': [t('只拿到本地地址'), 'warn'],
    'no-address': [t('没有 IP 地址'), 'bad'], 'no-carrier': [t('没插线'), 'warn'],
    down: [t('已禁用'), 'warn'], virtual: [t('虚拟网卡'), ''], loopback: [t('回环'), ''],
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
    const [text, icon] = KIND[n.kind] || [t('不确定'), ''];
    if (!n.kind) return t('<span class=\"dim\">不确定</span>');
    const guess = n.kindSrc === 'name';
    return `<span title="${guess ? t('按网卡名推测，未经系统确认') : t('系统给出的类型')}">`
      + `${icon} ${guess ? t('可能是') : ''}${esc(text)}</span>`;
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
  const head = t('<tr><th>网卡</th><th>类型</th><th>状态</th><th>地址</th><th>MAC</th><th>MTU</th></tr>');

  root.appendChild($(t('<div class=\"card\">\n    <h2>在用的网卡</h2>\n    <p class=\"hint\">下面这些拿到了地址，可以用来 ping、探端口、发 DHCP。</p>\n    {0}\n  </div>', [on.length ? `<table>${head}${on.map(row).join('')}</table>`
               : t('<div class=\"empty\">一块都没有拿到地址。检查网线、交换机，或者用「开启路由」自己发地址。</div>')])));

  if (off.length) {
    const rest = $(t('<div class=\"card\">\n      <h2>没在用的网卡 <span class=\"pill\">{0}</span></h2>\n      <p class=\"hint\">虚拟网卡、没插线的、被禁用的。排查时一般不用管。</p>\n      <button class=\"btn\" id=\"more\">展开</button>\n      <div id=\"offbox\" style=\"display:none;margin-top:10px\"></div>\n    </div>', [off.length]));
    root.appendChild(rest);
    const box = rest.querySelector('#offbox');
    rest.querySelector('#more').onclick = (e) => {
      const openNow = box.style.display === 'none';
      box.style.display = openNow ? 'block' : 'none';
      e.target.textContent = openNow ? t('收起') : t('展开');
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
  'no-carrier': t('没插线'), down: t('已禁用'), 'v6-only': t('只有 IPv6'),
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
  'dhcp-found': [t('这个网已经有人在发地址'), 'bad',
    t('★ 别再起第二个。两边同时发地址时，设备拿到哪个看运气，故障是间歇的、而且每台机器不一样 —— 这是现场最难查的一类问题。要看是谁在发，问它下发的网关和 DNS 指向哪。')],
  'no-dhcp': [t('这个网里没人发地址'), 'ok',
    t('可以放心开。★ 这只代表刚才那几秒没人应答；网里随时可能接入一台带 DHCP 的设备（路由器、热点、别的电脑），开之前再点一次问一遍。')],
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
    else if (cls === 'needsAddr') tail = t('没有固定 IP，选中后先设一个');
    else tail = DHCP_DISABLED_REASON[n.verdict.verdict] || n.verdict.verdict;
    return `<option value="${esc(n.name)}" data-cls="${cls}"${cls === 'disabled' ? ' disabled' : ''}>`
      + t('{0}（{1}）{2}</option>', [esc(n.name), esc(word), tail ? ' — ' + esc(tail) : '']);
  }).join('');

  const card = $(t('<div class=\"card\">\n    <h2>把这台电脑变成 DHCP 服务器</h2>\n    <p class=\"hint\">设备都插在交换机上、没人自动分 IP 时用它。选好网卡后参数会自动算好，可以直接改。</p>\n    <label>在哪块网卡上服务</label>\n    <select id=\"iface\">{0}</select>\n\n    <div id=\"addrPanel\" style=\"display:none;margin-top:12px;padding:12px;border-radius:10px;background:var(--panel-2);border:1px solid var(--line)\">\n      <p class=\"hint\" id=\"addrWhy\"></p>\n      <div class=\"row\">\n        <div><label>给它设的 IP</label><input id=\"addrIp\" value=\"192.168.50.1\"></div>\n        <div><label>掩码位数</label><input id=\"addrPrefix\" value=\"24\"></div>\n      </div>\n      <button class=\"btn primary\" id=\"btnSetAddr\" style=\"margin-top:8px\">设静态地址</button>\n      <p class=\"hint\">设完这块网卡就能发地址了。改系统网络设置需要管理员权限，弹出来就输入开机密码。</p>\n    </div>\n\n    <div id=\"poolPanel\">\n      <div class=\"row\">\n        <div><label>地址池起</label><input id=\"start\"></div>\n        <div><label>地址池止</label><input id=\"end\"></div>\n        <div><label>租期（小时）</label><input id=\"lease\" value=\"12\"></div>\n      </div>\n      <label>下发网关（可留空）</label>\n      <input id=\"router\" placeholder=\"留空 = 不下发\">\n      <p class=\"hint\" id=\"routerNote\"></p>\n      <div style=\"margin-top:14px;display:flex;gap:10px\">\n        <button class=\"btn\" id=\"btnProbe\">先看看有没有别人在发地址</button>\n        <button class=\"btn primary\" id=\"btnStart\">开始发地址</button>\n      </div>\n    </div>\n    <div class=\"out\" id=\"out\" style=\"margin-top:12px;display:none\"></div>\n  </div>', [opts || t('<option>没有可用网卡</option>')]));
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
    if (!d.ok) { say(t('算不出默认参数：') + d.message); return; }
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
        t('网卡 {0} 还没有可用的固定 IP，DHCP 服务器得先有一个自己的地址才能发。给它设一个：', [n.name]);
    } else {
      addrPanel.style.display = 'none';
      poolPanel.style.display = 'block';
      fillDefaults();
    }
  }
  sel.onchange = onSelect;

  card.querySelector('#btnSetAddr').onclick = async () => {
    const btn = card.querySelector('#btnSetAddr');
    btn.disabled = true; say(t('正在设静态地址…（可能弹出管理员密码框）'));
    const r = await call('net.address.set', {
      iface: sel.value,
      ip: card.querySelector('#addrIp').value,
      prefix: Number(card.querySelector('#addrPrefix').value) || 24,
    });
    btn.disabled = false;
    if (!r.ok) { say(t('没设成：') + r.message); return; }
    // ★ 后端会回去核一眼地址有没有真用上。没插线时配置写进去了但地址不激活，
    //   这时候不能重渲染成「设好了」——把后端的诚实提示原样说出来，让人去查网线。
    if (r.verdict === 'address-set-inactive') { say('⚠ ' + r.note); return; }
    say(t('设好了，正在重新读取网卡…'));
    show();  // 重渲染：这块网卡现在能直接发地址了
  };

  if (!listed.length) { say(t('这台机器上没有能发地址的物理网卡。')); }
  else { onSelect(); }

  card.querySelector('#btnProbe').onclick = async () => {
    say(t('正在广播探测…（约 3 秒）'));
    out.style.whiteSpace = 'pre-wrap';
    const p = await call('net.dhcp.probe', { iface: sel.value, waitMs: 3000 });
    if (!p.ok) { say(t('探测失败：') + p.message); return; }
    const v = p.values || {};
    const servers = v.servers || [];
    const [title, cls, advice] = PROBE_DHCP_CODE[p.verdict] || [p.verdict || t('没给判定'), '', ''];
    const rows = servers.map((s) => `<tr>
        <td><code>${esc(s.serverId || s.from || '')}</code>${s.serverId && s.from && s.serverId !== s.from
          ? t('<br><span class=\"dim\">报文来自 <code>{0}</code></span>', [esc(s.from)]) : ''}</td>
        <td>${esc(s.offeredIp || '—')}</td>
        <td>${esc(s.mask || '—')}</td>
        <td>${esc(s.router || '—')}</td>
        <td>${(s.dns || []).length ? esc(s.dns.join(t('、'))) : '—'}</td>
        <td>${s.leaseSeconds ? esc(String(Math.round(s.leaseSeconds / 60))) + t(' 分钟') : '—'}</td>
      </tr>`).join('');
    out.style.whiteSpace = 'normal';
    out.innerHTML = `<p><span class="pill ${cls}">${esc(title)}</span></p>
      ${rows ? t('<table>\n        <tr><th>它自称</th><th>打算发的地址</th><th>掩码</th><th>网关</th><th>DNS</th><th>租期</th></tr>{0}\n      </table>', [rows]) : ''}
      <p class="dim" style="margin:10px 0 0">${esc(p.note || '')}</p>
      ${advice ? adviceBox(cls, esc(advice)) : ''}`;
  };

  card.querySelector('#btnStart').onclick = async () => {
    say(t('正在启动…启动前会自动探一遍，确认没有别的 DHCP 在发地址。'));
    const r = await call('net.dhcp.serve', {
      iface: sel.value,
      start: card.querySelector('#start').value,
      end: card.querySelector('#end').value,
      leaseHours: Number(card.querySelector('#lease').value) || 12,
      router: card.querySelector('#router').value || undefined,
    });
    if (!r.ok) { say(t('没有启动：') + r.message); return; }
    if (r.verdict === 'dhcp-found') { say('⚠ ' + r.note); return; }
    evSeq = 0; freshMacs = new Set();
    show();
  };
}

async function runningCard(state) {
  const v = state.values;
  const wrap = $(t('<div>\n    <div class=\"card\">\n      <h2>正在发地址 <span class=\"pill ok\">服务中</span></h2>\n      <p class=\"hint\">网卡 {0} · 池子共 {1} 个地址 · 已发出 <b id=\"cnt\">{2}</b> 个</p>\n      <button class=\"btn danger\" id=\"btnStop\">停止服务</button>\n    </div>\n    <div class=\"card\">\n      <h2>已接入的设备</h2>\n      <p class=\"hint\">新接入的会高亮显示。想改某台的 IP，直接在它那一行改完点「改地址」——\n        设备会在下次续租时换过去，拔插一下网线可立刻生效。<br>\n        「钉住」是给这台设备定死一个地址：以后它每次来（换时间、重启、重新插线）都拿这一个，\n        摄像机、盒子接在平台上的配置不用回头再改一遍。钉的时候如果它现在拿着别的地址，当前租约会作废，下次续租换过来。</p>\n      <div id=\"leases\"></div>\n    </div>\n  </div>', [esc(v.iface), v.poolSize, v.count]));
  wrap.querySelector('#btnStop').onclick = async () => {
    const r = await call('net.dhcp.stop');
    if (!r.ok) alert(t('停不下来：') + r.message);
    show();
  };
  drawLeases(wrap.querySelector('#leases'), state.values.leases || [], state.values.reserved || {});
  return wrap;
}

function drawLeases(box, leases, reserved) {
  if (!leases.length) { box.innerHTML = t('<div class=\"empty\">还没有设备来要地址。把设备插上交换机，它们会陆续出现。</div>'); return; }
  const res = reserved || {};
  const rows = leases.map((l) => t('\n    <tr class=\"{0}\">\n      <td><code>{1}</code>{2}</td>\n      <td><code>{3}</code></td>\n      <td>{4}</td>\n      <td><input value=\"{5}\" data-mac=\"{6}\" data-from=\"{7}\" style=\"width:140px\"></td>\n      <td><button class=\"btn\" data-act=\"{8}\">改地址</button>\n        <button class=\"btn\" data-bind=\"{9}\" title=\"以后这台每次来都拿这个地址\">钉住</button></td>\n    </tr>', [freshMacs.has(l.mac) ? 'fresh' : '', esc(l.ip), res[l.mac] ? t(' <span class=\"pill ok\">已钉住</span>') : '', esc(l.mac), esc(l.host || '—'), esc(l.ip), esc(l.mac), esc(l.ip), esc(l.mac), esc(l.mac)])).join('');
  box.innerHTML = t('<table><tr><th>IP</th><th>MAC</th><th>设备名</th><th>改成</th><th></th></tr>{0}</table>', [rows]);
  box.querySelectorAll('button[data-act]').forEach((b) => {
    b.onclick = async () => {
      const inp = box.querySelector(`input[data-mac="${b.dataset.act}"]`);
      const r = await call('net.dhcp.setip', { mac: b.dataset.act, to: inp.value });
      alert(r.ok ? r.note : t('改不了：') + r.message);
      show();
    };
  });
  box.querySelectorAll('button[data-bind]').forEach((b) => {
    b.onclick = async () => {
      const inp = box.querySelector(`input[data-mac="${b.dataset.bind}"]`);
      const r = await call('net.dhcp.bind', { mac: b.dataset.bind, ip: inp.value });
      alert(r.ok ? r.note : t('钉不住：') + r.message);
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
    if (box) drawLeases(box, ls.values.leases || [], ls.values.reserved || {});
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
  'reachable': [t('通'), 'ok', t('往返和丢包在下面。★ 通了只说明 ICMP 过得去，不说明端口开着。')],
  'unreachable': [t('回了明确的不可达'), 'bad',
    t('★ 这个「不通」是有用的：有设备（多半是路由或防火墙）回答了「到不了」，说明「路是通的」，问题在终点或那条路由。去查对端的地址、路由和防火墙，别再 ping 了。')],
  'no-reply': [t('完全没回应'), 'bad',
    t('分不清是机器不在、还是 ICMP 被静默丢掉 —— 这两件事的下一步完全不同：先用「探端口」或网段扫描问一次，能连上就说明机器在。')],
};

const PROBE_CODE = {
  'open': [t('端口开着'), 'ok', t('三次握手成了。★ 这只说明有人在听，服务是不是对的要看它回什么（RTSP、HTTP、SNMP 各有各的卡）。')],
  'closed': [t('端口关着（对方回了拒绝）'), 'warn',
    t('对端明确回了 RST —— ★ 主机是「活着」的，只是这个端口没服务。去看服务起没起、端口号对不对。')],
  'filtered': [t('没有任何回应'), 'bad',
    t('等到超时，一个回包都没有。多半是中间有人静默丢（防火墙/ACL），也可能主机压根不在。')],
};

function pingCard() {
  const card = $(t('<div class=\"card\">\n    <h2>ping 一个地址 <span id=\"p-top\"></span></h2>\n    <p class=\"hint\">只问一次，看它答不答。★ ping 区分「回了明确的不可达」和「完全没回应」——\n      前者说明路是通的、问题在终点；后者连机器在不在都说不清。要连着看稳不稳，去「路径与质量」那一页用「连续 ping」。</p>\n    <div class=\"row\">\n      <div><label>目标地址</label><input id=\"p-t\" placeholder=\"192.168.1.1 或 fd00::1\"></div>\n      <div style=\"flex:0 0 190px\"><label>端口（探端口时填）</label><input id=\"p-p\" placeholder=\"554\"></div>\n    </div>\n    <div style=\"margin-top:12px;display:flex;gap:10px\">\n      <button class=\"btn primary\" id=\"p-bp\">ping</button>\n      <button class=\"btn\" id=\"p-bt\">探端口</button>\n    </div>\n    <div id=\"p-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#p-out');
  const top = card.querySelector('#p-top');
  const say = (html) => { out.innerHTML = html; };
  card.querySelector('#p-bp').onclick = async () => {
    top.innerHTML = '';
    say(t('<div class=\"empty\">ping 中…</div>'));
    const r = await call('net.ping', { addr: card.querySelector('#p-t').value.trim(), count: 4 });
    if (!r.ok) { say(t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)])); return; }
    const [title, cls, advice] = PING_CODE[r.verdict] || [r.verdict, '', ''];
    const v = r.values || {};
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    say(`<table>
        ${tCell(t('目标'), `<code>${esc(v.target || '')}</code> <span class="dim">${esc(v.family || '')}</span>`)}
        ${tCell(t('发 / 收到'), `${v.sent ?? '—'} / ${v.received ?? '—'}`)}
        ${tCell(t('丢包'), v.lossPercent === undefined ? '—' : `${Math.round(v.lossPercent)}%`)}
        ${tCell(t('往返（最快/平均/最慢）'), ms(v.rttMinMs) + ' / ' + ms(v.rttAvgMs) + ' / ' + ms(v.rttMaxMs))}
      </table>${advice ? adviceBox(cls, esc(advice)) : ''}`);
  };
  card.querySelector('#p-bt').onclick = async () => {
    top.innerHTML = '';
    say(t('<div class=\"empty\">探测中…</div>'));
    const port = Number(card.querySelector('#p-p').value);
    const r = await call('net.tcp.probe', {
      addr: card.querySelector('#p-t').value.trim(), port: port || undefined,
    });
    if (!r.ok) { say(t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)])); return; }
    const [title, cls, advice] = PROBE_CODE[r.verdict] || [r.verdict, '', ''];
    const v = r.values || {};
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    say(`<table>
        ${tCell(t('目标'), `<code>${esc(v.target || '')}</code> <span class="dim">${esc(v.family || '')}</span>`)}
        ${tCell(t('端口'), v.port ?? '—')}
        ${tCell(t('等了多久'), ms(v.elapsedMs))}
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
  'no-address': [t('没拿到地址'), 'bad', t('两个地址族都没有可用地址、也没有默认路由 —— 这台机器现在基本没网。')],
  'dual-healthy': [t('双栈正常'), 'ok', t('IPv4 和 IPv6 都能出外网。')],
  'v6-egress-broken': [t('IPv6 出不了外网'), 'bad',
    t('IPv4 正常，但 IPv6 有地址/路由却出不了外网。应用优先走 IPv6，所以每次连接先卡一下再回落到 IPv4 —— 这就是「网很慢」的真身。')
    + t('要么修上游的 IPv6，要么先把这台机器的 IPv6 关掉。')],
  'v4-egress-broken': [t('IPv4 出不了外网'), 'bad', t('IPv6 正常，但 IPv4 出不了外网。')],
  'both-egress-broken': [t('两族都出不了外网'), 'bad', t('两族都有地址，但都出不了外网 —— 多半是纯内网，或上游整个断了。')],
  'v4-only': [t('只有 IPv4，正常'), 'ok', t('只有 IPv4 能出外网（这台机器没启用 IPv6，或 IPv6 没拿到地址）。')],
  'v6-only': [t('只有 IPv6，正常'), 'ok', t('只有 IPv6 能出外网。')],
  'single-no-egress': [t('在线，但出不了外网'), 'bad', t('只有一族在线，而且出不了外网。')],
};
// 出口 / 单地址连接 → 人话。★ 这里和探端口用的是同一批码。
const DS_CONN = {
  'open': [t('通'), 'ok'], 'closed': [t('被拒绝'), 'warn'], 'filtered': [t('静默丢包'), 'bad'],
  'no-route': [t('没有默认路由'), 'bad'], 'error': [t('连不上'), 'bad'],
  'skipped': [t('未测'), ''], 'pending': ['—', ''],
};
const DS_GW = {
  'reachable': [t('通'), 'ok'], 'no-reply': [t('没回应'), 'warn'], 'unreachable': [t('明确不可达'), 'bad'],
  'no-gateway': [t('无下一跳'), ''], 'skipped': [t('未测'), ''],
};
const DS_DNS = {
  'ok': [t('解析出记录'), 'ok'], 'no-record': [t('这一族没有记录'), 'warn'],
  'error': [t('解析失败'), 'bad'], 'skipped': [t('未测'), ''],
};
// Happy Eyeballs 那一步的读数。★ 单独拎出来是因为「按症状排查」走到双栈时，
//   吐的顶层判定就是这一批码 —— 两处共用一份，换一句说法不必改两个地方。
const DS_EYEBALLS = {
  'eyeballs-ok': [t('不会卡'), 'ok'], 'eyeballs-stall': [t('★ 会先卡一下'), 'bad'],
  'eyeballs-single': [t('只有一族能连，没得选'), 'warn'], 'eyeballs-fail': [t('这个域名两族都连不上'), 'bad'],
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
    : t('<span class=\"dim\">没有全局地址</span>');
  const route = f.hasRoute
    ? t('<span class=\"pill ok\">有</span>{0}', [f.gateway ? t(' <code>{0}</code> 经 {1}', [esc(f.gateway), esc(f.routeIface)]) : ''])
      + (f.routeCount > 1 ? t(' <span class=\"dim\">（共 {0} 条）</span>', [f.routeCount]) : '')
    : t('<span class=\"pill bad\">没有</span>');
  const gw = pillOf(DS_GW, f.gwReachable) + (f.gwRttMs ? ` <span class="dim">${ms(f.gwRttMs)}</span>` : '');
  const egress = pillOf(DS_CONN, f.egress)
    + ` <span class="dim">${esc(f.egressTarget || '')}${f.egressRttMs ? ' ' + ms(f.egressRttMs) : ''}</span>`;
  const dns = pillOf(DS_DNS, f.dns) + ` <span class="dim">${ms(f.dnsRttMs)}</span>`;
  return `<div><table>
    <tr><th colspan="2">${f.family === 'ipv4' ? 'IPv4' : 'IPv6'}</th></tr>
    ${tCell(t('地址'), addrs)}${tCell(t('默认路由'), route)}${tCell(t('网关'), gw)}
    ${tCell(t('出外网'), egress)}${tCell('DNS', dns)}
  </table></div>`;
}

function attemptRow(title, list) {
  if (!list || !list.length) return tCell(title, t('<span class=\"dim\">域名没有这类记录</span>'));
  const cells = list.map((a) => `<div><code>${esc(a.addr)}</code> ${pillOf(DS_CONN, a.code)}`
    + ` <span class="dim">${a.code === 'open' || a.rttMs ? ms(a.rttMs) : ''}</span></div>`).join('');
  return tCell(title, cells);
}

function eyeballRow(eb) {
  const [text, cls] = DS_EYEBALLS[eb.code] || [eb.code, ''];
  let extra = '';
  if (eb.code === 'eyeballs-stall') {
    extra = t(' 应用先试 <b>{0}</b>，{1}ms 没连上就并行起 <b>{2}</b>：', [esc(eb.preferred), eb.connDelayMs, esc(eb.winner)])
      + t('守规矩的应用大约卡 <b>{0}</b>，不守规矩的（串行把 v6 试到超时）最坏卡 <b>{1}</b>。', [ms(eb.stallMs), ms(eb.worstMs)]);
  } else if (eb.winner) {
    extra = t(' 应用会先用 <b>{0}</b> 连上这个域名。', [esc(eb.winner)]);
  }
  return tCell('Happy Eyeballs', `<span class="pill ${cls}">${esc(text)}</span>${extra}`);
}

function dualStackCard() {
  const card = $(t('<div class=\"card\">\n    <h2>双栈体检 <span id=\"ds-top\"></span></h2>\n    <p class=\"hint\">一次测完 IPv4 与 IPv6 各自：有没有地址、有没有默认路由、网关通不通、出不出得了外网、DNS 通不通；\n      再对同一个域名的 A 与 AAAA 分别连一次比耗时，按 Happy Eyeballs(RFC 8305) 判断应用会不会先卡一下。\n      ★ 专治「有 IPv6 地址却出不了外网，结果上网很慢」这类现场最难查的问题。</p>\n    <div class=\"row\">\n      <div><label>体检用的域名</label><input id=\"ds-d\" placeholder=\"默认 www.cloudflare.com\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn primary\" id=\"ds-go\">开始体检</button></div>\n    </div>\n    <div id=\"ds-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#ds-out');
  const top = card.querySelector('#ds-top');
  card.querySelector('#ds-go').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">体检中…（要发几轮连接，约 5 秒）</div>');
    const domain = card.querySelector('#ds-d').value.trim();
    const r = await call('net.dualstack.check', domain ? { domain } : {});
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">体检失败：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [title, cls, advice] = DS_TOP[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      <div class=\"row\" style=\"margin-top:14px\">{3}{4}</div>\n      <table style=\"margin-top:14px\">\n        <tr><th colspan=\"2\">域名 <code>{5}:{6}</code>\n          <span class=\"dim\">解析 {7}ms{8}</span></th></tr>\n        {9}\n        {10}\n        {11}\n      </table>', [bg, line, esc(advice), familyTable(v.v4), familyTable(v.v6), esc(v.domain.name), v.domain.port, v.domain.lookupMs, v.domain.err ? ' · ' + esc(v.domain.err) : '', attemptRow(t('A 记录（v4）'), v.domain.a), attemptRow(t('AAAA 记录（v6）'), v.domain.aaaa), eyeballRow(v.eyeballs)]);
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
  'all-good': [t('八项都过'), 'ok',
    t('有地址、有默认路由、到网关不丢、解析得出、出得了外网、时钟也对得上。')
    + t('★ 这只说明「这台机器到公网这一段」没问题 —— 两台设备之间通不通，得拿那两台的地址另问。')],
  'degraded': [t('没有硬故障，但有值得看一眼的'), 'warn',
    t('下面标出来的几项都不会让网断，却常常就是「慢」和「偶尔卡一下」的来源 —— 从标了「先看这一步」的那项开始。')],
  'broken-at-iface': [t('坏在本机网卡'), 'bad',
    t('没有一块「启用、有链路、且有可用地址」的网卡 —— 后面每一项都是在它之上测的，先把这一步解决掉。')],
  'broken-at-route': [t('坏在默认路由'), 'bad',
    t('有地址却没有默认路由，这台机器只会发到本网段：局域网里 ping 得通，外面什么都到不了。')
    + t('查 DHCP 有没有发网关，或者静态地址里那个网关填错了。')],
  'broken-at-gateway': [t('坏在到网关这一段'), 'bad',
    t('★ 网关在丢包时，DNS 和出口的「慢」都是链路带出来的，不是那两层自己的毛病 —— 先修它，再回头看后面那些数。')
    + t('查线、查 AP、查网关本身；最好另拿一台机器同时发一份对照，才知道是不是只有这台的事。')],
  'broken-at-dns': [t('坏在域名解析'), 'bad',
    t('配了 DNS 服务器却问不出名字（或者根本没配）。出口那几项是拿 IP 直连测的，所以它们正常不代表解析正常 ——')
    + t('「网页打不开，但 IP ping 得通」就是这一层。')],
  'broken-at-egress': [t('局域网好，出不了外网'), 'bad',
    t('到网关不丢、名字也问得出，但 TCP 连不上公网 —— 往上查：网关的 NAT、ACL、认证门户，')
    + t('或者这条链路本来就只放行内网。')],
  'broken-at-clock': [t('本机时钟偏得太多'), 'bad',
    t('偏差已经大到会出事：TLS 证书校验直接失败、日志时间戳互相对不上、带时间有效性的令牌全部被拒。')
    + t('先校时，再回头看别的。')],
};

const CK_STEP = {
  iface: t('本机网卡'), route: t('默认路由'), gateway: t('到网关'), dns: t('域名解析'),
  egress: t('出外网'), mtu: t('出口 MTU'), clock: t('本机时钟'), proxy: t('系统代理'),
};

// 每一步自己的坏法。★ tone 空的是「没问」——它不算结论，别渲染成红。
const CK_CODE = {
  iface: {
    'ok': [t('在用'), 'ok'], 'no-nic': [t('没有一块网卡'), 'bad'],
    'all-disabled': [t('网卡全被禁用了'), 'bad'],
    'no-link': [t('启用了但没链路（没插线 / 没连上 AP）'), 'bad'],
    'no-address': [t('没有可用地址'), 'bad'],
    'virtual-only': [t('只有隧道口有地址'), 'warn'],
  },
  route: {
    'ok': [t('两族都有'), 'ok'], 'v4-only': [t('只有 IPv4'), 'ok'],
    'v6-only': [t('只有 IPv6'), 'warn'], 'none': [t('没有默认路由'), 'bad'],
  },
  gateway: {
    'ok': [t('不丢也不抖'), 'ok'], 'stable': [t('不丢也不抖'), 'ok'],
    'jitter': [t('偶尔抖一下'), 'warn'],
    'loss': [t('在丢包'), 'bad'], 'no-route': [t('包根本发不出去'), 'bad'],
    'unreachable': [t('明确回了不可达'), 'bad'],
    'no-reply': [t('不回 ping'), 'warn'],
    'no-gateway': [t('没有下一跳（点对点链路）'), ''],
    'tunnel': [t('走隧道口，没问'), ''], 'not-asked': [t('没问'), ''],
  },
  dns: {
    'ok': [t('问得出名字'), 'ok'], 'no-server': [t('系统没配 DNS'), 'bad'],
    'error': [t('解析失败'), 'bad'], 'no-record': [t('一条记录都问不出'), 'bad'],
    'no-v4-record': [t('v4 问空了'), 'warn'],
  },
  egress: {
    'ok': [t('出得去'), 'ok'], 'v6-egress-broken': [t('IPv6 出得去一半'), 'warn'],
    'v4-egress-broken': [t('IPv4 出得去一半'), 'warn'],
    'broken': [t('出不了外网'), 'bad'], 'not-asked': [t('没问'), ''],
  },
  mtu: {
    'ok': [t('正常'), 'ok'], 'small': [t('偏小'), 'warn'],
    'tunnel': [t('走隧道口，那样是对的'), 'ok'], 'unknown': [t('没读到'), ''],
  },
  clock: {
    'ok': [t('对得上'), 'ok'], 'skew': [t('有点偏'), 'warn'],
    'big-skew': [t('偏得太多'), 'bad'], 'not-asked': [t('没问到'), ''],
  },
  proxy: {
    'none': [t('没设代理'), 'ok'], 'set': [t('走了代理'), 'warn'],
    'unsupported': [t('这台读不到'), ''],
  },
};

const ckFam = (f, fn) => ['ipv4', 'ipv6'].filter((k) => f && f[k])
  .map((k) => `<div><b class="dim">${k === 'ipv4' ? 'IPv4' : 'IPv6'}</b> ${fn(f[k])}</div>`).join('');

const ckLoss = (n) => (n || n === 0 ? t('丢 {0}%', [Math.round(n)]) : '');

// 事实那一列：只把后端给的数摊开，不在这里下判断。
function ckFacts(step, f) {
  if (!f) return '<span class="dim">—</span>';
  switch (step) {
    case 'iface': {
      const names = f.withAddress || [];
      return t('{0} 块网卡 · 启用 {1} · 有链路 {2} · ', [f.nics || 0, f.up || 0, f.running || 0])
        + (names.length ? t('有地址：<code>{0}</code>', [esc(names.join(t('、')))])
                        : t('<span class=\"dim\">没有一块网卡有可用地址</span>'));
    }
    case 'route':
      return ckFam(f, (x) => (x.hasRoute
        ? t('→ <code>{0}</code> 经 {1}', [esc(x.gateway || t('无下一跳')), esc(x.iface || '?')])
          + (x.count > 1 ? t(' <span class=\"dim\">（共 {0} 条）</span>', [x.count]) : '')
        : t('<span class=\"dim\">没有默认路由</span>')));
    case 'gateway':
      return ckFam(f, (x) => pillOf(CK_CODE.gateway, x.code)
        + (x.sent
          ? t(' 到 <code>{0}</code> 发了 {1} 发 · {2}', [esc(x.gateway), x.sent, ckLoss(x.lossPercent)])
            + t(' · 中位 {0} · 抖动 {1}', [ms(x.rttMedianMs), ms(x.jitterAvgMs)])
            + (x.unreachable ? t(' · 明确不可达 {0} 发', [x.unreachable]) : '')
          : (x.gateway ? t(' 目标 <code>{0}</code>', [esc(x.gateway)]) : '')));
    case 'dns': {
      const srv = (f.servers || []).map((s) => `${esc(s.addr)}${s.iface ? t('（') + esc(s.iface) + t('）') : ''}`).join(t('、'));
      const at = (list) => {
        const cells = (list || []).map((a) => `<code>${esc(a.addr)}</code> ${pillOf(DS_CONN, a.code)}`
          + ` <span class="dim">${ms(a.rttMs)}</span>`).join(t('　'));
        return cells || t('<span class=\"dim\">没有</span>');
      };
      return t('<div>{0}\n        · <code>{1}</code>{2}{3}</div>\n        <div>A：{4}</div><div>AAAA：{5}</div>', [srv ? t('问 ') + srv : t('<span class=\"dim\">系统里没配 DNS 服务器</span>'), esc(f.domain || ''), f.lookupMs ? t(' 解析 ') + ms(f.lookupMs) : '', f.error ? ' · ' + esc(f.error) : '', at(f.v4), at(f.v6)]);
    }
    case 'egress':
      return ckFam(f, (x) => pillOf(DS_CONN, x.egress)
        + ` <code>${esc(x.target || '')}</code>${x.rttMs ? ' ' + ms(x.rttMs) : ''}`
        + (x.present ? '' : t(' <span class=\"dim\">这一族不在场</span>')));
    case 'mtu': {
      const others = (f.nics || []).filter((n) => n.iface !== f.egressIface).slice(0, 5)
        .map((n) => `${n.iface} ${n.mtu}${n.virtual ? t('（隧道）') : ''}`).join(t('、'));
      return t('出口 <code>{0}</code> MTU <b>{1}</b>', [esc(f.egressIface || t('未识别')), f.egressMtu || '—'])
        + (f.egressKind ? ` <span class="dim">${esc((KIND[f.egressKind] || [f.egressKind])[0])}</span>` : '')
        + (others ? t(' <span class=\"dim\">其它：{0}</span>', [esc(others)]) : '');
    }
    case 'clock': {
      // ★ 偏差那个数只有在它真答过话时才存在。没答时后端给的 offsetMs 是 0，
      //   照着写成「本机慢 0.0 毫秒」就是把「没问到」伪装成「问了、很准」。
      const asked = f.code === 'answered';
      const off = f.offsetMs;
      const why = {
        'time-no-response': t('没回话（内网封 UDP/123 时天天如此）'),
        'time-kiss-rejected': t('它拒答了（限速，或明说本机钟太离谱）'),
        'time-bad-response': t('回了，但不是 NTP 的样子'),
      }[f.code] || (f.code ? t('问不到：{0}', [esc(f.code)]) : t('没去问'));
      return t('问 <code>{0}</code> · 回了 {1}/{2} 包', [esc(f.server || ''), f.answers || 0, f.samples || 0])
        + (asked ? ` · <b>${off >= 0 ? t('本机慢') : t('本机快')} ${esc(humanMs(Math.abs(off)))}</b>`
                 : ` · <span class="dim">${why}</span>`)
        + (asked && f.rttMs ? t(' · 往返 {0}', [ms(f.rttMs)]) : '')
        + (asked && f.serverTime
            ? t('<div class=\"dim\">它说 {0} · 本机 {1}</div>', [esc(fmtStamp(f.serverTime)), esc(fmtStamp(f.localTime))]) : '');
    }
    case 'proxy': {
      const e = f.entries || [];
      if (e.length) return e.map((x) => `<code>${esc(x)}</code>`).join(t('　'));
      return f.scutilError ? t('<span class=\"dim\">读取代理设置失败：{0}</span>', [esc(f.scutilError)])
                           : t('<span class=\"dim\">没读到任何代理条目</span>');
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
    ? `<span class="pill ${it.severity === 'bad' ? 'bad' : 'warn'}">${it.severity === 'bad' ? t('先修这一步') : t('先看这一步')}</span>`
    : '';
  return `<tr><td class="dim">${i + 1}</td>
    <td>${esc(CK_STEP[it.step] || it.step)} ${flag}</td>
    <td><span class="pill ${tone}">${esc(text)}</span></td>
    <td>${ckFacts(it.step, it.facts)}</td></tr>`;
}

function checkupCard() {
  const card = $(t('<div class=\"card\">\n    <h2>一键体检 <span id=\"cku-top\"></span></h2>\n    <p class=\"hint\">什么都不用填，按老手的排查顺序把这台机器过一遍：网卡 → 默认路由 → 到网关丢不丢 →\n      解析 → 出外网 → MTU → 时钟 → 系统代理。<b>八项并行，两三秒出结果</b>，只发少量探测包、不改动任何东西。\n      ★ 顶层只说<b>第一个坏掉的是哪一步</b>，因为后面那些数是带着这个毛病测出来的 —— 从中间开始查，一定会查错方向。</p>\n    <details style=\"margin-top:8px\"><summary class=\"dim\">高级：换体检用的域名 / NTP 源 / 到网关发几发</summary>\n      <div class=\"row\" style=\"margin-top:10px\">\n        <div><label>域名（公网不通时换内网里一定解析得到的名字）</label><input id=\"cku-d\" placeholder=\"默认 www.cloudflare.com\"></div>\n        <div><label>NTP 源（内网有自己的时钟源就填它）</label><input id=\"cku-n\" placeholder=\"默认 pool.ntp.org\"></div>\n        <div style=\"flex:0 0 150px\"><label>到网关发几发</label><input id=\"cku-p\" placeholder=\"默认 6（3 到 20）\"></div>\n      </div>\n    </details>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"cku-go\">开始体检</button></div>\n    <div id=\"cku-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#cku-out');
  const top = card.querySelector('#cku-top');
  card.querySelector('#cku-go').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">体检中…（八项并行，约 3 秒）</div>');
    const args = {};
    const d = card.querySelector('#cku-d').value.trim();
    const n = card.querySelector('#cku-n').value.trim();
    const p = Number(card.querySelector('#cku-p').value);
    if (d) args.domain = d;
    if (n) args.ntpServer = n;
    if (p) args.lanProbes = p;
    const r = await call('net.checkup', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">体检失败：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const items = v.items || [];
    const [title, cls, advice] = CK_TOP[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      <table style=\"margin-top:14px\">\n        <tr><th></th><th>按排查顺序</th><th>判定</th><th>看到的事实</th></tr>\n        {3}\n      </table>\n      <p class=\"hint\" style=\"margin-top:10px\">★ 只有 v4/v6 分开给的两项（到网关、出外网）才算得清「有一族出得去一半」——\n        那种机器不会断网，但每次连接都慢半拍。</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{4}</pre></details>', [bg, line, esc(advice), items.map((it, i) => ckRow(it, i, v.first)).join(''), esc(JSON.stringify(v, null, 2))]);
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
  'bundle-written': [t('包已写好'), 'ok',
    t('整个附件发给对方就行。★ 发之前过一眼：包里有内网地址、机器名、网卡名、进程名，')
    + t('发出去就等于把这些给了对方。口令、团体名、令牌、私钥在落盘前已经抹掉、键名留着，')
    + t('所以「配了但没给你看」和「没配」在包里分得开。')],
  'bundle-partial': [t('包写好了，但有几项没读出来'), 'warn',
    t('缺的那几项也在包里，各自写明为什么读不到 —— 对方不会把「没权限读」看成「这台没配」。')
    + t('★ 这一档八成是没给管理员权限：邻居表、本机端口占用、hosts 在非管理员下读不全。')
    + t('用管理员权限再导一次才补得齐；只想补那几项，就在高级里单独勾它们。')],
  'bundle-not-written': [t('这台写不出来'), 'bad',
    t('一个文件都没写出来，别去目录里找半截的包。★ 先看用户配置目录还能不能写')
    + t('（磁盘满、目录被别的用户占有、路径太深都会这样），或者在高级里只勾几项再导一次。')],
};
const DB_SEC = {
  'section-read': [t('在包里'), 'ok'],
  // ★ 包没写成时不许说「在包里」：内容确实读到了，但那一页此刻不存在于任何文件里。
  //   说成「在包里」，对方会去解一个根本不存在的 zip。
  'section-read-nopack': [t('读到了（没进包）'), 'warn'],
  'section-unreadable': [t('没读出来'), 'bad'],
  'section-skipped': [t('按你的要求跳过'), 'warn'],
};
// ★ 空壳那一档要单独说：判定码仍然只有 written / partial / not-written 三种，
//   「缺几项」和「一项都没缺出来」是两个说法，但不是两个判定 —— 后者由后端的
//   nothingRead 给（界面不自己数行：数错了就把「有六页内容」的包喊成空壳，反之也一样）。
const DB_ALLBAD = t('★ 这一趟一项都没读出来 —— 这个包里全是「为什么读不到」，没有内容。')
  + t('别把它当「这台机器干净」发出去：先按上面说的解决权限，再重导一次。');
// 与后端 sectionLabel / sectionOrder 一一对应：勾选项的顺序就是包里的顺序。
const DB_ITEMS = [
  ['system', t('系统与时间')], ['nic', t('网卡与地址')], ['routes', t('路由表')],
  ['neighbors', t('邻居表（ARP 与 NDP）')], ['dns', t('DNS 服务器')], ['hosts', t('hosts 文件')],
  ['proxy', t('代理设置')], ['ports', t('本机端口占用')], ['journal', t('NetKit 改过什么')],
  ['checkup', t('连通性体检')],
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
    : t('<span class=\"dim\">{0} 行</span>', [it.lines || 0]);
  return `<tr><td>${esc(it.label || it.item)}</td>
    <td><span class="pill ${tone}">${esc(text)}</span></td>
    <td><code class="dim">${file}</code></td>
    <td>${note}</td></tr>`;
}

function diagBundleCard() {
  const card = $(t('<div class=\"card\">\n    <h2>导出诊断包 <span id=\"db-top\"></span></h2>\n    <p class=\"hint\">把这台机器的网络现状打成一个 zip：网卡与地址、路由表、邻居表、DNS、hosts、代理、\n      本机端口占用、NetKit 改过什么，外加一项按排查顺序跑的连通性体检。★ 每一项都带<b>读到的原文</b>，\n      读不到的那一项也留在包里写明为什么 —— 对方不必再回来问「网关是哪台」。\n      落盘前统一脱敏（口令 / 团体名 / 令牌 / 私钥抹成 <code>***</code>，键名留着），包内文件名一律 UTF-8。\n      只在自己的输出目录里新建这一个文件，不改任何东西。</p>\n    <div class=\"row\" style=\"margin-top:10px\">\n      <div style=\"flex:1 1 240px\"><label>包名上的现场标签（建议填现场名，可留空）</label>\n        <input id=\"db-label\" placeholder=\"如 金宇建安-盒1\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn\" id=\"db-go\">导出诊断包</button></div>\n    </div>\n    <details style=\"margin-top:8px\"><summary class=\"dim\">高级：只要其中几项 / 不跑要发包的那一项 / 换体检域名</summary>\n      <div class=\"row\" style=\"margin-top:10px\">\n        <div style=\"flex:1 1 240px\"><label>体检用哪个域名测 DNS 与出口</label>\n          <input id=\"db-domain\" placeholder=\"默认 www.cloudflare.com；内网填内网一定解析得到的名字\"></div>\n      </div>\n      <label style=\"display:flex;gap:6px;align-items:center;margin-top:8px\">\n        <input type=\"checkbox\" id=\"db-nolive\" style=\"width:auto\"> 不跑要发探测包的那一项（只留配置快照）</label>\n      <p class=\"dim\" style=\"margin:10px 0 4px\">只要下面勾的这几项（一个都不勾 = 全给）。★ 对方只问了某件事时\n        别把不相干的配置一起发出去：</p>\n      <div id=\"db-only\" style=\"display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:4px 12px\"></div>\n    </details>\n    <div id=\"db-out\" style=\"margin-top:14px\"></div>\n  </div>'));
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
    out.innerHTML = t('<div class=\"empty\">正在一项项读…（体检那一项要发少量探测包，约 3 秒）</div>');
    const r = await call('net.diag.bundle', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">导不出来：{0}</div>', [esc(r.message || r.error)]); return; }
    const v = r.values;
    let [title, cls, advice] = DB_TOP[r.verdict] || [r.verdict || t('没给判定'), '', ''];
    if (v.nothingRead === true) { // 「有几项没读出来」在这一档说轻了
      title = t('包写好了，但这一趟什么都没读出来');
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
    const cuPill = cu ? t('<span class=\"pill {0}\">体检：{1}</span>', [cuTone, esc(cuName)]) : '';
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      {4}\n      {5}\n      {6}\n      {7}\n      <p class=\"hint\" style=\"margin-top:10px\">★ 每一项都带读到的原文：解开后那几页是给别人<b>接着查</b>的，\n        不是截图那种「看着像结论」的东西。时钟准不准、v6 出不出得去，在包里「02 连通性」那一页 ——\n        界面上要单独再问一次，去「域名与时间」。</p>\n      <p class=\"dim\" style=\"margin:10px 0 0\">{8}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{9}</pre></details>', [bg, line, esc(advice).replace(/\n/g, '<br>'), v.path ? t('<p style=\"margin:12px 0 0\">包：<code>{0}</code><br>\n        <span class=\"dim\">{1} · {2} 个文件 · 用时 {3}</span>\n        {4}\n        </p>', [esc(v.path), esc(fsSize(v.bytes)), v.entries || 0, ms(v.tookMs), cuPill ? t('　') + cuPill : '']) : '', v.reason ? t('<p style=\"margin:12px 0 0\">原因：{0}{1}</p>', [esc(v.reason), v.dir ? t('<br><span class=\"dim\">输出目录：<code>{0}</code></span>', [esc(v.dir)]) : '']) : '', items.length ? t('<table style=\"margin-top:12px\">\n        <tr><th>{0}</th><th>判定</th><th>哪一页</th><th>行数 / 为什么没读出来</th></tr>\n        {1}\n      </table>', [v.path ? t('包里的项') : t('读到的项'), items.map((it) => dbRow(it, !!v.path)).join('')]) : '', v.redactedHow ? t('<p class=\"dim\" style=\"margin:10px 0 0\">脱敏：{0}</p>', [esc(v.redactedHow)]) : '', (v.truncated || []).length ? t('<p class=\"dim\" style=\"margin:4px 0 0\">被截断的页：{0} —— 原文太长，要看全文用对应的工具单独再查一次。</p>', [esc((v.truncated || []).join(t('、')))]) : '', esc(r.note), esc(JSON.stringify(v, null, 2))]);
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
  occupied: [t('有人正在听这个口'), 'bad',
    t('要腾这个口就得停掉列出来的那个进程。★ 停之前先确认它是不是你要起的那个服务的守护进程 —— ')
    + t('有的服务由 xinetd / launchd 这类父进程拉起，停父的没用，停子的马上又被拉起来。')],
  'outbound-only': [t('不是被占着，是本机连出去留下的口'), 'warn',
    t('这个本地端口上没有任何监听，列出来的是本机当客户端连出去时内核顺手占住的临时端口。')
    + t('★ 去停它等于把正在跑的会话掐断，而且你要起的服务照样起不来。')
    + t('如果报「地址已在使用」，接着查 IPv6 上的同一个口 —— v6only 和双栈绑定不是一回事。')],
  free: [t('这个口没人用'), 'ok',
    t('本机没有任何进程在听它，也没有本机发起的连接在用它。★ 这一句只对本机成立 —— ')
    + t('要是服务起不来并报「地址已在使用」，多半是另一个用户或容器命名空间占的口，那要用管理员权限再问一次。')],
  partial: [t('只读到一部分，不能下结论'), 'bad',
    t('看不到那些进程不等于没在听 —— 非管理员读不到别人进程的句柄。')
    + t('★ 用管理员权限再问一次才算数，别把这一栏当「没人用」。')],
  listening: [t('本机在听这些口'), 'ok',
    t('这里只列监听，也就是这台机器对外提供的服务；本机连出去占用的临时端口没算进来。')
    + t('★ 想看某个口的全部用途，把端口号填进去再问一次。')],
  'no-listener': [t('一个监听都没有'), 'warn',
    t('这台机器现在不对外提供任何服务 —— 从别的机器看过来，它所有端口都是关着的。')],
  unsupported: [t('这个平台读不到'), '',
    t('这个操作系统上没有可靠的「端口 → 进程」读法。★ 读不到不等于没人占用，所以这里不去猜一个答案 —— ')
    + t('要查请在这台机器上用系统自带的工具。')],
};

function ppRow(u) {
  const fam = u.family === 'ipv6' ? '6' : u.family === 'ipv4' ? '4' : '';
  // ★ 没有 PID 和「有 PID 却看不到名字」是两件事：前者是内核自己占着
  //   （TIME_WAIT 那类，本来就没有主人），后者才是权限不够。
  //   写成一句，会让人白跑一趟 sudo。
  const svc = u.pid ? (u.process ? `<code>${esc(u.process)}</code>`
                                 : t('<span class=\"dim\">看不到（权限不够）</span>'))
                   : t('<span class=\"dim\">内核（连接留下的，还在等时租）</span>');
  // ★ UDP 那条提示只对 UDP 用：TCP 三个读法都给得出状态，真给不出时留空，
  //   别把「不知道」写成一句听着像结论的话。
  const state = u.state ? esc(u.state)
    : (u.proto === 'udp' ? t('<span class=\"dim\">绑上了（UDP 没有监听状态）</span>') : '<span class="dim">—</span>');
  const peer = u.foreign ? `<div class="dim">→ ${esc(u.foreign)}</div>` : '';
  return `<tr><td>${esc(u.proto)}${fam}</td>
    <td><code>${esc(u.local || '*')}</code>:<b>${u.port}</b>${peer}</td>
    <td>${state}</td>
    <td>${svc}${u.user ? ` <span class="dim">${esc(u.user)}</span>` : ''}</td>
    <td>${u.pid ? u.pid : '<span class="dim">—</span>'}</td></tr>`;
}

function portProcCard() {
  const card = $(t('<div class=\"card\">\n    <h2>这个端口被谁占了 <span id=\"pp-top\"></span></h2>\n    <p class=\"hint\">读本机内核的端口表，把「有进程在听」「本机连出去留下的临时口」「真没人用」「只读到一部分」\n      分开答 —— 这四种的下一步完全不同，而探端口只能从外面看，看不出本机里是谁占着。\n      ★ 只给进程名和 PID，不给命令行（命令行里常有口令，而结果会发给 AI）。纯读本机，不发任何包。</p>\n    <div class=\"row\">\n      <div style=\"flex:0 0 200px\"><label>端口号（留空 = 列出全部在听的）</label><input id=\"pp-port\" placeholder=\"554\"></div>\n      <div style=\"flex:0 0 150px\"><label>协议</label><select id=\"pp-proto\">\n        <option value=\"both\">TCP 和 UDP</option><option value=\"tcp\">只看 TCP</option>\n        <option value=\"udp\">只看 UDP</option></select></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn primary\" id=\"pp-go\">查</button></div>\n    </div>\n    <p class=\"hint\" style=\"margin-top:8px\">★ 查 UDP 要单独选一下：很多服务的口在 TCP 上根本没有，\n      而 UDP 没有「监听」这个状态位 —— 绑上就算。</p>\n    <div id=\"pp-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#pp-out');
  const top = card.querySelector('#pp-top');
  card.querySelector('#pp-go').onclick = async () => {
    const args = {};
    const p = Number(card.querySelector('#pp-port').value.trim());
    if (p) args.port = p;
    const proto = card.querySelector('#pp-proto').value;
    if (proto !== 'both') args.proto = proto;
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">读本机端口表…（要扫一遍进程句柄，一两秒）</div>');
    const r = await call('net.port.process', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">查不了：{0}</div>', [esc(r.message || r.error)]); return; }
    const v = r.values;
    const [title, cls, advice] = PP_CODE[r.verdict] || [r.verdict || t('没给判定'), '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const rows = [...(v.listening || []), ...(v.connections || [])];
    const listed = (v.listening || []).length;
    const total = v.listenerCount || listed;
    // ★ 没读成功（unsupported）时一行计数都不给 —— 那时候任何「在听 0 个」都是假结论。
    const warn = v.partial ? t(' · <b>只读到一部分，看不到不等于没有</b>') : '';
    let head = '';
    if (v.port) {
      head = t('<p class=\"hint\" style=\"margin-top:12px\">这个口上共 {0} 条记录', [v.count])
        + t('（其中在听的 {0} 个{1}）{2}</p>', [total, v.proto ? t('，只看 {0}', [v.proto.toUpperCase()]) : '', warn]);
    } else if (v.count !== undefined) {
      head = t('<p class=\"hint\" style=\"margin-top:12px\">本机在听 {0} 个端口', [total])
        + (v.truncated ? t('，这里只列出前 {0} 个（还有 {1} 个没列，填上端口号再问）', [listed, total - listed]) : '')
        + (v.totalRead ? t(' · 本机一共在用 {0} 个套接字', [v.totalRead]) : '') + warn + '</p>';
    }
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{4}</pre></details>', [bg, line, esc(advice), rows.length ? t('<table style=\"margin-top:14px\">\n        <tr><th>协议</th><th>本机地址</th><th>状态</th><th>进程</th><th>PID</th></tr>\n        {0}</table>{1}', [rows.map(ppRow).join(''), head]) : head, esc(JSON.stringify(v, null, 2))]);
  };
  return card;
}

// ★ 每个码带一句「下一步往哪查」—— 这三类问题的处理办法完全不同，
//   只写「解析失败」等于把人送回原地。
const DNS_CODE = {
  resolved: [t('解析到记录'), 'ok', ''],
  'no-record': [t('域名在，但没有这类记录'), 'warn',
    t('这是 NODATA：域名存在，只是没配你要的这类记录（比如只配了 A、没配 AAAA）。不是故障。')],
  nxdomain: [t('域名不存在'), 'bad', t('服务器明确说这个域名没有 —— 先核对是不是拼错了。')],
  'server-failure': [t('服务器自己查不到'), 'bad',
    t('SERVFAIL 是服务器那一边的问题（它的上游或转发坏了），换一台服务器大概率就能出结果。')],
  refused: [t('服务器拒绝查询'), 'bad', t('这台解析器不给递归查询（常见于只服务内网的 DNS），换一台公共 DNS 再问。')],
  timeout: [t('没有任何回应'), 'bad',
    t('分不清是服务器挂了、53 端口被拦、还是没有路由。换成问 8.8.8.8 或网关，能分清是哪一层。')],
  unreachable: [t('连不上这台服务器'), 'bad', t('连地址都到不了 —— 先确认这台 DNS 在不在本网、有没有路由。')],
  'bad-response': [t('回的不是 DNS 报文'), 'bad', t('这个端口后面大概不是 DNS 服务。')],
};

function dnsCard() {
  const card = $(t('<div class=\"card\">\n    <h2>DNS 查询 <span id=\"dqv\"></span></h2>\n    <p class=\"hint\">点名问一台 DNS 服务器，看它回什么。★ 现场有一大类问题是「网络是好的，就是解析不对」，\n      而它又分三种：服务器没回、它说查不到、答案本身不对（劫持 / 配了内网 DNS 却在查公网）—— 处理办法完全不同。</p>\n    <div class=\"row\">\n      <div><label>域名（查 PTR 就填 IP）</label><input id=\"dqn\" placeholder=\"www.example.com\"></div>\n      <div><label>记录类型</label><select id=\"dqt\">\n        <option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option>\n        <option>TXT</option><option>NS</option><option>SOA</option><option>PTR</option><option>SRV</option>\n      </select></div>\n      <div><label>问哪台服务器（留空=系统配的）</label><input id=\"dqs\" placeholder=\"192.168.1.1 或 223.5.5.5\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label><button class=\"btn primary\" id=\"dqgo\">查询</button></div>\n    </div>\n    <div id=\"dqout\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#dqout');
  const v = card.querySelector('#dqv');
  card.querySelector('#dqgo').onclick = async () => {
    v.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">查询中…</div>');
    const args = { name: card.querySelector('#dqn').value.trim(), type: card.querySelector('#dqt').value };
    const srv = card.querySelector('#dqs').value.trim();
    if (srv) args.server = srv;
    if (!args.name) { out.innerHTML = t('<div class=\"empty\">先填要查的域名或 IP。</div>'); return; }
    const r = await call('net.dns.query', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">查不了：{0}</div>', [esc(r.message)]); return; }
    const [text, cls, advice] = DNS_CODE[r.verdict] || [r.verdict, '', ''];
    v.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const val = r.values;
    const sys = (val.systemServers || []).map((s) => `${s.addr}${s.iface ? t('（') + s.iface + t('）') : ''}`).join(t('、'));
    const rows = (val.answers || []).map((a) => `<tr><td class="dim">${esc(a.type)}</td>
        <td><code>${esc(a.value)}</code></td><td class="dim">TTL ${a.ttl}</td></tr>`).join('');
    const chain = (val.cnameChain || []).map((c) => `<div class="dim"><code>${esc(c)}</code></div>`).join('');
    out.innerHTML = t('\n      {0}\n      <p class=\"hint\">问的 <code>{1}</code>{2}\n        · 用时 {3}ms · rcode {4}{5}</p>\n      {6}\n      {7}', [advice ? `<p class="hint">${esc(advice)}</p>` : '', esc(val.server), val.via === 'tcp' ? t('（UDP 被截断，改走 TCP）') : '', val.elapsedMs, esc(val.rcode || ''), sys ? t(' · 系统配的 DNS：{0}', [esc(sys)]) : '', chain ? t('<p class=\"hint\">CNAME 链：{0}</p>', [chain]) : '', rows ? t('<table><tr><th>类型</th><th>值</th><th></th></tr>{0}</table>', [rows])
             : t('<div class=\"empty\">这台服务器没给任何答案。</div>')]);
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
  'cert-ok': [t('证书正常'), 'ok', t('证书没过期、名字对得上、本机也认这条链 —— 网页打不开的话，原因不在证书上，往服务和网络上查。')],
  'cert-expired': [t('证书已过期'), 'bad', t('必须重新签发一张。过期之后所有客户端都会拒绝，重装应用、清缓存都没用。')],
  'cert-not-yet-valid': [t('证书还没到生效时间'), 'bad',
    t('这条几乎从来不是证书的错，是这台设备的时钟不对（掉电后重置回几年前那种）。先校时，再回来看证书。')],
  'cert-name-mismatch': [t('证书上的名字和访问的地址对不上'), 'bad',
    t('要么改用证书上写着的名字访问，要么按现在这个地址重签一张。浏览器报 ERR_CERT_COMMON_NAME_INVALID 就是这一条。')],
  'cert-self-signed': [t('自签证书'), 'warn',
    t('证书本身没过期，只是本机不认它这个根 —— 内网设备的出厂默认。要么把它的根证书装进本机信任列表，要么换一张正规签发的。')],
  'cert-unknown-authority': [t('本机验不过这条链'), 'warn',
    t('签发者不在信任列表里：常见于设备上只放了叶子证书、缺中间证书，或者本机没装企业/设备的根证书。')],
  'cert-expiring-soon': [t('快要到期了'), 'warn', t('现在换是顺手的事，等到现场发现打不开就是加班的事。')],
  'cert-weak-protocol': [t('证书可用，但对方只支持老版本 TLS'), 'bad',
    t('TLS 1.0/1.1 已被新版浏览器和平台直接拒绝连接。要升级设备侧的 TLS 栈，换证书解决不了。')],
  'not-tls': [t('这个端口回的不是 TLS'), 'bad', t('端口给错了 —— 它后面多半是明文 HTTP 或 RTSP，换对端口再来一次。')],
  'handshake-failed': [t('连上了，但 TLS 没谈成'), 'bad',
    t('常见于双方的协议版本/加密套件没有交集，或者对端根本不是 TLS 服务。细节看 reason。')],
  'no-certificate': [t('握手成功却没出示证书'), 'warn', t('用的是匿名加密套件（没有身份可验证），或者它不是按 HTTPS 出证的。')],
  'name-unresolved': [t('域名解析不到地址'), 'bad', t('还没走到证书这一步 —— 先用上方的 DNS 查询把解析查通。')],
  'closed': [t('端口关着'), 'bad', t('这个端口上没有 TLS 服务（对方明确拒绝，说明主机是在的）。')],
  'filtered': [t('没有任何回应'), 'bad', t('分不清端口是关着还是被防火墙静默丢了。')],
  'unreachable': [t('地址到不了'), 'bad', t('连路由都不通 —— 先确认地址填对了、和它之间有没有路。')],
};

// 逐个地址那行要短 —— 整句标题排成四行就没法看了。
const CERT_SHORT = {
  'closed': t('端口关着'), 'filtered': t('没回应'), 'unreachable': t('到不了'),
  'not-tls': t('不是 TLS'), 'handshake-failed': t('没谈成'),
};

function certCard() {
  const card = $(t('<div class=\"card\">\n    <h2>证书检查 <span id=\"cv\"></span></h2>\n    <p class=\"hint\">连一下对方的 TLS，把「打不开 / 连接不安全」拆成具体是哪一个：<b>过期</b> / <b>名字不匹配</b> /\n      <b>自签未受信</b> / <b>设备只支持老 TLS</b>。★ 只握手、不读业务数据。用 IP 访问但想按域名核对证书时，把域名填在第三个框里。</p>\n    <div class=\"row\">\n      <div><label>地址（域名或 IP，可带端口）</label><input id=\"cu\" placeholder=\"192.168.1.64 或 cam.example.com:8443\"></div>\n      <div style=\"flex:0 0 100px\"><label>端口</label><input id=\"cp\" placeholder=\"443\"></div>\n      <div><label>按哪个名字核对</label><input id=\"cn\" placeholder=\"证书上写的域名\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label><button class=\"btn primary\" id=\"cgo\">检查</button></div>\n    </div>\n    <div id=\"cout\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#cout');
  const top = card.querySelector('#cv');
  card.querySelector('#cgo').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">握手中…</div>');
    const addr = card.querySelector('#cu').value.trim();
    if (!addr) { out.innerHTML = t('<div class=\"empty\">先填要检查的地址。</div>'); return; }
    const args = { addr };
    const p = Number(card.querySelector('#cp').value);
    const name = card.querySelector('#cn').value.trim();
    if (p) args.port = p;
    if (name) args.serverName = name;
    const r = await call('net.tls.check', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">检查不了：{0}</div>', [esc(r.message)]); return; }
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
      : v.daysLeft < 0 ? t('<span class=\"pill bad\">已过期 {0} 天</span>', [-v.daysLeft])
        : t('还剩 <b>{0}</b> 天', [v.daysLeft]);
    const tries = (v.attempts || []).map((a) => `<div><code>${esc(a.address)}</code>
        <span class="pill ${CERT_CODE[a.code] ? CERT_CODE[a.code][1] : ''}">${esc(CERT_SHORT[a.code] || a.code)}</span>
        <span class="dim">${esc(a.detail || '')}</span></div>`).join('');
    // 没拿到证书的那些判定（端口关、不是 TLS、解析不到）就别摆一张空证书表
    const proto = v.protocol ? tCell(t('协议 / 套件'), `<code>${esc(v.protocol)}</code> ·
        <code>${esc(v.cipherSuite || '—')}</code>${v.weakProtocol ? t('<span class=\"pill bad\">版本太老</span>') : ''}`) : '';
    const cert = v.subject ? `
        ${tCell(t('主体 / 签发者'), `${esc(v.subject)} <span class="dim">←</span> ${esc(v.issuer || '—')}`)}
        ${tCell(t('有效期'), t('{0} <span class=\"dim\">到</span> {1} · {2}', [esc(v.notBefore || '?'), esc(v.notAfter || '?'), days]))}
        ${tCell(t('包括的名字'), names.length ? names.map((n) => `<code>${esc(n)}</code>`).join(' ')
          : t('<span class=\"dim\">证书里没写备用名字（只有主题那一个）</span>'))}
        ${tCell(t('三项核对'), `${flag(v.hostnameMatch, t('名字对得上'), t('名字不对'))}
          ${flag(v.trusted, t('本机认这条链'), t('本机不认'), 'ok', 'warn')}
          ${flag(!v.selfSigned, t('正规签发'), t('自签'), 'ok', 'warn')}`)}
        ${v.chain && v.chain.length ? tCell(t('证书链'),
          v.chain.map((c) => `<code>${esc(c)}</code>`).join(' <span class="dim">←</span> ')) : ''}` : '';
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}{3}</div>\n      <table style=\"margin-top:14px\">\n        {4}\n        {5}\n        {6}\n        {7}\n      </table>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{8}</pre></details>', [bg, line, esc(advice), v.reason ? `<div class="dim" style="margin-top:6px">${esc(v.reason)}</div>` : '', tCell(t('连到哪'), `<code>${esc(v.target || '—')}</code>
          <span class="dim">${esc(v.family || '')}${v.hostname ? t(' · 域名 ') + esc(v.hostname) : ''}</span>`), proto, cert, tries ? tCell(t('逐个地址'), tries) : '', esc(JSON.stringify(v, null, 2))]);
  };
  return card;
}

// 网页探测的码 → 人话。★ 后端只给码，句子在这儿（多语种靠这条分工）。
const HTTP_CODE = {
  'http-ok': [t('通了'), 'ok', t('状态码是 2xx。慢不慢看下面那行分段耗时 —— 卡在网络还是卡在服务端，处理的人完全不同。')],
  'http-redirect': [t('它在跳转，还没到终点'), 'warn',
    t('全链在下面。★ 现场最常见的两种：http 没跳到 https（内容混拦，浏览器会提示不安全），或者跳到了一个本机到不了的内网地址。')],
  'http-client-error': [t('请求本身的事（4xx）'), 'warn',
    t('服务是活着的、明确回了话，拒的是这个请求：地址不对、没登录、或者方法不让用。往地址和权限上查，别往网络上查。')],
  'http-server-error': [t('服务端自己出错了（5xx）'), 'bad',
    t('网络这一趟是通的（它回话了），问题在它后面：程序异常、上游服务坏了、或者超出负载。')],
  'http-redirect-loop': [t('重定向绕圈'), 'bad',
    t('跳到这一链里已经来过的地址，永远到不了终点。多为反向代理和站点互相把 http 改 https、https 又改回 http。')],
  'http-timeout': [t('整条请求超时'), 'bad',
    t('哪一段没走完看下面的分段：耗时是 0 的那一段就是没走到的那一段。')],
  'not-http': [t('这个端口回的不是 HTTP'), 'warn',
    t('多半是 RTSP、RTMP 或设备自己的私有协议 —— 取流用「摄像头取流」那一页探。')],
  'wrong-scheme': [t('协议前缀写反了'), 'warn',
    t('★ 这不是故障：把地址开头的 http / https 换成另一个就能通。省得去查一个根本没坏的服务。')],
  'tls-handshake-failed': [t('TLS 握手被对方拒了'), 'bad',
    t('常见于它要求客户端证书，或者双方的协议版本没有交集。细节看原始结果里的 detail。')],
  'name-unresolved': [t('域名解析不到地址'), 'bad', t('还没走到连接这一步 —— 先用上方的 DNS 查询把解析查通。')],
  'closed': [t('端口关着'), 'bad', t('对方明确拒绝：这个端口上没有 HTTP 服务（机器本身是活的）。')],
  'filtered': [t('没有任何回应'), 'bad', t('分不清端口是关着还是被静默丢了 —— 换 net.ping 看主机在不在。')],
  'unreachable': [t('地址到不了'), 'bad', t('连路由都不通，先确认地址填对了、和它之间有没有路。')],
};

// 分段耗时条：四段按各自占比铺颜色，一眼看出长的那截是谁。
// ★ 「慢在网络」和「慢在服务端」的分工就是这一页存在的全部理由，所以非要把比例画出来不可。
function timingBar(tm, answered) {
  const segs = [
    [t('解析'), tm.lookupMs, 'var(--gold-dim)'],
    [t('连接'), tm.connectMs, 'var(--green-dim)'],
    ['TLS', tm.tlsMs, 'var(--green-bg)'],
    [t('服务端'), tm.serverMs, 'var(--red-bg)'],
  ];
  const net = (tm.lookupMs || 0) + (tm.connectMs || 0) + (tm.tlsMs || 0);
  const app = tm.serverMs || 0;
  const rest = Math.max(0, (tm.totalMs || 0) - net - app);
  const parts = segs.concat([[t('其他'), rest, 'var(--panel-2)']]);
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
    say = t('<span class=\"pill bad\">没走到终点</span>\n      <span class=\"dim\">分段耗时停在哪儿，路就断在哪儿 —— 服务端那一段根本没开始计时，不做归因。</span>');
  } else if (app >= net * 2 && app > 200) {
    say = t('<span class=\"pill warn\">慢在应用侧</span> <span class=\"dim\">网络三段加起来 {0}ms，服务端自己想 {1}ms —— 找维护这个服务的人，网络这边没问题。</span>', [net, app]);
  } else if (net >= app * 2 && net > 200) {
    say = t('<span class=\"pill bad\">慢在网络侧</span> <span class=\"dim\">解析+连接+TLS 共 {0}ms，服务端只想了 {1}ms —— 往链路、TLS 握手和 DNS 上查。</span>', [net, app]);
  }
  // 什么都没花到（比如端口直接关着）就别画一条空 bar —— 空条比没有条更像坏了
  const spent = parts.some(([, ms]) => ms > 0);
  if (!spent && !say) return '';
  return `${spent ? t('<div style=\"display:flex;height:18px;border-radius:4px;overflow:hidden;background:var(--panel-2)\">{0}</div>\n    <p class=\"hint\" style=\"margin:8px 0 0\">{1} <span class=\"dim\">·</span> 总计 <b>{2}</b>ms\n      {3}</p>', [bar, list, esc(tm.totalMs), tm.ttfbMs ? t('（首字节 {0}ms）', [tm.ttfbMs]) : '']) : ''}
    ${say ? `<p class="hint" style="margin:${spent ? '6px' : '0'} 0 0">${say}</p>` : ''}`;
}

function httpCard() {
  const card = $(t('<div class=\"card\">\n    <h2>网页 / 接口探测 <span id=\"hv\"></span></h2>\n    <p class=\"hint\">问一个 HTTP(S) 地址要状态码，并把耗时拆成 <b>解析 / 连接 / TLS / 等回话</b> 四段 ——\n      前三段慢是网络的事，最后一段慢是服务端的事。★ 重定向链每一跳都留着（自动跟随会把「它 301 到哪儿」吃掉）。\n      证书顺带判一次，但<b>不因证书坏就不给状态码</b>。不下载正文。</p>\n    <div class=\"row\">\n      <div><label>地址</label><input id=\"hu\" placeholder=\"192.168.1.64 或 https://cam.example.com/login\"></div>\n      <div style=\"flex:0 0 110px\"><label>方法</label><select id=\"hm\"><option>GET</option><option>HEAD</option></select></div>\n      <div style=\"flex:0 0 110px\"><label>最多跟几跳</label><input id=\"hr\" placeholder=\"10，填 0 只看第一跳\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label><button class=\"btn primary\" id=\"hgo\">探测</button></div>\n    </div>\n    <div id=\"hout\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#hout');
  const top = card.querySelector('#hv');
  card.querySelector('#hgo').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">请求中…</div>');
    const args = { url: card.querySelector('#hu').value.trim() };
    if (!args.url) { out.innerHTML = t('<div class=\"empty\">先填地址。</div>'); return; }
    const m = card.querySelector('#hm').value;
    if (m === 'HEAD') args.method = 'HEAD';
    const r = Number(card.querySelector('#hr').value);
    if (r >= 0 && card.querySelector('#hr').value.trim() !== '') args.maxRedirects = r;
    const res = await call('net.http.probe', args);
    if (!res.ok) { out.innerHTML = t('<div class=\"empty\">探测不了：{0}</div>', [esc(res.message)]); return; }
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
    const tlsRow = t ? tCell(t('证书'), `<span class="pill ${(CERT_CODE[t.verdict] || ['', ''])[1]}">
        ${esc((CERT_CODE[t.verdict] || [t.verdict])[0])}</span>
      <span class="dim">${esc(t.protocol || '')} · ${esc(t.subject || '')}${
      t.daysLeft === undefined ? '' : t.daysLeft < 0 ? t(' · 已过期 {0} 天', [-t.daysLeft]) : t(' · 剩 {0} 天', [t.daysLeft])}</span>`) : '';
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}{3}\n        {4}</div>\n      {5}\n      <table style=\"margin-top:14px\">\n        {6}\n        {7}\n      </table>\n      {8}\n      {9}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{10}</pre></details>', [bg, line, esc(advice), v.reason ? `<div class="dim" style="margin-top:6px">${esc(v.reason)}</div>` : '', v.detail ? `<div class="dim" style="margin-top:6px"><code>${esc(v.detail)}</code></div>` : '', v.timings ? `<div style="margin-top:14px">${timingBar(v.timings, v.status)}</div>` : '', tCell(t('结果'), `<span class="pill ${cls}">${esc(v.status || text)}</span>
          <code>${esc(v.method || 'GET')} ${esc(v.url)}</code>
          <span class="dim">${esc(v.proto || '')}${v.server ? ' · ' + esc(v.server) : ''}
            ${v.contentType ? ' · ' + esc(v.contentType) : ''}
            ${v.contentLength ? ' · ' + esc(v.contentLength) + t(' 字节') : ''}</span>`), v.remote ? tCell(t('实际连到'), t('<code>{0}</code>\n          <span class=\"dim\">域名两族都有记录时，这一条决定该往 v4 还是 v6 查</span>', [esc(v.remote)])) : '', chain ? t('<p class=\"hint\" style=\"margin:12px 0 4px\">重定向链{0}</p>\n        <div style=\"font-size:13.5px;line-height:1.9\">{1}</div>', [v.redirectCount ? t('（跟了 {0} 跳）', [v.redirectCount]) : '', chain]) : '', tlsRow ? `<table>${tlsRow}</table>` : '', esc(JSON.stringify(v, null, 2))]);
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
  'path-ok': [t('这条路走得通'), 'ok',
    t('每一族的追踪都到了终点。慢不慢看下面逐跳的往返 —— 某一跳突然变大，就是那里。到了终点还上不了服务，那是端口或服务的事，去「网站与证书」那一页问它回什么。')],
  'path-partial': [t('一族到、另一族断在半路'), 'bad',
    t('★ 双栈机器上最贵的一种漏报：应用往往优先走 IPv6，就先卡在那条上。下面两族并排，断的那族写着停在哪台设备。')],
  'path-broken': [t('两族都没走到终点'), 'bad',
    t('断在哪一跳、停在哪台设备上，见下面逐跳。先处理写着「本机没路」或「断在中间」的那一族。')],
  'path-incomplete': [t('结论不全，别急着查网络'), 'warn',
    t('有一族没给出结论：可能是这台机器缺追踪命令，也可能只是跳数或时间用完 —— 那两种都该调参数或换机器，而不是去查一条没坏的路。看下面各族自己那一行。')],
  'reached': [t('走到了终点'), 'ok', ''],
  'stalled': [t('断在中间某跳'), 'bad',
    t('最后一台有回应的设备之后，再没人回过话。停在哪台下面写着。')],
  'no-response': [t('第一跳就没回应'), 'warn',
    t('★ 这「不说明路断了」：路由器不回应 ICMP 超时时，整条路都是这个形状，目标可能好好的。改用 ping / 探端口确认到不到得了终点。')],
  'max-hops': [t('跳数用完了'), 'warn',
    t('一路都有回应、只是没走到终点。该做的是把上面的「最多几跳」调大再看，不是查网络。')],
  'no-route': [t('本机这一族没有出路'), 'bad',
    t('探测包在这台机器上就发不出去 —— v6 被关的招牌表现。查这一族的网卡地址和默认路由，用上方「双栈体检」。')],
  'needs-privilege': [t('命令要管理员权限'), 'warn',
    t('追踪要发原始探测包。以管理员身份再跑一次；Linux 上可换 tracepath，普通用户就能跑。')],
  'trace-timeout': [t('整条追踪超时'), 'warn',
    t('已经走到的跳在下面，并标了「不完整」。哪一族在耗时间，看它有没有跳出第一跳；要更久的话把上面的超时调大。')],
  'no-command': [t('这台机器没有可用的追踪命令'), 'warn',
    t('★ 这是工具没有，不是路上没设备 —— 装 traceroute 或换台机器再追，别去查网络。')],
  'name-unresolved': [t('域名解析不到地址'), 'bad', t('还没走到追路径这一步 —— 先用上方的 DNS 查询把解析查通。')],
};

const TRACE_SHORT = {
  'reached': t('到了终点'), 'stalled': t('断在中间'), 'no-response': t('没回应'),
  'max-hops': t('跳数用完'), 'no-route': t('本机没路'), 'needs-privilege': t('要权限'),
  'trace-timeout': t('超时'), 'no-command': t('没命令'),
};

// 逐跳画成一排小方块：丢的跳留灰块，别让它从图上消失 ——
// 只画回了的那些，人就看不出「其实第 3、4 跳根本没吭声」。
function traceRail(hops) {
  const chips = hops.map((h) => {
    const rtt = (h.rttMs || []).length
      ? `${Math.min(...h.rttMs).toFixed(1)}ms` : t('不回');
    const bg = h.isGoal ? 'var(--green-bg)' : h.addr ? 'var(--panel-2)' : 'var(--gold-bg)';
    const line = h.isGoal ? 'var(--green-dim)' : h.addr ? 'var(--gold-dim)' : 'var(--red-line)';
    return `<div title="${esc(h.addr || t('这一跳没回应'))}${h.mark ? ' · ' + esc(h.mark) : ''}"
      style="background:${bg};border:1px solid ${line};border-radius:5px;padding:5px 8px;min-width:96px;font-size:12.5px">
      <span class="dim">#${h.hop}</span>
      <code>${esc(h.addr || '—')}</code>
      <span class="${h.addr ? 'dim' : 'pill warn'}">${esc(rtt)}</span>
      ${h.lost ? t('<span class=\"dim\" title=\"这一跳发了几个、丢了几个\">丢{0}</span>', [h.lost]) : ''}
      ${h.mark ? `<span class="pill bad">${esc(h.mark)}</span>` : ''}
      ${h.isGoal ? t('<span class=\"pill ok\">终点</span>') : ''}</div>`;
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
      ? t('<p class=\"hint\"><span class=\"pill warn\">一个都没回</span> <span class=\"dim\">探测发出去了，从第一跳起没人吭声。</span></p>')
      : '';
  const stop = f.lastAddr
    ? t('<span class=\"dim\">停在</span> <code>{0}</code> <span class=\"dim\">第 {1} 跳</span>', [esc(f.lastAddr), f.hopsSeen]) : '';
  const extra = f.detail || f.tried
    ? `<div class="dim" style="margin-top:6px;font-size:12.5px">${esc([f.detail, f.tried].filter(Boolean).join(t(' ｜ ')))}</div>` : '';
  return `<div style="margin-top:14px">
    <p style="margin:0 0 8px">
      <b>${esc((f.family || '').toUpperCase())}</b>
      <span class="pill ${cls}">${esc(TRACE_SHORT[f.code] || text)}</span>
      ${f.partial ? t('<span class=\"pill warn\">不完整</span>') : ''}
      ${stop}
      <span class="dim"> · ${esc(f.command || '')}</span></p>
    ${rail}
    ${extra}</div>`;
}

function traceCard() {
  const card = $(t('<div class=\"card\">\n    <h2>路径追踪 <span id=\"tv\"></span></h2>\n    <p class=\"hint\">走到目标要经过哪几台设备、<b>断在哪一跳</b>。★ 默认 IPv4、IPv6 各追一遍并排给结果 ——\n      现场最常见的正是「一族到、另一族断在半路」。中途个别跳不全是常态，卡片不会据此说路断了；\n      整条都不回（路由器限速 ICMP）会单独标成「没回应」，而不是「断在第一跳」。用的哪条命令如实写出来。</p>\n    <div class=\"row\">\n      <div><label>目标（域名或 IP）</label><input id=\"th\" placeholder=\"192.168.1.1 或 camera.example.com\"></div>\n      <div style=\"flex:0 0 110px\"><label>地址族</label>\n        <select id=\"tf\"><option value=\"auto\">两族都追</option><option value=\"v4\">只追 v4</option><option value=\"v6\">只追 v6</option></select></div>\n      <div style=\"flex:0 0 90px\"><label>最多几跳</label><input id=\"tm\" placeholder=\"30\"></div>\n      <div style=\"flex:0 0 90px\"><label>每跳几个探测</label><input id=\"tq\" placeholder=\"1\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label><button class=\"btn primary\" id=\"tgo\">追踪</button></div>\n    </div>\n    <div id=\"tout\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#tout');
  const top = card.querySelector('#tv');
  card.querySelector('#tgo').onclick = async () => {
    top.innerHTML = '';
    const host = card.querySelector('#th').value.trim();
    if (!host) { out.innerHTML = t('<div class=\"empty\">先填目标地址。</div>'); return; }
    out.innerHTML = t('<div class=\"empty\">追踪中…（最长 1 分钟，两族各分一半时间）</div>');
    const args = { host, family: card.querySelector('#tf').value };
    const n = Number(card.querySelector('#tm').value);
    const q = Number(card.querySelector('#tq').value);
    if (n > 0) args.maxHops = n;
    if (q > 0) args.perHop = q;
    const r = await call('net.trace', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">追不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice] = TRACE_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      <p class=\"hint\" style=\"margin-top:12px\"><span class=\"dim\">引擎：{4}</span></p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{5}</pre></details>', [bg, line, esc(advice), (v.traces || []).map(traceFamilyBlock).join(''), esc(v.engine || ''), esc(JSON.stringify(v, null, 2))]);
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
  'quality-ok': [t('这条路一直很好'), 'ok', t('每一跳的丢包和往返都在正常范围里。要是还是觉得卡，那多半不是这条路径的事 —— 换「网页 / 接口探测」看服务自己慢不慢。')],
  'quality-silent-loss': [t('中间有设备不回探测，但路是通的'), 'warn',
    t('★ 看着吓人的那一行是「这台设备不爱回话」，不是它丢包：它后面的每一跳都收得到。家用和园区网的路由器普遍给 ICMP 超时做限速。要修的是探测能不能问到自己，不是这条路。')],
  'quality-path-changed': [t('同一跳出现过不止一个地址'), 'warn',
    t('多为等价路径负载分担（本来就这样），或者是路由在翻动。翻动本身不卡人，「每次换到一条更烂的路」才会 —— 对照下面的丢包和往返看。')],
  'quality-latency-jump': [t('从某一跳起明显变慢，而且一直到终点都慢'), 'bad',
    t('抬升起点那一跳就是分界：它之前还是好的，之后一路都带上这份延迟。要查的是那一段链路（或者出口拥塞），不是终点自己。')],
  'quality-target-loss': [t('中间的跳都正常，只有终点在丢'), 'bad',
    t('路是通的（每一跳都替它作证了），丢的是「到终点这最后一段」：终点自己在限速 ICMP、防火墙把它挡了，或者它真的忙不过来。先用 ping / 探端口确认它服不服务。')],
  'quality-loss': [t('从某一跳起，丢包一路延续到终点'), 'bad',
    t('★ 这才是真的拥塞/故障点：下面标了从第几跳开始。中间某跳丢但后面能收到，不算这一条 —— 那种是它不爱回话。')],
  'quality-no-response': [t('一个像样的样本都没拿到'), 'warn',
    t('★ 这「不说明路断了」：第一跳起就不回 ICMP（整条路都被限速）时就是这个形状。改用 ping / 探端口确认终点到不到得了。')],
  'no-route': [t('本机这一族没有出路'), 'bad', t('探测包在这台机器上就发不出去 —— v6 被关的招牌表现。查这一族的地址和默认路由，用上方「双栈体检」。')],
  'needs-privilege': [t('命令要管理员权限'), 'warn', t('持续逐跳探测要发原始包。以管理员身份再跑一次。')],
  'no-command': [t('这台机器没有可用的探测命令'), 'warn', t('★ 这是工具没有，不是路上没设备 —— 装 traceroute 或 mtr，或换台机器再测。')],
  'trace-timeout': [t('时间用完，只跑到一部分轮'), 'warn', t('已完成的轮都在下面。要更准的丢包率就调大「几轮」或超时，别调小。')],
  'name-unresolved': [t('域名解析不到地址'), 'bad', t('还没到探测这一步 —— 先用上方的 DNS 查询把解析查通。')],
  // 两族并排时，有一族没跑成：结论只覆盖跑成的那族
  'path-incomplete': [t('结论不全，别急着查网络'), 'warn',
    t('有一族压根没测成（缺命令或要权限）。跑成的那族结论在下面 —— 没测过的那族既不能说好也不能说坏。')],
};

const MTR_SHORT = {
  'quality-ok': t('一直很好'), 'quality-silent-loss': t('假丢包'), 'quality-path-changed': t('路径在翻动'),
  'quality-latency-jump': t('某跳起变慢'), 'quality-target-loss': t('只有终点丢'), 'quality-loss': t('一路在丢'),
  'quality-no-response': t('没样本'), 'no-route': t('本机没路'), 'needs-privilege': t('要权限'),
  'no-command': t('没命令'), 'trace-timeout': t('时间不够'),
};

// 每跳的注记 → 那行的颜色和那一句话。★ 注记是后端给的**判定**，不是样式提示。
const MTR_FLAG = {
  'loss-source': ['bad', t('丢包从这里开始，并且一路带到了终点')],
  'target': ['bad', t('只有它在丢：中间的跳都收到了')],
  'silent': ['warn', t('只丢自己的回应，转发的流量它一个没丢')],
  'latency-start': ['warn', t('往返从这里开始抬升，并延续到终点')],
  'path-moved': ['', t('这一跳见过不止一个下一跳')],
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
    const who = h.addr ? `<code>${esc(h.addr)}</code>` : t('<span class=\"dim\">不回</span>');
    const moved = h.addrs && h.addrs.length > 1
      ? t('<div class=\"dim\" style=\"font-size:12px\">还见过 {0}</div>', [esc(h.addrs.filter((a) => a !== h.addr).join(t('、')))]) : '';
    const goal = h.isGoal ? t('<span class=\"pill ok\">终点</span>') : '';
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
    ? `<div class="dim" style="margin-top:6px;font-size:12.5px">${esc([f.detail, f.tried].filter(Boolean).join(t(' ｜ ')))}</div>` : '';
  return t('<div style=\"margin-top:14px\">\n    <p style=\"margin:0 0 8px\">\n      <b>{0}</b>\n      <span class=\"pill {1}\">{2}</span>\n      <span class=\"dim\">{3}/{4} 轮 · {5}</span>\n      {6}\n      {7}\n      {8}\n      {9}</p>\n    {10}\n    {11}</div>', [esc((f.family || '').toUpperCase()), cls, esc(MTR_SHORT[f.code] || text), f.roundsDone, f.rounds, esc(f.engine || ''), f.partial ? t('<span class=\"pill warn\">不完整</span>') : '', f.lossHop ? t('<span class=\"pill bad\">丢包起点 第 {0} 跳</span>', [f.lossHop]) : '', f.latencyHop ? t('<span class=\"pill warn\">变慢起点 第 {0} 跳</span>', [f.latencyHop]) : '', !f.goalSeen && f.hops && f.hops.length ? t('<span class=\"pill warn\">一次都没走到终点</span>') : '', rows ? t('<table><tr><th>跳</th><th>设备</th><th>丢包</th><th>平均</th><th>最差</th><th></th></tr>{0}</table>', [rows]) :
      t('<p class=\"hint\">这一族一个样本都没拿到。</p>'), head]);
}

function mtrCard() {
  const card = $(t('<div class=\"card\">\n    <h2>路径质量（逐跳持续探测）<span id=\"qo\"></span></h2>\n    <p class=\"hint\">把「偶尔卡一下 / 隔十几秒花一格」这种主诉查出来：<b>同一批跳连着问几十次</b>，\n      每一跳给出丢包率（带分母）、平均和最差往返。★ 中间某跳丢、后面每跳都收得到，会明说是\n      「这台设备只丢自己的回应，没丢转发」，不当故障报；从某跳起一路丢到终点才算拥塞点，并点名那一跳。\n      装了 mtr 就用它（同样时间样本多一个量级），没装就跑多轮 traceroute，用的是哪个都写出来。</p>\n    <div class=\"row\">\n      <div><label>目标（域名或 IP）</label><input id=\"qh\" placeholder=\"192.168.1.1 或 camera.example.com\"></div>\n      <div style=\"flex:0 0 110px\"><label>地址族</label>\n        <select id=\"qf\"><option value=\"auto\">两族都测</option><option value=\"v4\">只测 v4</option><option value=\"v6\">只测 v6</option></select></div>\n      <div style=\"flex:0 0 80px\"><label>几轮</label><input id=\"qn\" placeholder=\"8\"></div>\n      <div style=\"flex:0 0 90px\"><label>每跳几个</label><input id=\"qq\" placeholder=\"3\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label><button class=\"btn primary\" id=\"qgo\">开始测量</button></div>\n    </div>\n    <div id=\"qout\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#qout');
  const top = card.querySelector('#qo');
  card.querySelector('#qgo').onclick = async () => {
    top.innerHTML = '';
    const host = card.querySelector('#qh').value.trim();
    if (!host) { out.innerHTML = t('<div class=\"empty\">先填目标地址。</div>'); return; }
    out.innerHTML = t('<div class=\"empty\">测量中…（默认 8 轮 × 每跳 3 发，最长 1 分钟）</div>');
    const args = { host, family: card.querySelector('#qf').value };
    const n = Number(card.querySelector('#qn').value);
    const q = Number(card.querySelector('#qq').value);
    if (n > 0) args.rounds = n;
    if (q > 0) args.perHop = q;
    const r = await call('net.mtr', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">测不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice] = MTR_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{4}</pre></details>', [bg, line, esc(advice), (v.reports || []).map(mtrFamilyBlock).join(''), esc(JSON.stringify(v, null, 2))]);
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
  'time-ok': [t('时钟是对的'), 'ok', t('几个时间源说的都对得上，本机时钟和标准只差几十毫秒以内 —— 证书、租约、日志排序不会因此出问题。要是还在报「证书没生效」，那是别的事。')],
  'time-skewed': [t('时钟有偏差'), 'warn', t('偏差不小，但还没到会把证书和租约判错的程度。★ 只有一个源答的时候，这里只说差多少，不说谁不对 —— 想指认本机，需要多个源互相印证。')],
  'time-way-off': [t('时钟差得足以让别的东西出错'), 'bad', t('这个量级上，证书会被判「还没生效」或「已过期」、租约会被算成早到期、日志时间戳排不进正确的顺序 —— 现场看到的「网有问题」，根在这里。至于是不是本机不对，看下面那行：多个源互相印证过才敢指认。')],
  'time-servers-disagree': [t('时间源之间自己就对不上'), 'warn', t('★ 这时候不能指认本机不对：至少有一个时间源自己就是坏的（或者中间有设备在改写 NTP）。先看下面哪一行和别的不一样，把它从服务器列表里去掉再问一次。')],
  'time-no-response': [t('一个时间源都没回'), 'warn', t('最常见是 UDP 123 被挡（很多出口默认不放）。★ 这只说明「问不到标准时间」，不说明本机的钟是坏的 —— 要判断时钟，先放行 NTP 或者换成内网的时钟源。')],
  'time-kiss-rejected': [t('时间源拒答'), 'warn', t('对方明确回了「不给」：RATE 是问得太密被限速，STEP 是它直说你的钟偏得超过它的容错 —— 后者等于替你确认了「时钟确实不对」。看下面每一行的码分别是哪一种。')],
  'time-bad-response': [t('回的不是 NTP'), 'bad', t('端口上有回应，但内容不是时间戳。多为链路上有设备在冒充/改写 NTP，或者这个端口上挂着别的服务。换一个端口或换一台服务器再问。')],
  'name-unresolved': [t('服务器域名解析不出来'), 'bad', t('还没到问时间这一步 —— 用上方「DNS 查询」把解析查通，或者直接填 IP。')],
};

const TIME_SHORT = {
  'time-ok': t('时钟对的'), 'time-skewed': t('有偏差'), 'time-way-off': t('差得离谱'),
  'time-servers-disagree': t('源对不上'), 'time-no-response': t('问不到'),
  'time-kiss-rejected': t('被拒答'), 'time-bad-response': t('回的不是NTP'), 'name-unresolved': t('解析不出'),
  'answered': t('答了'),
};

// 偏差要给人读成「慢了多少」而不是一个浮点数：几十毫秒和差三年，是两种完全不同的活。
function humanMs(ms) {
  const a = Math.abs(ms);
  if (a < 1000) return a.toFixed(1) + t(' 毫秒');
  if (a < 60000) return (a / 1000).toFixed(a < 10000 ? 1 : 0) + t(' 秒');
  if (a < 3600000) return Math.floor(a / 60000) + t(' 分 ') + Math.round((a % 60000) / 1000) + t(' 秒');
  if (a < 86400000) return Math.floor(a / 3600000) + t(' 小时 ') + Math.floor((a % 3600000) / 60000) + t(' 分');
  return (a / 86400000).toFixed(a < 864000000 ? 1 : 0) + t(' 天');
}

// 后端出 RFC3339（带毫秒），界面把它写成能一眼读完的一行。
function fmtStamp(s) {
  return s ? s.replace('T', ' ') : '—';
}

function timeSourceRow(s) {
  const [text, cls] = TIME_CODE[s.code] || [s.code, ''];
  const answered = s.code === 'answered';
  const dir = answered ? (s.offsetMs > 0 ? t('本机慢') : t('本机快')) : '';
  return `<tr>
    <td><code>${esc(s.server)}</code>${s.leap ? t('<div class=\"dim\" style=\"font-size:12px\">闰秒预警：{0}</div>', [s.leap === 'insert' ? t('接下来要插一秒') : t('这一分钟删过一秒')]) : ''}</td>
    <td><span class="pill ${answered ? '' : cls}">${esc(TIME_SHORT[s.code] || text)}</span>
        ${s.kiss ? `<span class="pill warn">${esc(s.kiss)}</span>` : ''}</td>
    <td>${answered ? `<b>${humanMs(s.offsetMs)}</b> <span class="dim">${dir}</span>` : '—'}</td>
    <td>${answered && s.rttMs ? esc(s.rttMs) + 'ms' : '—'}</td>
    <td>${answered ? `<span class="dim">stratum ${esc(s.stratum)}${s.refId ? ' ← ' + esc(s.refId) : ''}</span>` : '—'}</td>
    <td class="dim">${esc(s.samples)}/${esc(s.answers)}${s.detail ? `<div style="font-size:12px">${esc(s.detail)}</div>` : ''}</td>
  </tr>`;
}

function timeCard() {
  const card = $(t('<div class=\"card\">\n    <h2>校时检查 <span id=\"wv\"></span></h2>\n    <p class=\"hint\">问一台权威时间源「现在几点」。★ 时钟不对的症状从来不长在时间上 ——\n      <b>证书报「还没生效」、日志排不成序、租约被判过期</b>，现场查了半天查的是别的东西。\n      这一栏给偏差（带方向和量级）、给「本机说几点 / 标准说几点」，并且<b>只有多个时间源互相印证时</b>\n      才说「是本机的钟不对」；只问到一个源时只报差多少、不指认谁错。源之间对不上，会点出有个源自己就坏了。</p>\n    <div class=\"row\">\n      <div><label>时间源（留空问默认公网源；内网有自己的时钟源就填它的地址）</label>\n        <input id=\"ws\" placeholder=\"192.168.1.1, ntp.internal（逗号分隔）\"></div>\n      <div style=\"flex:0 0 90px\"><label>端口</label><input id=\"wp\" placeholder=\"123\"></div>\n      <div style=\"flex:0 0 100px\"><label>每个源问几次</label><input id=\"wn\" placeholder=\"3\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label><button class=\"btn primary\" id=\"wgo\">对一下表</button></div>\n    </div>\n    <div id=\"wout\" style=\"margin-top:14px\"></div>\n  </div>'));
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
    out.innerHTML = t('<div class=\"empty\">正在问时间源…（各源并行，最长约 10 秒）</div>');
    const r = await call('net.time.check', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice] = TIME_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const answered = v.agreeSources > 0;
    // ★ 指认「谁不对」的底气只来自源之间的一致：一个源的时候这句话不能说。
    const blame = v.attribution === 'corroborated'
      ? t('<span class=\"pill ok\">{0} 个源说得一致 → 是本机的钟不对</span>', [v.agreeSources]) :
      v.attribution === 'conflict' ? t('<span class=\"pill warn\">源之间对不上 → 不能指认本机</span>') :
      v.attribution === 'single-source' ? t('<span class=\"pill warn\">只问到一个源 → 只报偏差，不说谁错</span>') :
      t('<span class=\"pill warn\">没问到任何标准时间 → 无从指认</span>');
    out.innerHTML = t('\n      {0}\n      <div style=\"background:{1};border:1px solid {2};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {3}</div>\n      <p style=\"margin:10px 0 0\">{4}\n        {5}</p>\n      <table style=\"margin-top:10px\"><tr><th>时间源</th><th>结果</th><th>偏差</th><th>往返</th><th>它的上游</th><th>问/回</th></tr>\n        {6}</table>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{7}</pre></details>', [answered ? t('<div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n        <div><label>本机说</label><div><b>{0}</b></div></div>\n        <div><label>标准时间（{1}）</label><div><b>{2}</b></div></div>\n        <div><label>差</label><div><span class=\"pill {3}\">{4}，本机{5}</span></div></div>\n      </div>', [esc(fmtStamp(v.localTime)), esc(v.checkedWith || ''), esc(fmtStamp(v.standardTime)), cls, esc(humanMs(v.offsetMs)), v.localSlow ? t('慢') : t('快')]) : '', bg, line, esc(advice), blame, v.spreadMs ? t('<span class=\"dim\">源之间最大差 {0}</span>', [esc(humanMs(v.spreadMs))]) : '', (v.sources || []).map(timeSourceRow).join(''), esc(JSON.stringify(v, null, 2))]);
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
  'udp-responsive': [t('有回包'), 'ok', t('这个端口后面确实有个会答话的服务 —— 不用再猜了。')],
  'udp-closed': [t('端口没人监听'), 'warn',
    t('对方回了 ICMP 端口不可达：主机是活的，只是这个端口没有服务。要么是服务没起来，要么你打错了端口。')],
  'udp-silent-alive': [t('端口不出声，机器是活的'), 'warn',
    t('目标端口没答，但同一台机器的对照端口出声了 —— 至少能排除「整机不对」。剩下的两种还得往下分：')
    + t('端口开着但它不答你这一句（换成协议里真实的一条报文再问一次），或者这个端口被单独拦了。')],
  'udp-silent': [t('UDP 整段静默'), 'bad',
    t('目标端口和对照端口都没出声。分不清是机器不在、还是这条路把 UDP 整段丢了 —— ')
    + t('先用上面的 ping 看机器在不在，再往上查防火墙/交换机。')],
  'unknown': [t('判不出来'), 'warn', t('包根本没发出去（看原始结果里的 detail），这不算端口不通。')],
};

function udpCard() {
  const card = $(t('<div class=\"card\">\n    <h2>探 UDP 端口 <span id=\"uv\"></span></h2>\n    <p class=\"hint\">向一个 UDP 端口发一发看它答不答。<b>多数服务不认识空包</b> ——\n      只想知道「5060 上有没有 SIP」，就把 <code>payload</code> 填成协议里真实的一句话（或用\n      <code>payloadHex</code> 发二进制报文），否则它不理你，你只能拿到「没反应」。\n      对照探测会再打一个肯定没人监听的端口，用它的反应把「这台机器不对」和「只是这个端口的事」分开；\n      生产设备上不想到处发包可以关掉。</p>\n    <div class=\"row\">\n      <div><label>目标地址（只收 IP）</label><input id=\"ua\" placeholder=\"192.168.1.1\"></div>\n      <div style=\"flex:0 0 90px\"><label>端口</label><input id=\"up\" placeholder=\"5060\"></div>\n      <div><label>发的内容（留空 = 空包）</label><input id=\"upay\" placeholder=\"OPTIONS sip:1sip:1 SIP/2.0\"></div>\n      <div style=\"flex:0 0 130px\"><label>或十六进制</label><input id=\"uphex\" placeholder=\"00010000\"></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:10px\">\n      <div style=\"flex:0 0 130px\"><label>对照端口</label><input id=\"uctl\" placeholder=\"50000\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <label style=\"display:flex;align-items:center;gap:6px;font-weight:400\">\n          <input type=\"checkbox\" id=\"unctlo\" style=\"width:auto\"> 不跑对照，只发目标这一发</label></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn primary\" id=\"ugo\">探一下</button></div>\n    </div>\n    <div id=\"uout\" style=\"margin-top:14px\"></div>\n  </div>'));
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
    out.innerHTML = t('<div class=\"empty\">正在发…（要跑对照的话最坏等两个超时）</div>');
    const r = await call('net.udp.probe', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">探不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice] = UDP_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const c = v.control;
    out.innerHTML = t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n        <div><label>目标</label><div><b><code>{0}</code></b></div></div>\n        <div><label>回包</label><div>{1}</div></div>\n        <div><label>等了</label><div>{2}ms</div></div>\n        <div><label>对照端口</label><div>{3}</div></div>\n      </div>\n      <div style=\"background:{4};border:1px solid {5};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {6}{7}</div>\n      <p class=\"dim\" style=\"margin:10px 0 0\">{8}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{9}</pre></details>', [esc(v.target), v.answered ? t('<b>{0} 字节</b>', [esc(v.bytes)]) : t('<span class=\"dim\">没有</span>'), esc(v.elapsedMs), c
          ? `<code>:${esc(c.port)}</code> ${c.answered ? t('<span class=\"pill ok\">出声了</span>') : t('<span class=\"pill warn\">也没出声</span>')}`
          : t('<span class=\"dim\">没跑</span>'), bg, line, esc(advice), v.detail ? `<div class="dim" style="margin-top:6px;font-size:12.5px">${esc(v.detail)}</div>` : '', esc(r.note), esc(JSON.stringify(v, null, 2))]);
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
  'ports-open': [t('有端口开着'), 'ok',
    t('下面列出来的端口连上了。要知道某个服务为什么不通，再用上面的单端口探测看它答得多慢。')],
  'ports-closed': [t('没有端口开着，但主机是活的'), 'warn',
    t('有端口明确回了拒绝 —— 拒绝说明对方收到了包并且答了，所以主机在、路也通，只是这些端口上没有服务。')
    + t('★ 别把它当成「机器挂了」去查链路。')],
  'ports-no-response': [t('一个都没回话'), 'bad',
    t('所有端口都静默。这不能说明主机不在：整段被防火墙静默丢、地址根本没人用，都是这个形状。')
    + t('先用「ping 与端口」那一页问一次它在不在，再查对端的防火墙。')],
  'ports-no-route': [t('包根本没出去'), 'bad',
    t('到这个地址没有路 —— 一个包都没发出去，所以这跟对端防不防火没有关系。查自己：网卡起来了吗、')
    + t('和它是不是同一个网段（看「网卡与路由」那一页；两族是不是都通，去「域名与时间」那一页做双栈体检）。')],
};

// 单端口状态沿用 net.tcp.probe 那三个码，界面和体检项因此只有一套词。
const SCAN_STATUS = {
  'open': [t('开着'), 'ok'],
  'closed': [t('关着'), 'bad'],
  'filtered': [t('没回话'), 'warn'],
  'no-route': [t('没路'), 'bad'],
  'error': [t('判不出来'), 'warn'],
};

function scanCard() {
  const card = $(t('<div class=\"card\">\n    <h2>扫一片端口 <span id=\"sv\"></span></h2>\n    <p class=\"hint\">对<b>一台</b>主机批量做 TCP 连接探测。端口可以写 <code>22,80,443</code>、区间\n      <code>8000-8010</code>、混着写；留空扫一批现场常用端口（含 RTSP / ONVIF / 各厂商 SDK 端口）。\n      ★ 一次连太多端口，有些摄像机会当成爆破把这台机器临时锁掉 —— 在生产设备上把并发和端口数都收着点。</p>\n    <div class=\"row\">\n      <div><label>目标地址（只收 IP）</label><input id=\"sa\" placeholder=\"192.168.1.64\"></div>\n      <div><label>端口（留空 = 常用端口集）</label><input id=\"spts\" placeholder=\"22,80,554,37777 或 8000-8100\"></div>\n      <div style=\"flex:0 0 110px\"><label>单端口等待 ms</label><input id=\"stim\" placeholder=\"500\"></div>\n      <div style=\"flex:0 0 110px\"><label>同时几个</label><input id=\"scnc\" placeholder=\"32\"></div>\n    </div>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"sgo\">开始扫</button></div>\n    <div id=\"sout\" style=\"margin-top:14px\"></div>\n  </div>'));
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
    out.innerHTML = t('<div class=\"empty\">正在扫…（最坏要等「端口数 ÷ 并发数」轮超时，端口多就慢）</div>');
    const r = await call('net.ports.scan', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">扫不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice] = SCAN_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const open = (v.openPorts || []).map((p) => `<code>${esc(p)}</code>`).join(' ') || t('<span class=\"dim\">无</span>');
    const rows = (v.ports || []).map((p) => {
      const [w, pc] = SCAN_STATUS[p.status] || [p.status, ''];
      return `<tr><td><code>${esc(p.port)}</code></td><td><span class="pill ${pc}">${esc(w)}</span></td>
        <td class="dim">${p.elapsedMs ? esc(p.elapsedMs) + 'ms' : ''}</td>
        <td class="dim">${esc(p.detail || '')}</td></tr>`;
    }).join('');
    out.innerHTML = t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n        <div><label>目标</label><div><b><code>{0}</code></b></div></div>\n        <div><label>扫了</label><div>{1} 个</div></div>\n        <div><label>开着</label><div><b>{2}</b></div></div>\n        <div><label>关着</label><div>{3}</div></div>\n        <div><label>没回话</label><div>{4}</div></div>\n        <div><label>没路</label><div>{5}</div></div>\n      </div>\n      <div style=\"margin-bottom:12px\"><label>开着的端口</label><div>{6}</div></div>\n      {7}\n      <div style=\"background:{8};border:1px solid {9};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {10}</div>\n      {11}\n      <p class=\"dim\" style=\"margin:10px 0 0\">{12}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{13}</pre></details>', [esc(v.target), esc(v.scanned), esc(v.open), esc(v.closed), esc(v.filtered), esc(v.noRoute || 0), open, v.warning === 'many-connections' ? t('<div style=\"background:var(--gold-bg);border:1px solid var(--gold-dim);\n        border-radius:6px;padding:9px 12px;margin-bottom:12px;font-size:13px\">\n        这次连了 {0} 个端口。不少摄像头和录像机把短时间内的批量连接当成爆破，\n        会把这台机器临时锁几分钟 —— 扫完发现「突然什么都不通了」，先想到这个。</div>', [esc(v.scanned)]) : '', bg, line, esc(advice), rows ? t('<table style=\"margin-top:14px\"><tr><th>端口</th><th>状态</th><th>等了</th><th></th></tr>{0}</table>', [rows])
        : v.portsOmitted ? t('<p class=\"dim\" style=\"margin-top:14px\">扫了 {0} 个端口，逐端口的明细就不列了\n            —— 一整屏「关着」里没有一条是信息，反而会把真开着的几个埋掉。开着的端口已经在上面列出来了，\n            要看某几个的明细，把端口填窄一点再扫一次。</p>', [esc(v.scanned)]) : '', esc(r.note), esc(JSON.stringify(v, null, 2))]);
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
  'mtu-path': [t('路上有个更小的限制'), 'warn',
    t('大包就是在中间某个环节被挡住的：隧道、PPPoE、VPN、或者被人改小过 MTU 的交换机口。')
    + t('把这台机器的网卡 MTU 设成上面那个数（或更小）就能过去；要根治就去查中间那一环。')],
  'mtu-local': [t('上限是本机网卡，路上没测到更小的限制'), 'ok',
    t('没撞到比本机网卡更小的尺寸。大包发不出去的话，先查本机这块网卡的 MTU 和分片设置，')
    + t('别去翻隧道和路由器 —— 这一趟没看到它们挡过东西。')],
  'mtu-no-limit-found': [t('测到上限都没被挡'), 'ok',
    t('这次的「最大测到」是上面填的那个值，所以只能说到这儿都是通的。想确认更大的尺寸，')
    + t('把上限调大再测一次，多花的只是几次二分。')],
  'mtu-no-response': [t('对方不回回执，这一栏测不出东西'), 'bad',
    t('连起手的那个小包都没回执 —— 这台主机不回 ICMP，或者这条路把差错报文挡了。')
    + t('★ 这不代表 MTU 有问题：「收不到回执」和「大包真的过不去」长得一模一样。先用「ping 与端口」那一页问一次它在不在。')],
  'mtu-no-route': [t('包根本没出去'), 'bad',
    t('到这个地址没有路，一个包都没发出去，所以跟路径 MTU 无关。查自己：网卡起来了吗、')
    + t('和它是不是同一个网段（看「网卡与路由」那一页；两族是不是都通，去「域名与时间」那一页做双栈体检）。')],
  'mtu-df-unsupported': [t('这台机器上测不了'), 'bad',
    t('这一栏靠的是「不许分片」那个套接字选项；它设不上、或者设上了内核却照旧自己把大包切开时，')
    + t('量出来的数会大得离谱。宁可不给结论，也不端一个假的 MTU 出来 —— 那是会照着设进网卡的。')],
};

// 逐个尺寸的探测记录。二分不一定正好测到「第一个过不去」的那个，所以明细要摆出来给人看。
const MTU_OUTCOME = {
  'through': [t('过得去'), 'ok'],
  'too-big': [t('太大被挡'), 'bad'],
  'silent': [t('没回执'), 'warn'],
  'no-route': [t('没路'), 'bad'],
  'error': [t('发不出去'), 'warn'],
};

function mtuCard() {
  const card = $(t('<div class=\"card\">\n    <h2>路径 MTU <span id=\"mv\"></span></h2>\n    <p class=\"hint\">查<b>「连得上、小包都好，就是大包过不去」</b>：视频一出来就卡、传文件传到一半断，\n      而 ping 和端口探测都正常 —— 因为它们在路上过的包本来就不大。隧道 / VPN / PPPoE /\n      被改小过 MTU 的端口都会这样。做法是给一个 UDP 包设「不许分片」，二分地试不同大小，\n      看从哪儿开始发不出去。<b>只收 IP。</b></p>\n    <div class=\"row\">\n      <div><label>目标地址（只收 IP）</label><input id=\"ma\" placeholder=\"192.168.1.64\"></div>\n      <div style=\"flex:0 0 130px\"><label>探测端口</label><input id=\"mp\" placeholder=\"9253（留空即可）\"></div>\n      <div style=\"flex:0 0 130px\"><label>最大测到</label><input id=\"mm\" placeholder=\"留空 = 本机网卡 MTU\"></div>\n      <div style=\"flex:0 0 110px\"><label>单尺寸等待 ms</label><input id=\"mt\" placeholder=\"700\"></div>\n    </div>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"mgo\">开始探</button></div>\n    <div id=\"mout\" style=\"margin-top:14px\"></div>\n  </div>'));
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
    out.innerHTML = t('<div class=\"empty\">正在二分探大小…（大约十几步，每步最多等一个超时）</div>');
    const r = await call('net.mtu.path', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">探不了：{0}</div>', [esc(r.message)]); return; }
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
      ? t('<div><label>路径 MTU（IP 包总长）</label><div style=\"font-size:26px\"><b>{0}</b> 字节</div></div>', [esc(v.pathMtu)])
      : v.carriesAtLeast != null
        ? t('<div><label>至少能过</label><div style=\"font-size:26px\"><b>{0}</b> 字节</div></div>', [esc(v.carriesAtLeast)])
        : '';
    out.innerHTML = t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n        <div><label>目标</label><div><b><code>{0}</code></b></div></div>\n        {1}\n        <div><label>出口网卡</label><div>{2}</div></div>\n        <div><label>探测端口</label><div>{3}</div></div>\n        <div><label>靠哪一层测的</label><div>{4}</div></div>\n      </div>\n      {5}\n      {6}\n      <div style=\"background:{7};border:1px solid {8};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {9}</div>\n      {10}\n      <p class=\"dim\" style=\"margin:10px 0 0\">{11}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{12}</pre></details>', [esc(v.target), figure, e.mtu ? `<code>${esc(e.iface)}</code> MTU ${esc(e.mtu)}` : t('<span class=\"dim\">没读到</span>'), esc(v.port), esc(v.engine), v.dfVerified === false ? t('<div style=\"background:var(--red-bg);border:1px solid var(--red-line);\n        border-radius:6px;padding:9px 12px;margin-bottom:12px;font-size:13px\">\n        这台机器上「不许分片」设上了却不干活（超过网卡 MTU 的包照发出去，内核自己切开了）。\n        这样量出来的任何 MTU 都是假的，所以没有给数。</div>') : '', v.warning === 'below-ipv6-min' ? t('<div style=\"background:var(--gold-bg);border:1px solid var(--gold-dim);\n        border-radius:6px;padding:9px 12px;margin-bottom:12px;font-size:13px\">\n        IPv6 链路上按规定至少该能过 1280 字节，这里测出来比它还小 —— 中间有设备不守规矩，\n        这个数别当成正常的路径 MTU 用。</div>') : '', bg, line, esc(advice), rows ? t('<table style=\"margin-top:14px\"><tr><th>包大小（IP 总长）</th><th>结果</th><th>等了</th><th></th></tr>{0}</table>', [rows]) : '', esc(r.note), esc(JSON.stringify(v, null, 2))]);
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
  'no-reply': [t('没回执（超时）'), 'warn'],
  'unreachable': [t('明确不可达'), 'bad'],
  'error': [t('包没出去（本机）'), 'bad'],
};

const WATCH_CODE = {
  'stable': [t('稳'), 'ok',
    t('这一段每一发都有回执、快慢也平 —— 「卡」不是这一台在这段时间的问题，去别的环节找')
    + t('（应用自己的超时、DNS、对端的服务）。')],
  'jitter': [t('抖'), 'warn',
    t('没丢包，但快慢差得明显。★ 先看下面点名的那一发是第几秒 —— 无线链路、挤满的 AP、')
    + t('对端在干重活都会这样。如果整条线都在晃而挑不出单发，那是链路质量本身在晃，不是谁卡了一下。')],
  'loss': [t('丢包'), 'bad',
    t('有发数没拿到回执。★ 丢和抖是两种病，处理方向不同：丢要查链路（信号、网线、端口协商、环路），')
    + t('抖多半是排队。底下写清了丢在第几发、是超时还是明确不可达。')],
  'no-reply': [t('一个都没回'), 'warn',
    t('这一栏分不出「主机不在」和「ICMP 被挡」，所以给不出稳定性结论。先去「ping 与端口」那一页确认这台存在。')],
  'unreachable': [t('明确不可达'), 'bad',
    t('每一发都拿到了「到不了」的回执 —— 包出得去、也有人回话，中间的路是通的，')
    + t('问题在终点或路由（对端关机、地址没人要、中间设备没路由）。这跟「被防火墙挡了」是两个结论。')],
  'no-route': [t('本机没路'), 'bad',
    t('包根本没出去，跟对端没关系。查自己这边：网卡起没起、地址配没配、是不是同一个网段。')],
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
  return t('<svg viewBox=\"0 0 {0} {1}\" style=\"width:100%;height:auto;display:block\" role=\"img\"\n      aria-label=\"每一发的往返时间\">\n      <line x1=\"{2}\" y1=\"{3}\" x2=\"{4}\" y2=\"{5}\" stroke=\"var(--line)\"/>\n      {6}{7}{8}{9}\n      <text x=\"{10}\" y=\"{11}\" fill=\"var(--muted)\" font-size=\"10\">\n        {12}ms</text>\n      <text x=\"{13}\" y=\"{14}\" text-anchor=\"end\" fill=\"var(--muted)\" font-size=\"10\">\n        {15}s</text>\n    </svg>', [W, H, P, H - P, W - P, H - P, holes.join(''), segs.join(''), dots.join(''), rings, P, P - 4, esc(hi.toFixed(1)), W - P, P - 4, (span / 1000).toFixed(1)]);
}

// prefix 传 'baseline' 时读的是 baselineSent / baselineRttMedianMs 这一批 ——
// ★ 后端把前缀后的首字母大写了（mergeStats 里的 upper1），这里必须按同一个口径拼，
//   拼错不会报错，只会让对照组的八个格子全显示「没测到」。
function watchSummaryRows(v, prefix) {
  const p = prefix || '';
  const key = (k) => (p ? p + k[0].toUpperCase() + k.slice(1) : k);
  const num = (n, unit) => (n == null ? t('<span class=\"dim\">没测到</span>') : `<b>${esc(n)}</b>${unit}`);
  return t('<div class=\"row\" style=\"gap:18px;flex-wrap:wrap;margin-top:10px\">\n    <div><label>发了</label><div>{0}</div></div>\n    <div><label>回了</label><div>{1}</div></div>\n    <div><label>明确不可达</label><div>{2}</div></div>\n    <div><label>丢包率</label><div>{3}</div></div>\n    <div><label>中位</label><div>{4}</div></div>\n    <div><label>95 分位</label><div>{5}</div></div>\n    <div><label>最慢</label><div>{6}</div></div>\n    <div><label>相邻两发抖动</label><div>{7}</div></div>\n  </div>', [num(v[key('sent')], ''), num(v[key('recv')], ''), num(v[key('unreachable')], ''), num(v[key('lossPercent')], '%'), num(v[key('rttMedianMs')], 'ms'), num(v[key('rttP95Ms')], 'ms'), num(v[key('rttMaxMs')], 'ms'), num(v[key('jitterAvgMs')], 'ms')]);
}

function pingWatchCard() {
  const card = $(t('<div class=\"card\">\n    <h2>连续 ping（看抖不抖）<span id=\"pwv\"></span></h2>\n    <p class=\"hint\">专查<b>「有时候卡一下」</b>：四发的 ping 问不出这个毛病，因为那一下没赶上。\n      这里按时间连发，把每一发都留下 —— 曲线之外还会点出<b>第几发、第几秒、抖成什么样</b>，\n      拿那个时刻去对现场发生了什么。可选填一个对照地址（一般是网关），\n      用来分「只有这台慢」和「这一整段都在抖」。</p>\n    <div class=\"row\">\n      <div><label>目标地址</label><input id=\"pwa\" placeholder=\"192.168.1.64\"></div>\n      <div style=\"flex:0 0 130px\"><label>间隔 ms</label><input id=\"pwi\" placeholder=\"500\"></div>\n      <div style=\"flex:0 0 130px\"><label>看多久 ms</label><input id=\"pwd\" placeholder=\"10000（最多 60000）\"></div>\n      <div style=\"flex:0 0 130px\"><label>单发等待 ms</label><input id=\"pwt\" placeholder=\"1000\"></div>\n      <div><label>对照地址（可留空）</label><input id=\"pwb\" placeholder=\"192.168.1.1 网关\"></div>\n    </div>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"pwgo\">开始连发</button></div>\n    <div id=\"pwout\" style=\"margin-top:14px\"></div>\n  </div>'));
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
    out.innerHTML = t('<div class=\"empty\">连发中…（约 {0} 秒，两腿一起跑时要再久一点）</div>', [secs]);
    const r = await call('net.ping.watch', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">测不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice] = WATCH_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';

    const spikes = (v.spikes || []).length
      ? t('<div style=\"margin-top:12px\"><label>抖在哪一发</label><div style=\"font-size:13.5px\">\n          {0}</div></div>', [(v.spikes || []).map((s) => {
    const one = (v.samples || []).find((x) => x.seq === s) || {};
    return t('<span style=\"background:var(--gold-bg);border:1px solid var(--gold-dim);\n              border-radius:5px;padding:3px 8px;margin-right:8px;display:inline-block\">\n              第 {0} 发 · {1}s · {2}ms\n            </span>', [esc(s), esc(((one.atMs || 0) / 1000).toFixed(1)), esc(Math.round(one.rttMs || 0))]);
  }).join('')]) : '';

    const lost = (v.lostAt || []).length
      ? t('<div style=\"margin-top:12px\"><label>丢在哪几发</label>\n          <table><tr><th>第几发</th><th>第几秒</th><th>是哪种没回执</th></tr>\n          {0}\n          </table>\n          <p class=\"dim\" style=\"margin:6px 0 0\">★ 「明确不可达」和「超时」是两种东西：前者有人回话说够不着，\n            后者连句话都没有 —— 前者查路由和终点，后者多半是挡包。</p></div>', [(v.lostAt || []).map((m) => `<tr><td><code>${esc(m.seq)}</code></td>
            <td>${esc(((m.atMs || 0) / 1000).toFixed(1))}s</td>
            <td>${pillOf(WATCH_KIND, m.kind)}</td></tr>`).join('')]) : '';

    const baseBlock = v.compare ? t('\n      <div style=\"margin-top:16px\">\n        <label>对照组 {0} <span class=\"dim\">（同一轮里跑的，用来分「谁在抖」）</span></label>\n        {1}\n        {2}\n      </div>', [esc(v.baseline), watchChart(v.baselineSamples || [], v.baselineSpanMs || v.spanMs, 'base', []), watchSummaryRows(v, 'baseline')]) : '';
    const cmp = v.compare ? `
      <div style="margin-top:12px;background:${bg};border:1px solid ${line};border-radius:6px;
        padding:10px 12px;font-size:13.5px">${esc(CMP_TEXT[v.compare] || v.compare)}${
  v.compare === 'both' && v.compareWorse && v.compareWorse !== 'similar'
    ? esc(v.compareWorse === 'target' ? t('（更难看的是目标这台）') : t('（更难看的是对照组那台）')) : ''}</div>` : '';

    out.innerHTML = t('\n      <div class=\"row\" style=\"gap:18px;margin-bottom:10px;flex-wrap:wrap\">\n        <div><label>目标</label><div><b><code>{0}</code></b> {1}</div></div>\n        <div><label>间隔 / 时长</label><div>{2}ms · {3}s</div></div>\n        <div><label>实到</label><div>{4}s\n          {5}</div></div>\n      </div>\n      {6}\n      {7}\n      {8}{9}{10}{11}\n      <div style=\"margin-top:14px;background:{12};border:1px solid {13};border-radius:6px;\n        padding:10px 12px;font-size:13.5px\">{14}</div>\n      <p class=\"dim\" style=\"margin:10px 0 0\">{15}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果（逐发留痕）</summary>\n        <pre class=\"dim\">{16}</pre></details>', [esc(v.target), esc(v.family), esc(v.intervalMs), esc((v.durationMs / 1000).toFixed(0)), esc(((v.spanMs || 0) / 1000).toFixed(1)), v.actualIntervalMs && v.actualIntervalMs > v.intervalMs * 1.5
    ? t('<span class=\"pill warn\">实际每发 {0}ms</span>', [esc(v.actualIntervalMs)]) : '', watchChart(v.samples || [], v.spanMs, 'target', v.spikes), watchSummaryRows(v, ''), spikes, lost, baseBlock, cmp, bg, line, esc(advice), esc(r.note), esc(JSON.stringify(v, null, 2))]);
  };
  return card;
}

const CMP_TEXT = {
  'neither': t('两条线都干净 —— 目标这一路没毛病。'),
  'target-only': t('同一轮里对照组是干净的 —— 毛病只在这台，去查它自己（网卡、驱动、它那条链路）。'),
  'baseline-only': t('同一轮里反倒是对照组不干净，目标这台没问题。'),
  'both': t('同一轮里对照组也不干净 —— 先查这一段链路（网段、AP、出口），别只盯这一台。'),
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
  'hosts-found': [t('问到了设备'), 'ok',
    t('清单在下面，每台都写着凭什么判定它在线。★ 收到自己的 ping 应答最硬，')
    + t('「应了 ARP 但没应 ping」的摄像头很常见（不少设备管理页里有一键禁 ping），别当成不在。')],
  'no-hosts': [t('一个信号都没收到'), 'warn',
    t('这不能读成「这个网段是空的」：整段被静默（交换机端口隔离、防火墙拦 ICMP）')
    + t('和「真的没有设备」在结果上长一个样。先确认本机这块网卡真的接在这个网里。')],
};

// 一台设备被判在线的证据，按强弱分档。★ 不写凭什么，人就不敢信这张表。
const EVIDENCE = {
  icmp: [t('收到它自己的 ping 应答'), 'ok'],
  arp: [t('应了 ARP，没应 ping'), 'ok'],
  'arp-cache': [t('本机缓存里的旧记录'), 'warn'],
  tcp: [t('端口有应答（连上或被拒）'), 'ok'],
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
  'devices-found': [t('认出了是谁'), 'ok',
    t('下面每一台写的都是<b>它自己说过的话</b>（名字、类型、管理地址）。')
    + t('★ 空着的那一格意思是「这台没说」，不是「没有」——这一栏宁可留空也不按 MAC 前缀猜厂商：')
    + t('猜对九次、错一次，人就顺着错的那一次去机房。')],
  'heard-anonymous': [t('有人应，但一句身份都没说'), 'warn',
    t('这些地址上有东西在答话，可它没说过自己是谁 —— 这<b>不等于没有设备</b>，')
    + t('也不等于坏了。最常见的是固件里把发现服务关掉的摄像头，和不开 UPnP 的路由/交换机。')
    + t('下一步：拿其中一个地址去「ping 与端口」那一页扫端口，看它开了什么（554 是 RTSP、80/443 是管理页）。')],
  'no-device-answered': [t('问过的口径没人应答'), 'warn',
    t('★ 这一条<b>不能</b>读成「这个网段里没有设备」：设备不喊这几种话、中间隔着一层路由、')
    + t('交换机做了组播抑制，三种病在这里长一个样。先在「问几轮」填 3 再问一次')
    + t('（UDP 会丢，问两轮的命中率明显高于把一轮拉长），再用「网段上有哪些地址」那一页确认地址上到底有没有人。')],
  'no-interface': [t('一块能问的网卡都没有'), 'bad',
    t('一个都没问出去，所以这份结果里没有任何一栏可以说设备的事。')
    + t('先看网线插没插、这块网卡禁没禁用、有没有拿到 IPv4 地址（「网卡与路由」那一页）。')],
  'no-multicast-route': [t('组播发不出去'), 'bad',
    t('本机或路上某台设备把组播挡了 —— 容器里跑、VPN 只给了一个 /32、系统禁了组播，都会卡在这里。')
    + t('换一块有 IPv4 的网卡，或者在「点名问哪些地址」里直接填那个 IP：')
    + t('★ 点名时我们发的是<b>单播</b>，不靠组播出去，隔着路由也能问到。')],
  'stopped': [t('还没问到东西就停了'), 'warn',
    t('这份只覆盖停之前那一段，<b>不能</b>当成整个网段的答案：')
    + t('慢的设备（老摄像头、走 802.11 的笔记本）第二轮才答话是常态。')],
};

const DISCOVER_CODE = {
  'found-unconfigured': [t('有设备还没配好网络'), 'warn',
    t('下面标出来的设备只有 IPv6 链路本地地址、没有 IPv4 —— 大概率是刚拆封、还没配网的那台。')
    + t('这正是这一栏最值钱的用途：在一大堆设备里把「需要动手的那台」挑出来。')],
  'all-configured': [t('应答的设备都已经配好地址'), 'ok',
    t('没有发现缺 IPv4 地址的设备。★ 这里只听得见应 IPv6 应答的那些，')
    + t('纯 v4 的老设备不在这一栏的视野里，要看整段就去扫网段。')],
  'no-responder': [t('没人应答'), 'warn',
    t('一个应答都没收到。可能是这块网卡没插线、不在这个网里，或者上游把 IPv6 邻居发现挡了。')],
  'no-link-local': [t('本机喊不出去'), 'bad',
    t('要用的那块网卡连自己的 IPv6 链路本地地址都没有 —— 这个地址是自动生成的，')
    + t('没有它就说明这台的 IPv6 没起来，先去「网卡与路由」那一页看一眼。')],
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
  'snmp-ok': [t('SNMP 通，团体名可用'), 'ok',
    t('这台设备认这个团体名，路也是通的。下面 MAC 表、端口、PoE、LLDP 那几栏都可以问了。')],
  'snmp-no-reply': [t('没有回话'), 'bad',
    t('问了两次（重传）都没一个包回来。这三种病在报文上完全同形，分不开：')
    + t('团体名不对（v2c 不报错，直接把你的包丢在地上）、防火墙或设备 ACL 没放行、这台设备没开 SNMP。')
    + t('先核团体名，再用「ping 与端口」那一页的「探 UDP 端口」问 161/udp 有没有反应。')],
  'snmp-reply-unmatched': [t('有回包，但对不上号'), 'warn',
    t('路上有东西在回话，只是对不上这次问的 —— 这「不是」没人答。最常见的是设备上把 trap 目标')
    + t('配成了这台机器（那 SNMP 本身是通的，把团体名或视图再核一遍），其次是同网段有第二台在答同一个请求。')],
  'snmp-v1-only': [t('这台只认 v1'), 'warn',
    t('v2c 没答、换成 v1 就答了。★ 后面几栏（MAC 表、端口、PoE、LLDP）都要把版本填成 v1，')
    + t('不然每一栏都会「没回话」。v1 没有 GETBULK，走表会慢很多。')],
  'snmp-v2c-only': [t('这台只认 v2c'), 'warn',
    t('指定了 v1 没答、换成 v2c 答了 —— 把版本留空或填 v2c 即可。')],
  'snmp-error': [t('设备答了，但说「这一栏不给读」'), 'warn',
    t('设备认这个请求（团体名是对的、SNMP 也开着），只是这一栏不给读或读不了。')
    + t('★ 这跟「不通」是两回事：这一条要查的是设备上的视图/权限配置，不是防火墙。')],
  'unknown': [t('观测没做成'), 'warn', t('请求根本没发出去（看原始结果里的 detail），这不算设备不通。')],
};

const SNMP_SYS_LABEL = {
  sysDescr: t('说明'), sysObjectID: t('对象标识符'), sysName: t('设备名'),
  sysLocation: t('位置'), uptime: t('已开机'),
};

// 五张 SNMP 卡共用的一段表单。前缀传进来，免得五个 id 打架。
function snmpFormHTML(p) {
  return t('\n    <div class=\"row\">\n      <div><label>设备地址（只收 IP，可带端口）</label><input id=\"{0}a\" placeholder=\"192.168.1.2 或 192.168.1.2:1161\"></div>\n      <div style=\"flex:0 0 90px\"><label>端口</label><input id=\"{1}p\" placeholder=\"161\"></div>\n      <div><label>读团体名</label><input id=\"{2}c\" type=\"password\" placeholder=\"必填，没有默认值\" autocomplete=\"off\"></div>\n      <div style=\"flex:0 0 110px\"><label>版本</label><select id=\"{3}v\">\n        <option value=\"\">v2c（默认）</option><option value=\"v2c\">v2c</option><option value=\"v1\">v1</option>\n      </select></div>\n      <div style=\"flex:0 0 150px\"><label>从哪块网卡出去</label><input id=\"{4}i\" placeholder=\"en0 / 以太网\"></div>\n    </div>\n    <p class=\"hint\" style=\"margin:8px 0 0\">团体名<b>必填、故意不给默认值</b>：猜一个「public」只会把上面那三种病揉成一种。\n      它不会出现在结果里，也不会进日志。多网卡机器上「从哪块网卡出去」常常决定设备答不答\n      （管理 VLAN 只放行一个口，或者设备按源地址收口）；解不开这一栏会<b>直接报错</b>，不会退化成「随便哪个口都行」。</p>', [p, p, p, p, p]);
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
  const reply = v.matched === false ? t('<span class=\"pill warn\">有包，对不上号</span>')
    : v.answered ? t('<span class=\"pill ok\">有</span>') : t('<span class=\"pill bad\">没有</span>');
  return t('\n    <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n      <div><label>目标</label><div><b><code>{0}</code></b></div></div>\n      <div><label>版本</label><div>{1}\n        {2}\n        {3}</div></div>\n      <div><label>回话</label><div>{4}</div></div>\n      {5}\n      {6}\n    </div>', [esc(v.target), esc(v.version || ''), v.askedVersion && v.askedVersion !== v.version ? t('<span class=\"dim\">（问的是 {0}）</span>', [esc(v.askedVersion)]) : '', v.iface ? t('<span class=\"dim\">从 {0} 出去</span>', [esc(v.iface)]) : '', reply, v.elapsedMs !== undefined ? t('<div><label>等了</label><div>{0}ms</div></div>', [esc(v.elapsedMs)]) : '', v.vendor ? t('<div><label>厂商</label><div>{0}</div></div>', [esc(v.vendor)]) : '']);
}

function snmpAdviceBox(cls, advice, extra) {
  const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
  const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
  return `<div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
    ${esc(advice)}${extra ? `<div class="dim" style="margin-top:6px;font-size:12.5px">${esc(extra)}</div>` : ''}</div>`;
}

function snmpProbeCard() {
  const card = $(t('<div class=\"card\">\n    <h2>这台设备 SNMP 通不通 <span id=\"sv\"></span></h2>\n    <p class=\"hint\">问一句「你是谁、开机多久了」（系统组那七栏）。这是 SNMP 那几栏的第一步：\n      MAC 表、端口、PoE、LLDP 查不出来，先回这张卡确认团体名和路是通的。\n      没回话时会自动换另一档版本再问一次（v2c 不通换 v1），用来把「这台只认另一档」从三种病里摘出去。</p>\n    {0}\n    <div class=\"row\" style=\"margin-top:10px\">\n      <div style=\"flex:0 0 auto;min-width:0\">\n        <label style=\"display:flex;align-items:center;gap:6px;font-weight:400\">\n          <input type=\"checkbox\" id=\"snover\" style=\"width:auto\"> 不做版本对照（只问指定那一档）</label></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><button class=\"btn primary\" id=\"sgo\">问一问</button></div>\n    </div>\n    <div id=\"sout\" style=\"margin-top:14px\"></div>\n  </div>', [snmpFormHTML('sw')]));
  const out = card.querySelector('#sout');
  const top = card.querySelector('#sv');
  card.querySelector('#sgo').onclick = async () => {
    top.innerHTML = '';
    const args = readSnmpArgs(card, 'sw');
    args.noVersionProbe = card.querySelector('#snover').checked;
    out.innerHTML = t('<div class=\"empty\">正在问…（两档都试过的话最坏等四个超时）</div>');
    const r = await call('net.snmp.probe', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice] = SNMP_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const extra = [v.detail, v.versionProbe ? t('已换成 {0} 对照过', [v.versionProbe]) : '',
      v.otherVersionSilent ? t('另一档也没答（版本这一条已经排除了）') : ''].filter(Boolean).join(t('；'));
    const rows = Object.keys(SNMP_SYS_LABEL).filter((k) => v[k] !== undefined && v[k] !== '')
      .map((k) => `<tr><td>${SNMP_SYS_LABEL[k]}</td><td>${k === 'uptime'
        ? t('{0} <span class=\"dim\">（{1} 秒）</span>', [esc(v.uptime), esc(v.uptimeSeconds)])
        : `<code>${esc(v[k])}</code>`}</td></tr>`).join('');
    out.innerHTML = t('\n      {0}\n      {1}\n      {2}\n      <div style=\"margin-top:12px\">{3}</div>\n      <p class=\"dim\" style=\"margin:10px 0 0\">{4}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{5}</pre></details>', [snmpHead(v), rows ? t('<table><tr><th style=\"width:110px\">系统信息</th><th></th></tr>{0}</table>', [rows]) : '', v.sysMissing && v.sysMissing.length
        ? t('<p class=\"dim\" style=\"margin:8px 0 0\">设备没填这几栏：{0}\n           <span class=\"dim\">（v1 设备上少几栏很常见，不代表它坏了）</span></p>', [esc([].concat(v.sysMissing).join(t('、')))]) : '', snmpAdviceBox(cls, advice, extra), esc(r.note), esc(JSON.stringify(v, null, 2))]);
  };
  return card;
}

// MAC 表这一张独有的判定。共用的那些（no-reply / error / 只认另一档）退回 SNMP_CODE 那一份，
// ★ 不在两处各写一遍 —— 写两遍就会有一遍过期。
const SNMP_MAC_CODE = {
  'snmp-ok': [t('读到了'), 'ok',
    t('转发表读回来了。「在哪一个口」这句话的分量，取决于上面写的读了多少、有没有截断。')],
  'snmp-mac-not-found': [t('表里没有这个 MAC'), 'warn',
    t('表读全了，里面确实没有它。★ 这不等于「它不在这台设备上」：这张表只记最近发过帧的源地址，')
    + t('终端静默着就不在里面；其次是它可能挂在另一台设备或另一个 VLAN 上。')],
  'snmp-not-walked': [t('表没读完，下不了结论'), 'warn',
    t('读满限量就停了，后面还有什么谁都不知道 —— 这一条给的是下一步，不是结论。')
    + t('把「最多读几条」提到能盖住整张表再问一次（留空就是按整张表读）。')],
  'snmp-no-data': [t('这台没给出转发表'), 'warn',
    t('设备答了话（团体名是对的），只是两张转发表都不给内容。要么它不做二层交换')
    + t('（三层设备、透明转发），要么链路上确实没流量，要么这张表按 VLAN 分给了别的团体名。')],
};

const FDB_STATUS = {
  dynamic: [t('动态学到'), 'ok'],
  static: [t('手工配死'), 'warn'],
  self: [t('本机地址'), ''],
};

// 一张转发表该有哪些行。★ 端口名问不到的行只写「桥端口 N」，不猜口名 ——
//   猜错的那一次是人照着这句话去机房拔线，拔了别人的链路。
function fdbRowsHTML(es) {
  if (!es || !es.length) return '';
  const withVlan = es.some((e) => e.vlan !== undefined);
  const where = (e) => (e.port
    ? `<code>${esc(e.port)}</code>${e.ifIndex !== undefined ? ` <span class="dim">ifIndex ${esc(e.ifIndex)}</span>` : ''}`
    : t('<span class=\"dim\">桥端口 {0}（口名没读到）</span>', [esc(e.basePort)]));
  const st = (e) => {
    const s = FDB_STATUS[e.status];
    if (!s) return t('<span class=\"dim\">设备没给</span>');
    return `<span class="pill ${s[1]}">${esc(s[0])}</span>`;
  };
  return t('<table>\n    <tr><th>MAC</th>{0}\n      <th>在哪个口</th><th style=\"width:110px\">怎么进表的</th></tr>\n    {1}\n  </table>', [withVlan ? '<th style="width:80px">VLAN</th>' : '', es.map((e) => `<tr><td><code>${esc(e.mac)}</code></td>
      ${withVlan ? `<td>${e.vlan === undefined ? '<span class="dim">—</span>' : esc(e.vlan)}</td>` : ''}
      <td>${where(e)}</td><td>${st(e)}</td></tr>`).join('')]);
}

function snmpMacCard() {
  const card = $(t('<div class=\"card\">\n    <h2>谁插在哪个口（MAC 地址表） <span id=\"skstat\"></span></h2>\n    <p class=\"hint\">读一台设备的转发表。<b>填 MAC 就是反查</b>「这台终端插在交换机的哪个口上」，\n      不填读整张表。★ 反查默认把整张表读全（三万条的表要等一会儿）：\n      读到一半就说「表里没有」，会让人去查一条本来好好的链路。</p>\n    {0}\n    <div class=\"row\" style=\"margin-top:10px\">\n      <div><label>反查这个 MAC（留空 = 整张表）</label>\n        <input id=\"skmac\" placeholder=\"aa:bb:cc:dd:ee:ff / aa-bb-… / aabb.ccdd.eeff\"></div>\n      <div style=\"flex:0 0 110px\"><label>只看 VLAN</label><input id=\"skvlan\" placeholder=\"100\"></div>\n    </div>\n    <details style=\"margin-top:10px\"><summary class=\"dim\">读哪张表、最多读几条（一般不用动）</summary>\n      <div class=\"row\" style=\"margin-top:8px\">\n        <div style=\"flex:0 0 220px\"><label>读哪张表</label><select id=\"sktable\">\n          <option value=\"\">两张都试（默认）</option>\n          <option value=\"qbridge\">Q-BRIDGE（带 VLAN）</option>\n          <option value=\"bridge\">BRIDGE-MIB（老设备，不带 VLAN）</option>\n        </select></div>\n        <div style=\"flex:0 0 150px\"><label>最多读几条</label><input id=\"sklimit\" placeholder=\"整张表\"></div>\n      </div>\n      <p class=\"hint\">交换机有两张转发表：新的是 Q-BRIDGE（带 VLAN），老的是 BRIDGE-MIB（不带 VLAN）。\n        默认先读新的、读不到再退老的。点名只读一张，是用来处理\n        「这台设备的表结构被厂商改过、读出来是乱的」这种现场。\n        ★ 按 VLAN 筛是在<b>读回来之后</b>筛，不减读的量。</p>\n    </details>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"skgo\">读这张表</button></div>\n    <div id=\"skout\" style=\"margin-top:14px\"></div>\n  </div>', [snmpFormHTML('sk')]));
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
    out.innerHTML = t('<div class=\"empty\">正在问…{0}</div>', [mac
      ? t('反查一条 MAC 会把整张表读全，核心交换机上这一步要等几十秒')
      : t('表大时要等一会儿')]);
    const r = await call('net.snmp.mac', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice] = SNMP_MAC_CODE[r.verdict] || SNMP_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const extra = [v.detail,
      v.lookedUp === 'index' ? t('这一条是按索引直取的，没读整张表') : '',
      v.portNames === 'unavailable' ? t('端口名那一栏问不到（只给了桥端口号）') : '',
      v.unresolved ? t('{0} 行配不出口名', [v.unresolved]) : '',
      v.skipped ? t('{0} 行索引写法对不上，被跳过', [v.skipped]) : ''].filter(Boolean).join(t('；'));
    const readOut = v.lookedUp === 'index' ? t('<span class=\"pill ok\">按索引直取</span>')
      : t('读了 <b>{0}</b> 条', [esc(v.read)])
        + (v.truncated ? t(' <span class=\"pill warn\">撞上限量 {0}，没读完</span>', [esc(v.readLimit)]) : t(' <span class=\"pill ok\">读全了</span>'));
    // ★ 表没读回来（团体名不对、设备不给读）时这三格整排不出现：
    //   留三格空的「读了 条 / 剩下 条」，看着像读回来是 0 条 —— 那是另一种结论。
    const statsRow = v.read === undefined ? '' : t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:10px\">\n        <div><label>读的表</label><div><code>{0}</code>\n          <span class=\"dim\">（试过 {1}）</span></div></div>\n        <div><label>读了多少</label><div>{2}</div></div>\n        <div><label>筛完剩下</label><div><b>{3}</b> 条\n          {4}\n          {5}</div></div>\n      </div>', [esc(v.fdbTable || ''), esc([].concat(v.tablesTried || []).join(t('、'))), readOut, esc(v.count), v.vlanFilter ? t('<span class=\"dim\">按 VLAN {0} 筛过</span>', [esc(v.vlanFilter)]) : '', v.queriedMac ? t('<span class=\"dim\">反查 {0}</span>', [esc(v.queriedMac)]) : '']);
    out.innerHTML = t('\n      {0}\n      {1}\n      {2}\n      <div style=\"margin-top:12px\">{3}</div>\n      <p class=\"dim\" style=\"margin:10px 0 0\">{4}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{5}</pre></details>', [snmpHead(v), statsRow, fdbRowsHTML(v.entries), snmpAdviceBox(cls, advice, extra), esc(r.note), esc(JSON.stringify(v, null, 2))]);
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
  'snmp-ok': [t('读到了'), 'ok',
    t('表读回来了。★ 这不等于「这些口都还好」：整张表里有口 down 是正常现象（没插线的空口本来就该 down），')
    + t('要判断某一个口，把名字或编号填进去点名再问一次，那一次的判定才说得出「断了还是被关着」。')],
  'snmp-port-down': [t('链路没起来'), 'bad',
    t('管理上是开着的、链路上是断的 —— 这一条查物理层：对端开没开机、这根线、对端的口、光模块型号波长对不对。')
    + t('★ oper 是「等外部动作」或「下层没起」时别去查线：前者物理层已经好了，在等 802.1X/STP；')
    + t('后者是聚合口的成员没起来，要往下看成员口。')],
  'snmp-port-disabled': [t('这个口是被关着的'), 'warn',
    t('admin 本身就是 down —— 有人在设备上 shutdown 了它，不是链路故障，照着「查线」去跑一趟是白跑。')
    + t('要恢复得在设备上开回来（本工具只读，一行配置都不改）。')],
  'snmp-port-errors': [t('链路能用但在错包'), 'warn',
    t('口是 up 的，可这一段在错包/丢包：链路活着但在烂。最常见的是线或模块在坏，')
    + t('其次是两端速率/双工不匹配（一头自协商一头强制最容易出这个）。')
    + t('★ 把「读两遍之间等几秒」调大再问一次，看这几个数是不是在持续涨 —— 涨着才是要动手的那一个。')],
  'snmp-port-not-found': [t('没有点名的那个口'), 'warn',
    t('★ 先分清是哪一种：填 ifIndex 时只问了那一个编号（设备一栏都没给 = 没这个接口号）；')
    + t('按名字查且表读全了，才是这台真没有这个名字的口。面板上的「第 5 口」在很多设备上就是不等')
    + t('于 ifIndex 5（编号按槽位排、子接口还会插号），先把表列一遍对着 name 认。')],
  'snmp-not-walked': [t('表没读全，下不了结论'), 'warn',
    t('读到「最多列几个」那一档就停了，后面还有什么谁都不知道 —— 此刻「没这个口」和')
    + t('「其余口都还好」这两句都不成立。把限量提到能盖住整张表再问一次。')],
  'snmp-no-data': [t('这台没给出端口表'), 'warn',
    t('设备答了话（团体名是对的），只是 ifTable 是空的。要么它不做转发')
    + t('（一台主机把 SNMP 服务开着而已），要么这张表被藏进了别的视图 —— 换团体名再问一次 net.snmp.probe。')],
};

// oper 的七个值翻成人话。★ 名字（up/dormant/lowerLayerDown）留在这儿而不是后端：
// 后端给的是设备原文，界面上要的是「所以这一步该查什么」。
const PORT_OPER = {
  up: [t('在转发'), 'ok'],
  down: [t('没链路'), 'bad'],
  testing: [t('测试模式'), 'warn'],
  unknown: [t('问不出来'), 'warn'],
  dormant: [t('等外部动作'), 'warn'],
  notPresent: [t('不在位'), 'warn'],
  lowerLayerDown: [t('下层没起'), 'warn'],
};

// 顶上一格（判定）。★「链路没起来」只适用于 oper=down：后端把 oper 不是 up 的都归到
// snmp-port-down 这一个代码里，而 dormant / lowerLayerDown / notPresent 的下一步
// 和「查线」完全相反（等放行、看成员口、看模块）。给它们挂一颗红「链路没起来」，
// 等于界面上把后端那句「这两种别去查线」推翻了一遍。
const PORT_DOWN_HINT = {
  down: [t('链路没起来'), 'bad',
    t('管理上是开着的、链路上是断的 —— 这一条查物理层：对端开没开机、这根线、对端的口、光模块型号波长对不对。')],
  dormant: [t('物理层好了，还没进转发'), 'warn',
    t('★ 这一步别去查线：链路上已经起来了，是被上面卡住的 —— 802.1X 没放行、STP 还在监听/学习、或者口没划进 VLAN。')
    + t('查那三样，不是查这根线。')],
  lowerLayerDown: [t('这个口下面那一层没起'), 'warn',
    t('★ 别查这个口的线：它是一个聚合口/子接口，它的成员口没起来所以它起不来。')
    + t('往下看成员口（把「口名或编号」留空列一遍整张表，看是哪几个成员 down）。')],
  notPresent: [t('这个口的部件不在位'), 'warn',
    t('模块没插、或者这台不支持这个口 —— 不是故障。换一个在位的口再看。')],
  testing: [t('口在测试模式'), 'warn',
    t('admin 是 testing（设备在做线测），这一趟的状态不代表正常转发时的状态。')],
  unknown: [t('状态问不出来'), 'warn',
    t('★ 这一条不能说它是通的还是断的：设备自己答不出这个口的链路状态（驱动/固件没往上送）。')
    + t('先换一种问法确认它在不在（整张表列一遍、或者去 ARP 表里看），别照这句话去机房查线。')],
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
    ${e.kind && e.kind !== t('物理网口') ? `<div class="dim">${esc(e.kind)}</div>` : ''}`;

  // ★ 被关着的口要在这格里同时看得见：只写 oper 会把「有人 shutdown」显示成「断了」。
  const state = (e) => {
    const o = PORT_OPER[e.oper] || [t('状态没读到'), 'warn'];
    const bits = [`<span class="pill ${o[1]}">${esc(o[0])}</span>`];
    if (e.admin && e.admin !== 'up') bits.push(t('<span class=\"pill warn\">被关着</span>'));
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
    const s = e[st] === 'unreliable' ? t('算不准') : t('不给读');
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
        return t('{0}<span class=\"dim\" title=\"这一栏只有 32 位，千兆口 34 秒就绕回一圈\">（32 位）</span>', [humanOctets(e[low])]);
      }
      // 表里有行给了字节数、这一行没给 = 这一向这台不给读，不是 0。
      if (withTotal) return t('<span class=\"dim\" title=\"这一向的字节数设备没给，不是 0\">不给读</span>');
      return dash;
    };
    return `↓ ${one('inOctets', 'inOctets32')} ↑ ${one('outOctets', 'outOctets32')}`;
  };

  const counts = (label, dIn, dOut, cIn, cOut) => (e) => {
    const cell = (k) => (e[k] === undefined ? dash : esc(e[k]));
    const got = e[dIn] !== undefined || e[dOut] !== undefined || e[cIn] !== undefined || e[cOut] !== undefined;
    if (!got) return '';
    return `<div>${label} ${cell(dIn)} / ${cell(dOut)}`
      + t('<span class=\"dim\"> 共 {0}/{1}</span></div>', [cell(cIn), cell(cOut)]);
  };
  const errCell = counts(t('错包'), 'inErrorsDelta', 'outErrorsDelta', 'inErrors', 'outErrors');
  const discCell = counts(t('丢包'), 'inDiscardsDelta', 'outDiscardsDelta', 'inDiscards', 'outDiscards');

  const since = (e) => (e.sinceChange === undefined ? dash
    : t('{0}<div class=\"dim\">前换的状态</div>', [esc(e.sinceChange)]));

  const head = t('<tr><th>口</th><th style=\"width:150px\">现在</th><th style=\"width:70px\">线速</th>\n    {0}\n    {1}\n    {2}\n    {3}</tr>', [withRate ? t('<th style=\"width:110px\">这一段速率</th>') : '', withTotal ? t('<th style=\"width:150px\">一共跑了</th>') : '', withErr ? t('<th style=\"width:190px\">错包 / 丢包（入/出）</th>') : '', withSince ? t('<th style=\"width:110px\">这个状态多久了</th>') : '']);

  // ★ 格子里的短标签必须在表下面对回整句话，否则「不给读」和「算不准」看着像
  //   同一个「读不出来」——而它们的下一步相反（换团体名 / 把测量间隔调短）。
  // ★ 集合里存的是**后端给的状态码**（unreliable / no-counter），不是中文标签：
  //   原来这里 add(t('不给读'))、而下面查表用的是没译过的中文键 —— 选英文时查出来是
  //   undefined，整句图例在界面上静默消失（四本词典里全过，只有这一格什么都没写）。
  const whySet = new Set();
  for (const e of es) {
    for (const k of ['inRateStatus', 'outRateStatus']) {
      if (e[k] === 'unreliable' || e[k] === 'no-counter') whySet.add(e[k]);
    }
  }
  if (withTotal && es.some((e) => e.inOctets === undefined && e.inOctets32 === undefined
    && e.outOctets === undefined && e.outOctets32 === undefined)) whySet.add('no-counter');
  const legendText = {
    'no-counter': t('「不给读」= 这一向的字节数这台没给 —— 不是 0，也不是「没流量」'),
    unreliable: t('「算不准」= 计数器对不上（绕了不止一圈、被重置过，或者两遍用的不是同一档），宁可不给数'),
  };
  const legend = whySet.size
    ? t('<p class=\"hint\" style=\"margin:6px 0 0\">{0}。', [[...whySet].map((w) => legendText[w]).join(t('；'))])
      + t('<span class=\"dim\">（鼠标停在格子上有整句话）</span></p>') : '';

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
  const card = $(t('<div class=\"card\">\n    <h2>这个口到底怎么样（端口表） <span id=\"spstat\"></span></h2>\n    <p class=\"hint\">读一台设备的端口表：<b>开着没有、链路起来没有、跑多快、这一段流了多少、有没有在错包丢包</b>。\n      ★ 填了「口名或编号」才是点名，那一次的判定才说得出「断了还是被关着」；\n      不填只列表 —— 整张表里有口 down 不是故障（空口本来就该 down），所以列表一律给「读到了」。</p>\n    {0}\n    <div class=\"row\" style=\"margin-top:10px\">\n      <div><label>口名或编号（留空 = 整张表）</label>\n        <input id=\"spwho\" placeholder=\"GE1/0/5、Gi1/0/5、Vlanif100，或者备注里的字（如「配线架12」）\"></div>\n      <div style=\"flex:0 0 130px\"><label>ifIndex</label><input id=\"spidx\" placeholder=\"点名一个口时填\"></div>\n      <div style=\"flex:0 0 130px\"><label>只看</label><select id=\"spstate\">\n        <option value=\"\">都列</option><option value=\"up\">在转发的</option><option value=\"down\">没起来的</option>\n      </select></div>\n      <div style=\"flex:0 0 150px\"><label>读两遍之间等几秒</label><input id=\"spwatch\" placeholder=\"0 = 只读一遍\"></div>\n    </div>\n    <details style=\"margin-top:10px\"><summary class=\"dim\">最多列几个口 / 只问状态（一般不用动）</summary>\n      <div class=\"row\" style=\"margin-top:8px\">\n        <div style=\"flex:0 0 150px\"><label>最多列几个口</label><input id=\"splimit\" placeholder=\"512\"></div>\n        <div style=\"flex:0 0 auto;min-width:0;padding-top:18px\">\n          <label style=\"display:flex;align-items:center;gap:6px;font-weight:400\">\n            <input type=\"checkbox\" id=\"spnoc\" style=\"width:auto\"> 只问状态，不问流量计数器</label></div>\n      </div>\n      <p class=\"hint\">★ 筛状态是在<b>读回来之后</b>筛，不减读的量；「一共几个口」记的是筛掉之前有几个。\n        几百口的设备上「只问状态」能省掉大半报文，代价是没有速率和错包那几栏。\n        撞上限量的那一次不会给「其余口都还好」这种结论。</p>\n    </details>\n    <p class=\"hint\" style=\"margin-top:8px\">「读两遍之间等几秒」填了才给速率和这段时间内的错包增量。\n      ★ 千兆口上 32 位计数器 <b>34 秒</b>就绕一圈（万兆 3.4 秒），间隔越长绕圈的概率越大；\n      绕了不止一圈时界面上是「不给读 / 算不准」，不会给一个看着合理的假速率。</p>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"spgo\">读端口表</button></div>\n    <div id=\"spout\" style=\"margin-top:14px\"></div>\n  </div>', [snmpFormHTML('sp')]));
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
    out.innerHTML = t('<div class=\"empty\">正在问…{0}</div>', [watch > 0
      ? t('（读了两遍，中间等了 {0} 秒）', [esc(watch)])
      : t('表大时要等一会儿')]);
    const r = await call('net.snmp.ports', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)]); return; }
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
      v.counterBits === 64 ? t('字节数两向都是 64 位（不会绕回）')
        : v.counterBits === 32 ? t('有向只给到 32 位计数器，千兆口 34 秒就绕一圈（表里那几格已标出）')
          : (args.noCounters ? t('这一趟只问了状态，没问流量计数器')
            : (ports.length ? t('字节数那一栏这台不给读') : '')),
      // 重启这件事表上面已经有一整段在讲了（连后端那句 rateUnsure 一起），
      // 这里再写一遍只会让人以为除了重启还有另一桩病。
      v.rateUnsure && !v.rebooted ? t('速率：{0}', [v.rateUnsure]) : '',
      v.sampleAborted ? v.sampleAborted : '',
      v.truncated ? t('撞上限量 {0}，这张表没读全', [v.readLimit]) : ''].filter(Boolean).join(t('；'));
    // ★ 列表空着、可表其实读了回来：这一格必须自己说话。不写的话界面只剩一颗
    //   「读到了」加一张空表，看着像「这台一个口都没有」——那是另一种结论。
    //   （没点状态筛而列表空的只有「按名字没找着」那一种，后端那条判定已经说清了。）
    const emptyLine = (ports.length || !v.read || !v.stateFilter) ? '' : t('\n      <p class=\"hint\">★ 一个口都没列出来，但这不是「这台没有口」：按「{0}」筛之前，这一趟读了 {1} 个口，没有一个在这个状态上。被筛掉不等于没有。</p>', [esc(v.stateFilter === 'up' ? t('在转发的') : t('没起来的')), esc(v.read)]);
    // ★ 读回来几口 / 筛完剩几口要看得见：只看下面那张表的人会把
    //   「筛过剩下 3 个」读成「这台只有 3 个口」。
    const statsRow = v.read === undefined ? '' : t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:10px\">\n        <div><label>读了多少</label><div><b>{0}</b> 个口\n          {1}\n          {2}</div></div>\n        {3}\n        {4}\n      </div>', [esc(v.read), v.count !== undefined && v.count !== v.read
            ? t('<span class=\"dim\">筛完列出 <b>{0}</b> 个</span>', [esc(v.count)]) : '', v.truncated ? t('<span class=\"pill warn\">撞上限量 {0}</span>', [esc(v.readLimit)]) : '', v.up !== undefined ? t('<div><label>在转发 / 没链路 / 被关着</label>\n          <div><b>{0}</b> / <b>{1}</b> / <b>{2}</b></div></div>', [esc(v.up), esc(v.down), esc(v.adminDown)]) : '', v.sampleSeconds !== undefined ? t('<div><label>测了多久</label><div>{0} 秒</div></div>', [esc(v.sampleSeconds)]) : '']);
    out.innerHTML = t('\n      {0}\n      {1}\n      {2}\n      {3}\n      {4}\n      {5}\n      {6}\n      <div style=\"margin-top:12px\">{7}</div>\n      <p class=\"dim\" style=\"margin:10px 0 0\">{8}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{9}</pre></details>', [snmpHead(v), statsRow, v.rebooted ? t('<p class=\"hint\">★ 这台设备在两次读之间重启过（sysUpTime 倒退），\n        所以这一趟<b>没有速率和增量</b> —— 计数器全被清零过，相减得到的是「开机到现在」，\n        不是「这一秒跑了多少」。上面的累计值是第二次读到的那一份。</p>') : '', emptyLine, portRowsHTML(v.ports), (v.errorPorts && v.errorPorts.length) ? t('<p class=\"hint\" style=\"margin:8px 0 0\">\n        这一段在错包的口：{0}</p>', [esc([].concat(v.errorPorts).join(t('、')))]) : '', (v.recentlyChanged && v.recentlyChanged.length) ? t('<p class=\"hint\" style=\"margin:6px 0 0\">\n        五分钟内换过状态的口：{0}\n        <span class=\"dim\">—— 「偶尔断一下」先看这几个</span></p>', [esc([].concat(v.recentlyChanged).join(t('、')))]) : '', snmpAdviceBox(cls, advice, extra), esc(r.note), esc(JSON.stringify(v, null, 2))]);
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
  'snmp-ok': [t('读到了'), 'ok',
    t('电源池和口的状态都读回来了。★ 整张表里有口「在检测」不是故障清单：没插受电设备的空口本来就该在检测。')
    + t('要判断某一个口，把组号口号（或 ifIndex）填进去点名再问一次。')],
  'snmp-poe-pse-fault': [t('整台的 PoE 电源报故障'), 'bad',
    t('电源池自己报了 faulty —— 这是电源模块、整机供电的事，不是哪一根线、也不是哪个口的配置。')
    + t('★ 这一条压过下面每一行的状态：池子塌了的时候口那一栏写什么都不是那个口的事。')],
  'snmp-poe-off': [t('这台的 PoE 电源总开关是关着的'), 'bad',
    t('整台的电源池 oper=off —— 逐个口去看「有没有供电」是白跑，每一个都只会是「没在供」。')
    + t('先确认这是不是有人有意关掉的（本工具只读，不会开回来）。')],
  'snmp-poe-budget': [t('PoE 余量紧了'), 'warn',
    t('这一档说的是「下一个插上来的设备可能被拒绝」，不是「现在哪个口坏了」。')
    + t('两条路：按优先级把不重要的口排开（预算不够时设备先断优先级低的那几个），或者减掉一些负载。')],
  'snmp-poe-disabled': [t('这个口没在供电'), 'warn',
    t('★ 先看上面「允不允许」那一格：被人关着的和这台自己不供，下一步完全不一样。')],
  'snmp-poe-searching': [t('在检测、没供上电'), 'warn',
    t('检测状态卡在 searching：没插东西、插上来的东西签名不合规、或者它要的电超了这台给的档。')
    + t('★ 把「读两遍之间等几秒」填上再问一次，看「签名不合规」「要电被拒」这两个计数器涨不涨 —— 涨着的那一种才要动手。')],
  'snmp-poe-fault': [t('这个口自己报故障'), 'bad',
    t('口的 detectionStatus 报 fault / otherFault —— 是这一个口（或它下面那根线、那个设备）的事，')
    + t('不是电源池的事。先把这个口的线和对端换一次试试，再看「过载」「短路」两个计数器。')],
  'snmp-poe-not-found': [t('没有点名的那一行'), 'warn',
    t('★ 先分清是哪一种：按「组号 + 口号」直取时只问了那一行，本结果没走整张表；')
    + t('走表筛过、而且表读全了，才是这台真没有这一行。')
    + t('堆叠设备上每一箱都有自己的 5 号口 —— 不填组号时它跟面板上的第 5 口不是一回事。')],
  'snmp-not-walked': [t('PoE 表没读全，下不了结论'), 'warn',
    t('读到「最多列几个」那一档就停了，后面还有什么谁都不知道 —— 此刻「没有这一行」和')
    + t('「其余口都还好」这两句都不成立。把限量提到能盖住整张表再问一次。')],
  'snmp-no-data': [t('这台没给出 PoE 表'), 'warn',
    t('设备答了话（团体名是对的），只是 PoE 那棵子树没给出认行用的那一栏。三种下一步相反：')
    + t('它不是供电端（不支持 PoE 的交换机、以及受电设备本来就没有这棵树）、这一棵被藏进了别的视图、')
    + t('或者它只给了别的栏 —— 下面那句会写明它给了哪几栏。')],
};

// 整张表里报错 ≠ 点名的那一个口报错：顶上一格说错了范围，人就照着去查一个口。
const POE_FAULT_LISTING = [t('表里有口在报故障'), 'bad',
  t('口这一栏报 fault / otherFault —— 是那几个口（或它们下面的线、对端设备）的事，不是电源池的事。')
  + t('★ 逐个口把线重做一遍，再看「过载」「短路」两个计数器是不是在涨；整张表读回来了才有这一句。')];

const POE_STATUS = {
  disabled: [t('没在供'), 'warn'],
  searching: [t('在检测'), 'warn'],
  deliveringPower: [t('在供电'), 'ok'],
  fault: [t('报故障'), 'bad'],
  test: [t('测试中'), 'warn'],
  otherFault: [t('报故障'), 'bad'],
};

// 「没在供」这一颗顶栏必须跟着 admin 那一格走：后端把「有人关了」和「这台自己不供」
// 归到同一个码里，可前者的下一步是去设备上开回来、后者是去看电源池预算。
const POE_DISABLED_HINT = {
  disabled: [t('这个口的供电被人关着'), 'warn',
    t('adminEnable=false —— 有人在设备上把这个口的 PoE 关掉了，不是故障，照着「查线」跑一趟是白跑。')],
  enabled: [t('允许供电，可这台自己不供'), 'warn',
    t('admin 是开着的 —— 这不是有人关的：多半它本来就不是 PoE 口，或者电源池不够、设备把它排除了。')
    + t('★ 去看上面那一栏的余量，别去问是谁关的。')],
  missing: [t('分不清是谁关的'), 'warn',
    t('使能那一栏这台没给，所以「人关的」和「设备自己排除的」分不开 —— 这两种下一步不一样，')
    + t('先确认这一栏在设备的 SNMP 视图里能不能读。')],
};

const PSE_OPER = {
  on: [t('开着'), 'ok'],
  off: [t('关着'), 'bad'],
  faulty: [t('报故障'), 'bad'],
};

const PSE_BUDGET = {
  ok: [t('还够'), 'ok'],
  tight: [t('紧了'), 'warn'],
  unknown: [t('算不出来'), 'warn'],
};

// 五个计数器：格子里给短标签，整句话在下面的图例里对回去。
// ★ 它们是「从开机攒到现在」的次数，不带这一句，「3 次」看着像「刚才 3 次」。
const POE_COUNTER = {
  mpsAbsent: [t('掉电'), t('供着供着掉回去（检测不到受电设备的维持签名）')],
  invalidSignature: [t('签名不合规'), t('插上来的东西签名不对（不是标准 PD，或者线不行）')],
  powerDenied: [t('要电被拒'), t('插上来要电、被这台拒绝了（多半是余量不够）')],
  overLoad: [t('过载'), t('过载保护跳过')],
  shortCircuit: [t('短路'), t('短路保护跳过')],
};

const POE_PRIORITY = { critical: t('关键'), high: t('高'), low: t('低') };

const POE_MATCHED = {
  'portIndex-equals-ifIndex': t('按编号猜的'),
  'pethPsePortType-names-the-port': t('设备对的口名'),
  'both-mappings': t('两条都对上'),
};

// 电源池那一张小表：整台的额定 / 实测 / 还剩 / 阈值。
// ★ 它排在口的上面，因为池子级的问题（关着、故障、余量紧）压过每一个口的结论。
function pseRowsHTML(es) {
  if (!es || !es.length) return '';
  const dash = '<span class="dim">—</span>';
  const w = (n) => (n === undefined ? dash : `${esc(n)}<span class="dim">W</span>`);
  return t('<table>\n    <tr><th style=\"width:70px\">电源池</th><th style=\"width:150px\">总开关</th>\n      <th style=\"width:60px\">额定</th><th style=\"width:80px\">实测在耗</th>\n      <th style=\"width:56px\">已用</th><th style=\"width:60px\">还剩</th>\n      <th style=\"width:52px\">阈值</th><th>余量</th></tr>\n    {0}\n  </table>\n    <p class=\"hint\" style=\"margin:6px 0 0\">★ 额定和实测这两栏的口径是设备自己定的（RFC 里单位是瓦，可有些设备报的不是瓦）。\n      「还剩」是这两个数相减，不是「还能再插几台设备」。</p>', [es.map((e) => {
    const o = PSE_OPER[e.oper];
    const b = PSE_BUDGET[e.budget] || [e.budget, 'warn'];
    // ★ 每一句解释挂在它讲的那一栏下面：operMeaning 讲的是总开关，
    //   挂到「余量」那一格就等于把「电源开着」说成了对余量的结论。
    const why = e.pseInconsistent || e.budgetWhy || e.budgetBasis || '';
    const clip = (s) => (s.length > 34 ? `${s.slice(0, 34)}…` : s);
    return t('<tr>\n        <td><code>第 {0} 组</code></td>\n        <td>{1}\n          {2}</td>\n        <td>{3}</td>\n        <td>{4}</td>\n        <td>{5}</td>\n        <td>{6}</td>\n        <td>{7}</td>\n        <td><span class=\"pill {8}\">{9}</span>{10}</td>\n      </tr>', [esc(e.group), o ? `<span class="pill ${o[1]}">${esc(o[0])}</span>` : t('<span class=\"dim\" title=\"这一栏这台没给\">不给读</span>'), e.operMeaning && e.oper !== 'on' ? `<div class="dim" title="${esc(e.operMeaning)}">${esc(clip(e.operMeaning))}</div>` : '', w(e.powerW), w(e.consumptionW), e.usedPct === undefined ? dash : `${esc(e.usedPct)}%`, w(e.remainingW), e.thresholdPct === undefined ? dash : `${esc(e.thresholdPct)}%`, b[1], esc(b[0]), why
      ? `<div class="dim" title="${esc(why)}">${esc(clip(why))}</div>` : '']);
  }).join('')]);
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

  const who = (e) => t('\n    <div><code>{0} 组 {1} 号</code></div>\n    {2}\n    {3}', [esc(e.group), esc(e.port), e.pdType ? `<div class="dim">${esc(e.pdType)}</div>` : '', e.matchedBy ? `<div class="dim" title="${esc(e.matchedByWhy)}">${esc(POE_MATCHED[e.matchedBy] || e.matchedBy)}</div>` : '']);

  // ★ 允不允许 / 现在怎样 是两栏，不能并成一栏：admin 开着但设备不供、
  //   和 admin 被人关了，界面上看着一样就会有人去查线。
  const allow = (e) => {
    if (e.admin === undefined) return t('<span class=\"dim\" title=\"使能这一栏这台没给\">不给读</span>');
    if (e.admin === 'disabled') {
      return t('<span class=\"pill warn\" title=\"{0}\">被关着</span>', [esc(e.adminWhy)]);
    }
    return t('<span class=\"pill\">允许</span>');
  };
  const now = (e) => {
    if (e.status === undefined) {
      return t('<span class=\"pill warn\" title=\"{0}\">说不清</span>', [esc(e.statusMissing)]);
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
    if (e.class) bits.push(t('<div title=\"{0}\">等级 {1}</div>', [esc(e.classNote), esc(e.class)]));
    else if (e.classUnknown !== undefined) {
      bits.push(t('<div class=\"dim\" title=\"{0}\">等级 {1}（不换算成瓦）</div>', [esc(e.classNote), esc(e.classUnknown)]));
    } else if (e.classSkipped) {
      bits.push(t('<div class=\"dim\" title=\"{0}\">等级不报</div>', [esc(e.classSkipped)]));
    }
    if (e.priority) {
      bits.push(t('<div class=\"dim\" title=\"{0}\">优先级 {1}</div>', [esc(e.priorityNote), esc(POE_PRIORITY[e.priority] || e.priority)]));
    }
    return bits.join('') || dash;
  };
  const pairs = (e) => {
    if (e.pairs === undefined) {
      return e.pairsControllable === false
        ? t('<span class=\"dim\" title=\"这台不能切线对\">固定</span>') : dash;
    }
    // 设备原文（signal/spare）放进悬停：格子里只留一个中文词，别中英各写一遍。
    return `<div class="dim" title="${esc(e.pairs)} · ${esc(e.pairsNote)}">${
      e.pairs === 'signal' ? t('信号线对') : t('备用线对')}</div>`;
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
      return keys.some((k) => e[k] !== undefined) ? t('<span class=\"dim\">都是 0</span>') : dash;
    }
    if (e.countersUnreliable) {
      bits.push(t('<div class=\"dim\" title=\"{0}\">增量算不准</div>', [esc(e.countersUnreliable)]));
    }
    return bits.join('');
  };

  const legend = new Set();
  for (const e of es) for (const k of keys) if (e[k] || e[`${k}Delta`]) legend.add(POE_COUNTER[k][1]);

  return t('<table>\n    <tr><th style=\"width:120px\">PoE 口</th><th style=\"width:80px\">允不允许</th>\n      <th style=\"width:150px\">现在</th>\n      {0}\n      {1}\n      {2}</tr>\n    {3}\n  </table>{4}', [withGrade ? t('<th style=\"width:118px\">等级 / 优先级</th>') : '', withPairs ? t('<th style=\"width:80px\">线对</th>') : '', withCnt ? t('<th style=\"width:150px\">这一段 / 累计</th>') : '', es.map((e) => `<tr>
      <td>${who(e)}</td>
      <td>${allow(e)}</td>
      <td>${now(e)}</td>
      ${withGrade ? `<td>${grade(e)}</td>` : ''}
      ${withPairs ? `<td>${pairs(e)}</td>` : ''}
      ${withCnt ? `<td>${cnt(e)}</td>` : ''}
    </tr>`).join(''), legend.size ? t('<p class=\"hint\" style=\"margin:6px 0 0\">计数器：{0}。', [[...legend].join(t('；'))])
    + t('<span class=\"dim\">（红角标是这次读的两遍之间涨的，那才是要动手的）</span></p>') : '']);
}

function snmpPoeCard() {
  const card = $(t('<div class=\"card\">\n    <h2>这个口给不给电（PoE） <span id=\"postat\"></span></h2>\n    <p class=\"hint\">读一台设备的 PoE 供电：<b>整台的电源池够不够、这个口允不允许供电、现在在不在供、\n      检测卡在哪一步、掉电/被拒/过载/短路各攒了几次</b>。\n      ★ 这一栏<b>给不出「某个口用了几瓦」</b> —— RFC 3621 只有整台的实测值，谁在这里编一个每口功率谁就是在编。\n      先跑最上面那张「SNMP 通不通」。</p>\n    {0}\n    <div class=\"row\" style=\"margin-top:10px\">\n      <div style=\"flex:0 0 110px\"><label>组号</label><input id=\"pogroup\" placeholder=\"1，堆叠才有\"></div>\n      <div style=\"flex:0 0 110px\"><label>口号</label><input id=\"poport\" placeholder=\"PoE 表里的编号\"></div>\n      <div style=\"flex:0 0 110px\"><label>ifIndex</label><input id=\"poidx\" placeholder=\"按接口号问\"></div>\n      <div><label>或者在备注里找这几个字</label><input id=\"polabel\" placeholder=\"AP-3F、NVR-12…（很多设备上这栏是空的）\"></div>\n      <div style=\"flex:0 0 130px\"><label>只看</label><select id=\"postate\">\n        <option value=\"\">都列</option><option value=\"on\">在供电的</option><option value=\"off\">没在供电的</option>\n      </select></div>\n      <div style=\"flex:0 0 150px\"><label>读两遍之间等几秒</label><input id=\"powatch\" placeholder=\"0 = 只读一遍\"></div>\n    </div>\n    <details style=\"margin-top:10px\"><summary class=\"dim\">最多列几个口 / 只问状态（一般不用动）</summary>\n      <div class=\"row\" style=\"margin-top:8px\">\n        <div style=\"flex:0 0 150px\"><label>最多列几个口</label><input id=\"polimit\" placeholder=\"512\"></div>\n        <div style=\"flex:0 0 auto;min-width:0;padding-top:18px\">\n          <label style=\"display:flex;align-items:center;gap:6px;font-weight:400\">\n            <input type=\"checkbox\" id=\"ponoc\" style=\"width:auto\"> 只问状态，不问那几个计数器</label></div>\n      </div>\n      <p class=\"hint\">★ 筛状态是在<b>读回来之后</b>筛，不减读的量；「读了多少」记的是筛掉之前有几个。\n        撞上限量的那一次不会给「其余口都还好」这种结论。</p>\n    </details>\n    <p class=\"hint\" style=\"margin-top:8px\">★ 「口号」既不是面板上的第几口、也不等于 ifIndex：\n      堆叠设备里每一箱都有自己的 5 号口，不填组号会把每一组的 5 号都列出来。\n      填 ifIndex 时这一条是<b>猜的映射</b>（RFC 3621 没规定两者的关系），结果里每一行都会写明是怎么对上的 ——\n      只有设备自己把口名写在 pethPsePortType 那一栏里，那条才算设备给的。</p>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"pogo\">读 PoE 供电情况</button></div>\n    <div id=\"poout\" style=\"margin-top:14px\"></div>\n  </div>', [snmpFormHTML('po')]));
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
    out.innerHTML = t('<div class=\"empty\">正在问…{0}</div>', [watch > 0
      ? t('（读了两遍，中间等了 {0} 秒）', [esc(watch)])
      : t('整台加整张 PoE 表，口多时要等一会儿')]);
    const r = await call('net.snmp.poe', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)]); return; }
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
      v.truncated ? t('撞上限量 {0}，这张表没读全', [v.readLimit]) : ''].filter(Boolean).join(t('；'));
    const statsRow = v.read === undefined ? '' : t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:10px\">\n        <div><label>读了多少</label><div><b>{0}</b> 个 PoE 口\n          {1}\n          {2}\n          {3}</div></div>\n        {4}\n        {5}\n      </div>', [esc(v.read), v.count !== undefined && v.count !== v.read
            ? t('<span class=\"dim\">筛完列出 <b>{0}</b> 个</span>', [esc(v.count)]) : '', v.truncated ? t('<span class=\"pill warn\">撞上限量 {0}</span>', [esc(v.readLimit)]) : '', v.truncated ? t('<span class=\"dim\">（读到这一档就停了，一共有几个口没说）</span>')
            : v.countTotal === undefined ? t('<span class=\"dim\">（这一条没走整张表，一共有几个口没说）</span>')
              : t('<span class=\"dim\">表里一共 {0} 行</span>', [esc(v.countTotal)]), v.powering === undefined ? '' : t('<div><label>在供电 / 在检测 / 没在供 / 报错</label>\n          <div><b>{0}</b> / <b>{1}</b> / <b>{2}</b> / <b>{3}</b>\n          {4}\n          {5}</div></div>', [esc(v.powering), esc(v.searching), esc(v.disabled), esc(v.faulty), v.adminOff !== undefined ? t('<span class=\"dim\">其中 {0} 个是被关着的</span>', [esc(v.adminOff)]) : '', v.statusUnknown ? t('<span class=\"dim\">另有 {0} 行说不清</span>', [esc(v.statusUnknown)]) : '']), v.sampleSeconds !== undefined ? t('<div><label>测了多久</label><div>{0} 秒</div></div>', [esc(v.sampleSeconds)]) : '']);
    // ★ 表空的、可其实读回来过：这一格必须自己说话，不然只剩一颗「读到了」加一张空表，
    //   看着像「这台一个 PoE 口都没有」。
    const emptyLine = (ports.length || !v.read || !v.stateFilter) ? '' : t('\n      <p class=\"hint\">★ 一个口都没列出来，但这不是「这台没有 PoE 口」：按「{0}」筛之前读了 {1} 行，没有一行在这个状态上。被筛掉不等于没有。</p>', [esc(v.stateFilter === 'on' ? t('在供电的') : t('没在供电的')), esc(v.read)]);
    out.innerHTML = t('\n      {0}\n      {1}\n      {2}\n      {3}\n      <h2 style=\"margin-top:16px\">口的供电</h2>\n      {4}\n      {5}\n      {6}\n      {7}\n      <div style=\"margin-top:12px\">{8}</div>\n      <p class=\"dim\" style=\"margin:10px 0 0\">{9}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{10}</pre></details>', [snmpHead(v), statsRow, v.rebooted ? t('<p class=\"hint\">★ 这台设备在两次读之间重启过（sysUpTime 倒退），计数器被清零了，\n        所以这一趟<b>没有增量</b> —— 表里那几个数是累计值，不是「这一会儿涨的」。</p>') : '', pseRowsHTML(v.pse), emptyLine, poeRowsHTML(v.poePorts), (v.faultPorts && v.faultPorts.length) ? t('<p class=\"hint\" style=\"margin:8px 0 0\">\n        报故障的口：{0}</p>', [esc([].concat(v.faultPorts).join(t('、')))]) : '', (v.powerDeniedPorts && v.powerDeniedPorts.length) ? t('<p class=\"hint\" style=\"margin:6px 0 0\">\n        攒下「要电被拒」的口：{0}\n        <span class=\"dim\">—— 插得上、要不到电，先看上面那栏余量</span></p>', [esc([].concat(v.powerDeniedPorts).join(t('、')))]) : '', snmpAdviceBox(cls, advice, extra), esc(r.note), esc(JSON.stringify(v, null, 2))]);
  };
  return card;
}

const SNMP_LLDP_CODE = {
  'snmp-lldp-unsupported': [t('这台没有 LLDP 这一棵'), 'warn',
    t('设备答了话（团体名是对的），可 LLDP-MIB 那棵子树整个读不到。三种下一步完全相反：')
    + t('这台不是网管设备/没开 LLDP、这一棵被藏进了别的视图、或者它只做 CDP 不做 LLDP')
    + t('（★ 只发 CDP 的设备在这里就是不存在，读不到邻居不等于对端不存在 —— 那要换 CDP 那一侧去问）。')],
  'snmp-lldp-tx-only': [t('这个口的 LLDP 是「只发不收」'), 'warn',
    t('lldpPortConfigAdminStatus=txOnly：这一档按标准只把自己发出去、不存对端发来的东西，')
    + t('所以它的邻居表本来就该是空的。★ 这不是对端没发，是这台自己不存 —— 要互相看得见，')
    + t('去设备上把这个口改成收发（本工具只读，不改配置）。')],
  'snmp-lldp-port-off': [t('这个口的 LLDP 关着'), 'warn',
    t('lldpPortConfigAdminStatus=disabled：不发也不存，这个口上永远不会有邻居。')
    + t('先去设备上确认这是不是有意关的（本工具只读）。')],
  'snmp-lldp-no-neighbor': [t('没有邻居'), 'warn',
    t('这台有 LLDP 那棵树、这个口也在收，可邻居表里一条都没有。剩下两种病：对端根本没发 LLDP')
    + t('（老设备、打印机、IPC 常常只发 CDP 或不发），或者对端发的被中间的东西吞了。')
    + t('★ 这一条不是「这根线上没东西」，是「没有东西在向它说 LLDP」—— 线下插着什么还得看 MAC 表那一栏。')],
  'snmp-lldp-not-found': [t('点名的那个口没有邻居行'), 'warn',
    t('★ 别的口有邻居，只有这一个口没有 —— 这一条比「整台没邻居」有用得多。')
    + t('先看这一口的 LLDP 开关是不是「只发不收」或关着；是收发、可就是没有，再去查对端发不发。')],
  'snmp-lldp-multi': [t('一个口上听见了好几个邻居'), 'warn',
    t('★ 这不是故障，是拓扑：这个口下面接了台非网管交换机、hub 或者分光器。')
    + t('设备不会主动把这件事说出来，要理拓扑就顺着这几个口去现场看一眼。')],
  'snmp-lldp-aging': [t('邻居在老化（它会消失）'), 'bad',
    t('刚才那一段里，某个口上的邻居老化计数涨了：对端停发 LLDP、或者它给的存活时间比自己的发包间隔短、')
    + t('或者这条链路在抖。★ 这一条不是「没有邻居」，是「邻居会消失」—— 查对端为什么停发，别查这台没配。')],
  'snmp-not-walked': [t('邻居表没读全，下不了结论'), 'warn',
    t('这张表读到一半停住了（撞上限量，或者设备走着走着不往前走了）。')
    + t('★ 这时候「这个口没有邻居」和「其余口都还好」两句都不成立 —— 少读的那几行里')
    + t('就可能正好有你要找的那一台。把「最多列几条」提到能盖住整张表再问一次。')],
  'snmp-no-data': [t('这台没给出 LLDP 的内容'), 'warn',
    t('设备答了话（团体名是对的），可 LLDP 那几组一栏都没给。要么这台的 LLDP 服务没开')
    + t('（不少设备上不开服务时这棵树就不存在），要么整棵被放进了别的视图 —— 换团体名再问一次 net.snmp.probe。')],
};

const LLDP_ADMIN = {
  txOnly: [t('只发不收'), 'warn'],
  rxOnly: [t('只听不发'), 'warn'],
  txAndRx: [t('收发'), 'ok'],
  disabled: [t('关着'), 'bad'],
};

const LLDP_ADMIN_LABEL = {
  txAndRx: t('收发'), txOnly: t('只发不收'), rxOnly: t('只听不发'), disabled: t('关着'), other: t('别的值'),
};

const LLDP_MATCHED = {
  'dot1dBasePortIfIndex': t('设备对的映射'),
  'lldpLocPort-names-it': t('设备对的口名'),
  'portNum-equals-ifIndex': t('按编号猜的'),
  'both-mappings': t('两条都对上'),
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
    return t('<div><code>口号 {0}</code>{1}</div>\n      {2}\n      {3}\n      {4}', [esc(e.portNum), e.remIndex > 1 ? t('<span class=\"dim\"> 第 {0} 行</span>', [esc(e.remIndex)]) : '', e.localPortName ? `<div><b>${esc(e.localPortName)}</b></div>` : '', e.portMatchedBy ? `<div class="dim" title="${esc(e.portMatchWhy)}">${esc(LLDP_MATCHED[e.portMatchedBy] || e.portMatchedBy)}</div>` : '', a ? `<span class="pill ${a[1]}" title="${esc(e.localLldpAdminMeaning || '')}">${esc(a[0])}</span>` : '']);
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
    if (e.gone) bits.push(t('<span class=\"pill bad\">第二遍不见了</span>'));
    if (e.newNeighbor) bits.push(t('<span class=\"pill warn\">这一趟新出现的</span>'));
    if (e.missingColumns) {
      // 整句掐到 24 个字会切成「lldpRemPortId / …」这种半截话 —— 按「、」一条一条数，
      // 只展示第一条 + 一共缺几栏，全文留给鼠标提示。
      const list = (e.missingColumns.split(t('：'))[1] || '').split(' —— ')[0];
      const cols = list ? list.split(t('、')).filter(Boolean) : [];
      bits.push(cols.length
        ? t('<div class=\"dim\" title=\"{0}\">缺栏：{1}{2}</div>', [esc(e.missingColumns), esc(cols[0]), cols.length > 1 ? t(' 等 {0} 栏', [cols.length]) : ''])
        : t('<div class=\"dim\" title=\"{0}\">缺栏：{1}</div>', [esc(e.missingColumns), esc(list || t('这一行的栏没列出来'))]));
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
    if (e.capabilities) bits.push(`<div>${esc([].concat(e.capabilities).join(t('、')))}</div>`);
    if (e.capabilitiesEnabled) {
      bits.push(t('<div class=\"dim\" title=\"enabled 是另一张位图，界面上「对端是什么」按这一张认\">已启用：{0}</div>', [esc([].concat(e.capabilitiesEnabled).join(t('、')))]));
    } else if (e.capabilities) {
      bits.push(t('<div class=\"dim\">enabled 没给，只按 supported 说</div>'));
    }
    if (e.capabilityNote) bits.push(`<div class="dim" title="${esc(e.capabilityNote)}">${esc(e.capabilityNote.replace(/^★\s*/, ''))}</div>`);
    return bits.join('') || dash;
  };
  const fresh = (e) => {
    const bits = [];
    if (e.lastUpdate) {
      const old = e.lastUpdateSeconds > 600;
      bits.push(old
        ? t('<span class=\"pill warn\" title=\"比 LLDP 一般的存活时间老得多：这台只是把第一次听到的东西留着没清\">{0}前刷新</span>', [esc(e.lastUpdate)])
        : t('<div>{0}前刷新</div>', [esc(e.lastUpdate)]));
    } else if (e.lastUpdateWhy) {
      bits.push(t('<div class=\"dim\" title=\"{0}\">算不出多久以前</div>', [esc(e.lastUpdateWhy)]));
    }
    if (e.ageoutsDelta) bits.push(t('<span class=\"pill bad\">这一段老化 {0} 次</span>', [esc(e.ageoutsDelta)]));
    else if (e.ageoutsTotal !== undefined) bits.push(t('<div class=\"dim\" title=\"从开机攒到现在的次数，单看一个数说明不了任何事\">累计老化 {0}</div>', [esc(e.ageoutsTotal)]));
    return bits.join('') || dash;
  };

  return t('<table>\n    <tr><th style=\"width:150px\">这台这个口</th><th style=\"width:200px\">对端是谁</th>\n      <th style=\"width:160px\">对端的口</th><th style=\"width:150px\">它自称</th>\n      {0}\n      {1}</tr>\n    {2}\n  </table>', [withMgmt ? t('<th style=\"width:150px\">它留的管理地址</th>') : '', withAge ? t('<th style=\"width:130px\">多久没刷新 / 老化</th>') : '', es.map((e) => `<tr>
      <td>${local(e)}</td>
      <td>${who(e)}</td>
      <td>${rport(e)}</td>
      <td>${caps(e)}</td>
      ${withMgmt ? `<td>${e.mgmtAddresses
        ? [].concat(e.mgmtAddresses).map((a) => `<div><code>${esc(a)}</code></div>`).join('') : dash}</td>` : ''}
      ${withAge ? `<td>${fresh(e)}</td>` : ''}</tr>`).join('')]);
}

function lldpStatsHTML(s) {
  if (!s) return '';
  if (s.note && !s.tableInserts && !s.tableDeletes && !s.tableDrops && !s.tableAgeouts
    && !s.ageoutPorts && !s.rxErrorPorts) {
    return `<p class="hint">${esc(s.note)}</p>`;
  }
  const item = (label, v, why) => (v === undefined ? ''
    : `<div><label>${esc(label)}</label><div><b>${esc(v)}</b>${
      why ? t('<span class=\"dim\">（{0}）</span>', [esc(why)]) : ''}</div></div>`);
  return t('<div class=\"row\" style=\"align-items:flex-end;gap:18px\">\n    {0}\n    {1}\n    {2}\n    {3}\n    {4}\n    {5}\n  </div><p class=\"hint\" style=\"margin:6px 0 0\">★ 这几个数是从设备<b>开机攒到现在</b>的，\n    单看一个数说明不了任何事 —— 要看「这一段涨没涨」，把上面「读两遍之间等几秒」填一个数再问一次。</p>', [item(t('插入过几条'), s.tableInserts), item(t('被清掉几条'), s.tableDeletes), item(t('表满丢掉几条'), s.tableDrops), item(t('自然老化几条'), s.tableAgeouts), item(t('老过化的口'), s.ageoutPorts && [].concat(s.ageoutPorts).join(t('、'))), item(t('收包出错的口'), s.rxErrorPorts && [].concat(s.rxErrorPorts).join(t('、')))]);
}

function snmpLldpCard() {
  const card = $(t('<div class=\"card\">\n    <h2>这根线另一头是谁（LLDP 邻居） <span id=\"llstat\"></span></h2>\n    <p class=\"hint\">读一台设备的 LLDP 邻居：<b>哪一个口上听见了对端哪台设备、它在对端的哪个口、\n      对端自称是什么、它留下的管理地址</b>，外加每个口的 LLDP 开关和邻居老化次数。\n      ★ 这一棵树里<b>没有 CDP</b>：只发 CDP 的老设备、打印机、摄像头在这里就是不存在，\n      「读不到邻居」不等于「线上没东西」。先跑最上面那张「SNMP 通不通」。</p>\n    {0}\n    <div class=\"row\" style=\"margin-top:10px\">\n      <div style=\"flex:0 0 120px\"><label>LLDP 口号</label><input id=\"llport\" placeholder=\"lldpRemLocalPortNum\"></div>\n      <div style=\"flex:0 0 120px\"><label>ifIndex</label><input id=\"lridx\" placeholder=\"按接口号问\"></div>\n      <div><label>或者在口名里找这几个字</label><input id=\"llname\" placeholder=\"Gi1/0/5、GE1/0/5…\"></div>\n      <div style=\"flex:0 0 150px\"><label>读两遍之间等几秒</label><input id=\"llwatch\" placeholder=\"0 = 只读一遍\"></div>\n    </div>\n    <details style=\"margin-top:10px\"><summary class=\"dim\">最多列几行 / 不读统计计数器（一般不用动）</summary>\n      <div class=\"row\" style=\"margin-top:8px\">\n        <div style=\"flex:0 0 150px\"><label>最多列几行</label><input id=\"lllimit\" placeholder=\"512\"></div>\n        <div style=\"flex:0 0 auto;min-width:0;padding-top:18px\">\n          <label style=\"display:flex;align-items:center;gap:6px;font-weight:400\">\n            <input type=\"checkbox\" id=\"llnostats\" style=\"width:auto\"> 不读那几个统计计数器</label></div>\n      </div>\n      <p class=\"hint\">★ 不读计数器就看不出「邻居在老化」这一条（邻居本身照读）。\n        撞到限量的那一次不会给「其余口都还好」这种结论。</p>\n    </details>\n    <p class=\"hint\" style=\"margin-top:8px\">★ <b>LLDP 口号既不是面板上的第几口、也不等于 ifIndex</b>：\n      MIB 规定桥设备按 dot1dBasePort 编号。填 ifIndex 时结果里每一行都会写明这一条是怎么对上的\n      —— 设备的映射（可以当准）、还是「编号正好相等」猜的（要核）；几条路指着不同口号时全列出来，不挑一个。</p>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"llgo\">读 LLDP 邻居</button></div>\n    <div id=\"llout\" style=\"margin-top:14px\"></div>\n  </div>', [snmpFormHTML('ll')]));
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
    out.innerHTML = t('<div class=\"empty\">正在问…{0}</div>', [watch > 0
      ? t('（读了两遍，中间等了 {0} 秒）', [esc(watch)])
      : t('整棵邻居子树都要走一遍，口多时要等一会儿')]);
    const r = await call('net.snmp.lldp', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const rows = [].concat(v.neighbors || []);
    const base = SNMP_LLDP_CODE[r.verdict] || SNMP_CODE[r.verdict] || [r.verdict, '', ''];
    const [text, cls, advice] = base;
    // 共用那句「下面几栏都可以问了」是设备体检那张卡的口径；在这张卡上邻居已经列出来了，
    // 再说一遍等于走错了门，所以这一条换成说眼前这张表。
    const say = r.verdict === 'snmp-ok'
      ? t('这台设备认这个团体名，路也是通的。上面这些邻居行就是它直接答的。') : advice;
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const extra = [v.detail, v.answeredEarlier, v.portMapping, v.name,
      v.queriedPorts ? t('别的口上有邻居：口号 {0}', [[].concat(v.queriedPorts).join(t('、'))]) : '',
      v.sampleUnsure, v.sampleAborted,
      v.truncated ? t('撞上限量 {0}，这张表没读全', [v.readLimit]) : ''].filter(Boolean).join(t('；'));
    const local = v.local || {};
    const localLine = Object.keys(local).length ? t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n        <div><label>这台自称</label><div><b>{0}</b>\n          {1}</div></div>\n        {2}\n        {3}\n      </div>{4}', [esc(local.sysName || ''), local.chassisId ? `<span class="dim" title="${esc(local.chassisIdType || '')}"><code>${esc(local.chassisId)}</code></span>` : '', local.capabilities ? t('<div><label>它说自己会这些</label><div>{0}\n          {1}</div></div>', [esc([].concat(local.capabilities).join(t('、'))), local.capabilitiesEnabled ? t('<span class=\"dim\">已启用：{0}</span>', [esc([].concat(local.capabilitiesEnabled).join(t('、')))]) : '']) : '', local.sysDesc ? t('<div><label>设备说明</label><div class=\"dim\" title=\"{0}\">{1}{2}</div></div>', [esc(local.sysDesc), esc(String(local.sysDesc).slice(0, 60)), String(local.sysDesc).length > 60 ? '…' : '']) : '', local.capabilityNote ? `<p class="hint">${esc(local.capabilityNote)}</p>` : '']) : '';
    const counts = v.portAdminCounts
      ? t('<div><label>这台的 LLDP 开关</label><div>{0}<span class=\"dim\">（按口数的，只发了一遍开关表）</span></div></div>', [Object.entries(v.portAdminCounts)
        .map(([k, n]) => `${esc(LLDP_ADMIN_LABEL[k] || k)} <b>${esc(n)}</b>`)
        .join(' · ')]) : '';
    const statsRow = v.read === undefined ? '' : t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:10px\">\n        <div><label>读回几条</label><div><b>{0}</b> 行邻居\n          {1}\n          {2}\n          {3}</div></div>\n        {4}\n        {5}\n        {6}\n        {7}\n      </div>', [esc(v.read), v.count !== undefined && v.count !== v.read
            ? t('<span class=\"dim\">这一趟列出 <b>{0}</b> 行</span>', [esc(v.count)]) : '', v.truncated ? t('<span class=\"pill warn\">撞上限量 {0}</span>', [esc(v.readLimit)]) : '', v.countTotal === undefined ? '' : t('<span class=\"dim\">表里一共 {0} 行</span>', [esc(v.countTotal)]), v.ports === undefined ? '' : t('<div><label>涉及几个口</label><div><b>{0}</b>\n          {1}</div></div>', [esc(v.ports), v.multiNeighborPorts ? t('<span class=\"pill warn\">{0} 个口上不止一个邻居</span>', [esc(v.multiNeighborPorts)]) : '']), counts, v.uptimeSeconds !== undefined ? t('<div><label>这台开了</label><div class=\"dim\">{0}</div></div>', [esc(v.uptime || v.uptimeSeconds + t(' 秒'))]) : '', v.sampleSeconds !== undefined ? t('<div><label>测了多久</label><div>{0} 秒</div></div>', [esc(v.sampleSeconds)]) : '']);
    out.innerHTML = t('\n      {0}\n      {1}\n      {2}\n      {3}\n      {4}\n      {5}\n      <h2 style=\"margin-top:16px\">邻居</h2>\n      {6}\n      {7}\n      {8}\n      <div style=\"margin-top:12px\">{9}</div>\n      <p class=\"dim\" style=\"margin:10px 0 0\">{10}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{11}</pre></details>', [snmpHead(v), localLine, statsRow, v.portMappingAmbiguous ? t('<p class=\"hint\">★ 这一条是靠猜对上的：两条路指着不同的口号，候选的口都问了 —— 别把它们当成同一根线。</p>') : '', v.rebooted ? t('<p class=\"hint\">★ 这台设备在两次读之间重启过（sysUpTime 倒退），计数器被清零了，\n        所以这一趟<b>没有增量</b> —— 只按两遍的行数比了邻居。</p>') : '', v.newNeighborRows ? t('<p class=\"hint\">★ 这一趟之间多出 {0} 行邻居（只有第二遍才读到）——\n        下面标着「这一趟新出现的」那几行就是它。</p>', [esc(v.newNeighborRows)]) : '', rows.length ? lldpRowsHTML(rows) : t('<div class=\"empty\">这一趟一条邻居都没列出来。\n        {0}</div>', [v.queriedPorts ? t('但别的口上有：口号 {0}', [esc([].concat(v.queriedPorts).join(t('、')))]) : '']), v.agingPorts ? t('<p class=\"hint\" style=\"margin:8px 0 0\">老过化的口：{0}\n        <span class=\"dim\">—— 这一条说的是「邻居会消失」，不是「没有邻居」</span></p>', [esc([].concat(v.agingPorts).join(t('、')))]) : '', v.stats ? t('<div style=\"margin-top:14px\"><h2>邻居表统计</h2>{0}</div>', [lldpStatsHTML(v.stats)]) : '', snmpAdviceBox(cls, say, extra), esc(r.note), esc(JSON.stringify(v, null, 2))]);
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
// ★ 一组里最多四页、一页里最多五张：取流这一叠（ONVIF / RTSP / HLS / RTMP / GB28181）
//   到这儿正好五张，各问一件事，没有第六张的位置 —— 再加流相关的工具就得先拆页，别往这页塞。

async function renderDevice(root) {
  root.appendChild(deviceIdentifyCard());
  root.appendChild(discoverCard());
  root.appendChild(wolCard());
}

// 三张卡是一条流水线，不是三个并列的工具：
// 只有设备 IP → ONVIF 问出取流地址 → RTSP 验这路流到没到本机 → HLS 问平台那份清单还写着什么
// → RTMP 问反方向那一句：推上去的东西到没到服务器
// → GB28181 问信令那一层：这台在不在平台的名册上（在播与否前面四张已经答过）。
async function renderStream(root) {
  root.appendChild(onvifCard());
  root.appendChild(rtspCard());
  root.appendChild(hlsCard());
  root.appendChild(rtmpCard());
  root.appendChild(gbCard());
}

// ONVIF 这一张排在「取流探测」前面，不是随手放的：
// ★ 现场手里往往只有这台设备的 IP，取流地址恰恰是要问出来的那一个。
//   ONVIF 把「有几路流、每路什么规格、第一路的 rtsp:// 地址」答得出来，
//   答完直接抄进下面那张卡去验流 —— 「没画面」的排查因此从问出地址开始，不是从猜地址开始。
function onvifCard() {
  const card = $(t('<div class=\"card\">\n    <h2>问一台 ONVIF 设备 <span id=\"ov-top\"></span></h2>\n    <p class=\"hint\">向设备发几问<b>只读</b>的 SOAP：它是谁、它自己说现在几点、服务挂在哪儿、\n      有几路码流、第一路的取流地址是多少。<b>不改它任何配置。</b>\n      ★ 哪一问没问出去会单独占一行，不会糊成「问了，一切正常」。密码只进请求，不进结果。</p>\n    <div class=\"row\">\n      <div><label>服务地址（只填 IP 也行，默认 80 端口与设备服务路径）</label>\n        <input id=\"ov-u\" placeholder=\"192.168.1.64 或 http://192.168.1.64:8899/onvif/device_service\"></div>\n      <div style=\"flex:0 0 170px\"><label>ONVIF 账号</label>\n        <input id=\"ov-a\" placeholder=\"多数相机匿名只回 Fault\"></div>\n      <div style=\"flex:0 0 170px\"><label>密码</label>\n        <input id=\"ov-w\" type=\"password\" autocomplete=\"new-password\"></div>\n    </div>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"ov-b\">问一遍</button></div>\n    <div id=\"ov-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#ov-out');
  const top = card.querySelector('#ov-top');
  card.querySelector('#ov-b').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">正在问…（几问是排着队发的，设备慢或者第一问就要账号时会多等几秒）</div>');
    const args = {};
    const put = (id, key) => { const s = card.querySelector(id).value.trim(); if (s) args[key] = s; };
    put('#ov-u', 'url'); put('#ov-a', 'username'); put('#ov-w', 'password');
    const r = await call('media.onvif.info', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message || r.error)]); return; }
    const v = r.values || {};
    const [title, cls, advice] = ONVIF_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;

    const led = (v.steps || []).map((s) => {
      const st = ONVIF_STEP[s.state] || [s.state || '—', 'bad', ''];
      return `<tr><td>${esc(s.step || '')}</td>`
        + `<td><span class="pill ${st[1]}">${esc(st[0])}</span></td>`
        + `<td>${s.note ? esc(s.note) : t('<span class=\"dim\">它照答了</span>')}</td></tr>`;
    }).join('');

    const ps = v.profiles || [];
    const streamRows = ps.length
      ? t('<tr><th>码流名</th><th>token（问地址用它）</th><th>编码</th><th>分辨率</th><th>帧率</th><th>上限码率</th><th>音频</th></tr>')
        + ps.map((p) => `<tr><td>${esc(p.name || '—')}</td><td><code>${esc(p.token || '')}</code></td>`
          + `<td>${esc(p.codec || '—')}</td>`
          + `<td>${p.width ? `${p.width}×${p.height}` : t('<span class=\"dim\">没报</span>')}</td>`
          + `<td>${esc(p.framerate || '—')}</td>`
          + `<td>${p.bitrateKbps ? esc(p.bitrateKbps) + ' kbps' : '—'}</td>`
          + `<td>${esc(p.audio || t('没有'))}</td></tr>`).join('')
      : '';

    // 时间那一格答的是「它自己说几点、它靠什么对时」。偏移照给，但注明是相对本机 ——
    // 拿本机那把尺去论设备的对错，本机自己歪的时候就把它的准算成了错。
    const off = typeof v.offsetMsVsLocal === 'number'
      ? t('<b>{0}</b> <span class=\"dim\">它比本机{1}（相对本机；本机准不准归「校时检查」判）</span>', [esc(humanMs(v.offsetMsVsLocal)), v.offsetMsVsLocal > 0 ? t('快') : t('慢')])
      : t('<span class=\"dim\">没换算成偏差 —— 它只报了本地时间，或者这一问没问出去。<b>只给本地时间就不换算</b>：时区一差几小时，会凭空造出一个「它时间不对」。</span>');
    const ntp = (v.ntpServers || []).join(t(' 、')) || (v.ntpFromDHCP ? t('由 DHCP 下发') : '');

    // ★ 有内容才现身：第一问就被挡下时，「它是谁 / 几点 / 几路流」四张空表
    //   会把真正那一条信息（问话记录）挤到屏幕外，还看着像「查过了，都没查到」。
    const step = (name) => (v.steps || []).find((x) => x.step === name);
    // 只有「这一问真的问出去了、它答了没有码流」才说它没配 —— 第一问就断掉时
    // 这一问根本没发生，说成「它说没有码流」就是替设备编了一句它没说过的话。
    const mediaAsked = step(t('问它有几路码流')) && step(t('问它有几路码流')).state === 'asked';
    const hasWho = v.manufacturer || v.model || v.firmwareVersion || v.serialNumber || v.hardwareId || v.mediaService;
    const hasClock = v.deviceTime || v.deviceTimeType || typeof v.offsetMsVsLocal === 'number'
      || (v.ntpServers || []).length || v.ntpFromDHCP;
    const secs = [];
    if (v.mediaUri) {
      secs.push(t('<h2 style=\"margin-top:16px\">它报的取流地址</h2>\n        <table>{0}</table>', [tCell(t('拿这个去验流'), `<code>${esc(v.mediaUri)}</code>`)]));
    }
    if (ps.length) {
      secs.push(t('<h2 style=\"margin-top:16px\">它报的码流</h2><table>{0}</table>', [streamRows]));
    } else if (mediaAsked) {
      secs.push(t('<h2 style=\"margin-top:16px\">它报的码流</h2>\n        <div class=\"empty\">媒体服务答得清清楚楚：这台上一条码流都没配。几路流、什么规格，都得先在设备那侧把码流配出来。</div>'));
    }
    if (hasWho) {
      secs.push(t('<h2 style=\"margin-top:16px\">它是谁</h2>\n        <table>\n          {0}\n          {1}\n          {2}\n          {3}\n        </table>', [tCell(t('厂商 / 型号'), `${esc(v.manufacturer || t('它没说'))} ${v.model ? '· ' + esc(v.model) : ''}`), tCell(t('固件 / 硬件'), `${esc(v.firmwareVersion || '—')}${v.hardwareId ? ' · ' + esc(v.hardwareId) : ''}`), tCell(t('序列号'), v.serialNumber ? `<code>${esc(v.serialNumber)}</code>` : t('<span class=\"dim\">它没说</span>')), v.mediaService ? tCell(t('媒体服务挂在'), t('<code>{0}</code> <span class=\"dim\">（它自报的路径与端口，主机仍钉在这台）</span>', [esc(v.mediaService)])) : '']));
    }
    if (hasClock) {
      secs.push(t('<h2 style=\"margin-top:16px\">它说现在几点</h2>\n        <table>\n          {0}\n          {1}\n          {2}\n          {3}\n        </table>', [tCell(t('它的时刻'), v.deviceTime ? `<code>${esc(v.deviceTime)}</code>` : t('<span class=\"dim\">这一问没答</span>')), tCell(t('和差多少'), off), tCell(t('靠什么对时'), `${esc(v.deviceTimeType || t('它没说'))}${v.deviceTimezone ? t(' · 时区 ') + esc(v.deviceTimezone) : ''}${v.daylightSavings === true ? t(' · 开了夏令时') : ''}`), ntp ? tCell(t('它的时间源'), `<code>${esc(ntp)}</code>`) : '']));
    }
    secs.push(t('<h2 style=\"margin-top:16px\">问话记录</h2>\n      <table><tr><th>问了什么</th><th>状态</th><th>为什么</th></tr>{0}</table>', [led]));
    out.innerHTML = `${advice ? adviceBox(cls, esc(advice)) : ''}
      ${r.note ? `<p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>` : ''}${secs.join('')}`;
  };
  return card;
}

const ONVIF_STEP = {
  'asked': [t('问出去了'), 'ok', ''],
  'not-asked': [t('没问出去'), 'bad',
    t('这一步的结论不算它的读数 —— 连问都没问到，就不能说这一项没问题。')],
};

const ONVIF_CODE = {
  'onvif-ok': [t('身份与码流都问到了'), 'ok',
    t('★ 上面那个取流地址直接抄进下面「取流探测」验流。码流表里有几个 token 就是几条流 —— ')
    + t('主码流 / 子码流是两条不同的 profile，对一下分辨率是不是你要的那一路，再对上下游平台期望的那一路。')],
  'onvif-no-profile': [t('它说一条码流都没配'), 'bad',
    t('★ 媒体服务答得出来、也明确说了没有流 —— 这就不是链路的问题了。去设备自己的通道 / 码流配置看有没有启用')
    + t('（多数相机加完通道只开主码流，子码流默认是关的），配好再问一次。')],
  'onvif-partial': [t('身份问到了，媒体那一路问不出'), 'warn',
    t('★ 设备确实是 ONVIF，只是媒体服务没答（那个端口不通、不认这一问、或者这台没实现媒体服务）。')
    + t('下面「问话记录」写了是哪一问、为什么。这一段问不出地址，取流地址先回设备网页后台或厂商工具里抄。')],
  'auth-required': [t('要账号，或者这个账号被挡'), 'warn',
    t('★ 先分清是哪一种：账号没填 = 它在要；填了还被挡 = 这个账号不够格。')
    + t('很多相机把 ONVIF 账号和 Web 登录账号分开管 —— 要在它自己的用户列表里另加一个，并勾上媒体权限。')
    + t('拿「网页能登录」去推「ONVIF 也该能用」，就会一直卡在这一格。')],
  'onvif-fault': [t('它回了 Fault，是不接这一问'), 'bad',
    t('★ Fault 是「问到了、但不这么答」，不是密码不对，别去翻密码。')
    + t('看问话记录里那句原因：Action not supported 这类是这台固件没实现这个操作，')
    + t('去对一下它的 ONVIF Profile 支持范围（S 只给取流，T 才给云台那一套）。')],
  'not-onvif': [t('这个地址不是 ONVIF 服务'), 'bad',
    t('★ 连得上、也回了话，回的却是网页或别的协议，所以「没回应」这个说法在这儿是错的。')
    + t('ONVIF 常见在 80，也有 8899 / 2020 / 8080；先进设备网页后台确认 ONVIF 开关是开着的。')
    + t('那个端口如果是 TLS，地址前缀要写 https://。')],
  'no-response': [t('连上了，一声不响'), 'bad',
    t('★ 端口活着却不答话：服务卡死，或者它只放行白名单里的 IP 发 ONVIF。')
    + t('先看这台的网络服务要不要重启，再确认本机地址在不在它的允许列表里。')],
  'unreachable': [t('连不上'), 'bad',
    t('★ 连不上先别改密码 —— 密码错不会导致连不上。去「ping 与端口」那页确认这个端在不在：')
    + t('端口不在 = ONVIF 没开、或者中间隔了路由/防火墙；端口在而这里连不上 = 前缀（http / https）写错了。')],
};

function rtspCard() {
  const card = $(t('<div class=\"card\">\n    <h2>取流探测 <span id=\"rt-top\"></span></h2>\n    <p class=\"hint\">问一个 RTSP 地址「这里有一路流吗」。读的是它的应答（SDP），\n      ★ 不解码、不放画面、不装任何播放器 —— 所以它答的是「设备肯不肯给流、给的是什么规格」，\n      图像本身好不好看不归它管。</p>\n    <div style=\"display:flex;gap:12px;align-items:flex-end\">\n      <div style=\"flex:1\"><label>取流地址</label>\n        <input id=\"rt-u\" placeholder=\"rtsp://192.168.1.64:554/cam/realmonitor?channel=1&subtype=0\"></div>\n      <div style=\"flex:0 0 160px\"><label>实收听多久</label><select id=\"rt-w\">\n        <option value=\"3000\">三秒（默认）</option>\n        <option value=\"6000\">六秒 —— 起流慢的设备</option>\n        <option value=\"10000\">十秒 —— 慢到可疑</option>\n        <option value=\"0\">不听，只问参数</option>\n      </select></div>\n    </div>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"rt-b\">探测</button></div>\n    <div id=\"rt-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#rt-out');
  const top = card.querySelector('#rt-top');
  card.querySelector('#rt-b').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">探测中…</div>');
    const u = card.querySelector('#rt-u').value.trim();
    const w = Number(card.querySelector('#rt-w').value);
    const r = await call('media.rtsp.probe', { url: u, measureMs: w });
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)]); return; }
    const [title, cls, advice] = RTSP_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const v = r.values || {};
    const rows = (v.tracks || []).map((t) => `<tr><td>${esc(t.kind || '')}</td>`
      + `<td>${esc(t.codec || '—')}</td>`
      + `<td>${t.width ? `${t.width}×${t.height}${t.fps ? ' @' + t.fps + 'fps' : ''}` : t('<span class=\"dim\">没给参数集</span>')}</td></tr>`).join('');
    // 有流时 note 就是那几轨的文字版，表格里已经有了，不再重复一行。
    const note = r.note && r.verdict !== 'stream-ok'
      ? `<p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>` : '';
    out.innerHTML = `<table>
      ${tCell(t('问的地址'), `<code>${esc(v.url || u)}</code>`)}
      ${tCell(t('连的端'), `<code>${esc(v.target || '')}</code>${v.status ? t(' · 应答 {0}', [v.status]) : ''}`)}
      ${rows ? t('<tr><th>轨</th><th>编码</th><th>规格（分辨率 / 帧率）</th></tr>{0}', [rows]) : tCell(t('轨'), t('<span class=\"dim\">应答里没有媒体描述</span>'))}
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
    const why = v.measureNote || (v.measured === false ? t('这一次没收流') : '');
    // 「换了路子」这一句量没量到都得露：只在有读数时才显示，
    // 就把「UDP 没谈成」那一格悄悄抹掉了，而那正是下一步要看的。
    const switched = v.transportNote ? `<p class="dim" style="margin:6px 0 0">${esc(v.transportNote)}</p>` : '';
    return why ? t('<p class=\"dim\" style=\"margin:10px 0 0\">实际收到：{0}</p>{1}', [esc(why), switched]) : '';
  }
  const has = (x) => x !== undefined && x !== null && x !== 0;
  const loss = has(r.lostPackets)
    ? t('{0} 包（{1}%）', [r.lostPackets, r.lossPercent])
    : (r.lossNote ? `<span class="dim">${esc(r.lossNote)}</span>` : t('一个没丢'));
  const cells = [
    [t('收流走的口子'), (v.transport === 'udp' ? 'UDP' : t('TCP 交织')) + t(' · {0} 毫秒里到了 {1} 包', [r.measuredMs, r.packets])],
    [t('实际码率'), has(r.bitrateKbps) ? t('{0} kbps（只按载荷字节算）', [r.bitrateKbps]) : t('<span class=\"dim\">窗口太短，没算</span>')],
    [t('到达帧率'), has(r.receivedFps) ? t('{0} fps（数的是 marker 位，一帧的最后一包）', [r.receivedFps]) : t('<span class=\"dim\">没算</span>')],
    [t('丢包'), loss],
    [t('乱序 / 重复'), `${r.reordered || 0} / ${r.duplicates || 0}`],
    [t('关键帧'), has(r.keyframes) ? t('{0} 张', [r.keyframes]) + (has(r.keyframeEveryMs) ? t(' · 隔 {0} 毫秒一张', [r.keyframeEveryMs]) : '')
      : t('<span class=\"dim\">这路编码认不出关键帧，只数了包</span>')],
  ];
  const why = (v.measureNote || r.rateNote || '')
    ? `<p class="dim" style="margin:6px 0 0">${esc(v.measureNote || r.rateNote)}</p>` : '';
  const other = (r.measureNotes || []).map((x) => `<p class="dim" style="margin:6px 0 0">${esc(x)}</p>`).join('');
  const switched = v.transportNote ? `<p class="dim" style="margin:6px 0 0">${esc(v.transportNote)}</p>` : '';
  return t('<p class=\"hint\" style=\"margin:14px 0 4px\">实际收到 —— 这一段是量出来的，不是设备说的</p>\n    <table>{0}</table>{1}{2}{3}', [cells.map(([k, val]) => tCell(k, val)).join(''), why, switched, other]);
}

const RTSP_CODE = {
  'stream-ok': [t('有流'), 'ok',
    t('★ 设备肯给流，上面这些轨就是它能给的全部规格。接进平台前对一下编码和分辨率是不是要的那路码流——主码流/子码流常常只差路径里的一位数字。')],
  'stream-no-media': [t('回了 200，但一轨媒体都没有'), 'bad',
    t('★ 连上、认证都过了，这条路径上却没配出码流 —— 不是下游的问题。去设备那侧看这个通道有没有启用（很多相机加完通道默认不开子码流），再把路径里的通道号 / 码流类型对一遍。')],
  'stream-no-data': [t('它答应给流，可一个包都没来'), 'bad',
    t('★ 轨是有的、账号是过了、PLAY 也回了 200 —— 前面那几步全都对，唯独码流没到本机。')
    + t('先确认这台设备让不让第二路取流（多数型号只开一路，平台正在拉流时它就这么答）；')
    + t('再分清是哪一路没通：走 UDP 时收流用的是本机一批临时偶数口，')
    + t('隔了 NAT 或防火墙只看已知服务口，包就回不来 —— 换 TCP 交织再问一次，')
    + t('TCP 那一路要能收到，就是那批 UDP 口被挡了，不是设备没发。')],
  'auth-required': [t('要账号密码'), 'warn',
    t('★ 401 不是设备坏了，是问到了、只是不让看。先核对账号密码，再确认这个账号有没有该通道的取流权限（NVR 上不同用户开的通道不一样）。')],
  'not-found': [t('这个路径没有流'), 'bad',
    t('★ 设备是好的、账号是好的，只有路径不对。海康是 /Streaming/Channels/101，大华是 /cam/realmonitor?channel=1&subtype=0，通道号和码流类型就在最后那几位。')],
  'no-response': [t('连上了没回应'), 'bad',
    t('端口开着却不回 RTSP，大概率端口号填错了：554 才是 RTSP，80 是 Web，8000 / 8200 是各家私有 SDK 的口子。也可能是设备只放行了指定 IP。')],
  'unreachable': [t('连不上'), 'bad',
    t('★ 连不上先别改密码。去「ping 与端口」那页探一下这个端在不在：端口在而 RTSP 不通，是服务的问题；端口就不在，先确认地址、网段和中间隔没隔路由。')],
};

// hlsCard 排在「取流探测」后面，顺序就是现场的动作顺序：
// 先问设备要地址（ONVIF）→ 验这路流到没到本机（RTSP）→ 最后问平台那份清单此刻还写着什么（这一张）。
function hlsCard() {
  const card = $(t('<div class=\"card\">\n    <h2>拉一路 HLS（m3u8） <span id=\"hl-top\"></span></h2>\n    <p class=\"hint\">问平台<b>这份清单此刻还在不在往前加片子</b>。★ 它和上面那张「取流探测」问的不是同一件事：\n      RTSP 量的是码流到没到本机，这一路中间隔着一层平台 —— 盒子说没画面，\n      有一种毛病是清单还在、里面的分片却早就不加了。同样不解码、不放画面、不改任何东西。</p>\n    <div style=\"display:flex;gap:12px;align-items:flex-end\">\n      <div style=\"flex:1\"><label>清单地址</label>\n        <input id=\"hl-u\" placeholder=\"http://192.168.1.20:80/hls/cam1/index.m3u8\"></div>\n      <div style=\"flex:0 0 190px\"><label>隔多久再看一次清单</label><select id=\"hl-w\">\n        <option value=\"4000\">四秒（默认）</option>\n        <option value=\"8000\">八秒 —— 切片周期长的平台</option>\n        <option value=\"15000\">十五秒 —— 慢到可疑</option>\n        <option value=\"0\">不看，只拉一次（点播）</option>\n      </select></div>\n      <div style=\"flex:0 0 130px\"><label>抽查几片</label><select id=\"hl-s\">\n        <option value=\"2\">两片（默认）</option>\n        <option value=\"3\">三片</option>\n        <option value=\"1\">只看最新那片</option>\n        <option value=\"0\">不取分片</option>\n      </select></div>\n    </div>\n    <details style=\"margin-top:8px\"><summary class=\"dim\">这台要账号（Basic）/ 一次请求的超时</summary>\n      <div class=\"row\" style=\"margin-top:8px\">\n        <div><label>账号</label><input id=\"hl-usr\" autocomplete=\"off\"></div>\n        <div><label>口令</label><input id=\"hl-pw\" type=\"password\" autocomplete=\"off\"></div>\n        <div style=\"flex:0 0 160px\"><label>单次超时 ms</label><input id=\"hl-t\" placeholder=\"5000\"></div>\n      </div>\n      <p class=\"hint\" style=\"margin-top:6px\">地址里已经带了账号（http://user:pass@host/…）就别填这两个，\n        ★ 口令只进请求头，不进结果、不进日志。</p>\n    </details>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"hl-b\">拉一遍</button></div>\n    <div id=\"hl-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#hl-out');
  const top = card.querySelector('#hl-top');
  card.querySelector('#hl-b').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">正在拉清单…（隔几秒再拉一次对照，稍等）</div>');
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
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)]); return; }
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
      title: t('录完的这一段读得到'), cls: 'ok',
      advice: t('★ 清单末尾写着这一段录完了，所以「窗口在不在往前加」本来就不适用 —— 这一句说的是')
        + t('分片取得到、清单点得出的东西都在。播放不到去查别的：清单里的地址、签名有没有过期、播放器那一头。'),
    };
  }
  const sawSeg = (v.sampled || []).length > 0;
  const sawWindow = v.windowAdvanced !== undefined;
  if (sawSeg && sawWindow) return { title: raw[0], cls: raw[1], advice: raw[2] };
  const missing = [];
  const tips = [];
  if (!sawSeg) {
    missing.push(t('一片分片都没取过'));
    tips.push(t('把「抽查几片」换成两片再问一次'));
  }
  if (!sawWindow) {
    missing.push(t('没看第二遍，说不了它在不在往前加'));
    tips.push(t('把「隔多久再看一次清单」换成四秒再问一次'));
  }
  return {
    title: t('清单读得到，但') + missing.join(t('、')),
    cls: '',
    advice: t('★ 这一句只验到「清单此刻读得到」，上面没说的两格还算没排除：')
      + tips.join(t('、')) + t('。'),
  };
}

// hlsResult 把一次探测摊开。★ 每一格都留了「为什么没有这一格」的位置：
// 空着和填了 0 是两种结论（没去看窗口 ≠ 看了没动，没取分片 ≠ 分片取不到）。
function hlsResult(r) {
  const v = r.values || {};
  const { cls, advice } = hlsDisplay(r);
  const dim = (x) => `<span class="dim">${x}</span>`;
  const cells = [tCell(t('问的地址'), `<code>${esc(v.url || '')}</code>`
    + (v.finalURL ? ` · ${dim(t('最后落在'))} <code>${esc(v.finalURL)}</code>` : ''))];
  // ★ closed（主机在、这个口没服务）与 filtered（一句都不答）是下一步走两条路的分界，
  //   它连着不上时根本没有状态码 —— 那一格不能跟着状态码一起消失。
  const said = [];
  if (v.httpStatus) said.push(`HTTP ${esc(v.httpStatus)}`);
  if (v.contentType) said.push(esc(v.contentType));
  if (v.looksLike) said.push(dim(t('内容看着像 {0}', [esc(v.looksLike)])));
  if (v.reach) said.push(dim(v.reach === 'closed' ? t('端口明确拒绝（主机在，这个口没服务）') : t('没有任何回应')));
  if (said.length) cells.push(tCell(t('它回的'), said.join(' · ')));
  if (v.master) {
    const rows = (v.variants || []).map((x) => `<tr><td><code>${esc(x.uri || '')}</code></td>`
      + `<td>${x.bandwidth ? esc((x.bandwidth / 1000).toFixed(0)) + ' kbps' : '—'}</td>`
      + `<td>${esc(x.resolution || '—')}</td><td>${esc(x.codecs || '—')}</td></tr>`).join('');
    cells.push(tCell(t('这是一份主清单'), t('里面列了 {0} 路，★ 下面问的是带宽最高的那一路', [(v.variants || []).length])
      + t('<table><tr><th>地址</th><th>带宽</th><th>分辨率</th><th>编码</th></tr>{0}</table>', [rows])
      + (v.variant ? t('<div>替你看的是 <code>{0}</code>{1}</div>', [esc(v.variant), v.variantResolution ? ' · ' + esc(v.variantResolution) : '']) : '')));
  }
  const kind = v.isLive === undefined ? '' : (v.isLive ? t('直播（还在往前加）') : t('点播（这一段录完了）'));
  if (kind) {
    cells.push(tCell(t('这份清单'), [
      kind,
      t('{0} 片', [v.segmentCount ?? 0]),
      v.windowSec ? t('窗口共 {0} 秒', [esc(v.windowSec)]) : dim(t('一片都没有，谈不上窗口')),
      v.mediaSequence ? t('序号从 {0} 起', [esc(v.mediaSequence)]) : '',
      v.targetDurationSec ? t('写着每片最长 {0} 秒', [esc(v.targetDurationSec)]) : dim(t('没写每片最长')),
      v.hasInitSegment ? t('带初始化段（fMP4 切的）') : '',
      v.discontinuities ? dim(t('中间有 {0} 处时间戳断点', [esc(v.discontinuities)])) : '',
    ].filter(Boolean).join(' · ')));
  }
  if (v.longestSegmentSec) {
    cells.push(tCell(t('最长的那一片'), t('{0} 秒 —— 比清单承诺的长，播放器会在这里缓冲', [esc(v.longestSegmentSec)])));
  }
  const sampled = (v.sampled || []).map((x) => {
    // ★ 先读 error 再读状态码：回 200/206 而正文是空的，那一条的毛病写在 error 里，
    //   按状态码显示就成了「回 HTTP 206」—— 数字很好看，毛病却被盖住。
    const got = x.ok ? t('{0} 字节 · {1} 毫秒', [(x.bytes || 0).toLocaleString(), x.elapsedMs ?? 0])
      : (x.error ? esc(x.error)
        : (x.httpStatus ? t('回 HTTP {0}', [esc(x.httpStatus)]) : t('没取到')));
    return `<tr><td>${x.initSegment ? t('初始化段') : (t('第 ') + (x.seq ?? '?') + t(' 片'))}</td>`
      + `<td>${x.durationSec ? esc(x.durationSec) + t(' 秒') : '—'}</td>`
      + `<td>${got}${x.truncated ? dim(t('（读满上限，没读完）')) : ''}${x.byteRange ? dim(t(' · 段 ') + esc(x.byteRange)) : ''}</td>`
      + `<td><code>${esc(x.uri || '')}</code></td></tr>`;
  }).join('');
  if (sampled) {
    cells.push(tCell(t('抽查的分片'),
      t('<table><tr><th>哪一片</th><th>标称时长</th><th>取回的</th><th>地址</th></tr>{0}</table>', [sampled])));
  }
  if (v.missingSegment) {
    cells.push(tCell(t('取不到的是哪一片'), `<code>${esc(v.missingSegment)}</code>`
      + ` ${dim(t('它回的是什么，写在上面「抽查的分片」那一格里'))}`));
  }
  if (v.bitrateKbps) {
    cells.push(tCell(t('实际码率'), `${esc(v.bitrateKbps)} kbps · ${dim(esc(v.bitrateBasis || ''))}`
      + (v.bitrateSkipped ? `<br>${dim(esc(v.bitrateSkipped))}` : '')));
  } else if (v.sampled) {
    cells.push(tCell(t('实际码率'), dim(t('没算 —— 抽查的片没一片是「整片读完」的'))));
  }
  if (v.windowAdvanced !== undefined) {
    cells.push(tCell(t('窗口挪了没有'), (v.windowAdvanced
      ? t('<b>挪了</b> · 等了 {0} 毫秒', [esc(v.watchedMs ?? 0)])
      : t('<b>一片没换</b> · 等了 {0} 毫秒', [esc(v.watchedMs ?? 0)]))
      + (v.stuckOn ? t(' · 一直停在 <code>{0}</code>', [esc(v.stuckOn)]) : '')
      + (v.lastSegmentNow ? t(' · 此刻最后一片是 <code>{0}</code>', [esc(v.lastSegmentNow)]) : '')));
  } else if (v.isLive) {
    cells.push(tCell(t('窗口挪了没有'), dim(t('这一次没看（只拉了一次清单，说不了卡不卡）'))));
  }
  if ((v.unknownTags || []).length) {
    cells.push(tCell(t('认不出的标签'), dim(t('只留了名字，值没抄：{0}', [(v.unknownTags || []).map(esc).join(t('、'))]))));
  }
  if (typeof v.detail === 'string' && v.detail) cells.push(tCell(t('原文那一错'), dim(esc(v.detail))));
  // 判定本身是好的时候，note 就是那一格读数的复述，不再单占一行。
  const note = r.note && r.verdict !== 'hls-ok'
    ? `<p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>` : '';
  return `<table>${cells.join('')}</table>${note}`
    + (advice ? adviceBox(cls, esc(advice)) : '')
    + t('<details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>')
    + `<pre>${esc(JSON.stringify(r.raw || v, null, 2))}</pre></details>`;
}

const HLS_CODE = {
  'hls-ok': [t('这一路是活的'), 'ok',
    t('★ 清单拉得到、抽查的分片取回、窗口还在往前加 —— 平台这一头是好的。画面上还是没东西，')
    + t('那就不是源的问题：查播放器到平台之间那一段（它拉的地址是不是这一路、域名解析到哪、账号是谁的）。')],
  'hls-stalled': [t('清单还在，可窗口一片没换'), 'bad',
    t('★ 这是这一路最值钱的一档：地址对、不报错、清单也还写着 —— 唯独不再往前加分片。')
    + t('说明推流那一早就不推了，而平台没把这路下线。去找推流端（设备、编码器、推流服务）看它还活不活，')
    + t('别在重启平台上绕圈 —— 重启完它还是拿到一份不动的清单。')],
  'hls-segment-missing': [t('清单点出来的分片取不到'), 'bad',
    t('★ 清单和分片对不上号：多半是平台删得比写得快（窗口给播放器留得太短），或者源站和平台之间换了机器。')
    + t('分清回的是 404 还是没回话：404 是对不上号，没回话是分片还在写或者那条路被挡了。')],
  'hls-empty-playlist': [t('清单是空的'), 'bad',
    t('★ 里面一片都没有 —— 这一路此刻根本没在推（刚点开播，或者已经掉线）。先确认推流端起来了再问一次；')
    + t('如果它一直空着而平台显示「在线」，那是平台的通道状态是假的，不是网络的问题。')],
  'hls-target-over': [t('分片比清单承诺的长'), 'warn',
    t('★ 能播，但播放器会反复缓冲：清单写着每片最长几秒，实际有一片明显超过。')
    + t('多半是码率突然冲高，或者编码器的 GOP 比切片周期还长 —— 改切片周期或码率上限，不是改网络。')],
  'hls-auth-required': [t('要账号'), 'warn',
    t('★ 401、403 不是坏了，是问到了、只是不给。注意清单和分片可能用两套凭据（分片走签名地址的那种更常见）：')
    + t('先把这份地址原样丢进浏览器看能不能下下来，再核对账号对这条通道有没有权限。')],
  'hls-not-found': [t('这个路径上没有清单'), 'bad',
    t('★ 十有八九是流名写错。各平台是 /hls/流名/index.m3u8、/流名.m3u8、/live/流名/playlist.m3u8 这几套写法，')
    + t('回平台把这条通道的播放地址原样抄一遍，别手敲。')],
  'hls-not-hls': [t('回的不是清单'), 'bad',
    t('★ 它答话了，答的不是 HLS：可能是设备自己的网页、一段裸流（FLV、MP4），或者这个口上说的压根不是 HTTP。')
    + t('结果里「内容看着像」那一格写了头几个字节认出的形状。RTSP、RTMP 那两路用上面几张卡去问。')],
  'hls-unreachable': [t('连不上'), 'bad',
    t('★ 连不上先别改密码 —— 密码错不会导致连不上。端口明确回了拒绝，说明主机活着、这个口上没有服务，')
    + t('去核对端口号和平台进程；什么都没回，先回「ping 与端口」那页确认这台在不在、中间隔没隔路由。')],
  'hls-timeout': [t('连上了没回话'), 'bad',
    t('★ 端口通了却不给清单：多半是平台那边压着一堆请求，或者它只放行内网某几段地址。')
    + t('把单次超时放宽到十秒再问一次；还是不通，就看那台服务器的负载和访问日志里有没有这一问 —— ')
    + t('日志里没有，就是没到这里。')],
};

// RTMP_CODE 是「推上去的那一路」的十二档。
//
// ★ 这一族的问题方向和上面几张卡是反的：RTSP / HLS 问的是「平台肯不肯把流给我」，
//   这里问的是「推流端送上去的东西，到没到服务器」。所以最值钱的一档是
//   rtmp-no-media —— 命令全通、状态码说好、码流却没过来，那一句「推流没到平台」说的就是它。
const RTMP_CODE = {
  'rtmp-ok': [t('这路在推，码流真到了'), 'ok',
    t('★ connect、createStream、play 三步全过，而且观测窗口里收到了媒体字节 —— 推流这一路是通的。')
    + t('看上面「实际码率」与推流端声明的差多少：差一半以上是链路上在丢或者服务器在限。')
    + t('平台还是没画面，问题在它后面那层（转分发、播放地址、播放器账号），用 HLS 那张卡接着往下问。')],
  'rtmp-no-media': [t('服务器说有这路，可一个媒体字节都没到'), 'bad',
    t('★★ 命令全通、play 也答应了，唯独码流没过来 —— 「推流没到平台」在现场十有九就是这一档。')
    + t('先分清是「没推上来」还是「上来了却没转发给你」：在服务器本机问一次，本机有字节说明中间那道')
    + t('（NAT、防火墙、只放行命令口的策略）挡住了媒体；本机也没有，就是推流端在推一个空壳。')
    + t('★ 只给一秒窗口时，低帧率的事件触发流可能刚好一片都没落进来 —— 换成六秒再问一次，')
    + t('还是零字节才坐实「没推上来」。')],
  'rtmp-stream-absent': [t('这个名字上根本没有流'), 'bad',
    t('★ 服务器直接回 StreamNotFound —— 和「有这路但没人推」是两回事，它是连找都没找到。')
    + t('核对流名：各家把参数算在名字里（?live=1、?key=xxx），少一段就是另一个流；')
    + t('也要确认推流端用的流名和平台这条通道的流名是同一个，别拿播放地址的流名去推。')],
  'rtmp-stream-not-publishing': [t('名字认得，可此刻没人往上面推'), 'bad',
    t('★ 服务器知道这一路，但现在没人在推 —— 毛病在推流端那一头，不在这台服务器。')
    + t('去看相机 / OBS / 转推服务那台机器活不活、它的日志里有没有断线重连、它推的是不是这个地址。')
    + t('重启服务器没用：重启完还是没人推。')],
  'rtmp-app-accepted': [t('这台认这个应用，但「这路在不在推」没问'), 'warn',
    t('★ 这一条不是好消息也不是坏消息：地址里没写流名，所以只问到 connect 那一步就停了。')
    + t('把地址补成 rtmp://主机/应用名/流名 再问一次 —— 差的那一段才是「有没有画面」的答案。')],
  'rtmp-app-rejected': [t('connect 被拒'), 'bad',
    t('★ 握手做完了，可它不认这个应用。三种可能：应用名拼错（live / stream / openapi 各家不同）、')
    + t('这台只允许推不允许看、或者它按 vhost 分租户而这次没带。')
    + t('先抄平台给的原样地址；仍被拒就问平台「播放侧要不要单独开」。')],
  'rtmp-auth-required': [t('这台要凭据才给进'), 'warn',
    t('★ 拒绝的理由写的是 key / token / 口令 —— 不是坏了，是问到了只是不给。')
    + t('RTMP 的凭据有三种挂法：流名后面那段 ?key=、应用名那一段、或者 connect 参数里的 vhost。')
    + t('结果里「它说的那句」会指出是哪种，照那个位置补，别改地址前缀。')],
  'rtmp-command-silent': [t('握手通了，命令发出去到点不回话'), 'bad',
    t('★★ 与「connect 被拒」下一步完全相反：被拒是它答了不给，沉默是它压根不答。')
    + t('多半是这台只肯收推流、对播放侧的命令直接丢弃，或者中间那台设备只放行握手那种小报文。')
    + t('换到服务器本机问一次：本机回话就是中间那道的问题。')],
  'rtmp-not-rtmp': [t('那个口接了 TCP，却不说 RTMP'), 'bad',
    t('★ 端口开着、连接也建了，但对面回的不是 RTMP 握手 —— 结果里「看着像」那一格说了它像什么。')
    + t('常见的三种：1935 上跑的其实是 HTTP-FLV、端口号抄错撞上了 Web 管理页、')
    + t('或者这台只开了 TLS（要把前缀改成 rtmps://）。')],
  'rtmp-unreachable': [t('连不上那个口'), 'bad',
    t('★ 先看 reach 那一栏：closed 是机器在、这个口上没服务（RTMP 服务没起，或端口不是 1935）；')
    + t('filtered 是它一句都不答（防火墙只放行白名单 —— 相机与平台之间最常卡这一条）。')
    + t('这两种下一步完全不同，别并成「网络不通」。')],
  'rtmp-timeout': [t('端口能连上，可握手那一句到点没回'), 'bad',
    t('★ TCP 建起来了，RTMP 握手却石沉大海 —— 这一档几乎不是「服务没起」（没起会直接拒），')
    + t('而是中间有东西只放行 TCP 三次握手、往下看都不看就丢，或者这台只对外地那几台地址答话。')
    + t('先去服务器本机问 127.0.0.1：本机通、外部不通，就是访问控制。')],
  'rtmp-connection-lost': [t('问到一半它把连接断了'), 'bad',
    t('★ 连接建立、命令也发了，可它在答完之前就把连接关了。断之前问到什么是一道分界：')
    + t('收到 Play.Start 才断 —— 服务器不认这个客户端（版本、并发上限、单连接时长限制）；')
    + t('connect 后面就断 —— 这台的白名单或频次限制把这一问踢了；什么都没收到就断 —— 中间那台在掐。')],
};

// FLV_CODE 是 HTTP-FLV 裸流的九档 —— 同一个 media.rtmp.probe，地址前缀换成 flv://。
//
// ★★ 为什么单独一张表，不并进 RTMP_CODE：这一族的问法根本不是「命令答没答」，
//   它没有握手、没有 connect、没有 play。它是 HTTP 一句 GET，然后看**字节本身**。
//   最值钱的一档是 flv-audio-only：画面没出来但声音有 —— 现场那句「打开了但没画面」
//   十有九是这一档，而它长成「一切正常」的样子（200、有标签、码流在动），
//   只有按容器数标签才看得出来。
const FLV_CODE = {
  'flv-ok': [t('这一路有画面，容器里数到视频标签了'), 'ok',
    t('★ HTTP 200、FLV 头对得上、窗口里确实有视频标签 —— 这一段裸流是在给画面的。')
    + t('看上面「容器里数到的」那一格：编码、声明分辨率、关键帧个数，几个数对不对得上下游那台播放器。')
    + t('★ 有画面但播放器还是不出图，问题不在这一段链路上，去问解码那一头（编码它支不支持、')
    + t('首帧要等到下一个关键帧）。')],
  'flv-audio-only': [t('这一路只有声音，没有画面'), 'bad',
    t('★★ 现场那句「打开了但没画面」说的就是这一档 —— 它不是坏了：HTTP 200、头是好的、')
    + t('标签一直在来、只有音频那一种。播放器拿到的是「有声音的黑屏」，而多数播放器不报错。')
    + t('往上游一层问：推流端有没有真的编出视频（OBS 里视频源被关掉、相机只给了音频通道）、')
    + t('平台转码模板有没有把视频轨丢掉（各家「仅音频」的模板长得很像默认模板）。')
    + t('对照方法：同一台拿 rtmp:// 那一路再问一次，RTMP 侧有视频而 FLV 侧没有 —— 是分发这一层丢的。')],
  'flv-no-media': [t('答应了给，可一个音视频标签都没有'), 'bad',
    t('★ 两种成因，结果里那一格分得开：给了 200 却一个字节都没来（正文是空的），')
    + t('或者头是完好的 FLV、往后数了半天一个音视频标签都没有。')
    + t('前者多半是这一路此刻没人推、平台却仍然挂着这个地址；后者是转封装只写完了头就停了 —— ')
    + t('去看平台那个 worker 有没有在跑。')
    + t('★ 别把「窗口太短」当成这一档：事件触发的低帧率流，三秒里可能真的什么都没有，')
    + t('把上面「收多久」调到十秒再问一次。')],
  'flv-not-flv': [t('回 200，可里面不是 FLV'), 'bad',
    t('★ 这一问最容易被误读的一档：地址通、200、有正文 —— 但那堆字节不是 FLV 容器。')
    + t('结果里「那一段看着像」会说出它像什么：像网页就是端口或路径配错了（撞上管理页），')
    + t('像 MP4 是这路存成了点播文件而不是直播裸流，像 RTMP 握手是这台只开了 1935 那条协议。')
    + t('★ 拿 1935 那个口去问 RTMP（前缀写 rtmp://），别在 HTTP 口上等 FLV。')],
  'flv-http-status': [t('它按 HTTP 说了句话，没说给流'), 'warn',
    t('★ 状态码就是答案本身，别看成人话里的「不通」：404 是这个名字没有（应用名/流名写错），')
    + t('403·401 是要凭据（key/sign 或账号，补齐再问），3xx 是这一路被领去了别处（去向见结果），')
    + t('429 是这一刻问得太多不是这路坏了，5xx 是那台自己给不出。')
    + t('★ 3xx 这一问没有跟着跳：跟着跳就去问另一台机器了，而你要知道的是此刻这一台说了什么。')],
  'flv-unreachable': [t('连不上那个 HTTP 口'), 'bad',
    t('★ 先看 reach 那一栏：closed 是主机在、这个口上没服务（FLV 分发没起，或者端口不是 80）；')
    + t('filtered 是它一句都不答（只放行白名单 —— 相机与平台之间最常卡这一条）。')
    + t('这两种下一步完全不同，别并成「网络不通」。顺手核一遍端口：flv:// 默认打 80，')
    + t('很多平台挂在 8080 / 554 / 自定端口上，要写成 flv://主机:端口/应用/流名。')],
  'flv-timeout': [t('口能连上，可它到点不给东西'), 'bad',
    t('★ TCP 建起来了，那一句 GET 的回要么不来、要么来了个头就没正文 —— 这一档卡在通道，')
    + t('不在这一路存不存在。常见两种：这台只允许固定的几个来源地址取流；')
    + t('或者它对单个连接压着不发（等着凑够一段再冲出来）。')
    + t('换到平台那台机器本机问一次 127.0.0.1：本机给流、外部不给，就是访问控制那一层。')],
  'flv-tag-broken': [t('标签声称的长度与到手的对不上'), 'bad',
    t('★★ 这是容器层才看得见的一种坏：前面都对，读到一个标签时它说自己有多长、')
    + t('实际到手的不够，往下就没有可信的边界了 —— 后面全是猜的，所以只能停。')
    + t('断之前数到的标签与字节照实在结果里给出，那不是零，那是「它撑到哪儿才散」。')
    + t('成因两段：中间有设备在改长度或截断（代理、WAF、只转发半截的网关），')
    + t('或者平台写 FLV 的那段代码算错偏移（各家转封装都出过这种 bug）。')
    + t('对照一次：同一台拿 rtmp:// 问，RTMP 侧完整而 FLV 侧断 —— 是转封装那一层。')],
  'flv-stream-dropped': [t('读到一半它把连接关了'), 'bad',
    t('★ 流在动，然后连接被对端关掉。断之前数到了多少标签、多少字节，是这一档唯一的分界证据：')
    + t('数到几十个就断 —— 平台按连接数或时长在掐（并发上限、试听窗口）；')
    + t('数到几千个才断 —— 更像推流端在那一头停了，分发跟着收尾。')
    + t('★ 直播裸流被服务端关是常态动作，不要看到「断了」就当链路坏了：')
    + t('先比上面那一段的速率与时长，够不够一屏画面。')],
};

const isFLVVerdict = (code) => typeof code === 'string' && code.startsWith('flv-');

// rtmpCard 排在 HLS 后面，问的是这条流水线的**另一头**：
// ★ 上面几张卡问的是「平台肯不肯把流给我」，这一张问的是「推流端送上去的东西到没到服务器」。
//   两问的地址长得一样、落点完全相反，所以同页不同卡。
function rtmpCard() {
  const card = $(t('<div class=\"card\">\n    <h2>问一路 RTMP 推流 <span id=\"rm-top\"></span></h2>\n    <p class=\"hint\">问「相机 / OBS / 转推服务送上来的那一路，此刻到没到服务器」。这一问拆成五步：\n      端口通不通 → 是不是 RTMP 握手 → 应用认不认 → 这个流名上有没有流 → 有没有真的媒体字节过来\n      （在推的话顺手量出码率）。<b>只读</b>：只发 connect / createStream / play 三条命令，\n      ★ 绝不发 publish 那几条 —— 那是往别人服务器上挂一路流。口令与 key 只发出去，不进结果、不进日志。</p>\n    <div style=\"display:flex;gap:12px;align-items:flex-end\">\n      <div style=\"flex:1\"><label>推流地址（应用名是第一段，后面算流名）</label>\n        <input id=\"rm-u\" placeholder=\"rtmp://192.168.1.20:1935/live/cam1\"></div>\n      <div style=\"flex:0 0 190px\"><label>收多久的媒体字节</label><select id=\"rm-w\">\n        <option value=\"3000\">三秒（默认）</option>\n        <option value=\"1000\">一秒 —— 只确认在不在推</option>\n        <option value=\"6000\">六秒 —— 低帧率的监控流</option>\n        <option value=\"10000\">十秒 —— 事件触发的流</option>\n      </select></div>\n      <div style=\"flex:0 0 130px\"><label>一步超时 ms</label><input id=\"rm-t\" placeholder=\"5000\"></div>\n    </div>\n    <details style=\"margin-top:8px\"><summary class=\"dim\">地址里没写全（应用名 / 流名分开填）、这台还要 vhost 或 key</summary>\n      <div class=\"row\" style=\"margin-top:8px\">\n        <div><label>应用名（填了覆盖地址里那一段）</label><input id=\"rm-app\" placeholder=\"live\"></div>\n        <div><label>流名（留空就只问「这台认不认这个应用」）</label><input id=\"rm-stream\" placeholder=\"cam1\"></div>\n      </div>\n      <div class=\"row\" style=\"margin-top:8px\">\n        <div><label>vhost</label><input id=\"rm-vhost\" autocomplete=\"off\"></div>\n        <div><label>key / token</label><input id=\"rm-key\" type=\"password\" autocomplete=\"new-password\"></div>\n      </div>\n      <p class=\"hint\" style=\"margin-top:6px\">★ 这两个值是发进 connect 命令里的，结果与日志里都不会出现 ——\n        但「这台要不要单独配 vhost」那一条信息会留下。地址里已经带了 ?key= 就别再填一遍。</p>\n    </details>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"rm-b\">问一遍</button></div>\n    <div id=\"rm-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#rm-out');
  const top = card.querySelector('#rm-top');
  card.querySelector('#rm-b').onclick = async () => {
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">正在问…（握手、三条命令，再收几秒码流，稍等）</div>');
    const args = { url: card.querySelector('#rm-u').value.trim() };
    const app = card.querySelector('#rm-app').value.trim();
    const stream = card.querySelector('#rm-stream').value.trim();
    if (app) args.app = app;
    if (stream) args.stream = stream;
    args.watchMs = Number(card.querySelector('#rm-w').value);
    const t = Number(card.querySelector('#rm-t').value);
    if (t) args.timeoutMs = t;
    const cp = {};
    const vhost = card.querySelector('#rm-vhost').value.trim();
    const key = card.querySelector('#rm-key').value;
    if (vhost) cp.vhost = vhost;
    if (key) cp.key = key;
    if (Object.keys(cp).length) args.connectParams = cp;
    const r = await call('media.rtmp.probe', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message)]); return; }
    const d = rtmpDisplay(r);
    top.innerHTML = `<span class="pill ${d.cls}">${esc(d.title)}</span>`;
    out.innerHTML = rtmpResult(r);
  };
  return card;
}

// rtmpDisplay 把判定码翻成界面要说的那一句（标题、颜色、下一步的手）。
//
// ★ 窗口短于一秒那种「我们没问到」在卡片上就问不出来（最短给一秒），
//   后端对这种问法直接在判定里写明，不在这里另起一套话。
function rtmpDisplay(r) {
  const v = r.values || {};
  // ★ 同一支工具、两张表：flv:// 那一支没有握手 / connect / play 可问，
  //   拿 RTMP 那张表去查它的码，查不到就只剩一个裸的 "flv-audio-only" 在界面上。
  const table = v.protocol === 'flv' || isFLVVerdict(r.verdict) ? FLV_CODE : RTMP_CODE;
  const raw = table[r.verdict] || [r.verdict, '', ''];
  return { title: raw[0], cls: raw[1], advice: raw[2] };
}

// rtmpSteps 五步流水线，每步只有三种说法：问到了 / 它不给 / 根本没问到。
// ★★ 「没问到」必须自己占一格 —— 少问一步就给一句「都正常」，是这张卡最不能犯的错。
function rtmpSteps(v, verdict) {
  const mark = { on: '✓', bad: '✗', none: '—' };
  const tail = { on: '', bad: t('（它不给）'), none: t('（没问到）') };
  const step = (label, st) => `<span class="dim" style="margin-right:12px">${mark[st]} ${label}${tail[st]}</span>`;
  const tcp = v.stage === 'dial' ? 'bad' : 'on';
  const hs = v.stage === 'handshake' ? 'bad' : (v.handshakeMs !== undefined ? 'on' : 'none');
  const refused = v.connectLevel === 'error' || v.connectReply === '_error';
  const app = refused ? 'bad' : (v.connectReply ? 'on' : 'none');
  // 回包到了但不给这一路：状态码是「没有 / 没人推」时，这一步算它不给
  const gone = ['rtmp-stream-absent', 'rtmp-stream-not-publishing', 'rtmp-no-media'].includes(verdict);
  const play = !v.playCode ? 'none' : (gone ? 'bad' : 'on');
  const media = v.mediaBytes === undefined ? 'none' : (Number(v.mediaBytes) > 0 ? 'on' : 'bad');
  return step(t('端口'), tcp) + step(t('握手'), hs) + step(t('应用'), app) + step(t('这一路'), play) + step(t('码流'), media);
}

// flvSteps 是 HTTP-FLV 那一支的四步，和上面 RTMP 的五步**不是一条流水线**：
// ★ 这里没有 connect / play 可问，能问的是「连上没 → 状态码给不给 → 是不是 FLV 容器 → 里面有没有画面」。
//   最后一步才是现场要的那一句，而它跟前一步都可能是「一切正常」——所以不许省。
function flvSteps(v, verdict) {
  const mark = { on: '✓', bad: '✗', none: '—' };
  const tail = { on: '', bad: t('（它不给）'), none: t('（没问到）') };
  const step = (label, st) => `<span class="dim" style="margin-right:12px">${mark[st]} ${label}${tail[st]}</span>`;
  const conn = verdict === 'flv-unreachable' ? 'bad'
    : (v.httpStatus !== undefined || v.bodyBytes !== undefined ? 'on'
      : (verdict === 'flv-timeout' ? 'bad' : 'none'));
  const status = v.httpStatus === undefined ? 'none' : (Number(v.httpStatus) === 200 ? 'on' : 'bad');
  // 容器这一步：数到过标签或读过字节才算「是 FLV」；not-flv / 头都读不成都算不给。
  const container = v.httpStatus !== undefined && status === 'bad' ? 'none'
    : (verdict === 'flv-not-flv' ? 'bad'
      : (v.tags !== undefined || v.bodyBytes !== undefined ? 'on' : 'none'));
  const tags = v.tags === undefined ? 'none' : (Number(v.tags) > 0 ? 'on' : 'bad');
  const video = v.hasVideo === undefined ? 'none' : (v.hasVideo ? 'on' : 'bad');
  return step(t('连上'), conn) + step(t('状态码'), status) + step(t('是 FLV'), container)
    + step(t('有标签'), tags) + step(t('有画面'), video);
}

function flvResult(r, v, dim) {
  const cells = [tCell(t('问的地址'), `<code>${esc(v.url || '')}</code>`
    + (v.path ? ` · ${dim(t('路径'))} <code>${esc(v.path)}</code>` : '')
    + (v.port !== undefined ? ` · ${dim(t('打的口'))} ${esc(v.port)}` : '')
    + (v.hasUserinfo ? `<br>${dim(t('★ 地址里那段 user:pass 走的是 HTTP Basic 头，没写进这一问的地址账上'))}` : ''))];
  cells.push(tCell(t('问到哪一步'), flvSteps(v, r.verdict)));

  const http = [];
  if (v.httpStatus !== undefined) http.push(t('状态码 {0}', [esc(v.httpStatus)]));
  if (v.contentType) http.push(t('它说是 {0} 这一类东西', [esc(v.contentType)]));
  if (v.contentLength) http.push(t('正文声明 {0} 字节', [esc(v.contentLength)]));
  if (http.length) {
    cells.push(tCell(t('HTTP 那一句'), http.join(' · ')
      + (v.redirectLocation ? `<br>${dim(t('★ 它把这一路领去了 {0} —— 这一问没有跟着跳，跳过去问的就是另一台机器了', [esc(v.redirectLocation)]))}` : '')));
  }

  const seen = [];
  if (v.tags !== undefined) seen.push(t('{0} 个标签', [esc(v.tags)]));
  if (v.videoTags !== undefined) seen.push(t('视频 {0}', [esc(v.videoTags)]));
  if (v.audioTags !== undefined) seen.push(t('音频 {0}', [esc(v.audioTags)]));
  if (v.scriptTags !== undefined) seen.push(t('脚本 {0}', [esc(v.scriptTags)]));
  if (v.bodyBytes !== undefined) seen.push(t('{0} 字节', [(Number(v.bodyBytes) || 0).toLocaleString()]));
  if (v.keyframes !== undefined) seen.push(Number(v.keyframes) > 0 ? t('{0} 个关键帧', [esc(v.keyframes)]) : dim(t('一个关键帧都没数到')));
  if (v.videoCodec) seen.push(esc(v.videoCodec) + (v.width && v.height ? ` ${esc(v.width)}×${esc(v.height)}` : ''));
  if (Array.isArray(v.audioFormats) && v.audioFormats.length) seen.push(t('音频 {0}', [v.audioFormats.map(esc).join('/')]));
  if (Array.isArray(v.videoFormats) && v.videoFormats.length) seen.push(t('视频轨 {0}', [v.videoFormats.map(esc).join('/')]));
  if (seen.length) {
    cells.push(tCell(t('容器里数到的'), seen.join(' · ')
      + (v.multiTrack ? `<br>${dim(t('★ Enhanced RTMP 的多轨封装：这一版认得它、不拆里面的轨'))}` : '')
      + (v.videoParamsNote ? `<br>${dim(esc(v.videoParamsNote))}` : '')));
  }
  if (v.firstMediaTS !== undefined && v.lastMediaTS !== undefined) {
    cells.push(tCell(t('这一段流的时间戳'),
      t('{0} → {1} 毫秒', [esc(v.firstMediaTS), esc(v.lastMediaTS)])
      + (v.firstKeyTS !== undefined ? ` · ${dim(t('首个关键帧 {0}', [esc(v.firstKeyTS)]))}` : '')));
  }
  if (v.metadataSeen) {
    cells.push(tCell(t('脚本标签里的元数据'), v.metadata
      ? Object.keys(v.metadata).slice(0, 12).map((k) => `${esc(k)}=${esc(String(v.metadata[k]))}`).join(' · ')
      : t('有，但没有可以照摊的项')));
  }
  const stop = [];
  if (v.stopReason) stop.push(FLV_STOP[v.stopReason] || esc(v.stopReason));
  if (v.prevTagSizeBad) stop.push(dim(t('PrevTagSize 对不上的标签 {0} 个（这一项常见的平台上很多，不改判定）', [esc(v.prevTagSizeBad)])));
  if (v.scriptTooBig) stop.push(dim(t('太大的脚本标签跳过 {0} 个', [esc(v.scriptTooBig)])));
  if (stop.length) cells.push(tCell(t('它为什么停在这里'), stop.join(' · ')));
  if (v.looksLike) cells.push(tCell(t('那一段看着像'), esc(v.looksLike)));
  for (const [k, label] of [['detail', t('它说的那句')], ['reach', t('端口那一头')]]) {
    if (v[k]) cells.push(tCell(label, dim(esc(v[k]))));
  }
  return { cells, dim };
}

// FLV_STOP 把容器层那四种「停」翻成四种不同的话 —— ★ 它们绝不都是「出错」：
// 读满预算与读到末尾是直播流的正常答案，只有断在标签里才是坏。
const FLV_STOP = {
  window: t('收满了要的那几秒（直播流本来就没有「读完」这一说，这是正常收口）'),
  byte: t('到了字节上限'),
  tag: t('标签数到了上限'),
  ended: t('它自己关到了正文末尾'),
};

function rtmpResult(r) {
  const v = r.values || {};
  const { cls, advice } = rtmpDisplay(r);
  const dim = (x) => `<span class="dim">${x}</span>`;
  // ★ 前缀是 flv:// 的那一支走另一张表、另一套格子：它的账是「容器里数到了什么」，
  //   不是「哪条命令答了什么」。混在一格里，FLV 的结果会长出一排「（没问到）」的
  //   握手 / connect / play —— 那不是信息，那是把问错的问题也印出来。
  if (v.protocol === 'flv' || isFLVVerdict(r.verdict)) {
    const { cells } = flvResult(r, v, dim);
    const note = r.note ? `<p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>` : '';
    return `<table>${cells.join('')}</table>${note}` + (advice ? adviceBox(cls, esc(advice)) : '');
  }
  const cells = [tCell(t('问的地址'), `<code>${esc(v.url || '')}</code>`
    + (v.app ? ` · ${dim(t('应用'))} ${esc(v.app)}` : '')
    + (v.stream ? ` · ${dim(t('流名'))} <code>${esc(v.stream)}</code>` : '')
    + (v.ignoredUserinfo ? `<br>${dim(t('★ 地址里写了 user:pass —— RTMP 没有 Basic 这一说，这一问没带上它'))}` : '')
    + (v.streamHasQuery ? `<br>${dim(t('★ 流名后面那段参数（已打码）是跟着 play 一起发出去的'))}` : ''))];
  cells.push(tCell(t('问到哪一步'), rtmpSteps(v, r.verdict)));
  const said = [];
  if (v.handshakeMs !== undefined) said.push(t('握手 {0} 毫秒', [esc(v.handshakeMs)]));
  if (v.server) said.push(t('它自报 {0}', [esc(v.server)]));
  if (v.connectReply) said.push(t('connect 回的是 {0}{1}', [esc(v.connectReply), v.connectCode ? ' · ' + esc(v.connectCode) : '']));
  if (v.playCode) said.push(t('play 回的是 {0}', [esc(v.playCode)]));
  if (v.stage) said.push(dim(t('停在「{0}」这一步', [esc(v.stage)])));
  if (v.reach) said.push(dim(v.reach === 'closed' ? t('端口明确拒绝（主机在，这个口没服务）') : t('没有任何回应')));
  if (v.looksLike) said.push(dim(t('那一段看着像 {0}', [esc(v.looksLike)])));
  if (v.firstBytes) said.push(dim(t('头几个字节 {0}', [esc(v.firstBytes)])));
  if (said.length) cells.push(tCell(t('它答的'), said.join(' · ')));
  if ((v.statusCodes || []).length) {
    cells.push(tCell(t('这一路上收到过的状态'), (v.statusCodes || []).map(esc).join(' · ')));
  }
  if (v.mediaBytes !== undefined) {
    cells.push(tCell(t('窗口里到的码流'), [
      t('{0} 字节', [(v.mediaBytes || 0).toLocaleString()]),
      t('音频 {0} · 视频 {1}', [(v.audioBytes || 0).toLocaleString(), (v.videoBytes || 0).toLocaleString()]),
      t('{0} 条消息', [v.messages ?? 0]),
      v.keyFrames ? t('{0} 个关键帧', [esc(v.keyFrames)]) : dim(t('一个关键帧都没数到')),
      t('等了 {0} / {1} 毫秒', [esc(v.observedMs ?? 0), esc(v.watchMs ?? 0)]),
    ].filter(Boolean).join(' · ')
      + (v.observedShort ? `<br>${dim(t('★ 没等满窗口（它提前断了），这个码率的分母比要的那几秒短'))}` : '')));
  }
  if (v.bitrateKbps) {
    cells.push(tCell(t('实际码率'), `${esc(v.bitrateKbps)} kbps · ${dim(esc(v.bitrateBasis || ''))}`));
  }
  const declared = [];
  if (v.declaredWidth) declared.push(`${esc(v.declaredWidth)}×${esc(v.declaredHeight ?? '?')}`);
  if (v.declaredFps) declared.push(t('{0} 帧/秒', [esc(v.declaredFps)]));
  if (v.declaredVideoCodec) declared.push(esc(v.declaredVideoCodec));
  if (v.declaredVideoKbps) declared.push(t('视频 {0} kbps', [esc(v.declaredVideoKbps)]));
  if (v.declaredAudioKbps) declared.push(t('音频 {0} kbps', [esc(v.declaredAudioKbps)]));
  if (declared.length) {
    cells.push(tCell(t('推流端自己声明的'), declared.join(' · ')
      + (v.bitrateKbps && v.declaredVideoKbps && Number(v.bitrateKbps) * 2 < Number(v.declaredVideoKbps)
        ? `<br>${dim(t('★ 实测不到声明的一半 —— 到了，但没按它说的速率过来'))}` : '')));
  }
  for (const [k, label] of [['connectDetail', t('它说的那句')], ['playDetail', t('它对这一路说的那句')],
    ['detail', t('原文那一错')]]) {
    if (v[k]) cells.push(tCell(label, dim(esc(v[k]))));
  }
  const note = r.note && r.verdict !== 'rtmp-ok'
    ? `<p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>` : '';
  return `<table>${cells.join('')}</table>${note}`
    + (advice ? adviceBox(cls, esc(advice)) : '')
    + t('<details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>')
    + `<pre>${esc(JSON.stringify(r.raw || r.values || {}, null, 2))}</pre></details>`;
}

// GB_CODE 覆盖两条问法的判定码：media.gb28181.probe（问它）与 media.gb28181.register（本机注册一趟）。
//
// ★ 「口是关的」「口开着没人答」「那个口不说 SIP」必须各占一档 —— 现场为这三句话
//   各跑过一整趟：换端口、查防火墙、找平台加白名单，下一步完全不一样。
//   合成一句「没回应」，那三天工就白跑。
const GB_CODE = {
  'gb28181-port-closed': [t('这个信令口是关的'), 'bad',
    t('对面主机在，但这个 UDP 口没人接（它回了不可达）。先核对地址与端口抄对没有，')
    + t('再看那台上 SIP 服务起没起来。★ 这一档和「开着没人答」不是一回事，别去查防火墙。')],
  'gb28181-silent': [t('口开着，一个字节都没回'), 'bad',
    t('发出去了（而且重发过），到点没回音。要么中间有东西吃掉它（防火墙、交换机 ACL、平台白名单），')
    + t('要么它压根不理这一句。★ 还有一种：它从**另一个端口**回话，这一问的套接字只收对端那一对地址，')
    + t('那种表现也是超时 —— 换个端口再问一次看看。')],
  'gb28181-not-sip': [t('那个口接了东西，却不说 SIP'), 'bad',
    t('口上有服务在答话，但那不是 SIP 报文（HTTP、TLS 都会这样）。★ 5061 常常挂的是 TLS 上的 SIP，')
    + t('这一问只按 UDP 问 —— 那个端口要换成对端的明文 SIP 口再问。')],
  'gb28181-sip-unreadable': [t('看着是 SIP，可这条报文读不成句'), 'bad',
    t('起始行对，后面断了。多半是中间那台（SIP 网关、ALG）改写了报文，或者它的固件发的不是标准 CRLF。')
    + t('★ 这一档别去查设备配置，先查中间有没有那台改包的东西。')],
  'gb28181-auth-required': [t('它要先看凭据才答'), 'warn',
    t('这个口认 SIP，而且它在按国标收设备。下一步是带上编号与口令走右边那颗「本机注册一趟」，')
    + t('不是去查网络。')],
  'gb28181-denied': [t('它不认这个编号，或不接这一句'), 'bad',
    t('回了 403/404/405/501 这一类。先核编号（20 位，错一格就是另一台设备），')
    + t('再看那台上有没有把本机授权进去。问通道表不成的话，改走注册那一条，让它自己来问。')],
  'gb28181-busy': [t('它在，可这一刻腾不出手'), 'warn',
    t('回了 480/486/500/503/504。它在，服务也在，是这一刻忙。★ 不要连着重试，')
    + t('先去那台机器上看它在忙什么（并发满、正在重启、内部出错）。')],
  'gb28181-alive': [t('它是一个 SIP / 国标信令口'), 'ok',
    t('OPTIONS 答了。★ 这只回答「它在、它说 SIP」，设备自述与通道表这次没问 —— ')
    + t('别拿这一条当「设备正常」。勾上上面的问法再问一次。')],
  'gb28181-responsive': [t('问到的它都答了'), 'ok',
    t('信令这一层是通的，而且它把内容答出来了。通道数、自述字段、在线状态都在下面的账里。')],
  'gb28181-query-silent': [t('OPTIONS 它答了，某一问它不答'), 'warn',
    t('★ 这一条最要紧的一句话：网络是通的（OPTIONS 回得来）。它不答这一问，多半是不认这个查询 —— ')
    + t('来路编号不对、或者这项能力没开。先核「平台侧编号」填的是它配的那个。')],
  'gb28181-empty-body': [t('它接了这句，却不给正文'), 'warn',
    t('回了 200，正文是空的：这句它接了但没答内容。要么是固件把这一类查询当形式应答，')
    + t('要么是它要求先注册才答。下一步走「本机注册一趟」。')],
  'gb28181-bad-body': [t('它答了，可那份正文读不成'), 'bad',
    t('正文不是能读下来的 MANSCDP。有的固件在这一句上发的是别的内容类型，那种要按它发的算，')
    + t('不能当没答。★ 中间有 ALG 改包也会是这个表现。')],
  'gb28181-catalog-empty': [t('它在线，可通道是空的'), 'warn',
    t('通道表答了、这一页数到 0 条 —— 现场那句「平台说设备在线、通道是空的」就死在这一格。')
    + t('先看是不是只问了第一页（用下面的分页参数再问一次），或这台把通道挂在别的编号下。')],
  'gb28181-cut-short': [t('这次的预算到点了，没问完'), 'warn',
    t('★ 这一档说的是我们自己：有一问是被这次的时间掐断的，不是它不答。')
    + t('把「一步超时」放宽、或少勾几样再问一次。别拿这一条去判断它有没有这项能力。')],
  'gb28181-registered': [t('注册上了'), 'ok',
    t('它给了 200，这条注册被收下。★ 「收下」不等于「它把这台当成能点播的设备」—— ')
    + t('要看它有没有回过头来问，那一段的账在下面。')],
  'gb28181-registered-accepted': [t('注册上了，它还会回过头来问'), 'ok',
    t('这是「那台平台真把这台当设备」最硬的证据：它主动问了通道表，或者发了点播。')
    + t('★ 我们不应答它（这台不做真设备，编不出也不该编一路通道），所以它那几问是没答的。')],
  'gb28181-registered-unauthenticated': [t('注册上了，可这一趟没要凭据'), 'warn',
    t('第一发 REGISTER 就直接 200。★ 这是一条安全事实：那道门没收口令，任何一台机器报个编号就能挂上去。')],
  'gb28181-challenge-missing': [t('它回 401，却没把挑战带上'), 'bad',
    t('要求认证却没给 WWW-Authenticate，本机算不出该签什么，只能干等。')
    + t('这是那一头的实现问题（或中间把这条头改掉了），不是口令错。')],
  'gb28181-credential-rejected': [t('带了口令，它还是回 401'), 'bad',
    t('口令不对，或者摘要用的 realm / 算法与那台配的不是一回事。★ 现场最常见的一种错：')
    + t('设备里填的认证域和平台 401 给的那个不一样 —— 看下面「用的域」那一栏两边各是什么。')],
};

// GB_ASK 是每一问的落点。★ 「被掐断」和「它不答」必须两个词，
// 前者是我们的预算问题，后者才是它的毛病。
const GB_ASK = {
  'ok': [t('答了'), 'ok'],
  'silent': [t('没答'), 'bad'],
  'status': [t('回了状态码'), 'warn'],
  'transport': [t('连收发都没成'), 'bad'],
  'empty-body': [t('接了不给正文'), 'warn'],
  'bad-body': [t('正文读不成'), 'bad'],
  'cut-short': [t('这次没等够'), 'warn'],
};

// 账里那一格写的是协议里的拼法（Catalog / DeviceInfo），不是参数里那三种小写名。
// ★ 两边都收：这里只挑中文，认不出来的原样露出来，不拿「未知」把一条真实的落点盖掉。
const GB_CMD_CN = {
  deviceInfo: t('设备自述'), deviceStatus: t('在线状态'), catalog: t('通道表'),
  DeviceInfo: t('设备自述'), DeviceStatus: t('在线状态'), Catalog: t('通道表'),
};

// gbCard 是这条流水线的最后一张，问的是**信令这一层**。
//
// ★ 它和上面四张的分工：ONVIF/RTSP/HLS/RTMP 问的是「这路流到没到」，这一张问的是
//   「这台设备在不在国标平台的名册上」。金宇建安那一路「设备接不上平台」的账，
//   只有这一张能拆开 —— 而且全程不解码、不放播放器、不发 INVITE（点播会真占一路码流）。
// ★ 两颗按钮一张卡：这一页到这儿已经是第五个问题，再拆一张就破了「一页不超过五张」。
//   两条问法用的本来就是同一批地址与编号，分开填两遍反而更容易填成互相不对的两套。
function gbCard() {
  const card = $(t('<div class=\"card\">\n    <h2>问一路国标（GB28181）信令 <span id=\"gb-top\"></span></h2>\n    <p class=\"hint\">拆「这台设备接不上国标平台」这句话。左边那颗<b>只读</b>：先问 OPTIONS 看这个口在不在行当里，\n      再按需要问设备自述 / 在线状态 / 通道表。<b>全程不解码、不放播放器，也不发点播</b>\n      （点播会真的占住一路码流，那是改动）。<br>\n      右边那颗是<b>会改东西的</b>：本机扮成一台设备往平台注册一趟，看它收不收、收完会不会回头来问 ——\n      ★ 填真设备的编号会<b>顶掉那条真注册</b>，那台相机会当场掉线，所以要你点头、并且记进改动账本。\n      问完立刻发注销（Expires:0）把这条收回来，注销成没成也照实记。口令只进那一次摘要计算，\n      不进结果、不进日志、不进账本、批准框那句话里也没有它。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 190px\"><label>对端地址（问它 = 那台设备；注册 = 那台平台）</label>\n        <input id=\"gb-host\" placeholder=\"192.168.1.64\"></div>\n      <div style=\"flex:0 0 110px\"><label>SIP 信令口</label><input id=\"gb-port\" placeholder=\"5060\"></div>\n      <div style=\"flex:1 1 210px\"><label>那台设备的 20 位编号</label>\n        <input id=\"gb-dev\" placeholder=\"34020000001110000001\"></div>\n      <div style=\"flex:1 1 210px\"><label>平台侧那一段 20 位编号</label>\n        <input id=\"gb-plat\" placeholder=\"34020000002000000001\"></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:10px\">\n      <div style=\"flex:1 1 auto;min-width:0\"><label>OPTIONS 通了接着问哪几样（一颗都不勾 = 只问它在不在）</label>\n        <div style=\"display:flex;gap:14px;flex-wrap:wrap;padding-top:4px\">\n          <label style=\"display:flex;gap:5px;align-items:center;font-size:13px\">\n            <input type=\"checkbox\" class=\"gb-ask\" value=\"deviceInfo\">设备自述</label>\n          <label style=\"display:flex;gap:5px;align-items:center;font-size:13px\">\n            <input type=\"checkbox\" class=\"gb-ask\" value=\"deviceStatus\">在线状态</label>\n          <label style=\"display:flex;gap:5px;align-items:center;font-size:13px\">\n            <input type=\"checkbox\" class=\"gb-ask\" value=\"catalog\">通道表</label>\n        </div></div>\n      <div style=\"flex:0 0 130px\"><label>一步超时 ms</label><input id=\"gb-t\" placeholder=\"3000\"></div>\n    </div>\n    <p class=\"hint\" style=\"margin-top:6px\">★ 「平台侧那一段编号」在两颗按钮上各有用处，都必填得看具体情况：\n      勾了上面任何一问就得填（设备按它配好的那个平台编号核对来路，没报上名字的表现是它一声不吭 ——\n      那不是网络不通）；注册那一趟不填就按设备编号前 10 位推所属域，用的哪一种结果里会写清。</p>\n    <details style=\"margin-top:8px\"><summary class=\"dim\">通道表分页、注册时长与口令、注册后听多久</summary>\n      <div class=\"row\" style=\"margin-top:8px\">\n        <div><label>通道表从第几条开始问</label><input id=\"gb-cs\" placeholder=\"留空 = 全量\"></div>\n        <div><label>这一页最多问几条</label><input id=\"gb-cc\" placeholder=\"留空 = 全量\"></div>\n        <div><label>注册时长秒（30-3600）</label><input id=\"gb-exp\" placeholder=\"60\"></div>\n        <div><label>注册成功后听多久（0 = 不听）</label><input id=\"gb-watch\" placeholder=\"3000\"></div>\n      </div>\n      <div class=\"row\" style=\"margin-top:8px\">\n        <div><label>注册口令（不会被记下来）</label>\n          <input id=\"gb-pass\" type=\"password\" autocomplete=\"new-password\"></div>\n        <div><label>认证域 realm（留空就照它 401 给的那个算）</label>\n          <input id=\"gb-realm\" autocomplete=\"off\"></div>\n      </div>\n      <p class=\"hint\" style=\"margin-top:6px\">★ 只问一页就按「它一共几路」下结论是把账混了 ——\n        设备自己声明的 SumNum 与这一页数到的条数在结果里分开给。\n        realm 那一栏留空才是对的：现场最常见的一种错就是设备配的 realm 与平台给的不是一个，\n        填了它才知道两边各是什么。</p>\n    </details>\n    <div style=\"display:flex;gap:10px;margin-top:12px\">\n      <button class=\"btn primary\" id=\"gb-ask-b\">问它（只读）</button>\n      <button class=\"btn danger\" id=\"gb-reg-b\">本机注册一趟（会改对面）</button>\n    </div>\n    <div id=\"gb-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#gb-out');
  const top = card.querySelector('#gb-top');
  const say = (html) => { top.innerHTML = ''; out.innerHTML = html; };
  const common = () => {
    const a = { host: card.querySelector('#gb-host').value.trim() };
    const port = Number(card.querySelector('#gb-port').value.trim());
    const dev = card.querySelector('#gb-dev').value.trim();
    const plat = card.querySelector('#gb-plat').value.trim();
    const t = Number(card.querySelector('#gb-t').value.trim());
    if (port) a.port = port;
    if (dev) a.deviceId = dev;
    if (plat) a.platformId = plat;
    if (t) a.timeoutMs = t;
    return a;
  };

  card.querySelector('#gb-ask-b').onclick = async () => {
    const args = common();
    if (!args.host) { say(t('<div class=\"empty\">先写给哪个地址：那台设备或平台的 IP。</div>')); return; }
    const asks = [...card.querySelectorAll('.gb-ask')].filter((x) => x.checked).map((x) => x.value);
    if (asks.length) args.ask = asks;
    const cs = Number(card.querySelector('#gb-cs').value.trim());
    const cc = Number(card.querySelector('#gb-cc').value.trim());
    if (cs) args.catalogStart = cs;
    if (cc) args.catalogCount = cc;
    say(t('<div class=\"empty\">正在问…（OPTIONS 加上勾的那几问，每问最多等几秒）</div>'));
    const r = await call('media.gb28181.probe', args);
    if (!r.ok) { say(t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message || r.error)])); return; }
    top.innerHTML = gbPill(r.verdict);
    out.innerHTML = gbProbeResult(r);
  };

  card.querySelector('#gb-reg-b').onclick = async () => {
    const args = common();
    if (!args.host || !args.deviceId) {
      say(t('<div class=\"empty\">这一趟要两个值：平台的地址，和拿哪个编号去报名字。</div>'));
      return;
    }
    const pass = card.querySelector('#gb-pass').value;
    if (pass) args.password = pass;
    const realm = card.querySelector('#gb-realm').value.trim();
    if (realm) args.realm = realm;
    const exp = Number(card.querySelector('#gb-exp').value.trim());
    if (exp) args.expires = exp;
    const w = card.querySelector('#gb-watch').value.trim();
    if (w !== '') args.watchMs = Number(w);
    say(t('<div class=\"empty\">等你点批准…（取消的话一个包都不发）<br>')
      + t('批准之后：REGISTER → 401 挑战 → 带摘要重发 → 收 200，再听几秒看它回不回头问，最后发注销。</div>'));
    const r = await call('media.gb28181.register', args);
    card.querySelector('#gb-pass').value = '';   // 口令不留在输入框里
    if (!r.ok) { say(t('<div class=\"empty\">没走：{0}</div>', [esc(r.message || r.error)])); return; }
    top.innerHTML = gbPill(r.verdict);
    out.innerHTML = gbRegisterResult(r);
  };
  return card;
}

function gbPill(code) {
  const raw = GB_CODE[code];
  if (!raw) return `<span class="pill">${esc(code || t('没给判定'))}</span>`;
  return `<span class="pill ${raw[1]}">${esc(raw[0])}</span>`;
}

function gbWords(v, key) {
  const list = v[key];
  return Array.isArray(list) && list.length ? list.map(esc).join(t('、')) : '';
}

function gbProbeResult(r) {
  const v = r.values || {};
  const dim = (x) => `<span class="dim">${x}</span>`;
  const cells = [tCell(t('问的哪一台'), `<code>${esc(v.peer || '')}</code> ${dim('UDP')}`
    + (v.device ? ` · ${dim(t('那台编号'))} <code>${esc(v.device)}</code>` : '')
    + (v.domain ? ` · ${dim(t('平台侧编号'))} <code>${esc(v.domain)}</code>` : '')
    + `<br>${dim(t('本机这一头'))} <code>${esc(v.local || '')}</code>`)];
  const said = [];
  if (v.optionsMs !== undefined) said.push(t('OPTIONS 回了 {0} 毫秒', [esc(v.optionsMs)]));
  if (v.optionsSent) said.push(t('发出去 {0} 发', [esc(v.optionsSent)]));
  if (v.optionsInterims) said.push(t('中途收到 {0} 条临时应答（100/180 那一类）', [esc(v.optionsInterims)]));
  if (v.status) said.push(t('它回的状态 {0}', [esc(v.status)]));
  const allow = gbWords(v, 'allow');
  if (allow) said.push(t('它报的能力 {0}', [allow]));
  if (v.userAgent) said.push(t('它自报 {0}', [esc(v.userAgent)]));
  if (v.server) said.push(`Server ${esc(v.server)}`);
  if (v.bodyBytes !== undefined) said.push(t('正文 {0} 字节', [esc(v.bodyBytes)]));
  if (said.length) cells.push(tCell(t('它答的'), said.join(' · ')));
  const queries = Array.isArray(v.queries) ? v.queries : [];
  if (queries.length) {
    cells.push(tCell(t('每一问的账'), queries.map((q) => {
      const st = GB_ASK[q.outcome] || [esc(q.outcome || ''), ''];
      const bits = [`<span class="pill ${st[1]}">${st[0]}</span> ${esc(GB_CMD_CN[q.cmdType] || q.cmdType)}`];
      if (q.sent) bits.push(t('发 {0} 次', [esc(q.sent)]));
      if (q.ms !== undefined) bits.push(t('{0} 毫秒', [esc(q.ms)]));
      if (q.status) bits.push(t('回了 {0}', [esc(q.status)]));
      if (q.items !== undefined) bits.push(t('数到 {0} 条', [esc(q.items)]));
      if (q.sumNum !== undefined) bits.push(t('它自己声明 {0} 条', [esc(q.sumNum)]));
      if (q.answersThisQuery === false) bits.push(dim(t('★ 正文里的 CmdType/SN 与这一问对不上')));
      if (q.nonUTF8) bits.push(dim(t('★ 正文里有非 UTF-8 字节')));
      if ((q.channelIds || []).length) {
        bits.push(dim(t('编号：{0}', [q.channelIds.slice(0, 6).map(esc).join(t('、'))])
          + (q.channelIds.length > 6 ? t(' 等 {0} 个', [q.channelIds.length]) : '')));
      }
      if (q.channelsWithoutId) bits.push(dim(t('★ 有 {0} 条条目没带编号', [esc(q.channelsWithoutId)])));
      if ((q.repeatedKeys || []).length) bits.push(dim(t('同名键出现多次：{0}', [q.repeatedKeys.map(esc).join(t('、'))])));
      if ((q.oddShape || []).length) bits.push(dim(t('形状上也可能只是字段包装的那一层：{0}', [q.oddShape.map(esc).join(t('、'))])));
      const fields = q.fields && Object.keys(q.fields).length
        ? `<br>${dim(Object.entries(q.fields).map(([k, x]) => `${esc(k)}=${esc(x)}`).join(' · '))}` : '';
      return `<div style="margin-bottom:6px">${bits.join(' · ')}${fields}`
        + (q.detail ? `<br>${dim(esc(q.detail))}` : '') + '</div>';
    }).join('')));
  }
  for (const k of ['queryOutcome', 'kind']) {
    if (v[k]) cells.push(tCell(dim(t('落点')), esc(String(v[k]))));
  }
  if (v.detail) cells.push(tCell(t('原文那一错'), dim(esc(v.detail))));
  return gbTail(r, cells);
}

function gbRegisterResult(r) {
  const v = r.values || {};
  const dim = (x) => `<span class="dim">${x}</span>`;
  const cells = [tCell(t('往哪台注册'), `<code>${esc(v.peer || '')}</code> ${dim('UDP')}`
    + ` · ${dim(t('报名字用'))} <code>${esc(v.device || '')}</code>`
    + `<br>${dim(t('本机这一头'))} <code>${esc(v.local || '')}</code>`
    + `<br>${dim(t('请求行里的域'))} <code>${esc(v.domain || '')}</code>`
    + (v.domainSource ? ` ${dim(t('（从 {0} 来的）', [esc(v.domainSource)]))}` : ''))];
  const auth = [];
  if (v.hasPassword) auth.push(t('带了口令（内容不会被记下来）'));
  else auth.push(t('没填口令，按空口令走的一趟'));
  if (v.authenticated === true) auth.push(t('它先回 401 出了挑战，本机按 RFC 2617 算了摘要'));
  if (v.authenticated === false) auth.push(t('第一发就直接 200：它没要凭据'));
  if (v.realm) auth.push(t('它给的域 <code>{0}</code>', [esc(v.realm)]));
  if (v.realmDiffers) auth.push(t('本机按填的那个算的：<code>{0}</code> ★ 两边不是一个', [esc(v.realmGiven)]));
  if (v.qop) auth.push(`qop ${esc(v.qop)}`);
  if (v.firstStatus) auth.push(t('第一发回的是 {0}', [esc(v.firstStatus)]));
  cells.push(tCell(t('认证这一路'), auth.join(' · ')));
  const acc = [];
  if (v.status) acc.push(t('最后回的是 {0}', [esc(v.status)]));
  if (v.expiresAccepted !== undefined) {
    acc.push(v.expiresAccepted === Number(v.expires)
      ? t('注册时长 {0} 秒（和要的一样）', [esc(v.expiresAccepted)])
      : t('<b>它只给了 {0} 秒</b>（要的是 {1}）', [esc(v.expiresAccepted), esc(v.expires)])
      + `<br>${dim(t('★ 「每隔一分钟就掉线、平台上一会儿有一会儿没有」这一类毛病，根子常常在这一格'))}`);
  }
  if (v.toTag) acc.push(dim(t('200 带了 tag（这一趟对话算立住了）')));
  if (v.gotTrying) acc.push(dim(t('中途收到 100 Trying')));
  if (v.serverAgent) acc.push(dim(t('它自报 {0}', [esc(v.serverAgent)])));
  cells.push(tCell(t('它收不收'), acc.length ? acc.join(' · ') : dim(t('没走到这一格'))));
  // ★ 后面两栏只在真注册上之后才成立：没注册上还写「它一句都没回头来问」「注销没成、
  //   这条注册会留在平台上」，等于凭空报出一条压根没发生的改动 —— 现场人会拿着这句话
  //   去平台上找一个不存在的在线设备。
  if (v.registered) {
    const back = [];
    if (v.watchMs) back.push(t('注册后又听了 {0} 毫秒', [esc(v.watchMs)]));
    else back.push(dim(t('这一趟没听它回话（监听窗口关着）')));
    const reqs = gbWords(v, 'platformRequests');
    const cmds = gbWords(v, 'platformCmdTypes');
    if (reqs) back.push(t('它回过头来问了：{0}{1}', [reqs, cmds ? t('（问的是 {0}）', [cmds]) : '']));
    else back.push(dim(t('它一句都没回头来问 —— 注册收下不等于它把这台当成能点播的设备')));
    if (v.platformInvite) back.push(t('<b>★ 它肯发点播 —— 这才是真把这台当能取流的设备</b>'));
    if (v.inviteSDP) back.push(`<br>${dim(t('点播正文：') + esc(v.inviteSDP))}`
      + `<br>${dim(t('★ 那份正文照实留着，本机没去接那一路码流'))}`);
    cells.push(tCell(t('它回头问了吗'), back.join(' · ')));
    const cut = [];
    cut.push(v.deregistered ? t('注销发了，它答了 2xx —— 那台平台上不会留着这台')
      : t('<b>注销那一发没成</b>：这条注册会留在那台平台上，最长到它应允的时长才自己过期'));
    if (v.deregisterTries) cut.push(t('一共发了 {0} 发', [esc(v.deregisterTries)]));
    if (v.deregisterDetail) cut.push(dim(esc(v.deregisterDetail)));
    cells.push(tCell(t('收回来没有'), cut.join(' · ')));
  } else {
    cells.push(tCell(t('它回头问了吗'), dim(t('没走到这一格 —— 注册没成，那台平台上不会多出这台'))));
    cells.push(tCell(t('收回来没有'), dim(t('没有要收回的东西：这一趟没注册上'))));
  }
  if (v.detail) cells.push(tCell(t('原文那一错'), dim(esc(v.detail))));
  return gbTail(r, cells);
}

// gbTail 把后端那句判定带上。★ 界面不算账、也不改写：note 是后端从同一份账里长出来的，
// 这里只负责把它排好；没译成中文的码原样露出来，不编一句人话顶上。
function gbTail(r, cells) {
  const raw = GB_CODE[r.verdict] || ['', '', ''];
  const note = r.note ? `<p class="dim" style="margin:10px 0 0">${esc(r.note)}</p>` : '';
  return `<table>${cells.join('')}</table>${note}`
    + (raw[2] ? adviceBox(raw[1], esc(raw[2])) : '')
    + t('<details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>')
    + `<pre>${esc(JSON.stringify(r.raw || r.values || {}, null, 2))}</pre></details>`;
}

function subnetScanCard() {
  const card = $(t('<div class=\"card\">\n    <h2>扫一个网段 <span id=\"nv\"></span></h2>\n    <p class=\"hint\">问一遍<b>某个 IPv4 网段上现在有谁</b>。网段留空就扫本机自己所在的各段。\n      ★ 只扫 IPv4：IPv6 一个 /64 有 1.8×10<sup>19</sup> 个地址，逐个问是问不完的，\n      v6 那一套在「设备是谁」那一页的「听谁在应答」里。</p>\n    <div class=\"row\">\n      <div><label>网段（CIDR，留空 = 本机所在网段）</label><input id=\"nc\" placeholder=\"192.168.1.0/24\"></div>\n      <div style=\"flex:0 0 150px\"><label>只扫某块网卡</label><input id=\"ni\" placeholder=\"en0 / 以太网\"></div>\n      <div style=\"flex:0 0 110px\"><label>最多问几个</label><input id=\"nm\" placeholder=\"1024\"></div>\n      <div style=\"flex:0 0 110px\"><label>每轮等待 ms</label><input id=\"nw\" placeholder=\"1500\"></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:10px\">\n      <div><label>TCP 兜底端口（扫路由过来的网段时填）</label>\n        <input id=\"np\" placeholder=\"留空；或 22,80,554 —— ARP 用不上那段全靠它\"></div>\n    </div>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"ngo\">开始扫</button></div>\n    <div id=\"nout\" style=\"margin-top:14px\"></div>\n  </div>'));
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
    out.innerHTML = t('<div class=\"empty\">正在扫…（发一轮再等回执，慢设备或者隔着无线就把等待时间调大）</div>');
    const r = await call('net.subnet.scan', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">扫不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice0] = SUBNET_CODE[r.verdict] || [r.verdict, '', ''];
    const advice = r.verdict === 'no-hosts' && v.onLink === false
      ? t('这个网段<b>不是</b>本机所在的链路（是路由过来的）：那里 ARP 永远只有网关一条，')
        + t('扫不到人是正常的。带上「TCP 兜底端口」再扫一次才有意义。')
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
    out.innerHTML = t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n        <div><label>扫了哪些网段</label><div><b><code>{0}</code></b></div></div>\n        <div><label>问过</label><div>{1} 个地址</div></div>\n        <div><label>在线</label><div><b>{2}</b></div></div>\n        <div><label>没信号</label><div>{3}</div></div>\n        <div><label>本机链路</label><div>{4}</div></div>\n      </div>\n      {5}\n      {6}\n      <div style=\"background:{7};border:1px solid {8};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {9}</div>\n      {10}\n      {11}\n      <p class=\"dim\" style=\"margin:10px 0 0\">{12}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{13}</pre></details>', [esc((v.subnets || []).join(' ')), esc(v.asked), esc(v.alive), esc(v.noSignal), v.onLink ? t('是（ARP 用得上）') : t('否（ARP 用不上）'), v.skippedSelf ? t('<p class=\"dim\" style=\"margin:0 0 10px\">这几个地址是本机自己的，没有列进清单：\n        <code>{0}</code>（问自己必然有回执，列出来只会多一行莫名其妙的设备）</p>', [esc((v.skippedSelf || []).join(' '))]) : '', v.skippedIface && v.skippedIface.length ? t('<p class=\"dim\" style=\"margin:0 0 10px\">跳过了：{0}</p>', [esc(v.skippedIface.join(t('；')))]) : '', bg, line, advice, rows ? t('<table style=\"margin-top:14px\"><tr><th>地址</th><th>MAC</th><th>网卡</th><th>凭什么判定在线</th><th>等了</th></tr>{0}</table>', [rows]) : '', v.alive ? t('<p class=\"dim\" style=\"margin-top:10px\">「没信号」的那些<b>不是</b>「不在线」的证据 ——\n        它们只是没在这轮里吭声。要确认某一台，去「ping 与端口」那一页单独 ping 它。</p>') : '', esc(r.note), esc(JSON.stringify(v, null, 2))]);
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
    ['ssdp', 'SSDP / UPnP', t('媒体服务器、智能设备、多数网络摄像头')],
    ['mdns', 'mDNS / DNS-SD', t('NAS、打印机、Mac、AirPlay 与投屏')],
    ['ws-discovery', 'WS-Discovery', t('监控设备（ONVIF）、Windows 的网络发现')],
    ['netbios', 'NetBIOS', t('老 Windows 与打印机。★ 只有这一路给得出 MAC，它要点名问')],
  ];
  const card = $(t('<div class=\"card\">\n    <h2>问一遍：这些地址是哪台设备 <span id=\"xv\"></span></h2>\n    <p class=\"hint\">上面「扫一个网段」答的是<b>有没有人</b>，这一张答<b>它是哪一台</b>：\n      把设备自己喊出来的话摊开 —— 名字、类型、管理地址、MAC。\n      ★ 只放设备自己说过的话，没说的留空并写明「这台没说」，一律不按 MAC 前缀猜厂商。</p>\n    <div class=\"row\">\n      <div style=\"flex:0 0 190px\"><label>只问哪块网卡</label><input id=\"xi\" placeholder=\"留空 = 插着线的都问\"></div>\n      <div style=\"flex:0 0 110px\"><label>每轮等几秒</label><input id=\"xs\" placeholder=\"3\"></div>\n      <div style=\"flex:0 0 90px\"><label>问几轮</label><input id=\"xr\" placeholder=\"2\"></div>\n      <div><label>点名问哪些地址（留空 = 对着网段喊）</label>\n        <input id=\"xa\" placeholder=\"10.0.12.77，或 10.0.12.0/24；空格或逗号分开\"></div>\n      <div style=\"flex:0 0 100px;align-self:flex-end\"><button class=\"btn primary\" id=\"xgo\">问一遍</button></div>\n    </div>\n    <details style=\"margin-top:8px\"><summary class=\"dim\">高级：只问某几种自报 / 额外问哪些服务 / 顺带取描述文件</summary>\n      <p class=\"dim\" style=\"margin:10px 0 4px\">只勾怀疑的那几种，问得更快、也少打扰别人：</p>\n      <div id=\"xproto\" style=\"display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:4px 12px\"></div>\n      <div class=\"row\" style=\"margin-top:10px\">\n        <div><label>额外问哪些 DNS-SD 服务类型</label>\n          <input id=\"xsvc\" placeholder=\"留空即可；如 _raop._tcp.local、_googlecast._tcp.local\"></div>\n      </div>\n      <label style=\"display:flex;gap:6px;align-items:center;margin-top:8px\">\n        <input type=\"checkbox\" id=\"xdesc\" style=\"width:auto\">\n        顺着 SSDP 给的管理地址再取一份描述文件（能多问出型号、序列号）</label>\n      <p class=\"hint\" style=\"margin:6px 0 0\">★ 这一条是往<b>设备上</b>发一个 HTTP GET：只读，\n        但会在那台的访问日志里多一条 —— 有些老设备（门禁、编码器）日志一满就重启，所以默认不取。\n        最多取 12 份，只认 http/https。</p>\n    </details>\n    <div id=\"xout\" style=\"margin-top:14px\"></div>\n  </div>'));
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

    out.innerHTML = t('<div class=\"empty\">正在问…（先把查询发出去，再在窗口里等各方答话。')
      + t('走无线的那块网卡常常慢一拍）</div>');
    const r = await call('net.device.identify', args);
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">问不了：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    const v = r.values;
    const [text, cls, advice] = DEVICE_CODE[r.verdict] || [r.verdict, '', ''];
    const stopPill = v.stopped
      ? t('<span class=\"pill warn\">中途停了：只问了 {0}/{1} 轮</span>', [esc(v.roundsDone), esc(v.rounds)]) : '';
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span> ${stopPill}`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';

    // 四路各自那一本账：一路没应不代表设备不在，只代表它不说这一种话。
    const tally = (v.protocols || []).map((p) => {
      const askedCell = p.asked
        ? `<span class="dim">${p.protocol === 'netbios'
          ? t('点名问过 ') + esc(p.targets) + t(' 个地址') : t('在 ') + esc(p.targets) + t(' 块网卡上问过')}</span>`
        : t('<span class=\"pill\">这一路没问</span>');
      return t('<tr><td>{0}</td><td>{1}</td>\n        <td{2}>{3} 条</td>\n        <td>{4} 个地址</td></tr>', [esc(p.protocol), askedCell, p.asked && !p.reports ? ' class="dim"' : '', esc(p.reports), esc(p.hosts)]);
    }).join('');
    const rows = (v.devices || []).map((d) => {
      const inst = (d.instances || []).filter((s) => s && s !== d.name).slice(0, 3);
      const types = (d.types || []).filter((s) => s && s !== d.kind).slice(0, 3);
      return `<tr${d.identified ? '' : ' style="opacity:.72"'}>
        <td><code>${esc(d.addr)}</code>${d.port ? `<span class="dim">:${esc(d.port)}</span>` : ''}</td>
        <td>${d.name ? `<b>${esc(d.name)}</b>` : t('<span class=\"dim\">没说名字</span>')}
          ${inst.length ? t('<div class=\"dim\" style=\"font-size:12px\">还报了 {0}', [esc(inst.join(t('、')))])
            + `${(d.instances || []).length > 3 ? t(' 等') : ''}</div>` : ''}</td>
        <td>${d.kind ? esc(d.kind) : t('<span class=\"dim\">没说类型</span>')}
          ${types.length ? `<div class="dim" style="font-size:12px">${esc(types.join(t('、')))}</div>` : ''}
          ${(d.detail || []).length ? `<div class="dim" style="font-size:12px">${esc(d.detail.join(t('；')))}</div>` : ''}</td>
        <td>${d.url ? `<code class="dim" style="font-size:12px">${esc(d.url)}</code>`
          : t('<span class=\"dim\">没给</span>')}</td>
        <td><code class="dim">${esc(d.mac || '—')}</code></td>
        <td class="dim">${esc((d.protocols || []).join(t('、')))}</td>
        <td class="dim">${esc(d.iface || '—')}</td></tr>`;
    }).join('');

    // 「一次都没问出去」的那几个判定（没网卡、组播发不出去）没有这几栏可填。
    // ★ 摆一排空统计比不摆更坏：人会读成「问到 0 个」，而实际是「没问」。
    const ran = v.count !== undefined;
    out.innerHTML = t('\n      {0}\n      <div style=\"background:{1};border:1px solid {2};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {3}{4}</div>\n      {5}\n      {6}\n      {7}\n      {8}\n      <p class=\"dim\" style=\"margin:10px 0 0;white-space:pre-line\">{9}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{10}</pre></details>', [ran ? t('<div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n        <div><label>应了的地址</label><div><b>{0}</b> 个</div></div>\n        <div><label>其中报了身份的</label><div><b>{1}</b> 个</div></div>\n        <div><label>收到自报</label><div>{2} 条</div></div>\n        <div><label>问过的网卡</label><div>{3}</div></div>\n        <div><label>问了几轮</label><div>{4}/{5}</div></div>\n        {6}\n      </div>', [esc(v.count), esc(v.identified || 0), esc(v.reports), esc((v.interfaces || []).join(t('、'))) || '—', esc(v.roundsDone), esc(v.rounds), v.targets ? t('<div><label>点名</label><div>{0} 个地址</div></div>', [esc((v.targets || []).length)]) : '']) : '', bg, line, advice, v.reason ? t('<div class=\"dim\" style=\"margin-top:6px\">本机报出来的原因：\n          <code>{0}</code> <span class=\"dim\">（这一句是本机自己说的，不是设备上看到的）</span></div>', [esc(v.reason)]) : '', v.count ? t('<table style=\"margin-top:14px\"><tr><th>地址</th><th>它是谁</th><th>它是什么</th>\n        <th>管理地址（它自己给的）</th><th>MAC</th><th>谁说的</th><th>哪块网卡</th></tr>{0}</table>\n        <p class=\"dim\" style=\"margin-top:10px\">管理地址这一栏是<b>设备自己写的</b>，所以不做成链接：\n          抄下来自己核对一眼再打开。「谁说的」那几路里，NetBIOS 是唯一给得出 MAC 的，\n          空着就是那台不理 NetBIOS（不是它没 MAC）。</p>', [rows]) : '', tally ? t('<h2 style=\"margin-top:16px\">四路各自问到什么</h2>\n      <table><tr><th>自报口径</th><th>问的情况</th><th>收到几条</th><th>几个地址答的</th></tr>{0}</table>', [tally]) : '', v.notAsked ? t('<p class=\"hint\" style=\"margin:10px 0 0\">另有 {0} 个地址\n        <b>一个包都没发出去</b>：<code>{1}</code>\n        <span class=\"dim\">—— 问都没问过，不是问了没人答。</span></p>', [esc((v.notAsked || []).length), esc([].concat(v.notAsked).join(' '))]) : '', v.skipped ? t('<p class=\"dim\" style=\"margin:10px 0 0\">这些没去问：\n        {0}</p>', [[].concat(v.skipped).map((s) => esc(s)).join('<br>')]) : '', esc(r.note), esc(JSON.stringify(v, null, 2))]);
  };
  return card;
}

function discoverCard() {
  const card = $(t('<div class=\"card\">\n    <h2>听谁在应答（找没配网的设备）<span id=\"dv\"></span></h2>\n    <p class=\"hint\">往 IPv6 组播喊一声，谁应答就记下来 —— 现场最常用的一招是\n      <b>在一堆设备里把刚拆封、还没配 IPv4 地址的那台挑出来</b>。★ 它只能听见应 v6 的设备，\n      纯 IPv4 的老设备看不见（那种用上面「扫一个网段」）。</p>\n    <div class=\"row\">\n      <div style=\"flex:0 0 200px\"><label>只在哪块网卡上听</label><input id=\"di\" placeholder=\"留空 = 所有网卡\"></div>\n      <div style=\"flex:0 0 130px\"><label>等待 ms</label><input id=\"dw\" placeholder=\"1200\"></div>\n      <div style=\"flex:1 1 auto;align-self:flex-end\"><button class=\"btn primary\" id=\"dgo\">听一次</button></div>\n    </div>\n    <div id=\"dout\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#dout');
  const top = card.querySelector('#dv');
  card.querySelector('#dgo').onclick = async () => {
    top.innerHTML = '';
    const args = {};
    const i = card.querySelector('#di').value.trim();
    const w = Number(card.querySelector('#dw').value);
    if (i) args.iface = i;
    if (w > 0) args.waitMs = w;
    out.innerHTML = t('<div class=\"empty\">正在听…（要等组播应答跑完这一轮）</div>');
    const r = await call('net.discover', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">听不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const [text, cls, advice] = DISCOVER_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(text)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const rows = (v.devices || []).map((d) => {
      const un = !d.hasIPv4;
      return `<tr${un ? ' style="background:var(--gold-bg)"' : ''}>
        <td><code class="dim">${esc(d.linkLocal || '')}</code></td>
        <td>${un ? t('<b>没有 IPv4</b>') : `<code>${esc(d.ipv4)}</code>`}</td>
        <td><code class="dim">${esc(d.mac || '—')}</code></td>
        <td class="dim">${esc(d.iface || '')}</td>
        <td class="dim">${d.rttMs ? esc(Math.round(d.rttMs)) + 'ms' : ''}</td>
        <td class="dim">${d.self ? t('本机') : ''}</td></tr>`;
    }).join('');
    out.innerHTML = t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n        <div><label>应答</label><div><b>{0}</b> 台</div></div>\n        <div><label>没配好地址</label><div><b>{1}</b> 台</div></div>\n        <div><label>在哪些网卡上听的</label><div>{2}</div></div>\n      </div>\n      {3}\n      <div style=\"background:{4};border:1px solid {5};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {6}</div>\n      {7}\n      {8}\n      <p class=\"dim\" style=\"margin:10px 0 0\">{9}</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{10}</pre></details>', [esc(v.count), esc(v.unconfigured || 0), esc((v.interfaces || []).join(t('、'))) || '—', v.probedV4Networks && v.probedV4Networks.length ? t('<p class=\"dim\" style=\"margin:0 0 10px\">\n        为了让「没有 IPv4」这个结论站得住，先把这些网段主动问过一遍：\n        <code>{0}</code>（ARP 只是缓存，光靠它会把活设备读成没配网）</p>', [esc(v.probedV4Networks.join(' '))]) : '', bg, line, esc(advice), rows ? t('<table style=\"margin-top:14px\"><tr><th>IPv6 链路本地地址</th><th>IPv4</th><th>MAC</th>\n        <th>网卡</th><th>等了</th><th></th></tr>{0}</table>', [rows]) : '', v.skipped && v.skipped.length ? t('<p class=\"dim\" style=\"margin-top:10px\">跳过：{0}</p>', [esc(v.skipped.join(t('；')))]) : '', esc(r.note), esc(JSON.stringify(v, null, 2))]);
  };
  return card;
}

// ★ 状态这一栏是这张表唯一说人话的地方，而三个平台打的是三套字母：
//   macOS/Linux 的 ndp 用 R/S/T/I/U，Linux 的 ip neigh 用 REACHABLE/STALE/FAILED，
//   Windows 直接打「动态/静态」。认不全的原样带出来就行 —— 那比猜错好。
const NBR_STATE = {
  R: [t('可达'), 'ok'],
  S: [t('缓存里的旧记录'), 'warn'],
  T: [t('延迟确认'), ''],
  I: [t('没解析出来'), 'warn'],
  U: [t('不可达'), 'bad'],
  G: [t('刚被引用过'), ''],
  REACHABLE: [t('可达'), 'ok'],
  STALE: [t('缓存里的旧记录'), 'warn'],
  DELAY: [t('延迟确认'), ''],
  PROBE: [t('正在问'), ''],
  INCOMPLETE: [t('没解析出来'), 'warn'],
  FAILED: [t('没解析出来'), 'warn'],
  '动态': [t('刚问过'), 'ok'],
  '静态': [t('手工写死的'), 'warn'],
};
// ★ 这一张不放顶层判定：它读的是本机缓存，没有「结论」可言 ——
//   有意义的是每一条的状态，人自己会判断哪几条算数。
function neighborsCard() {
  const card = $(t('<div class=\"card\">\n    <h2>本机邻居表</h2>\n    <p class=\"hint\">一个包都不发，只读本机现在的邻居表：IPv4 是 ARP 表，IPv6 是 NDP 表，\n      两张表一并给出。用它快速回答「这个 MAC 是哪个 IP」「刚才那个地址是谁」。\n      ★ 这是<b>缓存</b>：表里没有它，<b>不等于</b>它不在 —— 要问「有谁在场」请用上面那张卡。</p>\n    <div class=\"row\">\n      <div style=\"flex:0 0 160px\"><label>看哪一族</label><input id=\"qf\" value=\"both\" placeholder=\"both / ipv4 / ipv6\"></div>\n      <div style=\"flex:0 0 200px\"><label>只看某块网卡</label><input id=\"qi\" placeholder=\"留空 = 全部\"></div>\n      <div style=\"flex:1 1 auto;align-self:flex-end\"><button class=\"btn\" id=\"qgo\">读一次</button></div>\n    </div>\n    <div id=\"qout\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#qout');
  card.querySelector('#qgo').onclick = async () => {
    out.innerHTML = t('<div class=\"empty\">读取中…</div>');
    const args = { family: card.querySelector('#qf').value.trim() || 'both' };
    const i = card.querySelector('#qi').value.trim();
    if (i) args.iface = i;
    const r = await call('net.neighbors', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">读不了：{0}</div>', [esc(r.message)]); return; }
    const v = r.values;
    const ns = (v.neighbors || []).map((n) => {
      const [w, pc] = NBR_STATE[n.state] || [n.state || '—', ''];
      // 没有 MAC 就是没解析出来 —— 不管状态那一栏是什么字母，都不许给个绿点
      const label = n.mac ? w : t('没解析出来');
      const cls = n.mac ? (pc || '') : 'warn';
      return `<tr><td><code>${esc(n.addr)}</code></td>
        <td><code class="dim">${esc(n.mac || '—')}</code></td>
        <td class="dim">${esc(n.iface || '')}</td>
        <td class="dim">${esc(n.family || '')}</td>
        <td><span class="pill ${cls}">${esc(label)}</span></td></tr>`;
    }).join('');
    out.innerHTML = t('\n      <div class=\"row\" style=\"align-items:flex-end;gap:18px;margin-bottom:12px\">\n        <div><label>多少条</label><div><b>{0}</b></div></div>\n        <div><label>其中没解析出 MAC 的</label><div>{1}</div></div>\n      </div>\n      {2}\n      <p class=\"dim\" style=\"margin:10px 0 0\">「没解析出来」的那几条是内核之前问过、对方没应的占位记录 ——\n        表里有这一行不等于设备在场。★ 这一张卡一个包都不发，它只是把本机现在记着什么念出来。</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{3}</pre></details>', [esc(v.count), esc((v.neighbors || []).filter((n) => !n.mac).length), ns ? t('<table><tr><th>地址</th><th>MAC</th><th>网卡</th><th>族</th><th>状态</th></tr>{0}</table>', [ns])
        : t('<div class=\"empty\">表是空的 —— 这台机器最近没跟谁通过话。这不是「网段里没人」的证据。</div>'), esc(JSON.stringify(v, null, 2))]);
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
  if (!r.ok) { root.appendChild($(t('<div class=\"card\">远程功能不可用：{0}</div>', [esc(r.message)]))); return; }
  const devices = r.values.devices || [];
  root.appendChild(notifyCard(r.values.notifyTarget !== false));
  root.appendChild(deviceTable(devices));
  root.appendChild(addDeviceCard());
  root.appendChild(auditCard());
}

async function renderRemoteWork(root) {
  const r = await call('remote.device.list');
  if (!r.ok) { root.appendChild($(t('<div class=\"card\">远程功能不可用：{0}</div>', [esc(r.message)]))); return; }
  const devices = r.values.devices || [];
  const sel = devices.find((d) => d.id === remoteSel) || null;
  root.appendChild(devicePickCard(devices));
  // 有活儿才现身：没挑设备时下面那两张卡除了占地方没有别的用处。
  if (sel) root.appendChild(remoteOps(sel));
  root.appendChild(playbookCard(devices, sel));
}

function devicePickCard(devices) {
  const card = $(t('<div class=\"card\">\n    <h2>这一页要对哪台干活</h2>\n    <p class=\"hint\">登记、删除、看审计在「远程设备与审计」那页。这里只挑一台，下面每一项都会先弹框确认再动。</p>\n    <div class=\"row\" style=\"align-items:flex-end\">\n      <div style=\"min-width:280px\"><label>设备</label>\n        <select id=\"pick\">{0}</select></div>\n      <button class=\"btn primary\" id=\"go\"{1}>就这台</button>\n      <button class=\"btn\" id=\"clr\"{2}>取消选择</button>\n    </div>\n  </div>', [devices.length
          ? devices.map((d) => `<option value="${esc(d.id)}" ${d.id === remoteSel ? 'selected' : ''}>${esc(d.name || d.id)} · ${esc(OS_LABEL[d.os] || t('系统未知'))}</option>`).join('')
          : t('<option value=\"\">（还没有登记的设备）</option>'), devices.length ? '' : ' disabled', remoteSel ? '' : ' disabled']));
  card.querySelector('#go').onclick = () => { remoteSel = card.querySelector('#pick').value; show(); };
  card.querySelector('#clr').onclick = () => { remoteSel = null; show(); };
  return card;
}

// 剧本的状态码 → 界面中文。后端只给码（和判定与账同源的那套规矩一致）。
const PLAYBOOK_STEP = {
  ran: [t('问到'), 'ok'],
  failed: [t('没问到答案'), 'bad'],
  timeout: [t('没跑完'), 'bad'],
  'skipped-platform': [t('这台问不出'), 'warn'],
  aborted: [t('没问到（机器已经不答话）'), 'warn'],
};
const PLAYBOOK_VERDICT = {
  'playbook-ok': [t('该问的都问到了'), 'ok'],
  'playbook-step-failed': [t('有几条没问到答案'), 'bad'],
  'playbook-platform-skipped': [t('这一本在这台机器上一条都没问到'), 'warn'],
  'playbook-unreachable': [t('问到一半机器不答话了'), 'bad'],
  'playbook-empty': [t('这本是空的'), 'warn'],
};

function playbookCard(devices, sel) {
  const card = $(t('<div class=\"card\">\n    <h2>体检剧本</h2>\n    <p class=\"hint\">把「连上去挨个敲那十几条」录成一本能看、能改、能发给同事的剧本。\n      跑之前先看清它要敲什么、有几条会改那台机器的东西 —— 批准框上也会照原样念一遍。</p>\n    <div id=\"body\"><div class=\"empty\">读取中…</div></div>\n  </div>'));
  const body = card.querySelector('#body');
  // ★ 存完 / 删完的那句话要活得过重绘：不然点下去只看见列表闪了一下，
  //   到底存没存上得靠人去猜。换一本时清掉（那句话说的是上一本）。
  let flash = '';
  // ★ 刚存的那本也要活得过重绘：存完跳回列表第一本，等于没告诉他存到哪了。
  let keepBook = '';

  const load = async () => {
    const r = await call('remote.playbook.list', sel ? { device: sel.id } : {});
    if (!r.ok) { body.innerHTML = t('<div class=\"empty\">列不出剧本：{0}</div>', [esc(r.message)]); return; }
    draw(r.values.playbooks || [], r.values);
  };

  const draw = (books, vals) => {
    const known = sel && sel.os && sel.os !== 'unknown';
    body.innerHTML = t('\n      {0}\n      <div class=\"row\" style=\"align-items:flex-end\">\n        <div style=\"min-width:300px\"><label>挑一本</label>\n          <select id=\"book\">{1}</select></div>\n        <div style=\"max-width:120px\"><label>每条等多久</label>\n          <select id=\"wait\"><option value=\"0\">按剧本标的</option><option value=\"30\">30 秒</option><option value=\"60\">60 秒 —— 磁盘慢的机器</option></select></div>\n        <button class=\"btn primary\" id=\"run\"{2}>跑这一本</button>\n      </div>\n      <p class=\"dim\" style=\"margin:8px 0 0\" id=\"applies\"></p>\n      <details style=\"margin-top:6px\"><summary class=\"dim\">这一本要问哪几问、哪几条会改东西</summary>\n        <div id=\"preview\" style=\"margin-top:8px\"></div></details>\n      {3}\n      <div class=\"out\" id=\"result\" style=\"display:none;margin-top:12px\"></div>\n      <details style=\"margin-top:12px\"><summary class=\"dim\">改这一本 / 另存一本 / 导入同事发来的</summary>\n        <div id=\"editor\" style=\"margin-top:8px\"></div></details>', [flash ? `<p class="hint" id="flash" style="color:var(--gold)">${esc(flash)}</p>` : '', books.map((b) => t('<option value=\"{0}\"{1}>{2} —— {3} 条，其中 {4} 条会改东西{5}</option>', [esc(b.id), b.id === keepBook ? ' selected' : '', esc(b.name), esc(b.stepCount), esc(b.writeSteps), b.builtIn ? t('（内置）') : ''])).join(''), sel && known ? '' : ' disabled', sel && !known ? t('<p class=\"hint\" style=\"color:var(--gold)\">这台机器的系统还没探过 —— 先去「远程设备与审计」那页点一次「探测」。不知道系统就把分系统的条判成「问不出」，那是猜的。</p>') : '']);

    const bookOf = () => books.find((b) => b.id === body.querySelector('#book').value) || books[0];
    const drawBook = () => {
      const b = bookOf();
      if (!b) return;
      const pv = body.querySelector('#preview');
      pv.innerHTML = t('{0}\n        <table><tr><th>问什么</th><th>敲什么</th><th>哪种系统</th><th></th></tr>\n        {1}</table>\n        <p class=\"dim\" style=\"margin:8px 0 0\">跑完的每一条都会回到审计日志里（命令和字节数，输出不进审计 —— 里面可能有口令）。</p>', [b.note ? `<p class="hint">${esc(b.note)}</p>` : '', b.steps.map((s) => `<tr>
          <td>${esc(s.name)}<br><span class="dim">${esc(s.why || '')}</span></td>
          <td><code class="dim">${esc(s.run)}</code></td>
          <td class="dim">${(s.os || []).map((o) => OS_LABEL[o] || o).join(' / ') || t('哪都一样')}</td>
          <td>${s.write ? t('<span class=\"pill bad\">会改东西</span>') : t('<span class=\"pill\">只看</span>')}</td></tr>`).join('')]);
      const a = body.querySelector('#applies');
      if (!a) return;
      if (!sel) { a.textContent = t('还没挑设备 —— 挑一台才能跑。'); return; }
      if (!known) { a.textContent = ''; return; }
      a.textContent = t('在 {0}（{1}）上，这本有 {2}/{3} 条问得出去。', [sel.name || sel.id, OS_LABEL[sel.os] || sel.os, b.appliesOnDevice, b.stepCount]);
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
      ed.innerHTML = t('\n        <p class=\"hint\">这里改的就是那本剧本的原文。<b>改内置那本只能另存成新的一本</b> ——\n        内置的那本是「照着官方那本跑」的基准，覆盖了就没人知道你和别人跑的不是同一套。</p>\n        <p class=\"hint\">同事发来的那本：把整段 JSON 贴进下面这个框，点「存成新的一本」就进来了。\n        不合式的贴法会原样把哪儿不合式说回来，不会存半本进去。</p>\n        <textarea id=\"txt\" rows=\"14\" style=\"width:100%;font-family:ui-monospace,Menlo,monospace\">{0}</textarea>\n        <div style=\"display:flex;gap:8px;margin-top:8px;flex-wrap:wrap\">\n          <button class=\"btn primary\" id=\"saveAs\">存成新的一本</button>\n          <button class=\"btn\" id=\"saveOver\"{1}>保存修改这一本</button>\n          <button class=\"btn\" id=\"copy\">复制这段（发给同事）</button>\n          <button class=\"btn\" id=\"copyOut\">复制最近一次结果</button>\n          <button class=\"btn danger\" id=\"del\"{2}>删掉这一本</button>\n        </div>\n        <div class=\"out\" id=\"esave\" style=\"display:none;margin-top:8px\"></div>', [esc(json), b.builtIn ? t(' disabled title=\"内置那本不许覆盖\"') : '', b.builtIn ? t(' disabled title=\"内置那本删不掉\"') : '']);
      let lastResult = '';
      ed.querySelector('#copy').onclick = async (e) => {
        const t = ed.querySelector('#txt').value;
        try { await navigator.clipboard.writeText(t); e.target.textContent = t('已复制，发过去就行'); }
        catch { e.target.textContent = t('复制不了，全选框里那段自己拷'); }
      };
      ed.querySelector('#copyOut').onclick = async (e) => {
        const t = lastResult || body.querySelector('#result').innerText;
        try { await navigator.clipboard.writeText(t); e.target.textContent = t('已复制'); }
        catch { e.target.textContent = t('复制不了'); }
      };
      const save = (replace) => {
        const say = (s) => { const o = ed.querySelector('#esave'); o.style.display = 'block'; o.textContent = s; };
        let book;
        try { book = JSON.parse(ed.querySelector('#txt').value); }
        catch (err) { say(t('这段不是合法 JSON：') + err.message); return; }
        say(replace ? t('保存中…（等待批准）') : t('存入中…（等待批准）'));
        call('remote.playbook.save', { playbook: book, replace }).then((r) => {
          if (!r.ok) { say(t('存不下：') + r.message); return; }
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
          t('删掉剧本「{0}」？', [cur.name]),
          [t('只删本机配置目录里那一个文件，<b>设备上跑过的痕迹和审计日志都不动</b>。'),
           t('内置的那些本删不掉，这里也不会去碰它们。'),
           t('想留着的话：先点「复制这段（发给同事）」把 JSON 收好，再回来删。')],
          t('确认删掉'));
        if (!ok) return;
        const r = await call('remote.playbook.delete', { playbook: cur.id });
        const say = (s) => { const o = ed.querySelector('#esave'); o.style.display = 'block'; o.textContent = s; };
        if (!r.ok) { say(t('删不掉：') + r.message); return; }
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
      o.textContent = t('正在 {0} 上跑「{1}」…（{2} 条会改东西，批准框上会一条条念给你看）', [sel.id, b.name, b.writeSteps]);
      const args = { device: sel.id, playbook: b.id };
      if (wait) args.timeoutSec = wait;
      const r = await call('remote.playbook.run', args);
      if (!r.ok) { o.textContent = t('跑不了：') + r.message; return; }
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
        ${s.write ? t('<span class=\"pill bad\">改了那台机器的东西</span>') : ''}
        ${s.exitCode ? t('<span class=\"pill warn\">退出码 {0}</span>', [esc(s.exitCode)]) : ''}
        <span class="dim">${esc(s.elapsedMs ? (s.elapsedMs / 1000).toFixed(1) + t(' 秒') : '')}</span></div>
      ${s.why ? t('<p class=\"dim\" style=\"margin:4px 0\">为什么问它：{0}</p>', [esc(s.why)]) : ''}
      <p style="margin:4px 0"><code>${esc(s.command)}</code></p>
      ${hits.map((h) => t('<div style=\"border-left:3px solid var(--gold);padding:2px 0 2px 8px;margin:6px 0\">\n          <b>命中 {0} 行</b>\n          {1}\n          <p style=\"margin:4px 0 0\">{2}</p></div>', [esc(h.lines), (h.sample || []).map((x) => `<pre class="hit" style="margin:2px 0;white-space:pre-wrap">${esc(x)}</pre>`).join(''), esc(h.say)])).join('')}
      ${misses.length ? t('<p class=\"dim\" style=\"margin:6px 0 0\">这几样在这段输出里没提到：{0}\n        —— <b>没提到不等于没有</b>，它只说明这本剧本要找的那句话没出现。</p>', [misses.map((h) => t('「{0}」', [esc(h.say)])).join(t('、'))]) : ''}
      ${s.output ? `<pre class="out" style="white-space:pre-wrap;margin:6px 0 0">${esc(s.output)}</pre>` : ''}
      ${s.error ? t('<p style=\"margin:6px 0 0\">没问到的原因：{0}</p>', [esc(s.error)]) : ''}
      ${s.note ? `<p class="dim" style="margin:6px 0 0">${esc(s.note)}</p>` : ''}
    </div>`;
  }).join('');

  return t('<div><span class=\"pill {0}\">{1}</span> <b>{2}</b></div>\n    <p class=\"dim\" style=\"margin:8px 0\">共 {3} 条：问到 {4}、没问到答案 {5}、\n      没跑完 {6}、这台问不出 {7}、没问到（机器断了）{8}{9}</p>\n    {10}\n    {11}\n    <p style=\"margin:10px 0 0\"><b>下一步：</b>{12}\n      <span class=\"dim\">（这台 {13} · 剧本 {14} · 用了 {15} 秒）</span></p>', [cls, esc(label), esc(v.verdictNote || r.note || ''), esc(c.total), esc(c.ran), esc(c.failed), esc(c.timedOut), esc(c.skippedPlatform), esc(c.aborted), c.hitLines ? t('；关键词命中 {0} 处', [esc(c.hitLines)]) : '', red ? t('<p class=\"hint\" style=\"color:var(--gold)\">结果里抹掉了凭据：{0}。键名留着、值换成掩码 —— 那是「有口令、没给你看」，不是「没配口令」。</p>', [esc(v.redactedHow)])
          : t('<p class=\"dim\" style=\"margin:8px 0\">凭据核过一遍：{0}。</p>', [esc(v.redactedHow)]), steps, esc(v.nextStep || ''), esc(v.device), esc(v.playbook), esc(v.seconds ? v.seconds.toFixed(1) : '—')]);
}

function notifyCard(on) {
  const card = $(t('<div class=\"card\">\n    <h2>对方可见 <span class=\"pill {0}\">{1}</span></h2>\n    <p class=\"hint\">开着时，远程连接 / 控制 / 连桌面会先在目标机屏幕上提示一声（带「来自 NetKit·谁」的标识）。\n      审计日志不受这个开关影响，怎么设都照记。</p>\n    <button class=\"btn {2}\" id=\"tog\">{3}</button>\n  </div>', [on ? 'ok' : 'bad', on ? t('开（默认）') : t('静默'), on ? 'danger' : 'primary', on ? t('关闭（进入静默）') : t('打开')]));
  card.querySelector('#tog').onclick = async () => {
    if (on) {
      // ★ 关静默 = 要被记住的选择：当场弹一次，写明责任归属，人点了才发
      const ok = await confirmModal(
        t('关闭「对方可见」，进入静默模式？'),
        [t('之后远程连接 / 控制这台设备时，<b>目标机屏幕前的人将不会收到任何提示</b>。'),
         t('请确认场景是无人值守（服务器、机柜一体机、数字标牌）。'),
         t('<b>由购买方负责在其组织内合规使用并履行告知义务。</b>'),
         t('审计日志不受影响，照记；这次选择本身也会进审计。')],
        t('我已了解，确认关闭'));
      if (!ok) return;
    }
    const r = await call('remote.config.set', { notifyTarget: !on });
    if (!r.ok) { alert(t('改不了：') + r.message); return; }
    show();
  };
  return card;
}

/** 自己画的确认框：责任那段话必须完整摆出来，不用 confirm()（放不下也不体面）。 */
function confirmModal(title, htmlLines, okText) {
  return new Promise((resolve) => {
    const ov = $(t('<div class=\"modal-ov\"><div class=\"modal\">\n      <h2>{0}</h2>\n      {1}\n      <div style=\"display:flex;gap:10px;margin-top:14px;justify-content:flex-end\">\n        <button class=\"btn\" id=\"no\">取消</button>\n        <button class=\"btn danger\" id=\"yes\">{2}</button>\n      </div></div></div>', [esc(title), htmlLines.map((l) => `<p class="hint">${l}</p>`).join(''), esc(okText)]));
    document.body.appendChild(ov);
    const done = (v) => { ov.remove(); resolve(v); };
    ov.querySelector('#no').onclick = () => done(false);
    ov.querySelector('#yes').onclick = () => done(true);
    ov.onclick = (e) => { if (e.target === ov) done(false); };
  });
}

const OS_LABEL = { windows: 'Windows', linux: 'Linux', darwin: 'macOS' };

function deviceTable(devices) {
  const card = $(t('<div class=\"card\">\n    <h2>登记的设备 <span class=\"pill\">{0}</span></h2>\n    <p class=\"hint\">凭据只落盘在本机 0600 的文件里，不出现在这里、也不进日志。点「操作」展开命令行 / 传文件 / 弹消息 / 开桌面。</p>\n    <div id=\"box\"></div>\n  </div>', [devices.length]));
  const box = card.querySelector('#box');
  if (!devices.length) {
    box.innerHTML = t('<div class=\"empty\">还没有登记设备。在下面填地址和账号加一台，SSH 通了就能诊断、传文件、开桌面。</div>');
    return card;
  }
  const row = (d) => {
    const host = d.identity && d.identity.hostname ? t(' <span class=\"dim\">（{0}）</span>', [esc(d.identity.hostname)]) : '';
    const seen = d.lastSeen ? new Date(d.lastSeen).toLocaleString() : t('还没连过');
    return t('<tr>\n      <td><b>{0}</b>{1}{2}</td>\n      <td>{3}</td>\n      <td class=\"dim\">{4}{5}</td>\n      <td class=\"dim\">{6}</td>\n      <td style=\"white-space:nowrap\">\n        <button class=\"btn primary\" data-act=\"sel\" data-id=\"{7}\">{8}</button>\n        <button class=\"btn\" data-act=\"probe\" data-id=\"{9}\">探测</button>\n        <button class=\"btn danger\" data-act=\"rm\" data-id=\"{10}\">删除</button>\n      </td></tr>', [esc(d.name || d.id), d.name ? `<br><code class="dim">${esc(d.id)}</code>` : '', host, esc(OS_LABEL[d.os] || t('未知')), esc(d.auth || ''), d.hostKeyKnown ? '' : t('<br><span class=\"dim\">主机密钥未记录</span>'), esc(seen), esc(d.id), d.id === remoteSel ? t('收起') : t('操作'), esc(d.id), esc(d.id)]);
  };
  box.innerHTML = t('<table><tr><th>设备</th><th>系统</th><th>认证</th><th>最近探测</th><th></th></tr>\n    {0}</table>', [devices.map(row).join('')]);
  box.querySelectorAll('button[data-act]').forEach((b) => {
    b.onclick = async () => {
      const id = b.dataset.id;
      if (b.dataset.act === 'sel') { remoteSel = remoteSel === id ? null : id; show(); return; }
      if (b.dataset.act === 'rm') {
        if (!confirm(t('把 {0} 从登记簿删掉（连同存的凭据）？', [id]))) return;
        await call('remote.device.remove', { device: id });
        if (remoteSel === id) remoteSel = null;
        show(); return;
      }
      b.disabled = true; b.textContent = t('连接中…');
      const r = await call('remote.device.probe', { device: id });
      alert(r.ok ? r.note : t('探测失败：') + r.message);
      show();
    };
  });
  return card;
}

function addDeviceCard() {
  const card = $(t('<div class=\"card\">\n    <h2>登记一台设备</h2>\n    <p class=\"hint\">走 SSH。能用私钥就别用口令；不确定账号名就先猜一个，连不上时探测会把线索报回来。</p>\n    <div class=\"row\">\n      <div><label>地址 *</label><input id=\"host\" placeholder=\"192.168.3.82 或 fe80::1%en0\"></div>\n      <div style=\"max-width:110px\"><label>端口</label><input id=\"port\" placeholder=\"22\"></div>\n      <div><label>账号 *</label><input id=\"user\" placeholder=\"administrator / root / pc\"></div>\n      <div><label>备注名</label><input id=\"name\" placeholder=\"收银台那台\"></div>\n    </div>\n    <div class=\"row\">\n      <div><label>口令</label><input id=\"pw\" type=\"password\" placeholder=\"和私钥二选一\"></div>\n      <div><label>私钥路径（本机）</label><input id=\"key\" placeholder=\"/Users/me/.ssh/id_ed25519\"></div>\n    </div>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"add\">登记并探测</button></div>\n    <div class=\"out\" id=\"o\" style=\"display:none;margin-top:10px\"></div>\n  </div>'));
  const g = (s) => card.querySelector(s).value.trim();
  card.querySelector('#add').onclick = async () => {
    const o = card.querySelector('#o');
    const say = (s) => { o.style.display = 'block'; o.textContent = s; };
    if (!g('#host') || !g('#user')) { say(t('地址和账号是必填的')); return; }
    if (!g('#pw') && !g('#key')) { say(t('口令和私钥至少给一个 —— 没凭据连不上')); return; }
    const args = { host: g('#host'), user: g('#user'), name: g('#name') || undefined,
      password: g('#pw') || undefined, keyPath: g('#key') || undefined };
    if (g('#port')) args.port = Number(g('#port'));
    const r = await call('remote.device.add', args);
    if (!r.ok) { say(t('登记失败：') + r.message); return; }
    say(t('已登记，正在连接探测…'));
    const id = r.values.id;
    const p = await call('remote.device.probe', { device: id });
    say(p.ok ? p.note : t('登记成功，但探测失败：') + p.message);
    remoteSel = id;
    setTimeout(show, 1200);
  };
  return card;
}

function remoteOps(d) {
  const card = $(t('<div class=\"card\">\n    <h2>操作 <code>{0}</code> <span class=\"dim\">{1}</span></h2>\n    <p class=\"hint\">下面每一项改系统的操作都会先弹框确认，且全程记入审计。</p>\n\n    <label>执行命令（远程诊断主力：看资源、抓日志、重启服务）</label>\n    <div style=\"display:flex;gap:8px\">\n      <input id=\"cmd\" placeholder=\"{2}\">\n      <button class=\"btn primary\" id=\"bcmd\">执行</button>\n      <button class=\"btn\" id=\"bsess\">看会话</button>\n    </div>\n    <div class=\"out\" id=\"ocmd\" style=\"display:none;margin-top:8px\"></div>\n\n    <label>给屏幕发消息（自动带发送方标识）</label>\n    <div style=\"display:flex;gap:8px\">\n      <input id=\"msg\" placeholder=\"如：10 分钟后重启收银系统，请保存工作\">\n      <button class=\"btn\" id=\"bmsg\">发送</button>\n    </div>\n    <div class=\"out\" id=\"omsg\" style=\"display:none;margin-top:8px\"></div>\n\n    <label>传文件（断点续传 + 整包 SHA256 复核）</label>\n    <div class=\"row\">\n      <div><label>本机路径</label><input id=\"flocal\" placeholder=\"/Users/me/升级包.bin\"></div>\n      <div><label>设备路径</label><input id=\"fremote\" placeholder=\"{3}\"></div>\n    </div>\n    <div style=\"display:flex;gap:8px;margin-top:8px\">\n      <button class=\"btn\" id=\"bpush\">推到设备 ↑</button>\n      <button class=\"btn\" id=\"bpull\">拉回本机 ↓</button>\n    </div>\n    <div class=\"out\" id=\"ofile\" style=\"display:none;margin-top:8px\"></div>\n\n    <label>远程桌面</label>\n    <div style=\"display:flex;gap:8px\">\n      <button class=\"btn\" id=\"bdq\">查状态</button>\n      <button class=\"btn primary\" id=\"bdo\">打通并连接{4}</button>\n    </div>\n    <div class=\"out\" id=\"odesk\" style=\"display:none;margin-top:8px\"></div>\n    {5}\n  </div>', [esc(d.id), esc(OS_LABEL[d.os] || t('系统未知，先探测')), d.os === 'windows' ? 'ipconfig /all' : 'systemctl status nginx', d.os === 'windows' ? t('C:\\\\tmp\\\\升级包.bin') : t('/tmp/升级包.bin'), d.os === 'windows' ? t('（RDP 没开会替它开）') : '', d.hostKeyKnown ? t('\n    <label>主机密钥</label>\n    <div style=\"display:flex;gap:8px;align-items:center\">\n      <button class=\"btn danger\" id=\"bkey\">忘掉这台的主机密钥</button>\n      <span class=\"dim\">连不上说「密钥对不上」时才用：确认那台机器重装过系统/换过机器。密钥变了也可能是有人冒充它。</span>\n    </div>\n    <div class=\"out\" id=\"okey\" style=\"display:none;margin-top:8px\"></div>') : '']));
  const out = (id, s) => { const o = card.querySelector(id); o.style.display = 'block'; o.textContent = s; };
  const busy = async (btn, fn) => {
    const b = card.querySelector(btn); const t = b.textContent;
    b.disabled = true; b.textContent = t('进行中…');
    try { await fn(); } finally { b.disabled = false; b.textContent = t; }
  };

  card.querySelector('#bcmd').onclick = () => busy('#bcmd', async () => {
    const cmd = card.querySelector('#cmd').value.trim();
    if (!cmd) return;
    out('#ocmd', t('执行中…（等待批准）'));
    const r = await call('remote.exec', { device: d.id, command: cmd });
    if (!r.ok) { out('#ocmd', t('执行失败：') + r.message); return; }
    const v = r.values;
    out('#ocmd', t('退出码 {0} · {1} 秒\n── 输出 ──\n{2}{3}', [v.exitCode, v.seconds.toFixed(1), v.stdout || t('(空)'), v.stderr ? t('\n── 错误 ──\n') + v.stderr : '']));
  });

  card.querySelector('#bsess').onclick = () => busy('#bsess', async () => {
    const r = await call('remote.sessions', { device: d.id });
    if (!r.ok) { out('#ocmd', t('查会话失败：') + r.message); return; }
    const ss = r.values.sessions || [];
    out('#ocmd', ss.length ? ss.map((s) =>
      `#${s.id}  ${s.state}${s.active ? t('（有人）') : ''}${s.current ? t(' ← SSH 落在这') : ''}  ${s.name}  ${s.user || ''}`).join('\n')
      : t('这台机器上没有登录会话'));
  });

  card.querySelector('#bmsg').onclick = () => busy('#bmsg', async () => {
    const text = card.querySelector('#msg').value.trim();
    if (!text) return;
    const r = await call('remote.msg.send', { device: d.id, text });
    const LABEL = { sent: t('✓ 已发到对方屏幕'), 'sent-unconfirmed': t('△ 发了，但不保证对方看得见'), 'no-session': t('✗ 屏幕前没人'), 'send-failed': t('✗ 发不出去') };
    out('#omsg', r.ok ? `${LABEL[r.verdict] || r.verdict}\n${r.note}` : t('失败：') + r.message);
  });

  const transfer = (tool, args) => busy(tool === 'remote.file.push' ? '#bpush' : '#bpull', async () => {
    out('#ofile', t('传输中…（等待批准；大文件要一会儿，断了再点一次会续传）'));
    const r = await call(tool, args);
    out('#ofile', r.ok ? r.note : t('失败：') + r.message);
  });
  card.querySelector('#bpush').onclick = () => {
    const l = card.querySelector('#flocal').value.trim(), rm = card.querySelector('#fremote').value.trim();
    if (!l || !rm) { out('#ofile', t('两个路径都要填')); return; }
    transfer('remote.file.push', { device: d.id, local: l, remote: rm });
  };
  card.querySelector('#bpull').onclick = () => {
    const l = card.querySelector('#flocal').value.trim(), rm = card.querySelector('#fremote').value.trim();
    if (!l || !rm) { out('#ofile', t('两个路径都要填')); return; }
    transfer('remote.file.pull', { device: d.id, local: l, remote: rm });
  };

  card.querySelector('#bdq').onclick = () => busy('#bdq', async () => {
    const r = await call('remote.desktop.open', { device: d.id });
    out('#odesk', r.ok ? t('{0}\n判定：{1}', [r.note, r.verdict]) : t('失败：') + r.message);
  });
  card.querySelector('#bdo').onclick = () => busy('#bdo', async () => {
    out('#odesk', t('打通中…（等待批准；Windows 目标 RDP 没开时会改对端注册表和防火墙）'));
    const r = await call('remote.desktop.open', { device: d.id, enable: true });
    out('#odesk', r.ok ? t('{0}\n判定：{1}', [r.note, r.verdict]) : t('失败：') + r.message);
  });
  const keyBtn = card.querySelector('#bkey');
  if (keyBtn) keyBtn.onclick = async () => {
    if (!confirm(t('忘掉 {0} 的主机密钥？\n\n只在确认那台机器重装过系统/换过机器时做。下次连接会重新记录一把新密钥；如果其实没人换过机器，这一步等于把「有人在冒充它」这个信号抹掉了。', [d.id]))) return;
    const r = await call('remote.device.forget-hostkey', { device: d.id });
    out('#okey', r.ok ? r.note : t('没清掉：') + r.message);
  };
  return card;
}

function auditCard() {
  const card = $(t('<div class=\"card\">\n    <h2>审计日志</h2>\n    <p class=\"hint\">谁、何时、对哪台、做了什么、结果如何。静默模式只关屏幕提示，不关这里的留痕。</p>\n    <button class=\"btn\" id=\"load\">取最近 50 条</button>\n    <div id=\"box\" style=\"margin-top:10px\"></div>\n  </div>'));
  card.querySelector('#load').onclick = async () => {
    const box = card.querySelector('#box');
    const r = await call('remote.audit.tail', { n: 50 });
    if (!r.ok) { box.innerHTML = `<div class="empty">${esc(r.message)}</div>`; return; }
    const es = (r.values.entries || []).slice().reverse();
    if (!es.length) { box.innerHTML = t('<div class=\"empty\">还没有记录</div>'); return; }
    box.innerHTML = t('<table><tr><th>时间</th><th>谁</th><th>动作</th><th>对哪台</th><th>细节</th><th>结果</th></tr>\n      {0}</table>', [es.map((e) => `<tr>
        <td class="dim" style="white-space:nowrap">${esc(new Date(e.at).toLocaleString())}</td>
        <td class="dim">${esc(e.actor || '')}</td>
        <td><code>${esc(e.action || '')}</code></td>
        <td>${esc(e.target || '')}</td>
        <td class="dim">${esc(e.detail || '')}</td>
        <td class="${String(e.result).startsWith('failed') || e.result === 'send-failed' ? 'bad' : 'dim'}">${esc(e.result || '')}</td>
      </tr>`).join('')]);
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
  'single-address': [t('只是一个地址'), '', (v) => v.prefixAssum
    ? t('掩码没填上，所以按「一个地址」算 —— 没替你猜一个 /24。要算一段，把掩码补上再算一次。')
    : t('填的就是 /{0}：一个地址自成一个段。要算一段，把斜杠后面的数字改小（如 /24）。', [v.prefix])],
  'v4-network': [t('填的是网段地址'), 'ok', (v) => v.pointToPoint
    ? t('这是 /31 互联口：这一段的两个地址都能配给设备，没有「减掉网络地址和广播地址」这一步。')
    : t('这个可以直接登记。★ 网络地址本身不能分给设备用（它是「这一段」的名字）。')],
  'v4-host-address': [t('填的是主机地址'), 'warn', t('段算得出来（见下），但登记时别把这个地址抄成网段地址。')],
  'v4-broadcast-address': [t('填的是广播地址'), 'bad', t('它不能配在任何设备上 —— 大概率末段该写 0。')],
  'v6-prefix': [t('IPv6 段'), '', t('v6 没有广播地址、也没有「总数减二」，按下面「地址总数」那一栏读。')],
  'networks-overlap': [t('两段重叠'), 'bad',
    t('这是「有时候连得上有时候连不上」的根因：两条路由都能到一个地址，走哪条看内核当时怎么选。得改掩码或改地址池。')],
  'families-differ': [t('两族各自编址'), '',
    t('这个问法本身不成立 —— v4 段和 v6 段谈不上撞。要说「这台机器两族是不是都通」，去「域名与时间」那一页做双栈体检。')],
};

function subnetCalcCard() {
  const card = $(t('<div class=\"card\">\n    <h2>子网计算 <span id=\"sc-top\"></span></h2>\n    <p class=\"hint\">填什么都认：192.168.1.0/24、192.168.1.0/255.255.255.0（从设备页抄下来的写法）、\n      只写地址（按一个地址算，★ 不替你猜 /24）。\n      掩码 1 不连续（比如 255.0.255.0）会直接报错 —— 那种掩码不成段，硬算出来的答案是假的。\n      纯算术，不发任何包，所以它答不了「这段里有没有人」，那要用网段扫描。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 260px\"><label>要算的段或地址</label>\n        <input id=\"sc-cidr\" placeholder=\"192.168.1.100/255.255.255.0\"></div>\n      <div style=\"flex:1 1 260px\"><label>对照段（可留空，填了就问撞不撞）</label>\n        <input id=\"sc-peer\" placeholder=\"192.168.1.128/25\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn primary\" id=\"sc-go\">算</button></div>\n    </div>\n    <div id=\"sc-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#sc-out');
  const top = card.querySelector('#sc-top');
  const run = async () => {
    const args = { cidr: card.querySelector('#sc-cidr').value.trim() };
    const peer = card.querySelector('#sc-peer').value.trim();
    if (peer) args.peer = peer;
    if (!args.cidr) { out.innerHTML = t('<div class=\"empty\">先填要算的段或地址。</div>'); return; }
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">计算中…</div>');
    const r = await call('net.subnet.calc', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">算不了：{0}</div>', [esc(r.message || r.error)]); return; }
    const v = r.values;
    const [title, cls, advice] = SC_CODE[r.verdict] || [r.verdict || t('没给判定'), '', ''];
    const say = typeof advice === 'function' ? advice(v) : advice;
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    // ★ 只列后端真给了的字段：v6 没有掩码/通配码/广播，硬排上去会出现「广播：undefined」
    const items = [
      [t('规整网段'), v.canonical], [t('这个段是'), v.network],
      [t('掩码'), v.mask], [t('通配码'), v.wildcard],
      [t('地址总数'), v.size], [t('可用主机数'), v.usable],
      [t('首个可用'), v.firstUsable], [t('末个可用'), v.lastUsable], [t('广播地址'), v.broadcast],
      [t('反向解析区'), v.reverseZone],
    ].filter((x) => x[1] !== undefined && x[1] !== '');
    const n6 = v.v6Notes || {};
    if (n6.kind) items.push([t('地址性质'), ({
      ula: t('站内自建（ULA）—— 不该出现在公网'), 'link-local': t('链路本地 —— 出不了这条链路'),
      global: t('公网可路由'), multicast: t('组播地址 —— 不是用来配的'), loopback: t('本机回环'),
    }[n6.kind] || n6.kind)]);
    if (n6.sla64Count) items.push([t('可切出的 /64'), n6.sla64Count + t(' 个（v6 通常一条链路一个 /64）')]);
    if (v.pointToPoint) items.push([t('点对点段'), t('两个地址都能用（/31 互联口，没有网络/广播地址）')]);
    if (v.peer) items.push([t('对照段'), v.peer]);
    const rel = [];
    if (v.overlaps === true) {
      rel.push([t('怎么撞的'), ({
        'identical': t('两段完全相同'), 'peer-inside': t('填的这段把对照段整个包住'),
        'peer-contains': t('对照段把填的这段整个包住'),
      }[v.contains] || v.contains)]);
      if (v.overlapSize) rel.push([t('重叠地址数'), v.overlapSize]);
    }
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      <table style=\"margin-top:14px\"><tr><th></th><th></th></tr>\n        {3}\n        {4}</table>\n      {5}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{6}</pre></details>', [bg, line, esc(say), items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><code>${esc(x)}</code></td></tr>`).join(''), rel.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><b>${esc(x)}</b></td></tr>`).join(''), v.prefixAssum ? t('<p class=\"hint\">★ 输入的掩码是空的，这一栏按「一个地址」算 —— 没有替你猜一个 /24。</p>') : '', esc(JSON.stringify(v, null, 2))]);
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
  'mac-unset': [t('没读到 MAC'), 'bad',
    t('六个字节全零 —— 这不是「厂商库里缺这一条」，是这块网卡根本没把地址交出来')
    + t('（MAC 没烧进去、驱动没读上来、或那是个没配地址的虚拟接口）。去查网卡，别换库、别换工具。')],
  'mac-broadcast': [t('广播地址'), 'bad',
    t('全一只能用来发，不许当任何设备的源地址。邻居表里出现它，记下的是协议帧的目的地，不是一台设备。')],
  'protocol-group': [t('不是一台设备'), '', (v) => v.who
    ? t('这是{0}，出处 {1} —— 协议规定的地址。{2}', [v.who, v.whoSrc, v.whoWhy || ''])
    : t('第一个字节最低位是 1，说明它是发给「一组地址」的，本来就不对应某一台设备。')],
  'virtual-nic': [t('像是虚机 / 容器'), 'warn', (v) =>
    t('{0}（依据 {1}）。{2}', [v.who, v.whoSrc, v.whoWhy || ''])
    + t(' ★ 这是按软件的默认地址段推的，属推测 —— 不是哪里的登记信息。')],
  'locally-administered': [t('地址是软件造的'), 'warn',
    t('本机管理位是置着的：iOS / Android 的私有 Wi-Fi 地址、Windows 的随机 MAC、MAC 克隆都在这里。')
    + t('别拿它当设备唯一标识 —— 同一台设备换个网络就可能换一个，用它做统计会把一台数成好几台。')],
  'device-address': [t('厂商发的地址'), 'ok', (v) => v.who
    ? t('厂商多半是 {0}。{1}', [v.who, v.whoWhy || ''])
    : t('这个地址可以当设备身份用。') + (v.vendorWhy || '')],
};

function macCard() {
  const card = $(t('<div class=\"card\">\n    <h2>MAC 地址 <span id=\"ma-top\"></span></h2>\n    <p class=\"hint\">粘什么写法都认：02:42:ac:11:00:02、02-42-ac-11-00-02、0242.ac11.0002（交换机）、\n      0242ac110002（连写）。答的是「这个地址能不能当设备身份」，不只是「它是谁」：\n      全零是网卡没交出地址，组播本来就不是一台设备，本机管理位置着的多半是随机地址或虚机网卡。\n      ★ 厂商名默认不报 —— IEEE 那张注册表是非商业许可，不打进安装包；\n      要这一栏有名字，把后端的环境变量 NETKIT_OUI_FILE 指到你从 ieee.org 下的 oui.txt。\n      纯解析，不发任何包。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 320px\"><label>要问的 MAC / 以太网地址</label>\n        <input id=\"ma-mac\" placeholder=\"02:42:ac:11:00:02\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn primary\" id=\"ma-go\">查</button></div>\n    </div>\n    <div id=\"ma-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#ma-out');
  const top = card.querySelector('#ma-top');
  const run = async () => {
    const args = { mac: card.querySelector('#ma-mac').value.trim() };
    if (!args.mac) { out.innerHTML = t('<div class=\"empty\">先填要问的 MAC。</div>'); return; }
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">查中…</div>');
    const r = await call('net.mac.analyze', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">查不了：{0}</div>', [esc(r.message || r.error)]); return; }
    const v = r.values;
    const [title, cls, advice] = MA_CODE[r.verdict] || [r.verdict || t('没给判定'), '', ''];
    const say = typeof advice === 'function' ? advice(v) : advice;
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    // ★ 只列后端真给了的字段：组播地址不给接口标识，非 Docker 前缀不给反推的 IPv4，
    //   硬排上去就会显示「IPv6 接口标识：undefined」，而那一栏看起来像真的
    const items = [
      [t('这个地址'), v.canonical], [t('交换机写法'), v.dotForm], [t('连写'), v.bareForm],
      [t('地址长度'), v.family === 'eui-64' ? t('{0} 字节（EUI-64）', [v.octets]) : t('{0} 字节', [v.octets])],
      [t('第一个字节'), t('{0}（二进制 {1}）', [v.firstOctet, v.firstOctetBin])],
      // ★ 全零 / 全一不谈「发给谁、哪来的」：那两栏会把人带回「这是台设备的地址」，
      //   而这一档的结论恰恰是它不属于任何设备
      v.special ? [t('这种地址'), v.special === 'all-zero'
        ? t('六个字节全零 —— 不是任何设备的地址') : t('六个字节全一 —— 广播，只用于发')]
        : [t('发给谁'), v.group ? t('一组地址（组播）') : t('一台设备（单播）')],
      !v.special && [t('地址哪来的'), v.administered === 'local'
        ? t('本机管理 —— 不是哪家厂商名下的地址（随机地址、虚机网卡、协议组播都在这里）')
        : t('全球唯一 —— 前缀是 IEEE 分给某厂商的')],
      // ★ 「厂商前缀」这个名字只给真在厂商名下的地址用：组播、随机地址、全零 / 全一
      //   的前 3 字节不在任何厂商名下，标成「厂商前缀」就是在编一个没登记的归属
      v.special || v.administered !== 'global' || v.group ? [t('前 3 字节'), v.oui] : [t('厂商前缀'), v.oui],
      v.special || v.administered !== 'global' || v.group ? [t('其余字节'), v.nic] : [t('设备位'), v.nic],
      [t('IPv6 接口标识'), v.iid && t('{0}（EUI-64，SLAAC 配出来的地址里就是这段）', [v.iid])],
      [t('藏着的 IPv4'), v.derivedIPv4 && t('{0}（Docker 把容器地址写进了后四字节）', [v.derivedIPv4])],
    ].filter((x) => x && x[1] !== undefined && x[1] !== '');
    const bold = [];
    if (v.who) bold.push([t('来路'), t('{0}（{1}）', [v.who, v.whoBasis === 'standard' ? t('协议规定，是事实')
      : v.whoBasis === 'registry' ? t('按你挂的厂商表查的') : t('软件约定推的，属推测')])]);
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      <table style=\"margin-top:14px\"><tr><th></th><th></th></tr>\n        {3}\n        {4}</table>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{5}</pre></details>', [bg, line, esc(say), items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><code>${esc(x)}</code></td></tr>`).join(''), bold.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><b>${esc(x)}</b></td></tr>`).join(''), esc(JSON.stringify(v, null, 2))]);
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
  'random-generated': [t('可以放心用'), 'ok',
    t('本机管理位是置着的、组播位是清着的：能当设备源地址，也不在任何厂商名下的地址段里。')
    + t('随机部分 40 位，局域网里撞不上真设备。★ 这里只是生成了字符串，本机网卡地址没动。')],
  'clone-generated': [t('保留了你给的前缀'), 'warn', (v) =>
    t('前缀 {0} 原样保留，随机部分只剩 {1} 位（{2} 个组合）。', [v.prefix, v.randomBits, v.space])
    + (v.vendorBlock
      ? t('★ 这个前缀是 IEEE 登记给某家厂商的 —— 那一段里的真设备是活着的，撞上就是两台机器同一个 MAC，')
        + t('症状是「几台机器同时时通时不通」，比配不上难查得多。确认要再用。')
      : t('这个前缀本身是本机管理段，不在任何厂商名下。'))],
};

function macRandomCard() {
  const card = $(t('<div class=\"card\">\n    <h2>随机 MAC <span id=\"mr-top\"></span></h2>\n    <p class=\"hint\">生成能直接用的地址：默认把本机管理位置着、组播位清着 —— 少处理一位，\n      症状都不是「生成失败」而是配上去收不到回包，或者撞进别人名下的地址段。\n      填了前缀就是克隆模式（有些系统的授权看 MAC 前缀），那一档会把随机位还剩多少、\n      是不是在厂商名下算给你看。★ 只生成字符串，不改任何网卡设置。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 200px\"><label>生成几个（1~10）</label>\n        <input id=\"mr-count\" placeholder=\"1\"></div>\n      <div style=\"flex:1 1 260px\"><label>保留的前缀（可留空；也可粘一个完整 MAC）</label>\n        <input id=\"mr-prefix\" placeholder=\"00:1a:2b\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn primary\" id=\"mr-go\">生成</button></div>\n    </div>\n    <div id=\"mr-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#mr-out');
  const top = card.querySelector('#mr-top');
  const run = async () => {
    const args = {};
    const c = card.querySelector('#mr-count').value.trim();
    // ★ 只 trim 显示、不按 trim 后的空不空来决定发不发：输入框里敲了几个空格就算「给了前缀」，
    //   这里替它丢掉等于偷偷换成纯随机，而人要的是克隆 —— 后端专门拦这一条，界面不许绕过
    const p = card.querySelector('#mr-prefix').value;
    if (c && !/^\d+$/.test(c)) {
      out.innerHTML = t('<div class=\"empty\">生成不了：「几个」那一栏要写 1~10 的数字。</div>');
      return;
    }
    if (c) { args.count = Number(c); }
    if (p !== '') { args.prefix = p; }
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">生成中…</div>');
    const r = await call('net.mac.random', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">生成不了：{0}</div>', [esc(r.message || r.error)]); return; }
    const v = r.values;
    const [title, cls, advice] = MR_CODE[r.verdict] || [r.verdict || t('没给判定'), '', ''];
    const say = typeof advice === 'function' ? advice(v) : advice;
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const f = v.formats || {};
    const items = [
      [t('模式'), v.mode === 'clone' ? t('克隆（保留 {0}）', [v.prefix]) : t('纯随机（本机管理 + 单播）')],
      [t('随机部分'), t('{0} 位，{1} 个组合', [v.randomBits, v.space])],
      [t('第一个字节怎么处理'), v.firstOctetPolicy],
      [t('第一个的其它写法'), `${f.dash || ''} / ${f.dot || ''} / ${f.bare || ''}`],
    ].filter((x) => x[1] !== undefined && x[1] !== '');
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      <div style=\"margin-top:12px;display:flex;flex-direction:column;gap:6px\">\n        {3}\n      </div>\n      <table style=\"margin-top:14px\"><tr><th></th><th></th></tr>\n        {4}</table>\n      <p class=\"hint\">点上面任意一个地址选中后可复制；要看看它会被读成什么，粘到上面那张「MAC 地址」卡里查一次。</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{5}</pre></details>', [bg, line, esc(say), (v.macs || []).map((m) => t('<code class=\"mono\" style=\"font-size:15px;user-select:all;cursor:pointer\" title=\"点一下整条选中\">{0}</code>', [esc(m)])).join(''), items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><code>${esc(x)}</code></td></tr>`).join(''), esc(JSON.stringify(v, null, 2))]);
  };
  card.querySelector('#mr-go').onclick = run;
  card.querySelector('#mr-count').onkeydown = (e) => { if (e.key === 'Enter') run(); };
  card.querySelector('#mr-prefix').onkeydown = (e) => { if (e.key === 'Enter') run(); };
  return card;
}

// ★ 编解码这一页的措辞难点在「解出来不是文本」：多数工具在这儿报「失败」，
//   人就换工具、或者去查设备坏没坏 —— 而那两种都不是结论。所以每一档都带下一步。
const CC_CODE = {
  'decoded-text': [t('解出来了，是可读文本'), 'ok', (v) =>
    (v.shape === 'jwt'
      ? t('这是一枚签名令牌，上面已经把头解出来 —— ★ 这里只解码，不验签，所以「解得开」不等于「这枚令牌有效」。载荷里常带账号、内部 IP，别整段贴进工单。')
      : t('下面那一栏就是解出来的原文，可以直接复制。')) +
    (v.alphabetUnclaimed
      ? t(' 这一段里 + 和 / 、- 和 _ 都没出现过，两派 base64 字母表解出来一模一样 —— 指哪一种都不影响结果；') +
        t('哪天串里真出现了这一类字符，指错了会被当场拦下来，不会悄悄解成一个错值。')
      : '')],
  'decoded-binary': [t('解出来是二进制'), 'warn', (v) =>
    v.looksLikeGbk
      ? t('这一串既不是合法 UTF-8、也不像随机数据，而是老设备固件里那种 GBK 中文。这里不替你猜字符表 —— 猜出来的中文比乱码更容易被当成事实。要看成人话，得拿转码工具整份转一次。')
      : t('★ 解码没有失败：是这些字节本来就不该当文本读。要么它是加密 / 压缩过的数据（那本来就解不出人话），要么它压根不是这一种编码 —— 换一种读法再判一次。')],
  'still-encoded': [t('还套着一层编码'), 'warn', t('解出来一次，里面还剩编码 —— 多半是被编了两遍（常见于把一个链接整个塞进另一个链接的参数里）。再判一次就解到底了。')],
  'ambiguous-encoding': [t('几种读法都成立'), 'warn', (v) =>
    t('几种读法各自解出了不同东西，都列在下面了。多半是 {0} —— {1}。★ 没替你挑一个，因为挑错了你会拿着那个结果去对设备。', [CC_ENC[v.mostLikely] || v.mostLikely, v.why || ''])],
  'plain-text': [t('这段没在编码'), '', (v) => v.why || t('它原样就是它自己。')],
  'not-decodable': [t('这一种解不开'), 'bad', (v) => v.why || t('解不开。')],
  encoded: [t('编好了'), 'ok', t('挑一种贴走。★ base64 不是加密，别拿它藏密码 —— 它一眼就能解回来。')],
};

const CC_ENC = {
  base64: t('Base64（标准字母表）'), base64url: t('Base64（URL 安全，带 - 和 _）'),
  hex: t('十六进制'), url: t('URL 百分号转义'), unicode: t('\\u 转义'), jwt: t('签名令牌'),
};

// ★ 工具替人放宽了什么，必须逐条摆出来：不记下来就等于悄悄改了数据。
const CC_FIX = {
  'outer-whitespace': t('去掉了首尾空白'),
  'quotes-trimmed': t('去掉了成对引号'),
  'padding-added': t('补上了缺失的填充符 ='),
  'url-safe-alphabet': t('按 URL 安全字母表读的（认了 - 和 _）'),
  'line-wrapped': t('去掉了折行带的换行（命令行输出那种每 76 列一段）'),
  'inner-whitespace': t('去掉了中间的空格 —— ★ 要是这段是从网址里抄的，那个空格原本可能是个加号'),
  'hex-0x-prefix': t('去掉了开头的 0x'),
  'separators-removed': t('去掉了字节之间的分隔符'),
  'plus-in-url': t('串里有加号，按「查询串」和「路径」两种读法分开给了'),
};

function codecCard() {
  const card = $(t('<div class=\"card\">\n    <h2>编解码 <span id=\"cc-top\"></span></h2>\n    <p class=\"hint\">整段贴进来：Base64 / Base64URL / 十六进制 / 网址百分号转义 / \\u 转义，认得出是哪种并解开；\n      反过来要编进去也行。\n      ★ 解出来不是文本时不会报「失败」—— 二进制就是二进制，那是两种不同的下一步。\n      几种读法都说得通的串（比如 32 个十六进制字符），两种结果都摆出来让你指一个，不替你猜。\n      纯字符串运算：不发任何包，也不碰文件。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 100%\"><label>要判的字符串</label>\n        <textarea id=\"cc-text\" rows=\"3\" placeholder=\"贴 Base64、网址里抄的一段、或者一串十六进制\"\n          style=\"width:100%\"></textarea></div>\n    </div>\n    <div class=\"row\">\n      <div style=\"flex:1 1 160px\"><label>怎么处理</label>\n        <select id=\"cc-op\">\n          <option value=\"auto\">自动（判是什么并解开）</option>\n          <option value=\"decode\">只要解开</option>\n          <option value=\"encode\">只要编进去</option>\n        </select></div>\n      <div style=\"flex:1 1 190px\"><label>按哪种读法（可留自动）</label>\n        <select id=\"cc-enc\">\n          <option value=\"\">自动判断</option>\n          <option value=\"base64\">Base64</option>\n          <option value=\"base64url\">Base64URL</option>\n          <option value=\"hex\">十六进制</option>\n          <option value=\"url\">URL 转义</option>\n          <option value=\"unicode\">\\u 转义</option>\n        </select></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn primary\" id=\"cc-go\">判一下</button></div>\n    </div>\n    <div id=\"cc-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#cc-out');
  const top = card.querySelector('#cc-top');
  const mono = 'user-select:all;cursor:pointer;word-break:break-all';
  const run = async () => {
    const text = card.querySelector('#cc-text').value;
    if (!text.trim()) { top.innerHTML = ''; out.innerHTML = t('<div class=\"empty\">先贴一段字符串。</div>'); return; }
    const args = { text, op: card.querySelector('#cc-op').value };
    const enc = card.querySelector('#cc-enc').value;
    if (enc) args.encoding = enc;
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">判一下…</div>');
    const r = await call('net.codec.convert', args);
    if (!r.ok) { out.innerHTML = t('<div class=\"empty\">判不了：{0}</div>', [esc(r.message || r.error)]); return; }
    const v = r.values;
    const [title, cls, advice] = CC_CODE[r.verdict] || [r.verdict || t('没给判定'), '', ''];
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
      [rejected ? t('你指的读法') : t('认出的写法'), v.encoding ? (CC_ENC[v.encoding] || v.encoding) : undefined],
      [passthrough ? t('这段多少字节') : t('解出多少字节'),
        v.byteLen !== undefined && r.verdict !== 'encoded' ? String(v.byteLen) : undefined],
      [t('是不是合法 UTF-8'), v.utf8 === undefined ? undefined : (v.utf8 ? t('是') : t('不是'))],
      [t('头（签名令牌）'), v.header],
      [t('按查询串读'), v.plusAmbiguous ? v.asQuery : undefined],
      [t('按路径读'), v.plusAmbiguous ? v.asPath : undefined],
      [t('原文'), v.plainText],
      ['Base64', v.base64], ['Base64URL', v.base64url],
      [t('十六进制'), v.hex],
      [t('URL 转义'), v.url], [t('\\u 转义'), v.unicode],
      [t('编了多少字节'), r.verdict === 'encoded' ? String(v.byteLen) : undefined],
    ].filter((x) => x[1] !== undefined && x[1] !== '');
    const rows = items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
      <td><code style="${mono}">${esc(x)}</code></td></tr>`).join('');
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      {4}\n      {5}\n      {6}\n      {7}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{8}</pre></details>', [bg, line, esc(say), fixes.length ? t('<p class=\"hint\" style=\"margin-top:8px\">替你放宽过：{0}</p>', [esc(fixes.join(t('；')))]) : '', v.text ? t('<div style=\"margin-top:10px\"><label class=\"dim\">解出来</label>\n        <pre style=\"{0};margin:4px 0 0;white-space:pre-wrap\">{1}</pre></div>', [mono, esc(v.text)]) : '', v.hexDump ? t('<div style=\"margin-top:10px\"><label class=\"dim\">按字节看</label>\n        <pre style=\"{0};margin:4px 0 0;white-space:pre-wrap\">{1}</pre></div>', [mono, esc(v.hexDump)]) : '', v.readings ? t('<table style=\"margin-top:12px\"><tr><th>读法</th><th>解出来</th><th>这一种放宽过什么</th></tr>\n        {0}</table>', [v.readings.map((x) => `<tr><td class="dim" style="white-space:nowrap">${esc(CC_ENC[x.encoding] || x.encoding)}
          ${x.encoding === v.mostLikely ? t('（多半是这种）') : ''}</td>
          <td><code style="${mono}">${esc(x.readable ? x.text : x.hexDump)}</code></td>
          <td class="dim">${esc((x.normalized || []).map((f) => CC_FIX[f] || f).join(t('；'))) || '—'}</td></tr>`).join('')]) : '', rows ? `<table style="margin-top:14px"><tr><th></th><th></th></tr>${rows}</table>` : '', esc(JSON.stringify(v, null, 2))]);
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
  'sent-broadcast': [t('已发到本机网段'), 'ok'],
  'sent-unicast': [t('已发到指定地址'), 'ok'],
};
const WL_CODE = {
  'likely-awake': [t('它此刻在邻居表里，没发'), 'warn'],
};
// 这块网卡是怎么定下来的——现场发错地方，八成在这一步
const WL_FROM = {
  'given': t('你指定的'),
  'neighbor-table': t('这个 MAC 在邻居表里是从这块网卡学到的'),
  'default-route': t('没有它的记录，按 IPv4 默认路由选了这块'),
  'only-usable-v4': t('没默认路由，本机只有这一块带可用 IPv4 的网卡'),
};
const WL_DST = {
  'directed-broadcast': t('本机网段的定向广播地址'),
  'forwarded-unicast': t('你指定的地址（跨网段）'),
};

function wolCard() {
  const card = $(t('<div class=\"card\">\n    <h2>Wake-on-LAN 唤醒 <span id=\"wl-top\"></span></h2>\n    <p class=\"hint\">往目标网卡的 MAC 发一枚魔术帧，把睡着的机器叫起来。\n      ★ 这会改变那台机器的状态，所以一次只唤醒一台、要你点头才发，并且留一笔痕迹。\n      默认只往指定网卡自己网段的广播地址发（不用全 255 那一发，它从默认路由的网卡出去，\n      可能吵醒一整层楼）。网卡留空就自己推：先看这个 MAC 是哪块网卡学到的，再看默认路由。\n      ★ 发出去不等于醒了：看结果里「从哪发到哪」和「它在不在邻居表里」两栏，\n      最后一步是过一两分钟回来看它回没回来。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 220px\"><label>要唤醒的 MAC（只能一台）</label>\n        <input id=\"wl-mac\" placeholder=\"aa:bb:cc:dd:ee:ff\"></div>\n      <div style=\"flex:1 1 140px\"><label>从哪块网卡（留空自动选）</label>\n        <input id=\"wl-iface\" placeholder=\"en0 / eth0\"></div>\n      <div style=\"flex:1 1 180px\"><label>跨网段时发到哪（目标网段广播地址）</label>\n        <input id=\"wl-host\" placeholder=\"留空 = 本机网段\"></div>\n    </div>\n    <div class=\"row\">\n      <div style=\"flex:0 0 110px\"><label>端口</label>\n        <input id=\"wl-port\" placeholder=\"9\"></div>\n      <div style=\"flex:0 0 110px\"><label>连发几枚</label>\n        <input id=\"wl-repeats\" placeholder=\"1\"></div>\n      <div style=\"flex:1 1 180px\"><label>SecureOn 口令（可留空，不会被记下来）</label>\n        <input id=\"wl-pass\" type=\"password\" autocomplete=\"off\" placeholder=\"4 或 6 字节 hex\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn danger\" id=\"wl-go\">唤醒这台</button></div>\n    </div>\n    <label style=\"display:flex;gap:6px;align-items:center;margin-top:8px;font-size:13px\">\n      <input type=\"checkbox\" id=\"wl-force\" style=\"flex:0 0 auto\">\n      邻居表里现在还有它（刚才醒着）也照发 —— 部分主机会因此走一次开机流程</label>\n    <div id=\"wl-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#wl-out');
  const top = card.querySelector('#wl-top');
  const run = async () => {
    const mac = card.querySelector('#wl-mac').value.trim();
    if (!mac) {
      out.innerHTML = t('<div class=\"empty\">先写要唤醒哪一台：从设备标签、DHCP 租约或邻居表里抄它的 MAC。</div>');
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
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消的话一枚都不发）</div>');
    const r = await call('net.wol', args);
    card.querySelector('#wl-pass').value = '';  // 口令不留在输入框里
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">没有发出去：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    const v = r.values || {};
    const sent = WL_SENT[r.verdict];
    const awake = WL_CODE[r.verdict];
    let title, cls;
    if (sent) { [title, cls] = sent; } else if (awake) { [title, cls] = awake; } else {
      title = r.verdict || t('没给判定'); cls = '';
    }
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    let say;
    if (sent) {
      say = t('已经发出去的只证明「从这块网卡到了这个地址」，不证明它醒了。')
        + (v.needsRelay
          ? t(' ★ 这一发的目标不在本机任何网段里，要经路由器转发 —— ')
            + t('多数路由器默认丢掉定向广播，没醒先怀疑这一条。')
          : t(' 过一两分钟回来看邻居表：它回来了才是真醒了。'))
        + (v.seenAt ? t(' 发之前邻居表里已经有它（{0}），是你勾了照发才发的。', [esc(v.seenAt)])
          : t(' 发之前邻居表里没有它。'));
    } else if (awake) {
      say = t('没有发。邻居表里现在还有它（{0}），说明它刚才大概率醒着', [esc(v.seenAt || t('没给地址'))])
        + t('。★ 这不是铁证：条目要几分钟才过期。确定它是关着的话勾上下面那个框再发一次。');
    } else {
      say = t('后端给了一个这里还没认得的判定，原文在下面展开看。');
    }
    const items = [
      [t('唤醒哪台'), v.mac],
      [t('从哪块网卡'), v.iface ? t('{0}（{1}', [v.iface, WL_FROM[v.ifaceFrom] || v.ifaceFrom || t('没说怎么选的')])
        + (v.ifaceKind ? t('，{0}', [v.ifaceKind]) : '') + (v.ifaceVirtual ? t('，虚拟/隧道口') : '') + t('）') : undefined],
      [t('本机地址'), v.src ? t('{0}（{1}）', [v.src, v.subnet]) : undefined],
      [sent ? t('发到哪') : t('本来会发到哪'),
        v.dst ? t('{0}:{1}（{2}）', [v.dst, v.port, WL_DST[v.dstKind] || v.dstKind]) : undefined],
      [t('发了几枚'), v.sent === undefined ? undefined
        : v.sent ? t('{0} / 要发 {1}', [v.sent, v.sends]) : t('一枚都没发（要发 {0}）', [v.sends])],
      [t('帧'), v.frame ? t('{0} 字节', [v.frameBytes]) : undefined],
      [t('口令'), v.passwordUsed ? t('用过，没写进结果和日志') : undefined],
    ].filter((x) => x[1] !== undefined && x[1] !== '');
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      <table style=\"margin-top:14px\"><tr><th></th><th></th></tr>\n        {4}</table>\n      {5}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{6}</pre></details>', [bg, line, say, v.frame ? t('<div style=\"margin-top:10px\"><label class=\"dim\">发出去的帧（和别人的工具对拍，口令不在里面）</label>\n        <pre class=\"mono\" style=\"margin:4px 0 0;word-break:break-all;font-size:11.5px\">{0}</pre></div>', [esc(v.frame)]) : '', items.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
          <td><code>${esc(x)}</code></td></tr>`).join(''), sent ? t('<p class=\"hint\">没醒的常规原因，按概率排：设备没在开机卡/电源供电（WoL 要待机取电）、\n        固件里这个功能没开、换机器换了网卡所以 MAC 不对、快速启动导致关机后不再监听、\n        以及跨网段那一发被路由器丢了。</p>') : '', esc(JSON.stringify(v, null, 2))]);
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
  'routes-listed': [t('已读到本机路由表'), ''],
  'route-found': [t('出口确定了'), 'ok'],
  'no-route': [t('没有路可走'), 'bad'],
  'route-mismatch': [t('按表算的和系统选的不一样'), 'warn'],
  'route-split': [t('一个名字解出几个地址，走的路不一样'), 'warn'],
  'route-local': [t('这个地址就是本机自己'), 'warn'],
  'multi-default-route': [t('同族有多条默认路由'), 'bad'],
  'table-unreadable': [t('这台机器上读不到路由表'), 'bad'],
};
const RT_FROM = {
  os: t('系统自己给的'),
  table: t('按表算的（照这张表做最长前缀匹配）'),
};

function routesCard() {
  const card = $(t('<div class=\"card\">\n    <h2>路由表 <span id=\"rt-top\"></span></h2>\n    <p class=\"hint\">本机所有出口的总账，并且能问一句「去往这个地址会从哪块网卡出去」。\n      ★ 纯读本机，一个探测包都不发（只有你填的是域名时解析一次）；\n      所以它答的是<strong>该走哪</strong>，不是<strong>走不走得到</strong>。\n      多网卡机器上「时通时不通」、插了 VPN 之后某个网段上不去，都是这张表里两条在打架。\n      表按系统选路的优先级排：越具体的网段越靠前，默认路由压在最后 ——\n      按顺序从上往下看第一条盖得住的，就是实际生效的那条。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 240px\"><label>去往哪儿（地址或域名，留空 = 只看表）</label>\n        <input id=\"rt-dest\" placeholder=\"192.168.1.100 / fd00::1 / camera.local\"></div>\n      <div style=\"flex:0 0 150px\"><label>看哪一族</label>\n        <select id=\"rt-family\">\n          <option value=\"\">两族都看</option>\n          <option value=\"ipv4\">只看 IPv4</option>\n          <option value=\"ipv6\">只看 IPv6</option>\n        </select></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn primary\" id=\"rt-go\">读一下</button></div>\n    </div>\n    <div id=\"rt-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#rt-out');
  const top = card.querySelector('#rt-top');

  const destOf = (r) => (r.destination === '0.0.0.0/0' || r.destination === '::/0')
    ? 'default' : r.destination;
  const isDefault = (r) => r.destination === '0.0.0.0/0' || r.destination === '::/0';

  // 一行「该走哪」的答复。并列、问不到、直连，全部要说在明处。
  const decideLine = (d, ties, extra) => {
    const parts = [t('去往 <code>{0}</code> 从 <b>{1}</b> 出去', [esc(d.addr), esc(d.iface || t('（没给网卡名）'))])];
    parts.push(d.gateway ? t('下一跳 <code>{0}</code>', [esc(d.gateway)])
      : t('是本网段直连，不经过网关'));
    if (d.from === 'table') {
      // 按表算的答案：把真正生效的那一条指给人看（表里就有这一行，高亮着）
      parts.push(t('命中的是 <code>{0}</code> 那一行', [esc(destOf(d))]));
    }
    parts.push(t('依据：{0}', [RT_FROM[d.from] || d.from]));
    if (d.metric) parts.push(t('度量 {0}', [d.metric]));
    if (d.src) parts.push(t('本机用 <code>{0}</code>', [esc(d.src)]));
    if (ties) {
      parts.push(t('★ 还有 {0} 条同样匹配，而本机没给可比的依据（表里不带度量），', [ties])
        + t('这里列的只是其中一条 —— 别把它当成「就这一条路」'));
    }
    if (extra) parts.push(extra);
    return parts.join(t('；')) + t('。');
  };

  const run = async () => {
    const args = {};
    const dest = card.querySelector('#rt-dest').value.trim();
    const fam = card.querySelector('#rt-family').value;
    if (dest) args.dest = dest;
    if (fam) args.family = fam;
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">读中…</div>');
    const r = await call('net.routes', args);
    if (!r.ok) {
      // ★ 解不开名字这一句必须留着：不写「.local 走 mDNS」，
      //   人会以为那台设备下线了，接着去 ping —— 而 ping 同样解不开这个名字。
      out.innerHTML = t('<div class=\"empty\">没读到：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    const v = r.values || {};
    const [title, cls] = RT_CODE[r.verdict] || [r.verdict || t('没给判定'), ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';

    let say;
    switch (r.verdict) {
      case 'route-found':
        say = decideLine(v.decision || {}, v.ties || 0,
          v.osUnavailable ? t('★ 系统那边问不到（这个平台没有「问一句」的命令，或者它没答），所以这一条是照表算的') : '');
        break;
      case 'multi-default-route':
        say = t('同一族有两条以上的默认路由。★ 出外网走哪条不看表的顺序，只看度量 —— ')
          + t('这就是「ping 得通一半」「插了 VPN 某个网段上不去」最常见的来源。')
          + t('下面「默认路由」那一栏把每一条挂在哪块网卡都列出来了。')
          + t('★ 先按网卡名分一下：多出来的那些如果都挂在 utun / ppp / tun / tap 这类')
          + t('隧道口上，那是 VPN 自己在收路线，一般不算故障；')
          + t('两块物理网卡（en / eth / WLAN 之类）各带一条默认路由，才是真会时通时不通的那种。');
        break;
      case 'no-route':
        say = v.familyRoutes === 0
          ? t('<code>{0}</code> 是个 {1} 地址，', [esc(v.destAddr || v.dest), v.family === 'ipv6' ? 'IPv6' : 'IPv4'])
            + t('可这张表里 {0} 一条路由都没有 —— 这台机器这一族<strong>没启用</strong>。', [v.family === 'ipv6' ? 'IPv6' : 'IPv4'])
            + t('★ 不是防火墙拦的，也不是对端不理：先去把这一族开起来，查防火墙是白查。')
          : t('表里 {0} 条 {1} 路由，', [v.familyRoutes, v.family === 'ipv6' ? 'IPv6' : 'IPv4'])
            + t('没有一条盖得住 <code>{0}</code>。', [esc(v.destAddr || v.dest)])
            + t('★ 到不了它是<strong>没路</strong>，不是「对端不理」—— 这两个的下一步完全不同：')
            + t('没路要加路由（或换一块有路口的网卡），不理才去查对端和防火墙。');
        break;
      case 'route-mismatch':
        say = t('★ 按表算是一个出口，系统自己给的是另一个 —— 这台机器的路由不能靠看表判断。')
          + t('Linux 上多半是策略路由（每块网卡各自一张表，主表那条不算数）。')
          + t('以系统给的那一条为准，两个答案都摆在下面。');
        break;
      case 'route-split':
        say = t('{0} 解出 {1} 个地址，', [esc(v.dest), v.destAddrs ? v.destAddrs.length : (v.paths || []).length])
          + t('而它们走的路不一样。★ 实际走哪条由应用挑哪个地址决定，不由本机决定 —— ')
          + t('所以这不是配置错误，是必须看见的事实（一个域名同时给 v4/v6、或者轮询解析就是这样）。');
        break;
      case 'route-local':
        say = t('<code>{0}</code> 是<strong>本机自己的地址</strong> —— ', [esc(v.destAddr || v.dest)])
          + t('发往它会走回环，不会出网卡。★ 如果你以为它是另一台设备，那就是两台机器的 IP 撞了')
          + t('（现场最常见：设备的固定地址被误配到了本机网卡上）。')
          + t('这时候「能 ping 通」恰恰是假象，通的是自己。');
        break;
      case 'table-unreadable':
        say = t('这台机器上一条路由都没读到。★ 这<strong>不等于</strong>「这台机器没有路由」—— ')
          + t('多半是这个平台这里的读取方式还没实现，或者被系统挡住了。')
          + t('换成只填一族的 IPv4 / IPv6 再试一次；要查出口请直接用「路径追踪」。');
        break;
      default:
        say = t('下面就是本机的路由表。★ 只看了本机，一个包都没发。')
          + t('想知道「去往某个地址会从哪块网卡出去」，把地址填上面问一句 —— ')
          + t('光看表要自己在几十行里做最长前缀匹配，很容易看漏一条压住默认路由的 /24。');
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
        <td><code>${esc(destOf(x))}</code>${isDefault(x) ? t(' <span class=\"pill\">默认</span>') : ''}</td>
        <td>${x.gateway ? `<code>${esc(x.gateway)}</code>` : t('<span class=\"dim\">直连（不经网关）</span>')}</td>
        <td><b>${esc(x.iface || '—')}</b></td>
        <td class="dim">${x.metric ? x.metric : '—'}</td>
      </tr>`;
    }).join('');
    const hasMetric = (v.routes || []).some((x) => x.metric);

    const pathRows = (v.paths || []).map((p) => `<tr>
      <td><code>${esc(p.addr)}</code></td>
      <td><b>${esc(p.iface || '—')}</b></td>
      <td>${p.gateway ? `<code>${esc(p.gateway)}</code>` : t('<span class=\"dim\">直连</span>')}</td>
      <td class="dim">${esc(destOf(p))}</td>
      <td class="dim">${esc(RT_FROM[p.from] || p.from || '')}</td>
    </tr>`).join('');

    const oneRow = (label, d) => d ? `<tr><td class="dim" style="white-space:nowrap">${esc(label)}</td>
      <td>${d.iface ? `<b>${esc(d.iface)}</b>` : '—'}${d.gateway ? t(' · 下一跳 <code>{0}</code>', [esc(d.gateway)]) : t(' · 直连')}
        ${d.from === 'table' ? t('· 命中 <code>{0}</code>', [esc(destOf(d))]) : ''}${d.metric ? t(' · 度量 {0}', [d.metric]) : ''}
        · <span class="dim">${esc(RT_FROM[d.from] || d.from || '')}</span></td></tr>` : '';

    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      {4}\n      {5}\n      {6}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{7}</pre></details>', [bg, line, say, v.defaults && v.defaults.length ? t('<p class=\"hint\" style=\"margin-top:8px\">默认路由：{0}{1}</p>', [v.defaults.map((d) => t('{0}（下一跳 {1}，{2}）', [esc(d.iface || '?'), esc(d.gateway || t('无')), d.family])).join(t('；')), v.multiDefault ? t(' ★ 同族不止一条') : '']) : '', r.verdict === 'route-mismatch' ? t('<table style=\"margin-top:12px\"><tr><th></th><th>答案</th></tr>\n        {0}{1}</table>', [oneRow(t('系统自己选的'), v.byOS), oneRow(t('按表算的'), v.byTable)]) : '', pathRows ? t('<table style=\"margin-top:12px\"><tr><th>解出的地址</th><th>出口网卡</th>\n        <th>下一跳</th><th>命中</th><th>依据</th></tr>{0}</table>', [pathRows]) : '', rows ? t('<div style=\"margin-top:12px;max-height:360px;overflow:auto\">\n        <table><tr><th>族</th><th>目的</th><th>下一跳</th><th>出口网卡</th><th>度量</th></tr>\n        {0}</table></div>\n        {1}', [rows, hasMetric ? '' : t('<p class=\"hint\">这张表里一条度量都没给（macOS 的读取方式就不带这一栏）—— ')
          + t('碰到并列时这里没法替你判谁生效，会照实写在结论里。</p>')]) : '', esc(JSON.stringify(v, null, 2))]);
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
  'share-serving': [t('正在共享'), 'ok'],
  'share-stopped': [t('已经停掉了'), ''],
  'share-idle': [t('没在共享'), ''],
};

// ★ 这几种「没成」的处置完全不同，界面不许并成一句「失败」：
//   partial 是设备那头掉了或网断了（重发一次就行），not-found 是文件名填错
//   （去改设备那一页的地址），denied 是有人在试上传或想翻出共享目录。
const FS_TAKE = {
  ok: [t('整份取走了'), ''],
  head: [t('只问了大小'), ''],
  range: [t('按段取的（断点续传在跑）'), ''],
  partial: [t('传到一半断了'), 'bad'],
  list: [t('翻了目录'), 'warn'],
  denied: [t('被拒（想上传 / 想翻出共享目录）'), 'bad'],
  'not-found': [t('没有这个文件（地址里那个文件名没对上）'), 'warn'],
  // TFTP 那一侧独有的三种：处置和上面几种完全不同，不许并回「失败」。
  aborted: [t('协商完就没回话（多半这台设备不认 OACK）'), 'bad'],
  busy: [t('同时传得太多了，这一笔没接'), 'warn'],
  'octet-served': [t('按原样字节发完了（它要的是 netascii）'), ''],
};

// 后端给的是「这块口凭什么选上」的原话，界面翻成人话，并且把风险点一句带上：
// 指定网卡这条路是绕开默认路由的，机器上那块口连着谁，只有现场的人知道。
const FS_WHY = {
  '你指定的网卡': t('说的就是你指的那块口 ★ 这一条没照着默认路由挑，确认一下这块口连着谁'),
  'IPv4 默认路由走这块': t('按 IPv4 默认路由挑的（这台机器往上走的那块口）'),
  '本机只有一块带可用 IPv4 的网卡': t('自动挑的：本机只有这一块带可用的 IPv4 地址'),
};

function fsSize(n) {
  if (typeof n !== 'number') return '—';
  if (n >= 1073741824) return (n / 1073741824).toFixed(1) + ' GB';
  if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
  if (n >= 1024) return Math.round(n / 1024) + ' KB';
  return n + t(' 字节');
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
  if (m < 60) return t('{0} 分钟', [m]);
  return t('{0} 小时 {1} 分', [Math.floor(m / 60), m % 60]);
}

// 台账：现场查「设备说下载失败」就看这一栏 —— 有没有人来取过、
// 取到第几个字节断的，看了就不用猜。
function fsLedger(recent) {
  const list = recent || [];
  if (!list.length) {
    return t('<div class=\"empty\">还没有设备来取过文件。它说不行的时候回来看这一栏：')
      + t('空着说明根本没来（地址或网不对），有半截的说明传断了。</div>');
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
  return t('<div style=\"max-height:280px;overflow:auto\"><table>\n    <tr><th>什么时候</th><th>谁取的</th><th>哪个协议</th><th>取了什么</th><th>多少</th><th>结果</th></tr>\n    {0}</table></div>\n    <p class=\"hint\">只留最近 50 笔。「被拒」那一行是分开的：想上传的（http 的 PUT、tftp 的 WRQ、ftp 的 STOR/DELE）一律不收，\n      文件名写错只算没找到，不混成「有人在攻击」。协议那一栏看得出设备是从哪个口来取的 ——\n      同一台设备换个地址栏就会换一行，开着三种协议时这一栏也是「谁在动这个目录」的清单。</p>', [rows]);
}

function fsWarn(lines) {
  if (!lines || !lines.length) return '';
  return `<div style="margin-top:10px;padding:10px 12px;border-radius:6px;font-size:13.5px;
      background:var(--gold-bg);border:1px solid var(--gold-dim);color:var(--gold)">★ ${
    lines.map((x) => esc(x)).join('<br>★ ')}</div>`;
}

let fsTimer = null;

function fileshareCard() {
  const card = $(t('<div class=\"card\">\n    <h2>文件共享（只读） <span id=\"fs-top\"></span></h2>\n    <p class=\"hint\">把本机一个目录开成 http 下载地址 —— 设备的升级页面要填一个\n      「固件下载地址」，交换机要把配置文件拉回去，都是这一张。\n      ★ 遇到<strong>只认 tftp 的老设备</strong>（填 http 一律「下载失败」），勾上「连 TFTP 一起开」：\n      同一个目录、同样只读，只是多开一个 UDP 口。另一批设备/交换机的地址栏只认\n      <strong>ftp://</strong>，那就勾「连 FTP 一起开」。\n      ★ <strong>只读</strong>：只发不收，同网段谁都改不了、删不了本机任何东西\n      （http 只接 GET/HEAD，tftp 的上传请求当场回「不接受上传」，\n      ftp 的 STOR/DELE/MKD/RNFR 这些命令压根不认）。\n      ★ 只绑你挑的那块网卡上的地址，<strong>不绑 0.0.0.0</strong> ——\n      多网卡机器上那等于把目录从办公网甚至公网口也开出去。\n      ★ 无鉴权：开着的时候同一网段任何设备不必登录就能把这个目录整个读走，\n      所以每次开都要你点头，用完请点停掉（停是当场断，正在传的那一发也立刻断）。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 300px\"><label>要共享的目录（只放要发出去的那些文件）</label>\n        <input id=\"fs-root\" placeholder=\"/Users/you/firmware 或 D:\\固件\"></div>\n      <div style=\"flex:0 0 150px\"><label>开在哪块网卡（留空自动）</label>\n        <input id=\"fs-iface\" placeholder=\"en0 / eth0 / WLAN\"></div>\n      <div style=\"flex:0 0 100px\"><label>端口</label>\n        <input id=\"fs-port\" placeholder=\"8080\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn danger\" id=\"fs-go\">开共享</button></div>\n    </div>\n    <div class=\"row\">\n      <div style=\"flex:1 1 260px\"><label>或者只绑这几个地址（填了就按这个来，覆盖上面那块网卡）</label>\n        <input id=\"fs-addrs\" placeholder=\"192.168.1.20 fd00::1（不许写 0.0.0.0）\"></div>\n      <div style=\"flex:0 0 110px\"><label>TFTP 端口（默认 69）</label>\n        <input id=\"fs-tftpport\" placeholder=\"69\"></div>\n      <div style=\"flex:0 0 110px\"><label>FTP 端口（默认 21）</label>\n        <input id=\"fs-ftpport\" placeholder=\"21\"></div>\n    </div>\n    <div class=\"row\">\n      <label style=\"display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap\">\n        <input type=\"checkbox\" id=\"fs-list\" checked style=\"flex:0 0 auto\">\n        允许翻目录列表</label>\n      <label style=\"display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap\"\n        title=\"老设备的升级页面只认 tftp://，填 http 一律「下载失败」。开了就是多开一个 UDP 口，一样只读、一样不鉴权。\">\n        <input type=\"checkbox\" id=\"fs-tftp\" style=\"flex:0 0 auto\">\n        连 TFTP 一起开（老设备只认它）</label>\n      <label style=\"display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap\"\n        title=\"还有一批设备和交换机的地址栏只认 ftp://。开的是只读：上传、删除、改名这些命令当场拒。数据口只绑在这块网卡上。\">\n        <input type=\"checkbox\" id=\"fs-ftp\" style=\"flex:0 0 auto\">\n        连 FTP 一起开（交换机/老设备只认 ftp://）</label>\n    </div>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <div style=\"flex:0 0 auto;min-width:0\">\n        <button class=\"btn\" id=\"fs-refresh\">刷新台账</button>\n        <button class=\"btn danger\" id=\"fs-stop\" style=\"display:none\">立刻停掉</button></div>\n    </div>\n    <div id=\"fs-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#fs-out');
  const top = card.querySelector('#fs-top');
  const btnStop = card.querySelector('#fs-stop');

  const paint = (verdict, v) => {
    const [title, cls] = FS_CODE[verdict] || [verdict || t('没给判定'), ''];
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
      say = t('现在没开着。开一次就是一次对外暴露，需要时再开、用完就停 —— ')
        + t('这个共享不鉴权，同网段谁都能读。');
    } else if (verdict === 'share-stopped') {
      // ★ 停掉之后不再摆下载地址：那几条已经读不到东西了，还做成可复制的样子，
      //   人就照旧往设备里粘，然后回来查「为什么下载失败」。
      say = t('{0} 的端口都已经放掉，{1} 不再对外可读。', [protos.join(t('、')), esc(root)])
        + t('这中间一共被取走 {0} 次、{1}。', [v.requests || 0, esc(fsSize(v.bytes || 0))])
        + t('已经下到设备里的文件不受影响。');
    } else if (serving && v.iface) {
      say = t('目录 <code>{0}</code> 正从网卡 <b>{1}</b>', [esc(root), esc(v.iface)])
        + t('（{0}）发出去，http 端口 {1}', [esc(FS_WHY[v.ifaceWhy] || v.ifaceWhy || t('怎么定的没说')), port || '—'])
        + (tftp ? t('、TFTP 端口 {0}', [tftpPort || '—']) : '')
        + (ftp ? t('、FTP 端口 {0}', [ftpPort || '—']) : '') + t('。')
        + t('只读，不收上传。★ 同一网段的设备不必登录就能读到这个目录里的东西。');
    } else if (serving) {
      say = t('目录 <code>{0}</code> 正绑在这些地址上：{1}，http 端口 {2}', [esc(root), (v.addrs || st.addrInfo || []).map((x) => `<code>${esc(x)}</code>`).join(t('、')), port || '—'])
        + (tftp ? t('、TFTP 端口 {0}', [tftpPort || '—']) : '')
        + (ftp ? t('、FTP 端口 {0}', [ftpPort || '—']) : '') + t('。只读，不收上传。');
    } else {
      say = t('后端给了一个这里还没认得的判定，原文在下面展开看。');
    }

    const facts = [];
    if (serving || verdict === 'share-stopped') {
      if (typeof v.entries === 'number') {
        facts.push([t('目录里有多少'), t('{0} 个文件{1}，共 {2}', [v.entries, v.dirs ? t('、{0} 个子目录', [v.dirs]) : '', esc(fsSize(v.bytes || 0))])]);
      }
      if (typeof st.requests === 'number') {
        facts.push([t('已被取走'), t('{0} 次、{1}', [st.requests, esc(fsSize(st.bytes || 0))])
          // ★ 两个数分开摆：想上传的是有人在试，文件名没对上的是现场抄错了字。
          //   并成一个「失败 N 次」的话，前者会被后者淹掉。
          + (st.denied ? t('；<b class=\"bad\">{0} 次被拒</b>（想上传 / 想翻出目录）', [st.denied]) : '')
          + (st.notFound ? t('；{0} 次文件名没对上', [st.notFound]) : '')]);
      }
      if (st.since) facts.push([t('开了多久'), fsSpan(st.since)]);
      if (serving) {
        // ★ 这一栏在状态刷新后也要留着：关没关列表决定了别人能不能把文件名挨个抄走
        facts.push([t('能不能翻目录'), listing
          ? t('能（同网段谁都能把这个目录的文件名挨个列走）') : t('不能（要写对完整文件名才取到走）')]);
        if (tftp) {
          // ★ 多开的那是一个 UDP 口，也要一直看得见：现场防火墙对 UDP 的默认放行
          //   往往比 TCP 松，只报 http 等于少说了一半。
          facts.push([t('TFTP 那一侧'), t('开着，UDP 端口 {0}；一样只读，上传请求一律回「不接受上传」', [tftpPort || '—'])]);
        }
        if (ftp) {
          // ★ 这一栏要说的是「它还额外开了什么」：FTP 每传一个文件要临时开一个数据口，
          //   只放行 21 的防火墙会卡在取文件那一步 —— 不说，现场会去怀疑设备。
          facts.push([t('FTP 那一侧'), t('开着，端口 {0}；只读，STOR/DELE/MKD/RNFR 这些命令当场拒', [ftpPort || '—'])
            + t('；每传一个文件临时开一个数据口（只绑这块网卡的地址），防火墙只放行这一个口会卡在取文件那一步')]);
        }
      }
    }
    const factRows = facts.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td>
      <td>${x}</td></tr>`).join('');

    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      {4}\n      {5}\n      {6}\n      {7}\n      {8}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{9}</pre></details>', [bg, line, say, urls.length && serving ? t('<div style=\"margin-top:12px\"><label class=\"dim\">下载地址（贴进设备的升级页面）</label>\n        {0}\n        <p class=\"hint\">点一下整条就选中，直接抄。跨网段的设备要用它自己能到的那个地址，\n          不是随便挑一条。</p></div>', [urls.map((u) => `<div style="margin-top:4px"><code style="user-select:all;cursor:cell">${esc(u)}</code></div>`).join('')]) : '', turls.length && serving ? t('<div style=\"margin-top:12px\"><label class=\"dim\">TFTP 地址（设备的升级页面只认 tftp 时用这一条）</label>\n        {0}\n        <p class=\"hint\">设备那一栏通常只填「文件名」或「地址 + 文件名」：<code>{1}固件名.bin</code> 这样接。\n          ★ TFTP 没有目录列表，文件名必须写全，写错就是「没有这个文件」。\n          69 号口绑不上（要更高权限）时，界面上会让它换一个端口，设备的地址栏能填端口就填上。</p></div>', [turls.map((u) => `<div style="margin-top:4px"><code style="user-select:all;cursor:cell">${esc(u)}</code></div>`).join(''), esc(turls[0] || '')]) : '', furls.length && serving ? t('<div style=\"margin-top:12px\"><label class=\"dim\">FTP 地址（交换机、老设备的配置/固件栏只认 ftp:// 时用这一条）</label>\n        {0}\n        <p class=\"hint\">多数设备的 ftp 栏要的是「地址 + 文件名」：<code>{1}固件名.bin</code> 这样接。\n          ★ 要用户名的地方随便填一个就行（这个共享不鉴权），密码同理 —— 别把你别的账号填进去。\n          主动模式（PORT）只允许连回它自己连进来的那个地址，隔着 NAT 的设备会取不到文件，那种设备请让它走 PASV。</p></div>', [furls.map((u) => `<div style="margin-top:4px"><code style="user-select:all;cursor:cell">${esc(u)}</code></div>`).join(''), esc(furls[0] || '')]) : '', factRows ? `<table style="margin-top:12px"><tr><th></th><th></th></tr>${factRows}</table>` : '', fsWarn(v.warnings), serving ? t('<div style=\"margin-top:12px\"><label class=\"dim\">谁在取、取走了什么（每 3 秒自己刷新）</label>\n        <div id=\"fs-ledger\">{0}</div></div>', [fsLedger(st.recent)]) : '', esc(JSON.stringify(v, null, 2))]);
  };

  const refresh = async (quiet) => {
    const r = await call('net.fileshare.status');
    if (!r.ok) {
      if (!quiet) out.innerHTML = t('<div class=\"empty\">看不了状态：{0}</div>', [esc(r.message || r.error)]);
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
      out.innerHTML = t('<div class=\"empty\">先写要共享哪个目录。只放要发出去的那些文件 —— ')
        + t('别把整个用户目录端出来（里面有 id_rsa、.env 这类东西）。</div>');
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
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消的话一个端口都不开）</div>');
    const r = await call('net.fileshare.serve', args);
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">没有开起来：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    paint(r.verdict, r.values || {});
    if (fsTimer) clearInterval(fsTimer);
    fsTimer = setInterval(() => refresh(true), 3000);
  };
  card.querySelector('#fs-refresh').onclick = () => refresh(true);
  card.querySelector('#fs-stop').onclick = async () => {
    btnStop.disabled = true;
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消就还开着）</div>');
    const r = await call('net.fileshare.stop');
    btnStop.disabled = false;
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">停不下来：{0}</div>', [esc(r.message || r.error)]);
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
 * ── 两台机器对测（net.throughput.*）──
 *
 * ★★ 这一页回答的是「这两台之间此刻能吃下多少」，而它必须单独成页：
 *   现场问「网太慢」的时候，前面那几页（ping、路径、端口）给的都是「通不通、多久」，
 *   没有一个能说出「一秒真过得去多少字节」。要问出这个数，得两头各跑一次这个工具 ——
 *   所以页面上就两张卡：这台开对测口，另一台连过来打。
 *
 * ★ 为什么两张卡都要人点头：开那半句改的是这台机器对外的可见面（同网段任何机器
 *   连上来都能让它收发字节，这一套协议不鉴权）；测那半句改的是这条链路
 *   （一秒的满速流量足够把现场正在跑的摄像头、PLC 轮询挤掉）。
 *
 * ★ 界面上不算任何东西：Mbps、字节数、往返、天花板都是后端给的数，
 *   这里只负责把「本机这一侧」和「对面那一侧」并排放，让人自己看见差。
 */

const THRU_CODE = {
  // 对测口那三问
  'thru-serving': [t('正在开着对测口'), 'ok'],
  'thru-idle': [t('没在开'), ''],
  'thru-stopped': [t('已经停掉了'), ''],
  // 打一次对测的十二档。★ 每一档的下一步都不一样，所以不许并成一句「测失败」。
  'thru-ok': [t('量到了，也稳'), 'ok'],
  'thru-loopback': [t('打在自己身上'), 'warn'],
  'thru-bufferbloat': [t('中间那台在囤包'), 'bad'],
  'thru-unstable': [t('一阵一阵'), 'warn'],
  'thru-window-limited': [t('卡在这条连接自己'), 'warn'],
  'thru-truncated': [t('被对面的闸截了'), 'warn'],
  'thru-dropped': [t('两端账对不上'), 'bad'],
  'thru-busy': [t('对面的口满了'), 'warn'],
  'thru-proto': [t('那端口不是这套协议'), 'bad'],
  'thru-closed': [t('对面没开对测口'), 'bad'],
  'thru-filtered': [t('一句不答（路上被静默丢掉）'), 'bad'],
  'thru-timeout': [t('连上了，问到一半超时'), 'warn'],
};

// 后端给的是「这块口凭什么选上」的原话，界面翻成人话，并把风险点一句带上：
// 指定网卡这条路绕开了默认路由，那块口连着谁只有现场的人知道。
const THRU_WHY = {
  '人指定的网卡': t('说的就是你指的那块口 ★ 这一条没照着默认路由挑，确认一下这块口连着谁'),
  'IPv4 默认路由走这块': t('按 IPv4 默认路由挑的（这台机器往上走的那块口）'),
  '本机只有一块带可用 IPv4 的网卡': t('自动挑的：本机只有这一块带可用的 IPv4 地址'),
};

// 内核那本账哪些字段这台给不了 —— 给不了就写出来，不许拿 0 冒充「没有重传」。
const THRU_NO_TCP = t('这台给不了');

let thruTimer = null;

async function renderThru(root) {
  root.appendChild(thruServeCard());
  root.appendChild(thruTestCard());
}

function thruSay(verdict, v) {
  const [title, cls] = THRU_CODE[verdict] || [verdict || t('没给判定'), ''];
  if (!title) return [t('后端给了一个这里还没认得的判定。'), ''];
  return [title, cls];
}

// thruChart 把每 200 毫秒一个点的那一列画出来。
//
// ★ 为什么非画不可：平均数会骗人 —— 稳定 900M 和 1800M/0 交替，平均值一模一样，
//   而这两种的下一步完全不同（前者查链路，后者查谁在抢这条路）。
//   ★ 落在那一段 0 的位置上要看得见：断流不是「慢」，是「没动」。
function thruChart(samples, word) {
  const s = (samples || []).filter((x) => x && typeof x.mbps === 'number');
  if (s.length < 2) {
    return s.length ? t('<p class=\"hint\">{0}：只取到 1 个点，画不出形状 —— ', [esc(word)])
      + t('秒数给到 5 秒以上才看得见稳态。</p>') : '';
  }
  const W = 560, H = 132, P = 28;
  const hi = Math.max(...s.map((x) => x.mbps)) * 1.15 || 1;
  const span = Math.max(1, s[s.length - 1].atMs || 1);
  const X = (at) => P + (at / span) * (W - 2 * P);
  const Y = (m) => H - P - (m / hi) * (H - 2 * P);
  let prev = null;
  const segs = [], dots = [], stops = [];
  for (const x of s) {
    const cx = X(x.atMs), cy = Y(x.mbps);
    if (x.mbps === 0) {
      // 这一格没动：线在这里断开，另画一个方块，别让它看着像「慢到 0」的一条斜线
      stops.push(`<rect x="${(cx - 3.5).toFixed(1)}" y="${(H - P - 3.5).toFixed(1)}" width="7" height="7"
          fill="var(--red-bg)" stroke="var(--red-line)"/>`);
      prev = null;
      continue;
    }
    if (prev) {
      segs.push(`<line x1="${prev[0].toFixed(1)}" y1="${prev[1].toFixed(1)}"
          x2="${cx.toFixed(1)}" y2="${cy.toFixed(1)}" stroke="var(--green-dim)" stroke-width="1.7"/>`);
    }
    dots.push(`<circle cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="2.6" fill="var(--green-dim)"/>`);
    prev = [cx, cy];
  }
  // ★ 宽高写死在属性上：这条线是画在 <td> 里的，百分比宽度在表格里会退成默认小图，
  //   曲线就细成一团 —— 而这一格要看的正是形状。
  return t('<svg viewBox=\"0 0 {0} {1}\" width=\"{2}\" height=\"{3}\"\n      style=\"max-width:100%;height:auto;display:block\"\n      role=\"img\" aria-label=\"{4}这一段一段的速率\">\n      <line x1=\"{5}\" y1=\"{6}\" x2=\"{7}\" y2=\"{8}\" stroke=\"var(--line)\"/>\n      {9}{10}{11}\n      <text x=\"{12}\" y=\"{13}\" fill=\"var(--muted)\" font-size=\"10\">{14} Mbps</text>\n      <text x=\"{15}\" y=\"{16}\" text-anchor=\"end\" fill=\"var(--muted)\" font-size=\"10\">\n        {17} 秒 · {18} 个点</text>\n      <text x=\"{19}\" y=\"{20}\" fill=\"var(--muted)\" font-size=\"10\">\n        方块 = 那 200 毫秒一个字节都没过</text>\n    </svg>', [W, H, W, H, esc(word), P, H - P, W - P, H - P, segs.join(''), dots.join(''), stops.join(''), P, P - 6, esc(hi.toFixed(0)), W - P, P - 6, (span / 1000).toFixed(1), s.length, P, H - P + 14]);
}

// 空载 / 带载 并排。★ 少了空载那一格，带载那个数就没有对照，
//   「涨了」和「一向就这么高」分不出来 —— 后端没量到时给的是 count=0，这里写「没问到」。
function thruRTT(v) {
  const one = (r, label) => {
    if (!r || !r.count) {
      return t('<div><label>{0}</label><div><span class=\"dim\">没问到</span></div></div>', [esc(label)]);
    }
    const f = (n) => (typeof n === 'number' ? n.toFixed(1) : '—');
    return t('<div><label>{0}</label>\n      <div><b>{1}</b> ms <span class=\"dim\">平均</span>\n        · 最快 {2} · 最慢 {3} · 抖动 {4}</div>\n      <div class=\"dim\">{5} 发{6}</div></div>', [esc(label), f(r.avgMs), f(r.minMs), f(r.maxMs), f(r.jitterMs), esc(r.count), r.fault ? t(' · 断在：') + esc(r.fault) : '']);
  };
  return t('<div class=\"row\" style=\"gap:22px;flex-wrap:wrap;margin-top:10px\">\n    {0}{1}\n  </div>\n  <p class=\"hint\">这两格是<strong>两条不同的线</strong>各量各的：复用正在传数据的那条量不出缓冲膨胀 ——\n    那 8 个字节排在几万个字节后面，量到的是队列深度，不是链路往返。\n    带载比空载涨几倍，现场的表现就是「带宽明明够，画面就是卡」。</p>', [one(v.idle, t('空载往返（没人打流的时候）')), one(v.loaded, t('带载往返（正在打流的时候）'))]);
}

// 一个方向的一行账：本机这侧与对面那侧并排放，差多少一眼看见。
function thruDirRow(word, d) {
  if (!d) return '';
  const num = (x, unit) => (x == null ? '<span class="dim">—</span>' : `<b>${esc(x)}</b>${unit}`);
  const gap = d.bytes > 0 && d.peerBytes > 0 && d.peerBytes !== d.bytes
    ? t('<span class=\"bad\">差 {0}</span>', [esc(fsSize(Math.abs(d.bytes - d.peerBytes)))]) : t('<span class=\"dim\">一致</span>');
  return `<tr>
    <td class="dim" style="white-space:nowrap"><b>${esc(word)}</b></td>
    <td>${num(d.mbps, ' Mbps')}<div class="dim">${esc(d.size || fsSize(d.bytes))} / ${esc(d.elapsedMs)} ms</div></td>
    <td>${num(d.peerMBps, ' Mbps')}<div class="dim">${esc(d.peerSize || fsSize(d.peerBytes))} / ${esc(d.peerElapsedMs)} ms</div></td>
    <td>${gap}${d.truncated ? t('<div class=\"warn\">被对面的字节闸截了</div>') : ''}</td>
    <td>${thruTCPCell(d)}</td>
  </tr>`;
}

// 曲线单独占一行，而且要**在 table 里面**：`<div>` 直接写进 `<table>` 会被浏览器
// 挪到表格外头（foster parenting），那张 200 毫秒一个点的图就会跑到看不见的位置上。
function thruChartRow(word, d) {
  if (!d || !d.samples || !d.samples.length) return '';
  return t('<tr><td class=\"dim\" style=\"white-space:nowrap\">这一向的形状</td>\n    <td colspan=\"4\" style=\"padding:4px 0 10px\">{0}</td></tr>', [thruChart(d.samples, word)]);
}

// 内核自己那本账：这一格说的不是「慢」，是「为什么慢」。
function thruTCPCell(d) {
  const t = d.tcp;
  if (!t || !t.given) {
    return `<span class="dim">${esc(THRU_NO_TCP)}${t && t.why ? t('：') + esc(t.why) : ''}</span>`;
  }
  const f = (n, unit) => (typeof n === 'number' ? `${esc(n.toFixed ? n.toFixed(1) : n)}${unit}` : '<span class="dim">—</span>');
  return t('<div>往返估计 {0} · 重传 {1} 段</div>\n    <div class=\"dim\">拥塞窗口 {2}\n      {3}</div>\n    <div class=\"dim\">{4}</div>', [f(t.srttMs, ' ms'), esc(t.retransSegments || 0), esc(fsSize(t.sndCwndBytes || 0)), typeof d.ceilingMbps === 'number' ? t(' · 这条连接的顶约 {0} Mbps', [esc(d.ceilingMbps.toFixed(0))]) : '', esc(d.tcpSource ? t('取自 ') + d.tcpSource : '')]);
}

function thruLedger(recent) {
  const rows = (recent || []).map((s) => `<tr>
    <td class="dim">${esc((s.endedAt || '').replace('T', ' ').slice(0, 19))}</td>
    <td><code>${esc(s.peer || '—')}</code></td>
    <td class="dim">${esc({ up: t('它往外打'), down: t('它收'), ping: t('只量往返') }[s.mode] || t('没说模式'))}</td>
    <td>${esc(fsSize(s.bytes || 0))}</td>
    <td class="dim">${typeof s.mbps === 'number' ? esc(s.mbps.toFixed(0)) + ' Mbps' : '—'}</td>
    <td class="${s.fault ? 'bad' : ''}">${esc(s.fault || t('跑完了'))}</td>
  </tr>`).join('');
  if (!rows) return t('<p class=\"hint\">还没有谁来连过这个口。</p>');
  return t('<div style=\"max-height:260px;overflow:auto\"><table>\n    <tr><th>什么时候</th><th>谁连的</th><th>哪一向</th><th>过了多少</th><th>速率</th><th>结果</th></tr>\n    {0}</table></div>\n    <p class=\"hint\">只留最近 20 路，跑砸的那些也在里面（★ 排查「另一台说连不上 / 连上就断」就靠这一列）。</p>', [rows]);
}

function thruServeCard() {
  const card = $(t('<div class=\"card\">\n    <h2>本机对测口 <span id=\"th-top\"></span></h2>\n    <p class=\"hint\">在这台机器上开一个局域网对测口，另一台 NetKit 用下面那张卡连过来打一轮 ——\n      两头各记一份账，才知道「这两台之间此刻能吃下多少」。\n      ★ 这不是 iperf3，也不听别的协议：回的不是这一套的第一句就被拒掉。\n      ★ 只绑你挑的那块网卡上的地址，<strong>不绑 0.0.0.0</strong> ——\n      多网卡机器上那等于把对测口从办公网甚至公网那块口也开出去。\n      ★ 这个口<strong>不鉴权</strong>：开着的时候同网段任何机器连上来都能让这台机器收发字节，\n      拦住它的是三道闸（一路最多多少字节、同时几路、每路最长 5 分钟）。\n      所以每次开都要你点头，用完请点停掉。</p>\n    <div class=\"row\">\n      <div style=\"flex:0 0 170px\"><label>开在哪块网卡（留空自动）</label>\n        <input id=\"th-iface\" placeholder=\"en0 / eth0 / WLAN\"></div>\n      <div style=\"flex:1 1 240px\"><label>或者只绑这几个地址（填了就覆盖上面那块网卡）</label>\n        <input id=\"th-addrs\" placeholder=\"192.168.1.20 fd00::1（不许写 0.0.0.0）\"></div>\n      <div style=\"flex:0 0 100px\"><label>端口</label>\n        <input id=\"th-port\" placeholder=\"5201\"></div>\n      <div style=\"flex:0 0 130px\"><label>一路最多（GiB）</label>\n        <input id=\"th-max\" placeholder=\"默认 16\"></div>\n      <div style=\"flex:0 0 110px\"><label>同时几路</label>\n        <input id=\"th-sess\" placeholder=\"默认 4\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn danger\" id=\"th-go\">开对测口</button></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <div style=\"flex:0 0 auto;min-width:0\">\n        <button class=\"btn\" id=\"th-refresh\">刷新台账</button>\n        <button class=\"btn danger\" id=\"th-stop\" style=\"display:none\">立刻停掉</button></div>\n    </div>\n    <div id=\"th-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#th-out');
  const top = card.querySelector('#th-top');
  const btnStop = card.querySelector('#th-stop');

  const paint = (verdict, v) => {
    const [title, cls] = thruSay(verdict, v);
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
    btnStop.style.display = verdict === 'thru-serving' ? '' : 'none';
    const serving = verdict === 'thru-serving';
    const st = v.status || v;
    const port = v.port || st.port || 0;
    const addrs = (v.addrs && v.addrs.length ? v.addrs : st.addrs) || [];
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--sunken)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--line)';

    let say;
    if (verdict === 'thru-idle') {
      say = t('现在没开着。对面连过来会得到「明确拒绝」。要量就先开一下，用完停掉 —— ')
        + t('这一口不鉴权。');
    } else if (verdict === 'thru-stopped') {
      say = t('{0} 的 {1} 端口已经放掉，', [addrs.map((x) => `<code>${esc(x)}</code>`).join(t('、')), port])
        + t('同网段连不上来了。这中间一共过了 {0}、{1} 路。', [esc(fsSize(v.servedBytes || 0)), v.sessions || 0])
        + t('跑完的那些账还在下面的「最近」里（停口不清账）。');
    } else if (serving) {
      say = t('对测口正开着：{0}', [v.iface ? t('网卡 <b>{0}</b>（{1}），', [esc(v.iface), esc(THRU_WHY[v.ifaceWhy] || v.ifaceWhy || t('怎么定的没说'))]) : ''])
        + t('绑 {0} 端口 {1}。', [addrs.map((x) => `<code>${esc(x)}</code>`).join(t('、')), port || '—'])
        + t('★ 一路最多 {0}、同时 {1} 路、每路最长 5 分钟。', [esc(fsSize(v.maxBytes || 0)), esc(v.maxSessions || 0)]);
    } else {
      say = t('后端给了一个这里还没认得的判定，原文在下面展开看。');
    }

    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      {4}\n      {5}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{6}</pre></details>', [bg, line, say, serving ? t('<div style=\"margin-top:12px\"><label class=\"dim\">对面那台怎么填</label>\n        <div style=\"margin-top:4px\"><code style=\"user-select:all;cursor:cell\">{0}</code></div>\n        <p class=\"hint\">★ 两端必须是同一个端口号，地址要用<strong>对面那块口到得了的那一个</strong>（隔着 VLAN 就连不通）。\n          对面那台上开的是它自己的口，两台别互相填成自己的地址 —— 那会量成「打在自己身上」。</p></div>', [esc(v.peerHelp || '')]) : '', serving ? t('<table style=\"margin-top:12px\"><tr><th></th><th></th></tr>\n        <tr><td class=\"dim\">一共过了多少字节</td><td><b>{0}</b>\n          <span class=\"dim\">★ 这一格是「这口被人当炮使了多久」的唯一证据</span></td></tr>\n        <tr><td class=\"dim\">此刻在跑</td><td>{1}</td></tr>\n        <tr><td class=\"dim\">字节闸 / 路数闸</td><td>{2} / {3} 路\n          <span class=\"dim\">· 每路最长 5 分钟</span></td></tr>\n        </table>\n        <div style=\"margin-top:12px\"><label class=\"dim\">最近跑过哪几路（每 3 秒自己刷新）</label>\n          <div id=\"th-ledger\">{4}</div></div>', [esc(v.servedSize || fsSize(v.servedBytes || 0)), st.active ? t('<b class=\"warn\">第 {0} 路正在跑</b>', [esc(st.active)]) : t('<span class=\"dim\">没人连着</span>'), esc(fsSize(v.maxBytes || 0)), esc(v.maxSessions || 0), thruLedger(st.recent)]) : '', !serving && v.recent && v.recent.length ? t('<div style=\"margin-top:12px\">\n        <label class=\"dim\">最后跑过的那几路（口停了，账还在 —— 刚跑砸的那一路就靠这一列认）</label>\n        <div id=\"th-ledger\">{0}</div></div>', [thruLedger(v.recent)]) : '', esc(JSON.stringify(v, null, 2))]);
  };

  const refresh = async (quiet) => {
    const r = await call('net.throughput.status');
    if (!r.ok) {
      if (!quiet) out.innerHTML = t('<div class=\"empty\">看不了状态：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    paint(r.verdict, r.values || {});
    if (r.verdict === 'thru-serving') {
      if (thruTimer) clearInterval(thruTimer);
      thruTimer = setInterval(() => refresh(true), 3000);
    } else if (thruTimer) {
      clearInterval(thruTimer);
      thruTimer = null;
    }
  };

  card.querySelector('#th-go').onclick = async () => {
    const args = {};
    const iface = card.querySelector('#th-iface').value.trim();
    const addrs = card.querySelector('#th-addrs').value.split(/[\s,、]+/).filter(Boolean);
    const port = card.querySelector('#th-port').value.trim();
    const max = card.querySelector('#th-max').value.trim();
    const sess = card.querySelector('#th-sess').value.trim();
    if (iface) { args.iface = iface; }
    if (addrs.length) { args.addrs = addrs; }
    if (port) { args.port = Number(port); }
    // 界面上按 GiB 收，换成字节交给后端去夹（这里替它猜一个号等于人没同意过的闸）
    if (max) { args.maxBytes = Math.round(Number(max) * 1024 * 1024 * 1024); }
    if (sess) { args.maxSessions = Number(sess); }
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消的话一个端口都不开）</div>');
    const r = await call('net.throughput.serve', args);
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">没有开起来：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    paint(r.verdict, r.values || {});
    if (thruTimer) clearInterval(thruTimer);
    thruTimer = setInterval(() => refresh(true), 3000);
  };
  card.querySelector('#th-refresh').onclick = () => refresh(true);
  card.querySelector('#th-stop').onclick = async () => {
    btnStop.disabled = true;
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消就还开着）</div>');
    const r = await call('net.throughput.stop');
    btnStop.disabled = false;
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">停不下来：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    if (thruTimer) { clearInterval(thruTimer); thruTimer = null; }
    paint(r.verdict, r.values || {});
  };
  refresh(true);   // 只读一次状态，不动系统：进页面就要看得见「现在开着没有」
  return card;
}

function thruTestCard() {
  const card = $(t('<div class=\"card\">\n    <h2>打一次对测 <span id=\"tx-top\"></span></h2>\n    <p class=\"hint\">连到<strong>另一台</strong>开着对测口的 NetKit，量「这两台之间此刻能吃下多少」。\n      ★ 这一发会把这条链路推到接近满好几秒：现场正跑着摄像头、PLC 轮询的时候别打，\n      所以它要人点头。\n      ★ 对端填本机自己的地址会单独判成「打在自己身上」—— 那个数几百 G 也很正常，\n      量的却是这台机器的协议栈，跟链路一点关系都没有。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 240px\"><label>对面那台的地址</label>\n        <input id=\"tx-host\" placeholder=\"192.168.1.30 或 192.168.1.30:5201\"></div>\n      <div style=\"flex:0 0 100px\"><label>端口</label>\n        <input id=\"tx-port\" placeholder=\"5201\"></div>\n      <div style=\"flex:0 0 170px\"><label>方向</label>\n        <select id=\"tx-mode\">\n          <option value=\"both\">两向各一轮（默认）</option>\n          <option value=\"up\">本机往外打</option>\n          <option value=\"down\">本机收</option>\n        </select></div>\n      <div style=\"flex:0 0 110px\"><label>每向几秒（1–10）</label>\n        <input id=\"tx-secs\" placeholder=\"默认 3\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn danger\" id=\"tx-go\">打一次对测</button></div>\n    </div>\n    <div id=\"tx-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#tx-out');
  const top = card.querySelector('#tx-top');
  const go = card.querySelector('#tx-go');

  // note 是后端那句账（跑砸的那几档，值里根本没有 up/down，话全在 note 上）
  const paint = (verdict, v, note) => {
    const [title, cls] = thruSay(verdict, v);
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
    const say = note || v.verdictReason || t('后端没给这句话。');
    const dirRows = [thruDirRow(t('往外打'), v.up), thruChartRow(t('往外打'), v.up),
      thruDirRow(t('收'), v.down), thruChartRow(t('收'), v.down)].join('');
    // ★ 这张表全是这里写死的句子（一个字节都不是对面发来的），所以不进 esc ——
    //   它带的就是「下一步去动哪一头」，界面上必须看得见。
    const hint = {
      'thru-loopback': t('★ 这一发打在自己身上：把数拿去说「链路行/不行」都是错的，')
        + t('要在<strong>另一台</strong>上开对测口再来问一次。'),
      'thru-window-limited': t('想问出更高的数：换多路并发分别打（这一条连接的窗口就是这么多，链路还没饱和）。'),
      'thru-truncated': t('对面那台的字节闸开小了。在那台上把「一路最多」放大再打一次，才是这条链路的真数。'),
      'thru-bufferbloat': t('带宽这一项是够的，卡在中间那台的队列上：去看路上那台的限速/队列配置，别再往两端找。'),
      'thru-dropped': t('先把「这条链路在吞数据」这件事查掉（网线、协商速率、中间那台丢包），快慢的数等账对上再看。'),
      'thru-filtered': t('这一条先去查防火墙/ACL：连机器在不在都不知道，别去重启那台。'),
      'thru-closed': t('那台机器是活的，只是没开对测口 —— 去那台上点一下「开对测口」。'),
      'thru-proto': t('端口填错或那台上跑着别的服务（iperf3 也会落在这一格）。两端要填同一个号。'),
      'thru-busy': t('对面的口同时跑的路数满了：等几秒再问，或去那台上把没在用的会话停掉。'),
      'thru-timeout': t('连上了却没问到话：先看那台上是不是正有人在打流，再怀疑中间设备。'),
    }[verdict];

    out.innerHTML = v && (v.up || v.down) ? t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      {4}\n      <table style=\"margin-top:12px\">\n        <tr><th></th><th>本机这侧</th><th>对面那侧</th><th>两端账</th><th>内核那本账</th></tr>\n        {5}\n      </table>\n      <p class=\"hint\">两列各是一份账：<strong>「本机这侧」是我数到的，「对面那侧」是对方数到的</strong>。\n        发送侧写完而接收侧收得少，说明东西堆在本机的发送缓冲里，链路其实没吃下那么多。\n        ★ 对面回执里写了它自己的字节闸：{6}{7}。\n        {8}</p>\n      {9}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{10}</pre></details>', [bg, line, esc(say), hint ? `<div style="margin-top:8px;font-size:13px">${hint}</div>` : '', v.fault ? t('<p class=\"hint\">断在哪：{0}</p>', [esc(v.fault)]) : '', dirRows, esc(v.peerMaxSize || fsSize(v.peerMaxBytes || 0)), v.peerMaxBytes ? '' : t('（没问到）'), v.seconds ? t('{0} 秒/向，模式 {1}。', [esc(v.seconds), esc(v.mode === 'both' ? t('两向各一轮') : v.mode)]) : '', thruRTT(v), esc(JSON.stringify(v, null, 2))]) : t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      {3}\n      {4}\n      {5}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{6}</pre></details>', [bg, line, esc(note || v.verdictReason || t('这一发没跑成，下面带的是已经拿到的东西。')), hint ? `<div style="margin-top:8px;font-size:13px">${hint}</div>` : '', v.fault ? t('<p class=\"hint\">断在哪：{0}</p>', [esc(v.fault)]) : '', v.addr ? t('<p class=\"hint\">问的是 <code>{0}</code>。★ 这一格说的是「连到哪儿没成」，不是链路慢。</p>', [esc(v.addr)]) : '', esc(JSON.stringify(v, null, 2))]);
  };

  go.onclick = async () => {
    const host = card.querySelector('#tx-host').value.trim();
    if (!host) {
      out.innerHTML = t('<div class=\"empty\">先填对面那台的地址 —— 就是它开对测口时报出来的那几个地址之一。</div>');
      return;
    }
    const args = { host, mode: card.querySelector('#tx-mode').value };
    const port = card.querySelector('#tx-port').value.trim();
    const secs = card.querySelector('#tx-secs').value.trim();
    if (port) { args.port = Number(port); }
    if (secs) { args.seconds = Number(secs); }
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（这一发会把链路占住几秒，取消就什么都不打）</div>');
    go.disabled = true;
    const r = await call('net.throughput.test', args);
    go.disabled = false;
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">没打成：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
  };
  card.querySelector('#tx-host').onkeydown = (e) => { if (e.key === 'Enter') go.click(); };
  out.innerHTML = t('<div class=\"empty\">对面那台先开对测口（它屏幕上就是上面那张卡），')
    + t('把它报出来的地址填进来。★ 别填这台自己的地址。</div>');
  return card;
}

/*
 * ── 出去公网有多快（net.speed.test）──
 *
 * ★★ 这一页回答的是「出去公网关没关、有多快」，跟上面那张对测不重复：
 *   对测量的是内圈（这两台之间），它量不到出口那条路；
 *   而浏览器只会说「加载失败」，不会说它当时走的是 v4 还是 v6。
 *
 * ★★ 界面上没有、也不许有「一键测速」：这一张不预设任何测速服务器。
 *   填了目标才动，没填就判 speed-no-target，一个包都不替你发 ——
 *   这个软件不替用户去碰别人家的机器。
 *
 * ★ 两栈的数并排放，不平均：绑名字去连时栈由系统挑，
 *   现场最常见的「v6 路由不通所以整体慢」正好被平均掉。
 */

const SPEED_CODE = {
  'speed-no-target': [t('没给目标'), ''],
  'speed-local-target': [t('量的是内网，不是公网'), 'warn'],
  'speed-unreachable': [t('一次都没连上'), 'bad'],
  'speed-flaky': [t('这条路本身在抖'), 'bad'],
  'speed-bad-status': [t('目标回的不是数据'), 'bad'],
  'speed-cut-short': [t('搬到一半断了'), 'bad'],
  'speed-capped': [t('这个数是下界'), 'warn'],
  'speed-latency-only': [t('只量到往返'), 'warn'],
  'speed-one-sided': [t('只量到一头'), 'warn'],
  'speed-single-family': [t('只有一条栈量到'), 'warn'],
  'speed-ok': [t('量到了'), 'ok'],
};

// 每一头收尾的原因。★ 「读完了」和「到点收的」给出同一个数，前者是实测后者是下界，
//   界面必须分开写，不然人拿下界去对运营商的合同。
const SPEED_END = {
  'complete': [t('搬完了'), 'ok'],
  'time-cap': [t('秒数到点收的'), 'warn'],
  'byte-cap': [t('字节闸到点收的'), 'warn'],
  'cut': [t('中途断了'), 'bad'],
  'failed': [t('没搬成'), 'bad'],
};

const SPEED_ERR = {
  'refused': [t('那一口关着'), 'bad'],
  'timeout': [t('一声不响'), 'bad'],
  'tls': [t('TLS 没谈成'), 'bad'],
  'other': [t('连着就没下文'), 'bad'],
};

// 每栈的那句下一步 —— 判定不是错误，但每条都得告诉人下一步动哪一头。
const SPEED_WAY = {
  'speed-no-target': t('填一个<strong>公网上</strong>能下载的地址（http/https）再问；只想问往返就填一个 host。'),
  'speed-local-target': t('★ 这个数不能拿去答「出去公网关没关」。把目标换成公网上的一个地址；')
    + t('确实要量内网那一跳，就勾上下面那个开关，但那是一台机器到另一台机器的数。'),
  'speed-unreachable': t('先别问快慢：用「ping 与端口」那张卡看那个 IP 在不在、那个端口开不开。')
    + t('关着与一声不响是两种病，值里那两栏已经分开了。'),
  'speed-flaky': t('连得上但有几发没通：去看出口设备和链路（拔一下网线、换一个口），')
    + t('速率那一栏只能当下限。'),
  'speed-bad-status': t('目标回的是错误页不是数据，这一趟的数不代表链路 —— 先把那个地址本身弄对')
    + t('（它可能要点登录、可能过期了、可能压根不给直接下载）。'),
  'speed-cut-short': t('搬到一半断了：这多半就是现场要找的那个病。去看路上谁在掐长连接')
    + t('（NAT 超时、防火墙会话、SSL 中间设备）。'),
  'speed-capped': t('这一趟是被秒数或字节闸收的，不是搬完了 —— 想看到顶，把秒数和上限一起加大再问一次。'),
  'speed-latency-only': t('只填了 host，所以只量到往返。要知道快慢，再填一个能下载的地址。'),
  'speed-one-sided': t('另一头没测到：要么没填那一头的地址，要么填了但它自己没通 —— 值里那一栏是空的还是 failed，一眼看得见。'),
  'speed-single-family': t('没测到那条栈不是坏了，是这个名字没写那一栈的记录。')
    + t('如果现场本来就该有 v6，去「双栈体检」那张卡看这台机器的 v6 出不出得去。'),
};

function renderSpeed(root) {
  root.appendChild(speedCard());
}

function speedCard() {
  const card = $(t('<div class=\"card\">\n    <h2>量一次公网 <span id=\"sp-top\"></span></h2>\n    <p class=\"hint\">往<strong>你填的那个地址</strong>量四件事：下载多快、上传多快、往返多少毫秒、往返抖不抖。\n      IPv4 与 IPv6 各钉一条栈单独量，两本账并排放 ——\n      ★ 绑名字去连时栈由系统挑，混在一个数里，「v6 不通所以整体慢」就会被平均掉。\n      ★ 这里<strong>不预设任何测速服务器</strong>：没填目标就判「没给目标」，一个包都不替你发。\n      下载读到的正文直接丢掉（不落盘、不上传给任何人）；上传发的是<strong>纯填充字节</strong>，\n      不含本机任何内容，但对面可能把它存下来 —— 所以这一张要点批准。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 260px\"><label>下载地址（量下载与往返）</label>\n        <input id=\"sp-url\" placeholder=\"https://下载.example/文件.zip\"></div>\n      <div style=\"flex:1 1 200px\"><label>上传地址（收 POST 的，选填）</label>\n        <input id=\"sp-ul\" placeholder=\"https://same.example/upload\"></div>\n      <div style=\"flex:1 1 160px\"><label>或者只填一个 host（只量往返）</label>\n        <input id=\"sp-host\" placeholder=\"example.com 或 203.0.113.9:443\"></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <div style=\"flex:0 0 130px\"><label>量哪条栈</label>\n        <select id=\"sp-fam\">\n          <option value=\"auto\">v4 与 v6 各一遍（默认）</option>\n          <option value=\"v4\">只量 IPv4</option>\n          <option value=\"v6\">只量 IPv6</option>\n        </select></div>\n      <div style=\"flex:0 0 110px\"><label>每头几秒（1–30）</label>\n        <input id=\"sp-secs\" placeholder=\"默认 5\"></div>\n      <div style=\"flex:0 0 120px\"><label>每头上限 MiB</label>\n        <input id=\"sp-max\" placeholder=\"默认 64\"></div>\n      <div style=\"flex:0 0 120px\"><label>往返打几发</label>\n        <input id=\"sp-conns\" placeholder=\"默认 10\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn danger\" id=\"sp-go\">量一次</button></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <label class=\"dim\" style=\"display:flex;gap:6px;align-items:center;font-size:13px\">\n        <input type=\"checkbox\" id=\"sp-priv\" style=\"width:auto\"> 目标是内网/本机地址时也照量\n        <span class=\"dim\">（默认不发：拿内网的数答「公网关没关」是错的，默认往现场设备打几十 MiB 更是错的）</span>\n      </label>\n    </div>\n    <div id=\"sp-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#sp-out');
  const top = card.querySelector('#sp-top');
  const go = card.querySelector('#sp-go');

  go.onclick = async () => {
    const args = {};
    const grab = (id, key) => {
      const s = card.querySelector(id).value.trim();
      if (s) { args[key] = s; }
    };
    grab('#sp-url', 'url');
    grab('#sp-ul', 'uploadUrl');
    grab('#sp-host', 'host');
    args.family = card.querySelector('#sp-fam').value;
    const secs = card.querySelector('#sp-secs').value.trim();
    const max = card.querySelector('#sp-max').value.trim();
    const conns = card.querySelector('#sp-conns').value.trim();
    if (secs) { args.seconds = Number(secs); }
    if (max) { args.maxMiB = Number(max); }
    if (conns) { args.connects = Number(conns); }
    if (card.querySelector('#sp-priv').checked) { args.allowPrivate = true; }

    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（批准框里逐条写着往哪儿发多少；取消就一个包都不发）</div>');
    go.disabled = true;
    const r = await call('net.speed.test', args);
    go.disabled = false;
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">没量成：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    speedPaint(r.verdict, r.values || {}, r.note, card);
  };
  out.innerHTML = t('<div class=\"empty\">填一个公网上能下载的地址 —— 或者只填一个 host，那只量往返。')
    + t('<strong>别填内网地址</strong>：默认那一趟一个字节都不发。</div>');
  return card;
}

function speedPaint(verdict, v, note, card) {
  const sides = v.sides || [];
  // ★ 同一个码有两种现场：内网那台**真量了**（勾了开关），和压根**一个字节都没发**（默认）。
  //	标题说「量的是内网」而表里什么都没有，人就来回翻那个开关 —— 这两句得分开说。
  const ranAny = sides.some((s) => !s.skipped);
  let [title, cls] = SPEED_CODE[verdict] || [verdict || t('没给判定'), ''];
  let way = SPEED_WAY[verdict];
  if (verdict === 'speed-local-target' && !ranAny) {
    title = t('目标是内网，一个字节都没发');
    way = t('这一趟照默认收了手，所以<strong>没有数</strong>（不是量出来是 0）。要答「出去公网关没关」，')
      + t('把目标换成公网上的一个地址；确实要量本机到这一台，勾上下面那个开关再问一次。');
  }
  // ★ 「只有一条栈量到」听着像另一条量出了别的数；ran==0 那一档是两条都没发，标题得先说没数。
  if (verdict === 'speed-single-family' && !ranAny) {
    title = t('那条栈没地址，一个连接都没发');
  }
  const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
  const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
  card.querySelector('#sp-top').innerHTML = title
    ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
  const say = note || v.verdictReason || t('后端没给这句话。');
  card.querySelector('#sp-out').innerHTML = t('\n    <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n      {2}</div>\n    {3}\n    <p class=\"hint\">问的是 <code>{4}</code> 端口 {5}\n      · {6}\n      · 每头最长 {7} 秒 / {8} MiB · 往返 {9} 发。\n      ★ 秒数那道闸只管搬数据那一段，建连与 TLS 握手另算。</p>\n    {10}\n    <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n      <pre class=\"dim\">{11}</pre></details>', [bg, line, esc(say), way ? `<div style="margin-top:8px;font-size:13px">${way}</div>` : '', esc(v.target || '—'), esc(v.port || '—'), esc(v.family === 'auto' ? t('v4 与 v6 各一遍') : v.family || '—'), esc(v.seconds), esc(v.maxMiB), esc(v.connects), sides.length ? t('<table style=\"margin-top:8px\">\n      <tr><th>栈</th><th>落到的地址</th><th>往返</th><th>下载</th><th>上传</th></tr>\n      {0}</table>', [sides.map(speedSideRow).join('')]) : '', esc(JSON.stringify(v, null, 2))]);
}

function speedSideRow(s) {
  const fam = s.family === 'v4' ? 'IPv4' : s.family === 'v6' ? 'IPv6' : esc(s.family);
  if (s.skipped === 'no-address') {
    return t('<tr><td><b>{0}</b></td><td colspan=\"4\"><span class=\"dim\">这个名字在那条栈里没有地址', [fam])
      + t(' —— 那一栈没量到，不是量出 0。</span></td></tr>');
  }
  if (s.skipped === 'local') {
    return t('<tr><td><b>{0}</b></td><td><code>{1}</code></td>\n      <td colspan=\"3\"><span class=\"warn\">解出来是内网/本机地址，默认一个字节都没发</span></td></tr>', [fam, esc(s.addr)]);
  }
  const addr = `<code>${esc(s.addr)}</code>${s.private ? t(' <span class=\"warn\">内网</span>') : ''}`;
  const lat = s.latency;
  let latCell = t('<span class=\"dim\">没问到</span>');
  if (lat) {
    const f = (n) => (typeof n === 'number' ? esc(n.toFixed(2)) : '—');
    const tries = t('<div class=\"dim\">{0}/{1} 发连上', [esc(lat.connected), esc(lat.sent)])
      + `${lat.refused ? t(' · <span class=\"bad\">拒 {0}</span>', [esc(lat.refused)]) : ''}`
      + `${lat.timedOut ? t(' · <span class=\"bad\">没声 {0}</span>', [esc(lat.timedOut)]) : ''}`
      + `${lat.untried ? t(' · 提前收表没发 {0}', [esc(lat.untried)]) : ''}</div>`;
    if (!lat.connected) {
      // ★ 一发都没连上时不许摆一排 0.00：那是「没问到」，摆成数就有人拿 0 ms 去说「这条路很快」。
      latCell = t('<span class=\"bad\">一发都没连上，没有往返可报</span>') + tries;
    } else {
      const bad = lat.sent > lat.connected;
      latCell = t('<b>{0}</b> ms <span class=\"dim\">中位</span>\n        <div class=\"dim\">最快 {1} · 平均 {2} · P95 {3} · 最慢 {4}</div>\n        <div class=\"dim\">抖动 {5} ms</div>{6}\n        {7}', [f(lat.medMs), f(lat.minMs), f(lat.avgMs), f(lat.p95Ms), f(lat.maxMs), f(lat.jitterMs), tries, bad ? t('<div class=\"bad\">这几发没通本身就是结论：这条路在抖</div>') : '']);
    }
  }
  return `<tr><td><b>${fam}</b></td><td>${addr}</td><td>${latCell}</td>
    <td>${speedXfer(s.download)}</td><td>${speedXfer(s.upload)}</td></tr>`;
}

function speedXfer(x) {
  if (!x) return t('<span class=\"dim\">没给这一头的地址</span>');
  const [ew, ec] = SPEED_END[x.end] || [x.end || t('没说'), ''];
  const [kw, kc] = x.errKind ? (SPEED_ERR[x.errKind] || [x.errKind, '']) : ['', ''];
  const mbps = typeof x.mbps === 'number' ? `<b>${esc(x.mbps.toFixed(1))}</b> Mbps` : '—';
  const f = (n) => (typeof n === 'number' ? esc(n) : '—');
  return `${mbps} <span class="${ec}">${esc(ew)}</span>
    <div class="dim">${esc(fsSize(x.bytes || 0))} / ${f(x.ms)} ms
      ${typeof x.ttfbMs === 'number' ? t(' · 等首字节 {0} ms', [esc(x.ttfbMs.toFixed(2))]) : ''}
      ${x.contentLength ? t(' · 它说这份 {0}', [esc(fsSize(x.contentLength))]) : ''}
      ${x.status ? t(' · 回 {0}', [f(x.status)]) : ''}</div>
    ${kw ? `<div class="${kc}">${esc(kw)}</div>` : ''}
    ${x.error ? `<div class="dim">${esc(x.error)}</div>` : ''}`;
}

/*
 * ── 盯一段时间（net.quality.*）──
 *
 * ★★ 这一页回答的是「那一段时间到底怎么样」，不是「此刻怎么样」。
 *   前面两页量的都是现在这一秒（对测、公网），而现场最常见的说法是
 *   「偶尔卡一下，你去的时候它又是好的」—— 那一句只能靠一本按窗记下来的账去问。
 *
 * ★ 开这一路要人点头：它是后台持续发包 + 一直写文件，一开就是几十分钟起步，
 *   没人点「停」它就一直在发（[OTS-7.1]）。
 *
 * ★★ 界面上一处都不算：丢包率、中位、抖动、断档、被截过，全是后端从那本账里算好的。
 *   图上那一格和判定点名的那一窗必须同源，否则人看完图再看结论就对不上，
 *   对不上一次，这张图以后就没人信了。
 *
 * ★ 断档画成缺口，不许连一条落到 0 的斜线：那一段是「没问到」，不是「慢到 0」。
 *   画成后者等于凭空造一个现场没有的故障 —— 和对测那张图的方块同一条线。
 */

const QUALITY_STATE = {
  'quality-running': [t('正在盯'), 'ok'],
  'quality-idle': [t('没在跑'), ''],
  'quality-stopped': [t('停掉了，账还在'), ''],
  'quality-barred': [t('包发不出去'), 'bad'],
  'quality-ledger-blocked': [t('账写不下去'), 'bad'],
};

// 读一本账的七档。★ 每一档的下一步不一样，所以不许并成一句「有问题」。
const QUALITY_READ = {
  'quality-stable': [t('这些窗里没毛病'), 'ok'],
  'quality-loss': [t('有窗在丢包'), 'warn'],
  'quality-flapping': [t('通断交替'), 'bad'],
  'quality-rtt-rise': [t('往返在往上走'), 'warn'],
  'quality-gap': [t('留痕有断档'), 'warn'],
  'quality-truncated': [t('看到的不是全程'), 'warn'],
  'quality-barred': [t('这本账全是包没出去'), 'bad'],
  'quality-idle': [t('还没有账可读'), ''],
};

let qualityTimer = null;
let qualityPick = null;   // 状态卡上的「读这本账」按下去，填进报表卡

async function renderQuality(root) {
  root.appendChild(qualityWatchCard());
  root.appendChild(qualityReportCard());
}

const qHms = (s) => (s ? String(s).replace('T', ' ').slice(11, 19) : '—');

// qDur 与后端 note 里那个 humanDur 同一个口径：整刻度不写小数点。
// ★ 这里显示的是「你选的刻度」，不是量出来的数 —— 「每 5.0 秒一窗」让人以为
//   刻度本身在抖，而 500.0 毫秒这种写法 nobody reads。
const qDur = (ms) => {
  const a = Math.round(Math.abs(Number(ms) || 0));
  if (a < 1000) return t('{0} 毫秒', [a]);
  if (a < 60000 && a % 1000 === 0) return t('{0} 秒', [a / 1000]);
  return humanMs(a);
};

/**
 * qualityChart 一本账两条线：上面是每窗中位往返，下面是每窗丢包率。
 *
 * ★ 为什么两条一起画：只看往返会把「全丢」画成没有点（图上是一段空白），
 *   只看丢包会把「越来越慢」看不出来 —— 现场那两种病的下一步完全不同。
 */
function qualityChart(recs) {
  const rs = (recs || []).filter((x) => x && x.startAt && x.endAt);
  if (!rs.length) return '';
  if (rs.length < 2) {
    return t('<p class=\"hint\">只有一窗，画不出形状 —— 一窗是一段时间的平均，')
      + t('至少两窗才看得见「变没变」。多等一窗，或者把窗口调短。</p>');
  }
  const W = 620, H = 208, PL = 46, PR = 14, TOP = 30, MID = 122, BOT = 190;
  const t0 = Date.parse(rs[0].startAt);
  const t1 = Date.parse(rs[rs.length - 1].endAt);
  const span = Math.max(1, t1 - t0);
  const X = (t) => PL + ((t - t0) / span) * (W - PL - PR);
  const hi = Math.max(...rs.map((x) => Number(x.medianMs) || 0)) * 1.2 || 1;
  const Y = (v) => MID - (v / hi) * (MID - TOP);
  const segs = [], dots = [], holes = [], bars = [], lost = [];
  let prev = null, prevEnd = null;
  for (const x of rs) {
    const a = Date.parse(x.startAt), b = Date.parse(x.endAt);
    const bw = Math.max(2.5, X(b) - X(a) - 1);
    // 两窗之间空了一大段：那是「没采到」，先把缺口画出来，再把线断掉。
    if (prevEnd !== null && a - prevEnd > (Number(x.windowMs) || 0) * 1.6) {
      holes.push(`<rect x="${X(prevEnd).toFixed(1)}" y="${TOP}" width="${(X(a) - X(prevEnd)).toFixed(1)}"
          height="${MID - TOP}" fill="var(--sunken)" stroke="var(--line)" stroke-dasharray="3 3"/>`);
      prev = null;
    }
    const sent = Number(x.sent) || 0, recv = Number(x.recv) || 0;
    const lp = Number(x.lossPercent) || 0;
    if (lp > 0) {
      const h = Math.max(2, (lp / 100) * (BOT - MID - 16));
      bars.push(`<rect x="${X(a).toFixed(1)}" y="${(BOT - h).toFixed(1)}" width="${bw.toFixed(1)}"
          height="${h.toFixed(1)}" fill="${lp >= 50 ? 'var(--red-bg)' : 'var(--sunken)'}"
          stroke="${lp >= 50 ? 'var(--red-line)' : 'var(--line)'}"/>`);
    }
    if (x.blocked) {
      // 包根本没出去：这一窗那条丢包线不是对端不响，是这台机器没路 —— 单画一种颜色
      lost.push(`<rect x="${X(a).toFixed(1)}" y="${(MID - 9).toFixed(1)}" width="${bw.toFixed(1)}" height="9"
          fill="var(--red-bg)" stroke="var(--red-line)"/>`);
      prev = null;
      prevEnd = b;
      continue;
    }
    if (!recv) {
      lost.push(`<rect x="${(X(a) + bw / 2 - 3).toFixed(1)}" y="${(MID - 3).toFixed(1)}" width="7" height="7"
          fill="none" stroke="var(--red-line)"/>`);
      prev = null;
      prevEnd = b;
      continue;
    }
    const cx = X((a + b) / 2), cy = Y(Number(x.medianMs) || 0);
    if (prev) {
      segs.push(`<line x1="${prev[0].toFixed(1)}" y1="${prev[1].toFixed(1)}"
          x2="${cx.toFixed(1)}" y2="${cy.toFixed(1)}" stroke="var(--green-dim)" stroke-width="1.7"/>`);
    }
    dots.push(`<circle cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="2.6" fill="var(--green-dim)"/>`);
    prev = [cx, cy];
    prevEnd = b;
  }
  const hhmm = (ms) => {
    const d = new Date(ms);
    return Number.isFinite(d.getTime()) ? d.toTimeString().slice(0, 8) : '';
  };
  const ticks = [0, 0.5, 1].map((k) => `<text x="${(PL + k * (W - PL - PR)).toFixed(1)}" y="${H - 4}"
      text-anchor="${k === 0 ? 'start' : k === 1 ? 'middle' : 'end'}"
      fill="var(--muted)" font-size="10">${esc(hhmm(t0 + k * span))}</text>`).join('');
  return t('<svg viewBox=\"0 0 {0} {1}\" width=\"{2}\" height=\"{3}\"\n      style=\"max-width:100%;height:auto;display:block\" role=\"img\" aria-label=\"这一本账每一窗的往返与丢包\">\n      <line x1=\"{4}\" y1=\"{5}\" x2=\"{6}\" y2=\"{7}\" stroke=\"var(--line)\"/>\n      <line x1=\"{8}\" y1=\"{9}\" x2=\"{10}\" y2=\"{11}\" stroke=\"var(--line)\"/>\n      {12}{13}{14}{15}{16}\n      <text x=\"{17}\" y=\"{18}\" fill=\"var(--muted)\" font-size=\"10\">{19} ms</text>\n      <text x=\"{20}\" y=\"{21}\" text-anchor=\"end\" fill=\"var(--muted)\" font-size=\"10\">\n        {22} 窗 · 每窗 {23}</text>\n      <text x=\"{24}\" y=\"{25}\" fill=\"var(--muted)\" font-size=\"10\">100% 丢包</text>\n      <text x=\"{26}\" y=\"{27}\" text-anchor=\"end\" fill=\"var(--muted)\" font-size=\"10\">\n        下方柱 = 那一窗的丢包率（0–100%）</text>\n      {28}\n      <text x=\"6\" y=\"{29}\" fill=\"var(--muted)\" font-size=\"10\">中位往返</text>\n      <text x=\"6\" y=\"{30}\" fill=\"var(--muted)\" font-size=\"10\">0</text>\n    </svg>\n    <p class=\"hint\">红底方块 = 那一窗包根本没出去（这台机器没路，不是对端不响）·\n      空心方块 = 发出去了但一个回执都没有 · 虚线框 = 那一段时间<strong>没有账</strong>，\n      是「没问到」不是「没问题」。</p>', [W, H, W, H, PL, MID, W - PR, MID, PL, BOT, W - PR, BOT, holes.join(''), bars.join(''), segs.join(''), dots.join(''), lost.join(''), PL, TOP - 8, esc(hi.toFixed(1)), W - PR, TOP - 8, rs.length, esc(qDur(Number(rs[0].windowMs) || 0)), PL, BOT + 4, W - PR, BOT + 4, ticks, TOP + 6, MID - 2]);
}

// 断档与全丢段：这两样是后端从那本账里算出来的，这里只摊开给人看是哪几段。
function qualityAudit(aud) {
  if (!aud) return '';
  const holes = (aud.holes || []).map((h) => t('<tr>\n      <td class=\"dim\">{0} → {1}</td>\n      <td>{2}</td>\n      <td class=\"bad\">该有 {3} 窗，一窗都没有</td></tr>', [esc(qHms(h.from)), esc(qHms(h.to)), esc(qDur(Number(h.ms) || 0)), esc(h.expectedWindows ?? '—')])).join('');
  const silent = (aud.silent || []).map((s) => `<tr>
      <td class="dim">${esc(qHms(s.from))} → ${esc(qHms(s.to))}</td>
      <td>${esc(qDur(Number(s.ms) || 0))}</td>
      <td class="${s.block ? 'bad' : 'warn'}">${s.block ? t('包发不出去（查自己这台）') : t('一个回执都没有（查对端与路上）')}</td></tr>`).join('');
  const parts = [];
  if (holes) {
    parts.push(t('<div><label>账上的洞（共 {0} 段{1}）</label>\n      <table><tr><th>哪一段</th><th>多久</th><th>缺多少</th></tr>{2}</table></div>', [(aud.holes || []).length, aud.missingSeqs ? t('，另外序号还缺 {0} 个', [esc(aud.missingSeqs)]) : '', holes]));
  }
  if (silent) {
    parts.push(t('<div style=\"margin-top:10px\"><label>连着全丢的那几段</label><table><tr><th>哪一段</th><th>多久</th><th>这一段的病</th></tr>')
      + `${silent}</table></div>`);
  }
  // ★ 只说数得出的那个数：序号不是从 1 起的才有「滚掉了几窗」，
  //   尾部没写干净那种不完整（droppedWindows 是 0）不许写成「滚掉过 0 窗」——那是句空话。
  if ((aud.droppedWindows || 0) > 0) {
    parts.push(t('<p class=\"warn\">这本账被滚掉过 {0} 窗（留痕到上限，最早的先走）—— 你看到的不是全程。</p>', [esc(aud.droppedWindows)]));
  }
  if (typeof aud.staleMs === 'number' && aud.staleMs > 0) {
    parts.push(t('<p class=\"warn\">这一路还挂着，但最新一窗距今 {0} 没落账 —— 到点了没写进来。</p>', [esc(qDur(aud.staleMs))]));
  }
  if (!parts.length) return '';
  return `<div style="margin-top:12px">${parts.join('')}</div>`;
}

function qualityLedgerTable(ledgers) {
  const rows = (ledgers || []).map((l) => {
    const err = l.error ? t('<span class=\"bad\">这本读不了：{0}</span>', [esc(l.error)]) : '';
    return t('<tr>\n      <td><code>{0}</code>{1}</td>\n      <td class=\"dim\">{2} 窗{3}</td>\n      <td class=\"dim\">{4} → {5}</td>\n      <td class=\"dim\">{6}</td>\n      <td class=\"{7}\">{8}%</td>\n      <td><button class=\"btn\" data-q=\"{9}\">读这本账</button></td>\n    </tr>', [esc(l.target || '—'), err, esc(l.windows ?? '—'), l.tailBroken ? t('<span class=\"warn\"> · 尾部有一条没写完</span>') : '', esc(qHms(l.firstAt)), esc(qHms(l.lastAt)), typeof l.lastMedianMs === 'number' ? esc(l.lastMedianMs.toFixed(1)) + ' ms' : '—', (l.lastLossPercent || 0) > 0 ? 'warn' : 'dim', esc(l.lastLossPercent ?? '—'), esc(l.target || '')]);
  }).join('');
  return t('<table><tr><th>盯的是谁</th><th>多少窗</th><th>哪一段时间</th><th>最新中位</th><th>最新丢包</th><th></th></tr>{0}</table>', [rows]);
}

function qualityWindowTable(recs) {
  const rs = recs || [];
  if (!rs.length) return '';
  const show = rs.slice(-12);
  const rows = show.map((x) => {
    const say = x.blocked ? `<span class="bad">${esc(x.blocked)}</span>`
      : (!x.recv ? t('<span class=\"warn\">一个回执都没有</span>')
        : (x.unreachable ? t('<span class=\"warn\">不可达 {0} 发</span>', [esc(x.unreachable)]) : '<span class="dim">—</span>'));
    const f = (n) => (typeof n === 'number' ? `${esc(n.toFixed(1))} ms` : '<span class="dim">—</span>');
    return t('<tr>\n      <td class=\"dim\">第 {0} 窗<div>{1} → {2}</div></td>\n      <td>{3} 发 / {4} 回</td>\n      <td class=\"{5}\">{6}%</td>\n      <td>{7}</td><td>{8}</td><td>{9}</td>\n      <td class=\"dim\">{10}</td>\n      <td>{11}</td></tr>', [esc(x.seq), esc(qHms(x.startAt)), esc(qHms(x.endAt)), esc(x.sent), esc(x.recv), (x.lossPercent || 0) > 0 ? 'warn' : 'dim', esc(x.lossPercent), f(x.medianMs), f(x.maxMs), f(x.jitterMs), (x.spikes || []).length ? t('尖峰 {0} 处', [esc((x.spikes || []).length)]) : '—', say]);
  }).join('');
  return t('<div style=\"margin-top:12px\"><label class=\"dim\">最近 {0} 窗（图上那几格就是这几行；一本账共 {1} 窗在这一次的读数里）</label>\n    <div style=\"max-height:300px;overflow:auto\"><table>\n      <tr><th>哪一窗</th><th>发/回</th><th>丢包</th><th>中位</th><th>最慢</th><th>抖动</th><th>尖峰</th><th>这一窗的话</th></tr>\n      {2}</table></div></div>', [show.length, rs.length, rows]);
}

function qualityWatchCard() {
  const card = $(t('<div class=\"card\">\n    <h2>盯一段时间 <span id=\"q-top\"></span></h2>\n    <p class=\"hint\">「偶尔卡一下，你去的时候它又是好的」—— 这一句只能靠一本<strong>按窗记下来的账</strong>去问。\n      开一路之后它每隔一会儿发一发 ping，每满一窗把那一段时间记成一行（丢包率、中位、最慢、抖动、尖峰在哪几发）。\n      ★ 它改的是这台机器：后台持续对外发包 + 一直往配置目录写文件，所以要你点头，\n      而且<strong>会一直跑到你点停</strong>（或者这个后端退出）。\n      ★ 停掉<strong>不删账</strong> —— 那本账就是开这一路的目的；要腾地方自己删那个文件。\n      ★ 一次只开一路：现场那颗「停」必须明确知道停的是谁。\n      ★ 跨网段的目标请自己确认出口策略允许（持续发包在防火墙上看着像扫描）。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 220px\"><label>盯哪个地址</label>\n        <input id=\"q-addr\" placeholder=\"网关 / 平台 / 那台摄像头\"></div>\n      <div style=\"flex:0 0 130px\"><label>多久发一发（毫秒）</label>\n        <input id=\"q-interval\" placeholder=\"默认 1000\"></div>\n      <div style=\"flex:0 0 140px\"><label>多久记一窗（毫秒）</label>\n        <input id=\"q-window\" placeholder=\"默认 30000\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn danger\" id=\"q-go\">开这一路监测</button></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <div style=\"flex:0 0 auto;min-width:0\">\n        <button class=\"btn\" id=\"q-refresh\">刷新状态</button>\n        <button class=\"btn danger\" id=\"q-stop\" style=\"display:none\">立刻停掉</button></div>\n    </div>\n    <div id=\"q-err\" style=\"margin-top:12px\"></div>\n    <div id=\"q-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#q-out');
  const errBox = card.querySelector('#q-err');
  const top = card.querySelector('#q-top');
  const btnStop = card.querySelector('#q-stop');

  const paint = (code, v, note) => {
    const [title, cls] = QUALITY_STATE[code] || [code || t('没给判定'), ''];
    const say = uiNote(code, note);
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
    btnStop.style.display = code === 'quality-running' ? '' : 'none';
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--sunken)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--line)';
    const facts = [];
    if (v.target) { facts.push([t('盯的是'), `<code>${esc(v.target)}</code>`]); }
    if (v.intervalMs) { facts.push([t('发一发'), t('{0} 毫秒', [esc(v.intervalMs)])]); }
    if (v.windowMs) { facts.push([t('记一窗'), t('{0} 毫秒', [esc(v.windowMs)])]); }
    if (typeof v.windows === 'number') {
      // ★ 同一份 v.windows 在两种读数里不是同一个意思：
      //   「这一路自己记了几窗」只在停掉那一刻才有，「这本账现在有几窗」是整本账。
      //   后端两个都给了（windows / totalWindows），这里就得按给的是哪个来写标签。
      facts.push([typeof v.totalWindows === 'number' ? t('这一路记了几窗') : t('这本账现在有几窗'),
        t('{0} 窗', [esc(v.windows)])]);
    }
    if (typeof v.totalWindows === 'number' && v.totalWindows !== v.windows) {
      facts.push([t('这本账现在一共'), t('{0} 窗', [esc(v.totalWindows)])]);
    }
    if (v.startedAt) { facts.push([t('这一路什么时候开的'), esc(fmtStamp(v.startedAt))]); }
    if (v.nextAt) { facts.push([t('下一窗大约'), `${esc(qHms(v.nextAt))}${typeof v.nextInMs === 'number' ? t('（还有 {0}）', [esc(qDur(v.nextInMs))]) : ''}`]); }
    if (v.file) { facts.push([t('账落在'), `<code style="user-select:all">${esc(v.file)}</code>`]); }
    if (v.last && v.last.seq) {
      facts.push([t('最新那一窗'), t('第 {0} 窗：{1} 发回了 {2} 发', [esc(v.last.seq), esc(v.last.sent), esc(v.last.recv)])
        + t('（丢包 {0}%）、中位 {1} ms', [esc(v.last.lossPercent), esc((Number(v.last.medianMs) || 0).toFixed(1))])]);
    }
    const ledgers = v.ledgers || [];
    out.innerHTML = `
      <div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
        ${esc(say || '')}</div>${uiNoteTail(code, note)}
      ${facts.length ? `<table style="margin-top:12px"><tr><th></th><th></th></tr>
        ${facts.map((f) => `<tr><td class="dim" style="white-space:nowrap">${f[0]}</td><td>${f[1]}</td></tr>`).join('')}</table>` : ''}
      ${ledgers.length ? t('<div style=\"margin-top:12px\"><label class=\"dim\">盘上还留着哪几本账（停掉不删，这些就是现场留下的东西）</label>\n        {0}</div>', [qualityLedgerTable(ledgers)]) : ''}`;
    out.querySelectorAll('button[data-q]').forEach((b) => {
      b.onclick = () => { if (qualityPick) qualityPick(b.dataset.q); };
    });
  };

  // ★ busy：人正在点「开」或「停」的那一段时间（里面还包括等批准，可能几十秒）。
  //   这段时间 3 秒一次的轮询不许往画布上画 —— 它一回来说「没在跑」，
  //   就把人刚点出来的「等你点批准」或者「停掉了，账还在」盖掉了。
  let busy = false;

  const refresh = async (quiet) => {
    const r = await call('net.quality.status');
    if (busy) return;
    if (!r.ok) {
      if (!quiet) out.innerHTML = t('<div class=\"empty\">看不了状态：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
    if (r.verdict === 'quality-running') {
      if (qualityTimer) clearInterval(qualityTimer);
      qualityTimer = setInterval(() => refresh(true), 3000);
    } else if (qualityTimer) {
      clearInterval(qualityTimer);
      qualityTimer = null;
    }
  };

  const hush = () => {
    busy = true;
    if (qualityTimer) { clearInterval(qualityTimer); qualityTimer = null; }
  };

  card.querySelector('#q-go').onclick = async () => {
    const addr = card.querySelector('#q-addr').value.trim();
    if (!addr) {
      out.innerHTML = t('<div class=\"empty\">先写盯哪个地址。这一路要盯几十分钟以上才有意义 —— ')
        + t('挑那个「卡一下」最该怪到的地址（网关、平台、那台摄像头）。</div>');
      return;
    }
    const args = { addr };
    const iv = card.querySelector('#q-interval').value.trim();
    const wd = card.querySelector('#q-window').value.trim();
    // 不填就交给后端按默认来：这里替它填一个号，等于人没同意过的刻度
    if (iv) { args.intervalMs = Number(iv); }
    if (wd) { args.windowMs = Number(wd); }
    hush();
    errBox.innerHTML = '';
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消的话一个包都不发）</div>');
    const r = await call('net.quality.watch', args);
    busy = false;
    if (!r.ok) {
      // 这一路没开起来 —— 但「这一路没开起来」和「现在这台是什么状态」是两句话：
      // 前一句写在这里，后一句照样问回来（多半是「正在盯」的是上一路）。
      errBox.innerHTML = t('<div class=\"empty\">这一路没开起来：{0}</div>', [esc(r.message || r.error)]);
      refresh(true);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
    if (qualityTimer) clearInterval(qualityTimer);
    if (r.verdict === 'quality-running') qualityTimer = setInterval(() => refresh(true), 3000);
  };
  card.querySelector('#q-refresh').onclick = () => refresh(true);
  card.querySelector('#q-stop').onclick = async () => {
    btnStop.disabled = true;
    hush();
    errBox.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消就还在跑）</div>');
    const r = await call('net.quality.stop');
    btnStop.disabled = false;
    busy = false;
    if (!r.ok) {
      errBox.innerHTML = t('<div class=\"empty\">停不下来：{0}</div>', [esc(r.message || r.error)]);
      // 停失败多半意味着它还在跑：把真实状态问回来，别让画面冻在「等你点批准」。
      refresh(true);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
  };
  card.querySelector('#q-addr').onkeydown = (e) => { if (e.key === 'Enter') card.querySelector('#q-go').click(); };
  refresh(true);
  return card;
}

function qualityReportCard() {
  const card = $(t('<div class=\"card\">\n    <h2>这一本账怎么说 <span id=\"qr-top\"></span></h2>\n    <p class=\"hint\">读某一路留下的那本账，把「那一段时间」摊开：一条往返线、一条丢包柱，\n      外加<strong>账本身的洞</strong>（哪一段没采到、被滚掉了多少窗、上一次是不是没干净退出）。\n      ★ 结论按证据先后给：账上有洞的时候，绝不因为「洞以外没发现问题」就说成稳定 ——\n      那等于把「没问到」写成「问了没问题」。\n      ★ 没留痕的时候这里只会说「根本没采过」，不会说「没问题」。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 220px\"><label>读哪个地址的账</label>\n        <input id=\"qr-addr\" placeholder=\"就是开监测时填的那个地址\"></div>\n      <div style=\"flex:0 0 150px\"><label>读最近多少窗</label>\n        <input id=\"qr-windows\" placeholder=\"默认 120，最多 2000\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn\" id=\"qr-go\">读这本账</button></div>\n    </div>\n    <div id=\"qr-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#qr-out');
  const top = card.querySelector('#qr-top');
  const addr = card.querySelector('#qr-addr');

  const read = async () => {
    const a = addr.value.trim();
    if (!a) {
      out.innerHTML = t('<div class=\"empty\">先写读哪个地址的账 —— 一本账一个地址，各读各的。</div>');
      return;
    }
    const args = { addr: a };
    const n = card.querySelector('#qr-windows').value.trim();
    if (n) { args.windows = Number(n); }
    out.innerHTML = t('<div class=\"empty\">读这本账…</div>');
    const r = await call('net.quality.report', args);
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">读不出来：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    const v = r.values || {};
    const [title, cls] = QUALITY_READ[r.verdict] || [r.verdict || t('没给判定'), ''];
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
    const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--sunken)';
    const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--line)';
    const recs = v.windows || [];
    const facts = [];
    facts.push([t('盯的是'), `<code>${esc(v.target || a)}</code>${v.running ? t(' <span class=\"pill ok\">这一路还在跑</span>') : ''}`]);
    facts.push([t('这一次读了多少窗'), t('{0} 窗{1}', [recs.length, typeof v.totalWindows === 'number' ? t('（这本账一共 {0} 窗）', [esc(v.totalWindows)]) : ''])]);
    if (recs.length) {
      facts.push([t('哪一段时间'), t('{0} → {1}（共 {2}）', [esc(fmtStamp(v.from)), esc(fmtStamp(v.to)), esc(qDur(Number(v.spanMs) || 0))])]);
      facts.push([t('每窗 / 每发'), t('每窗 {0}、每发 {1}', [esc(qDur(Number(recs[0].windowMs) || 0)), esc(qDur(Number(recs[0].intervalMs) || 0))])]);
    }
    if (typeof v.droppedWindows === 'number' && v.droppedWindows > 0) {
      facts.push([t('被滚掉多少窗'), t('<span class=\"warn\">{0} 窗（留痕到上限，最早的先走）—— 你看到的不是全程</span>', [esc(v.droppedWindows)])]);
    } else if (v.truncated) {
      facts.push([t('被滚掉多少窗'), t('<span class=\"warn\">序号不是从 1 起的：这本账前面还有过东西</span>')]);
    }
    if (v.tailBroken) {
      facts.push([t('上一次怎么退出的'), t('<span class=\"warn\">文件尾部有一条没写完的窗（{0} 行解不开）', [esc(v.skippedLines || 1)])
        + t(' —— 上一次这个后端不是干净退出的（被杀 / 断电）</span>')]);
    }
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}</div>\n      <table style=\"margin-top:12px\"><tr><th></th><th></th></tr>\n        {3}</table>\n      {4}\n      {5}\n      {6}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{7}</pre></details>', [bg, line, esc(r.note || ''), facts.map((f) => `<tr><td class="dim" style="white-space:nowrap">${f[0]}</td><td>${f[1]}</td></tr>`).join(''), recs.length ? `<div style="margin-top:14px">${qualityChart(recs)}</div>` : '', qualityAudit(v.audit), qualityWindowTable(recs), esc(JSON.stringify(v, null, 2))]);
  };
  card.querySelector('#qr-go').onclick = read;
  addr.onkeydown = (e) => { if (e.key === 'Enter') read(); };
  qualityPick = (t) => {
    addr.value = t;
    read();
    card.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  return card;
}

/*
 * ── 谁在吃流量（net.bandwidth.top）──
 *
 * ★★ 这一张摆的是**两份口径**，不是一个大数拆成两半：网卡那一栏问的是
 *   「这条链路过了多少包」（链路层，含包头、广播，回环自己收一遍算两遍），
 *   进程那一栏问的是「哪个进程自己的套接字收发了多少」（传输层）。
 *   所以这里绝不做减法、也不画「占了总量的百分之几」—— 一旦画出来，
 *   「回环上 500 Mbps」会被读成「网被吃满了」，而那条网一根线都没动。
 *   两栏各自排自己的名次，各自标自己的单位，人对的是哪一栏一目了然。
 *
 * ★ 这一张不发任何包，纯读本机内核计数；给的是进程名与 PID，**不给命令行、
 *   不给对端地址**（命令行里常有口令和 token，而这份结果会整份发给 AI）。
 *
 * ★★ 「数不到进程」在这张卡上是三种不同的现场（Windows 整台数不到、
 *   Linux 非管理员只数到一部分、macOS 数得全），每种下一步不一样：
 *   换工具、提权、还是直接点名 —— 所以判定码有六个，这里一个都不合并。
 */

const BANDWIDTH_STATE = {
  'bandwidth-busy': [t('有进程在吃'), 'warn'],
  'bandwidth-idle': [t('这一段没人吃'), 'ok'],
  'bandwidth-not-mine': [t('过的包不是本机要发的'), 'bad'],
  'bandwidth-link-only': [t('只数得到网卡'), 'warn'],
  'bandwidth-partial': [t('只数到一部分进程'), 'warn'],
  'bandwidth-no-source': [t('这台机器数不了'), 'bad'],
};

// 每一种判定的下一步 —— 只补后端那句里没有的东西（往哪儿点、换哪张卡）。
const BANDWIDTH_WAY = {
  'bandwidth-busy': t('要腾下来就停点名那个进程（拿那个 PID 去做）；★ 停之前先确认它是不是')
    + t('某个服务的守护进程，父进程拉起的停父的没用。想抓「偶尔冒一下」那股，把窗口拉到 10~30 秒再数一次。'),
  'bandwidth-idle': t('这一栏答的是「刚才这一段」。要留长时间的血迹去「盯一段时间」那一页，')
    + t('这里数完就散了、什么都没留。'),
  'bandwidth-not-mine': t('★ 下一步不在「本机哪个进程」：先问谁在借这台机器走 —— ')
    + t('「网卡与路由」看有没有开共享/桥接/NAT，「网段上有哪些地址」看是不是有人在往它身上打。'),
  'bandwidth-link-only': t('这一栏只答「这条链路忙不忙」，不点名。要落到具体是谁：')
    + t('「本机端口与文件共享」看现在是谁在听、谁连着（不量字节），')
    + t('「两台机器对测」量这两台之间此刻能吃下多少 —— 后端那句下一步（提权那类）才是拿回进程名单的正路。'),
  'bandwidth-partial': t('用管理员权限再问一次才算数；看不见的那些里才可能藏着主角。'),
  'bandwidth-no-source': t('这台机器上连每块网卡过了多少字节都读不到，什么都不结论。')
    + t('要查请先用系统自带的工具看着（活动监视器 / 资源监视器 / <code>cat /proc/net/dev</code>）。'),
};

const BW_KIND = {
  link: [t('网卡'), ''],
  loopback: [t('本机回环'), 'dim'],
  tunnel: [t('隧道口'), 'dim'],
  unreadable: [t('这一段读不到'), 'warn'],
};

const BW_ATTR = {
  full: [t('进程数得全'), 'ok'],
  partial: [t('只数到一部分'), 'warn'],
  none: [t('数不到进程'), 'warn'],
};

function renderBandwidth(root) {
  root.appendChild(bandwidthCard());
}

function bandwidthCard() {
  const card = $(t('<div class=\"card\">\n    <h2>数一会儿，看谁在吃 <span id=\"bw-top\"></span></h2>\n    <p class=\"hint\">数一段（默认 3 秒），同时给两份口径：<strong>每块网卡在这段里过了多少</strong>\n      （链路层，答「这条路满没满」）和 <strong>每个进程自己收发了多少</strong>\n      （套接字层，答「该停谁」）。★ 这两个数<strong>不相减、也不换算成百分比</strong> ——\n      网卡含包头与广播，回环上本机跟自己说话还要算两遍，减出来的「剩多少」是假数。\n      纯读本机内核计数，<strong>一个包都不发</strong>；只给进程名与 PID，不给命令行和对端地址。</p>\n    <div class=\"row\">\n      <div style=\"flex:0 0 130px\"><label>数几秒（1–30）</label>\n        <input id=\"bw-win\" placeholder=\"默认 3\"></div>\n      <div style=\"flex:0 0 130px\"><label>进程列几条</label>\n        <input id=\"bw-topn\" placeholder=\"默认 10\"></div>\n      <div style=\"flex:0 0 auto\"><label>&nbsp;</label>\n        <button class=\"btn\" id=\"bw-go\">数一会儿</button></div>\n    </div>\n    <div id=\"bw-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#bw-out');
  const top = card.querySelector('#bw-top');
  const go = card.querySelector('#bw-go');
  const win = card.querySelector('#bw-win');
  const topn = card.querySelector('#bw-topn');

  const run = async () => {
    const args = {};
    const w = win.value.trim();
    const n = topn.value.trim();
    if (w) { args.windowSeconds = Number(w); }
    if (n) { args.top = Number(n); }
    top.innerHTML = '';
    go.disabled = true;
    out.innerHTML = t('<div class=\"empty\">正在数<span class=\"dim\">（这一页只等这一段窗口，不发包、不写盘）</span>…</div>');
    const r = await call('net.bandwidth.top', args);
    go.disabled = false;
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">没数成：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    bandwidthPaint(r.verdict, r.values || {}, r.note);
  };
  go.onclick = run;
  [win, topn].forEach((el) => { el.onkeydown = (e) => { if (e.key === 'Enter') run(); }; });
  out.innerHTML = t('<div class=\"empty\">按默认的 3 秒数一次就够看「现在谁在吃」。')
    + t('<strong>要找那种偶尔冒一下的</strong>：把秒数拉到 10~30 再数（窗口越长越不会被背景抖动骗到，')
    + t('但也会把那一下摊薄）。</div>');
  return card;
}

const bwMb = (x) => (typeof x === 'number' ? esc(x.toFixed(2)) : '—');
// 条长只是「跟这一栏里最忙的那条比」，不参与任何结论 —— 数一律是后端给的。
const bwBar = (v, max, cls) => {
  const pct = max > 0 && v > 0 ? Math.max(1.5, Math.min(100, (v / max) * 100)) : 0;
  return `<div class="bwbar ${cls || ''}" style="width:${pct.toFixed(1)}%"></div>`;
};

function bandwidthPaint(verdict, v, note) {
  const top = document.getElementById('bw-top');
  const out = document.getElementById('bw-out');
  const [title, cls] = BANDWIDTH_STATE[verdict] || [verdict || t('没给判定'), ''];
  if (top) {
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
  }
  if (!out) return;

  const say = note || t('后端没给这句话。');
  const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--gold-bg)';
  const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--gold-dim)';
  const box = `<div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px">
      ${esc(say)}</div>
    ${BANDWIDTH_WAY[verdict] ? `<div style="margin-top:8px;font-size:13px">${BANDWIDTH_WAY[verdict]}</div>` : ''}`;

  // 「数不了」这一档连计数都读不到，底下任何一栏、任何一个合计都是空 ——
  // 摆两张空表等于把「什么都不结论」演成「表在这，自己看」。只留结论和原因。
  if (verdict === 'bandwidth-no-source') {
    out.innerHTML = t('{0}\n      <p class=\"hint\">这一段窗口 <strong>{1} 秒</strong>，\n        原因：<code>{2}</code>。\n        ★ 没有表不是因为「什么都没发生」，是因为两个口径一个都没量到。</p>\n    <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n      <pre class=\"dim\">{3}</pre></details>', [box, esc(v.windowSec ?? '—'), esc(v.reason || t('（后端没给原因）')), esc(JSON.stringify(v, null, 2))]);
    return;
  }

  const ifaces = v.interfaces || [];
  const procs = v.processes || [];
  const busy = (x) => (Number(x.rxBytes) || 0) + (Number(x.txBytes) || 0);
  const named = (x) => x.egress || x.defaultRoute || x.kind === 'unreadable';
  // ★ 这一段完全没过东西、又不是出口/读不到的口，折成一行：一台 macOS 有 20 多块
  //   内核口，全列出来时真正在动的那两条被埋在最下面 —— 而这一栏要答的就是「哪条在动」。
  //   名字一个都不藏（照列），原始结果里也全在。
  const silent = ifaces.filter((x) => busy(x) === 0 && !named(x));
  const shown = ifaces.filter((x) => busy(x) > 0 || named(x));
  // ★ 进结论的那些口（counts）排在前面，回环与隧道压到下面 —— 后端是按字节数排的，
  //   本机自己跟自己说话能刷出几千 Mbps，让它骑在出口那行上面，「没人吃」这一档
  //   看上去就像反着说。这里只换先后，不改任何一个数。
  shown.sort((a, b) => (a.counts === false ? 1 : 0) - (b.counts === false ? 1 : 0));
  // 条长只按**进结论的那些口**定标：回环与隧道本来就不进出网总量，
  // 让它们当标尺会把唯一那块在动的出口压成看不见的一条线。
  const iMax = shown.reduce((a, x) => Math.max(a, x.counts === false ? 0 : busy(x)), 0);
  const pMax = procs.reduce((a, x) => Math.max(a, busy(x)), 0);
  const attr = BW_ATTR[v.attribution] || [v.attribution || t('没说'), ''];

  const iRows = shown.map((x) => {
    const [kw, kc] = BW_KIND[x.kind] || [x.kind || '—', ''];
    const mark = x.egress ? t('<span class=\"ok\">出口</span> ') : '';
    const dr = x.defaultRoute ? t('<span class=\"dim\">（系统说出口是它）</span>') : '';
    const dim = x.counts === false ? ' style="opacity:.62"' : '';
    const bar = x.counts === false ? '' : bwBar(busy(x), iMax);
    const ubar = x.counts === false ? '' : bwBar(busy(x), iMax, 'up');
    return `<tr${dim}>
      <td><code>${esc(x.name)}</code> ${mark}${dr}<div class="dim ${kc}">${esc(kw)}</div></td>
      <td>${bar}<b>${bwMb(x.rxMbps)}</b> <span class="dim">/ ${esc(fsSize(x.rxBytes || 0))}</span></td>
      <td>${ubar}<b>${bwMb(x.txMbps)}</b> <span class="dim">/ ${esc(fsSize(x.txBytes || 0))}</span></td>
    </tr>`;
  }).join('');

  const pRows = procs.length ? procs.map((x) => `<tr>
      <td><b>${esc(x.process || t('（没名字）'))}</b><div class="dim">PID ${esc(x.pid ?? '—')}</div></td>
      <td>${bwBar(busy(x), pMax)}<b>${bwMb(x.rxMbps)}</b> <span class="dim">/ ${esc(fsSize(x.rxBytes || 0))}</span></td>
      <td>${bwBar(busy(x), pMax, 'up')}<b>${bwMb(x.txMbps)}</b> <span class="dim">/ ${esc(fsSize(x.txBytes || 0))}</span></td>
    </tr>`).join('')
    : t('<tr><td colspan=\"3\"><span class=\"warn\">这一栏没数</span>\n      <span class=\"dim\"> —— {0}。\n      ★ 没有这一栏不等于没人在吃。</span></td></tr>', [esc(v.attributionNote || t('这个平台上按进程数网络字节这条路走不通'))]);

  const html = t('\n    {0}\n    <p class=\"hint\">数了 <strong>{1} 秒</strong>（实际取数用了 {2} 毫秒，\n      速率按这段算）· 出口网卡 <code>{3}</code>\n      · 网卡侧合计 下 <b>{4}</b> / 上 <b>{5}</b> Mbps\n      · 进程侧合计 <span class=\"pill {6}\">{7}</span>\n      下 <b>{8}</b> / 上 <b>{9}</b> Mbps\n      {10}。\n      ★ 两个「合计」口径不同，本来就不该相等。</p>\n    <div class=\"row\" style=\"gap:18px;align-items:flex-start;margin-top:10px\">\n      <div style=\"flex:1 1 320px\">\n        <label>网卡（链路口径 · 答「这条路忙不忙」）</label>\n        <table>\n          <tr><th>哪块口</th><th>收 Mbps</th><th>发 Mbps</th></tr>{11}\n        </table>\n        {12}\n        <p class=\"hint\">「出口」那行就是上面结论按的那块口。\n          <strong>回环与隧道不进出网总量</strong>：本机跟自己说话的字节不算过网，\n          隧道口上到的包物理口会再数一遍，两块一起加就是双倍。\n          {13}\n          {14}\n          {15}</p>\n      </div>\n      <div style=\"flex:1 1 320px\">\n        <label>进程（套接字口径 · 答「该停谁」）</label>\n        <table>\n          <tr><th>谁</th><th>收 Mbps</th><th>发 Mbps</th></tr>{16}\n        </table>\n        <p class=\"hint\">按收发合计排的名，同名的多个进程不合并（一个软件开几个进程是常事，\n          合并就看不出是哪一路）。\n          {17}\n          {18}\n          {19}</p>\n      </div>\n    </div>\n    <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n      <pre class=\"dim\">{20}</pre></details>', [box, esc(v.windowSec ?? '—'), esc(v.measuredMs ?? '—'), esc(v.egress || '—'), bwMb(v.linkRxMbps), bwMb(v.linkTxMbps), attr[1], esc(attr[0]), bwMb(v.processRxMbps), bwMb(v.processTxMbps), typeof v.quietBytesPerSecond === 'number'
        ? t('· 安静线 {0}/秒（低于它就当没在动）', [esc(fsSize(v.quietBytesPerSecond))]) : '', iRows, silent.length ? t('<p class=\"hint\">这一段没过东西的口还有 {0} 块：{1}。\n          <span class=\"dim\">它们只是这一段没动，不是不存在 —— 全列在这儿会把在动的那两条埋掉，\n          原始结果里一块都不少。</span></p>', [esc(silent.length), esc(silent.map((x) => x.name).join(t('、')))]) : '', ifaces.some((x) => x.kind === 'loopback') ? t('回环这一段合计 {0}，单独列着。', [esc(fsSize(v.loopbackTotalBytes || 0))]) : '', ifaces.some((x) => x.kind === 'tunnel') ? t('隧道口合计 {0}。', [esc(fsSize(v.tunnelTotalBytes || 0))]) : '', ifaces.some((x) => x.kind === 'unreadable') ? t('<span class=\"warn\">有口标着「这一段读不到」：它不是没过东西，是计数被清零了（接口重建或重启过）。</span>') : '', pRows, v.truncated ? t('<span class=\"warn\">只列了前 {0} 条，一共数到 {1} 条 —— 要看得更全把条数加大。</span>', [esc(v.processCountShown ?? '—'), esc(v.processCount ?? '—')]) : '', v.attributionNote ? `<span class="dim">${esc(v.attributionNote)}</span>` : '', v.attributionNext ? t('<span class=\"dim\">下一步：{0}</span>', [esc(v.attributionNext)]) : '', esc(JSON.stringify(v, null, 2))]);
  out.innerHTML = html;
}

/*
 * ── 手机互联与投屏（net.portal.*）──
 *
 * ★ 这张卡和文件共享的分工：那一张开的是**给设备取**的只读目录，
 *   这一张开的是**给手机用**的门户 —— 扫码进来传文件、当遥控器、把屏幕投过来。
 *   批准说明为什么比共享那半句更长：门户多了一条写路径（收件目录）和一条
 *   能驱动别的机器的通道（遥控器），点批准的人必须知道自己是同意了这些。
 *
 * ★ 二维码每 3 秒刷新状态时**不许**跟着重画：img 一重画就闪一下，
 *   正对着 scanner 的手机会被闪断。URL 没变（没换码）就保持原节点不动。
 */

const MP_CODE = {
  'portal-serving': [t('门户开着'), 'ok'],
  'portal-idle': [t('没在开'), ''],
  'portal-stopped': [t('已经关掉了'), ''],
};

let portalTimer = null;

function renderMobile(root) {
  root.appendChild(portalCard());
}

function portalCard() {
  const card = $(t('<div class=\"card\">\n    <h2>手机互联与投屏 <span id=\"mp-top\"></span></h2>\n    <p class=\"hint\">在这台机器的局域网里开一个<strong>手机门户</strong>：界面出二维码，\n      手机相机扫一下就能进来 —— 互相传文件（手机传来的落进收件目录，主机要发的从发件目录取）、\n      当遥控器操作「远程设备」页里登记过的机器、把手机屏幕实时投到这台机器上。\n      ★ 进门户要<strong>一次性令牌</strong>：码只显示这一张，10 分钟没人扫作废，\n      被一台手机用过也作废 —— 第二台要进来点「换一张二维码」，别把链接转群里。\n      ★ 只绑你挑的网卡上的地址（IPv4 和 IPv6 一起给，双栈网段里手机从哪边都进得来），\n      <strong>不绑 0.0.0.0</strong>。\n      ★ 手机上点到的执行动作走的是同一张工具表：改系统的照旧<strong>在这台机器上弹框等你点头</strong>，\n      手机绕不过去。谁扫了码、传了什么、跑了哪个动作，活动表和审计各记一笔。</p>\n    <div class=\"row\">\n      <div style=\"flex:0 0 150px\"><label>开在哪块网卡（留空自动）</label>\n        <input id=\"mp-iface\" placeholder=\"en0 / eth0 / WLAN\"></div>\n      <div style=\"flex:0 0 100px\"><label>端口</label>\n        <input id=\"mp-port\" placeholder=\"8642\"></div>\n      <div style=\"flex:1 1 260px\"><label>或者只绑这几个地址（填了就覆盖上面那块网卡；不许写 0.0.0.0）</label>\n        <input id=\"mp-addrs\" placeholder=\"192.168.1.20 fd00::1\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn danger\" id=\"mp-go\">开门户</button></div>\n    </div>\n    <div class=\"row\">\n      <label style=\"display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap\">\n        <input type=\"checkbox\" id=\"mp-files\" checked style=\"flex:0 0 auto\">\n        文件收发</label>\n      <label style=\"display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap\"\n        title=\"手机页面上能看已登记的远程设备、执行命令、发消息、开桌面、跑剧本 —— 全部走工具表，改系统的要在主机确认。\">\n        <input type=\"checkbox\" id=\"mp-remote\" checked style=\"flex:0 0 auto\">\n        遥控器</label>\n      <label style=\"display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap\"\n        title=\"收手机投过来的屏幕。开了会自动带 https —— 手机浏览器只在安全上下文里交出屏幕，这不是偏好是边界；手机第一次会提示证书不受信任，点「继续」。\">\n        <input type=\"checkbox\" id=\"mp-cast\" checked style=\"flex:0 0 auto\">\n        收手机投屏（自动开 https）</label>\n      <label style=\"display:flex;gap:6px;align-items:center;font-size:13px;font-weight:normal;white-space:nowrap\"\n        title=\"★ 这一条端出去的是这台机器本身：配过对的手机能实时看到你的屏幕。默认关。\">\n        <input type=\"checkbox\" id=\"mp-screen\" style=\"flex:0 0 auto\">\n        <span style=\"color:var(--gold)\">把主机屏幕推给手机</span></label>\n    </div>\n    <div class=\"row\">\n      <div style=\"flex:1 1 260px\"><label>收件目录（手机传过来的落这里，留空用默认）</label>\n        <input id=\"mp-inbox\" placeholder=\"默认在配置目录 portal/inbox\"></div>\n      <div style=\"flex:1 1 260px\"><label>发件目录（手机能下载的，留空用默认）</label>\n        <input id=\"mp-outbox\" placeholder=\"默认在配置目录 portal/outbox\"></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <div style=\"flex:0 0 auto\">\n        <button class=\"btn\" id=\"mp-refresh\">刷新</button>\n        <button class=\"btn danger\" id=\"mp-stop\" style=\"display:none\">关掉门户</button></div>\n    </div>\n    <div id=\"mp-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#mp-out');
  const top = card.querySelector('#mp-top');
  const btnStop = card.querySelector('#mp-stop');
  // 二维码那格单独有个稳定容器：轮询重画会把正对着 scanner 的图闪断。
  let qrKey = '';

  const paint = (verdict, v) => {
    const st = v.status || {};
    const serving = verdict === 'portal-serving';
    const [title, cls] = MP_CODE[verdict] || [verdict || t('没给判定'), ''];
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
    btnStop.style.display = serving ? '' : 'none';

    const bg = cls === 'ok' ? 'var(--green-bg)' : 'var(--sunken)';
    const line = cls === 'ok' ? 'var(--green-dim)' : 'var(--line)';
    let say;
    if (verdict === 'portal-idle') {
      say = t('现在没开。开一次就是一次对外暴露（多一个写路径、多一条能驱动别的机器的通道），')
        + t('需要时再开、用完就关 —— 关掉是当场断，手机上残留的页面再请求一律失效。');
    } else if (verdict === 'portal-stopped') {
      say = t('端口 {0} 已释放，{1} 台手机的配对当场作废。', [v.port || '—', v.sessions || 0])
        + t('投屏抓拍目录里已存下的图不受影响。');
    } else if (serving) {
      say = t('门户开在 <b>{0}://{1}:{2}</b>', [esc(st.scheme || ''), esc((st.addrs || [])[0] || ''), st.port || '—'])
        + (v.iface ? t('，网卡 <b>{0}</b>（{1}）', [esc(v.iface), esc(FS_WHY[v.ifaceWhy] || v.ifaceWhy || t('怎么定的没说'))]) : '')
        + t('；手机连同一个 Wi-Fi / 网段，相机对准下面的码就能进。');
    } else {
      say = t('后端给了一个这里还没认得的判定，原文在下面展开看。');
    }

    // —— 二维码 + 进入链接 ——
    const qrs = v.qr || [];
    const key = qrs.map((q) => q.url).join('\n');
    let qrHTML = '';
    if (serving && qrs.length) {
      qrHTML = t('<div style=\"margin-top:12px\"><label class=\"dim\">进入二维码{0} {1}</label>\n        <div id=\"mp-qr\" style=\"display:flex;gap:14px;flex-wrap:wrap;align-items:flex-start;margin-top:6px\"></div>\n        {2}\n        </div>', [qrs.length > 1 ? t('（手机扫哪张都一样，是一张码的多个地址写法）') : '', serving ? t('<button class=\"btn\" id=\"mp-rotate\" style=\"font-size:12px;padding:2px 8px\">换一张</button>') : '', st.entryUsed ? t('<p class=\"hint\" style=\"color:var(--gold)\">这张码<strong>已经被扫过了</strong> —— ')
          + t('再要一台手机进来，点上面「换一张」（旧链接同时作废，已配对的手机不受影响）。</p>')
          : t('<p class=\"hint\">这张码 <b>{0}</b> 后作废。它是一次性的：扫一次就换。</p>', [esc(mpSpan(st.entryExpiresAt))])]);
    }
    const urls = (st.urls || []).map((u) => `<div style="margin-top:4px"><code style="user-select:all;cursor:cell">${esc(u)}</code></div>`).join('');
    const localNote = st.localName
      ? t('<p class=\"hint\">手机换了网络还想进得来？macOS 上系统会自动应答 <code style=\"user-select:all\">{0}</code> 这个名字 —— 上面是 IP，这个是备用写法，两边都试。</p>', [esc(st.localName)]) : '';

    const facts = [];
    if (serving) {
      facts.push([t('收件目录（手机→主机）'), t('<code>{0}</code>：只新增、不覆盖，单文件封顶见批准说明', [esc(st.inbox || '—')])]);
      facts.push([t('发件目录（主机→手机）'), t('<code>{0}</code>：对手机只读', [esc(st.outbox || '—')])]);
      const cn = st.castNow || {};
      if (st.cast) {
        facts.push([t('手机投屏'), cn.active
          ? t('正在收 <code>{0}</code> 的{1}：{2} 帧、{3}{4}', [esc(cn.peer || ''), cn.mode === 'camera' ? t('摄像头') : t('屏幕'), cn.frames || 0, esc(fsSize(cn.bytes || 0)), cn.stale ? t('；<b class=\"bad\">已经 5 秒没新帧</b>（手机切后台了？）') : ''])
          : t('开着，现在没有手机在投')]);
      }
      if (st.screen) {
        facts.push([t('主机屏幕外送'), t('开着 —— {0} 台手机正在看这台机器的屏幕', [st.screenLiveWatchers || 0])]);
      }
      if (st.sessionHours) facts.push([t('会话寿命'), t('{0} 小时', [st.sessionHours])]);
    }
    const factRows = facts.map(([k, x]) => `<tr><td class="dim" style="white-space:nowrap">${esc(k)}</td><td>${x}</td></tr>`).join('');

    const sessions = st.sessions || [];
    const sessTable = serving ? (sessions.length
      ? t('<div style=\"max-height:220px;overflow:auto\"><table>\n        <tr><th>什么时候进的</th><th>哪台手机</th><th>浏览器/机型</th><th>请求</th><th>还剩</th><th></th></tr>\n        {0}</table></div>\n        <p class=\"hint\">「踢下线」只对得上这一台：它的凭据当场作废，再要进来得重新扫码。换人值班、手机递出去了，就点这个。</p>', [sessions.map((x) => t('<tr>\n          <td class=\"dim\">{0}</td>\n          <td><code>{1}</code></td>\n          <td class=\"dim\" style=\"max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\">{2}</td>\n          <td class=\"dim\">{3}</td>\n          <td class=\"dim\">{4}</td>\n          <td><button class=\"btn\" data-kick=\"{5}\" style=\"font-size:12px;padding:2px 8px\">踢下线</button></td>\n        </tr>', [esc(fsClock(x.joinedAt)), esc(x.peer), esc(x.ua || '—'), x.requests || 0, esc(mpSpan(x.expiresAt)), esc(x.id)])).join('')])
      : t('<div class=\"empty\">还没有手机扫进来。码在上面的格子里。</div>')) : '';

    const acts = (st.activity || []).slice(0, 20);
    const actTable = acts.length ? t('<div style=\"max-height:260px;overflow:auto\"><table>\n      <tr><th>什么时候</th><th>谁</th><th>干了什么</th><th>对象</th><th>结果</th></tr>\n      {0}</table></div>', [acts.map((a) => `<tr>
        <td class="dim">${esc(fsClock(a.at))}</td><td><code>${esc(a.peer || '—')}</code></td>
        <td>${esc(MP_ACTION[a.action] || a.action)}</td>
        <td class="dim" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.target || a.detail || '—')}</td>
        <td>${esc(a.result || '')}</td></tr>`).join('')]) : '';

    // —— 主机端看投屏（回环口，只在这台机器上有效）——
    let castHTML = '';
    if (serving && st.cast) {
      const live = `http://127.0.0.1:${st.port}/local/cast/live`;
      const cn = st.castNow || {};
      castHTML = t('<div style=\"margin-top:14px\" id=\"mp-castbox\">\n        <label class=\"dim\">投屏直播（手机投过来的画面，只在这台机器上看）</label>\n        <div style=\"margin-top:6px;display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap\">\n          <img id=\"mp-cast-img\" src=\"{0}\" alt=\"\" style=\"max-width:420px;max-height:300px;border-radius:6px;border:1px solid var(--line);background:var(--sunken)\">\n          <div style=\"font-size:13px\" class=\"dim\">\n            {1}\n            <br><button class=\"btn\" id=\"mp-cast-save\" style=\"margin-top:6px\">存这一帧</button>\n            <span id=\"mp-saved\" class=\"hint\" style=\"margin-left:8px\"></span>\n          </div>\n        </div>\n        <p class=\"hint\">「存这一帧」落到 <code>{2}</code>。\n          这一路走的是本机回环口，局域网里的手机看不到这个画面，只有这台机器看得到。</p>\n      </div>', [live, cn.active ? t('来自 <code>{0}</code>（{1}）<br>{2} 帧、{3}{4}', [esc(cn.peer), cn.mode === 'camera' ? t('摄像头') : t('屏幕'), cn.frames || 0, esc(fsSize(cn.bytes || 0)), cn.stale ? t('<br><b class=\"bad\">5 秒没新帧了：手机多半切后台了</b>') : ''])
              : t('现在没有手机在投。<br>手机上开「投屏」后，画面会出现在这里。'), esc(v.snapDir || t('（主机没设抓拍目录）'))]);
    }

    // 整块 out 每次重画都会重建 —— 二维码不能跟着重建：正对着 scanner 的图
    // 每 3 秒闪断一次等于让人扫不上。key 没变就把旧节点原样搬回来（不重新解码）。
    const oldQR = card.querySelector('#mp-qr');
    const hadKey = qrKey;

    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">{2}</div>\n      {3}\n      {4}\n      {5}\n      {6}\n      {7}\n      {8}\n      {9}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{10}</pre></details>', [bg, line, say, qrHTML, serving && urls ? t('<div style=\"margin-top:10px\"><label class=\"dim\">门户地址（手机浏览器直接输这个也行，进去还是要扫码）</label>{0}{1}</div>', [urls, localNote]) : '', factRows ? `<table style="margin-top:12px"><tr><th></th><th></th></tr>${factRows}</table>` : '', mpWarn(st.warnings), sessTable ? t('<div style=\"margin-top:12px\"><label class=\"dim\">连进来的手机（每 3 秒自己刷新）</label>{0}</div>', [sessTable]) : '', castHTML, actTable ? t('<div style=\"margin-top:12px\"><label class=\"dim\">最近的活动（留最近 100 笔，审计另有整本账）</label>{0}</div>', [actTable]) : '', esc(JSON.stringify(v, null, 2))]);

    if (serving && qrs.length) {
      const box = card.querySelector('#mp-qr');
      if (key === hadKey && oldQR && box && oldQR !== box) {
        box.replaceWith(oldQR);   // 码没换：把画好的一整格搬回来，img 不重新加载、不闪
      } else {
        qrKey = key;
        if (box) box.innerHTML = qrs.map((q) => t('<div style=\"text-align:center\">\n          <img src=\"{0}\" width=\"200\" height=\"200\" alt=\"进入二维码\" style=\"background:#fff;border-radius:8px;padding:6px\">\n          <div class=\"dim\" style=\"font-size:11px;max-width:200px;word-break:break-all;margin-top:4px\">{1}</div>\n        </div>', [q.png, esc(q.url)])).join('');
      }
      const rot = card.querySelector('#mp-rotate');
      if (rot) rot.onclick = async () => {
        rot.disabled = true;
        const r = await call('net.portal.rotate');
        rot.disabled = false;
        if (!r.ok) {
          top.innerHTML = t('<span class=\"pill\">换码失败</span> <span class=\"hint\">{0}</span>', [esc(r.message || r.error)]);
          return;
        }
        paint(r.verdict, r.values || {});
      };
    }
    card.querySelectorAll('[data-kick]').forEach((b) => {
      b.onclick = async () => {
        b.disabled = true;
        const r = await call('net.portal.kick', { session: b.dataset.kick });
        if (!r.ok) b.disabled = false;
        if (r.ok && r.verdict === 'portal-session-gone') { /* 已经不在了，下面那次刷新会把它抹掉 */ }
        refresh(true);
      };
    });
    const save = card.querySelector('#mp-cast-save');
    if (save) save.onclick = async () => {
      const port = (v.status || {}).port;
      const span = card.querySelector('#mp-saved');
      try {
        const resp = await fetch(`http://127.0.0.1:${port}/local/cast/save`, { method: 'POST' });
        const j = await resp.json();
        span.textContent = j.ok ? t('已存：{0}', [j.path]) : t('没存上：{0}', [j.error || t('未知原因')]);
      } catch (e) {
        span.textContent = t('没存上：{0}', [e]);
      }
    };
  };

  const refresh = async (quiet) => {
    const r = await call('net.portal.status');
    if (!r.ok) {
      if (!quiet) out.innerHTML = t('<div class=\"empty\">看不了状态：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    paint(r.verdict, r.values || {});
    if (r.verdict === 'portal-serving') {
      if (portalTimer) clearInterval(portalTimer);
      portalTimer = setInterval(() => refresh(true), 3000);
    } else if (portalTimer) {
      clearInterval(portalTimer);
      portalTimer = null;
    }
  };

  card.querySelector('#mp-go').onclick = async () => {
    const args = {};
    const iface = card.querySelector('#mp-iface').value.trim();
    const port = card.querySelector('#mp-port').value.trim();
    const addrs = card.querySelector('#mp-addrs').value.split(/[\s,、]+/).filter(Boolean);
    if (iface) args.iface = iface;
    if (port) args.port = Number(port);
    if (addrs.length) args.addrs = addrs;
    if (!card.querySelector('#mp-files').checked) args.files = false;
    if (!card.querySelector('#mp-remote').checked) args.remote = false;
    if (!card.querySelector('#mp-cast').checked) args.cast = false;
    if (card.querySelector('#mp-screen').checked) args.screen = true;
    const inbox = card.querySelector('#mp-inbox').value.trim();
    const outbox = card.querySelector('#mp-outbox').value.trim();
    if (inbox) args.inbox = inbox;
    if (outbox) args.outbox = outbox;
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消的话一个端口都不开）</div>');
    const r = await call('net.portal.start', args);
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">没有开起来：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    qrKey = '';   // 新门户新二维码，强制重画一次
    paint(r.verdict, r.values || {});
    if (portalTimer) clearInterval(portalTimer);
    portalTimer = setInterval(() => refresh(true), 3000);
  };
  card.querySelector('#mp-refresh').onclick = () => refresh(true);
  card.querySelector('#mp-stop').onclick = async () => {
    btnStop.disabled = true;
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消就还开着）</div>');
    const r = await call('net.portal.stop');
    btnStop.disabled = false;
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">关不掉：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    if (portalTimer) { clearInterval(portalTimer); portalTimer = null; }
    qrKey = '';
    paint(r.verdict, r.values || {});
  };
  refresh(true);
  return card;
}

// mpSpan：还剩多久（用于二维码有效期、会话剩余）。过期/没有显示「已过期」。
function mpSpan(iso) {
  if (!iso) return '—';
  const ms = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(ms)) return '—';
  if (ms <= 0) return t('已过期');
  const m = Math.floor(ms / 60000);
  if (m >= 60) return t('还剩 {0} 小时 {1} 分', [Math.floor(m / 60), m % 60]);
  if (m >= 1) return t('还剩 {0} 分钟', [m]);
  return t('还剩 {0} 秒', [Math.floor(ms / 1000)]);
}

const MP_ACTION = {
  enter: t('扫码进来'), 'denied': t('被拒（旧凭据/乱码）'), upload: t('传文件进来'),
  download: t('取走文件'), tool: t('跑了个动作'), 'cast.start': t('开始投屏'),
  'cast.save': t('存了投屏的一帧'), 'screen.live': t('手机在看主机屏幕'), kick: t('踢下线'),
};

function mpWarn(lines) {
  if (!lines || !lines.length) return '';
  return `<div style="margin-top:10px;padding:10px 12px;border-radius:6px;font-size:13.5px;
      background:var(--gold-bg);border:1px solid var(--gold-dim);color:var(--gold)">★ ${
    lines.map((x) => esc(x)).join('<br>★ ')}</div>`;
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
  'no-internet': [t('这台机器上不去网'),
    t('什么都不用填，这台机器就是主角。★ 要拿某个内网域名当对照组，再填在「目标」里。')],
  'host-down': [t('点名一台机器连不上'),
    t('把连不上的那一台填在「目标」（IP 或域名都收）。★ 不填就只查我们这台到公网那一段，点不到你手上那一台。')],
  'slow': [t('通是通，但很慢'),
    t('填那个慢的地址。要是慢的是某个网页或接口，把完整地址填在高级的「网址」里 —— 只有那样才量得出各段各占了多少。')],
  'flaky': [t('偶尔卡一下 / 时好时坏'),
    t('填那个「时好时坏」的地址。★ 这种病要多发几发才挑得出来，别勾「快一点」。')],
  'cert-error': [t('证书报错 / HTTPS 打不开'),
    t('填报错的那个地址（或者把浏览器地址栏那串贴到高级的「网址」）。★ 这一条会先问时间，再决定是不是证书的锅。')],
  'device-down': [t('一台设备不在线 / 没画面'),
    t('把那台设备的地址填进来。★ 有 rtsp 取流地址就填在高级的「网址」里；没有也行 —— 会先向设备问一次 ONVIF，把地址问出来再去验流。')],
};

// 五种状态。★ 这一列是这张卡最要紧的一列：「没去问」和「问了没有」差一次跑错机房。
const TREE_STATUS = {
  asked: [t('问了'), '', ''],
  'not-asked': [t('没问出去'), 'warn', t('缺前面的事实，这一步一个包都没发')],
  skipped: [t('没问到这一步'), '', t('停在前面那一步了，按顺序不必问')],
  unreadable: [t('问了，但没读出要的那一项'), 'bad', t('是我们读不到，不是网络没答')],
  failed: [t('这一步自己出错了'), 'bad', t('参数、权限或工具内部的错，不能当成「查过了没问题」')],
};

// 顶层那三种「没定位到根因」的读数。
const TREE_TOP = {
  'no-cause-found': [t('这条路每一步都正常'), 'warn',
    t('★ 这不等于「没毛病」，只等于「毛病不在我们问的这几步里」：症状多半在对端、在应用配置、或者在')
    + t('另一块网卡上。看下面哪几步压根没问出去 —— 那几步才是这份结论的边界，也是下一步该补的地方。')],
  stopped: [t('时间用完，只走到一半'), 'warn',
    t('这份路径只到标了状态的那几步，后面全是「没问到」。★ 别把这份当整条结论用：')
    + t('在高级里把「最长跑多久」调大，或者勾上「快一点」少发几发，再跑一次。')],
  'nothing-asked': [t('一步都没问出去'), 'bad',
    t('要问的目标信息压根没给够，所以一个探测包都没发。★ 这一档最容易被读成「查过了，都没事」—— ')
    + t('它什么都没说。把「目标」填上（点名的那台机器 / 那个网址）再来一次。')],
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
  hls: [HLS_CODE], rtmp: [RTMP_CODE],
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
  'cause-no-interface': [t('一块在用的网卡都没有'), 'bad',
    t('要么全被禁用，要么没有一块拿到可用地址 —— 后面每一步都是在它之上测的，先解决这一步。')
    + t('查网卡开关、虚拟口 / VPN 的残留、无线关联上了没有。')],
  'cause-link-down': [t('网卡开着，链路却没起来'), 'bad',
    t('线没插 / 对端那个口没起来 / 没连上 AP。★ 这一条不用查任何配置：先看这块口的灯和对端口，')
    + t('是物理层的事。')],
  'cause-no-address': [t('链路是好的，但没拿到地址'), 'bad',
    t('DHCP 没发地址（现场最常见的是那个口被划在另一个 VLAN 里），或者静态地址压根没配。')
    + t('去「DHCP 分地址」那一页看有没有应答，再回来看这块口的地址。')],
  'cause-no-default-route': [t('有地址，却没有默认路由'), 'bad',
    t('这台机器只会发到本网段：局域网里什么都通，外面一个都到不了。查 DHCP 有没有发网关、')
    + t('静态配置里网关那栏填了没有。')],
  'cause-gateway-loss': [t('到网关就在丢包'), 'bad',
    t('★ 网关在丢包时，解析和外网的「慢」都是它带出来的，不是那几层自己的毛病 —— 先修这一段，')
    + t('再回头看后面那些数。查线、查 AP 信号、查那个口的协商速率。')],
  'cause-gateway-unreachable': [t('网关明确回了「到不了」'), 'bad',
    t('有人答了话，说明本机到网关这一路是通的，是网关自己没有出路。')
    + t('查它上游那条链路、它自己的默认路由和 NAT。')],
  'cause-gateway-silent': [t('网关一个都不回'), 'bad',
    t('★ 这不能直接读成「网关死了」：它拦 ICMP 时长得一模一样。换个不依赖 ICMP 的办法验一次 —— ')
    + t('探一个公网 IP（跳过解析），或者另拿一台机器同时测，才知道是不是只有这台的事。')],
  'cause-dns-server-dead': [t('配了 DNS 服务器却问不到'), 'bad',
    t('「网页打不开，但 IP ping 得通」就是这一层。换成问网关或一个公共 DNS 再试一次：')
    + t('能出结果说明配的那台不干活，还不行就是 53 端口被拦。')],
  'cause-dns-upstream': [t('DNS 服务器自己查不到'), 'bad',
    t('SERVFAIL 是它那一侧的账（它的上游或转发坏了），改本机没用的方向。')
    + t('换一台服务器就能出结果 —— 现场常是内网 DNS 只配了转发、转发目标却不通。')],
  'cause-dns-refused': [t('DNS 服务器不给递归查询'), 'bad',
    t('这台解析器只服务内网（不替你查公网名字）。换一台公共 DNS，')
    + t('或者把查询发给你自己搭的那台递归。')],
  'cause-dns-bad-response': [t('回来的不是能解的 DNS 报文'), 'bad',
    t('★ 这多半不是 DNS 坏了，是有设备在冒充 / 改写它（老网关、透明代理、被投毒的缓存）。')
    + t('换一个 DNS 服务器或走加密 DNS 再问一次，能分清是谁在动。')],
  'cause-name-missing': [t('这个域名不存在'), 'bad',
    t('服务器明确说没有这个名字。先核对有没有拼错、少带后缀；内网名字要看这台机器有没有走')
    + t('那个搜索域 / 那个 hosts 文件。')],
  'cause-v6-egress-broken': [t('IPv6 有路却出不了外网'), 'bad',
    t('★ 这是「网很慢」的真身之一：应用先试 IPv6，等它失败才回落到 IPv4，于是每一次连接都慢半拍，')
    + t('而 ping 和体检看着都正常。要么修上游的 IPv6，要么先把这块口的 IPv6 关掉。')],
  'cause-path-stalled': [t('路断在中间某一跳'), 'bad',
    t('最后一台有回应的设备之后，再没人回过话 —— 停在哪台写在那一步的依据里。')
    + t('查那一台和它后面那条链路，别再从两头互相 ping 了。')],
  'cause-path-silent': [t('第一跳就没回应，说不通路断没断'), 'warn',
    t('★ 路由器不回应探测包时，「路好好的」和「路断了」是同一个形状。改用探端口或直接连服务确认')
    + t('终点到不到得了，再决定查哪一段。')],
  'cause-no-route-to-target': [t('本机没有去往那个地址的路由'), 'bad',
    t('一个包都没发出去，所以跟对端防不防火没有任何关系。查自己：地址和掩码配得对不对、')
    + t('是不是根本不在同一个网段、多网卡机器上有没有那块口的路由。')],
  'cause-clock-way-off': [t('本机时钟差得足以让别的东西出错'), 'bad',
    t('这个量级上证书会被判「已过期」或「还没生效」、租约会算成早到期、日志时间戳排不进正确顺序 —— ')
    + t('现场看到的「网有问题」，根在这里。先校时，再回头看别的。')],
  'cause-clock-skewed': [t('时钟有偏差，但还没到出事的地步'), 'warn',
    t('★ 只有一个时间源答的时候，这里只说差多少、不指认是谁不对。要指认，多配几个源再问一次。')],
  'cause-proxy-in-the-way': [t('系统代理指着一台连不上的机器'), 'bad',
    t('★ 这种机器最骗人：ping、探端口、直连公网全都正常，只有应用打不开 —— 因为应用走代理，')
    + t('而体检那一圈里有几项是不走代理的。查代理地址、端口，或者先把系统代理关掉再试。')],

  // ── 点名一台机器 ──
  'cause-target-off-link': [t('二层就没有它（同网段没人认它）'), 'bad',
    t('★ 这一条值得单独一档：扫的是它所在那一段，清单里别的设备都在，只有它一个信号都没发过 —— ')
    + t('网络配置已经不用查了，去查线、查供电（PoE 那个口给没给功率）、查它是不是关着机。')],
  'cause-target-alive-noicmp': [t('它是活的，只是不理 ping'), 'warn',
    t('同网段那一问里它吭过声（应了 ARP），却不回 ICMP —— 摄像头、NVR 十台九台这样，')
    + t('多数还带「一键禁 ping」的开关。★ 别再拿 ping 不通当证据了，直接去问它服务的端口。')],
  'cause-target-unreachable': [t('有设备明确回了「到不了这台」'), 'bad',
    t('这比「没回应」有用得多：包出得去、也有人回话，路是通的，问题在终点或某台设备的路由上。')
    + t('查它的地址还在不在、中间那台路由有没有到它的路由。')],
  'cause-target-no-reply': [t('一路都没回，也没拿到二层证据'), 'bad',
    t('★ 这一档故意不给「它挂了」的结论：整段被静默、它自己关机、地址被人改了，全是这个形状。')
    + t('要么把「目标」填成它的 IP（跳过解析）再跑一次，要么换一台同网段的机器同时测。')],
  'cause-service-closed': [t('机器在，那个端口上没服务'), 'bad',
    t('端口明确回了拒绝 —— 拒绝说明它收到了包，所以主机活着、路也通。')
    + t('去看服务起没起、端口号对不对（摄像头 554 是 RTSP，80 是 Web，8000 / 8200 是各家私有 SDK）。')],
  'cause-service-filtered': [t('那个端口一个回包都没有'), 'bad',
    t('多半是中间有人静默丢（防火墙 / ACL / 端口防护），也可能是主机根本不在。')
    + t('★ 这两件事的下一步完全不同，所以先用同网段那一问或探一片端口确认主机在不在。')],
  'cause-host-alive': [t('网络和端口都没问题，症状不在这条路上'), 'warn',
    t('★ 这一条是拿来收口的：它活着、端口也开着，所以「上不去」的账要记到服务里去的')
    + t('那一层（账号、通道号、并发满了、它只放行指定 IP）。拿取流那一步去问它回什么。')],

  // ── 通是通，但很慢 ──
  'cause-link-jitter': [t('链路本身在抖'), 'bad',
    t('没丢包，但快慢差得明显。★ 抖和丢是两种病：丢要查链路（线、信号、协商、环路），')
    + t('抖多半是排队 —— 查那条链路是不是被某台机器占满了，或者 AP 上挂了太多客户端。')],
  'cause-link-loss': [t('链路上有丢包，重传把一切拖慢'), 'bad',
    t('★ 丢包时的「慢」不该记到应用头上：TCP 每丢一次就要等一次重传超时，')
    + t('用户看到的就是「转很久」。先把这一段修干净，再看那些分段耗时还剩多少。')],
  'cause-v6-stall': [t('应用先卡在 IPv6 上，再回落'), 'bad',
    t('双栈机器上「慢」最省事的解释：每一次新建连接先赌 IPv6，赌输了再走 IPv4，')
    + t('于是每次多等一截。修上游 v6，或先把这块口的 IPv6 关掉再测一次对比。')],
  'cause-dns-slow': [t('慢在解析这一段'), 'bad',
    t('各段耗时里解析占了大头，说明服务器能答只是答得慢（转发链长、DNS sec 校验、')
    + t('或者被限速）。换一台近的 DNS、或者把常用名字做成本地解析，效果立竿见影。')],
  'cause-connect-slow': [t('慢在 TCP 握手这一段'), 'bad',
    t('网络往返本身就慢或第一跳 SYN 被丢了一次 —— 查路由距离、对端 backlog，')
    + t('以及中间有没有在改写连接。★ 服务端处理慢不是这一条。')],
  'cause-tls-slow': [t('慢在 TLS 那一段'), 'bad',
    t('常见于设备证书链太长、要现场补中间证书，或者双方的套件要来回试几轮才谈成。')
    + t('把证书链配齐（配上中间证书）能省掉这一段的大半。')],
  'cause-app-slow': [t('网络各段都利索，慢在服务自己想'), 'bad',
    t('★ 这条的作用是把人从网络侧叫回来：包没丢、往返没抬升、握手也快，账全在服务器处理时间里。')
    + t('去查那个服务的日志、数据库和上游，别再翻交换机了。')],
  'cause-path-latency': [t('从某一跳起往返抬升，并一路带到终点'), 'bad',
    t('抬升起点那一跳就是分界：它之前还是好的。要查的是那一段链路（或那个出口在拥塞），')
    + t('不是终点机器 —— 它只是替前面所有环节把账付了。')],
  'cause-mtu-too-small': [t('路上有一个更小的包长限制'), 'bad',
    t('大包就是在中间某一环被挡住或被迫分片：隧道、VPN、PPPoE、被人改小过的交换机口。')
    + t('★ 这条专门治「连得上、ping 得通，视频一出来就卡 / 传文件传到一半断」——')
    + t('因为别的探测发的是小包。把本机网卡 MTU 设成那一步给的建议值就能先绕过去。')],

  // ── 偶尔卡一下 ──
  'cause-intermittent-loss': [t('有一段在突发丢包'), 'bad',
    t('★ 「一直不丢」和「偶尔丢」是两个查法：一直丢能立刻定位，突发丢要么有规律（定时任务、')
    + t('无线信道跳频、某台机器周期发广播），要么是被偶发拥塞。连续 ping 和逐跳质量里都写了第几轮、')
    + t('第几发丢的，拿那个时间点对它的日志。')],
  'cause-path-moved': [t('等价路径在翻动'), 'warn',
    t('同一跳出现过不止一个下一跳：负载分担本来就这样，不算故障。★ 只有当每次翻到一条更烂的路时才卡人 —— ')
    + t('对照那一步的丢包和往返看，别看它翻没翻。')],
  'cause-multi-default': [t('同族有多条默认路由，选路在换'), 'bad',
    t('多网卡、或者插了 VPN 之后最典型的病：两条一样的路优先级接近，内核在它们之间换 —— ')
    + t('换到那条不通的就卡一下。★ 这是本机的事，留一条默认路由，或者给另一条降优先级 / ')
    + t('改成只走指定网段。')],
  'cause-round-robin-bad': [t('一个名字解出几台，其中一台是坏的'), 'bad',
    t('DNS 轮询里混了一台下线或半死的机器：解到它就通、解到它就不通，看上去完全是随机。')
    + t('★ 这一条要拿那个名字的完整清单去看，哪一台连不上就先从解析里摘掉。')],
  'cause-clock-disagree': [t('两台机器的钟不一致，日志对不上号'), 'bad',
    t('★ 这时候不能指认谁不对：至少有一个时间源自己就是坏的（或者中间有设备在改写 NTP）。')
    + t('先把对不上的那一个从服务器列表里去掉再问一次，剩下的才可信。')],

  // ── 证书 ──
  'cause-cert-expired': [t('证书确实过期了'), 'bad',
    t('时间也对得上，所以是证书自己的账。必须重新签发一张 —— 过期之后所有客户端都会拒绝，')
    + t('重装应用、清缓存、换浏览器都没用。')],
  'cause-cert-not-yet-valid': [t('证书确实还没到生效时间'), 'bad',
    t('★ 走到这一条，本机那个钟已经对过了、是好的（偏到足以冤枉证书的那种会单独报出来），')
    + t('所以「还没生效」是证书自己说的实话：要么这张证书刚签、还没到它写的生效时刻，')
    + t('要么签它的那台机器钟超前，把生效时间签到了未来。去签发的那一头对时刻。')],
  'cause-cert-name-mismatch': [t('证书上的名字和访问的地址对不上'), 'bad',
    t('要么改用证书上写着的名字访问，要么按现在这个地址重签一张。')
    + t('★ 用 IP 访问内网设备最常撞这一条（设备证书一般只写名字，不写 IP）。')],
  'cause-cert-untrusted': [t('证书本身没坏，是本机不认这条链'), 'warn',
    t('自签、缺中间证书、或者本机没装那个根 —— 内网设备的出厂默认。')
    + t('把它的根证书装进本机信任列表，或者让设备出示完整的链。')],
  'cause-cert-weak-protocol': [t('对方只肯谈老版本 TLS'), 'bad',
    t('TLS 1.0 / 1.1 已被新版浏览器和平台直接拒绝连接。★ 要升级的是设备侧的 TLS 栈，')
    + t('换证书解决不了 —— 老固件的设备只能换固件或者放在只走专网的位置上。')],
  'cause-clock-made-cert-bad': [t('证书是被本机时钟冤枉的'), 'bad',
    t('★★ 这一条是这张树里最值钱的一档：证书没过期，是这台机器的钟偏得把它推出了有效期窗口。')
    + t('没有「先问时间」这一步，现场就会白跑一趟 CA，而毛病在自己主机的任务栏上。先校时，')
    + t('再看那个报错还在不在。')],
  'cause-not-tls': [t('那个端口回的不是 TLS'), 'bad',
    t('地址写成了 https，端口后面却是明文服务（或者反过来）。★ 改个前缀就好，')
    + t('不用查证书也不用查网络 —— 这一条单独占一档就是为了别让人去装证书。')],

  // ── 一台设备不在线 / 没画面 ──
  'cause-device-off-link': [t('二层就没有这台设备'), 'bad',
    t('★ 同网段那一问里别的设备都在，只有它一个信号没发过：网络配置不用查了。')
    + t('去查线、查那个 PoE 口给没给功率、查它是不是关着机或被人搬走了。')],
  'cause-device-no-icmp': [t('设备活着，只是不理 ping'), 'warn',
    t('它应了 ARP 却不回 ICMP —— 这是摄像头的常态，不是毛病。★ 别拿「ping 不通」写进报告里说设备离线，')
    + t('去问它的服务端口（554 / 80 / 私有 SDK 口）。')],
  'cause-device-no-service': [t('设备在，但那些服务口一个都没开'), 'bad',
    t('端口明确回了拒绝，说明主机活着。★ 那就不是链路的事：查取流服务开没开、')
    + t('通道号对不对、这个账号有没有该通道的权限（NVR 上不同用户开的通道不一样）。')],
  // ── 「向设备问取流地址」那一步的七种落点 ──
  // ★ 这一批的共同点：地址问不出来，下一步就没东西可验 —— 所以话术全都在说
  //   「那这一格怎么补」，而不是复述 ONVIF 回了什么。
  'cause-onvif-auth': [t('设备要账号才肯说取流地址'), 'warn',
    t('401 是它答了、只是不放行，不是设备坏了。★ 很多相机把 ONVIF 账号和 Web 登录账号分开管，')
    + t('拿后台密码来问 ONVIF 问不通是常态 —— 去它自己的「用户 / ONVIF 设置」里单加一个。')],
  'cause-port-not-onvif': [t('那个端口上不是 ONVIF'), 'warn',
    t('连得上、也回了话，可回的不是 ONVIF 应答。★ 先照上面那一步自己那句话办：它要是说「那个端口说的是 HTTPS」，')
    + t('把地址前缀改成 https:// 再问一次就好，这不是故障；它回的是一页网页，那地址就得去后台的「取流 / 网络」页里抄。')],
  'cause-onvif-unsupported': [t('这台不接 ONVIF 的这一问'), 'warn',
    t('包它认、账号也过了，可它回一句「不会这一问」。ONVIF 是分档实现的（S / T / M），')
    + t('只做设备档的就没有媒体服务。★ 这不必去翻密码，要确认的是这台到底支持到哪一档。')],
  'cause-onvif-no-media': [t('身份问到了，可说 RTSP 的那一路没问出来'), 'warn',
    t('它肯报自己是哪台，但几路流、地址在哪这一路没答上来（媒体服务没起、挂在别的端口上，')
    + t('或者它只给了 http 那一路 —— 下一步只会说 RTSP）。★ 这路地址我们问不出来：')
    + t('去设备后台抄一条填在高级的「网址」里，这一步就接着往下问。')],
  'cause-onvif-no-profile': [t('设备自己说它一条码流都没配'), 'bad',
    t('媒体服务答得清清楚楚：0 路。这就不是链路、也不是账号的事 —— 是那个通道没出码流。')
    + t('去设备上把主 / 子码流建出来，配好再问一次地址。')],
  'cause-onvif-silent': [t('端口开着，可它不回 ONVIF 这一问'), 'bad',
    t('连上了一个字都没回 —— 和「连不上」是两种病，这一种多半是那个服务卡住了，')
    + t('或者它压根不在这端口上应答。★ 先看设备的 Web 后台打得开吗，再对端口号。')],
  'cause-onvif-unreachable': [t('ONVIF 那一问连都连不出去'), 'warn',
    t('默认 80 没人应 —— 各家会把 ONVIF 挪到 8899 / 2020 / 8080，或者只在 https 上。')
    + t('★ 先进后台确认它开了 ONVIF、端口是多少；有取流地址的话直接填到高级的「网址」里，这一步就绕过去了。')],
  // ── 「拉平台那份清单」那一步的十种落点（手里那一路是平台给的 m3u8）──
  // ★ 这一批和上面那批的区别只有一句话：中间隔着一层平台。
  //   设备肯给流 ≠ 平台这份清单还在往前挪，所以话术全在说「这一步查谁」。
  'cause-hls-ok': [t('平台这一路是活的，「没画面」在播放那一侧'), 'warn',
    t('★ 清单在往前挪、抽查的分片取得到、码率也量得出来 —— 推流和平台这两段都没事。')
    + t('去查客户端：编码是 H.265 的话浏览器基本不放（换 H.264 那一路）、')
    + t('播放器切没切到这一路、平台到客户端那一段（CDN / 反向代理）有没有换地址。')],
  'cause-hls-stalled': [t('清单还写着，可窗口一片没往前挪'), 'bad',
    t('★ 这一档最坑人：地址对、不报错、页面上看着一切正常，可连着两次拉的清单里')
    + t('那几片一模一样 —— 源头早就不往前推了，平台只是照着旧清单继续发。')
    + t('别在平台日志里找错，去推流那侧看编码器的码率曲线（多数已经掉到 0）；')
    + t('顺带确认这台是不是只有被人看时才出流（按需取流的设备一断观看就停推）。')],
  'cause-hls-segment-missing': [t('清单点名的分片，源上取不到'), 'bad',
    t('清单是新的、分片却回 404 / 403 —— 平台内部对不上号。★ 多是清理策略与窗口对不齐：')
    + t('留的片数比清单承诺的少，或者分片落在多台节点上而存储没共享（问到 A 节点、')
    + t('清单是 B 节点写的）。先在平台上换一路地址再问一次，只有一路这样就是这一路的配置。')],
  'cause-hls-empty': [t('清单是空的，一条分片都没点'), 'bad',
    t('★ 这一路此刻没有内容 —— 要么刚点开播还没推上来，要么设备到平台那一段断了。')
    + t('过十几秒再问一次：仍然空就去查推流端（它有没有在发），')
    + t('不空就是刚起来那一下没画面，不用改任何东西。')],
  'cause-hls-target-over': [t('能播，但每一片都比承诺的长'), 'warn',
    t('清单写着「一片最多 N 秒」，实测那片比这还长。★ 起播没问题，')
    + t('播放器会反复缓冲、画面越播越往后拖 —— 现场读成「卡」而不是「坏」。')
    + t('这是编码端的 GOP / 切片间隔改了而平台没跟着改承诺值，两边对一遍。')],
  'cause-hls-auth': [t('平台要账号才给这份清单'), 'warn',
    t('★ 401 / 403 是它答了、只是不放行，不是这一路坏了。')
    + t('清单地址常常带着有时效的签名参数（token 过期就是这一档）：地址要从页面上现抄，')
    + t('别把昨天那条存成书签。用固定账号访问就在本卡的高级里填，口令不进结果。')],
  'cause-hls-not-found': [t('这个路径上没有这路清单'), 'bad',
    t('平台在、这个应用名下没有这条流。★ 流名 / 应用名对不上是主因，')
    + t('再确认这一路在平台上起没起（很多平台只在有人订阅时才生成清单，那是空清单不是 404）。')],
  'cause-hls-not-hls': [t('它答话了，答的不是清单'), 'warn',
    t('★ 拿回来的东西认不出是 m3u8 —— 那个地址多半是网页、裸流（FLV / MP4）或别的服务，')
    + t('结果里 looksLike 那一栏说了它像什么。对上是 FLV 就去问 RTSP 或 HTTP-FLV 那一路，')
    + t('是一页网页说明抄地址抄到了后台页面上。')],
  'cause-hls-unreach': [t('连不上平台的那个口'), 'bad',
    t('★ 先看结果里 reach 那一栏：closed 是机器在、这个口上没服务（端口或前缀错了）；')
    + t('filtered 是它一句都不答（防火墙只放行了白名单）。这两种下一步完全不同，别并成「网络不通」。')],
  'cause-hls-timeout': [t('连上了，可它到点没回话'), 'bad',
    t('TCP 是建起来了，问一句清单过去半天不回。★ 平台的清单接口挂住了：')
    + t('它自己在等上游、或者后端取流慢把接口一起拖死。换个时段再问一次，')
    + t('同时问一段平台上别的路 —— 别的路也这样就是平台，只有这一路就是这路。')],
  'cause-rtmp-ok': [t('推上来这一路是好的，字节真到了服务器'), 'ok',
    t('★ 这一问的落点是「服务器已经收到码流了」—— 那么画面上没有，毛病在它后面那一层：')
    + t('平台的转发 / 分发（HLS、WebRTC 那几路是各自起的）、播放端用的地址与账号、')
    + t('或者域名解析到的不是这台。顺带看结果里声明码率与实测码率差多少，差一半是链路在丢。')],
  'cause-rtmp-no-media': [t('服务器说有这路、play 也答应了，可一个媒体字节都没到'), 'bad',
    t('★★ 这是 RTMP 这一问最值钱的一档，也是最容易被读成「正常」的一档：命令全部通、')
    + t('状态码是 Play.Start，唯独码流没过来。十有八九是推流端与服务器之间的中间那道 NAT / 防火墙')
    + t('只放行了 1935 上的命令，媒体从另一个口或者另一条连接走（SRS、nginx-rtmp 都有这种配法）。')
    + t('先让推流端在服务器本机跑一次：本机有字节 = 中间那道挡了，本机也没有 = 推流端在推空壳。')],
  'cause-rtmp-stream-absent': [t('这个名字上根本没有流'), 'bad',
    t('★ 服务器直接回 StreamNotFound —— 它连找都没找到，和「找到了但没人推」是两回事。')
    + t('核对推流地址与播放地址上的流名：各家服务器带参数（?live=1、?key=）时那一段也算名字的一部分，')
    + t('少一段就是另一个流。')],
  'cause-rtmp-not-publishing': [t('名字认得，可此刻没人往上面推'), 'bad',
    t('★ 服务器知道这一路（配置里写着、或者以前推过），现在没人在推 —— 问题在推流端那一头，')
    + t('不在服务器。看相机 / OBS / 转推服务那台机器活没活、它的推流日志有没有断线重连，')
    + t('再看它推的是不是这个地址。别在服务器上重启：重启完还是没人推。')],
  'cause-rtmp-app-only': [t('只问到「这台认不认这个应用」，这路在不在推根本没问'), 'warn',
    t('★ 这一条不是好消息也不是坏消息：地址里没写流名，所以探测只发到 connect 那一步就停了。')
    + t('把地址补成 rtmp://主机/应用名/流名 再问一次，才问得出「这一路此刻有没有码流」。')],
  'cause-rtmp-app-rejected': [t('connect 被拒 —— 应用名不对，或这台只肯收推流'), 'bad',
    t('★ 握手做完了，可它不认这个应用。三种可能：应用名拼错（live、stream、openapi 各家不同）、')
    + t('这台服务器只允许推不允许看（很多 nginx-rtmp 默认就这样）、或者它按 vhost 分租户而这次没带。')
    + t('先抄平台给的原样地址，别手敲；仍被拒就问平台要「播放侧要不要单独开」。')],
  'cause-rtmp-auth': [t('这台要凭据才给进'), 'warn',
    t('★ 拒绝的理由写的是 key / token / 口令不对 —— 不是坏了，是问到了只是不给。')
    + t('RTMP 的凭据有三种落点：挂在流名后面的 ?key=、挂在应用名上、或者进 connect 参数里的 vhost。')
    + t('结果里「拒绝原文」那一格说了它要哪一种，照那个位置补。')],
  'cause-rtmp-silent': [t('握手通了，命令发出去到点不回话'), 'bad',
    t('★★ 这一档和「connect 被拒」的下一步完全相反：被拒是它答了「不给」，沉默是它压根不答。')
    + t('多半是这台只肯收推流、对播放侧的命令直接丢弃（不少只做单向转推的服务器就这样），')
    + t('或者中间那台设备只放行了握手那种小报文。换到服务器本机问一次，本机有回话就是中间那道。')],
  'cause-port-not-rtmp': [t('那个口接了 TCP，却不说 RTMP'), 'bad',
    t('★ 端口是开的、连接也建了，但对面回的不是 RTMP 握手 —— 结果里 looksLike 那一栏说了它像什么。')
    + t('最常见的三种：1935 上配的其实是 HTTP-FLV（那就用 HLS / HTTP 那一张卡去问）、')
    + t('端口号抄错撞上了 Web 管理页、或者这台只开了 TLS（rtmps://）。')],
  'cause-rtmp-unreachable': [t('连不上推流服务器的那个口'), 'bad',
    t('★ 先看结果里 reach 那一栏：closed 是机器在、这个口上没服务（RTMP 服务没起，或者端口不是 1935）；')
    + t('filtered 是它一句都不答（防火墙只放行了白名单，相机与平台之间最常卡这一条）。')
    + t('这两种下一步完全不同，别并成「网络不通」。')],
  'cause-rtmp-handshake-silent': [t('端口能连上，可握手那一句到点没回'), 'bad',
    t('★ TCP 建起来了，RTMP 握手却石沉大海 —— 这一档几乎不是「服务没起」（没起会直接拒），')
    + t('而是中间有东西只放行 TCP 三次握手、往下看都不看就丢，或者这台只对外地那几台地址答话。')
    + t('先去服务器本机问 127.0.0.1：本机通、外部不通，就是访问控制而不是推流端。')],
  'cause-rtmp-dropped': [t('问到一半它把连接断了'), 'bad',
    t('★ 连接建立、命令也发了，可它在答完之前就把连接关了。结果里「断之前问到什么」那一格是分界的依据：')
    + t('收到 Play.Start 才断 —— 服务器不认这个客户端（版本、并发数、单连接时长限制）；')
    + t('connect 后面就断 —— 这台的白名单 / 频次限制把这一问踢了；什么都没收到就断 —— 中间那台设备在掐。')],
  'cause-stream-auth': [t('问到了，只是不让看'), 'warn',
    t('★ 401 不是设备坏了，是它答了并且认得这个请求。核对账号密码，再确认这个账号')
    + t('对该通道有取流权限 —— 现场十次有八次是权限而不是密码。')],
  'cause-port-not-rtsp': [t('那个口接了 TCP，却不说 RTSP'), 'bad',
    t('★ 端口是开的、连接也建了，但对面不认 RTSP 这句话 —— 多半是端口号填错了：')
    + t('554 才是 RTSP，80 是 Web 管理页，8000 / 8200 是各家私有 SDK 的口子。')
    + t('对着「扫一片端口」那一行看它到底开的是哪个口，再改地址里的端口。')],
  'cause-stream-missing': [t('设备答了，但这个通道上没有这路流'), 'bad',
    t('设备是好的、账号是好的，只有路径不对。★ 海康是 /Streaming/Channels/101，')
    + t('大华是 /cam/realmonitor?channel=1&subtype=0 —— 通道号和主/子码流就差最后那几位。')],
  'cause-stream-broken': [t('设备应了，但这路流没配出媒体轨'), 'bad',
    t('连上、认证都过了，DESCRIBE 的应答里一条媒体轨都没有 —— 这不是「拉不到画面」，')
    + t('是设备上那一通道根本没出码流。去设备那侧确认通道已启用、码流（主/子）已配置，')
    + t('再换一条路径问一次。')],
  'cause-stream-no-data': [t('它答应给流，可一个包都没来'), 'bad',
    t('★ 轨有、账号过、PLAY 也回了 200 —— 前面几步全对，唯独码流没到本机。')
    + t('先确认这台让不让第二路取流（多数型号只开一路，平台正在拉时它就这么答）；')
    + t('再分清是哪一路没通：走 UDP 时收流用的是本机一批临时偶数口，')
    + t('隔了 NAT 或防火墙只看已知服务口，包就回不来 —— 换 TCP 交织再问一次，')
    + t('TCP 收得到就是那批 UDP 口被挡，不是设备没发。')],
  'cause-stream-ok': [t('流在播，「没画面」是那头的显示侧'), 'warn',
    t('★ 这一条的作用是把人从设备前叫走：它肯给流、编码和分辨率都对。')
    + t('查客户端的解码能力、播放器那边收没收到、或者平台有没有把这路转发出去。')],
  'cause-egress-blocked': [t('路到得了出口那台机器，却连不上它那个口'), 'bad',
    t('局域网好、解析也正常、路径也追到了，就是连不上那个端口 —— 拦在中间或出口那一段：')
    + t('NAT 没做、ACL 只放行了内网、或者认证门户还没过。★ 这一档不该去查终端设备。')],
  'cause-wrong-scheme': [t('协议前缀写反了'), 'warn',
    t('明文口写成 https（或反过来）。★ 这不是慢，是先撞一次再重试 —— 所以症状看着像「慢」，')
    + t('改个前缀就消失。取流地址用 rtsp://，别用 http://。')],
};

// 每一步给人看的那几项取值。★ 后端按 shows 挑好了给人看的字段，这里只负责说清是什么。
const TREE_FACT = {
  first: t('先坏在'), count: t('一共几条'), multiDefault: t('同族默认路由'),
  iface: t('出口网卡'), destination: t('目的'), direct: t('是不是直连'), from: t('这个结论从哪来'),
  sent: t('发出'), recv: t('收到'), received: t('收到'), lossPercent: t('丢包率'),
  jitterAvgMs: t('抖动'), rttMaxMs: t('最大往返'), rttAvgMs: t('平均往返'), spikes: t('尖峰在第几发'),
  lostAt: t('丢在第几发'),
  rcode: t('应答码'), server: t('问的是哪台服务器'), elapsedMs: t('用时'), eyeballs: t('两族谁先连上'),
  family: t('地址族'), hopsSeen: t('见到几跳'), engine: t('用什么测的'),
  lossHop: t('丢包从第几跳起'), latencyHop: t('变慢从第几跳起'), goalSeen: t('见到终点'),
  roundsDone: t('跑完几轮'), target: t('问的是'), open: t('开着的口'), closed: t('关着的口'),
  transport: t('收流走的口子'), bitrateKbps: t('实际码率'),
  filtered: t('一个都没回'), scanned: t('扫了几个口'), openPorts: t('开着的端口清单'),
  subnets: t('扫的网段'), alive: t('在有几台'), asked: t('问了几个地址'), hosts: t('清单'),
  notAfter: t('到期时间'), notBefore: t('生效时间'), issuer: t('签发者'), subject: t('证书上的名字'),
  protocol: t('谈成的协议版本'), daysLeft: t('还剩几天'), status: t('状态'), timings: t('各段耗时'),
  url: t('地址'), offsetMs: t('差了多少'), checkedWith: t('问的是哪台时间源'),
  agreeSources: t('互相印证的源'), attribution: t('是谁不对'), codec: t('编码'),
  width: t('宽（像素）'), height: t('高（像素）'), trackCount: t('有几路轨'), answers: t('解出来的地址'),
  manufacturer: t('它自报是哪台'), model: t('型号'), profileCount: t('它自报几路码流'),
  mediaUri: t('问出来的取流地址'),
  // 平台清单那一步（media.hls.probe）给人看的几项
  httpStatus: t('它回的'), segmentCount: t('清单里有几片'), windowSec: t('窗口多长'),
  windowAdvanced: t('窗口往前挪了'), mediaSequence: t('序号起点'),
  pathMtu: t('路上允许的包长'), suggestion: t('建议设成'), mtu: t('这块口的 MTU'),
  lossAt: t('丢在第几发'),
  // 双栈那一步里 Happy Eyeballs 那几项
  code: t('读数'), preferred: t('先试'), winner: t('连上的是'), stallMs: t('要卡'),
  worstMs: t('最坏卡'), connDelayMs: t('多久回落'), willStall: t('会不会先卡'),
  // 网页探测那一步的分段耗时
  lookupMs: t('解析'), connectMs: t('建连'), tlsMs: 'TLS', serverMs: t('服务端'), totalMs: t('合计'),
};

// 布尔值在人话里必须带上「是谁给的」：direct=true 是「按表算着像直连」，不是「一定直连」。
const TREE_YESNO = { direct: [t('算直连'), t('不算直连')], goalSeen: [t('见到了'), t('没见到')],
  // 清单窗口那一格：★「一动不动」和「没问」是两件事，没问时后端根本不给这一栏。
  windowAdvanced: [t('往前挪了'), t('一片没换')] };

function treeFactWord(k, v) {
  if (typeof v === 'boolean') {
    // 布尔值也要有个名字：直接印 true/false 等于没译。
    const t = TREE_YESNO[k] || [t('是'), t('否')];
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
    if (!v.length) return t('<span class=\"dim\">一条都没有</span>');
    const items = v.slice(0, 4).map((x) => {
      if (x && typeof x === 'object') {
        // 主机 / 解析结果那一类：优先给地址，再给它凭什么在线。
        const addr = x.addr || x.ip || x.address || x.name || x.value || '';
        const ev = x.evidence ? t('（{0}）', [esc(EVIDENCE[x.evidence] ? EVIDENCE[x.evidence][0] : x.evidence)]) : '';
        const mac = x.mac ? `<span class="dim"> ${esc(x.mac)}</span>` : '';
        if (addr) return `${esc(addr)}${ev}${mac}`;
        return esc(Object.entries(x).slice(0, 2).map(([kk, vv]) => treeFactWord(kk, vv)).join(' '));
      }
      return esc(String(x));
    });
    const more = v.length > 4 ? t('<span class=\"dim\"> 等 {0} 条</span>', [v.length]) : '';
    return `${items.join(t('、'))}${more}`;
  }
  if (typeof v === 'object') {
    return Object.entries(v)
      .map(([kk, vv]) => `<span class="dim">${esc(TREE_FACT[kk] || kk)}</span> ${treeFactVal(kk, vv)}`)
      .join(t('　'));
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
  if (!e.length) return t('<span class=\"dim\">—（这一步不带参数）</span>');
  // ★ 后端已经把口令和团体名换成占位词了；这里只是别把它们摊成一大片。
  return e.map(([k, v]) => `<code>${esc(k)}=${esc(treeArgWord(k, v))}</code>`).join(' ');
}

function treeArgWord(k, v) {
  if (typeof v === 'boolean') return v ? t('是') : t('否');
  if (typeof v === 'object') return JSON.stringify(v);
  return v;
}

function treeStepRow(s, i) {
  const st = TREE_STATUS[s.status] || [s.status || '—', 'bad', ''];
  const codePill = s.code === 'tool-missing'
    // ★ 这一条不是网络的读数，是我们那张表写错了 —— 必须说成我们的锅。
    ? t('<span class=\"pill bad\">路线里写着它，可它没注册</span>')
    : treeCodePill(s.step, s.code);
  const why = s.note || s.toolNote || st[2];
  return `<tr>
    <td class="dim">${i + 1}</td>
    <td>${esc(s.stepName || s.step)}<div class="dim"><code>${esc(s.tool)}</code></div></td>
    <td>${treeArgs(s.args)}</td>
    <td><span class="pill ${st[1]}">${esc(st[0])}</span></td>
    <td>${codePill || t('<span class=\"dim\">没有判定</span>')}${why ? `<div class="dim" style="margin-top:3px">${esc(why)}</div>` : ''}</td>
    <td>${treeFacts(s.facts)}</td>
  </tr>`;
}

function troubleCard() {
  const card = $(t('<div class=\"card\">\n    <h2>按症状排查 <span id=\"tr-top\"></span></h2>\n    <p class=\"hint\">上面那张体检是「全过一遍」，这一张是<b>你说一句症状，我按工程师的顺序只走那一条路</b>，\n      停在第一个能解释它的判定上。★ 每一步都写明「问了什么工具、答了什么、所以接下来问什么」，\n      没问出去的那几步也留着 —— 那份推理路径可以直接拿去跟二线对质，比一句「网络没问题」有用。\n      全程只读、不发多余的包、不改任何东西。</p>\n    <div class=\"row\">\n      <div style=\"flex:0 0 250px\"><label>哪一句症状</label>\n        <select id=\"tr-s\">{0}</select></div>\n      <div><label>目标（地址或域名）</label>\n        <input id=\"tr-t\" placeholder=\"192.168.1.64 或 cam.example.com\"></div>\n      <div style=\"flex:0 0 110px\"><label>端口</label><input id=\"tr-p\" placeholder=\"554 / 443\"></div>\n    </div>\n    <p class=\"hint\" id=\"tr-hint\" style=\"margin-top:8px\"></p>\n    <div id=\"tr-auth\" style=\"display:none;margin-top:10px\">\n      <div class=\"row\">\n        <div><label>账号（问设备取流时用）</label><input id=\"tr-u\" autocomplete=\"off\"></div>\n        <div><label>口令</label><input id=\"tr-w\" type=\"password\" autocomplete=\"off\"></div>\n        <div><label>SNMP 团体名</label><input id=\"tr-c\" autocomplete=\"off\"></div>\n      </div>\n      <p class=\"dim\" style=\"margin-top:6px\">★ 填在这里的口令和团体名<b>不会</b>出现在结果、推理路径或诊断包里\n        —— 路径上只留「给了、但没写出来」，所以「配了但没给你看」和「没配」在结果里分得开。</p>\n    </div>\n    <details style=\"margin-top:8px\"><summary class=\"dim\">高级：换网址 / 多个端口 / 只在哪块网卡上找 / 跑多久</summary>\n      <div class=\"row\" style=\"margin-top:10px\">\n        <div><label>网址（慢、证书报错时给具体地址；取流给 rtsp://）</label>\n          <input id=\"tr-x\" placeholder=\"https://192.168.1.20 或 rtsp://...\"></div>\n        <div style=\"flex:0 0 170px\"><label>要看好几个端口</label><input id=\"tr-ps\" placeholder=\"554,80,8000\"></div>\n      </div>\n      <div class=\"row\" style=\"margin-top:10px\">\n        <div style=\"flex:0 0 190px\"><label>只在这块网卡上找</label><input id=\"tr-i\" placeholder=\"en0 / eth0\"></div>\n        <div style=\"flex:0 0 120px\"><label>单发等待 ms</label><input id=\"tr-to\" placeholder=\"默认 2000\"></div>\n        <div style=\"flex:0 0 130px\"><label>这棵树最长跑几秒</label><input id=\"tr-ms\" placeholder=\"默认 120\"></div>\n        <div style=\"flex:0 0 150px\"><label>&nbsp;</label>\n          <label class=\"dim\"><input type=\"checkbox\" id=\"tr-q\"> 快一点（少发几发，先要个方向）</label></div>\n      </div>\n    </details>\n    <div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"tr-go\">开始排查</button></div>\n    <div id=\"tr-out\" style=\"margin-top:14px\"></div>\n  </div>', [Object.entries(SYMPTOM).map(([k, v]) =>
          `<option value="${k}">${esc(v[0])}</option>`).join('')]));
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
    out.innerHTML = t('<div class=\"empty\">排查中…（按顺序只走那一条路，最长 {0} 秒 ——\n      逐跳和连续 ping 那几步要多发几发，稍等）</div>', [args.maxSeconds || 120]);
    const r = await call('net.troubleshoot', args);
    if (!r.ok) {
      top.innerHTML = '';
      out.innerHTML = t('<div class=\"empty\">没跑起来：{0}</div>', [esc(r.message || r.error)]);
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
    out.innerHTML = t('\n      <div style=\"background:{0};border:1px solid {1};border-radius:6px;padding:10px 12px;font-size:13.5px\">\n        {2}\n        {3}\n      </div>\n      <p class=\"dim\" style=\"margin:10px 0 0\">{4}</p>\n      <table style=\"margin-top:12px\">\n        <tr><th></th><th>按排查顺序</th><th>问了什么</th><th>状态</th><th>判定</th><th>依据</th></tr>\n        {5}\n      </table>\n      <p class=\"hint\" style=\"margin-top:10px\">★ 一共问了 {6} 步。状态写成「没问出去」或「没问到这一步」的那些，\n        就是这份结论的边界 —— 想让它们也问出结果，把「目标」填实，或者去高级里把时间调够。</p>\n      <p class=\"hint\" style=\"margin-top:6px\">每一步的判定用的就是那一页同一个工具的判定，话术一份都没有重写。\n        想单独把某一步问细，去下面「出问题了」以外的对应页。</p>\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{7}</pre></details>', [bg, line, esc(tAdvice), idx >= 0 ? t('<div class=\"dim\" style=\"margin-top:6px\">定位在第 {0} 步（{1}）—— 那一步的依据：{2}</div>', [idx + 1, esc(v.causeName || v.causeStep), causeFacts]) : '', esc(r.note), steps.map(treeStepRow).join(''), v.asked || 0, esc(JSON.stringify(r.raw, null, 2))]);
  };
  card.querySelector('#tr-t').onkeydown = (e) => { if (e.key === 'Enter') card.querySelector('#tr-go').click(); };
  return card;
}

/*
 * ── 抓包看内容（net.capture.*）──
 *
 * ★★ 这一页是「按症状排查」往下走的那一步。前面那些页都在问「通不通、快不快」，
 *   而现场最后一句永远是「那里面到底跑了什么」—— 那一问只有包能答。
 *
 * ★★ 两条口径必须分开摆：盘上那份 pcapng 是**原始包**（明文口令、SNMP 团体名、
 *   国标 digest response 全在里面），页面上这张表是**脱了敏的**（凭据只留「带没带、多长」）。
 *   所以每一张卡都把这句话带到人眼前：人转出去的是表；把文件发出去就等于把口令发出去。
 *
 * ★ 界面一处都不算。包数账、丢包口径、流表、逐条判定、跨流引用，全部来自后端；
 *   这里只把码翻成人话。判定点名的那个数和表上摆的那个数同源。
 *
 * ★ 「起不来」分四档各给一步：要提权 / 这平台没有这一档 / 场上挂着别人下的筛选器 /
 *   点名的网卡没有。混成一句「抓包失败」，人就只会一遍遍点同一个按钮。
 */

// 开 / 状态 / 停 这一张卡的九档。
const CAP_STATE = {
  'capture-running': [t('正在抓'), 'ok'],
  'capture-running-lossy': [t('正在抓，但内核已报丢包'), 'bad'],
  'capture-idle': [t('没在抓，上一次的账还在'), ''],
  'capture-stopped': [t('停掉了，文件留着'), ''],
  'capture-no-session': [t('这台机器上没有抓包的账'), ''],
  'capture-no-privilege': [t('起不来：这一档要提权'), 'bad'],
  'capture-unsupported': [t('这个平台没有现场抓这一档'), 'bad'],
  'capture-filter-present': [t('场上挂着别人下的筛选器'), 'bad'],
  'capture-no-interface': [t('点名的网卡在这台机器上没有'), 'bad'],
};

// 表这一张卡的六档。★ 与上面分开：「这份来源没包」和「这台机器起不来」是两种下一步。
const CAP_TABLE = {
  'capture-flows': [t('表出来了'), 'ok'],
  'capture-no-packets': [t('一个包都没收到'), 'warn'],
  'capture-no-flows': [t('收到包了，归不出一条流'), 'warn'],
  'capture-no-flow': [t('这一条流不在当前这张表上'), 'bad'],
  'capture-file-unreadable': [t('那份文件读不动'), 'bad'],
  'capture-no-session': [t('手上没有一份能看的账'), ''],
};

// ★ 丢包三种口径不许并成一句「有丢包/没丢包」：数到了几包才谈得上「丢的是哪几包」，
//   只知道丢过就只能说方向，而「这一档平台给不出计数」既不是没丢也不是丢了。
const CAP_DROP = {
  counted: [t('数到了包数'), 'bad'],
  'flagged-only': [t('只知道丢过，给不出几包'), 'warn'],
  'none-reported': [t('内核没报丢包（不等于一包没丢）'), 'ok'],
  unknown: [t('这一档说不出丢没丢'), 'warn'],
};

const CAP_WHY = {
  user: t('人停的'),
  duration: t('到了自己定的时长'),
  'max-bytes': t('★ 到了文件大小上限 —— 不是这条链路没流量了'),
  'io-error': t('读包或写文件出错（先查是不是盘满了）'),
  'close-timeout': t('★ 关口没回音，账先收在这儿：文件末尾可能还差几包'),
};

let capTimer = null;
let capPick = null;   // 流表上的「看这一条」按下去，填进明细卡
// ★ 对端那一路的轮询单独一个表：本机那一路停了不代表那一路停了，
//   两张卡各有各的「还在不在跑」，共用一个 timer 就会互相把对方掐了
let peerCapTimer = null;

async function renderCapture(root) {
  root.appendChild(captureCard());
  root.appendChild(captureFlowsCard());
  root.appendChild(captureFlowCard());
  root.appendChild(captureOpenCard());
  // ★ 第五张：对端那一路。放在最后是因为它依赖前面这几张的表 ——
  //   取回来的那份顶进的就是同一张账，人看完这一张就往下滑到「看表」那一张。
  root.appendChild(peerCaptureCard());
}

const capClock = (s) => (s ? fmtStamp(s) : '—');

// capFacts 一行一条「这一格从哪来」：抓包这一页的数全是现场证据，说不清出处就等于没有。
function capFacts(rows) {
  const kept = rows.filter(Boolean);
  if (!kept.length) return '';
  return `<table style="margin-top:12px"><tr><th></th><th></th></tr>
    ${kept.map((f) => `<tr><td class="dim" style="white-space:nowrap">${f[0]}</td><td>${f[1]}</td></tr>`).join('')}</table>`;
}

/*
 * ★ 「手上什么都没有」这几档，后端给的 note 是一句**没有插值的整话** ——
 *   它和判定码说的是同一件事，所以这句话该归界面：Go 里的中文字面量四本词典都到不了，
 *   而这一格恰恰是新装机器上第一屏读到的「下一步该干什么」。
 *   顶替之后，原话由 uiNoteTail 折在同一格下面（「原始结果」那一叠只 dump values，不含 note，
 *   所以不能拿它当兜底）。
 *
 * ★★ 认的是**后端那句原文的开头**（逐字抄自 backend/internal/tools/{capture,quality,peercapture}.go）：
 *   后端哪天改了口径，这里对不上就自动退回原话 —— 宁可露一句中文，
 *   也不许把「界面那句话」当成后端真说过的东西。带实测数的 note（文件名、包数、错误原文）
 *   不在这一张表里：那些是现场证据，不是套话，照原话上屏。
 */
const UI_SAYS_EMPTY = [
  ['capture-no-session', '本机现在没在抓，也没有上过一次的账', // i18n:source-match
    t('本机现在没在抓，也没有上过一次的账：用 net.capture.start 开一路，或者用 net.capture.open 打开一份别人抓好的文件。')],
  ['capture-no-session', '手上没有一份能看的账', // i18n:source-match
    t('手上没有一份能看的账：先用 net.capture.start 抓一路，或者用 net.capture.open 打开一个文件。')],
  ['capture-peer-no-session', '手上没有一路远程抓包。', // i18n:source-match
    t('手上没有一路远程抓包。先 net.capture.peer.probe 问那台上有什么，再 net.capture.peer.start 点名开一路。')],
  ['quality-idle', '本机没有在跑的持续质量监测，配置目录里也还没有任何留痕', // i18n:source-match
    t('本机没有在跑的持续质量监测，配置目录里也还没有任何留痕 —— 要盯一段时间先开一路（net.quality.watch）。')],
  ['quality-idle', '本机没有在跑的持续质量监测（而且找不到用户配置目录', // i18n:source-match
    t('本机没有在跑的持续质量监测（而且找不到用户配置目录，账没地方存）。')],
];

// 码对不上、或者后端那句话已经不是这里抄的那一句 → 原样退回后端 note。
function uiNote(code, note) {
  if (typeof note !== 'string' || !note) return note;
  for (const [c, prefix, say] of UI_SAYS_EMPTY) if (code === c && note.startsWith(prefix)) return say;
  return note;
}

// 顶替真的发生了，才把后端原话折起来留在下面一格：现场要核对的是
// 「界面这句话有没有替后端多说什么」，那句中文就是核对用的原件。折着不占版面，但一直在。
function uiNoteTail(code, note) {
  if (uiNote(code, note) === note) return '';
  return t('<details style="margin-top:6px"><summary class="dim">后端原话</summary>\n    <span class="dim">{0}</span></details>', [esc(note)]);
}

/*
 * ★ 对端那一路的「下一步」是后端按判定码挑的一句话（peercapture.go 的 peerNextStep），
 *   和 note 同一类毛病：这句话在 Go 里烤成中文，四本词典到不了，
 *   而它恰恰是整张卡上最该看懂的一格。所以按**码**在界面这边给同一句。
 *
 * ★★ 只收不含实测数的那些档。capPeerPullFailed / capPeerConvertFailed 那两档的话里
 *   嵌着对端文件路径（现场证据），界面这句说不出那个路径 —— 宁可让这一档继续露原话，
 *   也不许把没读到的路径编成一句漂亮话。
 *   现在收了 3 档（一次对端抓包从头到尾必经的三格）；剩下十几档没动，
 *   没动的那几档界面上照旧走 v.next 的原话，一条都不会被悄悄吞掉。
 */
const PEER_NEXT_SAY = {
  'capture-peer-ready': t('接着 net.capture.peer.start，interface 就点上面列表里那一个（别从本机网卡名猜）。'),
  'capture-peer-no-session': t('先 net.capture.peer.probe 问那台上有什么，再 net.capture.peer.start 点名开一路。'),
  'capture-peer-stopped': t('表已经在当前这本账上，直接 net.capture.flows 问；要那份原始包的路径就在 file 那一格。'),
};

function capShell(cls, text) {
  const bg = cls === 'ok' ? 'var(--green-bg)' : cls === 'bad' ? 'var(--red-bg)' : 'var(--sunken)';
  const line = cls === 'ok' ? 'var(--green-dim)' : cls === 'bad' ? 'var(--red-line)' : 'var(--line)';
  // ★ 后端这些 note 是分行的（包数账、下一步各占一行），HTML 会把 \n 折成空格：
  //   折完就是一整块看不清的话，而这一段正是这一页最长的一句结论。
  return `<div style="background:${bg};border:1px solid ${line};border-radius:6px;padding:10px 12px;font-size:13.5px;white-space:pre-wrap">
    ${esc(text || '')}</div>`;
}

/**
 * capAccount 这份来源自己的口径：包数账 + 整表那一层的毛病 + 只读了一半 / 到顶停的。
 * ★ 放在表外面而不是塞进某一条流：这些是**这份来源**的毛病，
 *   混进某条流的判定里就会把人支去查一台没病的机器。
 */
function capAccount(v) {
  const parts = [];
  if (v.packetAccount) {
    parts.push(t('<p class=\"dim\" style=\"margin:10px 0 0\">包数账：{0}\n      {1}</p>', [esc(v.packetAccount), v.partialRead ? t('<span class=\"bad\">· 这份文件只读了前面一段，下面所有结论只对读到的那一段成立</span>') : '']));
  }
  const rep = v.report || [];
  if (rep.length) {
    parts.push(t('<p class=\"warn\" style=\"margin:6px 0 0\">这份来源自己的毛病：<br>{0}</p>', [rep.map((r) => `· ${esc(r)}`).join('<br>')]));
  }
  if (v.stopWhy === 'max-bytes') {
    parts.push(t('<p class=\"bad\" style=\"margin:6px 0 0\">这一路是<strong>到了文件大小上限</strong>停的：后面的包没进来，别说成「这条链路没流量」。</p>'));
  }
  if (v.stopWhy === 'close-timeout') {
    parts.push(t('<p class=\"bad\" style=\"margin:6px 0 0\">关口没回音就收了账：文件末尾可能还差几包，别按「这就是全部」用。</p>'));
  }
  if (v.writeErr) {
    parts.push(t('<p class=\"bad\" style=\"margin:6px 0 0\">那一路写文件出过错：{0}（文件可能不完整）</p>', [esc(v.writeErr)]));
  }
  return parts.join('');
}

function captureCard() {
  const card = $(t('<div class=\"card\">\n    <h2>开一路抓包 <span id=\"cap-top\"></span></h2>\n    <p class=\"hint\">把这台机器上（或点名的那块网卡）<strong>每一个包原样</strong>落到一个 pcapng 文件里，\n      同时按流聚合成一张表。★ 默认就留全帧（一包 1600 字节）：「半截报文」是最难查的一种假象 ——\n      长度看着对，内容却是空的。\n      ★ <strong>文件里是原始包，含明文口令、SNMP 团体名、国标 digest response</strong>：\n      发给同事或 AI 的是下面那张脱敏的表，不是这个文件。\n      ★ 这一路会一直占着采集口、一直往盘上写，所以要你点头；一次只开一路，\n      那颗「停」只会停当前这一路。\n      ★ 丢包十有八九是内核环小了（默认 4MB，百兆口全速撑不到一秒），不是网络慢：\n      报了丢包就先把环调大或只抓点名的那块口再抓一次。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 200px\"><label>只抓哪块网卡</label>\n        <select id=\"cap-iface\"><option value=\"\">所有网卡（含回环）</option></select></div>\n      <div style=\"flex:0 0 140px\"><label>最长抓多少秒（空=不停）</label>\n        <input id=\"cap-seconds\" placeholder=\"默认一直抓到你点停\"></div>\n      <div style=\"flex:0 0 140px\"><label>文件上限 MB</label>\n        <input id=\"cap-max\" placeholder=\"默认 256\"></div>\n      <div style=\"flex:0 0 140px\"><label>内核环 MB</label>\n        <input id=\"cap-buffer\" placeholder=\"默认 4\"></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <div style=\"flex:0 0 160px\"><label>一包留多少字节</label>\n        <input id=\"cap-snap\" placeholder=\"默认 1600（全帧）\"></div>\n      <div style=\"flex:1 1 260px\"><label>落到哪个完整路径（空=NetKit 数据目录，文件名带时刻）</label>\n        <input id=\"cap-file\" placeholder=\"已经存在的文件会被直接拒，不覆盖\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <label class=\"dim\" style=\"font-weight:400\"><input type=\"checkbox\" id=\"cap-promisc\"> 混杂模式（不是发给本机的帧也收）</label></div>\n    </div>\n    <p class=\"hint\" style=\"margin-top:6px\">★ 混杂模式不是「抓到别人的包」的开关：交换机上本来就收不到别人的单播，\n      那一档要端口镜像。它只对集线器和镜像口有意义，而且虚拟口与部分无线网卡会直接拒。</p>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <div style=\"flex:0 0 auto;min-width:0\">\n        <button class=\"btn danger\" id=\"cap-go\">开始抓包</button>\n        <button class=\"btn\" id=\"cap-refresh\">刷新状态</button>\n        <button class=\"btn danger\" id=\"cap-stop\" style=\"display:none\">立刻停掉</button>\n        <button class=\"btn\" id=\"cap-reveal\" style=\"display:none\">去看这一张表</button>\n      </div>\n    </div>\n    <div id=\"cap-err\" style=\"margin-top:12px\"></div>\n    <div id=\"cap-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#cap-out');
  const errBox = card.querySelector('#cap-err');
  const top = card.querySelector('#cap-top');
  const btnStop = card.querySelector('#cap-stop');
  const btnGo = card.querySelector('#cap-go');
  const btnReveal = card.querySelector('#cap-reveal');
  const sel = card.querySelector('#cap-iface');

  // 网卡下拉：★ 这里列的是这台机器<strong>现在</strong>有哪几块口，抓不到对端的包
  // 第一个原因常常就是选错了口，所以名字后面带上地址。
  (async () => {
    const r = await call('net.interfaces');
    const ns = (r.ok && r.values.interfaces) || [];
    for (const n of ns) {
      const addr = (n.addrs || []).map((a) => a.cidr).join(' ');
      const o = document.createElement('option');
      o.value = n.name;
      o.textContent = addr ? t('{0}（{1}）', [n.name, addr]) : n.name;
      sel.appendChild(o);
    }
    if (!ns.length) {
      sel.innerHTML = t('<option value=\"\">所有网卡（含回环）</option>');
      errBox.innerHTML = t('<div class=\"empty\">网卡一块都没读到 —— 下拉是空的，只能按「所有网卡」抓。</div>');
    }
  })();

  let busy = false;

  const paint = (code, v, note) => {
    const [title, cls] = CAP_STATE[code] || [code || t('没给判定'), ''];
    const say = uiNote(code, note);
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
    const running = code === 'capture-running' || code === 'capture-running-lossy';
    btnStop.style.display = running ? '' : 'none';
    btnReveal.style.display = (running || v.packets) ? '' : 'none';
    const facts = [];
    if (v.interface !== undefined || running) {
      facts.push([t('抓的是'), v.interface
        ? `<code>${esc(v.interface)}</code>`
        : t('所有网卡（含回环）{0}', [typeof v.interfaces === 'number' ? t(' · 读到 {0} 块口', [esc(v.interfaces)]) : ''])]);
    }
    if (typeof v.snapLen === 'number') {
      facts.push([t('一包留'), t('{0} 字节{1}', [esc(v.snapLen), v.snapLen < 1600 ? t(' <span class=\"warn\">被剪过：正文与后面那半截字段不可信</span>') : ''])]);
    }
    if (typeof v.bufferMB === 'number') { facts.push([t('内核环'), `${esc(v.bufferMB)} MB`]); }
    if (v.promisc) { facts.push([t('混杂模式'), t('开着')]); }
    if (typeof v.packets === 'number') {
      facts.push([t('已经收到'), t('<b>{0}</b> 包 / {1}', [esc(v.packets), esc(fsSize(v.bytes || 0))])]);
    }
    if (v.startedAt) { facts.push([t('什么时候开的'), esc(capClock(v.startedAt))]); }
    if (v.stoppedAt) { facts.push([t('什么时候停的'), esc(capClock(v.stoppedAt))]); }
    if (typeof v.spanMs === 'number') { facts.push([t('抓了多久'), esc(humanMs(v.spanMs))]); }
    if (v.file) { facts.push([t('原始包落在'), `<code style="user-select:all">${esc(v.file)}</code>`]); }
    if (typeof v.maxMB === 'number' && running) { facts.push([t('文件上限'), t('{0} MB（到顶自己停，并且会写清是到顶不是没流量）', [esc(v.maxMB)])]); }
    if (typeof v.seconds === 'number' && v.seconds > 0 && running) {
      facts.push([t('自动停'), t('到 {0} 秒自己停', [esc(v.seconds)])]);
    }
    if (v.stopWhy) { facts.push([t('为什么停了'), esc(CAP_WHY[v.stopWhy] || v.stopWhy)]); }
    if (v.origin === 'file') { facts.push([t('这一张表的来路'), t('导入的文件 <code>{0}</code>', [esc(v.file || '')])]); }
    const drop = CAP_DROP[v.dropAccount];
    const dropRow = drop
      ? t('<p class=\"{0}\" style=\"margin:10px 0 0\">丢包口径：{1}</p>', [drop[1], esc(drop[0])])
      : (typeof v.dropped === 'number'
        ? t('<p class=\"{0}\" style=\"margin:10px 0 0\">这一本账记下的丢包：{1} 包{2}</p>', [v.dropped ? 'bad' : 'dim', esc(v.dropped), v.lossy ? t('（内核还标过「丢过」）') : ''])
        : '');
    out.innerHTML = capShell(cls, say) + uiNoteTail(code, note) + capFacts(facts) + dropRow
      + t('<details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{0}</pre></details>', [esc(JSON.stringify(v, null, 2))]);
  };

  const refresh = async (quiet) => {
    const r = await call('net.capture.status');
    if (busy) return;
    if (!r.ok) {
      if (!quiet) out.innerHTML = t('<div class=\"empty\">看不了状态：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
    const running = r.verdict === 'capture-running' || r.verdict === 'capture-running-lossy';
    if (capTimer) { clearInterval(capTimer); capTimer = null; }
    if (running) capTimer = setInterval(() => refresh(true), 3000);
  };

  const hush = () => {
    busy = true;
    if (capTimer) { clearInterval(capTimer); capTimer = null; }
  };

  btnGo.onclick = async () => {
    const args = {};
    // 不填就交给后端按默认来：这里替它填一个号，等于人没同意过的口径。
    const num = (id, key) => {
      const x = card.querySelector(id).value.trim();
      if (x) { args[key] = Number(x); }
    };
    if (sel.value) { args.interface = sel.value; }
    num('#cap-seconds', 'seconds');
    num('#cap-max', 'maxMB');
    num('#cap-buffer', 'bufferMB');
    num('#cap-snap', 'snapLen');
    if (card.querySelector('#cap-promisc').checked) { args.promisc = true; }
    const f = card.querySelector('#cap-file').value.trim();
    if (f) { args.file = f; }
    hush();
    errBox.innerHTML = '';
    top.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消的话一个包都不收，盘上也不留文件）</div>');
    const r = await call('net.capture.start', args);
    busy = false;
    if (!r.ok) {
      // 「这一路没开起来」和「现在这台是什么状态」是两句话：前一句写在这里，
      // 后一句照样问回来（多半是上一次那份账还躺在盘上）。
      errBox.innerHTML = t('<div class=\"empty\">这一路没开起来：{0}</div>', [esc(r.message || r.error)]);
      refresh(true);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
    if (capTimer) clearInterval(capTimer);
    if (r.verdict === 'capture-running' || r.verdict === 'capture-running-lossy') {
      capTimer = setInterval(() => refresh(true), 3000);
    }
  };

  card.querySelector('#cap-refresh').onclick = () => refresh(true);
  btnReveal.onclick = () => {
    const t = document.getElementById('cap-flows-go');
    if (t) { t.click(); t.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  };
  btnStop.onclick = async () => {
    btnStop.disabled = true;
    hush();
    errBox.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消就还在抓）</div>');
    const r = await call('net.capture.stop');
    btnStop.disabled = false;
    busy = false;
    if (!r.ok) {
      errBox.innerHTML = t('<div class=\"empty\">停不下来：{0}</div>', [esc(r.message || r.error)]);
      refresh(true);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
  };
  refresh(true);
  return card;
}

// capRowsHTML 流表的一行。★ 每条流自己那一层的判定直接摆在这行里，
// 不用先点开 —— 现场是「哪条不对点哪条」，反过来「先点开再发现不对」会漏。
function capRowsHTML(rows) {
  return (rows || []).map((f) => {
    const app = f.app
      ? t('<b>{0}</b> <span class=\"dim\">按{1}</span>', [esc(f.app), esc(f.appBy || t('端口'))])
      : t('<span class=\"dim\">认不出</span>');
    const dirs = `<span class="dim">${esc(f.ab ?? 0)} → / ← ${esc(f.ba ?? 0)}</span>`;
    const notes = [...(f.notes || []), ...((f.findings || []).map((x) => x.text))]
      .filter(Boolean);
    const miss = (f.missing || []).length
      ? t('<div class=\"bad\">信令里说好、表上没有的收流口：{0}</div>', [esc((f.missing || []).join(t('、')))]) : '';
    const links = [];
    if ((f.media || []).length) {
      links.push(t('这条信令开出来 {0} 条媒体流：{1}<span class=\"dim\">（{2}）</span>', [f.media.length, f.media.map((m) => `<button class="btn" data-k="${esc(m.key)}">${esc((m.endpoints || []).join(' ') || m.key)}</button>`).join(' '), esc(f.media.map((m) => m.why).join(t('、')))]));
    }
    if ((f.signaling || []).length) {
      links.push(t('这条媒体流是 {0} 条信令开的：{1}', [f.signaling.length, f.signaling.map((m) => `<button class="btn" data-k="${esc(m.key)}">${esc((m.endpoints || []).join(' ') || m.key)}</button>`).join(' ')]));
    }
    return t('<tr>\n      <td><code>{0}</code><div class=\"dim\">{1} → {2}</div>\n        {3}\n        {4}</td>\n      <td>{5}</td>\n      <td><b>{6}</b><div class=\"dim\">{7}</div>{8}</td>\n      <td class=\"dim\">{9}\n        <div>{10}</div></td>\n      <td>{11}\n        {12}</td>\n      <td>{13}{14}\n        {15}</td>\n      <td><button class=\"btn\" data-k=\"{16}\">看这一条</button></td>\n    </tr>', [esc(f.proto), esc(f.a), esc(f.b), f.iface ? t('<div class=\"dim\">口 {0}</div>', [esc(f.iface)]) : '', f.vlans && f.vlans.length ? `<div class="dim">VLAN ${esc(f.vlans.join(','))}</div>` : '', app, esc(f.packets), esc(fsSize(f.bytes || 0)), dirs, f.durationMs ? esc(humanMs(f.durationMs)) : '—', esc(capClock(f.first).slice(11)), f.handshake ? esc(f.handshake) : '<span class="dim">—</span>', f.creds ? t('<div class=\"dim\">已脱敏 {0} 处</div>', [esc(f.creds)]) : '', notes.length ? notes.map((n) => `<div class="warn">· ${esc(n)}</div>`).join('') : '<span class="dim">—</span>', miss, links.length ? `<div class="dim" style="margin-top:4px">${links.join('<br>')}</div>` : '', esc(f.key)]);
  }).join('');
}

// capTableOut 是「一张表」的统一画法：实时抓的、导入文件的两条来路走这一个函数。
// ★ 两条来路必须同一张形状，否则同一份包从网卡上接的和从磁盘上读的迟早给出两套说法。
function capTableOut(code, v, note) {
  const [title, cls] = CAP_TABLE[code] || [code || t('没给判定'), ''];
  const say = uiNote(code, note);
  const rows = v.flows || [];
  const facts = [];
  // ★ 只在真有一份账的时候摆这几行：「手上没账」那一档结果里一个字段都没有，
  //   照摆就成了「当前这一路：（空）· 还在抓 · 收了 0 包」—— 那句「还在抓」是凭空造的结论。
  if (v.origin) {
    facts.push([v.origin === 'file' ? t('这一张表的来路') : t('当前这一路'),
      v.origin === 'file' ? t('导入的文件 <code>{0}</code>', [esc(v.file || '')])
        // 「还在抓」按 stopWhy 空不空说：这一栏里空串就是「还在收」（后端同一口径）。
        : `<code>${esc(v.file || '')}</code>${!v.stopWhy ? t(' <span class=\"pill ok\">还在抓</span>') : ''}`]);
    facts.push([t('这份账收了'), t('{0} 包 / {1}', [esc(v.packets ?? 0), esc(fsSize(v.bytes || 0))])]);
    if (typeof v.interfaces === 'number') { facts.push([t('涉及几块口'), t('{0} 块', [esc(v.interfaces)])]); }
  }
  if (typeof v.flowCount === 'number') {
    facts.push([t('归出多少条流'), t('<b>{0}</b> 条，这一页列了 {1} 条', [esc(v.flowCount), rows.length])]);
  }
  return {
    html: `${capShell(cls, say)}${uiNoteTail(code, note)}${capFacts(facts)}${capAccount(v)}
      ${rows.length ? t('<div style=\"margin-top:12px;max-height:420px;overflow:auto\"><table>\n        <tr><th>端点</th><th>认出的协议</th><th>包数 / 字节 / 两向</th><th>多久</th><th>TCP 与脱敏</th><th>这一条自己的话</th><th></th></tr>\n        {0}</table></div>', [capRowsHTML(rows)]) : ''}`,
    pill: title ? `<span class="pill ${cls}">${esc(title)}</span>` : '',
  };
}

function captureFlowsCard() {
  const card = $(t('<div class=\"card\">\n    <h2>这一张流表 <span id=\"cf-top\"></span></h2>\n    <p class=\"hint\">把当前这一路（或刚导入的那份文件）按流聚合成一张表：端点、包数与字节、\n      两个方向各自的账、TCP 走到哪一步、认出的应用协议（以及它是<strong>按内容</strong>还是<strong>只按端口</strong>认的），\n      还有这一条流自己的全部判定。★ 表是整表<strong>脱敏</strong>的：认证那几格只留「带没带、多长」——\n      看不到口令不代表设备没带口令。\n      ★ 一条流上可以走一万包，所以「675 包 / 1 条流」不是表漏了什么。\n      只列前 N 条时一定会另外写出来还剩多少条没列。</p>\n    <div class=\"row\">\n      <div style=\"flex:0 0 160px\"><label>只看这个协议</label>\n        <input id=\"cf-app\" placeholder=\"rtsp / sip / onvif / mqtt / snmp / dhcp / dns / rtp\"></div>\n      <div style=\"flex:1 1 200px\"><label>只看端点带这一串的流</label>\n        <input id=\"cf-host\" placeholder=\"设备只有一台的时候用它把表收干净\"></div>\n      <div style=\"flex:0 0 130px\"><label>最多列几条流</label>\n        <input id=\"cf-flows\" placeholder=\"默认 60，最多 500\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn\" id=\"cap-flows-go\">刷新这张表</button></div>\n    </div>\n    <div id=\"cf-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#cf-out');
  const top = card.querySelector('#cf-top');

  const read = async () => {
    const args = {};
    const app = card.querySelector('#cf-app').value.trim();
    const host = card.querySelector('#cf-host').value.trim();
    const n = card.querySelector('#cf-flows').value.trim();
    if (app) { args.app = app; }
    if (host) { args.host = host; }
    if (n) { args.flows = Number(n); }
    out.innerHTML = t('<div class=\"empty\">聚合中…</div>');
    const r = await call('net.capture.flows', args);
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">表出不来：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    const v = r.values || {};
    const { html, pill } = capTableOut(r.verdict, v, r.note);
    top.innerHTML = pill;
    out.innerHTML = html + t('<details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n      <pre class=\"dim\">{0}</pre></details>', [esc(JSON.stringify(v, null, 2))]);
    bindCapKeys(out);
  };
  const go = card.querySelector('#cap-flows-go');
  go.onclick = read;
  card.querySelector('#cf-host').onkeydown = (e) => { if (e.key === 'Enter') read(); };
  read();   // 一开页就把现有的账摊出来：盘上躺着一份昨天的表，人不该去猜
  return card;
}

function bindCapKeys(box) {
  box.querySelectorAll('button[data-k]').forEach((b) => {
    b.onclick = () => { if (capPick) capPick(b.dataset.k); };
  });
}

function capMsgRow(m) {
  // ★ dir 是后端那个下标（0 = 这条流记的那一端 A 发出去，1 = 对端发回来），
  //   不是字符串：把它当 'ab'/'ba' 比一遍，箭头会永远画成「→」，
  //   而「谁先开的口」正是这一栏要回答的问题。
  const dir = Number(m.dir) === 1 ? t('← 对端发的') : t('→ 这一端发的');
  const fields = (m.fields || []).map((fd) => `${esc(fd.k)}=${
    fd.redacted ? t('<span class=\"warn\">〔已脱敏〕</span>') : esc(fd.v)}`).join(t('　'));
  const fs = (m.findings || []).map((x) => `<div class="warn">· ${esc(x.text)}</div>`).join('');
  return `<tr>
    <td class="dim">${esc(capClock(m.at).slice(11))}</td>
    <td>${dir}</td>
    <td><code>${esc(m.line || [m.proto, m.kind, m.method, m.status].filter(Boolean).join(' '))}</code>
      ${m.sdp ? `<div class="dim">${esc(m.sdp)}</div>` : ''}
      ${m.uri ? `<div class="dim">${esc(m.uri)}</div>` : ''}
      ${m.note ? `<div class="dim">${esc(m.note)}</div>` : ''}</td>
    <td class="dim">${fields || '—'}${m.creds ? t('<div>已脱敏 {0} 处</div>', [esc(m.creds)]) : ''}</td>
    <td>${fs || '<span class="dim">—</span>'}</td>
  </tr>`;
}

function captureFlowCard() {
  const card = $(t('<div class=\"card\">\n    <h2>某一条流的明细 <span id=\"cd-top\"></span></h2>\n    <p class=\"hint\">一条流的报文列表（每条一起始行 / 方法 / 状态码 / 关键字段）、跨流引用、\n      以及这一条自己的判定与注记。★ 字段是脱过敏的：认证那几格只留「带没带、多长」。\n      要看真正的包去磁盘上那份 pcapng（原始包，含明文口令，自己权衡发给谁）。\n      key 从上表每一行末那个按钮带过来就行。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 300px\"><label>哪一条流（key）</label>\n        <input id=\"cd-key\" placeholder=\"从上表点「看这一条」自动带过来\"></div>\n      <div style=\"flex:0 0 130px\"><label>最多列几条报文</label>\n        <input id=\"cd-msg\" placeholder=\"默认 40，最多 200\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn\" id=\"cd-go\">读这一条</button></div>\n    </div>\n    <div id=\"cd-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#cd-out');
  const top = card.querySelector('#cd-top');
  const key = card.querySelector('#cd-key');

  const read = async () => {
    const k = key.value.trim();
    if (!k) {
      out.innerHTML = t('<div class=\"empty\">先说是哪一条流 —— 上面那张表每行末点一下就把 key 带过来了。</div>');
      return;
    }
    const args = { key: k };
    const n = card.querySelector('#cd-msg').value.trim();
    if (n) { args.messages = Number(n); }
    out.innerHTML = t('<div class=\"empty\">读这一条…</div>');
    const r = await call('net.capture.flow', args);
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">读不出来：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    const v = r.values || {};
    const [title, cls] = CAP_TABLE[r.verdict] || [r.verdict || t('没给判定'), ''];
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
    const msgs = v.messagesList || [];
    const refs = [];
    if ((v.media || []).length) refs.push(t('开出来的媒体流：{0}', [v.media.map((m) => `<button class="btn" data-k="${esc(m.key)}">${esc((m.endpoints || []).join(' ') || m.key)}</button>`).join(' ')]));
    if ((v.signaling || []).length) refs.push(t('开出它的信令：{0}', [v.signaling.map((m) => `<button class="btn" data-k="${esc(m.key)}">${esc((m.endpoints || []).join(' ') || m.key)}</button>`).join(' ')]));
    out.innerHTML = t('{0}\n      {1}\n      {2}\n      {3}\n      {4}\n      <details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{5}</pre></details>', [capShell(cls, uiNote(r.verdict, r.note)) + uiNoteTail(r.verdict, r.note), capFacts([
        [t('端点'), `<code>${esc(v.a || '')} → ${esc(v.b || '')}</code>`],
        [t('这一条'), t('{0} 包 / {1}，列了 {2} 条报文', [esc(v.packets ?? 0), esc(fsSize(v.bytes || 0)), msgs.length])],
        v.proto === 'tcp' && v.handshake ? [t('TCP 走到哪一步'), esc(v.handshake)] : null,
        (v.notes || []).length ? [t('注记'), v.notes.map((n) => esc(n)).join('<br>')] : null,
        v.creds ? [t('这一条脱敏了几处'), t('{0} 处', [esc(v.creds)])] : null,
      ]), refs.length ? `<p class="dim" style="margin:10px 0 0">${refs.join('<br>')}</p>` : '', (v.findings || []).length ? `<div class="warn" style="margin-top:8px">${
        v.findings.map((f) => `· ${esc(f.text)}`).join('<br>')}</div>` : '', msgs.length ? t('<div style=\"margin-top:12px;max-height:420px;overflow:auto\"><table>\n        <tr><th>时刻</th><th>向</th><th>这一条是什么</th><th>关键字段</th><th>它自己的判定</th></tr>\n        {0}</table></div>', [msgs.map(capMsgRow).join('')]) : '', esc(JSON.stringify(v, null, 2))]);
    bindCapKeys(out);
  };
  card.querySelector('#cd-go').onclick = read;
  key.onkeydown = (e) => { if (e.key === 'Enter') read(); };
  capPick = (k) => {
    key.value = k;
    read();
    card.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  return card;
}

function captureOpenCard() {
  const card = $(t('<div class=\"card\">\n    <h2>打开一份现成的抓包文件 <span id=\"co-top\"></span></h2>\n    <p class=\"hint\">同事用 tcpdump 抓的、设备导出来的、Wireshark 转出来的都算（pcapng 与老 pcap 都认），\n      出与本机抓包<strong>同一张表</strong>：按流聚合、协议专解、逐条判定、整表脱敏。\n      ★ 这个工具只读，不改它、不删它。\n      ★ 有包数上限（默认 20 万）：撞到就停下并明写「只读了前 N 包」——\n      悄悄读完一半就给整份的判断，是最坏的一种错。\n      ★ 这一档也是「这台机器压根抓不了包」时的退路：抓不了就让能抓的人抓一份发过来，\n      在这里打开，看的是同一张表。表是脱敏的，<strong>原始文件里有明文口令</strong>，转发时自己权衡。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 320px\"><label>文件完整路径</label>\n        <input id=\"co-file\" placeholder=\"/Users/you/captures/x.pcapng\"></div>\n      <div style=\"flex:0 0 150px\"><label>最多读多少包</label>\n        <input id=\"co-packets\" placeholder=\"默认 200000\"></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn\" id=\"co-go\">打开并出表</button></div>\n    </div>\n    <div id=\"co-out\" style=\"margin-top:14px\"></div>\n  </div>'));
  const out = card.querySelector('#co-out');
  const top = card.querySelector('#co-top');

  const read = async () => {
    const f = card.querySelector('#co-file').value.trim();
    if (!f) {
      out.innerHTML = t('<div class=\"empty\">先给文件的完整路径 —— 相对路径会落在后端自己的工作目录上，而那个目录现场没人知道在哪。</div>');
      return;
    }
    const args = { file: f };
    const n = card.querySelector('#co-packets').value.trim();
    if (n) { args.packets = Number(n); }
    out.innerHTML = t('<div class=\"empty\">读这份文件…（大文件要等一会儿）</div>');
    const r = await call('net.capture.open', args);
    if (!r.ok) {
      out.innerHTML = t('<div class=\"empty\">打不开：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    const v = r.values || {};
    const { html, pill } = capTableOut(r.verdict, v, r.note);
    top.innerHTML = pill;
    out.innerHTML = html + t('<details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n      <pre class=\"dim\">{0}</pre></details>', [esc(JSON.stringify(v, null, 2))]);
    bindCapKeys(out);
  };
  card.querySelector('#co-go').onclick = read;
  card.querySelector('#co-file').onkeydown = (e) => { if (e.key === 'Enter') read(); };
  return card;
}

/*
 * ── 对端那一路抓包（net.capture.peer.*）──
 *
 * ★★ 这一张卡和上面那一张的根本差别：包不在本机的网卡上长，是在**别人家机器的盘上**长。
 *   所以「NetKit 退出了」不等于「那一路停了」—— 那个进程归那台机器管，
 *   这一路只在 net.capture.peer.stop 成功、或对端自己死了之后才算收干净。
 *   界面上每一句都要把这句话带到：人关页面之前得知道自己留下的是什么。
 *
 * ★ 取回来的那份会顶进「当前那本账」，和上面那张表是同一张 —— 来看表的卡点就行，
 *   这一张不重复算任何东西，只把「哪一路、落在对端哪儿、取回来落在哪儿、丢了没丢」说清。
 *
 * ★ 「停了」不是一个码：人停的、到时长、到量、对端自己退了、跟它失去联系、
 *   打招呼不听硬断的、对端没报账的、取不回来的、校验对不上的 —— 每一种的下一步都不一样，
 *   后端各给一个码，这里逐档翻成人话（不许合并成一句「停了」）。
 */

const PEER_STATE = {
  'capture-peer-ready': [t('对端能抓，口也列出来了'), 'ok'],
  'capture-peer-no-collector': [t('那台机器上没有采集器'), 'bad'],
  'capture-peer-no-interface-list': [t('那台报不出口列表'), 'warn'],
  'capture-peer-running': [t('对端正在抓'), 'ok'],
  'capture-peer-stopping': [t('正在收口（那份还在往回走）'), 'warn'],
  'capture-peer-stopped': [t('停了，那份已取回本机'), ''],
  'capture-peer-stopped-forced': [t('硬断的：文件可能短一截'), 'bad'],
  'capture-peer-stopped-no-counts': [t('停了，但对端没报那本账'), 'warn'],
  'capture-peer-pull-failed': [t('停了，那份没取回来'), 'bad'],
  'capture-peer-verify-mismatch': [t('取回来了，但整包摘要对不上'), 'bad'],
  'capture-peer-no-session': [t('手上没有这一路'), ''],
  'capture-peer-unsupported-os': [t('那台系统没探明，命令没法写'), 'bad'],
  'capture-peer-start-failed': [t('那一路没起来，对端说不出理由'), 'bad'],
  'capture-peer-no-privilege': [t('那边这个账号抓不了（要 root / CAP_NET_RAW；Windows 要管理员）'), 'bad'],
  'capture-peer-no-interface': [t('那块口在那台上没有'), 'bad'],
  'capture-peer-bad-filter': [t('过滤器那句话对端不认'), 'bad'],
  'capture-peer-filter-unsupported': [t('pktmon 那一档不认 BPF 过滤器'), 'bad'],
  'capture-peer-died-at-start': [t('起了又死，说不清是几种里的哪一种'), 'bad'],
  'capture-peer-stuck': [t('起来就卡住：既不继续也不退出'), 'bad'],
  'capture-peer-connection': [t('那台的通道断了'), 'bad'],
  // ── Windows/pktmon 这一路独有的几档 ──
  'capture-peer-no-etl2pcap': [t('那台 pktmon 没有 etl2pcap，转不成能读的表'), 'warn'],
  'capture-peer-convert-failed': [t('抓到了 .etl，收口时没转成 pcapng（原件还在对端）'), 'bad'],
  'capture-peer-busy': [t('那台已有一路 pktmon 在录（全机器只能一路）'), 'warn'],
};

// 对端那一路「为什么停了」——★ 和上面本机的 CAP_WHY 不合并：
// 「对端自己退了」与「跟它失去联系」是本机那一路没有的两种，而本机那两种对端没有。
const PEER_WHY = {
  user: t('人停的'),
  duration: t('到了自己定的时长'),
  'max-bytes': t('★ 到了文件大小上限 —— 不是这条链路没流量了'),
  'peer-died': t('★ 对端那一路自己退了（去看对端那句原文，不是我们停的）'),
  'peer-lost': t('★ 跟对端失去联系（进程在不在都不知道，先查通道与那台机器）'),
};

function peerCaptureCard() {
  const card = $(t('<div class=\"card\">\n    <h2>在对端那台机器上开一路抓包 <span id=\"pc-top\"></span></h2>\n    <p class=\"hint\">SSH 连过去，在<strong>那台机器上</strong>起一路 tcpdump，包写在那台机器的盘上；\n      停的时候用 SFTP 把那份取回本机，读成和上面<strong>同一张表</strong>。\n      ★ 这一路不是本机的延伸：<strong>NetKit 退出、页面关掉，那台上的采集进程都还在跑、文件还在长</strong>，\n      只有点「停掉并取回」或那一路自己死了才算收干净。\n      ★ 一次只许开一路，且必须先探一次（要知道那台上有没有采集器、口叫什么名字 ——\n      本机的网卡名在那边多半不成立）。\n      ★ 默认取回来就把对端那两份删掉：那是原始包，含明文口令与 SNMP 团体名，\n      留在别人机器上而我们这边已经有一份，没有道理。要留就得明写留。</p>\n    <div class=\"row\">\n      <div style=\"flex:1 1 200px\"><label>哪台设备（SSH 登记过的那台）</label>\n        <select id=\"pc-dev\"></select></div>\n      <div style=\"flex:1 1 180px\"><label>那台上的口（探一次才列得出来）</label>\n        <select id=\"pc-iface\"><option value=\"\">先探一次</option></select></div>\n      <div style=\"flex:0 0 auto;min-width:0\"><label>&nbsp;</label>\n        <button class=\"btn\" id=\"pc-probe\">探一次：那边能不能抓</button></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <div style=\"flex:1 1 240px\"><label>只收哪些包（BPF，空=全收）</label>\n        <input id=\"pc-filter\" placeholder=\"例：tcp port 554 或 host 10.0.0.7\"></div>\n      <div style=\"flex:0 0 140px\"><label>一包留多少字节</label>\n        <input id=\"pc-snap\" placeholder=\"默认 1600（全帧）\"></div>\n      <div style=\"flex:0 0 140px\"><label>最长抓多少秒（空=不停）</label>\n        <input id=\"pc-seconds\" placeholder=\"默认一直抓到你点停\"></div>\n      <div style=\"flex:0 0 140px\"><label>对端文件上限 MB</label>\n        <input id=\"pc-max\" placeholder=\"默认 256\"></div>\n    </div>\n    <div class=\"row\" style=\"margin-top:6px\">\n      <div style=\"flex:0 0 auto;min-width:0\">\n        <label class=\"dim\" style=\"font-weight:400\"><input type=\"checkbox\" id=\"pc-keep\"> 取回之后不删对端那一份（会把路径原样报出来）</label>\n      </div>\n      <div style=\"flex:0 0 auto;min-width:0\">\n        <button class=\"btn danger\" id=\"pc-go\">在对端开这一路</button>\n        <button class=\"btn\" id=\"pc-refresh\">刷新状态</button>\n        <button class=\"btn danger\" id=\"pc-stop\" style=\"display:none\">停掉并取回</button>\n        <button class=\"btn\" id=\"pc-reveal\" style=\"display:none\">去看这一张表</button>\n      </div>\n    </div>\n    <div id=\"pc-err\" style=\"margin-top:12px\"></div>\n    <div id=\"pc-out\" style=\"margin-top:14px\"></div>\n  </div>'));

  const out = card.querySelector('#pc-out');
  const errBox = card.querySelector('#pc-err');
  const top = card.querySelector('#pc-top');
  const devSel = card.querySelector('#pc-dev');
  const ifSel = card.querySelector('#pc-iface');
  const btnGo = card.querySelector('#pc-go');
  const btnStop = card.querySelector('#pc-stop');
  const btnReveal = card.querySelector('#pc-reveal');

  let busy = false;

  // 设备列表：★ 带上系统，因为 Windows 那一路是 pktmon 下发筛选器那一套，
  // 现在还不接 —— 让人在点之前就知道这一台点了也是白点。
  (async () => {
    const r = await call('remote.device.list');
    if (!r.ok) {
      errBox.innerHTML = t('<div class=\"empty\">设备列表问不出来：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    const ds = r.values.devices || [];
    if (!ds.length) {
      errBox.innerHTML = t('<div class=\"empty\">一台设备都没登记：这一页得先在「远程设备与审计」那页把 SSH 那台加进来。</div>');
      return;
    }
    devSel.innerHTML = ds.map((d) => `<option value="${esc(d.id)}">${esc(d.name || d.id)}`
      + ` · ${esc(OS_LABEL[d.os] || t('系统未知'))}${d.os === 'windows' ? t('（这一档还没接）') : ''}</option>`).join('');
  })();

  const facts = (v, running) => {
    const rows = [];
    if (v.device) { rows.push([t('抓的是哪台'), `<code>${esc(v.device)}</code>`]); }
    if (v.interface) { rows.push([t('那块口'), `<code>${esc(v.interface)}</code>`]); }
    if (v.collector) { rows.push([t('对端用的采集器'), `<code>${esc(v.collector)}</code>`]); }
    if (v.peerFile) { rows.push([t('包落在对端哪儿'), `<code style="user-select:all">${esc(v.peerFile)}</code>`]); }
    if (v.localFile && running) { rows.push([t('取回来落本机'), `<code style="user-select:all">${esc(v.localFile)}</code>`]); }
    if (v.file) { rows.push([t('本机这一份'), `<code style="user-select:all">${esc(v.file)}</code>`]); }
    if (typeof v.peerBytes === 'number' && running) { rows.push([t('对端已经写了'), t('{0} 字节', [esc(v.peerBytes)])]); }
    if (typeof v.bytes === 'number' && v.file) { rows.push([t('取回来多大'), esc(fsSize(v.bytes))]); }
    if (typeof v.packets === 'number') { rows.push([t('读成表的包数'), t('<b>{0}</b> 包', [esc(v.packets)])]); }
    if (typeof v.captured === 'number') { rows.push([t('对端报收到'), t('{0} 包（它自己数的）', [esc(v.captured)])]); }
    if (typeof v.received === 'number') { rows.push([t('对端过滤器放进'), t('{0} 包', [esc(v.received)])]); }
    if (typeof v.dropped === 'number' && v.droppedKnown !== false) {
      rows.push([t('内核丢掉'), t('<span class=\"{0}\">{1} 包</span>', [v.dropped ? 'bad' : 'dim', esc(v.dropped)])]);
    } else if (v.droppedKnown === false) {
      rows.push([t('内核丢掉'), t('<span class=\"warn\">说不出（对端退出时没报那本账）</span>')]);
    }
    if (typeof v.snapLen === 'number') {
      rows.push([t('一包留'), t('{0} 字节{1}', [esc(v.snapLen), v.snapLen < 1600 ? t(' <span class=\"warn\">被剪过：正文与后面那半截字段不可信</span>') : ''])]);
    }
    if (v.filter) { rows.push([t('只收'), t('<code>{0}</code> <span class=\"dim\">表上没有的可能是被筛掉了</span>', [esc(v.filter)])]); }
    if (typeof v.maxMB === 'number' && running) { rows.push([t('对端上限'), t('{0} MB（到顶自己停，并会写清是到顶不是没流量）', [esc(v.maxMB)])]); }
    if (typeof v.seconds === 'number' && v.seconds > 0 && running) { rows.push([t('自动停'), t('到 {0} 秒自己停', [esc(v.seconds)])]); }
    if (v.stopWhy) { rows.push([t('为什么停了'), esc(PEER_WHY[v.stopWhy] || v.stopWhy)]); }
    if (v.startedAt) { rows.push([t('什么时候开的'), esc(capClock(v.startedAt))]); }
    if (v.lastCheck && running) { rows.push([t('最后一次问到'), esc(capClock(v.lastCheck))]); }
    if (v.redacted) { rows.push([t('对端那句原文洗掉'), t('{0} 处{1}', [esc(v.redacted), v.redactedHow ? t('（{0}）', [esc(v.redactedHow)]) : ''])]); }
    if (v.peerRemoved === false && v.peerLeft) {
      rows.push([t('对端那两份还留着'), t('<code style=\"user-select:all\">{0}</code> <span class=\"bad\">原始包在别人机器上</span>', [esc(v.peerLeft)])]);
    }
    if (v.pullError) { rows.push([t('取不回来的原因'), esc(v.pullError)]); }
    return capFacts(rows);
  };

  const paint = (code, v, note) => {
    const [title, cls] = PEER_STATE[code] || [code || t('没给判定'), ''];
    const say = uiNote(code, note);
    top.innerHTML = title ? `<span class="pill ${cls}">${esc(title)}</span>` : '';
    const running = code === 'capture-peer-running';
    const stopping = code === 'capture-peer-stopping';
    btnStop.style.display = (running || stopping) ? '' : 'none';
    btnStop.disabled = stopping;
    btnGo.disabled = running || stopping;
    btnReveal.style.display = (typeof v.packets === 'number' || stopping) ? '' : 'none';
    const sayNext = PEER_NEXT_SAY[code];
    const next = (sayNext || v.next)
      ? t('<p class=\"dim\" style=\"margin:10px 0 0\">下一步：{0}</p>', [sayNext || esc(v.next)]) : '';
    const said = v.peerSaid
      ? t('<p class=\"dim\" style=\"margin:10px 0 0\">对端那句原文（第一行，已脱敏）：<code>{0}</code></p>', [esc(v.peerSaid)]) : '';
    out.innerHTML = capShell(cls, say) + uiNoteTail(code, note) + facts(v, running || stopping) + said + next
      + t('<details style=\"margin-top:10px\"><summary class=\"dim\">原始结果</summary>\n        <pre class=\"dim\">{0}</pre></details>', [esc(JSON.stringify(v, null, 2))]);
  };

  const pollOn = (code) => code === 'capture-peer-running' || code === 'capture-peer-stopping';

  const refresh = async (quiet) => {
    if (busy) return;
    const r = await call('net.capture.peer.status');
    if (!r.ok) {
      if (!quiet) out.innerHTML = t('<div class=\"empty\">问不出状态：{0}</div>', [esc(r.message || r.error)]);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
    if (peerCapTimer) { clearInterval(peerCapTimer); peerCapTimer = null; }
    if (pollOn(r.verdict)) peerCapTimer = setInterval(() => refresh(true), 3000);
  };

  card.querySelector('#pc-probe').onclick = async () => {
    errBox.innerHTML = '';
    if (!devSel.value) {
      errBox.innerHTML = t('<div class=\"empty\">先点一台设备 —— 没有设备就不知道往哪儿连。</div>');
      return;
    }
    out.innerHTML = t('<div class=\"empty\">正在那台机器上问：有没有采集器、有哪些口…</div>');
    const r = await call('net.capture.peer.probe', { device: devSel.value });
    if (!r.ok) {
      errBox.innerHTML = t('<div class=\"empty\">探不了：{0}</div>', [esc(r.message || r.error)]);
      out.innerHTML = '';
      return;
    }
    const v = r.values || {};
    paint(r.verdict, v, r.note);
    const ifs = v.interfaces || [];
    if (ifs.length) {
      ifSel.innerHTML = ifs.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
    } else {
      // ★ 报不出列表不等于不能抓：口名得人去那台上确认，这里不许替它编一个
      ifSel.innerHTML = t('<option value=\"\">（对端没列出口 —— 要自己确认那台上的口名）</option>');
    }
  };

  const peerArgs = () => {
    const args = { device: devSel.value };
    if (ifSel.value) { args.interface = ifSel.value; }
    const num = (id, key) => {
      const x = card.querySelector(id).value.trim();
      if (x) { args[key] = Number(x); }
    };
    const f = card.querySelector('#pc-filter').value.trim();
    if (f) { args.filter = f; }
    num('#pc-snap', 'snapLen');
    num('#pc-seconds', 'seconds');
    num('#pc-max', 'maxMB');
    if (card.querySelector('#pc-keep').checked) { args.keepPeer = true; }
    return args;
  };

  btnGo.onclick = async () => {
    if (!devSel.value) {
      errBox.innerHTML = t('<div class=\"empty\">先点一台设备。</div>');
      return;
    }
    busy = true;
    if (peerCapTimer) { clearInterval(peerCapTimer); peerCapTimer = null; }
    errBox.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（★ 批准框上写的就是那台上要起的那个采集进程，取消就什么都不起）</div>');
    const r = await call('net.capture.peer.start', peerArgs());
    busy = false;
    if (!r.ok) {
      errBox.innerHTML = t('<div class=\"empty\">这一路没开起来：{0}</div>', [esc(r.message || r.error)]);
      out.innerHTML = '';
      refresh(true);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
    if (pollOn(r.verdict)) peerCapTimer = setInterval(() => refresh(true), 3000);
  };

  btnStop.onclick = async () => {
    if (peerCapTimer) { clearInterval(peerCapTimer); peerCapTimer = null; }
    busy = true;
    errBox.innerHTML = '';
    out.innerHTML = t('<div class=\"empty\">等你点批准…（取消就还在抓）</div>');
    const args = {};
    if (card.querySelector('#pc-keep').checked) { args.keepPeer = true; }
    const r = await call('net.capture.peer.stop', args);
    busy = false;
    if (!r.ok) {
      errBox.innerHTML = t('<div class=\"empty\">停不下来：{0}</div>', [esc(r.message || r.error)]);
      out.innerHTML = '';
      refresh(true);
      return;
    }
    paint(r.verdict, r.values || {}, r.note);
    // ★ 收口那一段可能很久（那份要整份过一遍 SSH）：这一段继续问，别让它停在「正在收口」
    if (pollOn(r.verdict)) peerCapTimer = setInterval(() => refresh(true), 3000);
  };

  card.querySelector('#pc-refresh').onclick = () => refresh(true);
  btnReveal.onclick = () => {
    const t = document.getElementById('cap-flows-go');
    if (t) { t.click(); t.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  };
  refresh(true);
  return card;
}

// ── 网长什么样（拓扑画布）──
//
// ★★ 这一页只画探测出来的东西，一根线都不许手画（docs/设计.md §拓扑画布）。
//   节点和连线全部由后端 net.topology.build 从 网卡 / ARP·NDP 邻居 / 路由表 / LLDP 合成，
//   界面这边只干三件事：把图摆开、让人拖得动看得清、点谁就问谁。
//   所以「合成不出来」必须有话讲：看不见中间那台交换机就说看不见，
//   而不是画一个谁都看着顺眼的方块 —— 那种方块会把人送去查一个本来没问题的设备。
//
// ★ 为什么拖动只摆位置、不许拖出一条新线：在这页上「连一条线」等于改路由表，
//   而改路由表要走 预演→确认→登记→执行→回滚 那一整套（internal/state 那本账），
//   后端目前还没有「加一条路由」这个工具 —— 这是量出来的缺口，不是省出来的：
//   见 docs/交接.md 拓扑那一节。宁可画布上少一个动作，不给你一个假动作。

const TOPO_CODE = {
  'topo-ok': [t('形状问出来了'), 'ok', ''],
  'topo-no-ifaces': [t('一块能用的网卡都没问到'), 'bad',
    t('先去「网卡与路由」看这台的状态：权限没给够、或者网卡全被禁了，这里就没有东西可摆。')],
  'topo-l2-blind': [t('二层是看不见的（只画了三层）'), 'warn',
    t('这台只知道「同网段有哪些地址在答话」，不知道中间那台交换机是谁。要看见那一层：\n        给那台上 SNMP 团体名、读它的 LLDP 邻居表（本页顶上那两个格子）。')],
  'topo-hub-suspect': [t('一个口上挂了一大串邻居'), 'warn',
    t('这多半是一台非网管交换机或 hub —— 所以图上<b>没有</b>给它画节点：它没有能问出身份的东西。\n        要坐实就对那台上 SNMP 读 MAC 表，看这些地址是不是都从一个口学来的。')],
  'topo-island': [t('有块网卡是孤岛'), 'warn',
    t('口起来了、地址也有，可既没人应答也没路过去。查三样：网线/光模块、对端口是不是关着、\n        这个段上是不是根本没有别的设备（VLAN 划错了最常见的就是这个样子）。')],
  'topo-no-gateway': [t('这台没有默认出口'), 'bad',
    t('段内的地址能到，出了这个段就没路了。去「网卡与路由」看默认路由是谁、\n        在哪个口上、那个口还有没有地址。')],
  'topo-dualstack-skew': [t('v4 和 v6 的形状不一样'), 'warn',
    t('两族各自成线是故意的（合成一条会骗人）：一族有路、另一族只有一张网卡，\n        应用就会先撞在没路的那一族上再回落。哪一族缺路，去「网卡与路由」补哪一族。')],
  'topo-segment-conflict': [t('同一个地址出现在了两处'), 'bad',
    t('要么两台机器抢同一个地址，要么这台改了地址而邻居表里还留着旧的在答话。\n        先对一下 MAC：邻居表里这个 IP 挂的 MAC 换了没有，再看是哪台在发免费 ARP。')],
};

const TOPO_KIND = {
  local: t('本机'), iface: t('网卡口'), segment: t('网段'),
  host: t('设备'), switch: t('交换机'), gateway: t('出口'),
};
const TOPO_STATE = {
  up: [t('在'), 'ok'], down: [t('不通'), 'bad'], unknown: [t('没探到'), 'warn'],
};
const TOPO_LAYER = { l2: t('二层'), l3: t('三层'), tunnel: t('隧道') };
const POS_KEY = 'netkit.topo.pos';

// 分层：从本机出发按最少跳数摆开。没挂上任何线的（探测到了但不知道凭什么连）
// 单独堆在最右边那一列 —— 它们必须看得见，但绝不允许被画成「好像连着」。
function topoLayers(nodes, edges) {
  const adj = new Map();
  for (const n of nodes) adj.set(n.id, []);
  for (const e of edges) {
    if (adj.has(e.from)) adj.get(e.from).push(e.to);
    if (adj.has(e.to)) adj.get(e.to).push(e.from);
  }
  const start = (nodes.find((n) => n.kind === 'local') || nodes[0] || {}).id;
  const dist = new Map();
  if (start) {
    dist.set(start, 0);
    for (const q = [start]; q.length;) {
      const cur = q.shift();
      for (const nx of adj.get(cur) || []) if (!dist.has(nx)) { dist.set(nx, dist.get(cur) + 1); q.push(nx); }
    }
  }
  const reach = Math.max(0, ...[...dist.values()]);
  for (const n of nodes) if (!dist.has(n.id)) dist.set(n.id, reach + 1);
  return dist;
}

function topoDefaultPos(nodes, edges) {
  const dist = topoLayers(nodes, edges);
  const cols = new Map();
  for (const n of nodes) {
    const d = dist.get(n.id) || 0;
    if (!cols.has(d)) cols.set(d, []);
    cols.get(d).push(n);
  }
  const pos = new Map();
  const maxRows = Math.max(...[...cols.values()].map((c) => c.length));
  for (const [d, list] of [...cols.entries()].sort((a, b) => a[0] - b[0])) {
    list.sort((a, b) => String(a.label).localeCompare(String(b.label)));
    const h = 600;
    const step = Math.min(92, (h - 60) / Math.max(1, list.length));
    const y0 = (h - step * (list.length - 1)) / 2;
    list.forEach((n, i) => pos.set(n.id, { x: 110 + d * 230, y: y0 + i * step }));
  }
  return pos;
}

function topoLoadPos(nodes) {
  let raw = null;
  try { raw = localStorage.getItem(POS_KEY); } catch (_) { return null; }
  if (!raw) return null;
  let saved = null;
  try { saved = JSON.parse(raw); } catch (_) { return null; }
  if (!saved || typeof saved !== 'object') return null;
  const def = topoDefaultPos(nodes, []);
  const pos = new Map();
  for (const n of nodes) {
    const p = saved[n.id];
    pos.set(n.id, p && Number.isFinite(p.x) && Number.isFinite(p.y) ? { x: p.x, y: p.y } : def.get(n.id));
  }
  // 只留这次图上的节点：节点 id 由探测内容派生，段一变多几年就会攒下一堆对不上号的旧坐标，
  // 而那些旧坐标永远没人再看 —— 存得越多越不像缓存，像漏。
  try { localStorage.setItem(POS_KEY, JSON.stringify(Object.fromEntries(pos))); } catch (_) {}
  return pos;
}

function topoSVG(nodes, edges, pos) {
  const by = new Map(nodes.map((n) => [n.id, n]));
  const at = (id) => pos.get(id) || { x: 0, y: 0 };
  const xs = nodes.map((n) => at(n.id).x), ys = nodes.map((n) => at(n.id).y);
  const box = [Math.min(...xs, 60) - 60, Math.min(...ys, 60) - 46,
    Math.max(...xs, 60) + 60, Math.max(...ys, 60) + 46];
  const vb = `${box[0]} ${box[1]} ${box[2] - box[0]} ${box[3] - box[1]}`;
  const line = (e) => {
    const a = at(e.from), b = at(e.to);
    if (!by.has(e.from) || !by.has(e.to)) return '';
    const stroke = e.state === 'down' ? 'var(--red-line)' : e.state === 'unknown' ? 'var(--muted-2)' : 'var(--line)';
    const dash = e.state === 'unknown' ? ' stroke-dasharray="5 4"' : '';
    return `<g class="tp-e" data-from="${esc(e.from)}" data-to="${esc(e.to)}">
      <line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${stroke}" stroke-width="1.6"${dash}></line>
      <text x="${(a.x + b.x) / 2}" y="${(a.y + b.y) / 2 - 6}" class="tp-el"
        >${esc(TOPO_LAYER[e.layer] || e.layer || '')}${e.stack ? ' · ' + esc(e.stack) : ''}</text></g>`;
  };
  const node = (n) => {
    const p = at(n.id);
    const grey = n.state === 'down' || n.state === 'unknown';
    const fill = n.kind === 'local' ? 'var(--gold-bg)' : grey ? 'var(--sunken)' : 'var(--panel-2)';
    const edge = n.kind === 'local' ? 'var(--gold)' : grey ? 'var(--line-soft)' : 'var(--line)';
    const sub = n.kind === 'segment' ? (n.addrs[0] || '') : (n.addrs[0] || n.macs[0] || n.why || '');
    return `<g class="tp-n${n.id === topoSel ? ' on' : ''}" data-id="${esc(n.id)}" transform="translate(${p.x},${p.y})"
        style="cursor:grab">
      <rect x="-88" y="-24" width="176" height="48" rx="7" fill="${fill}" stroke="${edge}"></rect>
      <text x="0" y="-6" class="tp-nm">${esc(n.label || '')}</text>
      <text x="0" y="11" class="tp-sub">${esc(TOPO_KIND[n.kind] || n.kind)}${sub ? ' · ' + esc(String(sub).slice(0, 24)) : ''}</text>
      ${n.state !== 'up' ? `<circle cx="78" cy="-16" r="4" fill="${n.state === 'down' ? 'var(--red)' : 'var(--muted-2)'}"></circle>` : ''}
    </g>`;
  };
  // 线画在节点底下：端点都算到盒子中心就够了，压住看不见的那一截比精确求交更不容易出错。
  return `<svg viewBox="${vb}" width="100%" height="600" role="img" aria-label="${esc(t('这台机器在网里的连接图'))}">
    ${edges.map(line).join('')}${nodes.map(node).join('')}</svg>`;
}

let topoSel = '';

function topoDetail(nodes, edges, quality) {
  const n = nodes.find((x) => x.id === topoSel);
  if (!n) return t('<div class="empty">点左边或图上的任何一个，这里展开它的接口、地址和每根线的依据。</div>');
  const mine = edges.filter((e) => e.from === n.id || e.to === n.id);
  const by = new Map(nodes.map((x) => [x.id, x]));
  const rows = mine.map((e) => {
    const other = by.get(e.from === n.id ? e.to : e.from);
    const q = quality.get(e.from === n.id ? e.to : e.from);
    return `<tr><td>${esc(other ? other.label : '—')}</td><td>${esc(TOPO_LAYER[e.layer] || e.layer)}</td>`
      + `<td>${esc((e.ports || []).join(' / ') || '—')}</td>`
      + `<td>${esc(e.state === 'up' ? t('在') : e.state === 'down' ? t('不通') : t('没探到'))}</td>`
      + `<td>${q ? esc(q) : t('<span class="dim">没测过</span>')}</td>`
      + `<td class="dim">${esc((e.evidence || []).join(' · '))}</td></tr>`;
  }).join('');
  const kv = (k, v) => `<tr><td class="dim">${esc(k)}</td><td>${esc(v)}</td></tr>`;
  return `<div class="tp-panel">
    <table>${kv(t('名字'), n.label || '—')}${kv(t('是什么'), TOPO_KIND[n.kind] || n.kind)}
      ${kv(t('状态'), (TOPO_STATE[n.state] || [n.state || '—'])[0])}
      ${n.mtu ? kv(t('MTU'), n.mtu) : ''}
      ${n.stack ? kv(t('协议族'), n.stack) : ''}
      ${(n.addrs || []).map((a) => kv(t('地址'), a)).join('')}
      ${(n.macs || []).map((m) => kv(t('硬件地址'), m)).join('')}
      ${(n.ifaces || []).map((i) => kv(t('经过本机哪个口'), i)).join('')}
      ${kv(t('凭什么'), (n.source || []).join(' + ') || '—')}</table>
    ${n.why ? `<p class="hint" style="margin-top:8px">${esc(n.why)}</p>` : ''}
    <div class="row" style="margin-top:10px">
      <button class="btn" id="tp-ask">${esc(t('问这台一句'))}</button>
      <button class="btn" id="tp-who">${esc(t('这台是谁（识别设备）'))}</button>
    </div>
    <div id="tp-ask-out" style="margin-top:10px"></div>
    ${mine.length ? `<table style="margin-top:12px">
      <tr><th>${esc(t('连着谁'))}</th><th>${esc(t('哪一层'))}</th><th>${esc(t('口'))}</th><th>${esc(t('状态'))}</th><th>${esc(t('刚测的那几秒'))}</th><th>${esc(t('这根线凭什么'))}</th></tr>
      ${rows}</table>`
      : `<p class="hint" style="margin-top:12px">${esc(t('它没挂在任何一根线上：探测到了这台，但没有任何一份结果说明它和谁是直接相连的 —— 所以图上也不画它连着。') + (n.kind === 'host' ? t('常见原因是邻居表里有它，可本机到它的路上没有任何一段被别的工具问到（LLDP 没读、路由不经过它）。') : ''))}</p>`}
  </div>`;
}

function topoCard() {
  const card = $(t('<div class="card">\n    <h2>这台在网里的形状 <span id="tp-top"></span></h2>\n    <p class="hint">把<b>已经探测到的</b>网卡、邻居表、路由表和 LLDP 邻居合成一张图：这台是谁、挂在哪个口上、\n      中间有没有问得出身份的交换机、默认出口走哪条路。\n      ★ 图上每一根线都写着它是凭什么探测画出来的；看不见的地方（比如没人能告诉你中间是台什么设备）\n      会明说看不见，不会画一个方块凑数。拖动方块只是摆位置，不改任何配置。</p>\n    <div class="row">\n      <div style="flex:0 0 240px"><label>顺带读一台设备的 LLDP 邻居（可选，只读）</label>\n        <input id="tp-t" placeholder="留空则二层不画，只画三层"></div>\n      <div style="flex:0 0 190px"><label>SNMP 团体名</label>\n        <input id="tp-c" placeholder="读不到就按二层看不见处理"></div>\n      <div style="flex:0 0 210px"><label>&nbsp;</label>\n        <button class="btn primary" id="tp-b">合成拓扑</button></div>\n    </div>\n    <div id="tp-sum" style="margin-top:12px"></div>\n    <div id="tp-body" style="margin-top:12px"></div>\n  </div>'));
  const top = card.querySelector('#tp-top');
  const sum = card.querySelector('#tp-sum');
  const body = card.querySelector('#tp-body');
  let nodes = [], edges = [], pos = new Map(), quality = new Map(), svg = null;

  const draw = () => {
    body.querySelector('#tp-svg').innerHTML = topoSVG(nodes, edges, pos);
    svg = body.querySelector('#tp-svg svg');
    body.querySelector('#tp-detail').innerHTML = topoDetail(nodes, edges, quality);
    bindDetail();
    bindDrag();
  };

  const bindDrag = () => {
    if (!svg) return;
    const user = (ev) => {
      const m = svg.getScreenCTM();
      if (!m) return { x: 0, y: 0 };
      const p = new DOMPoint(ev.clientX, ev.clientY).matrixTransform(m.inverse());
      return { x: p.x, y: p.y };
    };
    svg.querySelectorAll('.tp-n').forEach((g) => {
      g.addEventListener('pointerdown', (ev) => {
        ev.preventDefault();
        const id = g.getAttribute('data-id');
        const start = user(ev), base = { ...pos.get(id) };
        let moved = false;
        const lines = [...svg.querySelectorAll('.tp-e')].filter((l) =>
          l.getAttribute('data-from') === id || l.getAttribute('data-to') === id);
        const move = (e2) => {
          const p = user(e2);
          const dx = p.x - start.x, dy = p.y - start.y;
          if (!moved && Math.abs(dx) + Math.abs(dy) < 2) return;
          moved = true;
          const at = { x: base.x + dx, y: base.y + dy };
          pos.set(id, at);
          g.setAttribute('transform', `translate(${at.x},${at.y})`);
          // 边跟着走：一次 pointermove 只碰这几条线，不重画整张图 ——
          // 重画会把正在拖的那个 <g> 换掉，手感当场断掉（也就会掉锁）。
          for (const l of lines) {
            const other = l.getAttribute('data-from') === id ? l.getAttribute('data-to') : l.getAttribute('data-from');
            const o = pos.get(other) || { x: 0, y: 0 };
            const ln = l.querySelector('line'), tx = l.querySelector('text');
            const from = l.getAttribute('data-from') === id;
            ln.setAttribute('x1', from ? at.x : o.x); ln.setAttribute('y1', from ? at.y : o.y);
            ln.setAttribute('x2', from ? o.x : at.x); ln.setAttribute('y2', from ? o.y : at.y);
            tx.setAttribute('x', (at.x + o.x) / 2); tx.setAttribute('y', (at.y + o.y) / 2 - 6);
          }
        };
        const up = () => {
          window.removeEventListener('pointermove', move);
          window.removeEventListener('pointerup', up);
          if (moved) {
            try { localStorage.setItem(POS_KEY, JSON.stringify(Object.fromEntries(pos))); } catch (_) {}
          } else { topoSel = id; draw(); paintList(); }
        };
        window.addEventListener('pointermove', move);
        window.addEventListener('pointerup', up);
      });
    });
  };

  const paintList = () => {
    const host = body.querySelector('#tp-list');
    if (!host) return;
    const q = (host.querySelector('#tp-q').value || '').trim().toLowerCase();
    const kind = host.querySelector('.tp-f.on') ? host.querySelector('.tp-f.on').getAttribute('data-k') : '';
    const shown = nodes.filter((n) => (!kind || n.kind === kind)
      && (!q || [n.label, ...(n.addrs || []), ...(n.macs || []), ...(n.ifaces || [])].join(' ').toLowerCase().includes(q)));
    host.querySelector('#tp-rows').innerHTML = shown.length ? shown.map((n) => {
      const st = TOPO_STATE[n.state] || [n.state || '—', 'warn'];
      return `<button class="btn sub${n.id === topoSel ? ' on' : ''}" data-id="${esc(n.id)}" style="display:block;width:100%;text-align:left">
        ${esc(n.label || '')} <span class="pill ${st[1]}" style="padding:0 6px">${esc(st[0])}</span></button>`;
    }).join('') : t('<div class="empty">按现在这个筛选，一台都没剩下。</div>');
    host.querySelectorAll('button[data-id]').forEach((b) => {
      b.onclick = () => { topoSel = b.getAttribute('data-id'); draw(); paintList(); };
    });
  };

  const bindDetail = () => {
    const a = body.querySelector('#tp-ask'), w = body.querySelector('#tp-who');
    const n = nodes.find((x) => x.id === topoSel);
    if (!n) return;
    const target = (n.addrs || [])[0] || '';
    const out = body.querySelector('#tp-ask-out');
    if (a) a.onclick = async () => {
      if (!target) { out.innerHTML = t('<div class="empty">这台没问到地址，只能靠口和硬件地址认它，问不了。</div>'); return; }
      out.innerHTML = `<div class="empty">${esc(t('正在问 {0}…', [target]))}</div>`;
      const r = await call('net.ping', { addr: target, count: 4 });
      if (!r.ok) { out.innerHTML = t('<div class="empty">问不出去：{0}</div>', [esc(r.message || r.error)]); return; }
      const v = r.values || {};
      const [title, cls, advice] = PING_CODE[r.verdict] || [r.verdict, '', ''];
      // 边上那一格写的是**刚测的那几秒**：ping 是一次一次的，不写时间人就会拿它当长期状态。
      quality.set(n.id, `${title} ${v.lossPercent === undefined ? '—' : Math.round(v.lossPercent) + '%'} @${new Date().toLocaleTimeString()}`);
      out.innerHTML = `<table>
          ${tCell(t('目标'), `<code>${esc(v.target || target)}</code> <span class="dim">${esc(v.family || '')}</span>`)}
          ${tCell(t('发 / 收到'), `${v.sent ?? '—'} / ${v.received ?? '—'}`)}
          ${tCell(t('丢包'), v.lossPercent === undefined ? '—' : `${Math.round(v.lossPercent)}%`)}
          ${tCell(t('往返（最快/平均/最慢）'), ms(v.rttMinMs) + ' / ' + ms(v.rttAvgMs) + ' / ' + ms(v.rttMaxMs))}
        </table>${advice ? adviceBox(cls, esc(advice)) : ''}`;
      draw();
    };
    if (w) w.onclick = async () => {
      if (!target) { out.innerHTML = t('<div class="empty">这台没问到地址，识别不了。</div>'); return; }
      out.innerHTML = `<div class="empty">${esc(t('正在问 {0} 是什么设备…', [target]))}</div>`;
      const r = await call('net.device.identify', { addrs: [target] });
      if (!r.ok) { out.innerHTML = t('<div class="empty">问不了：{0}</div>', [esc(r.message || r.error)]); return; }
      const d = ((r.values || {}).devices || [])[0];
      if (!d) { out.innerHTML = t('<div class="empty">一个应答都没收到 —— 不等于这台不在，它也可能只是不答这几种话。</div>'); return; }
      const kv = (k, val) => `<tr><td class="dim">${esc(k)}</td><td>${esc(val)}</td></tr>`;
      out.innerHTML = `<table>
          ${d.name ? kv(t('它报的名字'), d.name) : ''}
          ${d.kind ? kv(t('它说的类型'), d.kind) : ''}
          ${d.url ? kv(t('服务地址'), d.url) : ''}
          ${d.mac ? kv(t('硬件地址'), d.mac) : ''}
          ${(d.protocols || []).length ? kv(t('哪几种话应了'), d.protocols.join(' + ')) : ''}
        </table>`
        + (d.identified ? '' : `<p class="hint">△ ${esc(t('这台应了，但一句身份都没说 —— 要查它是谁得从别的口子进（端口、SNMP、抓包里的广播），这里不猜。'))}</p>`);
    };
  };


  const run = async () => {
    top.innerHTML = '';
    sum.innerHTML = t('<div class="empty">正在把这几份探测合成一张图…</div>');
    body.innerHTML = '';
    const args = {};
    const t0 = card.querySelector('#tp-t').value.trim();
    const c0 = card.querySelector('#tp-c').value.trim();
    if (t0) { args.target = t0; if (c0) args.community = c0; }
    const r = await call('net.topology.build', args);
    if (!r.ok) { sum.innerHTML = t('<div class="empty">合成不了：{0}</div>', [esc(r.message || r.error)]); return; }
    const v = r.values || {};
    nodes = v.nodes || []; edges = v.edges || [];
    if (!nodes.length) {
      const [title, cls, advice] = TOPO_CODE[r.verdict] || [r.verdict, 'warn', ''];
      top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
      sum.innerHTML = `<p class="hint">${esc(advice || t('后端一个节点都没合成出来：先看下面这几条「看不见」，再去别的页把探测做出来。'))}</p>`
        + (v.blind || []).map((b) => `<p class="hint">△ ${esc(b)}</p>`).join('');
      body.innerHTML = '';
      return;
    }
    topoSel = (nodes.find((n) => n.kind === 'local') || nodes[0]).id;
    pos = topoLoadPos(nodes) || topoDefaultPos(nodes, edges);
    quality = new Map();
    const [title, cls, advice] = TOPO_CODE[r.verdict] || [r.verdict, '', ''];
    top.innerHTML = `<span class="pill ${cls}">${esc(title)}</span>`;
    const kinds = [...new Set(nodes.map((n) => n.kind))];
    sum.innerHTML = `<p class="hint">${esc(t('图上 {0} 个节点、{1} 根线。每一根线都点得开，里面写着它凭什么存在。', [nodes.length, edges.length]))}</p>`
      + (advice ? `<p class="hint">★ ${esc(advice)}</p>` : '')
      + (v.blind || []).map((b) => `<p class="hint">△ ${esc(b)}</p>`).join('');
    body.innerHTML = `<div style="display:grid;grid-template-columns:210px 1fr 320px;gap:12px;align-items:start">
      <div id="tp-list">
        <input id="tp-q" placeholder="${esc(t('搜名字 / 地址 / 口'))}" style="width:100%">
        <div style="margin:8px 0 6px;display:flex;flex-wrap:wrap;gap:4px">
          <button class="btn sub on tp-f" data-k="">${esc(t('全部'))}</button>
          ${kinds.map((k) => `<button class="btn sub tp-f" data-k="${esc(k)}">${esc(TOPO_KIND[k] || k)}</button>`).join('')}
        </div>
        <div id="tp-rows" style="max-height:520px;overflow:auto"></div>
      </div>
      <div id="tp-svg" class="tp-canvas"></div>
      <div id="tp-detail"></div>
    </div>`;
    body.querySelectorAll('.tp-f').forEach((b) => {
      b.onclick = () => {
        body.querySelectorAll('.tp-f').forEach((x) => x.classList.remove('on'));
        b.classList.add('on');
        paintList();
      };
    });
    body.querySelector('#tp-q').oninput = paintList;
    draw();
    paintList();
  };

  card.querySelector('#tp-b').onclick = run;
  return card;
}

async function renderTopo(root) {
  root.appendChild(topoCard());
}

// ── 起步 ──

(async () => {
  API = await window.netkit.apiBase();
  const c = document.getElementById('conn');
  // 这一格写的是 t() 的结果，换语言靠整页重跑过来（i18n.js 的 setLang），
  // 所以这里只要起步时填一次 —— 不需要再留一个「换语言时重画顶栏」的钩子。
  const setConn = async () => {
    try {
      const r = await fetch(`${API}/ots`).then((x) => x.json());
      c.textContent = t('已连接 · {0} · 规范 {1}', [r.conformance, r.specVersion]);
    } catch { c.textContent = t('后端没连上'); }
  };
  await setConn();

  // 顶栏那颗搜索钮：文字和键名在这儿现填（要过词典，也要按键盘分苹果/其余两档）。
  const find = document.getElementById('find');
  if (find) {
    const lbl = document.createElement('span');
    lbl.className = 'lbl';
    lbl.textContent = t('要做什么？');
    const kbd = document.createElement('kbd');
    kbd.textContent = FIND_KEY;
    find.append(lbl, kbd);
    find.onclick = () => openFind();
  }
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openFind(); }
  });

  // ★ 能力表先到手，第一屏才敢报数、搜索才搜得到工具名 —— 这一步失败也只是清单空着，
  //   界面照样起（总览那一块写明是「后端没报出能力表」，不拿空表冒充「这台没功能」）。
  await loadTools();
  renderNav();
  await show();
  startRunWatch();
})();
