// 多语种层。范式是从昱弘播控（stage）搬过来的那一条：
//
//   ★ 中文原文就是 key，没译到自动回落中文，界面永远不露 key。
//
// 为什么不另造一套 `dhcp.leases.title` 式的编号：编号词典会把「中文写错了」
// 变成一件没人发现的问题（key 与文案对不上时界面还是绿的），而现场最怕的就是
// 界面上那句「所以怎么办」其实是上一版的说法。原文当 key，改文案就等于换 key，
// 没跟着译的那一条会立刻露回中文，看得见。
//
// 露回中文是**设计行为**，不是 bug：四本词典不可能同一天补齐，
// 但一条被误译成相反意思的话比一条没译的话害人大得多。
//
// 分工的另一半在后端：Go 只给判定码，不给拼好的句子（netif/verdict.go），
// 句子由这一层按语言出。所以 t() 的 key 里出现 `{n}` 这类槽位时，
// 语序必须由词典自己决定 —— 不许在代码里用 + 拼句子，拼死了就没法翻译。

const I18N = {
  lang: 'zh',
  dicts: {},
  loaded: {},
};

// LANGS 里第一个是兜底：它就是 key 本身，不需要词典文件。
const LANGS = [
  { id: 'zh', name: '简体中文' }, // i18n:endonym
  // ★ 语言名一律用**母语原文**（English／日本語／한국어／Русский）：选语言的人靠自己的字认，
  //   译成「韩语」这种反而让本地人找不着哪一项是自己。所以这几条不走 t()，
  //   行尾的 i18n:endonym 是给 scripts/i18n-lib.cjs 的放行标记（守卫只认这一种例外）。
  { id: 'en', name: 'English' }, // i18n:endonym
  { id: 'ja', name: '日本語' }, // i18n:endonym
  { id: 'ko', name: '한국어' }, // i18n:endonym
  { id: 'ru', name: 'Русский' }, // i18n:endonym
];

const LANG_KEY = 'netkit.lang';

function currentLang() {
  let saved = null;
  try { saved = localStorage.getItem(LANG_KEY); } catch (_) { /* 隐私模式下没存储，认中文 */ }
  return LANGS.some((l) => l.id === saved) ? saved : 'zh';
}

// 槽位写法：t('已发出 {0} 个地址', [n])。
// ★ 只有这一种。不许写 `t('已发出 ' + n + ' 个')` —— 那样 key 里带上了具体数字，
//   词典永远对不上，而且语序被锁死在中文那一版。
function fill(s, args) {
  if (!args || !args.length) return s;
  return s.replace(/\{(\d+)\}/g, (m, i) => (i < args.length ? String(args[i]) : m));
}

/** t('网卡与路由') / t('池子共 {0} 个地址', [size]) —— 没译到的原样回中文。 */
function t(zhKey, args) {
  if (typeof zhKey !== 'string') return zhKey;
  const dict = I18N.dicts[I18N.lang];
  const hit = dict && dict[zhKey];
  return fill(hit || zhKey, args);
}

// 词典按语言懒加载：默认中文时不该把四本词典都解析一遍，
// 而且没选过的语言根本不该出现在启动路径上。
function loadDict(lang) {
  if (lang === 'zh' || I18N.loaded[lang]) return Promise.resolve();
  return new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = 'locales/' + lang + '.js';
    s.onload = () => { I18N.loaded[lang] = true; resolve(); };
    // 词典文件缺失（比如只发了两本）不许把界面卡成空白：留在中文。
    s.onerror = () => { I18N.loaded[lang] = true; resolve(); };
    document.head.appendChild(s);
  });
}

async function setLang(lang) {
  if (!LANGS.some((l) => l.id === lang)) return;
  if (lang === I18N.lang) return;
  await loadDict(lang);
  I18N.lang = lang;
  try { localStorage.setItem(LANG_KEY, lang); } catch (_) { /* 存不上也照用 */ }
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : lang;
  // ★★ 换语言只能整页重跑，不能「就地重画」——这一条是量出来的，不是怕麻烦：
  //   判定码表（RTMP_CODE / HLS_CODE / …三十多张）里写的是 t('中文') 的**返回值**，
  //   它们在 app.js 被解析的那一次就烤死了。就地 show() 只是把同一批烤好的句子再印一遍：
  //   词典明明换成英文了，那些「下一步该干什么」还是中文 —— 而那一格是全界面最该看懂的话。
  //   （本来想让每张表延迟求值，但那要动三十多张表；而重画本来就会把已经问出来的结果
  //    和填进去的表单一起重建，省不下什么，所以选了这一条最短的、真的能换过来的路。）
  //   落在哪一页由 app.js 存的那一份决定，重起来还在原来那一页。
  location.reload();
}

// index.html 里那几处写死的界面文字（不含品牌名，品牌不许译）也走同一本词典。
function applyStatic() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    if (!el.dataset.zh) el.dataset.zh = el.textContent;
    el.textContent = t(el.dataset.zh);
  });
}

// 顶栏那颗语言钮：不常用的功能不许占默认版面 —— 只印一个缩写，
// 展开才是四本全名，且当前语言在列表里排第一个。
function mountLangSwitch() {
  const host = document.querySelector('#lang');
  if (!host) return;
  const render = () => {
    host.innerHTML = '';
    const list = LANGS.slice().sort((a, b) => (a.id === I18N.lang ? -1 : b.id === I18N.lang ? 1 : 0));
    const sel = document.createElement('select');
    sel.className = 'lang';
    sel.title = t('界面语言');
    list.forEach((l) => {
      const o = document.createElement('option');
      o.value = l.id;
      o.textContent = l.name;
      if (l.id === I18N.lang) o.selected = true;
      sel.appendChild(o);
    });
    sel.onchange = () => setLang(sel.value);
    host.appendChild(sel);
  };
  render();
}

// ★ 侦听器必须在任何 await 之前挂上：语言不是中文时下面要等一个词典文件，
//   事件早就发完了，晚挂一次就等于第一屏永远是中文。
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => { mountLangSwitch(); applyStatic(); });
} else {
  mountLangSwitch();
  applyStatic();
}

// 启动：先定语言、词典就位，**再**把 app.js 拉进来解析。
//
// ★★ app.js 为什么不在 index.html 里用 <script> 直接写死：它顶部那三十多张判定码表
//   （TOPO_CODE / CERT_CODE / TROUBLE…）写的是 t('中文') 的**返回值**，
//   词典是异步来的那一份，两个谁先到就是谁 —— 原来的顺序里 app.js 一定先到，
//   于是选英文的人冷启动看到的整页「下一步该干什么」全是中文：
//   词典明明对得上，烤进常量的那一份却是查词典之前的那一版。
//   （量出来的证据：改之前冷启动 en，路由表那一格印的是「Routing table 同族有多条默认路由」
//    —— 前一半查到了，后一半没查到，因为后一半在常量里。）
//   这里等一步，而不是像换语言那样整页 reload：reload 是把同一个坑再踩一遍
//   （重启之后词典还是异步的，还得加一个「只重载一次」的标记），而顺序本身才是那个坑。
(async function i18nBoot() {
  I18N.lang = currentLang();
  document.documentElement.lang = I18N.lang === 'zh' ? 'zh-CN' : I18N.lang;
  if (I18N.lang !== 'zh') await loadDict(I18N.lang);
  // page-index.js 必须在 app.js 之前 —— 它俩都是顶层常量，app.js 的 PIDX 直接读它。
  // ★ 那份索引不是手写的：scripts/page-index.cjs 从各 render 函数的源码量出来生成，
  //   --check 钉住它不跟源码漂（搜功能、右侧上下文栏、总览的卡片清单都靠它）。
  await new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = 'page-index.js';
    s.onload = resolve;
    s.onerror = resolve;
    document.head.appendChild(s);
  });
  await new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = 'app.js';
    s.onload = resolve;
    // app.js 自己起不来也不许把界面吊死在这儿：让它照常报错，界面至少还有顶栏。
    s.onerror = resolve;
    document.head.appendChild(s);
  });
})();
