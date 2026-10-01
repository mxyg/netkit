// 多语种的验收门。跑法：
//
//   node scripts/i18n-audit.cjs                    只数、只报
//   node scripts/i18n-audit.cjs --write-baseline   把当前的动态键清单钉成基线
//   node scripts/i18n-audit.cjs --fail-under en=100,ja=100
//
// ★ 为什么要有这个文件：`t()` 的覆盖率是「界面到底双语了没有」唯一的量化口径，
//   而这种计数最容易骗人的地方在于**分母**。提取器只认 `t('字面量')`，
//   碰到 t(变量) / t(a || b) 这类动态键它一辈子看不见 ——
//   于是「todo total: 0」会被读成「全译完了」，而付费窗的按钮当时正把中文送进英文界面。
//   所以这里把三件事分开数，并且**永远把看不见的数量印在结论旁边**：
//     · 字面量键：进分母，覆盖率按它算
//     · 动态键：不进分母，但必须一条不漏地列出来；新增一条 → 退出码 1
//   动态键不可能降到 0（有些文字本来就是数据里带来的），但可以降到「每一条都有人签过字」。
//
// 七条判据，每条都必须能红：
//   1) 槽位：译文里的 {0} {1} 集合必须和中文 key 完全一致 —— 少一个就是界面打出裸 {0}
//   2) 标签：译文里的 HTML 标签多重集必须一致 —— 译丢一个 <b> 就是把强调弄没了
//   3) 死条目：词典里有、源码里已经没人用的 key —— 中文原文改过而词典没跟着改，
//      表现是「这句悄悄退回中文」，只有这一条判据抓得住
//   4) 覆盖率：按语言分别数，不许用「总体」糊过去（英日韩俄可能一本满、三本空）
//   5) 加载顺序：app.js 必须等词典就位再解析（判定码表烤的是 t() 的返回值）
//   6) 分母之外的中文：没走 t() 的字面量 —— 覆盖率永远数不到它，所以单独红一次
//   7) 排版标点：全角标点按语言放宽（ja 正字、en/ko/ru 一律红）——
//      四本词典 100% 的那天，ko 界面上还挂着 너비（픽셀），汉字尺量不到这种抄法

const fs = require('fs');
const path = require('path');
const ts = require('typescript');

const ROOT = path.resolve(__dirname, '..');
const SRC = ['src/app.js', 'src/i18n.js'];
const LOCALE_DIR = path.join(ROOT, 'src', 'locales');
const BASELINE = path.join(ROOT, 'scripts', '.i18n-dynamic-keys.json');

// 槽位、HTML 骨架、「还留着中文」与「字面量键怎么抠」这四把尺子和 merge / chunks /
// check-part 共用一个实现（i18n-lib.cjs）——两边各写一份的最坏结局是
// 「merge 放过去、audit 事后报红」，红在已经进仓的词典里。
const { LANGS, entryIssues: libEntry, untranslatedBits, identityIsFine, literalKeys, unmarkedHTMLText } =
  require('./i18n-lib.cjs');

function read(p) { return fs.readFileSync(p, 'utf8'); }

// ---- 源码侧：把所有 t(...) 调用分成「字面量键」和「动态键」两堆 ----

// 分母只有一份口径（i18n-lib.cjs 的 literalKeys），三件事同时办成：
//   · index.html 里那几处 [data-i18n] 的写死文字 —— applyStatic() 运行时走
//     t(el.dataset.zh)，**从 JS 那边永远数不到**。不并进分母的话，覆盖率号称 100%
//     而顶栏那句「连接中…」在英文界面上原样留着中文 —— 正是这一整套活儿最不该犯的错。
//   · 切箱子的（chunks）与合成词典的（merge）用同一个函数，「键没进箱子」这条路被封。
//   · 漏标 data-i18n 的中文文字由 unmarkedHTMLText 直接报红，不靠人自觉。
function sourceKeys() {
  const dynamic = []; // "文件:行  原文"
  for (const rel of SRC) {
    const file = path.join(ROOT, rel);
    if (!fs.existsSync(file)) continue;
    const src = read(file);
    const sf = ts.createSourceFile(file, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
    const lineOf = (pos) => sf.getLineAndCharacterOfPosition(pos).line + 1;
    const walk = (n) => {
      if (ts.isCallExpression(n) && /(^|\.)t$/.test(n.expression.getText())) {
        const a = n.arguments[0];
        if (!a) {
          dynamic.push(`${rel}:${lineOf(n.getStart())}  t() 没带参数`);
        } else if (!(ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a))) {
          dynamic.push(`${rel}:${lineOf(a.getStart())}  t(${a.getText(sf).slice(0, 80).replace(/\s+/g, ' ')})`);
        }
        // 第二个参数必须是数组字面量，否则 fill() 拿不到槽位
        const b = n.arguments[1];
        if (b && !ts.isArrayLiteralExpression(b)) {
          dynamic.push(`${rel}:${lineOf(b.getStart())}  槽位数不是数组：t(…, ${b.getText(sf).slice(0, 60)})`);
        }
      }
      ts.forEachChild(n, walk);
    };
    ts.forEachChild(sf, walk);
  }
  const fromJs = new Set(literalKeys(ROOT, SRC, ''));
  const want = literalKeys(ROOT, SRC, 'src/index.html');
  const fromHtml = want.filter((k) => !fromJs.has(k)).length;
  if (fromHtml) console.log(`  · index.html [data-i18n] 文字 ${fromHtml} 处已并入分母`);
  return { want, dynamic, unmarked: unmarkedHTMLText(ROOT, 'src/index.html') };
}

// ---- 词典侧：把 locales/<lang>.js 当脚本跑一遍，取出它写进 I18N.dicts 的那个对象 ----

function loadDict(lang) {
  const file = path.join(LOCALE_DIR, lang + '.js');
  if (!fs.existsSync(file)) return null;
  const store = {};
  const I18N = { dicts: store };
  new Function('I18N', 'document', read(file))(I18N, {
    documentElement: {}, head: { appendChild() {} }, addEventListener() {}, readyState: 'loading',
    querySelector: () => null, querySelectorAll: () => [], createElement: () => ({}),
  });
  return store[lang] || null;
}

// lang 必给：同一份内容对 en 是漏译、对 ja 是正字（日文本来就写汉字），
// 拿一把尺量四种语言，报出来的红没有一条可信。
function entryIssues(lang, dict) {
  const out = [];
  for (const k of Object.keys(dict)) {
    const v = dict[k];
    for (const m of [...libEntry(k, v), ...untranslatedBits(lang, k, v)]) {
      out.push(`${m}\n   key: ${JSON.stringify(k).slice(0, 90)}\n   值:  ${JSON.stringify(v).slice(0, 90)}`);
    }
  }
  return out;
}

// ★★ 反证：这几道判据如果永远不红，就等于没写。所以每条都故意喂一份坏词典，
//    要求它必须报；同时喂一份**同形状的合法词典**，要求它不许报 ——
//    少了后半截，「一直报红」也会被当成「一直在把关」。
function selftest() {
  let n = 0;
  const expect = (name, got, wantCount) => {
    if (got === wantCount) console.log(`✓ ${name}`);
    else { n++; console.log(`✗ ${name}：判据读数 ${got}，应为 ${wantCount}`); }
  };
  expect('干净词典不报红', entryIssues('en', {
    '已发出 {0} 个地址': 'Issued {0} addresses',
    '池子<b>已被占用</b>': 'Pool <b>in use</b>',
  }).length, 0);
  expect('吃掉一个槽位会红', entryIssues('en', { '共 {0} 个': 'total' }).length, 1);
  expect('槽位编号写错会红', entryIssues('en', { '共 {0} 个': 'total {1}' }).length, 1);
  expect('译丢一个 <b> 会红', entryIssues('en', { '注意<b>危险</b>': 'Caution danger' }).length, 1);
  expect('凭空多出标签会红', entryIssues('en', { 注意: 'Caution <i>x</i>' }).length, 1);
  expect('值不是字符串会红', entryIssues('en', { 键: 42 }).length, 1);
  // 只改 class 名、文字全对 —— 这是最容易放过的一类「顺手把样式改了」
  expect('改标签属性会红', entryIssues('en', { 'a<span class="hint">b</span>': 'a<span class="err">b</span>' }).length, 1);
  expect('合法译文不红', entryIssues('en', { 'a<span class="hint">b</span>': 'a <span class="hint">b</span>' }).length, 0);
  // 显示性属性（placeholder / title / aria-label / alt）本来就该跟着语言走：
  // 把它们钉成不许变，等于要求德语界面上印着中文的输入框提示 —— 判据本身就写错了。
  expect('译 placeholder 不算毛病', entryIssues('en', {
    '<input id="spwho" placeholder="GE1/0/5 或备注里的字">': '<input id="spwho" placeholder="GE1/0/5 or text from the note">',
  }).length, 0);
  // 反向对照：id 一个字符都不能动 —— 它是脚本的锚点，改了界面不报错，只是从此点不动。
  expect('改 id 会红', entryIssues('en', {
    '<input id="spwho" placeholder="中文">': '<input id="spwho2" placeholder="English">',
  }).length, 1);
  expect('改 class 会红', entryIssues('en', {
    '<p class="hint">中文</p>': '<p class="err">English</p>',
  }).length, 1);
  // 标签换了名字（<b> 变 <strong>）也是改结构：视觉近似但样式表与读屏语义都不同
  expect('换标签名会红', entryIssues('en', { '<b>粗</b>': '<strong>bold</strong>' }).length, 1);
  // 「还留着中文」这一条必须分语言，而且要两头都钉住：
  // 太严会把日文正字报成红（人从此注掉判据），太松会把整段抄的放过去（假绿）。
  expect('en 里留中文会红', entryIssues('en', { 已连接: '接続済み' }).length, 1);
  expect('ru 里留中文会红', entryIssues('ru', { '端口范围': '端口范围' }).length, 1);
  expect('ja 用汉字正字不红', entryIssues('ja', {
    '已连接 {0} 台': '{0} 台に接続済み',
    '高可用集群': '高可用性クラスタ',
    '已连接到中继服务器': '中継サーバーに接続済み',
  }).length, 0);
  // ★★ 这一对控制钉的是「同形」这条判据的取舍，两边都必须写死读数：
  //   三个汉字的整条照抄（「已完成」）在 ja 里**故意不报** —— 日文短词与中文同形的太多，
  //   报上去就是假红，而假红一次，判据下一次就被注掉。代价照实记在这儿：
  //   三字以内的偷懒抄写，这把尺量不到。四字以上量得到，所以那边必须报。
  expect('ja 三字整条照抄不报（已知放过）', entryIssues('ja', { 已完成: '已完成' }).length, 0);
  expect('ja 四字以上整条照抄会红', entryIssues('ja', { 这台机器: '这台机器' }).length, 1);
  expect('ja 连抄四个汉字会红', entryIssues('ja', { '按流聚合统计': '按流聚合統計を表示' }).length, 1);
  expect('ja 单位与结构串照抄不红', entryIssues('ja', {
    ' 秒': ' 秒', '出口 MTU': '出口 MTU', 日本語: '日本語', '<div class="empty">ping 中…</div>': '<div class="empty">ping 中…</div>',
  }).length, 0);
  expect('ko 留两个汉字就红', entryIssues('ko', { '安全模式': '安全모드' }).length, 1);
  expect('ko 谚文正字不红', entryIssues('ko', { '已连接到中继': '중계에 연결됨' }).length, 0);
  // ★ 排版标点：全角括号在 ja 是正字、在 ko/en/ru 是「抄过来的证据」。这一对控制必须两头钉。
  //   （ko 词典里真出现过 너비（픽셀）—— 四本都 100% 的那天，界面上还挂着中文括号。）
  expect('ko 抄全角括号会红', entryIssues('ko', { '宽（像素）': '너비（픽셀）' }).length, 1);
  expect('ko 半角括号不红', entryIssues('ko', { '宽（像素）': '너비(픽셀)' }).length, 0);
  expect('ja 全角标点正字不红', entryIssues('ja', { '丢要查链路（信号、网线）。': 'ロスならリンク（信号、ケーブル）。' }).length, 0);
  expect('ja 用中文逗号会红', entryIssues('ja', { 这台机器: 'このマシン，' }).length, 1);
  expect('en 抄顿号会红', entryIssues('en', { '查信号、网线': 'Check signal、cable' }).length, 1);
  // 原文本来就没汉字（"VLAN ID"）时，译文与原文同形是正解，不许报
  expect('无汉字原文照抄不红', entryIssues('ja', { 'VLAN ID': 'VLAN ID' }).length, 0);
  process.exit(n ? 1 : 0);
}
if (process.argv.includes('--selftest')) selftest();

let fail = 0;
const bad = (msg) => { fail++; console.log('✗ ' + msg); };
const ok = (msg) => console.log('✓ ' + msg);

const { want, dynamic, unmarked } = sourceKeys();
console.log(`源码字面量键 ${want.length} 个（唯一）· 动态键 ${dynamic.length} 处`);
for (const u of unmarked) bad('HTML 里有界面文字绕过了 t()：' + u);

// 判据 0：动态键必须有账。基线是「键 → 为什么可以留着」的对照表，
// 光在册不算签字：空白理由一律红。否则三个月后这份文件就变成一份
// 「为了让检查器闭嘴而存在的名单」，那和没有检查器一样。
//
// ★ 在册与否按**行号抹掉**后的式子比：这一条 t(el.dataset.zh) 在 i18n.js 里本来就一处，
//   上面加两行注释就报「新增动态键」，报的是假红 —— 而假红的下场和被假红训练过的所有人
//   一样：下次真新增一条也没人看。行号照样印在消息里，只是不拿来当身份。
const asKey = (s) => s.replace(/:\d+(\s)/, '$1');
let base = null;
if (fs.existsSync(BASELINE)) {
  base = {};
  for (const [k, v] of Object.entries(JSON.parse(read(BASELINE)))) base[asKey(k)] = v;
  const fresh = dynamic.filter((d) => !(asKey(d) in base));
  const unsigned = dynamic.filter((d) => asKey(d) in base && !String(base[asKey(d)] || '').trim());
  if (fresh.length) {
    for (const d of fresh) bad('新增动态键（提取器看不见它，覆盖率算不到它）：' + d);
  }
  if (unsigned.length) {
    for (const d of unsigned) bad('动态键在册但没签字（基线里理由为空）：' + d);
  }
  if (!fresh.length && !unsigned.length) ok(`动态键与基线一致（${dynamic.length} 处，均已签字）`);
  const dyn = new Set(dynamic.map(asKey));
  const stale = Object.keys(base).filter((b) => !dyn.has(b));
  for (const s of stale) console.log(`! 基线里有一条源码已经不再产生：${s}（可以删掉，留着会误导）`);
} else {
  console.log(`! 没有动态键基线 —— 先跑 --write-baseline 钉住这 ${dynamic.length} 处`);
}
if (process.argv.includes('--write-baseline')) {
  const have = fs.existsSync(BASELINE) ? JSON.parse(read(BASELINE)) : {};
  const normHave = {};
  for (const [k, v] of Object.entries(have)) normHave[asKey(k)] = v;
  const out = {};
  for (const d of dynamic) out[asKey(d)] = asKey(d) in normHave ? normHave[asKey(d)] : '';
  fs.writeFileSync(BASELINE, JSON.stringify(out, null, 1) + '\n');
  const blank = dynamic.filter((d) => !String(out[asKey(d)] || '').trim()).length;
  console.log(`已写基线：${path.relative(ROOT, BASELINE)}（${dynamic.length} 条，其中 ${blank} 条理由为空 —— 手工补上「为什么可以留着」）`);
}
for (const d of dynamic) console.log('  · ' + d);

// 中文 key 里带 HTML/长句的那些，是翻译最容易出错的一批，单独数出来给人看。
const byLen = [0, 0, 0];
for (const k of want) byLen[k.length > 120 ? 2 : k.length > 60 ? 1 : 0]++;
console.log(`按长度：≤60 字 ${byLen[0]} · 61–120 字 ${byLen[1]} · >120 字 ${byLen[2]}（长句是回落中文的主要来源）`);

// ---- 判据 5、6：分母**之外**的那两类，先于覆盖率量 ----
//
// ★ 为什么放在这里而不是"有空再查"：分母就是 t() 的首参，所以这两类中文
//   永远不会让覆盖率变红 —— 「3073/3073 全过」和「界面上露一片中文」可以同时成立。
//   两条都是这一轮冷启动量出来的事故，不是设想：
//     · app.js 顶部的判定码表存的是 t('中文') 的**返回值**，app.js 抢在词典之前解析
//       → 选英文的人整页「下一步该干什么」全是中文（路由表那格印着「Routing table 同族有多条默认路由」）
//     · 表头那种没包的中文（宽 / 高）→ 覆盖率一辈子数不到它
//   还有第三种坏法最阴：把 t() 的结果当键去查一张中文键的表（不给读/算不准 那一条），
//   查出来是 undefined，界面上整句图例静默消失 —— 守卫数不到，只有读界面的人看见那里空着。
const { unwrappedCJK, uiLoadOrder } = require('./i18n-lib.cjs');
for (const m of uiLoadOrder(ROOT, 'src/index.html', 'src/i18n.js', 'app.js')) bad(m);
for (const m of unwrappedCJK(ROOT, SRC)) bad(`${m} —— 覆盖率数不到它，界面上原样露中文`);
console.log(`分母之外：没走 t() 的中文 ${unwrappedCJK(ROOT, SRC).length} 处 · 加载顺序问题 ${uiLoadOrder(ROOT, 'src/index.html', 'src/i18n.js', 'app.js').length} 处`);

const wantSet = new Set(want);
const argRe = /--fail-under=(\S+)/.exec(process.argv.join(' '));
// ★ 门槛默认就是「四本都必须 100%」，不是「跑的人记得加参数才生效」。
//   理由是在这一次的量里坐实的：源码里新增了 151 条句子，没人想起去补箱子，
//   于是那 151 句在全世界四种语言里都还是中文 —— 而覆盖率按「看得见的那一半」算，一路绿。
//   要临时放过（比如正在做一批新文案），显式写 --fail-under=en=0,ja=0,ko=0,ru=0，
//   放过一次要留得下来，别让它在下一次提交时静悄悄还在。
const floors = { en: 100, ja: 100, ko: 100, ru: 100 };
if (argRe) for (const part of argRe[1].split(',')) {
  const [l, v] = part.split('=');
  if (!(l in floors)) { console.error(`✗ --fail-under 不认的语言「${l}」，四本是 ${LANGS.join(' / ')}`); process.exit(2); }
  floors[l] = Number(v);
}

for (const lang of LANGS) {
  const dict = loadDict(lang);
  if (!dict) {
    console.log(`\n${lang}：没有词典文件（界面全回落中文）`);
    if (floors[lang] !== undefined && floors[lang] > 0) bad(`${lang} 覆盖率 0% < 要求 ${floors[lang]}%`);
    continue;
  }
  const keys = Object.keys(dict);
  const used = keys.filter((k) => wantSet.has(k));
  const dead = keys.filter((k) => !wantSet.has(k));
  // 分子只认「译出去了」的条目。★ 但「值与 key 一模一样」有两种，不能一棍子打死：
  //   一种是没译，另一种是这一条根本没有可译的东西（「 秒」这种单位、纯 HTML 骨架、
  //   只含品牌与路径的串）。后一种在 ja/ko 里成百，把它算成没译，
  //   这本字典的覆盖率就永远到不了 100% —— 而够不着的门槛最后会被整条删掉。
  //   分辨用同一把尺（untranslatedBits），不在这另写一套，免得两边判出两种结果。
  const same = used.filter((k) => dict[k] === k);
  const verbatim = same.filter((k) => !identityIsFine(lang, k, dict[k]));
  const identOK = same.length - verbatim.length;
  const translated = used.filter((k) => dict[k] !== k || identityIsFine(lang, k, dict[k]));
  const missing = want.filter((k) => !(k in dict));
  const pct = want.length ? (translated.length / want.length) * 100 : 100;

  console.log(`\n${lang}：已译 ${translated.length}/${want.length}（${pct.toFixed(1)}%）· 未收 ${missing.length} · 照抄未译 ${verbatim.length} · 无可译 ${identOK} · 死条目 ${dead.length}`);
  if (verbatim.length) bad(`${lang}：${verbatim.length} 条的值和中文一模一样 —— 界面上这一句一个字都没变`);

  const issues = entryIssues(lang, dict);
  for (const m of issues.slice(0, 30)) bad(`${lang}: ${m}`);
  if (issues.length > 30) bad(`${lang}: 另有 ${issues.length - 30} 条同类问题`);
  // 死条目只报数＋列前若干条：中文原文一旦改写，旧译文就永久失效，
  // 但它的危害是「这句退回中文」，不是崩，所以不拦交付，只拦「没人知道它在退」。
  if (dead.length) {
    console.log(`  死条目（源码里已经没人用，界面上这一句会露回中文）：`);
    for (const k of dead.slice(0, 10)) console.log('   · ' + JSON.stringify(k).slice(0, 100));
    if (dead.length > 10) console.log(`   … 其余 ${dead.length - 10} 条`);
  }
  if (floors[lang] !== undefined) {
    if (pct + 1e-9 < floors[lang]) bad(`${lang} 覆盖率 ${pct.toFixed(1)}% < 要求 ${floors[lang]}%`);
    else ok(`${lang} 覆盖率达标（${pct.toFixed(1)}% ≥ ${floors[lang]}%）`);
  }
}

console.log(fail ? `\n✗ 共 ${fail} 条不过` : '\n✓ 全过');
process.exit(fail ? 1 : 0);
