// t() 词典的一条共用判据：一段中文原文被译完之后，**结构**必须一模一样。
//
// 为什么单独成一个文件：i18n-audit.cjs（数覆盖率）和 i18n-merge.cjs（合成本品）必须
// 用同一把尺子。两边各写一份的话，最先出现的事故是「merge 放过去、audit 事后报红」，
// 而那红会出现在一份已经写进 src/locales/ 的词典里 —— 排查成本翻一倍。
//
// 两条尺子：
//   · 槽位 {0} {1}：少一个，界面上就打出裸的 "{0}"；编号错了，两个值会串位。
//   · HTML 骨架：标签种类与数量、以及**结构性属性**（id / class / style / …）不许动。
//
// ★★ 结构性属性只比名字+值，显示性属性（placeholder / title / aria-label / alt /
//    content）只比名字，不比值 —— 那几样是**给人看的文字**，翻译本来就该改它；
//    拿整串去比，等于要求「德语界面上印着中文的输入框提示」，判据本身成了错的。
//    id、class、style、name、type 反过来一个字符都不许变：改了就是把脚本的锚点、
//    样式、表单字段一起弄坏，而那种坏在界面上看不出来。

const fs = require('fs');
const path = require('path');

const STRUCTURAL = new Set([
  'id', 'class', 'style', 'name', 'type', 'for', 'colspan', 'rowspan', 'width',
  'height', 'src', 'href', 'disabled', 'checked', 'selected', 'autofocus',
  'autocomplete', 'maxlength', 'minlength', 'min', 'max', 'step', 'pattern',
  'required', 'multiple', 'size', 'tabindex', 'viewbox', 'd', 'cx', 'cy', 'r',
  'x', 'y', 'x1', 'x2', 'y1', 'y2', 'transform', 'fill', 'stroke', 'stroke-width',
]);
// data-* 是脚本自己读的钩子，不是文案，整串钉住。
const isStructural = (a) => STRUCTURAL.has(a.toLowerCase()) || /^data-/i.test(a);

const slots = (s) => (s.match(/\{\d+\}/g) || []).sort();

// 把一个标签拆成 { name, attrs }，再压成签名串。
function tagSig(x) {
  const m = /^<\/?\s*([a-zA-Z][\w:-]*)/.exec(x);
  if (!m) return null;
  const name = m[1].toLowerCase();
  const closing = /^<\//.test(x);
  const body = x.slice(m[0].length).replace(/\/?>$/, '');
  const attrs = [];
  const re = /([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  let one;
  while ((one = re.exec(body))) {
    const key = one[1].toLowerCase();
    const val = one[2] ?? one[3] ?? one[4] ?? '';
    attrs.push(isStructural(key) ? key + '=' + val.trim() : key);
  }
  attrs.sort();
  return (closing ? '/' : '') + name + (attrs.length ? ' ' + attrs.join(' ') : '');
}

function skeleton(s) {
  return (s.match(/<\/?[a-zA-Z][^>]*>/g) || []).map(tagSig).filter(Boolean).sort();
}

// 「译文里还留着中文」这条判据，四种语言不能共用一把尺：
//
//   · en / ru —— 拉丁与西里尔界面里出现任何一个中日韩字，就是没译。往严里判。
//   · ko      —— 现代韩文界面按约定全写谚文，汉字只在极少数人名里出现；
//     所以连着两个汉字就算抄的（「安全」在韩文里是 안전，不是 安全）。
//   · ja      —— 日文界面本来就写汉字，而且和中文共用一批同形词：
//     「接続」「転送」这类正字与中文长得不一样，但「高可用」「不支持」这种
//     三字同形的确实会合法出现。拿「有汉字 = 没译」去判，会把正确译文报成红的，
//     而一个人被假红报过一次，下一次他就把这条判据整条注掉 —— 那比没有判据更糟。
//     所以 ja 判的是**整段抄过来**：与原文连续同形 ≥4 个汉字，才算抄。
//
// ★ 这三个门槛（1 / 2 / 4）是我按各语言的书写约定定的，不是量出来的。
//   四本词典合完之后要用真实数据回看一眼：假红 = 门槛太松的反面，
//   漏放整段抄的 = 太严。谁先出现就往谁那边挪，并把这个注释改成量出来的口径。
const CJK = /[㐀-䶿一-鿿぀-ヿ가-힯]/;
// 只数汉字：假名和谚文本来就该出现在译文里，不算「留着中文」。
const HAN = /[㐀-䶿一-鿿]/;

// ── 照抄清单：译文里**允许**原样出现的中文串 ─────────────────────────
//
// 客户站点名（金宇建安）、品牌（昱弘网通）、带中文的路径（/tmp/升级包.bin）——
// 这些东西译了才是错的：现场看到的世界名就是那四个字，罗马化成
// "Jinyu Jian'an" 反而对不上工单和发票。所以「还留着中文」这条判据必须给它们开门。
//
// ★ 但门不能开在判据里（"看到四个汉字以下就算了"），只能开在**一张看得见的表**里：
//   例外写进 i18n-glossary.md 的那一节，谁都能读 diff，也都看得见它长没长。
//   写在代码里的例外，三个月后就没人记得为什么在那儿 —— 那才是判据真正的烂法。
// 表就在词典译者已经在读的那份文件里，不再另起一个文件（两处清单必然对不上）。
const KEEP_SECTION = '一·b';
let keepCache = null;
function keepLiterals() {
  if (keepCache) return keepCache;
  keepCache = [];
  const p = path.join(__dirname, 'i18n-glossary.md');
  if (fs.existsSync(p)) {
    // 按 ## 切节，找标题里带「一·b」的那一节。不用一条大正则：
    // JS 的 $ 带 m 标志会停在行尾，节末的边界反而更难写对。
    const md = fs.readFileSync(p, 'utf8');
    const sec = md.split(/^## /m).find((s) => s.startsWith(KEEP_SECTION) || /^[^\n]*一·b/.test(s));
    if (sec) {
      const body = sec.slice(sec.indexOf('\n'));
      for (const span of body.matchAll(/`([^`]+)`/g)) if (CJK.test(span[1])) keepCache.push(span[1]);
    }
  }
  return keepCache;
}
// 把清单里的那些串从文本里挖掉（挖成空格），剩下的才是「本该译却没译」的部分。
function maskKeeps(s) {
  let out = s;
  for (const lit of keepLiterals()) out = out.split(lit).join(' ');
  return out;
}
// 四本词典的名单也放在这里：audit 数覆盖率、merge 合成、check-part 自检
// 必须是同一批语言 —— 少一本的话，界面上那一种语言永远回落中文，
// 而「回落中文」在页面上看不出是漏了一本还是漏了一句。
const LANGS = ['en', 'ja', 'ko', 'ru'];
const MIN_RUN = { en: 1, ru: 1, ko: 2, ja: 4 };

// 原文与译文之间**连续同形**的最长汉字片段。
function longestCopiedRun(key, val) {
  let best = '';
  for (const run of key.split(/[^㐀-䶿一-鿿]+/)) {
    for (let i = 0; i + best.length < run.length; i++) {
      for (let n = run.length - i; n > best.length; n--) {
        const piece = run.slice(i, i + n);
        if (val.includes(piece)) { if (piece.length > best.length) best = piece; break; }
      }
    }
  }
  return best;
}

// ★★ 排版标点是**按语言**的，不是按字符的：同一枚「（」在日文里是正字，在英文、俄文、
//   韩文界面里就是「这一句是从中文界面上抄下来的」——读者不必看懂内容也能一眼看出来。
//   汉字那把尺（MIN_RUN）量不到它：一行抄过来的译文里可以一个汉字都不剩，
//   全角标点却还钉在那儿。所以单列一条，并按各语言的正字法放宽：
//   ja 只禁「，」——那是中文专用的逗号，日文并列用「、」；en/ko/ru 全禁。
const FW_PUNCT = ['，', '、', '。', '：', '；', '！', '？', '（', '）', '「', '」', '『', '』', '《', '》', '〈', '〉'];
const FW_OK = { ja: new Set(FW_PUNCT.filter((c) => c !== '，')) };

function foreignPunct(lang, val) {
  if (typeof val !== 'string') return [];
  const v = maskKeeps(val); // 照抄清单里的整块（中文专名、命令）原样出现，不算排版错
  const ok = FW_OK[lang] || new Set();
  const hit = [...new Set([...v].filter((c) => FW_PUNCT.includes(c) && !ok.has(c)))];
  return hit.length ? [`用的是中文排版的标点「${hit.join('')}」`] : [];
}

// 「还是中文」= 汉字没换掉 **或** 排版还留着中文那一套。两头都在这一把尺里，
// 消费者（audit / merge / check-part）就只认一个入口，不会两边判出两种结果。
function untranslatedBits(lang, key, val) {
  return [...stillChineseWords(lang, key, val), ...foreignPunct(lang, val)];
}

function stillChineseWords(lang, key, val) {
  if (typeof val !== 'string') return [];
  // 照抄清单先挖掉：剩下的中文才是「本该译却没译」的那部分。
  const [k, v] = [maskKeeps(key), maskKeeps(val)];
  const min = lang in MIN_RUN ? MIN_RUN[lang] : 1;
  if (min === 1) return CJK.test(v) ? ['译文里还留着中日韩字符'] : [];
  // 原文本来就没汉字（"VLAN ID"）时，译文与原文同形是正解，不判。
  if (!HAN.test(k)) return [];
  // ★ 「整条照抄」不再单列一条判据。它原来在，于是把「 秒」「出口 MTU」「日本語」
  //   「ping 中…」这类**日文本来就长一样**的条目报成红，而词典里这种短串成百。
  //   同形是抄的还是正字，只有「连着几个汉字」这一把尺能回答；再加一条
  //   「一样就红」等于把上面放宽的门槛调回最严那一档，前面白放宽。
  const run = longestCopiedRun(k, val);
  return run.length >= min ? [`照抄了原文的「${run}」`] : [];
}

// 覆盖率要把两种「值与 key 一模一样」分开：一种是真的没译，一种是这一条**没有可译的东西**
// （单位、纯结构、只含品牌与路径）。后者算译完了 —— 不然 ja/ko 的覆盖率永远到不了 100%，
// 而一个够不着的门槛最后被人整条删掉，比没有门槛更糟。
function identityIsFine(lang, key, val) {
  return typeof val === 'string' && val === key && untranslatedBits(lang, key, val).length === 0;
}

// 一条 key→value 的毛病清单；空数组就是这条过。
function entryIssues(key, val) {
  const out = [];
  if (typeof val !== 'string') return ['值不是字符串'];
  // ★ 原文本身就是空白（app.js 里 t('　') 当分隔符用的那几处）：没有任何可译的东西，
  //   唯一正解是照抄。原先这一条也走「值是空的」判红，翻译为了过关塞进来一个零宽空格 ——
  //   那是把界面上看得见的宽空格换成一个看不见的字符，比不改还难被发现。
  if (!key.trim()) {
    if (val !== key) out.push(`原文是空白分隔符，只能照抄（给的是 ${JSON.stringify(val)}）`);
    return out;
  }
  if (!val.trim()) return ['值是空的'];
  if (slots(key).join() !== slots(val).join()) {
    out.push(`槽位对不上：[${slots(key).join(' ')}] ≠ [${slots(val).join(' ')}]`);
  }
  const [a, b] = [skeleton(key), skeleton(val)];
  if (a.join() !== b.join()) {
    const diff = [];
    const seen = new Map();
    for (const x of a) seen.set(x, (seen.get(x) || 0) + 1);
    for (const y of b) seen.set(y, (seen.get(y) || 0) - 1);
    for (const [k, n] of seen) if (n !== 0) diff.push(`${k} ×${n}`);
    out.push(`HTML 骨架对不上：${diff.join('、')}`);
  }
  return out;
}

// ── 源码里的字面量键：全项目唯一一份提取口径 ───────────────────
//
// ★ 为什么这份要在 lib 里而不是各脚本自己写：数覆盖率的（audit）、
//   合成词典的（merge）、切箱子给翻译的（chunks）以前各扫各的。
//   切箱子的看不见 index.html 里那句 [data-i18n]，也看不见后来加进 app.js 的新句子 ——
//   于是出现「词典按箱子算 100%、界面上那句还留着中文」这种两边都说自己绿的情况。
//   三份口径并成一份之后，「键没进箱子」这条路就没有了。
// HTML 的可见文字，按「<tag 属性…>文字<」抠出来。注释原地挖成等量空白，行号才对得上。
function htmlTexts(root, htmlRel) {
  const file = path.join(root, htmlRel);
  if (!fs.existsSync(file)) return [];
  const html = fs.readFileSync(file, 'utf8').replace(/<!--[\s\S]*?-->/g, (x) => x.replace(/[^\n]/g, ' '));
  const out = [];
  for (const m of html.matchAll(/<([a-z]+)\b([^>]*)>([^<]*)</gi)) {
    out.push({ tagAttrs: m[2], text: m[3].trim(), line: html.slice(0, m.index).split('\n').length });
  }
  return out;
}

function literalKeys(root, srcFiles, htmlRel) {
  const ts = require('typescript');
  const keys = new Set();
  for (const rel of srcFiles) {
    const file = path.join(root, rel);
    if (!fs.existsSync(file)) continue;
    const sf = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
    const walk = (n) => {
      if (ts.isCallExpression(n) && /(^|\.)t$/.test(n.expression.getText())) {
        const a = n.arguments[0];
        if (a && (ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a))) keys.add(a.text);
      }
      ts.forEachChild(n, walk);
    };
    ts.forEachChild(sf, walk);
  }
  if (htmlRel) {
    // <tag … data-i18n …>中文</tag>：applyStatic() 运行时才把它当键，AST 从 JS 那边数不到
    for (const h of htmlTexts(root, htmlRel)) {
      if (/\bdata-i18n\b/.test(h.tagAttrs) && h.text && CJK.test(h.text)) keys.add(h.text);
    }
  }
  return [...keys];
}

// HTML 里**没标** data-i18n 的中文文字：这种句子永远进不了 t()，界面上就是死留中文。
function unmarkedHTMLText(root, htmlRel) {
  return htmlTexts(root, htmlRel)
    .filter((h) => h.text && CJK.test(h.text) && !/\bdata-i18n\b/.test(h.tagAttrs) && CJK.test(maskKeeps(h.text)))
    .map((h) => `${htmlRel}:${h.line}  「${h.text}」没标 data-i18n，也不在照抄清单里`);
}

// ── 分母之外的中文：这一组量的不是「译没译」，是「这句到底进不进得了词典」──
//
// ★★ 为什么非要有这一段：literalKeys 的分母**就是 t() 的首参**，所以「忘了包 t()」的中文
//   从来不在分母里 —— 「词典 3073/3073 全过」和「界面上露着一片中文」这两件事完全可以同时成立。
//   这不是设想，是冷启动量出来的：改之前选 en，路由表那一格印的是
//   「Routing table 同族有多条默认路由」—— 前一半查到了，后一半没查到。
//   所以覆盖率之前先跑这三个，否则 100% 这个数字是虚的。

function parseFile(ts, root, rel) {
  const file = path.join(root, rel);
  if (!fs.existsSync(file)) return null;
  return ts.createSourceFile(rel, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
}

// 每个 t() 的首参扫一遍：能被词典查到的只有「不带插值的字面量」这一种。
function tFirstArgs(ts, sf) {
  const out = [];
  (function w(n) {
    if (ts.isCallExpression(n) && /(^|\.)t$/.test(n.expression.getText())) out.push(n.arguments[0] || null);
    ts.forEachChild(n, w);
  })(sf);
  return out;
}

/** t() 首参是运行时才拼出来的（模板里有 ${}、字符串相加、变量）——这种 key 永远查不到词典。 */
function dynamicTKeys(root, srcFiles) {
  const ts = require('typescript');
  const bad = [];
  for (const rel of srcFiles) {
    const sf = parseFile(ts, root, rel);
    if (!sf) continue;
    for (const a of tFirstArgs(ts, sf)) {
      const ok = a && (ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a));
      const line = sf.getLineAndCharacterOfPosition((a || sf).getStart()).line + 1;
      if (!a) bad.push(`${rel}:${line} t() 没给 key`);
      else if (!ok) bad.push(`${rel}:${line} t() 的 key 是运行时拼出来的（${a.getText().slice(0, 46).replace(/\n/g, ' ')}…）—— 词典对不上，这一句永远露中文`);
    }
  }
  return bad;
}

/** 界面上会露出来、却没走 t() 的中文。 */
function unwrappedCJK(root, srcFiles) {
  const ts = require('typescript');
  const out = [];
  for (const rel of srcFiles) {
    const sf = parseFile(ts, root, rel);
    if (!sf) continue;
    // t() 首参整段算「已包」：里面的 ${} 是槽位，那些位子上的中文本来就不该再包一次
    const covered = [];
    for (const a of tFirstArgs(ts, sf)) if (a) covered.push([a.getFullStart(), a.getEnd()]);
    const inCovered = (s, e) => covered.some(([cs, ce]) => s >= cs && e <= ce);
    (function w(n) {
      if (ts.isObjectLiteralExpression(n)) {
        for (const pr of n.properties) {
          // ★ 对象字面量的**键位**不报：'动态': [...]、{'不给读': t(...)} 那种键是拿去和
          //   后端回来的值对得上的身份，不是给人看的字。把它包进 t()，en 界面上这一条
          //   直接查不到（不给读/算不准 那一条当时就是这么坏的）。
          if (ts.isPropertyAssignment(pr)) w(pr.initializer);
          else w(pr);
        }
        return;
      }
      let text = null;
      if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) text = n.text;
      else if (ts.isTemplateExpression(n)) text = [n.head, ...n.templateSpans.map((s) => s.literal)].map((x) => x.text).join('');
      if (text !== null && CJK.test(text) && !inCovered(n.getFullStart(), n.getEnd())) {
        const line = sf.getLineAndCharacterOfPosition(n.getStart()).line + 1;
        // 行尾写了 i18n:endonym 的放过：语言名按母语写（한국어 / English / Русский）是故意的，
        // 译成「韩语」反而让本地人认不出那一项是自己 —— 这种位子必须是原文。
        // 写了 i18n:source-match 的同样放过：那是拿去和**后端回来的中文字面量**逐字对的身份
        // （对不上就退回原话），上屏的另有 t() 那一份；包进 t() 反而永远对不上后端的原文。
        if (!/\bi18n:(endonym|source-match)\b/.test(sf.text.split('\n')[line - 1] || '')) {
          out.push(`${rel}:${line} 「${text.replace(/\n/g, ' ').slice(0, 60)}」没走 t()`);
        }
      }
      ts.forEachChild(n, w);
    })(sf);
  }
  return out;
}

/** app.js 必须等词典就位之后再解析（判定码表烤的是 t() 的返回值）。 */
function uiLoadOrder(root, htmlRel, i18nRel, appRel) {
  const out = [];
  const htmlPath = path.join(root, htmlRel);
  const i18nPath = path.join(root, i18nRel);
  if (!fs.existsSync(htmlPath) || !fs.existsSync(i18nPath)) return [`找不到 ${htmlRel} 或 ${i18nRel}`];
  // 注释里提一句 app.js 是讲解，不算加载 —— 先把注释抹了再看。
  const html = fs.readFileSync(htmlPath, 'utf8').replace(/<!--[\s\S]*?-->/g, '');
  if (new RegExp(`<script[^>]*src\\s*=\\s*["']?[^"'>]*${appRel}`).test(html)) {
    out.push(`${htmlRel} 里还直接挂着 <script src="${appRel}"> —— app.js 会赶在词典之前解析，判定码表整片烤成中文`);
  }
  const i18n = fs.readFileSync(i18nPath, 'utf8');
  const awaitDict = i18n.indexOf('await loadDict(I18N.lang)');
  const inject = i18n.indexOf(`'${appRel}'`);
  if (awaitDict < 0 || inject < 0) {
    out.push(`${i18nRel} 里找不到「await loadDict → 注入 ${appRel}」这一对 —— 顺序丢了就是冷启动露中文`);
  } else if (inject < awaitDict) {
    out.push(`${i18nRel} 里 ${appRel} 注入写在 await loadDict 之前 —— 词典还没到就把 app.js 解析了`);
  }
  return out;
}

module.exports = {
  LANGS, slots, skeleton, tagSig, entryIssues, untranslatedBits, foreignPunct, identityIsFine,
  isStructural, maskKeeps, literalKeys, unmarkedHTMLText,
  unwrappedCJK, dynamicTKeys, uiLoadOrder,
};
