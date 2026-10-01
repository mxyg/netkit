// 把 ui/src/*.js 里带中文的字符串写成 t('…')。中文原文就是 key，所以这一步
// 不改文案、不动逻辑：只把「界面上会出现的中文」圈出来，好让词典能对着它数覆盖率。
//
//   node scripts/i18n-codemod.mjs            只看会改什么（不写文件）
//   node scripts/i18n-codemod.mjs --write    落盘
//
// ★ 为什么不手改：app.js 一处渲染就是一整段 HTML 模板串，中文成百上千个，
//   手改必漏，而漏掉的那一处是**静默**的（界面照旧显示中文，没人发现这页没译）。
//   所以宁可走 AST：改完用结构对比证明「除了字符串本身，语法树一个字没变」。
//
// 跳过规则（都必须在报告里数得出来）：
//   · 注释（AST 天然看不见，另用 anti-erosion 断言保证没吞掉代码）
//   · console.* / 任何 console 调用里的参数 —— 那是给工程师看的日志，不是给人看的界面
//   · document.createElement(...)、querySelector(...)、addEventListener 的事件名：
//     选择器一旦被包上就选不中节点了，那是把界面弄坏，不是弄成双语
//   · 对象字面量里是 CSS 属性名的键（如 { backgroundColor: … }）
//   · 已经是 t(...) / tt(...) 调用的第一个参数（幂等：重复跑不套第二层）

const fs = require('fs');
const path = require('path');
const ts = require('typescript');

const ROOT = path.resolve(__dirname, '..');
const TARGETS = ['src/app.js', 'src/i18n.js'];
const WRITE = process.argv.includes('--write');
const CN = /[\u3000-\u303f\u3400-\u4dbf\u4e00-\u9fff\uff00-\uffef]/;

// 这些调用的**全部参数**都不译（选择器/DOM 工厂/日志）
const NEVER_WRAP_CALLEES = new Set([
  'querySelector', 'querySelectorAll', 'createElement', 'addEventListener',
  'removeEventListener', 'dispatchEvent', 'getElementById', 'matches', 'closest',
  'getAttribute', 'setAttribute', 'hasAttribute', 'removeAttribute', 'setProperty',
  'log', 'warn', 'error', 'info', 'debug',
]);

function stats() {
  return { wrapped: 0, skippedConsole: 0, skippedSelector: 0, skippedKey: 0, skippedAlready: 0, skippedEmpty: 0 };
}

// 一个字符串值要变成什么 key：模板串的静态片段拼成一个 key，${expr} 换成 {0} {1}…
function keyFromTemplate(node, sf) {
  let text = '';
  let idx = 0;
  const exprs = [];
  const head = node.head ? node.head.text : '';
  text += head;
  let cur = node.templateSpans;
  for (const span of cur) {
    text += '{' + idx + '}';
    exprs.push(span.expression.getText(sf));
    idx++;
    text += span.literal.text;
  }
  return { key: text, exprs };
}

// 颜色/尺寸这些值是品牌资产与布局参数，译了等于把界面画坏 —— 值挂在 CSS 属性名下面的，一律不包。
// （theme.css 顶部那条规矩在这里的翻版：颜色是资产，不是文案。）
const CSS_PROPS = new Set([
  'backgroundColor', 'background', 'color', 'border', 'borderTop', 'borderBottom',
  'borderLeft', 'borderRight', 'borderColor', 'borderStyle', 'borderRadius', 'boxShadow',
  'fill', 'stroke', 'font', 'fontFamily', 'fontSize', 'fontWeight', 'fontStyle',
  'gridTemplateColumns', 'gridTemplateRows', 'display', 'position', 'textAlign',
  'padding', 'margin', 'width', 'height', 'minWidth', 'minHeight', 'maxWidth', 'opacity',
  'cursor', 'transition', 'transform', 'lineHeight', 'letterSpacing', 'textDecoration',
  'overflow', 'whiteSpace', 'alignItems', 'justifyContent', 'gap', 'flex', 'zIndex',
]);

function isCssValue(node) {
  const p = node.parent;
  if (!p) return false;
  if (ts.isPropertyAssignment(p) && p.initializer === node && ts.isIdentifier(p.name)) {
    return CSS_PROPS.has(p.name.text);
  }
  // el.style.backgroundColor = '…'
  if (ts.isBinaryExpression(p) && p.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(p.left) && ts.isPropertyAccessExpression(p.left.expression) &&
      ts.isIdentifier(p.left.expression.expression) && p.left.expression.expression.text === 'style') {
    return true;
  }
  return false;
}

function isConsoleCall(node) {
  let p = node.parent;
  while (p) {
    if (ts.isCallExpression(p)) {
      const e = p.expression;
      if (ts.isPropertyAccessExpression(e) && e.expression.getText() === 'console') return true;
    }
    p = p.parent;
  }
  return false;
}

function inNeverWrapArg(node) {
  let p = node;
  while (p) {
    if (ts.isCallExpression(p)) {
      const name = ts.isPropertyAccessExpression(p.expression)
        ? p.expression.name.getText()
        : p.expression.getText();
      if (NEVER_WRAP_CALLEES.has(name) && p.arguments.some((a) => containsNode(a, node))) return true;
      if (name === 't' || name === 'tt') return false; // 已是 t()：里面不再包
      if (ts.isPropertyAccessExpression(p.expression) && p.expression.expression.getText() === 'console') return true;
    }
    if (ts.isComputedPropertyName(p)) return true;
    p = p.parent;
  }
  return false;
}

function containsNode(a, node) {
  if (a === node) return true;
  let hit = false;
  const walk = (n) => { if (hit) return; if (n === node) { hit = true; return; } ts.forEachChild(n, walk); };
  walk(a);
  return hit;
}

function isObjectKey(node) {
  return node.parent && (ts.isPropertyAssignment(node.parent) || ts.isShorthandPropertyAssignment(node.parent))
    && node.parent.name === node;
}

// 模板串里 ${} 插的值如果是「机器口径」（数字、判定码、.length、JSON），照旧插；
// 这一版先不做任何值级翻译 —— 报告里会列出带插值的 key 数量，词典要连着语序一起改。
function rewrite(src, file, st) {
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
  const edits = [];

  const visit = (node) => {
    if (CN.test(node.getText(sf)) === false && !ts.isTemplateExpression(node)) {
      ts.forEachChild(node, visit);
      return;
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      const text = node.text;
      if (CN.test(text)) {
        if (isConsoleCall(node)) st.skippedConsole++;
        else if (isCssValue(node)) st.skippedCss = (st.skippedCss || 0) + 1;
        else if (isObjectKey(node)) st.skippedKey++;
        else if (inNeverWrapArg(node)) st.skippedSelector++;
        else if (alreadyT(node)) st.skippedAlready++;
        else {
          edits.push({ pos: node.getStart(sf), end: node.getEnd(), text: `t(${quote(text)})` });
          st.wrapped++;
        }
      }
      return;
    }
    if (ts.isTemplateExpression(node)) {
      const { key, exprs } = keyFromTemplate(node, sf);
      if (!CN.test(key)) { ts.forEachChild(node, visit); return; }
      if (isConsoleCall(node) || inNeverWrapArg(node)) { st.skippedConsole++; return; }
      if (alreadyT(node)) { st.skippedAlready++; return; }
      const args = exprs.length ? `, [${exprs.join(', ')}]` : '';
      edits.push({ pos: node.getStart(sf), end: node.getEnd(), text: `t(${quote(key)}${args})` });
      st.wrapped++;
      return;
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);

  // 嵌套的那一层丢掉：模板串整体已经变成一个 key，里面 `${}` 表达式上的中文留给下一轮。
  // 两段编辑区间叠在一起按位置改文本会把代码改碎，而且这种坏法是静默的 —— 绝不允许。
  const merged = [];
  for (const e of edits.sort((a, b) => a.pos - b.pos || b.end - a.end)) {
    if (merged.length && e.pos < merged[merged.length - 1].end) {
      st.skippedNested = (st.skippedNested || 0) + 1;
      continue;
    }
    merged.push(e);
  }
  // 从后往前改，位置才不会互相打架
  merged.sort((a, b) => b.pos - a.pos);
  let out = src;
  for (const e of merged) out = out.slice(0, e.pos) + e.text + out.slice(e.end);
  return out;
}

function alreadyT(node) {
  const p = node.parent;
  return p && ts.isCallExpression(p) && /(^|\.)t$/.test(p.expression.getText()) && p.arguments[0] === node;
}

// 单引号优先，串里有单引号就换双引号；换行/反斜杠一律转义，保证包完还是同一句话。
function quote(s) {
  const esc = s.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t');
  if (!esc.includes("'")) return "'" + esc.replace(/"/g, '\\"') + "'";
  if (!esc.includes('"')) return '"' + esc.replace(/'/g, "\\'") + '"';
  return "'" + esc.replace(/'/g, "\\'").replace(/"/g, '\\"') + "'";
}

// ★ 这条才是「没把代码改坏」的证据。把改写前后的文件都走一遍，只留下
//   **表达式自己的 token**（字符串/模板片段一律不算，因为 key 本来就要重写它们；
//   t(...) 这一层包装也不留下 't'、括号和参数表的逗号方括号）。
//   两边逐 token 相等 = 除了被包起来的那些串，一个字的代码都没动过。
//   语法能不能编译另有 node --check 兜着，这里防的是「表达式被吃掉半截」这种坏法。
const STRING_KINDS = new Set([
  ts.SyntaxKind.StringLiteral, ts.SyntaxKind.NoSubstitutionTemplateLiteral,
  ts.SyntaxKind.TemplateHead, ts.SyntaxKind.TemplateMiddle, ts.SyntaxKind.TemplateTail,
  ts.SyntaxKind.RegularExpressionLiteral,
]);

function canon(src, file) {
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
  const out = [];
  const isT = (n) => ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 't';
  const isToken = (n) => n.kind >= ts.SyntaxKind.FirstToken && n.kind <= ts.SyntaxKind.LastToken;
  // Identifier 在 TypeScript 的枚举里就落在 FirstToken..LastToken 之间，
  // 所以「是不是 token」不能只按区间判 —— 两处必须走同一个 emit，否则前后比对会假红。
  const emit = (n) => {
    if (n.kind === ts.SyntaxKind.Identifier || n.kind === ts.SyntaxKind.PrivateIdentifier) out.push('id:' + n.getText(sf));
    else out.push(ts.SyntaxKind[n.kind] + ':' + n.getText(sf));
  };
  const walk = (n) => {
    if (STRING_KINDS.has(n.kind)) return;
    if (isT(n)) {
      // 参数 0 是 key（丢掉），参数 1 是槽位数组（只留元素表达式，按源序）
      const args = n.arguments;
      if (args[1]) {
        if (ts.isArrayLiteralExpression(args[1])) args[1].elements.forEach(walk);
        else walk(args[1]);
      }
      return;
    }
    if (n.kind === ts.SyntaxKind.Identifier || n.kind === ts.SyntaxKind.PrivateIdentifier) {
      emit(n);
      return;
    }
    ts.forEachChild(n, (c) => {
      if (STRING_KINDS.has(c.kind)) return;
      if (isToken(c)) emit(c);
      else walk(c);
    });
  };
  ts.forEachChild(sf, walk);
  return out;
}

function collectKeys(src, file) {
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
  const keys = new Set();
  const walk = (n) => {
    if (ts.isCallExpression(n) && /(^|\.)t$/.test(n.expression.getText()) && n.arguments[0]) {
      const a = n.arguments[0];
      if (ts.isStringLiteral(a)) keys.add(a.text);
    }
    ts.forEachChild(n, walk);
  };
  ts.forEachChild(sf, walk);
  return keys;
}

const st = stats();

// ★★ 自检：这条不是走过场 —— 「包完语法树对得上」这句话如果永远为真，它就等于没判。
//    所以这里既钉「该包的包了、不该包的没包」，也**故意造一次吃代码的改法**，
//    要求 canon() 必须报红。它不红，这个门就是假的。
function selftest() {
  const cases = [
    ['const a = "网卡与路由";', "const a = t('网卡与路由');"],
    ['console.log("日志不该译");', 'console.log("日志不该译");'],
    ['document.querySelector("查 网卡");', 'document.querySelector("查 网卡");'],
    ['const s = `池子共 ${n} 个地址`;', "const s = t('池子共 {0} 个地址', [n]);"],
    ['const o = { backgroundColor: "红", 标签: "中文值" };', 'const o = { backgroundColor: "红", 标签: t(\'中文值\') };'],
    ['const e = "ASCII only";', 'const e = "ASCII only";'],
    ['const t2 = `第一段 ${a} 中段 ${b} 尾`;', "const t2 = t('第一段 {0} 中段 {1} 尾', [a, b]);"],
    ['const q = `pure ${x} ascii`;', 'const q = `pure ${x} ascii`;'],
    ['const w = `多行\n中文 ${y}`;', "const w = t('多行\\n中文 {0}', [y]);"],
  ];
  let fail = 0;
  for (const [src, want] of cases) {
    const s2 = stats();
    let got;
    try { got = rewrite(src, 'f.js', s2); } catch (e) { got = 'THREW ' + e.message; }
    if (got !== want) {
      fail++;
      console.log('✗ 用例不符\n   输入: ' + src + '\n   得到: ' + got + '\n   期望: ' + want);
    } else console.log('✓ ' + src);
    // 每条用例都顺便过一遍 canon：包住之后表达式一个 token 都不许少
    const k1 = canon(src, 'f.js'); const k2 = canon(got, 'f.js');
    if (k1.join(' ') !== k2.join(' ')) {
      fail++;
      console.log('✗ canon 不认这条：' + src + '\n   前: ' + k1.join(' ') + '\n   后: ' + k2.join(' '));
    }
  }
  // 值级判据：包完之后那句话的**值**必须和原来一模一样（引号转义最容易在这里露馅）
  const valueCases = [
    "f('带\\'引号 中文');",
    'g("有\\"双引号 中文");',
    'h("中文\\n带反斜杠");',
  ];
  const grab = (code, withT) => {
    let cap;
    const f = (x) => { cap = x; };
    const g = f;
    const h = f;
    // withT=false 时不定义 t：原始那一份里根本没有 t()
    const body = withT ? 'const t = (x) => x;' : '';
    new Function('f', 'g', 'h', body + code)(f, g, h);
    return cap;
  };
  for (const src of valueCases) {
    const s2 = stats();
    const got = rewrite(src, 'f.js', s2);
    const before = grab(src, false);
    const after = grab(got, true);
    if (before !== after) { fail++; console.log('✗ 值变了\n   原值: ' + JSON.stringify(before) + '\n   新值: ' + JSON.stringify(after)); }
    else console.log('✓ 值不变 ' + JSON.stringify(before));
  }

  // canon 必须能抓到「表达式被吃掉」：手工造一个把 `${n}` 弄丢的改法
  const src = 'const s = `池子共 ${n} 个地址`;';
  const broken = "const s = t('池子共 个地址');";
  const cb = canon(src, 'f.js'); const ca = canon(broken, 'f.js');
  const caught = cb.length !== ca.length || cb.some((x, i) => x !== ca[i]);
  if (!caught) { fail++; console.log('✗ canon() 没抓到吃掉的表达式 —— 这道门是假的'); }
  else console.log('✓ canon() 能抓到表达式被吃掉（红一次才算数）');
  console.log(fail ? `✗ 自检 ${fail} 条不过` : '✓ 自检全过');
  process.exit(fail ? 1 : 0);
}
if (process.argv.includes('--selftest')) selftest();

const allKeys = new Set();
let changed = 0;
for (const rel of TARGETS) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) continue;
  const before = fs.readFileSync(abs, 'utf8');
  const after = rewrite(before, rel, st);
  if (after === before) continue;
  const cb = canon(before, rel);
  const ca = canon(after, rel);
  let bad = -1;
  for (let i = 0; i < Math.max(cb.length, ca.length); i++) {
    if (cb[i] !== ca[i]) { bad = i; break; }
  }
  if (bad >= 0) {
    console.error(`✗ ${rel}：第 ${bad} 个 token 起对不上，说明有表达式被吃掉了`);
    console.error('   前：' + cb.slice(Math.max(0, bad - 6), bad + 6).join(' '));
    console.error('   后：' + ca.slice(Math.max(0, bad - 6), bad + 6).join(' '));
    process.exit(1);
  }
  collectKeys(after, rel).forEach((k) => allKeys.add(k));
  changed++;
  if (WRITE) fs.writeFileSync(abs, after);
}

const dictDir = path.join(ROOT, 'src', 'locales');
if (WRITE && !fs.existsSync(dictDir)) fs.mkdirSync(dictDir, { recursive: true });
const keyList = [...allKeys].sort();
fs.writeFileSync(path.join(ROOT, 'scripts', '.i18n-keys.json'), JSON.stringify(keyList, null, 1));

console.log(JSON.stringify({
  mode: WRITE ? 'write' : 'dry-run',
  filesChanged: changed,
  keys: keyList.length,
  ...st,
}, null, 1));
