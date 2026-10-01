// 页面 ↔ 工具的对应关系，从源码里量出来，不许手抄第二份清单。
//
// ★ 为什么要有这个文件：界面要能回答「这个功能在哪」「这一页到底问了哪几件事」，
//   而这两问的答案本来就写在 app.js 里（哪个 render 调了哪个 call）。
//   再手抄一份映射表就是第四副本 —— 历史上「界面说没做、后端其实做了」就是这么来的。
//   所以这里用 AST 把源码里的事实抽出来生成 page-index.js，并且用 --check 钉住它不漂。
//
// 跑法：
//   node scripts/page-index.cjs            打印当前量到的结果（只读）
//   node scripts/page-index.cjs --write    生成 src/page-index.js
//   node scripts/page-index.cjs --check    比对盘上的 src/page-index.js，不一致退出 1
//
// ★ 只量两件事，都是从源码结构来的，不涉及词典：
//   tools —— 这一页（含它调用的所有 *Card 函数，递归）里出现过的工具名字符串
//   refs  —— 这一页的正文里点名了哪几页（「去『路径与质量』那一页」这种），
//            页名取 PAGES 里那一行的 t('…') 字面量，所以改页名等于自动跟着改
const fs = require('fs');
const path = require('path');
const ts = require('typescript');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src', 'app.js');
const OUT = path.join(ROOT, 'src', 'page-index.js');

const src = fs.readFileSync(SRC, 'utf8');
const sf = ts.createSourceFile(SRC, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);

// 工具名的形状：小写段 + 至少一个点，段内可带连字符（net.tcp.probe / media.rtsp.probe）。
const TOOLISH = /^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$/;

// ★ 顶层常量表（那 ~100 张判定码表 SCAN_CODE / MTU_CODE / …）也在卡片函数之外，
//   而「去『ping 与端口』那一页」这类跨页点名，十有八九写在码表的建议语里。
//   只走函数会把这一大片全量丢，所以码表按「谁引用了它」一起并进闭包。
const units = new Map(); // name -> {strings:Set, refs:Set, isFn:bool}

function addStrings(name, node) {
  const rec = { strings: new Set(), refs: new Set(), isFn: ts.isFunctionDeclaration(node) };
  units.set(name, rec);
  const see = (n) => {
    if (ts.isStringLiteral(n)) rec.strings.add(n.text);
    else if (ts.isNoSubstitutionTemplateLiteral(n)) rec.strings.add(n.text);
    else if (ts.isIdentifier(n)) rec.refs.add(n.text);
    n.forEachChild(see);
  };
  node.forEachChild(see);
}

sf.forEachChild((node) => {
  if (ts.isFunctionDeclaration(node) && node.name) { addStrings(node.name.text, node); return; }
  if (ts.isVariableStatement(node)) {
    for (const d of node.declarationList.declarations) {
      if (ts.isIdentifier(d.name) && d.initializer) addStrings(d.name.text, d.initializer);
    }
  }
});

// PAGES 数组：id -> {render, 中文页名, 组}
const pages = [];
(function findPages(node) {
  if (ts.isVariableDeclaration(node) && node.name.getText() === 'PAGES' && node.initializer &&
      ts.isArrayLiteralExpression(node.initializer)) {
    for (const item of node.initializer.elements) {
      if (!ts.isObjectLiteralExpression(item)) continue;
      const rec = { id: '', render: '', name: '', g: '' };
      for (const prop of item.properties) {
        const k = prop.name.getText();
        const init = prop.initializer;
        if (k === 'id' || k === 'g') rec[k] = init.getText().replace(/^'|'$/g, '');
        if (k === 'render') rec.render = init.getText();
        if (k === 'name') {
          // name: t('网卡与路由') —— 取那个字面量，它就是运行时的 key
          const m = init.getText().match(/^t\(\s*'([^']*)'\s*\)$/);
          if (m) rec.name = m[1];
          else if (ts.isCallExpression(init) && init.arguments.length &&
                   ts.isStringLiteral(init.arguments[0])) rec.name = init.arguments[0].text;
        }
      }
      pages.push(rec);
    }
    return;
  }
  node.forEachChild(findPages);
})(sf);

if (!pages.length) { console.error('PAGES 没量到，生成器先于源码失效了'); process.exit(2); }
for (const p of pages) {
  if (!units.has(p.render)) { console.error(`${p.id} 的 render（${p.render}）不是顶层函数`); process.exit(2); }
  if (!p.name) { console.error(`${p.id} 的页名没量到`); process.exit(2); }
}

// ★ 导航壳层那几个名字不许并进任何一页的闭包：show / PAGES 一进来就等于
//   「每一页都引用了全部页」，94 个工具会被摊到每一页头上，这张表当场变成噪音。
const STOP = new Set(['PAGES', 'GROUPS', 'show', 'renderNav', 'PAGE_INDEX']);

// 一引用就到底：render 里出现的本文件名字（函数、卡片、码表）全部并进来。
function closure(render) {
  const seen = new Set([render]);
  const q = [render];
  while (q.length) {
    for (const ref of units.get(q.shift()).refs) {
      if (!STOP.has(ref) && units.has(ref) && !seen.has(ref)) { seen.add(ref); q.push(ref); }
    }
  }
  seen.delete('show');
  return seen;
}

const byName = new Map(pages.map((p) => [p.name, p.id]));
// 卡片标题：模板里的 <h2>…</h2>。搜索要能落到「那一张卡」，而不只是落到那一页 ——
// 一页五张卡，跳到页首还得自己找，等于没跳到。
const H2 = /<h2>([^<]{2,48}?)\s*(?:<span|<\/h2>)/g;
const index = {};
for (const p of pages) {
  const tools = new Set();
  const refs = new Set();
  const strings = new Set();
  const cards = [];
  for (const unit of closure(p.render)) {
    for (const s of units.get(unit).strings) {
      strings.add(s);
      // 工具名只算**函数里**出现的那些：码表是一整块文字，万一写了个像工具名的词，
      // 记进「这一页调了它」就是凭空给界面加能力。
      if (units.get(unit).isFn && TOOLISH.test(s)) tools.add(s);
    }
    if (!units.get(unit).isFn) continue;
    const own = new Set();
    for (const s of units.get(unit).strings) if (TOOLISH.test(s)) own.add(s);
    for (const s of units.get(unit).strings) {
      H2.lastIndex = 0;
      let m;
      while ((m = H2.exec(s))) {
        const title = m[1].trim();
        // 模板里带槽位的标题（<h2>{0}</h2> 这种）不是稳定名字，跳过 —— 宁缺勿错
        if (!title || title.includes('{')) continue;
        cards.push({ t: title, tools: [...own].sort() });
      }
    }
  }
  // 引用了哪几页：正文（含码表的建议语）里出现别页的中文页名
  for (const [name, id] of byName) {
    if (id === p.id) continue;
    for (const s of strings) if (s.includes(name)) { refs.add(id); break; }
  }
  const seenCard = new Set();
  index[p.id] = {
    tools: [...tools].sort(),
    refs: [...refs].sort(),
    cards: cards.filter((c) => !seenCard.has(c.t) && seenCard.add(c.t)),
  };
}

const banner = `// ★★ 这个文件是**生成的**，别手改 —— 改 app.js，然后跑
//   node scripts/page-index.cjs --write
//   它量的是「哪一页调过哪些工具」「哪一页的正文点名了别页」这两件源码里本来就有的事实。
//   界面拿它做搜索、总览页的能力清单、右侧「这一页用到的工具」；
//   --check 那道闸保证它和 app.js 不漂。
`;
const file = banner + 'const PAGE_INDEX = ' + JSON.stringify(index, null, 1) + ';\n';

const mode = process.argv[2] || '';
if (mode === '--write') {
  fs.writeFileSync(OUT, file);
  console.log(`✓ 写了 ${path.relative(ROOT, OUT)}（${pages.length} 页）`);
} else if (mode === '--check') {
  const cur = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : '';
  if (cur !== file) {
    console.error('✗ src/page-index.js 与 app.js 对不上了 —— 跑 node scripts/page-index.cjs --write');
    process.exit(1);
  }
  console.log('✓ page-index.js 与 app.js 一致');
} else {
  for (const p of pages) {
    console.log(`${p.id.padEnd(12)} ${String(index[p.id].tools.length).padStart(2)} 工具 `
      + `${String(index[p.id].cards.length).padStart(2)} 卡  → ${index[p.id].refs.join(', ') || '—'}`);
    console.log(`  ${index[p.id].cards.map((c) => c.t).join(' / ')}`);
  }
}
