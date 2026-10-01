// 把要译的键切成分片，交给翻译并行做；翻译写 JSON 分片，最后由 i18n-merge.cjs 合成本品词典。
//
//   node scripts/i18n-chunks.cjs            首次切分（默认每片 300 键）
//   node scripts/i18n-chunks.cjs --size=120
//   node scripts/i18n-chunks.cjs --delta    只把「还没进过箱子」的键补成新箱子
//
// ★ 为什么要分片、还要按**字符数**排序后再分：词典的活儿按条数看差不多，按字数看差十倍 ——
//   一句「已发出 {0} 个地址」和一段 1200 字的带 HTML 说明，成本根本不是一个量级。
//   所以装箱按字符数做均衡（贪心：每次都往当前最轻的箱子里放最大的那块），
//   不然会出现一片 300 条全是短语、另一片 40 条却是一段长文，两边的活儿没法排。
//
// ★ 装箱口径只有一把尺子：literalKeys（在 i18n-lib.cjs），和 audit / merge 用的是同一支。
//   原先这里自己 AST 走一遍 app.js/i18n.js，于是 index.html 上标了 data-i18n 的那些句子
//   **永远进不了箱子** —— 界面上它们是要译的，词典里却根本没有这一条，
//   而 merge 只数得到自己看得见的那一半，照样报「全部合成完毕」。
//
// ★ 为什么要 --delta，而且默认模式在片已开始交付后就拒绝重切：
//   「片号稳定吗？—— 不稳定」。整箱重排会把已交付的 part-NN 全部作废（同一个键换到
//   另一箱，自检器按箱号数并集，于是那一箱报「缺 291 条」），而产物词典看起来还是齐的。
//   补译只许往**新箱子**里加：chunk-10、chunk-11…，老箱内容一个字节都不动。
//   覆盖率最终仍由 merge / audit 说了算，这一支只负责「别把做过的活儿弄丢」。

const fs = require('fs');
const path = require('path');
const { literalKeys } = require('./i18n-lib.cjs');

const ROOT = path.resolve(__dirname, '..');
const SRC = ['src/app.js', 'src/i18n.js'];
const HTML = 'src/index.html';
const WORK = path.join(ROOT, '.i18n-work');
const LANG_DIRS = ['en', 'ja', 'ko', 'ru'];
const argv = process.argv.slice(2);
const DELTA = argv.includes('--delta');
const RETIRE = argv.includes('--retire');
const m = /--size=(\d+)/.exec(argv.join(' '));
const SIZE = m ? Number(m[1]) : 300;

const all = [...new Set(literalKeys(ROOT, SRC, HTML))];
const allSet = new Set(all);
const chunkPath = (i) => path.join(WORK, `chunk-${String(i).padStart(2, '0')}.json`);
const existingNums = fs.existsSync(WORK)
  ? fs.readdirSync(WORK).map((f) => /^chunk-(\d+)\.json$/.exec(f)).filter(Boolean).map((x) => Number(x[1])).sort((a, b) => a - b)
  : [];

const boxed = new Set();
for (const i of existingNums) {
  for (const k of JSON.parse(fs.readFileSync(chunkPath(i), 'utf8'))) boxed.add(k);
}

// 某一箱是否已经有语言收过分片 —— 收过就不许再动这一箱的内容。
const delivered = (num) => {
  const re = new RegExp(`^part-${num}-?[\\w.]*\\.json$`);
  return LANG_DIRS.some((l) => {
    const dir = path.join(WORK, l);
    return fs.existsSync(dir) && fs.readdirSync(dir).some((f) => re.test(f));
  });
};

if (!DELTA && !RETIRE) {
  if (existingNums.length && (all.length !== boxed.size || [...boxed].some((k) => !allSet.has(k)))) {
    const missing = all.filter((k) => !boxed.has(k));
    const gone = [...boxed].filter((k) => !allSet.has(k));
    console.error(`✗ 箱子里已经有 ${boxed.size} 条，源码现在要 ${all.length} 条` +
      `（新 ${missing.length} · 源码里已没有 ${gone.length}）。`);
    console.error('  重切会把已交付的分片全部作废。补译请跑：node scripts/i18n-chunks.cjs --delta');
    for (const k of missing.slice(0, 5)) console.error('  新 ' + JSON.stringify(k).slice(0, 100));
    process.exit(2);
  }
  const busy = existingNums.filter(delivered);
  if (busy.length) {
    console.error(`✗ ${busy.map((i) => String(i).padStart(2, '0')).join('、')} 箱已有分片交付，` +
      '默认模式会重排箱内容、把它们全部作废。这一支只在第一次切分时用；之后用 --delta。');
    process.exit(2);
  }
}

// ★ --retire：中文原文被改写或删掉之后，把那一行从箱单和已交付的分片里一起摘掉。
//   为什么要有这一支：--delta 只管"长出来"，不管"缩回去"。上一轮把 LANGS 的语言名
//   改成母语原文（简体中文／日本語 不再走 t()）之后，箱单里还留着这两条，
//   分片自检器就一辈子报「这一箱缺 1 条」—— 而那条红是**假的**，源码里根本没这东西了。
//   手删分片能过今天这一关，但下一次改写文案的人不会知道要删哪儿，所以这一步得能跑。
if (RETIRE) {
  const gone = [...boxed].filter((k) => !allSet.has(k));
  if (!gone.length) { console.log(`✓ 箱单和源码对得上（${boxed.size} 条），没有要退的`); process.exit(0); }
  console.log(`要退 ${gone.length} 条（源码里已经没人用这些中文当 key 了）：`);
  for (const k of gone.slice(0, 10)) console.log('  · ' + JSON.stringify(k).slice(0, 90));
  if (gone.length > 10) console.log(`  … 其余 ${gone.length - 10} 条`);
  const goneSet = new Set(gone);
  let chunksTouched = 0; let partsTouched = 0;
  for (const i of existingNums) {
    const p = chunkPath(i);
    const ks = JSON.parse(fs.readFileSync(p, 'utf8'));
    const keep = ks.filter((k) => allSet.has(k));
    if (keep.length === ks.length) continue;
    fs.writeFileSync(p, JSON.stringify(keep, null, 1) + '\n');
    chunksTouched++;
  }
  for (const lang of LANG_DIRS) {
    const dir = path.join(WORK, lang);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir).filter((x) => /^part-[\w.-]+\.json$/.test(x))) {
      const fp = path.join(dir, f);
      const o = JSON.parse(fs.readFileSync(fp, 'utf8'));
      let n = 0;
      for (const k of Object.keys(o)) if (goneSet.has(k)) { delete o[k]; n++; }
      if (n) { fs.writeFileSync(fp, JSON.stringify(o, null, 1) + '\n'); partsTouched++; }
    }
  }
  console.log(`✓ 退了 ${gone.length} 条：箱单 ${chunksTouched} 个 · 分片 ${partsTouched} 个`);
  process.exit(0);
}

const toBox = DELTA ? all.filter((k) => !boxed.has(k)) : all;if (!toBox.length) {
  console.log(`✓ 源码 ${all.length} 条键全部已在箱内（${existingNums.length} 箱），没有要补译的`);
  process.exit(0);
}

// 贪心装箱：大的先放，每次放进当前字符数最少的箱子（箱子数由条数决定：ceil(n/SIZE)）。
const sorted = [...toBox].sort((a, b) => b.length - a.length);
const nBox = Math.max(1, Math.ceil(sorted.length / SIZE));
const boxes = Array.from({ length: nBox }, () => ({ keys: [], chars: 0 }));
for (const k of sorted) {
  let t = 0;
  for (let i = 1; i < nBox; i++) if (boxes[i].chars < boxes[t].chars) t = i;
  boxes[t].keys.push(k);
  boxes[t].chars += k.length;
}

fs.mkdirSync(WORK, { recursive: true });
const base = existingNums.length ? Math.max(...existingNums) + 1 : 0;
const nums = [];
for (let i = 0; i < nBox; i++) {
  boxes[i].keys.sort();
  fs.writeFileSync(chunkPath(base + i), JSON.stringify(boxes[i].keys, null, 1) + '\n');
  nums.push(String(base + i).padStart(2, '0'));
}
const chars = boxes.map((b) => b.chars);
console.log(JSON.stringify({
  mode: DELTA ? 'delta' : 'full',
  keys: all.length, boxed: boxed.size, newlyBoxed: sorted.length,
  boxes: nums, perBoxKeys: boxes.map((b) => b.keys.length),
  chars: sorted.reduce((s, k) => s + k.length, 0),
  perBoxCharsMin: Math.min(...chars), perBoxCharsMax: Math.max(...chars),
  work: path.relative(ROOT, WORK),
}));
