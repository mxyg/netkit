// 自检器：把一箱的分片**合起来**对着那一箱的输入数一遍。
//
//   node scripts/i18n-check-part.cjs <lang> <箱号>
//
// 箱号 00 对应输入 .i18n-work/chunk-00.json，输出可以是
// part-00.json，也可以是 part-00-1.json + part-00-2.json（一箱 291 句，
// 一个人/一个 agent 分成几笔写更稳：一次 Write 六十万 token 的巨型 JSON
// 是写不完的，历史上就这么死过一片）。判据只看并集，怎么切都行。
//
// 三件事，一件都不许靠自觉：
//   1) 输入片里的每一条 key 都必须出现（漏一条 = 界面上那一句退回中文，而且没人看得见）
//   2) 不许多出输入里没有的 key（错拼的 key 永远不会被用上，是死条目）
//   3) 每条过一遍 i18n-lib 的尺子：槽位、HTML 骨架，外加按语言判的「还留着中文」
//
// ★ 为什么把它做成单独一支命令：分片是并行的，合并器只在最后跑一次。
//   没有这一支的话，十条箱里有一条漏了 30 句，要等到 merge 才报出来，
//   而那时候已经没人记得是哪一片、哪一批做的了。

const fs = require('fs');
const path = require('path');
const { LANGS, entryIssues, untranslatedBits } = require('./i18n-lib.cjs');

const ROOT = path.resolve(__dirname, '..');
const lang = process.argv[2];
const num = String(process.argv[3] || '').padStart(2, '0');
if (!lang || !num) {
  console.error('用法：node scripts/i18n-check-part.cjs <lang> <箱号>');
  process.exit(2);
}
// 语言名拼错 = 用错尺子（不认的一律按最严的判，ja/ko 的正确译文会被整片报红），
// 所以这一句必须挡在前面，不能让自检器给出「你抄了中文」这种假的指控。
if (!LANGS.includes(lang)) {
  console.error(`✗ 不认的语言「${lang}」，四本词典是 ${LANGS.join(' / ')}`);
  process.exit(2);
}
const src = path.join(ROOT, '.i18n-work', `chunk-${num}.json`);
const dir = path.join(ROOT, '.i18n-work', lang);
if (!fs.existsSync(src)) { console.error(`✗ 输入片不存在：${src}`); process.exit(1); }
// 这一箱的分片：part-00.json / part-00-1.json / part-00a.json 都算，别的不算
const parts = fs.existsSync(dir)
  ? fs.readdirSync(dir).filter((f) => new RegExp(`^part-${num}[\\w.-]*\\.json$`).test(f)).sort()
  : [];
if (!parts.length) { console.error(`✗ ${lang}：${path.relative(ROOT, dir)}/ 里没有 part-${num}*.json`); process.exit(1); }

const want = JSON.parse(fs.readFileSync(src, 'utf8'));
const got = {};
let fail = 0;
for (const f of parts) {
  const obj = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  if (Array.isArray(obj) || typeof obj !== 'object' || obj === null) {
    fail++; console.log(`✗ ${f}：不是 { 中文原文: 译文 } 这种对象`); continue;
  }
  for (const [k, v] of Object.entries(obj)) {
    if (k in got && got[k] !== v) { fail++; console.log(`✗ ${f}: ${JSON.stringify(k).slice(0, 60)} 在这一箱的两片里都出现且译文不同`); }
    got[k] = v;
  }
}
const wantSet = new Set(want);

const missing = want.filter((k) => !(k in got));
const extra = Object.keys(got).filter((k) => !wantSet.has(k));
if (missing.length) {
  // 逐条累加，不是「这一类算一处」：报告里写「1 处问题」而列出 30 条漏句，
  // 读的人会以为剩下的 29 条是别的东西。
  fail += missing.length;
  console.log(`✗ 漏了 ${missing.length} 条：`);
  for (const k of missing.slice(0, 10)) console.log('   · ' + JSON.stringify(k).slice(0, 100));
  if (missing.length > 10) console.log(`   … 其余 ${missing.length - 10} 条`);
}
if (extra.length) {
  fail += extra.length;
  console.log(`✗ 多出 ${extra.length} 条输入里没有的 key（错拼的话它永远不会被用上）：`);
  for (const k of extra.slice(0, 10)) console.log('   · ' + JSON.stringify(k).slice(0, 100));
}
// 「还留着中文」这把尺子分语言：en/ru 见一个中日韩字就红，ja 认整段抄（≥4 个连排汉字），
// ko 只放宽到两个字 —— 日文本来就写汉字，韩文不写。细则与理由在 i18n-lib.cjs。
for (const [k, v] of Object.entries(got)) {
  for (const m of [...entryIssues(k, v), ...untranslatedBits(lang, k, v)]) {
    fail++;
    console.log(`✗ ${JSON.stringify(k).slice(0, 70)} —— ${m}`);
  }
}
const tag = `${lang} 第 ${num} 箱（${parts.length} 片）`;
console.log(fail ? `✗ ${tag}：${fail} 处问题` : `✓ ${tag}：${Object.keys(got).length} 条全对`);
process.exit(fail ? 1 : 0);
