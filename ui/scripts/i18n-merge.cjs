// 把翻译分片合成本品词典，并且**当场数一遍缺哪些**。
//
//   node scripts/i18n-merge.cjs en
//   node scripts/i18n-merge.cjs en ja ko ru
//
// 输入：.i18n-work/<lang>/part-*.json —— 每个是 { "中文原文": "译文" }
// 输出：src/locales/<lang>.js —— 浏览器里直接 <script> 加载的那一份
//
// ★ 为什么合并这一步必须自己数缺失：翻译是分片并行做的，
//   「八个 agent 都报告完成了」和「界面上一句中文都不剩」之间隔着的正是这里。
//   任何一个分片写坏、任何一个 key 没进 JSON，产物词典就少一句 ——
//   少了的那句会**安静地退回中文**，界面上看不出所以然。
//   所以 merge 不以「agent 说做完了」为准，以「源码里的 key 集合 ⊆ 词典 key 集合」为准，
//   不满足就退出码 1，并把缺的前若干条列出来。
//
// ★ 合并时顺带跑 i18n-audit 的同一套判据（槽位、标签）：分片里就拦下，
//   别让一句吃了 {0} 的译文进到产物里 —— 那种句子在界面上会打出裸的 "{0}"。

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SRC = ['src/app.js', 'src/i18n.js'];
const HTML = 'src/index.html';
const WORK = path.join(ROOT, '.i18n-work');
const OUT = path.join(ROOT, 'src', 'locales');
// 与 audit / chunks 同一把尺子（键的口径 + 槽位 + 标签 + 「还留着中文」），实现只有一份：i18n-lib.cjs
const { LANGS, entryIssues, untranslatedBits, literalKeys } = require('./i18n-lib.cjs');

function sourceKeys() {
  // ★ 以前这里自己 AST 走一遍 app.js/i18n.js，于是 index.html 上标了 data-i18n 的句子
  //   在 merge 这一头根本不存在：箱子（chunks）按同一把尺子把它们算了，merge 却说「没这条 key」，
  //   翻译照抄回来的那一条被当成死条目扔掉 —— 界面上就永远退回中文。
  return [...new Set(literalKeys(ROOT, SRC, HTML))];
}

const want = [...sourceKeys()];
const wantSet = new Set(want);
const langs = process.argv.slice(2).filter((a) => !a.startsWith('-'));
if (!langs.length) { console.error('用法：node scripts/i18n-merge.cjs <lang…>'); process.exit(2); }
// 语言名拼错时必须当场停：untranslatedBits 认不出的语言按最严的那把尺走，
// 于是 ja/ko 的正确译文会被整片报成没译，而「分片问题 2900 条」看起来像翻译的锅，
// 不是这一支脚本的锅。宁可在这里说一句人话。
for (const l of langs) {
  if (!LANGS.includes(l)) { console.error(`✗ 不认的语言「${l}」，四本词典是 ${LANGS.join(' / ')}`); process.exit(2); }
}

let failTotal = 0;
for (const lang of langs) {
  const dir = path.join(WORK, lang);
  const dict = new Map();
  const from = [];
  let fail = 0;
  if (fs.existsSync(dir)) {
    const all = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
    // ★ 只吃 part-*.json。翻译过程中有人在同一个目录里放过中间产物（一份数组、
    //   一份草稿），拿 *.json 一扫就把它们当成词典读进来：数组的 key 是 0,1,2…，
    //   于是几百条「源码里没有这个 key」糊满屏幕，真正缺的那几句反倒看不见。
    //   剩下的那些 .json 不读，但必须报出来 —— 静静忽略等于把现场扫干净。
    const stray = all.filter((f) => !/^part-[\w.-]+\.json$/.test(f)).sort();
    for (const f of stray) console.log(`! ${lang}/${f}：不是 part-*.json，这一支不读（要并进词典就先改名成 part-*.json）`);
    for (const f of all.filter((x) => /^part-[\w.-]+\.json$/.test(x)).sort()) {
      const raw = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
      if (Array.isArray(raw) || typeof raw !== 'object' || raw === null) {
        fail++; console.log(`✗ ${lang}/${f}：不是 { 中文原文: 译文 } 这种对象，读不了`); continue;
      }
      const obj = raw;
      from.push(f + ' ' + Object.keys(obj).length);
      for (const [k, v] of Object.entries(obj)) {
        if (!wantSet.has(k)) { fail++; console.log(`✗ ${lang}/${f}: 源码里没有这个 key（错拼或原文已改）\n   ${JSON.stringify(k).slice(0, 120)}`); continue; }
        // ★ 「值是空的」这一条交给尺子（entryIssues），不在这里再判一次 !v.trim()：
        //   app.js 里有拿全角空格当分隔符的 t('　')，那种条目**正解就是照抄**，
        //   而 trim 之后是空字符串 —— 在这儿判空等于把照抄判成没译，
        //   翻译为了过关就会去塞一个零宽空格，界面上那道分隔就悄悄换了字符。
        if (typeof v !== 'string') { fail++; console.log(`✗ ${lang}/${f}: 值不是字符串\n   ${JSON.stringify(k).slice(0, 80)}`); continue; }
        for (const m of entryIssues(k, v)) { fail++; console.log(`✗ ${lang}/${f}: ${m}\n   key: ${JSON.stringify(k).slice(0, 90)}\n   值:  ${JSON.stringify(v).slice(0, 90)}`); }
        // 「还留着中文」按语言判：日文界面写汉字是正字，整段抄过来才是没译。
        const left = untranslatedBits(lang, k, v);
        for (const m of left) { fail++; console.log(`✗ ${lang}/${f}: ${m}\n   key: ${JSON.stringify(k).slice(0, 90)}\n   值:  ${JSON.stringify(v).slice(0, 90)}`); }
        if (left.length) continue;
        if (dict.has(k) && dict.get(k) !== v) console.log(`! ${lang}: ${JSON.stringify(k).slice(0, 60)} 在两个分片里译文不同，取后一个`);
        dict.set(k, v);
      }
    }
  } else {
    console.log(`! ${lang}：没有 ${path.relative(ROOT, dir)} 目录`);
  }

  const missing = want.filter((k) => !dict.has(k));
  console.log(`\n${lang}：分片 ${from.length} 个 · 收 ${dict.size}/${want.length} · 缺 ${missing.length} · 分片问题 ${fail}`);
  for (const k of missing.slice(0, 20)) console.log('   缺 ' + JSON.stringify(k).slice(0, 110));
  if (missing.length > 20) console.log(`   … 其余 ${missing.length - 20} 条`);

  // 词典按 key 排序写出：译文顺序不该进 diff，重新装箱后同一句仍落在同一行。
  const body = [...dict.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))
    .map(([k, v]) => `    ${JSON.stringify(k)}: ${JSON.stringify(v)}`).join(',\n');
  fs.mkdirSync(OUT, { recursive: true });
  const dest = path.join(OUT, lang + '.js');
  // ★ 不许把已经做完的一本**改小**。分片是并行、分批交付的：只要有一次在片没收齐时
  //   跑了 merge，产物就会从 2922 条掉回几百条，而退出码只说「缺 N 条」——
  //   界面上那句「英文已经齐了」的印象就是这么被悄悄换掉的。掉条数就写到 .partial 里去，
  //   本品的这一份原样留着，改哪条都看得见。
  let shrink = 0;
  if (fs.existsSync(dest)) {
    const have = (fs.readFileSync(dest, 'utf8').match(/^\s{4}"/gm) || []).length;
    if (dict.size < have) shrink = have - dict.size;
  }
  const header = `// ${lang} 词典。由 scripts/i18n-merge.cjs 从 .i18n-work/${lang}/ 合成，别手改这一份 ——
// 手改会在下一次 merge 时被整片覆盖；要改文案去改分片，或者改源码里的中文原文（那等于换 key）。
//
// 中文原文就是 key，没收录的条目自动回落中文（i18n.js 里的 t()）。
// 覆盖率由 scripts/i18n-audit.cjs 数，不靠这里写注释保证。
I18N.dicts.${lang} = {
`;
  const text = header + body + '\n};\n';
  if (shrink) {
    fs.writeFileSync(dest + '.partial', text);
    console.log(`✗ ${lang}：这次只收 ${dict.size} 条，比 src/locales/${lang}.js 现有的少 ${shrink} 条 ——`);
    console.log(`  不覆盖正在用的那一份，半成品写到 ${path.relative(ROOT, dest)}.partial。分片收齐了再重跑这一句。`);
    fail++;
  } else {
    fs.writeFileSync(dest, text);
    console.log(`→ 写出 src/locales/${lang}.js（${dict.size} 条）`);
  }
  if (missing.length) { fail++; console.log(`✗ ${lang}：还缺 ${missing.length} 条，没齐`); }
  failTotal += fail + missing.length;
}
console.log(failTotal ? `\n✗ 合计 ${failTotal} 条问题` : '\n✓ 全部合成完毕，无缺条');
process.exit(failTotal ? 1 : 0);
