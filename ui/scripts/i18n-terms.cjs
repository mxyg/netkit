// 术语统一：把分片里那些「同一个词两种译法」的少数派，按基准改回去。
//
//   node scripts/i18n-terms.cjs            改（就地写回分片，打印每处）
//   node scripts/i18n-terms.cjs --check    只数不改，有少数派就退出码 1
//
// ★ 为什么要有这一支，而不是把基准写在 i18n-glossary.md 里就完事：
//   词典是几十个 agent 分箱并行译的，每个 agent 开工时拿到的是**我自己转述的基准**，
//   转述错过好几次（把 出口网卡 说成 送信側アダプタ、把 对端 说成 반대편），
//   而它对不上的那一次不会有任何人看见 —— 分片各自都自检通过，只有整页读下来才发现
//   同一格在两处叫两个名字。所以基准最终要以「能跑的替换表」存在，而不是以备忘存在。
//
// ★ 表里的每一项都是在**已交付分片里量出来的多数派**（不是我觉得哪个好听）：
//   计数见 git 之前的那一轮，例如 ko 的 상대=146 对 반대편=4、ja の ネイバーテーブル=24 对 隣接テーブル=6。
//   改之前要确认多数派自己站得住（ja 的「老化」是网络设备文档里的写法，不是抄中文），
//   少数派如果是**因为语境不同**（比如 prose 里的「向こう側」），就不该进这张表。

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// avoidHanziMerge: 替换后会和前面的汉字连成四个以上汉字时不改 —— ja 的判据按连排汉字数算，
// 「自然エージング」直接换成「自然老化」会被自己的尺子判成照抄中文。
const RULES = {
  ja: [
    // 老化 这一条是**反过来的**：原来按「多数派」定的是汉字「老化」，但整本词典读下来，
    // 同一类词全用片假名借词（ネイバーテーブル、マスキング、プロミスキャスモード、デュアルスタック、アプライアンス），
    // 只有这一个概念写成汉字 —— 而汉字写法跟中文原文一模一样，正是这套 i18n 尺子存在的意义所在
    // （审校的人看见「老化」两秒内判不出是日文还是漏译）。
    // ★ 外部佐证拿不到：这一轮 WebSearch/WebFetch 返回的全是中文文档，没有日文样语可数，
    //   所以这一条的依据是**库内的语域一致性**，不是「日文圈就这么写」这种我验证不了的断言。
    { from: '老化', to: 'エージング' },
    { from: 'マスク化', to: 'マスキング' },
    { from: '隣接テーブル', to: 'ネイバーテーブル' },
    { from: 'モニタリングモード', to: 'プロミスキャスモード' },
    { from: '出口のアダプタ', to: '送信側アダプタ' },
    { from: '出口アダプタ', to: '送信側アダプタ' },
  ],
  ko: [
    { from: '반대편', to: '상대' },
    { from: '인접 테이블', to: '인접 표' },
    { from: '출구 네트워크 어댑터', to: '출구 어댑터' },
    { from: '익명화', to: '마스킹' },
    // 老化 在 ko 里有三个名字（열화 2 / 수명 만료 1 / 노후화 6）—— 同一格在两处叫两个名字，
    // 读的人以为是两件事。열화 在韩文里更偏「画质劣化」，这里说的是表项到期，跟 노후화 不是一回事。
    { from: '열화', to: '노후화' },
    { from: '수명 만료', to: '노후화' },
  ],
  ru: [
    { from: 'таблица смежников', to: 'таблица соседей' },
    { from: 'Таблица смежников', to: 'Таблица соседей' },
    { from: 'Выходящий адаптер', to: 'Выходной адаптер' },
    { from: 'выходящий адаптер', to: 'выходной адаптер' },
    { from: 'анонимизация', to: 'обезличивание' },
    // 低帧率 = 频率，不是带宽。整箱量出来 1 处错写成 битрейт（码率），1 处对（частота кадров）；
    // 整条替换而不是换单词，因为 码率上限→Потолок битрейта 这类是真的在说码率，不能一起改。
    { from: 'поток с низким битрейтом по событию', to: 'событийный поток с низкой частотой кадров' },
  ],
  en: [
    { from: 'neighbour', to: 'neighbor' },
    { from: 'Neighbour', to: 'Neighbor' },
  ],
};

const CHECK = process.argv.includes('--check');
let hits = 0;
for (const [lang, rules] of Object.entries(RULES)) {
  const dir = path.join(ROOT, '.i18n-work', lang);
  if (!fs.existsSync(dir)) continue;
  for (const f of fs.readdirSync(dir).filter((x) => /^part-[\w.-]+\.json$/.test(x)).sort()) {
    const p = path.join(dir, f);
    const obj = JSON.parse(fs.readFileSync(p, 'utf8'));
    let n = 0;
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v !== 'string') continue;
      let w = v;
      for (const r of rules) {
        const re = r.avoidHanziMerge
          // 前面是汉字就不换：ja 的判据按连排汉字数算，「自然エージング」换成「自然老化」
          // 会被自己的尺子判成照抄中文（这一条是量出来的，不是假设）。
          ? new RegExp('(?<![\\u4e00-\\u9fff])' + r.from, 'g')
          : new RegExp(r.from, 'g');
        const next = w.replace(re, r.to);
        if (next !== w) w = next;
      }
      if (w !== v) { n++; hits++; if (!CHECK) obj[k] = w; }
    }
    if (n && !CHECK) fs.writeFileSync(p, JSON.stringify(obj, null, 1) + '\n');
    if (n) console.log(`${CHECK ? '! ' : '✓ '}${lang}/${f}: ${n} 条按基准统一`);
  }
}
console.log(hits ? `${CHECK ? '✗' : '→'} 共 ${hits} 处与基准不一致${CHECK ? '（跑 node scripts/i18n-terms.cjs 改）' : '，已改'}`
  : '✓ 全部术语与基准一致');
process.exit(CHECK && hits ? 1 : 0);
