#!/usr/bin/env bash
#
# 出包。**只由编译台调用**（yuhox-deploy 的 `ai.mjs release netkit`）。
#
# ★★ 不要直接跑它来出对外的包 —— 全局 CLAUDE.md §1：
#   编译台那一步还要刷 SDK、写签发公钥、取出包私钥。漏了要等客户装机才爆。
#   昱弘网通声明了「不做授权」（build-configs/netkit.json 的 licensing: none），
#   那几步会被跳过，但**跳过是编译台决定的，不是这个脚本决定的**。
#
# 本地想试编译：直接 `cd backend && go build ./...`，不要用这个脚本。
set -euo pipefail

VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    *) echo "不认识的参数：$1" >&2; exit 2 ;;
  esac
done
[ -n "$VERSION" ] || { echo "✗ 没给 --version" >&2; exit 2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist/release"
cd "$ROOT/backend"

# ★ 每次从干净目录出包：上一次的残留混进交付物，是那种"本机好好的、客户装了不对"的经典来源
rm -rf "$OUT"
mkdir -p "$OUT"

echo "→ 自检（不过就不出包）"
gofmt -l . | grep -q . && { echo "✗ 有没 gofmt 的文件："; gofmt -l .; exit 1; } || true
go vet ./...
go test ./...

# ★★ 界面这一遍必须跟着跑，否则「所有功能都做完了」这句话在**出厂那一刻**才算数就没意义了：
#   词典是三样东西凑出来的 —— 源码里的中文原文（唯一分母）、分片译文、合成好的 src/locales/*.js。
#   少了这三步里的任何一步，客户界面上就会出现一句露回中文的话，而这**在本机看不出来**：
#   本机跑的是合并后的那一份，改完源码没合成分片的人，看到的还是旧的词典。
#   顺序是有讲究的：先数术语（少数派改名要落在分片上），再合成（把分片烤进词典），
#   最后按整本词典量覆盖率 —— 审计读的是合成产物，不是分片，放在合成之前等于没量。
echo "→ 界面自检（术语统一 → 合成词典 → 覆盖率闸门，不过就不出包）"
cd "$ROOT/ui"
node scripts/i18n-terms.cjs --check
node scripts/i18n-merge.cjs en ja ko ru
node scripts/i18n-audit.cjs
cd "$ROOT/backend"

# ★★ 目标平台就是老板定的那四个（交接 §2 第 4 条）：Win10+、Win7、Linux、macOS。
#   Win7 单独一份：它要 Electron 22，界面那边分包；后端这一份用同样的产物即可，
#   但**必须单列**，否则没人会记得 Win7 这条线还活着。
#
# ★ CGO_ENABLED=0：静态链接，落到老系统上不会因为 glibc 版本起不来。
#   现场的机器什么年代的都有，这一条比体积重要。
targets="
linux/amd64/netkitd
linux/arm64/netkitd
darwin/amd64/netkitd
darwin/arm64/netkitd
windows/amd64/netkitd.exe
windows/386/netkitd.exe
"

echo "→ 交叉编译（版本 ${VERSION}）"
for t in $targets; do
  goos="${t%%/*}"; rest="${t#*/}"; goarch="${rest%%/*}"; bin="${rest#*/}"
  dir="$OUT/${goos}-${goarch}"
  mkdir -p "$dir"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath \
      -ldflags "-s -w -X main.Version=$VERSION" \
      -o "$dir/$bin" ./cmd/netkitd
  # 随包带上许可证与说明：源码公开、非商业免费，客户拿到包也该看得见
  cp "$ROOT/LICENSE" "$dir/LICENSE"
  cp "$ROOT/README.md" "$dir/README.md"
  echo "   ✓ ${goos}-${goarch}"
done

echo "→ 校验和"
cd "$OUT"
find . -type f -not -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS

echo "✓ 出包完成：$OUT"
ls -1 "$OUT"
