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

echo "→ 交叉编译（版本 $VERSION）"
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
