#!/usr/bin/env bash
#
# 一键发布到 GitHub Releases —— 昱弘网通的对外分发渠道。
#
# ★ 为什么发 GitHub：源码公开、非商业免费（PolyForm Noncommercial），
#   安装包挂 GitHub Releases 不占自家 OSS/CDN（免费分发不走 dl.yuhox.com 那条链路）。
#   参照 yuhox-board 的同一种做法：安装包 + SHA256SUMS.txt 一起发，客户能自己校验。
#
# 用法：
#   bash scripts/publish-github.sh <版本>                # 完整链路：出包 → 建 Release → 上传
#   bash scripts/publish-github.sh <版本> --draft        # 只建草稿，人工检查后再 publish
#   bash scripts/publish-github.sh <版本> --skip-build   # 安装包已在 dist/publish/ 里，只重传
#
# 前置：
#   - Go 工具链、ui/node_modules（electron-builder）就位
#   - gh 已登录（gh auth status）
#   - macOS 上出 Windows 包需要 wine（NSIS）；没有就先出其它平台，win 包去 Windows 机器上出
#
# 注意：这不是编译台那套（build-release.sh 仍只由编译台调用）。
#   编译台面向「平台登记与分发」；网通的对外包走这里，两不混。
set -euo pipefail

VERSION=""
DRAFT=0
SKIP_BUILD=0
while [ $# -gt 0 ]; do
  case "$1" in
    --draft) DRAFT=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    *) VERSION="${1:-}"; shift ;;
  esac
done
[ -n "$VERSION" ] || { echo "用法：publish-github.sh <版本> [--draft] [--skip-build]" >&2; exit 2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE="$ROOT/dist/release"          # 后端产物（build-release.sh 的输出）
PUBLISH="$ROOT/dist/publish"          # 对外安装包 + 校验和（GitHub Release 的内容）
REPO="mxyg/netkit"
TAG="v${VERSION}"

cd "$ROOT"

if [ "$SKIP_BUILD" != 1 ]; then
  echo "→ 第 1 步：后端出包（build-release.sh）"
  bash scripts/build-release.sh --version "$VERSION"

  # electron-builder 的 extraResources 路径用 ${os}-${arch}（mac/win/linux + x64/arm64），
  # build-release.sh 的目录名是 darwin/windows + amd64 —— 名字空间对不上。
  # ★ 这里只加软链不改名：build-release.sh 的输出布局不动，编译台认的是那套。
  echo "→ 第 2 步：目录名映射（软链 darwin→mac / windows→win / amd64→x64）"
  ln -sfn "$RELEASE/darwin-amd64"  "$RELEASE/mac-x64"
  ln -sfn "$RELEASE/darwin-arm64"  "$RELEASE/mac-arm64"
  ln -sfn "$RELEASE/windows-amd64" "$RELEASE/win-x64"
  ln -sfn "$RELEASE/linux-amd64"   "$RELEASE/linux-x64"

  echo "→ 第 3 步：界面出包（electron-builder 三平台）"
  cd "$ROOT/ui"
  export CSC_IDENTITY_AUTO_DISCOVERY=false   # 没接签名证书：出未签名包，客户拿到后校验 SHA256
  export ELECTRON_MIRROR="${ELECTRON_MIRROR:-https://npmmirror.com/mirrors/electron/}"
  export ELECTRON_BUILDER_BINARIES_MIRROR="${ELECTRON_BUILDER_BINARIES_MIRROR:-https://npmmirror.com/mirrors/electron-builder-binaries/}"
  # ★ 用仓里装好的那份（node_modules/.bin），不要 npx —— npx 会去 registry 解析，
  #   网络不通的机器上卡死也看不出报错
  EB="./node_modules/.bin/electron-builder"
  "$EB" --mac   --publish never
  "$EB" --win   --publish never
  "$EB" --linux --publish never
  cd "$ROOT"
else
  echo "→ 跳过构建（--skip-build）"
fi

echo "→ 第 4 步：汇总对外安装包到 $PUBLISH"
rm -rf "$PUBLISH"
mkdir -p "$PUBLISH"
INST="$ROOT/dist/installer"

# 命名规则与 relay/board 一致：yuhox-netkit-<版本>-<平台>.<扩展名>
# —— 版本号进了文件名，Release 页上一眼对得上；别用带中文与空格的原始名（URL 编码难看也难校验）
pick() { # <源文件通配> <目标名>
  local f
  f=$(compgen -G "$1" 2>/dev/null | head -1)
  if [ -z "$f" ]; then
    echo "✗ 缺安装包：$1（对应平台构建失败？）" >&2
    exit 1
  fi
  cp "$f" "$PUBLISH/$2"
  echo "   ✓ $2"
}
# 实际产物命名（electron-builder 默认）：版本号在前、架构在后 ——
#   昱弘网通-<版本>-arm64.dmg / 昱弘网通-<版本>.dmg（x64 不带后缀）/
#   昱弘网通 Setup <版本>.exe / 昱弘网通-<版本>[-arm64].AppImage /
#   YuhoxNetKit_<版本>_[amd64|arm64].deb
pick "$INST/*Setup*$VERSION.exe"        "yuhox-netkit-$VERSION-windows-setup.exe"
pick "$INST/*$VERSION*arm64.dmg"        "yuhox-netkit-$VERSION-mac-arm64.dmg"
pick "$INST/*$VERSION.dmg"              "yuhox-netkit-$VERSION-mac-x64.dmg"
pick "$INST/*$VERSION.AppImage"         "yuhox-netkit-$VERSION-linux-x86_64.AppImage"
pick "$INST/*$VERSION*arm64.AppImage"   "yuhox-netkit-$VERSION-linux-arm64.AppImage"
pick "$INST/*$VERSION*amd64.deb"        "yuhox-netkit-$VERSION-linux-amd64.deb"
pick "$INST/*$VERSION*arm64.deb"        "yuhox-netkit-$VERSION-linux-arm64.deb"

# 后端裸二进制也随包发：现场只要 netkitd 单文件时不用装整套界面
# ★ 只收 build-release.sh 真正编译的六个目录 —— 第 2 步建的软链（mac-x64 等）
#   指向同一份文件，照着收会把重复的校验值一起发上去
for n in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-386 windows-amd64; do
  b="$(compgen -G "$RELEASE/$n/netkitd*" 2>/dev/null | head -1)"
  if [ -n "$b" ]; then
    ext=""
    [ "${b##*.}" = exe ] && ext=".exe"
    cp "$b" "$PUBLISH/netkit-$VERSION-$n$ext"
    echo "   ✓ netkit-$VERSION-$n$ext"
  fi
done

echo "→ 第 5 步：校验和"
cd "$PUBLISH"
find . -type f -not -name SHA256SUMS.txt -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS.txt
cat SHA256SUMS.txt

echo "→ 第 6 步：发 GitHub Release（${TAG} → ${REPO}）"
NOTES="昱弘网通 $VERSION

安装包与校验和同页发布（SHA256SUMS.txt），下载后请核对 SHA256。
软件里没有任何授权机制：不用激活、不绑机、不到期；非商业使用免费。
源码与文档：https://github.com/mxyg/netkit
产品介绍与商业授权（纸面凭证）：https://net.yuhox.com"
GH_ARGS=(--title "$TAG" --notes "$NOTES" "$TAG")
[ "$DRAFT" = 1 ] && GH_ARGS+=(--draft)
gh release create "${GH_ARGS[@]}" "$PUBLISH"/*

echo "✓ 发布完成：https://github.com/$REPO/releases/tag/$TAG"
