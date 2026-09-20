#!/bin/bash
#
# 双击这个文件就能把昱弘网通跑起来（开发用）。
#
# ★ 它做两件事：把 Go 后端编出来，然后起 Electron 界面。
#   正式的安装包不走这里 —— 那要经编译台（见 scripts/build-release.sh 开头那段）。
cd "$(dirname "$0")" || exit 1

# ★ 新电脑可能连 node 都没有。Homebrew 装过的话把它的路径引进来，
#   否则双击运行时 PATH 里没有 node（图形界面启动不读 .zshrc）。
BREW=$(command -v brew || ls /opt/homebrew/bin/brew /usr/local/bin/brew 2>/dev/null | head -1)
[ -n "$BREW" ] && eval "$("$BREW" shellenv)"

echo "── 昱弘网通 NetKit ──"

if ! command -v go >/dev/null 2>&1; then
  echo "✗ 没有找到 Go。装一个：brew install go"
  read -r -p "按回车关闭…" _; exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "✗ 没有找到 Node。装一个：brew install node"
  read -r -p "按回车关闭…" _; exit 1
fi

echo "→ 编后端…"
if ! (cd backend && go build -o netkitd ./cmd/netkitd); then
  echo "✗ 后端没编过。上面有报错。"
  read -r -p "按回车关闭…" _; exit 1
fi
echo "  ✓ backend/netkitd"

if [ ! -d ui/node_modules ]; then
  echo "→ 头一次跑，装界面依赖（要几分钟）…"
  (cd ui && npm install) || { echo "✗ 装依赖失败"; read -r -p "按回车关闭…" _; exit 1; }
fi

echo "→ 起界面…"
cd ui && npm start
