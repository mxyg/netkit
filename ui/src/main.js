/**
 * Electron 主进程。
 *
 * ★★ 界面**只是后端 API 的一个客户端**，和 AI 平起平坐
 * （见 docs/设计.md「AI 接口」）。这里不许有任何业务逻辑 ——
 * 加了就等于分叉出第二套能力，界面和 AI 看到的东西会开始不一样。
 *
 * 它干三件事：
 *   ① 把后端 netkitd 拉起来，拿到它监听的地址
 *   ② 开窗口
 *   ③ ★ 当后端的「批准渠道」：改系统的操作弹框问人 —— [OTS-7.1]
 */
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('node:child_process');
const path = require('node:path');
const http = require('node:http');

let backend = null;
let apiBase = '';
let win = null;

/** 找后端可执行文件：开发时在 backend/，打包后在资源目录。 */
function backendPath() {
  const exe = process.platform === 'win32' ? 'netkitd.exe' : 'netkitd';
  if (app.isPackaged) return path.join(process.resourcesPath, exe);
  return path.join(__dirname, '..', '..', 'backend', exe);
}

/**
 * 拉起后端并等它报出监听地址。
 *
 * ★ 后端把地址打在 stderr 的启动日志里（stdout 留给 MCP 协议，见 cmd/netkitd）。
 * ★ approvePort：批准渠道的地址要**在启动参数里**交给后端 ——
 *   不给 -approve-url = 后端没有批准渠道 = 改系统的工具一律拒绝（不是默认放行）。
 */
function startBackend(approvePort) {
  return new Promise((resolve, reject) => {
    const child = spawn(backendPath(), ['-addr', '127.0.0.1:0', '-mutations',
      '-approve-url', `http://127.0.0.1:${approvePort}/approve`], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let buf = '';
    const onData = (d) => {
      buf += d.toString();
      const m = buf.match(/addr=(\S+)/);
      if (m) {
        child.stderr.off('data', onData);
        resolve({ child, base: `http://${m[1]}` });
      }
    };
    child.stderr.on('data', onData);
    child.on('error', reject);
    child.on('exit', (code) => {
      if (!apiBase) reject(new Error(`后端没起来（退出码 ${code}）：\n${buf.slice(-800)}`));
    });
    setTimeout(() => reject(new Error(`后端 8 秒内没报出监听地址：\n${buf.slice(-800)}`)), 8000);
  });
}

async function createWindow() {
  win = new BrowserWindow({
    width: 1180, height: 820, minWidth: 900, minHeight: 600,
    title: '昱弘网通 NetKit',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true },
  });
  await win.loadFile(path.join(__dirname, 'index.html'));
}

/**
 * ★★ 批准渠道：后端遇到改系统的操作时，长轮询这里要一次人工确认。
 *
 * [OTS-7.1] 授权只能来自**人在界面上的那一下点击**，
 * [OTS-7.3] 调用参数里写什么都不算数。
 * 所以这段代码只做一件事：把后端给的那句话原样弹给人看，把人的选择原样回去。
 * **不许在这里替人做任何判断**（比如"这个看起来没风险就自动同意"）。
 */
function serveApproval() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      if (req.method !== 'POST' || req.url !== '/approve') {
        res.writeHead(404).end();
        return;
      }
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', async () => {
        let ask = {};
        try { ask = JSON.parse(body); } catch { /* 下面按空的处理 */ }
        const opts = {
          type: 'warning',
          buttons: ['取消', '确认执行'],
          defaultId: 0,          // ★ 默认停在"取消"：回车不该等于同意
          cancelId: 0,
          title: '这个操作会改动机器',
          message: ask.tool || '改动确认',
          detail: (ask.what || '(没有说明要改什么)') +
            '\n\n请求来自：' + (ask.caller || '未知') +
            '\n\n确认后会立刻执行，改动会被记录，可以还原。',
        };
        const r = win ? await dialog.showMessageBox(win, opts) : await dialog.showMessageBox(opts);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ approved: r.response === 1 }));
      });
    });
    // 端口 0 = 让系统挑一个，免得和机器上别的东西撞
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

app.whenReady().then(async () => {
  // ★ 先开批准渠道再拉后端：后端要拿着它的地址启动
  const approval = await serveApproval();
  try {
    const r = await startBackend(approval.address().port);
    backend = r.child;
    apiBase = r.base;
  } catch (e) {
    dialog.showErrorBox('后端起不来', String(e && e.message || e));
    app.quit();
    return;
  }
  await createWindow();
});

ipcMain.handle('api-base', () => apiBase);

app.on('window-all-closed', () => app.quit());
app.on('quit', () => { if (backend) backend.kill(); });
