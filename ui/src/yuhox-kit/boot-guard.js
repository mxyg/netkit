// 由运维台 scripts/sync-desktop-kit.mjs 从 templates/desktop-kit/ 同步，勿手改。
/**
 * 昱弘桌面统一件 · 启动可靠性（Electron 主进程，CommonJS）。
 *
 * 由运维台 sync-desktop-kit 同步进各产品仓（TS 仓落成 .ts 并加 @ts-nocheck），勿在产品仓改副本。
 *
 * 解决的是客户那句「装完双击没反应、连进程都没有」——以前这种情况**什么线索都不留**：
 *   · 单实例锁拿不到就静默 app.quit()（残留进程占着锁时，客户看到的就是没反应）
 *   · 出事时自家日志还没初始化，或写日志的 catch 把错误吞了
 *   · 主进程抛错 / 子进程 spawn 失败（杀毒拦截、文件被删）没人记、没人提示
 *   · 原生崩溃（进程直接没了）连 dump 都没有
 *
 * 用法（主进程入口，越早越好；userData 若要改名，先 setPath 再装）：
 *   const { installBootGuard } = require('./yuhox-kit/boot-guard')
 *   const guard = installBootGuard({ product: '昱弘播控' })
 *   if (!guard.lock(() => showMainWindow())) return   // 或把后续启动放进 else
 *   guard.child(spawn(exe, args), '后台服务')           // spawn 出来的每个子进程都过一下
 *   guard.mark('主窗口已显示')                          // 主窗口 show 之后调，否则 20 秒后记一条警告
 *
 * 日志：userData/logs/启动.log（2MB 翻页）。崩溃 dump：userData/Crashpad（只存本机，不上传）。
 * 不加密、不联网（公司红线）。
 */
const { app, crashReporter, dialog, BrowserWindow } = require('electron')
const { appendFileSync, mkdirSync, renameSync, statSync } = require('node:fs')
const { join } = require('node:path')

const MAX_BYTES = 2 * 1024 * 1024
let installed = null

function installBootGuard(opts) {
  if (installed) return installed
  const product = (opts && opts.product) || app.getName()
  const expectWindowMs = (opts && opts.expectWindowMs) || 20000
  const started = Date.now()
  let broken = false
  let alerted = false
  let windowMarked = false

  function logFile() {
    const dir = join(app.getPath('userData'), 'logs')
    mkdirSync(dir, { recursive: true })
    return join(dir, '启动.log')
  }

  function log(level, text) {
    const line = `${new Date().toISOString()} [${level}] ${text}\n`
    try {
      console.log(`[启动] ${text}`)
    } catch {
      // 没有控制台
    }
    if (broken) return
    try {
      const f = logFile()
      try {
        if (statSync(f).size > MAX_BYTES) renameSync(f, f.replace(/\.log$/, '.1.log'))
      } catch {
        // 文件还不存在
      }
      appendFileSync(f, line, 'utf8')
    } catch {
      broken = true
    }
  }

  function logPathForHuman() {
    try {
      return logFile()
    } catch {
      return '（日志目录不可写）'
    }
  }

  /** 弹一次就够：连着出错时连弹十个框，人只会全点掉 */
  function alert(title, detail) {
    if (alerted) return
    alerted = true
    try {
      dialog.showErrorBox(`${product} · ${title}`, `${detail}\n\n详细记录在：\n${logPathForHuman()}\n\n请把这个文件发给技术支持。`)
    } catch {
      // 太早或太晚弹不出来，日志里有
    }
  }

  // ⓪ stdout/stderr 断了不能反过来打死自己
  //
  // 开发时从终端起、终端先关，或者外壳把管道收了，之后 console.log 写的是一根断掉的管子。
  // 关键在于这个失败是**异步**的：write 当场返回，错误稍后从流的 error 事件冒出来，
  // 所以下面 log() 里包着 console.log 的那个 try/catch 一点用都没有 ——
  // 一条普通日志变成 uncaughtException（EPIPE），主进程被打掉，还顺手弹一个错误框。
  // 管子断了这件事本身对界面没有任何影响，也无处可报（报也得往同一根管子里写），静音。
  for (const s of [process.stdout, process.stderr]) {
    try {
      s.on('error', () => {})
    } catch {
      // 某些环境下 stdout 不是流
    }
  }

  // ① 本机崩溃 dump：进程被原生崩溃直接带走时，这是唯一的线索
  try {
    crashReporter.start({ uploadToServer: false, compress: true })
  } catch (e) {
    log('注意', `crashReporter 启动失败：${e && e.message}`)
  }

  log('信息', `—— ${product} 启动 ${app.getVersion()} · Electron ${process.versions.electron} · ${process.platform} ${safe(() => process.getSystemVersion())} ${process.arch} · pid ${process.pid} · ${process.execPath}`)

  // ② 主进程未捕获的错误：记下来并告诉人，不替产品决定要不要退出
  process.on('uncaughtException', (e) => {
    // 管道断裂不是「程序出错」：记一笔就够，别拿它弹框吓人（成因见上面 ⓪）
    if (e && (e.code === 'EPIPE' || e.code === 'ERR_STREAM_DESTROYED')) {
      log('注意', `输出管道断了（${e.code}），不影响界面，已忽略`)
      return
    }
    log('出错', `未捕获异常：${(e && e.stack) || e}`)
    alert('程序出错', `出现了一个没有处理的错误：\n${(e && e.message) || e}`)
  })
  process.on('unhandledRejection', (e) => {
    log('出错', `未处理的 Promise 拒绝：${(e && e.stack) || e}`)
  })

  // ③ 进程和窗口的去向
  app.on('render-process-gone', (_ev, wc, d) => {
    log('出错', `页面进程退出：${d.reason} code=${d.exitCode} url=${safe(() => wc.getURL())}`)
  })
  app.on('child-process-gone', (_ev, d) => {
    log('出错', `子进程退出：${d.type} ${d.name || ''} ${d.reason} code=${d.exitCode}`)
  })
  app.on('will-quit', () => log('信息', `退出（运行 ${Math.round((Date.now() - started) / 1000)} 秒）`))
  process.on('exit', (code) => log('信息', `进程结束 code=${code}`))

  // ④ 窗口迟迟不出来：留一条记录，排查「双击没反应」时一眼能看到卡在哪
  setTimeout(() => {
    if (windowMarked) return
    const visible = safe(() => BrowserWindow.getAllWindows().some((w) => w.isVisible())) || false
    if (!visible) log('注意', `启动 ${expectWindowMs / 1000} 秒还没有可见窗口`)
  }, expectWindowMs).unref?.()

  const api = {
    info: (t) => log('信息', t),
    warn: (t) => log('注意', t),
    error: (t) => log('出错', t),
    alert,

    /**
     * 单实例锁。拿到返回 true，并在「第二次双击」时调 onSecond（把窗口叫到前面 / 重建窗口）。
     * 拿不到：记日志后 app.quit() 并返回 false —— 以前这一步是静默的。
     */
    lock(onSecond) {
      if (app.requestSingleInstanceLock()) {
        app.on('second-instance', (_ev, argv) => {
          log('信息', `又被双击了一次（${(argv || []).slice(1).join(' ')}），交给当前实例处理`)
          try {
            if (onSecond) onSecond()
          } catch (e) {
            log('出错', `处理第二次启动失败：${(e && e.stack) || e}`)
          }
        })
        return true
      }
      log('注意', '已经有一个在运行（或上次没退干净的残留进程占着），本次退出，交给那个实例。若始终看不到窗口，请在任务管理器结束残留进程后再打开')
      app.quit()
      return false
    },

    /** spawn 出来的子进程：启动失败（杀毒拦截、文件被删、没权限）要有记录和提示，不能变成静默崩溃 */
    child(cp, name) {
      if (!cp) return cp
      cp.on('error', (e) => {
        log('出错', `${name} 启动失败：${(e && e.stack) || e}`)
        alert(`${name}启动失败`, `${name}没能启动：${(e && e.message) || e}\n\n常见原因：被杀毒软件拦截或隔离、安装目录里的文件被删。\n可以把安装目录加入杀毒软件信任后重新安装。`)
      })
      cp.on('exit', (code, signal) => {
        if (code !== 0) log('注意', `${name} 退出 code=${code} signal=${signal || ''}`)
      })
      return cp
    },

    /** 启动里程碑。含「窗口」字样时视为窗口已出现，不再报 20 秒警告 */
    mark(text) {
      if (/窗口/.test(text)) windowMarked = true
      log('信息', `${text}（+${Date.now() - started}ms）`)
    },

    logFile: logPathForHuman,
  }
  installed = api
  return api
}

function safe(fn) {
  try {
    return fn()
  } catch {
    return undefined
  }
}

module.exports = { installBootGuard }
