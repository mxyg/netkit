const device = new URLSearchParams(location.search).get('device');
const hint = document.getElementById('hint');
const img = document.getElementById('view');
const remoteCursor = document.getElementById('remote-cursor');
const showRemote = document.getElementById('show-remote');
let API = '';
let cursorURL = '';
let cursorBlob = '';
let hot = { x: 0, y: 0 };
let remotePos = { x: 0, y: 0 };

async function call(tool, args) {
  const r = await fetch(`${API}/tools/${tool}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  });
  const body = await r.json().catch(() => ({}));
  if (body && body.error) return { ok: false, message: body.message || '' };
  return { ok: true, values: body.values || body, note: body.note || '' };
}

function placed() {
  const stage = document.getElementById('stage').getBoundingClientRect();
  const nw = img.naturalWidth || stage.width;
  const nh = img.naturalHeight || stage.height;
  const scale = Math.min(stage.width / nw, stage.height / nh);
  const dw = nw * scale;
  const dh = nh * scale;
  const left = (stage.width - dw) / 2;
  const top = (stage.height - dh) / 2;
  return { left, top, dw, dh, scale };
}

function layout() {
  const p = placed();
  img.style.left = p.left + 'px';
  img.style.top = p.top + 'px';
  img.style.width = p.dw + 'px';
  img.style.height = p.dh + 'px';
  placeRemote();
}

function placeRemote() {
  if (!showRemote.checked || !img.naturalWidth) {
    remoteCursor.style.display = 'none';
    return;
  }
  const p = placed();
  remoteCursor.style.display = 'block';
  remoteCursor.style.left = (p.left + remotePos.x * p.dw - hot.x * p.scale) + 'px';
  remoteCursor.style.top = (p.top + remotePos.y * p.dh - hot.y * p.scale) + 'px';
  remoteCursor.style.width = (64 * p.scale) + 'px';
  remoteCursor.style.height = (64 * p.scale) + 'px';
}

function applyLocalCursor() {
  if (showRemote.checked) {
    img.style.cursor = 'none';
    return;
  }
  img.style.cursor = cursorBlob ? `url("${cursorBlob}") ${hot.x} ${hot.y}, auto` : 'default';
}

function xy(e) {
  const b = img.getBoundingClientRect();
  return {
    x: Math.min(1, Math.max(0, (e.clientX - b.left) / b.width)),
    y: Math.min(1, Math.max(0, (e.clientY - b.top) / b.height)),
  };
}

function send(ev) {
  call('remote.desk.input', Object.assign({ device }, ev));
}

let moveAt = 0;
function move(e) {
  const now = performance.now();
  if (now - moveAt < 30 && !e.buttons) return;
  moveAt = now;
  const p = xy(e);
  send({ kind: 'mouse', action: 'move', button: '', x: p.x, y: p.y });
}

async function main() {
  API = await window.netkit.apiBase();
  const opened = await call('remote.desk.open', { device });
  if (!opened.ok) { hint.textContent = '打不开：' + opened.message; return; }
  setInterval(async () => {
    const f = await call('remote.desk.frame', { device });
    if (!(f.ok && f.values && f.values.jpeg)) {
      if (!f.ok) hint.textContent = f.message;
      return;
    }
    hint.textContent = '';
    img.src = 'data:image/jpeg;base64,' + f.values.jpeg;
    remotePos = { x: Number(f.values.cx) || 0, y: Number(f.values.cy) || 0 };
    hot = { x: Number(f.values.hotx) || 0, y: Number(f.values.hoty) || 0 };
    if (f.values.png && f.values.png !== cursorURL) {
      cursorURL = f.values.png;
      if (cursorBlob) URL.revokeObjectURL(cursorBlob);
      const bin = atob(f.values.png);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      cursorBlob = URL.createObjectURL(new Blob([bytes], { type: 'image/png' }));
      remoteCursor.src = cursorBlob;
    }
    applyLocalCursor();
    layout();
  }, 200);
}

img.onload = layout;
window.addEventListener('resize', layout);
showRemote.onchange = () => { applyLocalCursor(); placeRemote(); };
img.onmousedown = (e) => { const p = xy(e); send({ kind: 'mouse', action: 'down', button: e.button === 2 ? 'right' : 'left', x: p.x, y: p.y }); };
img.onmouseup = (e) => { const p = xy(e); send({ kind: 'mouse', action: 'up', button: e.button === 2 ? 'right' : 'left', x: p.x, y: p.y }); };
img.onmousemove = move;
img.oncontextmenu = (e) => e.preventDefault();
window.addEventListener('keydown', (e) => {
  if (e.target && e.target.tagName === 'INPUT') return;
  e.preventDefault();
  send({ kind: 'key', action: 'down', key: e.key });
});
window.addEventListener('keyup', (e) => {
  if (e.target && e.target.tagName === 'INPUT') return;
  send({ kind: 'key', action: 'up', key: e.key });
});

document.body.addEventListener('dragover', (e) => { e.preventDefault(); });
document.body.addEventListener('drop', async (e) => {
  e.preventDefault();
  const files = [...(e.dataTransfer.files || [])];
  for (const f of files) {
    const local = f.path;
    if (!local) continue;
    const r = await call('remote.desk.drop', { device, local });
    hint.textContent = r.ok ? '' : ('没传上：' + r.message);
  }
});

main();
