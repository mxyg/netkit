/**
 * ★ contextIsolation 下的桥。只暴露"后端地址"这一件事 ——
 * 渲染进程自己用 fetch 调 API，不经过主进程转发。
 * 转发一层的话，主进程就会慢慢长出业务逻辑，而那正是要避免的。
 */
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('netkit', {
  apiBase: () => ipcRenderer.invoke('api-base'),
});
