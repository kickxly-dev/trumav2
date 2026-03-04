const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('truma', {
  onOpenUrl: (handler) => {
    ipcRenderer.on('truma-open-url', (_e, url) => handler(url));
  },
  onDownloadEvent: (handler) => {
    ipcRenderer.on('truma-download-event', (_e, payload) => handler(payload));
  },
  onShortcut: (handler) => {
    ipcRenderer.on('shortcut', (_e, action) => handler(action));
  },
  onBlockedRequest: (handler) => {
    ipcRenderer.on('blocked-request', (_e, type) => handler(type));
  },
  openDownloadedFile: (filePath) => ipcRenderer.invoke('truma-open-downloaded-file', filePath),
  showDownloadedInFolder: (filePath) => ipcRenderer.invoke('truma-show-downloaded-in-folder', filePath),
  clearDownloadHistory: () => ipcRenderer.invoke('truma-clear-download-history'),
  setHomepageShortcuts: (shortcuts) => ipcRenderer.invoke('truma-set-homepage-shortcuts', shortcuts),
  setAdblockLevel: (level) => ipcRenderer.invoke('truma-set-adblock-level', level)
});
