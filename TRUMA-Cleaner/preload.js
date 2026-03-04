const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('trumaCleaner', {
  scan: () => ipcRenderer.invoke('truma-cleaner-scan'),
  clean: (rootIds) => ipcRenderer.invoke('truma-cleaner-clean', rootIds),
  getSettings: () => ipcRenderer.invoke('truma-cleaner-get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('truma-cleaner-save-settings', settings),
  onScheduledDue: (callback) => ipcRenderer.on('truma-cleaner-scheduled-due', callback)
});
