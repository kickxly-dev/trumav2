const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('trumaSpoofer', {
  getAdapters: () => ipcRenderer.invoke('truma-get-adapters'),
  getVolumes: () => ipcRenderer.invoke('truma-get-volumes'),
  getMachineIds: () => ipcRenderer.invoke('truma-get-machine-ids'),
  checkAdmin: () => ipcRenderer.invoke('truma-check-admin'),
  spoofMAC: (adapterName, customMAC) => ipcRenderer.invoke('truma-spoof-mac', adapterName, customMAC),
  spoofVolume: (driveLetter, customSerial) => ipcRenderer.invoke('truma-spoof-volume', driveLetter, customSerial),
  spoofMachineGuid: (customGuid) => ipcRenderer.invoke('truma-spoof-machine-guid', customGuid),
  spoofSystemUuid: (customUuid) => ipcRenderer.invoke('truma-spoof-system-uuid', customUuid),
  generateMAC: () => ipcRenderer.invoke('truma-generate-mac'),
  generateSerial: () => ipcRenderer.invoke('truma-generate-serial'),
  generateGUID: () => ipcRenderer.invoke('truma-generate-guid'),
  getOriginal: (key) => ipcRenderer.invoke('truma-get-original', key),
  restore: (key) => ipcRenderer.invoke('truma-restore', key)
});
