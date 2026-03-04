const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { execSync } = require('child_process');
const os = require('os');

// In-memory storage for original values (zero persistence - user responsibility)
const originalValues = new Map();

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 800,
    backgroundColor: '#0b0b0b',
    title: 'TRUMA Spoofer',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, 'index.html'));
  return win;
}

// Generate random MAC address
function generateRandomMAC() {
  const hex = '0123456789ABCDEF';
  let mac = '';
  for (let i = 0; i < 6; i++) {
    if (i > 0) mac += ':';
    mac += hex[Math.floor(Math.random() * 16)];
    mac += hex[Math.floor(Math.random() * 16)];
  }
  return mac;
}

// Generate random volume serial (8 hex chars)
function generateVolumeSerial() {
  return Math.floor(Math.random() * 0xFFFFFFFF).toString(16).toUpperCase().padStart(8, '0');
}

// Generate random GUID
function generateGUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Get all network adapters with MAC addresses
function getNetworkAdapters() {
  try {
    const result = execSync('powershell -Command "Get-NetAdapter | Where-Object {$_.HardwareInterface -eq $true} | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed, NetCfgInstanceId | ConvertTo-Json -Compress"', {
      encoding: 'utf8',
      timeout: 10000,
      windowsHide: true
    });
    
    const adapters = JSON.parse(result);
    return Array.isArray(adapters) ? adapters : [adapters];
  } catch (e) {
    console.error('Failed to get adapters:', e);
    return [];
  }
}

// Get current MAC for an adapter
function getCurrentMAC(adapterName) {
  try {
    const result = execSync(`powershell -Command "(Get-NetAdapter -Name '${adapterName}').MacAddress"`, {
      encoding: 'utf8',
      timeout: 5000,
      windowsHide: true
    });
    return result.trim();
  } catch (e) {
    return null;
  }
}

// Change MAC address (requires admin)
function changeMAC(adapterName, newMAC) {
  try {
    // Store original if not already stored
    const key = `mac_${adapterName}`;
    if (!originalValues.has(key)) {
      const current = getCurrentMAC(adapterName);
      if (current) originalValues.set(key, current);
    }
    
    // Convert MAC to registry format (remove colons, uppercase)
    const macClean = newMAC.replace(/:/g, '').toUpperCase();
    
    // Find the adapter in registry and set NetworkAddress
    const regPath = `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}`;
    
    // First, get the adapter details including NetCfgInstanceId
    let targetAdapter = null;
    try {
      const adaptersResult = execSync(`powershell -Command "Get-NetAdapter -Name '${adapterName}' | Select-Object Name, InterfaceDescription, NetCfgInstanceId | ConvertTo-Json"`, {
        encoding: 'utf8',
        timeout: 10000,
        windowsHide: true
      });
      targetAdapter = JSON.parse(adaptersResult);
    } catch (e) {
      return { success: false, error: 'Could not get adapter details from PowerShell' };
    }
    
    // Get all subkeys
    let subkeysResult;
    try {
      subkeysResult = execSync(`reg query "${regPath}"`, {
        encoding: 'utf8',
        timeout: 10000,
        windowsHide: true
      });
    } catch (e) {
      return { success: false, error: 'Could not query registry path' };
    }
    
    // Parse subkeys - match lines ending with \XXXX where X is a digit
    const lines = subkeysResult.split('\n');
    let adapterKey = null;
    const searchedKeys = [];
    
    // Debug: log what we found
    console.log('Registry query output lines:', lines.length);
    
    // Try 1: Search by NetCfgInstanceId (most reliable)
    if (targetAdapter && targetAdapter.NetCfgInstanceId) {
      for (const line of lines) {
        // Match pattern: \0000, \0001, etc at end of line
        const match = line.match(/\\(\d{4})\s*$/);
        if (match) {
          const subkey = match[1];
          searchedKeys.push(subkey);
          try {
            const netCfgResult = execSync(`reg query "${regPath}\\${subkey}" /v NetCfgInstanceId 2>nul`, {
              encoding: 'utf8',
              timeout: 3000,
              windowsHide: true
            });
            
            if (netCfgResult.includes(targetAdapter.NetCfgInstanceId)) {
              adapterKey = subkey;
              console.log('Found adapter by NetCfgInstanceId:', subkey);
              break;
            }
          } catch (_) {}
        }
      }
    }
    
    // Try 2: Search by InterfaceDescription (often matches DriverDesc)
    if (!adapterKey && targetAdapter && targetAdapter.InterfaceDescription) {
      const interfaceDesc = targetAdapter.InterfaceDescription;
      for (const line of lines) {
        const match = line.match(/\\(\d{4})\s*$/);
        if (match) {
          const subkey = match[1];
          try {
            const descResult = execSync(`reg query "${regPath}\\${subkey}" /v DriverDesc 2>nul`, {
              encoding: 'utf8',
              timeout: 3000,
              windowsHide: true
            });
            
            const driverDesc = descResult.split('REG_SZ')[1]?.trim() || '';
            
            // Check various matching patterns
            if (driverDesc === interfaceDesc || 
                interfaceDesc.includes(driverDesc) ||
                driverDesc.includes(interfaceDesc) ||
                descResult.toLowerCase().includes(interfaceDesc.toLowerCase())) {
              adapterKey = subkey;
              console.log('Found adapter by InterfaceDescription:', subkey);
              break;
            }
          } catch (_) {}
        }
      }
    }
    
    // Try 3: Search by Name as last resort
    if (!adapterKey) {
      for (const line of lines) {
        const match = line.match(/\\(\d{4})\s*$/);
        if (match) {
          const subkey = match[1];
          try {
            const descResult = execSync(`reg query "${regPath}\\${subkey}" /v DriverDesc 2>nul`, {
              encoding: 'utf8',
              timeout: 3000,
              windowsHide: true
            });
            
            if (descResult.includes(adapterName) || descResult.toLowerCase().includes(adapterName.toLowerCase())) {
              adapterKey = subkey;
              console.log('Found adapter by Name:', subkey);
              break;
            }
          } catch (_) {}
        }
      }
    }
    
    if (!adapterKey) {
      return { success: false, error: `Could not find adapter "${adapterName}" in registry. Searched ${searchedKeys.length} keys.` };
    }
    
    // Disable adapter first
    try {
      execSync(`powershell -Command "Disable-NetAdapter -Name '${adapterName}' -Confirm:$false"`, {
        timeout: 15000,
        windowsHide: true
      });
    } catch (e) {
      return { success: false, error: 'Failed to disable adapter: ' + e.message };
    }
    
    // Write MAC to registry
    try {
      execSync(`reg add "${regPath}\\${adapterKey}" /v NetworkAddress /t REG_SZ /d "${macClean}" /f`, {
        timeout: 10000,
        windowsHide: true
      });
    } catch (e) {
      // Re-enable adapter on failure
      execSync(`powershell -Command "Enable-NetAdapter -Name '${adapterName}' -Confirm:$false"`, {
        timeout: 10000,
        windowsHide: true
      });
      return { success: false, error: 'Failed to write registry: ' + e.message };
    }
    
    // Re-enable adapter
    try {
      execSync(`powershell -Command "Enable-NetAdapter -Name '${adapterName}' -Confirm:$false"`, {
        timeout: 15000,
        windowsHide: true
      });
    } catch (e) {
      return { success: false, error: 'Adapter disabled but failed to re-enable: ' + e.message };
    }
    
    // Wait a moment for adapter to come back up
    execSync('powershell -Command "Start-Sleep -Milliseconds 500"', {
      timeout: 5000,
      windowsHide: true
    });
    
    return { success: true, newMAC };
  } catch (e) {
    // Try to re-enable adapter on failure
    try {
      execSync(`powershell -Command "Enable-NetAdapter -Name '${adapterName}' -Confirm:$false"`, {
        timeout: 10000,
        windowsHide: true
      });
    } catch (_) {}
    
    return { success: false, error: e.message };
  }
}

// Get volume information
function getVolumes() {
  try {
    const result = execSync('powershell -Command "Get-Volume | Where-Object {$_.DriveLetter} | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining | ConvertTo-Json -Compress"', {
      encoding: 'utf8',
      timeout: 10000,
      windowsHide: true
    });
    
    const volumes = JSON.parse(result);
    const volumeArray = Array.isArray(volumes) ? volumes : [volumes];
    
    // Get serial numbers
    return volumeArray.map(v => {
      try {
        const serialResult = execSync(`powershell -Command "(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='${v.DriveLetter}:'\").VolumeSerialNumber"`, {
          encoding: 'utf8',
          timeout: 5000,
          windowsHide: true
        });
        v.serialNumber = serialResult.trim();
      } catch (_) {
        v.serialNumber = 'Unknown';
      }
      return v;
    });
  } catch (e) {
    console.error('Failed to get volumes:', e);
    return [];
  }
}

// Change volume serial (requires admin)
function changeVolumeSerial(driveLetter, newSerial) {
  try {
    const key = `vol_${driveLetter}`;
    
    // Store original
    if (!originalValues.has(key)) {
      const volumes = getVolumes();
      const vol = volumes.find(v => v.DriveLetter === driveLetter);
      if (vol && vol.serialNumber) {
        originalValues.set(key, vol.serialNumber);
      }
    }
    
    // Use volumeid.exe method (Sysinternals) or label trick
    // For now, we'll simulate since actual serial changing requires kernel-level access
    // In production, this would use a driver or low-level disk access
    
    return { success: true, newSerial, note: 'Simulated - requires driver for actual change' };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Get machine GUID and other identifiers
function getMachineIds() {
  try {
    const result = {};
    
    // Machine GUID
    try {
      const guid = execSync('powershell -Command "(Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Cryptography).MachineGuid"', {
        encoding: 'utf8',
        timeout: 5000,
        windowsHide: true
      });
      result.machineGuid = guid.trim();
    } catch (_) {
      result.machineGuid = 'Unknown';
    }
    
    // System UUID (BIOS/SMBIOS)
    try {
      const uuid = execSync('powershell -Command "(Get-CimInstance Win32_ComputerSystemProduct).UUID"', {
        encoding: 'utf8',
        timeout: 5000,
        windowsHide: true
      });
      result.systemUuid = uuid.trim();
    } catch (_) {
      result.systemUuid = 'Unknown';
    }
    
    // Product ID
    try {
      const productId = execSync('powershell -Command "(Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion).ProductId"', {
        encoding: 'utf8',
        timeout: 5000,
        windowsHide: true
      });
      result.productId = productId.trim();
    } catch (_) {
      result.productId = 'Unknown';
    }
    
    // Computer name
    result.computerName = os.hostname();
    
    return result;
  } catch (e) {
    return { machineGuid: 'Unknown', systemUuid: 'Unknown', productId: 'Unknown', computerName: os.hostname() };
  }
}

// Check if running as admin
function isAdmin() {
  try {
    execSync('net session', { timeout: 5000, windowsHide: true });
    return true;
  } catch (e) {
    return false;
  }
}

// Change Machine GUID
function changeMachineGuid(newGuid) {
  try {
    const key = 'machine_guid';
    
    // Store original
    if (!originalValues.has(key)) {
      const current = execSync('powershell -Command "(Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Cryptography).MachineGuid"', {
        encoding: 'utf8',
        timeout: 5000,
        windowsHide: true
      }).trim();
      if (current) originalValues.set(key, current);
    }
    
    const guid = newGuid || generateGUID();
    
    // Write to registry
    execSync(`reg add "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid /t REG_SZ /d "${guid}" /f`, {
      timeout: 10000,
      windowsHide: true
    });
    
    return { success: true, newGuid: guid };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Change BIOS/SMBIOS UUID (System UUID in registry)
function changeSystemUuid(newUuid) {
  try {
    const key = 'system_uuid';
    
    // Store original - read from registry if exists
    if (!originalValues.has(key)) {
      try {
        const current = execSync('powershell -Command "(Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation).SystemUUID" 2>$null || (Get-CimInstance Win32_ComputerSystemProduct).UUID"', {
          encoding: 'utf8',
          timeout: 5000,
          windowsHide: true
        }).trim();
        if (current) originalValues.set(key, current);
      } catch (_) {}
    }
    
    const uuid = newUuid || generateGUID().toUpperCase();
    
    // Write to registry - creates/changes the SystemUUID value
    execSync(`reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation" /v SystemUUID /t REG_SZ /d "${uuid}" /f`, {
      timeout: 10000,
      windowsHide: true
    });
    
    return { success: true, newUuid: uuid };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// IPC Handlers
ipcMain.handle('truma-get-adapters', async () => {
  return getNetworkAdapters();
});

ipcMain.handle('truma-get-volumes', async () => {
  return getVolumes();
});

ipcMain.handle('truma-get-machine-ids', async () => {
  return getMachineIds();
});

ipcMain.handle('truma-check-admin', async () => {
  return isAdmin();
});

ipcMain.handle('truma-spoof-mac', async (_e, adapterName, customMAC) => {
  const mac = customMAC || generateRandomMAC();
  return changeMAC(adapterName, mac);
});

ipcMain.handle('truma-spoof-volume', async (_e, driveLetter, customSerial) => {
  const serial = customSerial || generateVolumeSerial();
  return changeVolumeSerial(driveLetter, serial);
});

ipcMain.handle('truma-generate-mac', async () => {
  return generateRandomMAC();
});

ipcMain.handle('truma-generate-serial', async () => {
  return generateVolumeSerial();
});

ipcMain.handle('truma-generate-guid', async () => {
  return generateGUID();
});

ipcMain.handle('truma-get-original', async (_e, key) => {
  return originalValues.get(key) || null;
});

ipcMain.handle('truma-restore', async (_e, key) => {
  if (!originalValues.has(key)) {
    return { success: false, error: 'No original value stored' };
  }
  
  const original = originalValues.get(key);
  
  if (key.startsWith('mac_')) {
    const adapterName = key.replace('mac_', '');
    return changeMAC(adapterName, original);
  }
  
  if (key.startsWith('vol_')) {
    const driveLetter = key.replace('vol_', '');
    return changeVolumeSerial(driveLetter, original);
  }
  
  if (key === 'machine_guid') {
    return changeMachineGuid(original);
  }
  
  if (key === 'system_uuid') {
    return changeSystemUuid(original);
  }
  
  return { success: false, error: 'Unknown key type' };
});

ipcMain.handle('truma-spoof-machine-guid', async (_e, customGuid) => {
  const guid = customGuid || generateGUID();
  return changeMachineGuid(guid);
});

ipcMain.handle('truma-spoof-system-uuid', async (_e, customUuid) => {
  const uuid = customUuid || generateGUID().toUpperCase();
  return changeSystemUuid(uuid);
});

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
