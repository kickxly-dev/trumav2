const { app, BrowserWindow, session, dialog, protocol, ipcMain, shell, globalShortcut } = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

// Import Privacy Manager
const PrivacyManager = require('./privacy/privacy-manager');

const TEMP_USER_DATA_DIR = path.join(os.tmpdir(), `TRUMA-Browser-${process.pid}`);

// Initialize Privacy Manager
const privacyManager = new PrivacyManager();

protocol.registerSchemesAsPrivileged([
  {
    scheme: 'truma',
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      allowServiceWorkers: false
    }
  }
]);

function getTrumaHomepageHtml() {
  const shortcuts = homepageShortcuts.length
    ? homepageShortcuts
    : [
      { label: 'DuckDuckGo', url: 'https://duckduckgo.com', icon: 'DDG' },
      { label: 'GitHub', url: 'https://github.com', icon: 'GH' },
      { label: 'Reddit', url: 'https://reddit.com', icon: 'RD' },
      { label: 'YouTube', url: 'https://youtube.com', icon: 'YT' }
    ];

  const esc = (s) => String(s || '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const gridHtml = shortcuts.slice(0, 8).map((s) => {
    const label = esc(s.label);
    const url = esc(s.url);
    const icon = esc(s.icon || label.slice(0, 3).toUpperCase());
    return `<a href="${url}"><div class="ico">${icon}</div><div>${label}</div></a>`;
  }).join('');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>TRUMA Home</title>
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{min-height:100vh;background:linear-gradient(135deg,#0b0b0b 0%,#1a0a0f 50%,#0b0b0b 100%);display:flex;align-items:center;justify-content:center;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#f2f2f2;overflow:hidden}
      .orb{position:absolute;width:720px;height:720px;border-radius:50%;background:radial-gradient(circle,rgba(176,0,32,0.18) 0%,transparent 70%);animation:p 4s ease-in-out infinite}
      @keyframes p{0%,100%{transform:scale(1);opacity:.55}50%{transform:scale(1.12);opacity:.9}}
      .wrap{position:relative;z-index:1;width:min(760px,92%);text-align:center}
      .badge{display:inline-flex;gap:8px;align-items:center;border:1px solid rgba(0,200,100,.25);background:rgba(0,200,100,.08);color:#00c864;padding:8px 14px;border-radius:999px;font-size:12px;font-weight:800;letter-spacing:.08em;margin-bottom:26px}
      .logo{font-size:54px;font-weight:900;letter-spacing:.22em;text-shadow:0 0 48px rgba(176,0,32,.55)}
      .sub{margin-top:10px;font-size:16px;font-weight:800;letter-spacing:.25em;color:#e0002a}
      .tag{margin-top:12px;font-size:13px;color:#8a8a8a;letter-spacing:.06em}
      form{margin:34px auto 18px;display:flex;gap:10px;align-items:center;background:rgba(255,255,255,.03);border:1px solid rgba(224,0,42,.28);border-radius:16px;padding:6px;max-width:560px}
      form:focus-within{border-color:rgba(224,0,42,.9);box-shadow:0 0 0 4px rgba(224,0,42,.12)}
      input{flex:1;height:40px;border:0;outline:0;background:transparent;color:#f2f2f2;font-size:16px;padding:0 10px}
      input::placeholder{color:#666}
      button{height:40px;border:0;border-radius:12px;padding:0 18px;font-weight:900;letter-spacing:.06em;color:#fff;cursor:pointer;background:linear-gradient(135deg,#b00020,#e0002a)}
      .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:18px}
      a{display:flex;flex-direction:column;gap:8px;align-items:center;justify-content:center;text-decoration:none;color:#bdbdbd;border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.02);border-radius:14px;padding:14px;transition:transform .12s ease,border-color .12s ease,background .12s ease}
      a:hover{transform:translateY(-2px);border-color:rgba(224,0,42,.32);background:rgba(224,0,42,.08)}
      .ico{width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center;background:rgba(224,0,42,.18)}
      .foot{margin-top:18px;font-size:11px;color:#444;letter-spacing:.12em}
    </style>
  </head>
  <body>
    <div class="orb"></div>
    <div class="wrap">
      <div class="badge">ZERO DATA  |  NO TRACKING  |  PRIVATE</div>
      <div class="logo">TRUMA</div>
      <div class="sub">BROWSER</div>
      <div class="tag">Private session. No history. No persistence.</div>
      <form onsubmit="return s()">
        <input id="q" placeholder="Search DuckDuckGo or type a URL..." autocomplete="off" />
        <button type="submit">SEARCH</button>
      </form>
      <div class="grid">
        ${gridHtml}
      </div>
      <div class="foot">TRUMA HOME</div>
    </div>
    <script>
      function isUrl(v){v=v.trim();if(!v)return false;if(v.startsWith('http://')||v.startsWith('https://'))return true;if(v.includes(' '))return false;return v.includes('.')}
      function s(){const v=document.getElementById('q').value.trim();if(!v)return false;location.href=isUrl(v)?(v.startsWith('http')?v:'https://'+v):('https://duckduckgo.com/?q='+encodeURIComponent(v));return false}
      document.getElementById('q').focus();
    </script>
  </body>
</html>`;
}

let homepageShortcuts = [];

let mainWindow = null;

function sendToUi(channel, payload) {
  try {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(channel, payload);
    }
  } catch (_) {
    // ignore
  }
}

function safeRemoveDir(dirPath) {
  try {
    if (fs.existsSync(dirPath)) {
      fs.rmSync(dirPath, { recursive: true, force: true });
    }
  } catch (_) {
    // best-effort
  }
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    backgroundColor: '#0b0b0b',
    title: 'TRUMA Browser',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webviewTag: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, 'index.html'));

  win.webContents.setWindowOpenHandler(({ url }) => {
    win.webContents.send('truma-open-url', url);
    return { action: 'deny' };
  });

  return win;
}

ipcMain.handle('truma-open-downloaded-file', async (_e, filePath) => {
  if (!filePath) return false;
  try {
    await shell.openPath(String(filePath));
    return true;
  } catch (_) {
    return false;
  }
});

ipcMain.handle('truma-show-downloaded-in-folder', async (_e, filePath) => {
  if (!filePath) return false;
  try {
    shell.showItemInFolder(String(filePath));
    return true;
  } catch (_) {
    return false;
  }
});

ipcMain.handle('truma-clear-download-history', async () => {
  sendToUi('truma-download-event', { type: 'clear' });
  return true;
});

ipcMain.handle('truma-set-homepage-shortcuts', async (_e, shortcuts) => {
  if (Array.isArray(shortcuts)) {
    homepageShortcuts = shortcuts
      .filter(s => s && typeof s.url === 'string' && typeof s.label === 'string')
      .slice(0, 8)
      .map(s => ({
        label: String(s.label).slice(0, 32),
        url: String(s.url).slice(0, 512),
        icon: s.icon ? String(s.icon).slice(0, 5) : undefined
      }));
  }
  // New tabs will use updated HTML automatically.
  return true;
});

ipcMain.handle('truma-set-adblock-level', async (_e, level) => {
  const v = String(level || '').toLowerCase();
  if (v === 'off' || v === 'basic' || v === 'strict') {
    privacyManager.updateModuleConfig('trackerBlocking', { level: v });
  }
  return privacyManager.config.trackerBlocking.level;
});

// Privacy Dashboard IPC handlers
ipcMain.handle('get-privacy-stats', async () => {
  return privacyManager.getStats();
});

ipcMain.handle('toggle-privacy-module', async (_e, module, enabled) => {
  return privacyManager.toggleModule(module, enabled);
});

ipcMain.handle('update-privacy-config', async (_e, module, config) => {
  return privacyManager.updateModuleConfig(module, config);
});

ipcMain.handle('clear-all-data', async () => {
  if (privacyManager.modules.sessionProtection) {
    return await privacyManager.modules.sessionProtection.wipe();
  }
  return null;
});

ipcMain.handle('reset-privacy-stats', async () => {
  privacyManager.resetStats();
  return true;
});

ipcMain.handle('export-privacy-settings', async () => {
  return privacyManager.config;
});

ipcMain.handle('handle-permission-response', async (_e, requestId, granted) => {
  if (privacyManager.modules.permissionProtection) {
    privacyManager.modules.permissionProtection.handlePermissionResponse(requestId, granted);
  }
  return true;
});

app.whenReady().then(async () => {
  safeRemoveDir(TEMP_USER_DATA_DIR);
  app.setPath('userData', TEMP_USER_DATA_DIR);

  const tempSess = session.fromPartition('temp:truma');
  
  // Initialize Privacy Manager
  await privacyManager.initialize(tempSess, null);

  try {
    tempSess.protocol.registerStringProtocol('truma', (request, callback) => {
      try {
        const u = new URL(request.url);
        // Serve homepage at truma://home
        if (u.hostname === 'home') {
          return callback({ data: getTrumaHomepageHtml(), mimeType: 'text/html' });
        }
        
        // Serve privacy dashboard at truma://privacy
        if (u.hostname === 'privacy') {
          const dashboardPath = path.join(__dirname, 'privacy', 'privacy-dashboard.html');
          const dashboardHtml = fs.readFileSync(dashboardPath, 'utf8');
          return callback({ data: dashboardHtml, mimeType: 'text/html' });
        }

        return callback({
          data: '<!doctype html><meta charset="utf-8"><title>Not Found</title><h1>TRUMA: Not Found</h1>',
          mimeType: 'text/html'
        });
      } catch (_) {
        return callback({
          data: '<!doctype html><meta charset="utf-8"><title>Error</title><h1>TRUMA: Error</h1>',
          mimeType: 'text/html'
        });
      }
    });
  } catch (_) {
    // best-effort
  }
  
  try {
    await tempSess.clearStorageData();
    await tempSess.clearCache();
  } catch (_) {
    // best-effort
  }

  mainWindow = createWindow();
  
  // Update privacy manager with main window reference
  privacyManager.mainWindow = mainWindow;

  // Register global keyboard shortcuts
  globalShortcut.register('CommandOrControl+T', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'new-tab');
    }
  });

  globalShortcut.register('CommandOrControl+W', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'close-tab');
    }
  });

  globalShortcut.register('CommandOrControl+R', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'reload');
    }
  });

  globalShortcut.register('F5', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'reload');
    }
  });

  globalShortcut.register('CommandOrControl+L', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'focus-url');
    }
  });

  globalShortcut.register('CommandOrControl+F', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'find');
    }
  });

  globalShortcut.register('F12', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'devtools');
    }
  });

  globalShortcut.register('CommandOrControl+Equal', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'zoom-in');
    }
  });

  globalShortcut.register('CommandOrControl+Minus', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'zoom-out');
    }
  });

  globalShortcut.register('CommandOrControl+0', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'zoom-reset');
    }
  });

  globalShortcut.register('CommandOrControl+U', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('shortcut', 'view-source');
    }
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('web-contents-created', (_event, contents) => {
  contents.on('will-attach-webview', (_e, webPreferences) => {
    webPreferences.partition = 'temp:truma';
    webPreferences.nodeIntegration = false;
    webPreferences.contextIsolation = true;
    webPreferences.webviewTag = true;
    webPreferences.sandbox = true;
  });

  // Block popups
  contents.setWindowOpenHandler(({ url }) => {
    console.log(`[PopupBlocker] Blocked: ${url}`);
    sendToUi('blocked-request', 'popup');
    return { action: 'deny' };
  });

  contents.on('will-download', async (event, item) => {
    const downloadId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    let filePath = '';
    try {
      filePath = path.join(app.getPath('downloads'), item.getFilename());
      item.setSavePath(filePath);
    } catch (_) {
      // best-effort
    }

    sendToUi('truma-download-event', {
      type: 'started',
      id: downloadId,
      filename: item.getFilename(),
      url: item.getURL(),
      filePath,
      totalBytes: item.getTotalBytes ? item.getTotalBytes() : 0
    });

    item.on('updated', (_e, state) => {
      try {
        const total = item.getTotalBytes ? item.getTotalBytes() : 0;
        const received = item.getReceivedBytes ? item.getReceivedBytes() : 0;
        const percent = total > 0 ? Math.round((received / total) * 100) : 0;
        sendToUi('truma-download-event', {
          type: 'progress',
          id: downloadId,
          state,
          receivedBytes: received,
          totalBytes: total,
          percent
        });
      } catch (_) {
        // ignore
      }
    });

    item.on('done', async (_e, state) => {
      sendToUi('truma-download-event', {
        type: 'done',
        id: downloadId,
        state,
        filePath
      });
      if (state === 'completed' || state === 'cancelled') return;
      try {
        await dialog.showMessageBox({
          type: 'warning',
          title: 'Download',
          message: `Download did not complete: ${state}`
        });
      } catch (_) {
        // ignore
      }
    });

    event.preventDefault();
    item.resume();
  });
});

app.on('before-quit', async () => {
  // Unregister all shortcuts
  globalShortcut.unregisterAll();
  
  // Cleanup privacy manager (auto-wipe session data)
  await privacyManager.cleanup();
  
  try {
    const tempSess = session.fromPartition('temp:truma');
    await tempSess.clearStorageData();
    await tempSess.clearCache();
  } catch (_) {
    // best-effort
  }

  safeRemoveDir(TEMP_USER_DATA_DIR);
});
