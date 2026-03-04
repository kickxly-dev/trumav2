const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');

// In-memory settings (zero persistence principle)
let appSettings = {
  autoScanOnLaunch: true,
  defaultSelection: 'recommended', // 'recommended', 'all', 'none'
  scheduledClean: false,
  scheduleInterval: 'weekly', // 'daily', 'weekly', 'monthly'
  lastCleanDate: null
};

// Load settings from a temp file if exists (session-only)
function loadSettings() {
  try {
    const settingsPath = path.join(os.tmpdir(), 'truma-cleaner-settings.json');
    if (fs.existsSync(settingsPath)) {
      const data = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
      appSettings = { ...appSettings, ...data };
    }
  } catch (_) {
    // ignore
  }
}

function saveSettings() {
  try {
    const settingsPath = path.join(os.tmpdir(), 'truma-cleaner-settings.json');
    fs.writeFileSync(settingsPath, JSON.stringify(appSettings), 'utf8');
  } catch (_) {
    // ignore
  }
}

loadSettings();

function createWindow() {
  const win = new BrowserWindow({
    width: 1040,
    height: 720,
    backgroundColor: '#0b0b0b',
    title: 'TRUMA Cleaner',
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

function safeStat(p) {
  try {
    return fs.statSync(p);
  } catch (_) {
    return null;
  }
}

function formatRoot(rootPath, label) {
  return {
    id: label.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
    label,
    rootPath,
    recommended: true,
    caution: false
  };
}

function makeRoot(id, label, rootPath, opts) {
  return {
    id,
    label,
    rootPath,
    recommended: opts && typeof opts.recommended === 'boolean' ? opts.recommended : true,
    caution: opts && typeof opts.caution === 'boolean' ? opts.caution : false,
    warning: opts && opts.warning ? opts.warning : null,
    special: opts && opts.special ? opts.special : null
  };
}

function getScanRoots() {
  const roots = [];
  const tmp = os.tmpdir();
  if (tmp) roots.push(makeRoot('temp-files', 'Temp Files', tmp, { recommended: true, caution: false }));

  const winTemp = process.env.TEMP || process.env.TMP;
  if (winTemp && winTemp !== tmp) roots.push(makeRoot('windows-temp', 'Windows Temp', winTemp, { recommended: true, caution: false }));

  const appData = process.env.APPDATA;
  const localAppData = process.env.LOCALAPPDATA;
  const programData = process.env.PROGRAMDATA;
  const windir = process.env.WINDIR;
  const userProfile = process.env.USERPROFILE;

  if (appData) {
    const recent = path.join(appData, 'Microsoft', 'Windows', 'Recent');
    roots.push(makeRoot('recent-items', 'Recent Items', recent, { recommended: true, caution: false }));

    const autoDest = path.join(recent, 'AutomaticDestinations');
    roots.push(makeRoot('recent-jumplists-auto', 'Jump Lists (Auto)', autoDest, { recommended: true, caution: true }));

    const customDest = path.join(recent, 'CustomDestinations');
    roots.push(makeRoot('recent-jumplists-custom', 'Jump Lists (Custom)', customDest, { recommended: false, caution: true }));
  }

  if (localAppData) {
    const crashDumps = path.join(localAppData, 'CrashDumps');
    roots.push(makeRoot('crash-dumps', 'Crash Dumps', crashDumps, { recommended: false, caution: true }));

    // Browser caches - Chrome
    const chromeCache = path.join(localAppData, 'Google', 'Chrome', 'User Data', 'Default', 'Cache');
    roots.push(makeRoot('chrome-cache', 'Chrome Cache', chromeCache, { 
      recommended: false, 
      caution: true, 
      warning: 'Will clear browsing cache. You may need to re-login to websites.' 
    }));

    const chromeCodeCache = path.join(localAppData, 'Google', 'Chrome', 'User Data', 'Default', 'Code Cache');
    roots.push(makeRoot('chrome-code-cache', 'Chrome Code Cache', chromeCodeCache, { 
      recommended: false, 
      caution: true, 
      warning: 'Clears JavaScript bytecode cache. Sites may load slower initially.' 
    }));

    // Browser caches - Edge
    const edgeCache = path.join(localAppData, 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache');
    roots.push(makeRoot('edge-cache', 'Edge Cache', edgeCache, { 
      recommended: false, 
      caution: true, 
      warning: 'Will clear browsing cache. You may need to re-login to websites.' 
    }));

    // Browser caches - Firefox
    const firefoxProfilePath = path.join(localAppData, 'Mozilla', 'Firefox', 'Profiles');
    if (fs.existsSync(firefoxProfilePath)) {
      try {
        const profiles = fs.readdirSync(firefoxProfilePath);
        profiles.forEach((profile, idx) => {
          const cachePath = path.join(firefoxProfilePath, profile, 'cache2');
          roots.push(makeRoot(`firefox-cache-${idx}`, `Firefox Cache (${profile})`, cachePath, { 
            recommended: false, 
            caution: true, 
            warning: 'Will clear browsing cache. You may need to re-login to websites.' 
          }));
        });
      } catch (_) {}
    }
  }

  if (programData) {
    const werArchive = path.join(programData, 'Microsoft', 'Windows', 'WER', 'ReportArchive');
    roots.push(makeRoot('wer-archive', 'Windows Error Reports (Archive)', werArchive, { recommended: false, caution: true }));

    const werQueue = path.join(programData, 'Microsoft', 'Windows', 'WER', 'ReportQueue');
    roots.push(makeRoot('wer-queue', 'Windows Error Reports (Queue)', werQueue, { recommended: false, caution: true }));
  }

  if (windir) {
    const systemTemp = path.join(windir, 'Temp');
    roots.push(makeRoot('system-temp', 'System Temp (Admin may be needed)', systemTemp, { recommended: false, caution: true }));
  }

  // Recycle Bin
  if (userProfile) {
    const recycleBin = path.join(userProfile, 'AppData', 'Local', 'Microsoft', 'Windows', 'Explorer');
    // Recycle bin is special - we'll handle it separately
    roots.push(makeRoot('recycle-bin', 'Recycle Bin (All Drives)', '$RECYCLE.BIN', { 
      recommended: false, 
      caution: true, 
      warning: 'PERMANENTLY deletes all items in Recycle Bin. Cannot be undone.',
      special: 'recycle-bin'
    }));
  }

  return roots;
}

function walkAndMeasure(dirPath, opts) {
  const maxFiles = opts.maxFiles ?? 60000;
  const maxDepth = opts.maxDepth ?? 12;

  let totalBytes = 0;
  let fileCount = 0;
  let dirCount = 0;
  const largest = [];

  function considerLargest(filePath, size) {
    if (!size || size <= 0) return;
    largest.push({ path: filePath, size });
    largest.sort((a, b) => b.size - a.size);
    if (largest.length > 12) largest.length = 12;
  }

  function walk(current, depth) {
    if (fileCount >= maxFiles) return;
    if (depth > maxDepth) return;

    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_) {
      return;
    }

    for (const ent of entries) {
      if (fileCount >= maxFiles) return;
      const full = path.join(current, ent.name);

      if (ent.isSymbolicLink && ent.isSymbolicLink()) {
        continue;
      }

      if (ent.isDirectory()) {
        dirCount += 1;
        walk(full, depth + 1);
      } else if (ent.isFile()) {
        const st = safeStat(full);
        if (!st) continue;
        totalBytes += st.size;
        fileCount += 1;
        considerLargest(full, st.size);
      }
    }
  }

  const rootStat = safeStat(dirPath);
  if (!rootStat || !rootStat.isDirectory()) {
    return {
      rootPath: dirPath,
      totalBytes: 0,
      fileCount: 0,
      dirCount: 0,
      largest: []
    };
  }

  walk(dirPath, 0);

  return {
    rootPath: dirPath,
    totalBytes,
    fileCount,
    dirCount,
    largest
  };
}

function safeCleanRoot(rootPath, special) {
  let deletedFiles = 0;
  let deletedDirs = 0;
  let failed = 0;
  const failedPaths = [];

  // Special handling for Recycle Bin
  if (special === 'recycle-bin') {
    return emptyRecycleBin();
  }

  let entries;
  try {
    entries = fs.readdirSync(rootPath, { withFileTypes: true });
  } catch (_) {
    return { deletedFiles, deletedDirs, failed, failedPaths };
  }

  for (const ent of entries) {
    const full = path.join(rootPath, ent.name);
    try {
      if (ent.isDirectory()) {
        fs.rmSync(full, { recursive: true, force: true });
        deletedDirs += 1;
      } else {
        fs.rmSync(full, { force: true });
        deletedFiles += 1;
      }
    } catch (_) {
      failed += 1;
      if (failedPaths.length < 20) failedPaths.push(full);
    }
  }

  return { deletedFiles, deletedDirs, failed, failedPaths };
}

// Special handler for Recycle Bin
function emptyRecycleBin() {
  let deletedFiles = 0;
  let deletedDirs = 0;
  let failed = 0;
  const failedPaths = [];
  
  try {
    // Use PowerShell to empty recycle bin
    const { execSync } = require('child_process');
    execSync('powershell -Command "Clear-RecycleBin -Confirm:$false -Force"', { 
      timeout: 30000,
      windowsHide: true 
    });
    // We can't get exact counts for recycle bin via this method
    deletedFiles = 1; // Placeholder to indicate success
  } catch (e) {
    failed += 1;
    failedPaths.push('Recycle Bin (some items may be in use)');
  }
  
  return { deletedFiles, deletedDirs, failed, failedPaths };
}

ipcMain.handle('truma-cleaner-scan', async () => {
  const roots = getScanRoots();
  const results = roots.map((r) => {
    if (r.special === 'recycle-bin') {
      // For recycle bin, estimate size differently
      const rbSize = getRecycleBinSize();
      return {
        id: r.id,
        label: r.label,
        rootPath: r.rootPath,
        recommended: !!r.recommended,
        caution: !!r.caution,
        warning: r.warning,
        special: r.special,
        totalBytes: rbSize,
        fileCount: rbSize > 0 ? 1 : 0,
        dirCount: 0,
        largest: []
      };
    }
    const measure = walkAndMeasure(r.rootPath, { maxFiles: 60000, maxDepth: 12 });
    return {
      id: r.id,
      label: r.label,
      rootPath: r.rootPath,
      recommended: !!r.recommended,
      caution: !!r.caution,
      warning: r.warning,
      special: r.special,
      totalBytes: measure.totalBytes,
      fileCount: measure.fileCount,
      dirCount: measure.dirCount,
      largest: measure.largest
    };
  });

  const totalBytes = results.reduce((a, b) => a + (b.totalBytes || 0), 0);
  return { roots: results, totalBytes, settings: appSettings };
});

ipcMain.handle('truma-cleaner-clean', async (_e, rootIds) => {
  const roots = getScanRoots();
  const idSet = new Set(Array.isArray(rootIds) ? rootIds.map(String) : []);

  const cleaned = [];
  for (const r of roots) {
    if (idSet.size && !idSet.has(String(r.id))) continue;
    const out = safeCleanRoot(r.rootPath, r.special);
    cleaned.push({ id: r.id, label: r.label, rootPath: r.rootPath, ...out });
  }
  
  // Update last clean date
  appSettings.lastCleanDate = Date.now();
  saveSettings();

  return { cleaned };
});

// Get Recycle Bin size estimate
function getRecycleBinSize() {
  try {
    const { execSync } = require('child_process');
    const result = execSync('powershell -Command "(Get-ChildItem -Path C:\\\\$Recycle.Bin -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum"', {
      encoding: 'utf8',
      timeout: 10000,
      windowsHide: true
    });
    const size = parseInt(result.trim(), 10);
    return isNaN(size) ? 0 : size;
  } catch (_) {
    return 0;
  }
}

// Settings IPC handlers
ipcMain.handle('truma-cleaner-get-settings', async () => {
  return { ...appSettings };
});

ipcMain.handle('truma-cleaner-save-settings', async (_e, newSettings) => {
  appSettings = { ...appSettings, ...newSettings };
  saveSettings();
  return { ...appSettings };
});

// Check if scheduled clean is due
function checkScheduledClean() {
  if (!appSettings.scheduledClean || !appSettings.lastCleanDate) return false;
  
  const now = Date.now();
  const last = appSettings.lastCleanDate;
  const oneDay = 24 * 60 * 60 * 1000;
  
  let intervalMs;
  switch (appSettings.scheduleInterval) {
    case 'daily': intervalMs = oneDay; break;
    case 'weekly': intervalMs = 7 * oneDay; break;
    case 'monthly': intervalMs = 30 * oneDay; break;
    default: intervalMs = 7 * oneDay;
  }
  
  return (now - last) >= intervalMs;
}

app.whenReady().then(() => {
  createWindow();
  
  // Check if scheduled clean is due and show notification
  if (checkScheduledClean()) {
    const win = BrowserWindow.getAllWindows()[0];
    if (win) {
      win.webContents.once('dom-ready', () => {
        win.webContents.send('truma-cleaner-scheduled-due');
      });
    }
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
