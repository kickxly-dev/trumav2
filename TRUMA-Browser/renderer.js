const tabsEl = document.getElementById('tabs');
const viewsEl = document.getElementById('views');
const omniboxEl = document.getElementById('omnibox');
const statusTextEl = document.getElementById('status-text');

const btnBack = document.getElementById('btn-back');
const btnForward = document.getElementById('btn-forward');
const btnReload = document.getElementById('btn-reload');
const btnGo = document.getElementById('btn-go');
const btnNewTab = document.getElementById('btn-new-tab');

let tabs = [];
let activeTabId = null;
let tabSeq = 0;

function setStatus(text) {
  statusTextEl.textContent = text;
}

function isProbablyUrl(input) {
  const v = input.trim();
  if (!v) return false;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v)) return true;
  if (v.startsWith('http://') || v.startsWith('https://')) return true;
  if (v.includes(' ') || v.includes('\n') || v.includes('\t')) return false;
  if (v.includes('.')) return true;
  return false;
}

function toNavigateUrl(input) {
  const raw = input.trim();
  if (!raw) return 'https://duckduckgo.com';

  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) return raw;
  if (raw.startsWith('http://') || raw.startsWith('https://')) return raw;

  if (isProbablyUrl(raw)) {
    return `https://${raw}`;
  }

  const q = encodeURIComponent(raw);
  return `https://duckduckgo.com/?q=${q}`;
}

function createWebview(tabId) {
  const wv = document.createElement('webview');
  wv.className = 'webview';
  wv.setAttribute('partition', 'temp:truma');
  wv.setAttribute('allowpopups', '');
  wv.dataset.tabId = String(tabId);

  wv.addEventListener('did-start-loading', () => {
    setStatus('Loading...');
    const tab = tabs.find(t => t.id === tabId);
    if (tab) {
      tab.loading = true;
      renderTabs();
    }
  });

  wv.addEventListener('did-stop-loading', () => {
    setStatus('Ready');
    const tab = tabs.find(t => t.id === tabId);
    if (tab) {
      tab.loading = false;
      renderTabs();
    }
    try {
      if (activeTabId === tabId) {
        omniboxEl.value = wv.getURL() || '';
      }
    } catch (_) {
      // ignore
    }
  });

  wv.addEventListener('page-title-updated', (e) => {
    const tab = tabs.find(t => t.id === tabId);
    if (!tab) return;
    tab.title = e.title || 'New Tab';
    renderTabs();
  });

  wv.addEventListener('page-favicon-updated', (e) => {
    const tab = tabs.find(t => t.id === tabId);
    if (!tab) return;
    tab.favicon = e.favicons && e.favicons[0] ? e.favicons[0] : null;
    renderTabs();
  });

  wv.addEventListener('did-navigate-in-page', () => {
    try {
      if (activeTabId === tabId) omniboxEl.value = wv.getURL() || '';
    } catch (_) {
      // ignore
    }
  });

  wv.addEventListener('did-navigate', () => {
    try {
      const url = wv.getURL();
      if (activeTabId === tabId) omniboxEl.value = url || '';
      trackSite(url);
      addToHistory(url, wv.getTitle());
    } catch (_) {
      // ignore
    }
  });

  wv.addEventListener('did-fail-load', () => {
    setStatus('Failed to load');
    const tab = tabs.find(t => t.id === tabId);
    if (tab) {
      tab.loading = false;
      renderTabs();
    }
  });

  wv.addEventListener('found-in-page', (e) => {
    const result = e.result;
    if (result && result.activeMatchOrdinal !== undefined) {
      findCount.textContent = `${result.activeMatchOrdinal}/${result.matches}`;
    }
  });

  return wv;
}

function addTab(initialUrl) {
  const id = ++tabSeq;

  const webview = createWebview(id);
  viewsEl.appendChild(webview);

  const tab = {
    id,
    title: 'New Tab',
    favicon: null,
    loading: false,
    webview
  };

  tabs.push(tab);
  setActiveTab(id);

  navigateActive(initialUrl || 'https://duckduckgo.com');
}

function removeTab(tabId) {
  const idx = tabs.findIndex(t => t.id === tabId);
  if (idx === -1) return;

  const tab = tabs[idx];
  try {
    tab.webview.remove();
  } catch (_) {
    // ignore
  }

  tabs.splice(idx, 1);

  if (activeTabId === tabId) {
    const next = tabs[idx] || tabs[idx - 1] || tabs[0];
    if (next) setActiveTab(next.id);
    else {
      activeTabId = null;
      omniboxEl.value = '';
      setStatus('Ready');
    }
  }

  renderTabs();
}

function setActiveTab(tabId) {
  activeTabId = tabId;

  for (const tab of tabs) {
    tab.webview.classList.toggle('active', tab.id === tabId);
  }

  const active = getActiveTab();
  if (active) {
    try {
      omniboxEl.value = active.webview.getURL() || '';
    } catch (_) {
      omniboxEl.value = '';
    }
  }

  renderTabs();
}

function getActiveTab() {
  return tabs.find(t => t.id === activeTabId) || null;
}

function navigateActive(input) {
  const active = getActiveTab();
  if (!active) return;

  const url = toNavigateUrl(input);
  setStatus(`Opening ${url}`);

  try {
    active.webview.setAttribute('src', url);
    if (typeof active.webview.loadURL === 'function') {
      active.webview.loadURL(url);
    }
  } catch (_) {
    setStatus('Navigation error');
  }
}

function renderTabs() {
  tabsEl.innerHTML = '';

  for (const tab of tabs) {
    const tabBtn = document.createElement('div');
    tabBtn.className = 'tab' + (tab.id === activeTabId ? ' active' : '');

    // Favicon or loading spinner
    const favicon = document.createElement('div');
    if (tab.loading) {
      favicon.className = 'tab-loading';
    } else {
      favicon.className = 'tab-favicon';
      if (tab.favicon) {
        favicon.innerHTML = `<img src="${tab.favicon}" style="width:16px;height:16px;border-radius:2px;" onerror="this.style.display='none'"/>`;
      } else {
        favicon.textContent = tab.title ? tab.title.charAt(0).toUpperCase() : '●';
      }
    }

    const title = document.createElement('div');
    title.className = 'tab-title';
    title.textContent = tab.title || 'New Tab';

    const close = document.createElement('button');
    close.className = 'tab-close';
    close.textContent = '×';

    tabBtn.addEventListener('click', () => setActiveTab(tab.id));
    close.addEventListener('click', (e) => {
      e.stopPropagation();
      removeTab(tab.id);
    });

    tabBtn.appendChild(favicon);
    tabBtn.appendChild(title);
    tabBtn.appendChild(close);

    tabsEl.appendChild(tabBtn);
  }
}

btnBack.addEventListener('click', () => {
  const t = getActiveTab();
  if (!t) return;
  try {
    if (t.webview.canGoBack()) t.webview.goBack();
  } catch (_) {
    // ignore
  }
});

btnForward.addEventListener('click', () => {
  const t = getActiveTab();
  if (!t) return;
  try {
    if (t.webview.canGoForward()) t.webview.goForward();
  } catch (_) {
    // ignore
  }
});

btnReload.addEventListener('click', () => {
  const t = getActiveTab();
  if (!t) return;
  try {
    t.webview.reload();
  } catch (_) {
    // ignore
  }
});

btnGo.addEventListener('click', () => {
  navigateActive(omniboxEl.value);
});

omniboxEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    navigateActive(omniboxEl.value);
  }
});

btnNewTab.addEventListener('click', () => {
  addTab(HOMEPAGE_URL);
});

if (window.truma && typeof window.truma.onOpenUrl === 'function') {
  window.truma.onOpenUrl((url) => {
    if (!url) return;
    addTab(url);
  });
}

// Welcome screen and startup flow
const welcomeScreen = document.getElementById('welcome-screen');

// Built-in TRUMA homepage served by Electron main process
const HOMEPAGE_URL = 'truma://home';

function hideWelcomeScreen() {
  welcomeScreen.classList.add('fade-out');
  setTimeout(() => {
    welcomeScreen.style.display = 'none';
  }, 600);
}

function initBrowser() {
  // Add first tab with TRUMA homepage
  addTab(HOMEPAGE_URL);
  
  // Hide welcome screen after animation completes
  setTimeout(hideWelcomeScreen, 2200);
  omniboxEl.placeholder = 'Search or type URL...';
}

// Start the browser after a brief delay to show welcome screen
setTimeout(initBrowser, 500);

// ==================== KEYBOARD SHORTCUTS FROM MAIN PROCESS ====================

if (window.truma && typeof window.truma.onShortcut === 'function') {
  window.truma.onShortcut((action) => {
    switch (action) {
      case 'new-tab':
        addTab(HOMEPAGE_URL);
        break;
      case 'close-tab':
        if (activeTabId) removeTab(activeTabId);
        break;
      case 'reload':
        const t = getActiveTab();
        if (t) {
          try { t.webview.reload(); } catch (_) {}
        }
        break;
      case 'focus-url':
        omniboxEl.focus();
        omniboxEl.select();
        break;
      case 'find':
        toggleFindBar();
        break;
      case 'devtools':
        const td = getActiveTab();
        if (td) {
          try {
            if (td.webview.isDevToolsOpened()) {
              td.webview.closeDevTools();
            } else {
              td.webview.openDevTools();
            }
          } catch (_) {}
        }
        break;
      case 'zoom-in':
        zoomIn();
        break;
      case 'zoom-out':
        zoomOut();
        break;
      case 'zoom-reset':
        zoomReset();
        break;
      case 'view-source':
        viewSource();
        break;
    }
  });
}

// ==================== PANELS (Bookmarks, Downloads, Settings) ====================

// Panel Elements
const btnBookmarks = document.getElementById('btn-bookmarks');
const btnHistory = document.getElementById('btn-history');
const btnDownloads = document.getElementById('btn-downloads');
const btnSettings = document.getElementById('btn-settings');

const bookmarksPanel = document.getElementById('bookmarks-panel');
const historyPanel = document.getElementById('history-panel');
const downloadsPanel = document.getElementById('downloads-panel');
const settingsPanel = document.getElementById('settings-panel');

const btnCloseBookmarks = document.getElementById('btn-close-bookmarks');
const btnCloseHistory = document.getElementById('btn-close-history');
const btnCloseDownloads = document.getElementById('btn-close-downloads');
const btnCloseSettings = document.getElementById('btn-close-settings');

const btnAddBookmark = document.getElementById('btn-add-bookmark');
const bookmarksList = document.getElementById('bookmarks-list');
const historyList = document.getElementById('history-list');
const downloadsList = document.getElementById('downloads-list');
const btnClearDownloads = document.getElementById('btn-clear-downloads');
const btnClearHistory = document.getElementById('btn-clear-history');

const drawer = document.getElementById('drawer');
const drawerOverlay = document.getElementById('drawer-overlay');

// In-memory data (zero-data principle)
let bookmarks = [];
let history = [];
let downloads = [];
let settings = {
  adBlock: true,
  blockThirdPartyCookies: true,
  strictHttps: false
};

function closeDrawer() {
  drawer.classList.add('hidden');
  drawerOverlay.classList.add('hidden');
  bookmarksPanel.classList.add('hidden');
  historyPanel.classList.add('hidden');
  downloadsPanel.classList.add('hidden');
  settingsPanel.classList.add('hidden');
}

// Toggle Panel
function togglePanel(panel) {
  const isHidden = panel.classList.contains('hidden');
  
  // Close all panels first
  bookmarksPanel.classList.add('hidden');
  historyPanel.classList.add('hidden');
  downloadsPanel.classList.add('hidden');
  settingsPanel.classList.add('hidden');
  
  // Open requested panel if it was hidden
  if (isHidden) {
    drawer.classList.remove('hidden');
    drawerOverlay.classList.remove('hidden');
    panel.classList.remove('hidden');
  } else {
    closeDrawer();
  }
}

// Panel Event Listeners
btnBookmarks.addEventListener('click', () => togglePanel(bookmarksPanel));
btnHistory.addEventListener('click', () => togglePanel(historyPanel));
btnDownloads.addEventListener('click', () => togglePanel(downloadsPanel));
btnSettings.addEventListener('click', () => togglePanel(settingsPanel));

btnCloseBookmarks.addEventListener('click', closeDrawer);
btnCloseHistory.addEventListener('click', closeDrawer);
btnCloseDownloads.addEventListener('click', closeDrawer);
btnCloseSettings.addEventListener('click', closeDrawer);

drawerOverlay.addEventListener('click', closeDrawer);

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeDrawer();
    closeFindBar();
  }

  // Keyboard shortcuts
  const isCtrl = e.ctrlKey || e.metaKey;

  // Ctrl+T - New Tab
  if (isCtrl && e.key === 't') {
    e.preventDefault();
    addTab(HOMEPAGE_URL);
  }

  // Ctrl+W - Close Tab
  if (isCtrl && e.key === 'w') {
    e.preventDefault();
    if (activeTabId) removeTab(activeTabId);
  }

  // Ctrl+R or F5 - Reload
  if ((isCtrl && e.key === 'r') || e.key === 'F5') {
    e.preventDefault();
    const t = getActiveTab();
    if (t) {
      try { t.webview.reload(); } catch (_) {}
    }
  }

  // Ctrl+L - Focus omnibox
  if (isCtrl && e.key === 'l') {
    e.preventDefault();
    omniboxEl.focus();
    omniboxEl.select();
  }

  // F12 - Toggle DevTools
  if (e.key === 'F12') {
    e.preventDefault();
    const t = getActiveTab();
    if (t) {
      try {
        if (t.webview.isDevToolsOpened()) {
          t.webview.closeDevTools();
        } else {
          t.webview.openDevTools();
        }
      } catch (_) {}
    }
  }

  // Ctrl+F - Find in page
  if (isCtrl && e.key === 'f') {
    e.preventDefault();
    toggleFindBar();
  }

  // Ctrl+= - Zoom in
  if (isCtrl && e.key === '=') {
    e.preventDefault();
    zoomIn();
  }

  // Ctrl+- - Zoom out
  if (isCtrl && e.key === '-') {
    e.preventDefault();
    zoomOut();
  }

  // Ctrl+0 - Reset zoom
  if (isCtrl && e.key === '0') {
    e.preventDefault();
    zoomReset();
  }
});

// ==================== BOOKMARKS ====================

function renderBookmarks() {
  if (bookmarks.length === 0) {
    bookmarksList.innerHTML = '<div class="empty-state">No bookmarks yet. Click "+ Add Current Page" to bookmark.</div>';
    return;
  }
  
  bookmarksList.innerHTML = '';
  bookmarks.forEach((bookmark, index) => {
    const item = document.createElement('div');
    item.className = 'bookmark-item';
    item.innerHTML = `
      <div class="bookmark-favicon">★</div>
      <div class="bookmark-info">
        <div class="bookmark-title">${bookmark.title}</div>
        <div class="bookmark-url">${bookmark.url}</div>
      </div>
      <button class="bookmark-delete" data-index="${index}">×</button>
    `;
    
    item.addEventListener('click', (e) => {
      if (!e.target.classList.contains('bookmark-delete')) {
        addTab(bookmark.url);
        bookmarksPanel.classList.add('hidden');
      }
    });
    
    bookmarksList.appendChild(item);
  });
  
  // Delete handlers
  bookmarksList.querySelectorAll('.bookmark-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const index = parseInt(btn.dataset.index);
      bookmarks.splice(index, 1);
      renderBookmarks();
    });
  });
}

btnAddBookmark.addEventListener('click', () => {
  const active = getActiveTab();
  if (!active) return;
  
  try {
    const url = active.webview.getURL();
    const title = active.webview.getTitle() || 'Untitled';
    
    // Check if already bookmarked
    if (bookmarks.some(b => b.url === url)) {
      setStatus('Already bookmarked');
      return;
    }
    
    bookmarks.push({ title, url });
    renderBookmarks();
    setStatus('Bookmark added');
  } catch (_) {
    setStatus('Failed to add bookmark');
  }
});

// ==================== HISTORY ====================

function addToHistory(url, title) {
  if (!url || url.startsWith('truma://')) return;
  
  // Remove if already exists (to move to top)
  const existingIndex = history.findIndex(h => h.url === url);
  if (existingIndex !== -1) {
    history.splice(existingIndex, 1);
  }
  
  // Add to beginning
  history.unshift({
    url,
    title: title || url,
    timestamp: Date.now()
  });
  
  // Keep only last 100 items
  if (history.length > 100) {
    history = history.slice(0, 100);
  }
  
  renderHistory();
}

function renderHistory() {
  if (history.length === 0) {
    historyList.innerHTML = '<div class="empty-state">No history yet. Browse to see your history here.</div>';
    return;
  }
  
  historyList.innerHTML = '';
  history.forEach((item, index) => {
    const el = document.createElement('div');
    el.className = 'history-item';
    
    const timeAgo = getTimeAgo(item.timestamp);
    
    el.innerHTML = `
      <div class="history-favicon">📄</div>
      <div class="history-info">
        <div class="history-title">${item.title}</div>
        <div class="history-url">${item.url}</div>
      </div>
      <div class="history-time">${timeAgo}</div>
    `;
    
    el.addEventListener('click', () => {
      addTab(item.url);
      historyPanel.classList.add('hidden');
    });
    
    historyList.appendChild(el);
  });
}

function getTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

btnClearHistory.addEventListener('click', () => {
  history = [];
  renderHistory();
  setStatus('History cleared');
});

// ==================== DOWNLOADS ====================

function renderDownloads() {
  if (downloads.length === 0) {
    downloadsList.innerHTML = '<div class="empty-state">No active downloads</div>';
    return;
  }
  
  downloadsList.innerHTML = '';
  downloads.forEach(dl => {
    const item = document.createElement('div');
    item.className = 'download-item';
    const stateLabel = dl.state === 'completed' ? '✓ Done' : (dl.state === 'cancelled' ? '✕ Cancelled' : '⬇ Downloading');
    const pct = typeof dl.percent === 'number' ? dl.percent : 0;
    item.innerHTML = `
      <div class="download-filename">${dl.filename}</div>
      <div class="download-progress">
        <div class="download-progress-bar" style="width: ${pct}%"></div>
      </div>
      <div class="download-status">
        <span>${stateLabel}</span>
        <span>${pct}%</span>
      </div>
      <div class="download-actions">
        <button class="mini-btn" data-action="open" data-id="${dl.id}">Open</button>
        <button class="mini-btn" data-action="folder" data-id="${dl.id}">Folder</button>
      </div>
    `;
    downloadsList.appendChild(item);
  });

  downloadsList.querySelectorAll('button.mini-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const id = btn.dataset.id;
      const action = btn.dataset.action;
      const dl = downloads.find(d => String(d.id) === String(id));
      if (!dl || !dl.filePath) return;
      if (!window.truma) return;

      if (action === 'open') {
        await window.truma.openDownloadedFile(dl.filePath);
      } else if (action === 'folder') {
        await window.truma.showDownloadedInFolder(dl.filePath);
      }
    });
  });
}

btnClearDownloads.addEventListener('click', async () => {
  downloads = [];
  renderDownloads();
  if (window.truma && typeof window.truma.clearDownloadHistory === 'function') {
    await window.truma.clearDownloadHistory();
  }
});

// ==================== SETTINGS ====================

const settingAdBlock = document.getElementById('setting-adblock');
const settingCookies = document.getElementById('setting-cookies');
const settingHttps = document.getElementById('setting-https');
const settingAdblockLevel = document.getElementById('setting-adblock-level');
const btnSaveShortcuts = document.getElementById('btn-save-shortcuts');

// Load settings
settingAdBlock.checked = settings.adBlock;
settingCookies.checked = settings.blockThirdPartyCookies;
settingHttps.checked = settings.strictHttps;

// Setting change handlers
settingAdBlock.addEventListener('change', (e) => {
  settings.adBlock = e.target.checked;
  setStatus(settings.adBlock ? 'Ad blocker enabled' : 'Ad blocker disabled');

  if (window.truma && typeof window.truma.setAdblockLevel === 'function') {
    const next = settings.adBlock ? (settingAdblockLevel.value || 'basic') : 'off';
    window.truma.setAdblockLevel(next);
  }
});

settingCookies.addEventListener('change', (e) => {
  settings.blockThirdPartyCookies = e.target.checked;
  setStatus(settings.blockThirdPartyCookies ? 'Third-party cookies blocked' : 'Third-party cookies allowed');
});

settingHttps.addEventListener('change', (e) => {
  settings.strictHttps = e.target.checked;
  setStatus(settings.strictHttps ? 'Strict HTTPS enabled' : 'Strict HTTPS disabled');
});

settingAdblockLevel.addEventListener('change', async (e) => {
  const v = e.target.value;
  // keep checkbox in sync
  settingAdBlock.checked = v !== 'off';
  settings.adBlock = v !== 'off';

  if (window.truma && typeof window.truma.setAdblockLevel === 'function') {
    const applied = await window.truma.setAdblockLevel(v);
    setStatus(`Adblock level: ${applied}`);
  }
});

function collectShortcutEdits() {
  const rows = {};
  document.querySelectorAll('.shortcut-input').forEach((inp) => {
    const i = inp.dataset.i;
    const field = inp.dataset.field;
    if (!rows[i]) rows[i] = { label: '', url: '', icon: '' };
    rows[i][field] = inp.value.trim();
  });

  return Object.keys(rows)
    .sort((a, b) => Number(a) - Number(b))
    .map((k) => rows[k])
    .filter((r) => r.url && r.label)
    .map((r) => ({
      label: r.label,
      url: r.url,
      icon: r.icon || undefined
    }));
}

btnSaveShortcuts.addEventListener('click', async () => {
  const shortcuts = collectShortcutEdits();
  if (window.truma && typeof window.truma.setHomepageShortcuts === 'function') {
    await window.truma.setHomepageShortcuts(shortcuts);
    setStatus('Homepage shortcuts saved');
  }

  // If current tab is home, reload it to reflect new shortcuts.
  const active = getActiveTab();
  if (active) {
    try {
      const url = active.webview.getURL();
      if (url && url.startsWith('truma://home')) {
        active.webview.reload();
      }
    } catch (_) {
      // ignore
    }
  }
});

// Initialize empty states
renderBookmarks();
renderDownloads();

// ==================== THEME SETTINGS ====================

const settingThemeMode = document.getElementById('setting-theme-mode');
const accentBtns = document.querySelectorAll('.accent-btn');

// Apply saved theme on load
const savedTheme = localStorage.getItem('truma-theme') || 'dark';
const savedAccent = localStorage.getItem('truma-accent') || 'crimson';
document.documentElement.setAttribute('data-theme', savedTheme);
document.documentElement.setAttribute('data-accent', savedAccent);
settingThemeMode.value = savedTheme;
accentBtns.forEach(btn => {
  btn.classList.toggle('active', btn.dataset.accent === savedAccent);
});

settingThemeMode.addEventListener('change', (e) => {
  const theme = e.target.value;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('truma-theme', theme);
  setStatus(`Theme: ${theme}`);
});

accentBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    const accent = btn.dataset.accent;
    document.documentElement.setAttribute('data-accent', accent);
    localStorage.setItem('truma-accent', accent);
    accentBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    setStatus(`Accent: ${accent}`);
  });
});

// ==================== PASSWORD GENERATOR ====================

const passwordModal = document.getElementById('password-modal');
const passwordOutput = document.getElementById('password-output');
const passwordLength = document.getElementById('password-length');
const passwordLengthValue = document.getElementById('password-length-value');
const passwordCopy = document.getElementById('password-copy');
const passwordRegenerate = document.getElementById('password-regenerate');
const passwordModalClose = document.getElementById('password-modal-close');
const toolPasswordGen = document.getElementById('tool-password-gen');

const pwdUpper = document.getElementById('pwd-upper');
const pwdLower = document.getElementById('pwd-lower');
const pwdNumbers = document.getElementById('pwd-numbers');
const pwdSymbols = document.getElementById('pwd-symbols');

function generatePassword() {
  const length = parseInt(passwordLength.value);
  let chars = '';
  if (pwdUpper.checked) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (pwdLower.checked) chars += 'abcdefghijklmnopqrstuvwxyz';
  if (pwdNumbers.checked) chars += '0123456789';
  if (pwdSymbols.checked) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  if (!chars) {
    passwordOutput.textContent = 'Select at least one option';
    return;
  }
  
  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  passwordOutput.textContent = password;
}

passwordLength.addEventListener('input', () => {
  passwordLengthValue.textContent = passwordLength.value;
  generatePassword();
});

[pwdUpper, pwdLower, pwdNumbers, pwdSymbols].forEach(cb => {
  cb.addEventListener('change', generatePassword);
});

passwordRegenerate.addEventListener('click', generatePassword);

passwordCopy.addEventListener('click', async () => {
  const pwd = passwordOutput.textContent;
  if (pwd && pwd !== 'Select at least one option') {
    await navigator.clipboard.writeText(pwd);
    setStatus('Password copied!');
  }
});

toolPasswordGen.addEventListener('click', () => {
  generatePassword();
  passwordModal.classList.add('visible');
});

passwordModalClose.addEventListener('click', () => {
  passwordModal.classList.remove('visible');
});

passwordModal.addEventListener('click', (e) => {
  if (e.target === passwordModal) {
    passwordModal.classList.remove('visible');
  }
});

// ==================== PRIVACY STATS ====================

const privacyModal = document.getElementById('privacy-modal');
const privacyModalClose = document.getElementById('privacy-modal-close');
const toolPrivacyStats = document.getElementById('tool-privacy-stats');

const statAds = document.getElementById('stat-ads');
const statTrackers = document.getElementById('stat-trackers');
const statCookies = document.getElementById('stat-cookies');
const statHttps = document.getElementById('stat-https');
const statSites = document.getElementById('stat-sites');

let privacyStats = {
  ads: 0,
  trackers: 0,
  cookies: 0,
  https: 0,
  sites: new Set()
};

// Track sites visited
function trackSite(url) {
  try {
    const hostname = new URL(url).hostname;
    if (hostname && !privacyStats.sites.has(hostname)) {
      privacyStats.sites.add(hostname);
    }
  } catch (_) {}
}

// Update stats display
function updatePrivacyStatsDisplay() {
  statAds.textContent = privacyStats.ads;
  statTrackers.textContent = privacyStats.trackers;
  statCookies.textContent = privacyStats.cookies;
  statHttps.textContent = privacyStats.https;
  statSites.textContent = privacyStats.sites.size;
  const statPopups = document.getElementById('stat-popups');
  if (statPopups) statPopups.textContent = privacyStats.popups || 0;
}

toolPrivacyStats.addEventListener('click', () => {
  updatePrivacyStatsDisplay();
  privacyModal.classList.add('visible');
});

privacyModalClose.addEventListener('click', () => {
  privacyModal.classList.remove('visible');
});

privacyModal.addEventListener('click', (e) => {
  if (e.target === privacyModal) {
    privacyModal.classList.remove('visible');
  }
});

// Listen for blocked requests from main process
if (window.truma && typeof window.truma.onBlockedRequest === 'function') {
  window.truma.onBlockedRequest((type) => {
    if (type === 'ad') privacyStats.ads++;
    if (type === 'tracker') privacyStats.trackers++;
    if (type === 'cookie') privacyStats.cookies++;
    if (type === 'popup') {
      privacyStats.popups = (privacyStats.popups || 0) + 1;
      showPopupNotification();
    }
  });
}

// ==================== POPUP BLOCKER ====================

const popupNotification = document.getElementById('popup-notification');
const popupAllow = document.getElementById('popup-allow');
const popupDismiss = document.getElementById('popup-dismiss');

let pendingPopupUrl = null;
let popupTimeout = null;

function showPopupNotification(url) {
  pendingPopupUrl = url;
  popupNotification.classList.remove('hidden');
  
  // Auto-dismiss after 5 seconds
  if (popupTimeout) clearTimeout(popupTimeout);
  popupTimeout = setTimeout(() => {
    hidePopupNotification();
  }, 5000);
}

function hidePopupNotification() {
  popupNotification.classList.add('hidden');
  pendingPopupUrl = null;
}

popupAllow.addEventListener('click', () => {
  if (pendingPopupUrl) {
    addTab(pendingPopupUrl);
  }
  hidePopupNotification();
});

popupDismiss.addEventListener('click', () => {
  hidePopupNotification();
});

// Initialize popup stat
privacyStats.popups = 0;

// ==================== VIEW SOURCE ====================

function viewSource() {
  const t = getActiveTab();
  if (!t) return;
  
  try {
    const url = t.webview.getURL();
    if (!url || url.startsWith('truma://')) {
      setStatus('Cannot view source for this page');
      return;
    }
    
    // Open view-source URL in new tab
    addTab('view-source:' + url);
  } catch (_) {
    setStatus('Failed to view source');
  }
}

// ==================== FIND IN PAGE ====================

const findBar = document.getElementById('find-bar');
const findInput = document.getElementById('find-input');
const findCount = document.getElementById('find-count');
const findPrev = document.getElementById('find-prev');
const findNext = document.getElementById('find-next');
const findClose = document.getElementById('find-close');

let findRequestId = 0;

function toggleFindBar() {
  if (findBar.classList.contains('hidden')) {
    findBar.classList.remove('hidden');
    findInput.focus();
    findInput.select();
  } else {
    closeFindBar();
  }
}

function closeFindBar() {
  findBar.classList.add('hidden');
  findInput.value = '';
  findCount.textContent = '';
  const t = getActiveTab();
  if (t) {
    try { t.webview.stopFindInPage('clearSelection'); } catch (_) {}
  }
}

function doFind(direction) {
  const query = findInput.value.trim();
  if (!query) {
    findCount.textContent = '';
    return;
  }

  const t = getActiveTab();
  if (!t) return;

  findRequestId++;
  try {
    t.webview.findInPage(query, {
      forward: direction === 'next',
      findNext: direction === 'next',
      matchCase: false
    });
  } catch (_) {}
}

findInput.addEventListener('input', () => doFind('next'));
findInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    doFind(e.shiftKey ? 'prev' : 'next');
  }
  if (e.key === 'Escape') {
    closeFindBar();
  }
});

findPrev.addEventListener('click', () => doFind('prev'));
findNext.addEventListener('click', () => doFind('next'));
findClose.addEventListener('click', closeFindBar);

// Handle find results
document.addEventListener('did-start-loading', () => {
  findCount.textContent = '';
});

// ==================== ZOOM ====================

let zoomLevel = 1.0;

function zoomIn() {
  zoomLevel = Math.min(zoomLevel + 0.1, 3.0);
  applyZoom();
}

function zoomOut() {
  zoomLevel = Math.max(zoomLevel - 0.1, 0.3);
  applyZoom();
}

function zoomReset() {
  zoomLevel = 1.0;
  applyZoom();
}

function applyZoom() {
  const t = getActiveTab();
  if (t) {
    try {
      t.webview.setZoomFactor(zoomLevel);
      setStatus(`Zoom: ${Math.round(zoomLevel * 100)}%`);
    } catch (_) {}
  }
}

// ==================== DOWNLOAD EVENTS ====================
if (window.truma && typeof window.truma.onDownloadEvent === 'function') {
  window.truma.onDownloadEvent((payload) => {
    if (!payload || !payload.type) return;

    if (payload.type === 'clear') {
      downloads = [];
      renderDownloads();
      return;
    }

    if (payload.type === 'started') {
      downloads.unshift({
        id: payload.id,
        filename: payload.filename || 'download',
        url: payload.url || '',
        filePath: payload.filePath || '',
        percent: 0,
        state: 'downloading'
      });
      renderDownloads();
      return;
    }

    const dl = downloads.find(d => String(d.id) === String(payload.id));
    if (!dl) return;

    if (payload.type === 'progress') {
      dl.percent = typeof payload.percent === 'number' ? payload.percent : dl.percent;
      dl.state = 'downloading';
      renderDownloads();
      return;
    }

    if (payload.type === 'done') {
      dl.state = payload.state || 'completed';
      if (dl.state === 'completed') dl.percent = 100;
      if (payload.filePath) dl.filePath = payload.filePath;
      renderDownloads();
    }
  });
}
