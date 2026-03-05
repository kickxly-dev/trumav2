const { app, BrowserWindow, ipcMain, Notification, Tray, Menu, nativeImage } = require('electron');
const path = require('path');
const axios = require('axios');

let mainWindow;
let tray;
let authToken = null;
let API_URL = 'https://trauma-suite.onrender.com'; // Change to your deployed URL

// Create main window
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        minWidth: 900,
        minHeight: 600,
        frame: false,
        backgroundColor: '#0a0a0a',
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        },
        icon: path.join(__dirname, 'icon.png')
    });

    mainWindow.loadFile('index.html');

    // Create tray icon
    const trayIcon = nativeImage.createFromDataURL(
        Buffer.from('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAABjSURBVDhPYxj6oDnE////Z2RkZPzPwMDwHxjqAwcG+v9HjhyJQQdhYmICRgkGFrDgPwZkJSQk/P/PwMD4H0gI8B+IbEIsYQACDAwM/2dQUP+DqwtQhlgENrFQNoYk2AAAbBcW4kFZdxwAAAAASUVORK5CYII=', 'base64')
    );
    
    tray = new Tray(trayIcon);
    const contextMenu = Menu.buildFromTemplate([
        { label: 'Open Control Panel', click: () => mainWindow.show() },
        { label: 'Stats', click: () => showQuickStats() },
        { type: 'separator' },
        { label: 'Quit', click: () => app.quit() }
    ]);
    tray.setToolTip('TRUMA NET V2 Control');
    tray.setContextMenu(contextMenu);

    mainWindow.on('close', (e) => {
        e.preventDefault();
        mainWindow.hide();
    });
}

// Show quick stats notification
async function showQuickStats() {
    if (!authToken) return;
    
    try {
        const res = await axios.get(`${API_URL}/api/security/realtime-stats`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        
        new Notification({
            title: 'TRUMA NET Stats',
            body: `Visitors: ${res.data.stats.visitors1h}/h | Threats: ${res.data.stats.threats1h} | Blocked: ${res.data.stats.totalBlocked}`
        }).show();
    } catch (err) {
        console.error('Failed to fetch stats');
    }
}

// IPC Handlers
ipcMain.handle('login', async (event, ownerCode) => {
    try {
        const res = await axios.post(`${API_URL}/api/auth/owner-login`, { ownerCode });
        authToken = res.data.token;
        return { success: true, user: res.data.user };
    } catch (err) {
        return { success: false, error: err.response?.data?.error || 'Connection failed' };
    }
});

ipcMain.handle('getStats', async () => {
    try {
        const res = await axios.get(`${API_URL}/api/security/realtime-stats`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        return res.data;
    } catch (err) {
        return null;
    }
});

ipcMain.handle('getSettings', async () => {
    try {
        const res = await axios.get(`${API_URL}/api/security/settings`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        return res.data.settings;
    } catch (err) {
        return null;
    }
});

ipcMain.handle('updateSettings', async (event, settings) => {
    try {
        const res = await axios.put(`${API_URL}/api/security/settings`, settings, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        return { success: true, settings: res.data.settings };
    } catch (err) {
        return { success: false };
    }
});

ipcMain.handle('getBlockedIPs', async () => {
    try {
        const res = await axios.get(`${API_URL}/api/security/blocked-ips`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        return res.data.blockedIPs;
    } catch (err) {
        return [];
    }
});

ipcMain.handle('blockIP', async (event, { ip, reason, durationHours }) => {
    try {
        const res = await axios.post(`${API_URL}/api/security/block-ip`, 
            { ip, reason, durationHours },
            { headers: { Authorization: `Bearer ${authToken}` } }
        );
        return { success: true };
    } catch (err) {
        return { success: false };
    }
});

ipcMain.handle('unblockIP', async (event, ip) => {
    try {
        await axios.delete(`${API_URL}/api/security/block-ip/${ip}`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        return { success: true };
    } catch (err) {
        return { success: false };
    }
});

ipcMain.handle('getThreats', async () => {
    try {
        const res = await axios.get(`${API_URL}/api/security/threats`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        return res.data.threats;
    } catch (err) {
        return [];
    }
});

ipcMain.handle('getSites', async () => {
    try {
        const res = await axios.get(`${API_URL}/api/truma-net/sites`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        return res.data.sites;
    } catch (err) {
        return [];
    }
});

ipcMain.handle('addSite', async (event, { siteId, siteName, siteUrl }) => {
    try {
        const res = await axios.post(`${API_URL}/api/truma-net/sites`, 
            { siteId, siteName, siteUrl },
            { headers: { Authorization: `Bearer ${authToken}` } }
        );
        return { success: true, embedCode: res.data.embedCode };
    } catch (err) {
        return { success: false };
    }
});

ipcMain.handle('removeSite', async (event, siteId) => {
    try {
        await axios.delete(`${API_URL}/api/truma-net/sites/${siteId}`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        return { success: true };
    } catch (err) {
        return { success: false };
    }
});

ipcMain.handle('emergencyMode', async (event, enabled) => {
    try {
        const res = await axios.post(`${API_URL}/api/security/emergency-mode`, 
            { enabled },
            { headers: { Authorization: `Bearer ${authToken}` } }
        );
        return { success: true };
    } catch (err) {
        return { success: false };
    }
});

ipcMain.handle('logout', () => {
    authToken = null;
    return true;
});

// Window controls
ipcMain.on('minimize', () => mainWindow.minimize());
ipcMain.on('maximize', () => {
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    else mainWindow.maximize();
});
ipcMain.on('close', () => mainWindow.hide());

// Auto-refresh stats every 30 seconds
setInterval(async () => {
    if (authToken && mainWindow.isVisible()) {
        const stats = await axios.get(`${API_URL}/api/security/realtime-stats`, {
            headers: { Authorization: `Bearer ${authToken}` }
        }).catch(() => null);
        
        if (stats) {
            mainWindow.webContents.send('stats-update', stats.data);
        }
    }
}, 30000);

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
