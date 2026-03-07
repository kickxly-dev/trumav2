/**
 * TRAUMA Auto-Updater
 * Checks for updates on all TRAUMA tools
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

// Configuration
const UPDATE_SERVER = process.env.TRAUMA_UPDATE_SERVER || 'https://api.trauma-suite.com';
const CURRENT_VERSION = require('./package.json')?.version || '2.0.0';

class TRAUMAUpdater {
    constructor(toolName, version = CURRENT_VERSION) {
        this.toolName = toolName;
        this.currentVersion = version;
        this.updateServer = UPDATE_SERVER;
        this.cacheDir = this.getCacheDir();
        this.tempDir = this.getTempDir();
    }

    getCacheDir() {
        const cacheDir = path.join(os.homedir(), '.trauma', 'cache');
        if (!fs.existsSync(cacheDir)) {
            fs.mkdirSync(cacheDir, { recursive: true });
        }
        return cacheDir;
    }

    getTempDir() {
        const tempDir = path.join(os.tmpdir(), 'trauma-updates');
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        return tempDir;
    }

    getHardwareId() {
        const info = [
            os.hostname(),
            os.platform(),
            os.cpus()[0]?.model || 'unknown',
            os.networkInterfaces()?.eth0?.[0]?.mac || 'unknown'
        ].join('-');
        return crypto.createHash('sha256').update(info).digest('hex').substring(0, 32);
    }

    async checkForUpdates() {
        return new Promise((resolve, reject) => {
            const url = `${this.updateServer}/updates/${this.toolName}/version`;
            
            const req = https.get(url, { timeout: 10000 }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        resolve({
                            hasUpdate: this.compareVersions(json.version, this.currentVersion),
                            latestVersion: json.version,
                            currentVersion: this.currentVersion,
                            changelog: json.changelog,
                            downloadUrl: json.downloadUrl,
                            checksum: json.checksum,
                            mandatory: json.mandatory || false,
                            releaseDate: json.releaseDate
                        });
                    } catch (e) {
                        reject(new Error('Invalid response from update server'));
                    }
                });
            });

            req.on('error', (e) => {
                // Fallback to GitHub releases
                this.checkGitHubUpdates().then(resolve).catch(reject);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Update check timeout'));
            });
        });
    }

    async checkGitHubUpdates() {
        return new Promise((resolve, reject) => {
            const url = `https://api.github.com/repos/kickxly-dev/trumav2/releases/latest`;
            
            const req = https.get(url, {
                headers: { 'User-Agent': 'TRAUMA-Updater' },
                timeout: 10000
            }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        const version = json.tag_name?.replace('v', '') || '0.0.0';
                        resolve({
                            hasUpdate: this.compareVersions(version, this.currentVersion),
                            latestVersion: version,
                            currentVersion: this.currentVersion,
                            changelog: json.body,
                            downloadUrl: json.assets?.[0]?.browser_download_url,
                            checksum: null,
                            mandatory: false,
                            releaseDate: json.published_at,
                            githubRelease: true
                        });
                    } catch (e) {
                        reject(new Error('Failed to check GitHub releases'));
                    }
                });
            });

            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('GitHub check timeout'));
            });
        });
    }

    compareVersions(v1, v2) {
        const parts1 = v1.split('.').map(Number);
        const parts2 = v2.split('.').map(Number);
        
        for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
            const p1 = parts1[i] || 0;
            const p2 = parts2[i] || 0;
            if (p1 > p2) return true;
            if (p1 < p2) return false;
        }
        return false;
    }

    async downloadUpdate(url, progressCallback = null) {
        return new Promise((resolve, reject) => {
            const tempFile = path.join(this.tempDir, `${this.toolName}-update.exe`);
            const file = fs.createWriteStream(tempFile);
            
            const protocol = url.startsWith('https') ? https : http;
            
            protocol.get(url, { timeout: 60000 }, (res) => {
                const totalSize = parseInt(res.headers['content-length'], 10);
                let downloaded = 0;

                res.on('data', (chunk) => {
                    downloaded += chunk.length;
                    if (progressCallback && totalSize) {
                        progressCallback({
                            percent: Math.round((downloaded / totalSize) * 100),
                            downloaded,
                            total: totalSize
                        });
                    }
                });

                res.pipe(file);

                file.on('finish', () => {
                    file.close();
                    resolve(tempFile);
                });
            }).on('error', (err) => {
                fs.unlink(tempFile, () => {});
                reject(err);
            });
        });
    }

    async verifyChecksum(filePath, expectedChecksum) {
        if (!expectedChecksum) return true;
        
        return new Promise((resolve) => {
            const hash = crypto.createHash('sha256');
            const stream = fs.createReadStream(filePath);
            
            stream.on('data', (data) => hash.update(data));
            stream.on('end', () => {
                const checksum = hash.digest('hex');
                resolve(checksum === expectedChecksum);
            });
            stream.on('error', () => resolve(false));
        });
    }

    async installUpdate(updateFile) {
        // For Windows EXE updates
        if (process.platform === 'win32') {
            const currentExe = process.execPath;
            const backupPath = currentExe + '.backup';
            
            // Create backup
            if (fs.existsSync(currentExe)) {
                fs.copyFileSync(currentExe, backupPath);
            }
            
            // Replace with new version
            fs.copyFileSync(updateFile, currentExe);
            
            // Clean up
            fs.unlinkSync(updateFile);
            
            return { success: true, requiresRestart: true };
        }
        
        return { success: false, error: 'Platform not supported for auto-install' };
    }

    async runUpdate(progressCallback = null) {
        try {
            // Check for updates
            const updateInfo = await this.checkForUpdates();
            
            if (!updateInfo.hasUpdate) {
                return { success: true, message: 'Already up to date' };
            }

            if (!updateInfo.downloadUrl) {
                return { success: false, error: 'No download URL available' };
            }

            // Download
            if (progressCallback) {
                progressCallback({ stage: 'downloading', percent: 0 });
            }
            
            const updateFile = await this.downloadUpdate(updateInfo.downloadUrl, progressCallback);

            // Verify
            if (progressCallback) {
                progressCallback({ stage: 'verifying', percent: 90 });
            }
            
            const valid = await this.verifyChecksum(updateFile, updateInfo.checksum);
            if (!valid) {
                fs.unlinkSync(updateFile);
                return { success: false, error: 'Checksum verification failed' };
            }

            // Install
            if (progressCallback) {
                progressCallback({ stage: 'installing', percent: 95 });
            }
            
            const result = await this.installUpdate(updateFile);
            
            if (progressCallback) {
                progressCallback({ stage: 'complete', percent: 100 });
            }

            return {
                ...result,
                oldVersion: this.currentVersion,
                newVersion: updateInfo.latestVersion,
                changelog: updateInfo.changelog
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // Background update check (non-blocking)
    startBackgroundChecks(intervalMs = 3600000) { // Default: 1 hour
        // Check immediately
        this.checkForUpdates().then(info => {
            if (info.hasUpdate) {
                this.notifyUpdate(info);
            }
        }).catch(() => {});

        // Schedule periodic checks
        this.checkInterval = setInterval(async () => {
            try {
                const info = await this.checkForUpdates();
                if (info.hasUpdate) {
                    this.notifyUpdate(info);
                }
            } catch (e) {}
        }, intervalMs);

        return this.checkInterval;
    }

    stopBackgroundChecks() {
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
    }

    notifyUpdate(info) {
        // Can be overridden by UI
        console.log(`
╔════════════════════════════════════════════════════════════╗
║  🔄 UPDATE AVAILABLE                                        ║
╠════════════════════════════════════════════════════════════╣
║  Current: v${info.currentVersion.padEnd(20)} Latest: v${info.latestVersion}  ║
║  ${info.mandatory ? '⚠️  MANDATORY UPDATE' : 'Optional update'.padEnd(54)}║
╚════════════════════════════════════════════════════════════╝
        `);
        
        // Emit event for UI
        if (this.onUpdateAvailable) {
            this.onUpdateAvailable(info);
        }
    }

    // Get cached update info
    getCachedUpdateInfo() {
        const cacheFile = path.join(this.cacheDir, 'update-info.json');
        try {
            if (fs.existsSync(cacheFile)) {
                return JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
            }
        } catch (e) {}
        return null;
    }

    // Cache update info
    cacheUpdateInfo(info) {
        const cacheFile = path.join(this.cacheDir, 'update-info.json');
        fs.writeFileSync(cacheFile, JSON.stringify({
            ...info,
            cachedAt: new Date().toISOString()
        }, null, 2));
    }
}

// CLI interface
if (require.main === module) {
    const toolName = process.argv[2] || 'trauma';
    const action = process.argv[3] || 'check';
    
    const updater = new TRAUMAUpdater(toolName);
    
    switch (action) {
        case 'check':
            updater.checkForUpdates().then(info => {
                console.log(JSON.stringify(info, null, 2));
                process.exit(info.hasUpdate ? 1 : 0);
            }).catch(e => {
                console.error('Error:', e.message);
                process.exit(2);
            });
            break;
            
        case 'update':
            updater.runUpdate((progress) => {
                console.log(`[${progress.stage}] ${progress.percent}%`);
            }).then(result => {
                console.log(JSON.stringify(result, null, 2));
                if (result.requiresRestart) {
                    console.log('\nRestart required to complete update.');
                }
            }).catch(e => {
                console.error('Error:', e.message);
                process.exit(1);
            });
            break;
            
        default:
            console.log(`
TRAUMA Updater

Usage:
  node shared-updater.js <tool> check   - Check for updates
  node shared-updater.js <tool> update  - Download and install update

Tools: trauma, osint, browser, cleaner
            `);
    }
}

module.exports = TRAUMAUpdater;
