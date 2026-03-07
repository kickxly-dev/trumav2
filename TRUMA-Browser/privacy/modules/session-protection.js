/**
 * TRUMA Browser - Session Protection Module
 * Auto-wipes session data on browser close
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

class SessionProtection {
    constructor(config, manager) {
        this.config = config;
        this.manager = manager;
        this.enabled = config.enabled !== false;
        this.sessionData = {
            cookies: [],
            cache: [],
            localStorage: new Map(),
            sessionStorage: new Map(),
            history: []
        };
    }

    /**
     * Initialize session protection
     */
    async initialize(sess) {
        this.session = sess;

        // Track session data
        if (this.config.autoWipe) {
            this.setupDataTracking();
        }

        console.log('[SessionProtection] Initialized with autoWipe:', this.config.autoWipe);
    }

    /**
     * Setup data tracking
     */
    setupDataTracking() {
        // Track cookies
        this.session.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, callback) => {
            const headers = details.responseHeaders || {};
            
            if (headers['set-cookie'] && this.config.wipeCookies) {
                const url = new URL(details.url);
                headers['set-cookie'].forEach(cookie => {
                    this.sessionData.cookies.push({
                        domain: url.hostname,
                        cookie: cookie
                    });
                });
            }

            callback({});
        });

        // Track navigation for history
        if (this.config.wipeHistory) {
            this.session.webRequest.onCompleted({ urls: ['*://*/*'] }, (details) => {
                if (details.type === 'mainFrame') {
                    this.sessionData.history.push({
                        url: details.url,
                        timestamp: Date.now()
                    });
                }
            });
        }
    }

    /**
     * Wipe all session data
     */
    async wipe() {
        console.log('[SessionProtection] Wiping session data...');

        const results = {
            cookies: 0,
            cache: false,
            localStorage: 0,
            sessionStorage: 0,
            history: 0
        };

        if (!this.enabled || !this.config.autoWipe) {
            return results;
        }

        try {
            // Clear cookies
            if (this.config.wipeCookies) {
                await this.session.clearStorageData({
                    storages: ['cookies']
                });
                results.cookies = this.sessionData.cookies.length;
                this.sessionData.cookies = [];
                console.log('[SessionProtection] Cleared cookies');
            }

            // Clear cache
            if (this.config.wipeCache) {
                await this.session.clearCache();
                await this.session.clearStorageData({
                    storages: ['serviceworkers']
                });
                results.cache = true;
                console.log('[SessionProtection] Cleared cache');
            }

            // Clear local storage
            if (this.config.wipeLocalStorage) {
                await this.session.clearStorageData({
                    storages: ['localstorage']
                });
                results.localStorage = this.sessionData.localStorage.size;
                this.sessionData.localStorage.clear();
                console.log('[SessionProtection] Cleared local storage');
            }

            // Clear session storage
            if (this.config.wipeSessionStorage) {
                await this.session.clearStorageData({
                    storages: ['sessionstorage']
                });
                results.sessionStorage = this.sessionData.sessionStorage.size;
                this.sessionData.sessionStorage.clear();
                console.log('[SessionProtection] Cleared session storage');
            }

            // Clear history
            if (this.config.wipeHistory) {
                results.history = this.sessionData.history.length;
                this.sessionData.history = [];
                console.log('[SessionProtection] Cleared history');
            }

            // Clear all storage data as final step
            await this.session.clearStorageData();
            await this.session.clearCache();
            await this.session.clearHostResolverCache();

            // Clear temporary files
            await this.clearTempFiles();

            console.log('[SessionProtection] Session wipe complete');
        } catch (e) {
            console.error('[SessionProtection] Wipe error:', e);
        }

        return results;
    }

    /**
     * Clear temporary files
     */
    async clearTempFiles() {
        const tempDir = os.tmpdir();
        const trumaTempPattern = /^TRUMA-Browser-/;

        try {
            const entries = fs.readdirSync(tempDir, { withFileTypes: true });
            
            for (const entry of entries) {
                if (trumaTempPattern.test(entry.name)) {
                    const fullPath = path.join(tempDir, entry.name);
                    try {
                        if (entry.isDirectory()) {
                            fs.rmSync(fullPath, { recursive: true, force: true });
                        } else {
                            fs.unlinkSync(fullPath);
                        }
                        console.log('[SessionProtection] Removed temp:', entry.name);
                    } catch (e) {
                        // Best effort
                    }
                }
            }
        } catch (e) {
            console.error('[SessionProtection] Failed to clear temp files:', e);
        }
    }

    /**
     * Quick wipe - clear only sensitive data
     */
    async quickWipe() {
        await this.session.clearStorageData({
            storages: ['cookies', 'localstorage', 'sessionstorage']
        });
        await this.session.clearCache();
        
        this.sessionData.cookies = [];
        this.sessionData.localStorage.clear();
        this.sessionData.sessionStorage.clear();
    }

    /**
     * Get session statistics
     */
    getStats() {
        return {
            cookies: this.sessionData.cookies.length,
            cacheEntries: this.sessionData.cache.length,
            localStorageEntries: this.sessionData.localStorage.size,
            sessionStorageEntries: this.sessionData.sessionStorage.size,
            historyEntries: this.sessionData.history.length
        };
    }

    /**
     * Update configuration
     */
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        this.enabled = this.config.enabled !== false;
    }

    /**
     * Cleanup
     */
    async cleanup() {
        await this.wipe();
    }
}

module.exports = SessionProtection;
