/**
 * TRUMA Browser - Privacy Manager
 * Central controller for all privacy protection modules
 */

const { session, net } = require('electron');
const path = require('path');
const fs = require('fs');

// Import privacy modules
const TrackerBlocker = require('./modules/tracker-blocker');
const FingerprintProtection = require('./modules/fingerprint-protection');
const CookieIsolation = require('./modules/cookie-isolation');
const DNSPrivacy = require('./modules/dns-privacy');
const PermissionProtection = require('./modules/permission-protection');
const SessionProtection = require('./modules/session-protection');

class PrivacyManager {
    constructor() {
        this.modules = {};
        this.stats = {
            trackersBlocked: 0,
            cookiesBlocked: 0,
            fingerprintsPrevented: 0,
            permissionsBlocked: 0,
            dnsQueriesEncrypted: 0
        };
        this.config = this.loadConfig();
        this.enabled = true;
    }

    /**
     * Load privacy configuration
     */
    loadConfig() {
        const configPath = path.join(__dirname, 'privacy-config.json');
        const defaultConfig = {
            trackerBlocking: {
                enabled: true,
                level: 'strict', // off, basic, strict
                blockThirdPartyCookies: true,
                blockThirdPartyScripts: true,
                customFilters: []
            },
            fingerprintProtection: {
                enabled: true,
                canvasNoise: true,
                webglNoise: true,
                audioNoise: true,
                fontProtection: true,
                hardwareSpoofing: true
            },
            cookieIsolation: {
                enabled: true,
                mode: 'strict', // off, relaxed, strict
                containerPrefix: 'truma-container'
            },
            dnsPrivacy: {
                enabled: true,
                mode: 'doh', // off, doh, dot
                provider: 'cloudflare', // cloudflare, google, quad9, custom
                customProvider: null
            },
            permissionProtection: {
                enabled: true,
                autoBlock: ['camera', 'microphone', 'location', 'notifications', 'geolocation'],
                promptOnBlock: true
            },
            sessionProtection: {
                enabled: true,
                autoWipe: true,
                wipeOnClose: true,
                wipeCookies: true,
                wipeCache: true,
                wipeLocalStorage: true,
                wipeSessionStorage: true,
                wipeHistory: true
            }
        };

        try {
            if (fs.existsSync(configPath)) {
                const saved = JSON.parse(fs.readFileSync(configPath, 'utf8'));
                return { ...defaultConfig, ...saved };
            }
        } catch (e) {
            console.error('[PrivacyManager] Failed to load config:', e);
        }

        return defaultConfig;
    }

    /**
     * Save privacy configuration
     */
    saveConfig() {
        const configPath = path.join(__dirname, 'privacy-config.json');
        try {
            fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
        } catch (e) {
            console.error('[PrivacyManager] Failed to save config:', e);
        }
    }

    /**
     * Initialize all privacy modules
     */
    async initialize(sess, mainWindow) {
        this.session = sess;
        this.mainWindow = mainWindow;

        console.log('[PrivacyManager] Initializing privacy modules...');

        // Initialize tracker blocker
        if (this.config.trackerBlocking.enabled) {
            this.modules.trackerBlocker = new TrackerBlocker(this.config.trackerBlocking, this);
            await this.modules.trackerBlocker.initialize(sess);
            console.log('[PrivacyManager] Tracker blocker initialized');
        }

        // Initialize fingerprint protection
        if (this.config.fingerprintProtection.enabled) {
            this.modules.fingerprintProtection = new FingerprintProtection(this.config.fingerprintProtection, this);
            await this.modules.fingerprintProtection.initialize(sess);
            console.log('[PrivacyManager] Fingerprint protection initialized');
        }

        // Initialize cookie isolation
        if (this.config.cookieIsolation.enabled) {
            this.modules.cookieIsolation = new CookieIsolation(this.config.cookieIsolation, this);
            await this.modules.cookieIsolation.initialize(sess);
            console.log('[PrivacyManager] Cookie isolation initialized');
        }

        // Initialize DNS privacy
        if (this.config.dnsPrivacy.enabled) {
            this.modules.dnsPrivacy = new DNSPrivacy(this.config.dnsPrivacy, this);
            await this.modules.dnsPrivacy.initialize();
            console.log('[PrivacyManager] DNS privacy initialized');
        }

        // Initialize permission protection
        if (this.config.permissionProtection.enabled) {
            this.modules.permissionProtection = new PermissionProtection(this.config.permissionProtection, this);
            await this.modules.permissionProtection.initialize(sess, mainWindow);
            console.log('[PrivacyManager] Permission protection initialized');
        }

        // Initialize session protection
        if (this.config.sessionProtection.enabled) {
            this.modules.sessionProtection = new SessionProtection(this.config.sessionProtection, this);
            await this.modules.sessionProtection.initialize(sess);
            console.log('[PrivacyManager] Session protection initialized');
        }

        console.log('[PrivacyManager] All modules initialized');
    }

    /**
     * Update statistics
     */
    updateStat(stat, increment = 1) {
        if (this.stats[stat] !== undefined) {
            this.stats[stat] += increment;
            this.sendStatsToUI();
        }
    }

    /**
     * Send statistics to UI
     */
    sendStatsToUI() {
        if (this.mainWindow && !this.mainWindow.isDestroyed()) {
            this.mainWindow.webContents.send('privacy-stats-update', this.stats);
        }
    }

    /**
     * Get current statistics
     */
    getStats() {
        return { ...this.stats };
    }

    /**
     * Reset statistics
     */
    resetStats() {
        this.stats = {
            trackersBlocked: 0,
            cookiesBlocked: 0,
            fingerprintsPrevented: 0,
            permissionsBlocked: 0,
            dnsQueriesEncrypted: 0
        };
        this.sendStatsToUI();
    }

    /**
     * Get module status
     */
    getModuleStatus() {
        const status = {};
        for (const [name, module] of Object.entries(this.modules)) {
            status[name] = {
                enabled: module.enabled,
                config: module.config
            };
        }
        return status;
    }

    /**
     * Toggle module
     */
    toggleModule(moduleName, enabled) {
        if (this.modules[moduleName]) {
            this.modules[moduleName].enabled = enabled;
            this.config[moduleName].enabled = enabled;
            this.saveConfig();
            return true;
        }
        return false;
    }

    /**
     * Update module config
     */
    updateModuleConfig(moduleName, newConfig) {
        if (this.config[moduleName]) {
            this.config[moduleName] = { ...this.config[moduleName], ...newConfig };
            this.saveConfig();
            if (this.modules[moduleName]) {
                this.modules[moduleName].updateConfig(this.config[moduleName]);
            }
            return true;
        }
        return false;
    }

    /**
     * Cleanup on browser close
     */
    async cleanup() {
        console.log('[PrivacyManager] Cleaning up...');
        
        if (this.modules.sessionProtection) {
            await this.modules.sessionProtection.wipe();
        }

        for (const module of Object.values(this.modules)) {
            if (module.cleanup) {
                await module.cleanup();
            }
        }
    }
}

module.exports = PrivacyManager;
