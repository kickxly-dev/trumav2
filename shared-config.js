/**
 * TRAUMA Encrypted Config Storage
 * Secure configuration storage using license key as encryption key
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

class ConfigManager {
    constructor(toolName, licenseKey = null) {
        this.toolName = toolName;
        this.licenseKey = licenseKey;
        this.configDir = this.getConfigDir();
        this.configFile = path.join(this.configDir, `${toolName}-config.enc`);
        this.algorithm = 'aes-256-gcm';
        this.config = {};
    }

    getConfigDir() {
        const configDir = path.join(os.homedir(), '.trauma', 'config');
        if (!fs.existsSync(configDir)) {
            fs.mkdirSync(configDir, { recursive: true });
        }
        return configDir;
    }

    setLicenseKey(key) {
        this.licenseKey = key;
    }

    deriveKey(key) {
        // Derive 32-byte key from license key using PBKDF2
        return crypto.pbkdf2Sync(
            key.toUpperCase(),
            'TRAUMA-CONFIG-SALT-2024',
            100000,
            32,
            'sha256'
        );
    }

    encrypt(data) {
        if (!this.licenseKey) {
            throw new Error('License key required for encryption');
        }

        const key = this.deriveKey(this.licenseKey);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(this.algorithm, key, iv);

        let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return {
            iv: iv.toString('hex'),
            data: encrypted,
            authTag: authTag.toString('hex'),
            version: 1
        };
    }

    decrypt(encryptedData) {
        if (!this.licenseKey) {
            throw new Error('License key required for decryption');
        }

        const key = this.deriveKey(this.licenseKey);
        const iv = Buffer.from(encryptedData.iv, 'hex');
        const authTag = Buffer.from(encryptedData.authTag, 'hex');

        const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return JSON.parse(decrypted);
    }

    save(config = null) {
        const dataToSave = config || this.config;
        
        if (!this.licenseKey) {
            // Save unencrypted if no license key
            const plainFile = path.join(this.configDir, `${this.toolName}-config.json`);
            fs.writeFileSync(plainFile, JSON.stringify(dataToSave, null, 2));
            return { encrypted: false, file: plainFile };
        }

        const encrypted = this.encrypt(dataToSave);
        fs.writeFileSync(this.configFile, JSON.stringify(encrypted, null, 2));
        
        return { encrypted: true, file: this.configFile };
    }

    load() {
        // Try encrypted file first
        if (fs.existsSync(this.configFile)) {
            try {
                const encryptedData = JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
                this.config = this.decrypt(encryptedData);
                return { success: true, encrypted: true, config: this.config };
            } catch (e) {
                // Decryption failed - wrong license key or corrupted
                return { success: false, error: 'Decryption failed - invalid license key' };
            }
        }

        // Try plain JSON file
        const plainFile = path.join(this.configDir, `${this.toolName}-config.json`);
        if (fs.existsSync(plainFile)) {
            try {
                this.config = JSON.parse(fs.readFileSync(plainFile, 'utf8'));
                return { success: true, encrypted: false, config: this.config };
            } catch (e) {
                return { success: false, error: 'Failed to parse config file' };
            }
        }

        // No config file exists
        this.config = this.getDefaultConfig();
        return { success: true, encrypted: false, config: this.config, isNew: true };
    }

    getDefaultConfig() {
        return {
            theme: 'dark',
            animations: true,
            autoUpdate: true,
            checkUpdatesOnStartup: true,
            saveHistory: true,
            maxHistoryItems: 100,
            apiKeys: {},
            lastUsed: new Date().toISOString(),
            preferences: {}
        };
    }

    get(key, defaultValue = null) {
        return this.config[key] ?? defaultValue;
    }

    set(key, value) {
        this.config[key] = value;
        return this;
    }

    delete(key) {
        delete this.config[key];
        return this;
    }

    clear() {
        this.config = this.getDefaultConfig();
        return this;
    }

    // Securely store API keys
    setApiKey(service, apiKey) {
        if (!this.config.apiKeys) {
            this.config.apiKeys = {};
        }
        // Store a hash of the key for verification
        this.config.apiKeys[service] = {
            hash: crypto.createHash('sha256').update(apiKey).digest('hex').substring(0, 16),
            encrypted: this.encryptValue(apiKey),
            addedAt: new Date().toISOString()
        };
        return this;
    }

    getApiKey(service) {
        const keyData = this.config.apiKeys?.[service];
        if (!keyData) return null;
        
        return this.decryptValue(keyData.encrypted);
    }

    encryptValue(value) {
        if (!this.licenseKey) return value;
        
        const key = this.deriveKey(this.licenseKey);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        
        let encrypted = cipher.update(value, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return iv.toString('hex') + ':' + encrypted;
    }

    decryptValue(encrypted) {
        if (!this.licenseKey || !encrypted.includes(':')) return encrypted;
        
        const key = this.deriveKey(this.licenseKey);
        const [ivHex, data] = encrypted.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        
        let decrypted = decipher.update(data, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    }

    // Export config (without sensitive data)
    export() {
        const exported = { ...this.config };
        delete exported.apiKeys;
        return exported;
    }

    // Import config
    import(config, merge = true) {
        if (merge) {
            this.config = { ...this.config, ...config };
        } else {
            this.config = config;
        }
        return this;
    }

    // Migrate from old config format
    migrate(oldConfigPath) {
        if (fs.existsSync(oldConfigPath)) {
            try {
                const oldConfig = JSON.parse(fs.readFileSync(oldConfigPath, 'utf8'));
                this.config = { ...this.getDefaultConfig(), ...oldConfig };
                this.save();
                return { success: true, migrated: true };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, error: 'Old config file not found' };
    }
}

// Browser-compatible version (uses localStorage)
class BrowserConfigManager {
    constructor(toolName, licenseKey = null) {
        this.toolName = toolName;
        this.licenseKey = licenseKey;
        this.storageKey = `trauma_${toolName}_config`;
        this.config = {};
    }

    // Simple XOR encryption for browser (not as secure as Node.js version)
    encrypt(data) {
        if (!this.licenseKey) return JSON.stringify(data);
        
        const str = JSON.stringify(data);
        const key = this.licenseKey.repeat(Math.ceil(str.length / this.licenseKey.length));
        
        let encrypted = '';
        for (let i = 0; i < str.length; i++) {
            encrypted += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i));
        }
        
        return btoa(encrypted);
    }

    decrypt(encrypted) {
        if (!this.licenseKey) {
            try {
                return JSON.parse(encrypted);
            } catch {
                return {};
            }
        }
        
        try {
            const str = atob(encrypted);
            const key = this.licenseKey.repeat(Math.ceil(str.length / this.licenseKey.length));
            
            let decrypted = '';
            for (let i = 0; i < str.length; i++) {
                decrypted += String.fromCharCode(str.charCodeAt(i) ^ key.charCodeAt(i));
            }
            
            return JSON.parse(decrypted);
        } catch {
            return {};
        }
    }

    load() {
        try {
            const stored = localStorage.getItem(this.storageKey);
            if (stored) {
                this.config = this.decrypt(stored);
            } else {
                this.config = this.getDefaultConfig();
            }
            return { success: true, config: this.config };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    save() {
        try {
            const encrypted = this.encrypt(this.config);
            localStorage.setItem(this.storageKey, encrypted);
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    getDefaultConfig() {
        return {
            theme: 'dark',
            animations: true,
            autoUpdate: true,
            preferences: {}
        };
    }

    get(key, defaultValue = null) {
        return this.config[key] ?? defaultValue;
    }

    set(key, value) {
        this.config[key] = value;
        return this;
    }
}

// Export appropriate version based on environment
if (typeof window !== 'undefined') {
    // Browser environment
    module.exports = BrowserConfigManager;
} else {
    // Node.js environment
    module.exports = ConfigManager;
    module.exports.BrowserConfigManager = BrowserConfigManager;
}
