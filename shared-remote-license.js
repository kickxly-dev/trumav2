/**
 * TRAUMA Remote License Validator
 * Validates licenses against the remote license server
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// Configuration
const LICENSE_SERVER = process.env.TRAUMA_LICENSE_SERVER || 'http://localhost:3001';
const LOCAL_CACHE_FILE = path.join(os.homedir(), '.trauma', 'license-cache.json');
const CACHE_DURATION = 3600000; // 1 hour

class RemoteLicenseValidator {
    constructor(toolName = 'unknown') {
        this.toolName = toolName;
        this.serverUrl = LICENSE_SERVER;
        this.cache = null;
        this.hardwareId = this.getHardwareId();
    }

    getHardwareId() {
        const info = [
            os.hostname(),
            os.platform(),
            os.cpus()[0]?.model || 'unknown',
            Object.values(os.networkInterfaces())
                .flat()
                .find(i => i.mac && !i.internal)?.mac || 'unknown'
        ].join('-');
        return crypto.createHash('sha256').update(info).digest('hex').substring(0, 32);
    }

    loadCache() {
        if (this.cache) return this.cache;
        
        try {
            if (fs.existsSync(LOCAL_CACHE_FILE)) {
                const data = JSON.parse(fs.readFileSync(LOCAL_CACHE_FILE, 'utf8'));
                if (Date.now() - data.cachedAt < CACHE_DURATION) {
                    this.cache = data;
                    return data;
                }
            }
        } catch (e) {}
        
        return null;
    }

    saveCache(key, data) {
        try {
            const cacheDir = path.dirname(LOCAL_CACHE_FILE);
            if (!fs.existsSync(cacheDir)) {
                fs.mkdirSync(cacheDir, { recursive: true });
            }
            
            this.cache = {
                key,
                ...data,
                cachedAt: Date.now()
            };
            
            fs.writeFileSync(LOCAL_CACHE_FILE, JSON.stringify(this.cache, null, 2));
        } catch (e) {}
    }

    async validate(key, useCache = true) {
        // Check cache first
        if (useCache) {
            const cache = this.loadCache();
            if (cache && cache.key === key && cache.valid) {
                return {
                    valid: true,
                    user: cache.user,
                    expires: cache.expires,
                    daysRemaining: cache.daysRemaining,
                    fromCache: true
                };
            }
        }

        return new Promise((resolve) => {
            const url = `${this.serverUrl}/api/license/validate`;
            const protocol = this.serverUrl.startsWith('https') ? https : http;
            
            const postData = JSON.stringify({
                key,
                tool: this.toolName,
                hardwareId: this.hardwareId
            });

            const urlObj = new URL(url);
            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
                path: urlObj.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData)
                },
                timeout: 10000
            };

            const req = protocol.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const result = JSON.parse(data);
                        
                        if (result.valid) {
                            this.saveCache(key, result);
                        }
                        
                        resolve(result);
                    } catch (e) {
                        // Fallback to local validation if server unreachable
                        resolve(this.fallbackValidate(key));
                    }
                });
            });

            req.on('error', () => {
                resolve(this.fallbackValidate(key));
            });

            req.on('timeout', () => {
                req.destroy();
                resolve(this.fallbackValidate(key));
            });

            req.write(postData);
            req.end();
        });
    }

    async activate(key) {
        return new Promise((resolve) => {
            const url = `${this.serverUrl}/api/license/activate`;
            const protocol = this.serverUrl.startsWith('https') ? https : http;
            
            const postData = JSON.stringify({
                key,
                tool: this.toolName,
                hardwareId: this.hardwareId
            });

            const urlObj = new URL(url);
            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
                path: urlObj.pathname,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData)
                },
                timeout: 10000
            };

            const req = protocol.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const result = JSON.parse(data);
                        resolve(result);
                    } catch (e) {
                        resolve({ success: false, error: 'Server error' });
                    }
                });
            });

            req.on('error', (e) => {
                resolve({ success: false, error: e.message });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve({ success: false, error: 'Timeout' });
            });

            req.write(postData);
            req.end();
        });
    }

    fallbackValidate(key) {
        // Try local license file if server is unreachable
        try {
            const localKeyFile = path.join(__dirname, 'TRUMA-OSINT', 'license.key');
            if (fs.existsSync(localKeyFile)) {
                const data = JSON.parse(fs.readFileSync(localKeyFile, 'utf8'));
                if (data.key === key) {
                    const expires = new Date(data.expires);
                    const valid = expires > new Date();
                    return {
                        valid,
                        user: data.user,
                        expires: data.expires,
                        daysRemaining: Math.ceil((expires - new Date()) / (1000 * 60 * 60 * 24)),
                        fromFallback: true
                    };
                }
            }
        } catch (e) {}
        
        return { valid: false, error: 'Server unreachable and no local license' };
    }

    async checkExpiryWarning(key) {
        return new Promise((resolve) => {
            const url = `${this.serverUrl}/api/license/warning/${encodeURIComponent(key)}`;
            const protocol = this.serverUrl.startsWith('https') ? https : http;
            
            const urlObj = new URL(url);
            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
                path: urlObj.pathname,
                method: 'GET',
                timeout: 10000
            };

            const req = protocol.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        resolve({ error: 'Server error' });
                    }
                });
            });

            req.on('error', (e) => {
                resolve({ error: e.message });
            });

            req.on('timeout', () => {
                req.destroy();
                resolve({ error: 'Timeout' });
            });

            req.end();
        });
    }

    clearCache() {
        this.cache = null;
        try {
            if (fs.existsSync(LOCAL_CACHE_FILE)) {
                fs.unlinkSync(LOCAL_CACHE_FILE);
            }
        } catch (e) {}
    }
}

// Browser-compatible version
class BrowserRemoteLicenseValidator {
    constructor(toolName = 'unknown') {
        this.toolName = toolName;
        this.serverUrl = localStorage.getItem('trauma_license_server') || 'http://localhost:3001';
    }

    async validate(key, useCache = true) {
        // Check cache
        if (useCache) {
            const cached = localStorage.getItem('trauma_license_cache');
            if (cached) {
                try {
                    const data = JSON.parse(cached);
                    if (data.key === key && data.valid && Date.now() - data.cachedAt < 3600000) {
                        return { ...data, fromCache: true };
                    }
                } catch (e) {}
            }
        }

        try {
            const response = await fetch(`${this.serverUrl}/api/license/validate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key, tool: this.toolName })
            });
            
            const result = await response.json();
            
            if (result.valid) {
                localStorage.setItem('trauma_license_cache', JSON.stringify({
                    key,
                    ...result,
                    cachedAt: Date.now()
                }));
            }
            
            return result;
        } catch (e) {
            return { valid: false, error: 'Server unreachable' };
        }
    }

    async activate(key) {
        try {
            const response = await fetch(`${this.serverUrl}/api/license/activate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key, tool: this.toolName })
            });
            
            return await response.json();
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    clearCache() {
        localStorage.removeItem('trauma_license_cache');
    }
}

// Export appropriate version
if (typeof window !== 'undefined') {
    module.exports = BrowserRemoteLicenseValidator;
} else {
    module.exports = RemoteLicenseValidator;
    module.exports.BrowserRemoteLicenseValidator = BrowserRemoteLicenseValidator;
}
