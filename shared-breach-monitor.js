/**
 * TRAUMA Dark Web / Breach Monitor
 * Check if credentials appear in known data breaches
 * Uses HaveIBeenPwned API and other sources
 */

const https = require('https');
const crypto = require('crypto');

class BreachMonitor {
    constructor(apiKey = null) {
        this.apiKey = apiKey; // HaveIBeenPwned API key (optional)
        this.userAgent = 'TRAUMA-Security-Suite';
        this.cache = new Map();
        this.cacheTimeout = 3600000; // 1 hour
    }

    // K-Anonymity check - only sends first 5 chars of SHA1 hash
    async checkPassword(password) {
        const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
        const prefix = sha1.substring(0, 5);
        const suffix = sha1.substring(5);

        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'api.pwnedpasswords.com',
                path: `/range/${prefix}`,
                method: 'GET',
                headers: {
                    'User-Agent': this.userAgent
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        const hashes = data.split('\r\n');
                        const found = hashes.find(h => h.startsWith(suffix));
                        
                        if (found) {
                            const count = parseInt(found.split(':')[1], 10);
                            resolve({
                                compromised: true,
                                occurrences: count,
                                severity: this.getSeverity(count),
                                recommendation: this.getPasswordRecommendation(count)
                            });
                        } else {
                            resolve({
                                compromised: false,
                                occurrences: 0,
                                severity: 'safe',
                                recommendation: 'Password not found in known breaches'
                            });
                        }
                    } else {
                        reject(new Error(`API error: ${res.statusCode}`));
                    }
                });
            });

            req.on('error', reject);
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            req.end();
        });
    }

    getSeverity(count) {
        if (count === 0) return 'safe';
        if (count < 10) return 'low';
        if (count < 100) return 'medium';
        if (count < 1000) return 'high';
        return 'critical';
    }

    getPasswordRecommendation(count) {
        if (count === 0) return 'Password not found in known breaches';
        if (count < 10) return 'Password found in a few breaches. Consider changing it.';
        if (count < 100) return 'Password found in multiple breaches. Change it immediately.';
        if (count < 1000) return 'Password is commonly breached. Do NOT use this password.';
        return 'Password is extremely compromised. Never use this password anywhere.';
    }

    // Check email against HaveIBeenPwned (requires API key)
    async checkEmail(email) {
        if (!this.apiKey) {
            return {
                error: 'API key required for email checks',
                alternative: 'Visit haveibeenpwned.com to check manually'
            };
        }

        // Check cache
        const cached = this.cache.get(`email:${email}`);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.data;
        }

        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'haveibeenpwned.com',
                path: `/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
                method: 'GET',
                headers: {
                    'User-Agent': this.userAgent,
                    'hibp-api-key': this.apiKey
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            const breaches = JSON.parse(data);
                            const result = {
                                compromised: true,
                                breachCount: breaches.length,
                                breaches: breaches.map(b => ({
                                    name: b.Name,
                                    domain: b.Domain,
                                    breachDate: b.BreachDate,
                                    addedDate: b.AddedDate,
                                    compromisedData: b.DataClasses,
                                    verified: b.IsVerified,
                                    sensitive: b.IsSensitive,
                                    description: b.Description
                                })),
                                severity: this.getEmailSeverity(breaches.length)
                            };
                            
                            // Cache result
                            this.cache.set(`email:${email}`, {
                                data: result,
                                timestamp: Date.now()
                            });
                            
                            resolve(result);
                        } catch (e) {
                            reject(new Error('Failed to parse response'));
                        }
                    } else if (res.statusCode === 404) {
                        // No breaches found
                        const result = {
                            compromised: false,
                            breachCount: 0,
                            breaches: [],
                            severity: 'safe'
                        };
                        
                        this.cache.set(`email:${email}`, {
                            data: result,
                            timestamp: Date.now()
                        });
                        
                        resolve(result);
                    } else if (res.statusCode === 401) {
                        resolve({
                            error: 'Invalid API key',
                            statusCode: 401
                        });
                    } else if (res.statusCode === 429) {
                        resolve({
                            error: 'Rate limited. Try again later.',
                            statusCode: 429
                        });
                    } else {
                        reject(new Error(`API error: ${res.statusCode}`));
                    }
                });
            });

            req.on('error', reject);
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            req.end();
        });
    }

    getEmailSeverity(breachCount) {
        if (breachCount === 0) return 'safe';
        if (breachCount < 3) return 'low';
        if (breachCount < 10) return 'medium';
        if (breachCount < 25) return 'high';
        return 'critical';
    }

    // Check if email appears in pastes (requires API key)
    async checkPastes(email) {
        if (!this.apiKey) {
            return {
                error: 'API key required for paste checks',
                alternative: 'Visit haveibeenpwned.com to check manually'
            };
        }

        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'haveibeenpwned.com',
                path: `/api/v3/pasteaccount/${encodeURIComponent(email)}`,
                method: 'GET',
                headers: {
                    'User-Agent': this.userAgent,
                    'hibp-api-key': this.apiKey
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            const pastes = JSON.parse(data);
                            resolve({
                                found: true,
                                pasteCount: pastes.length,
                                pastes: pastes.map(p => ({
                                    source: p.Source,
                                    id: p.Id,
                                    title: p.Title,
                                    date: p.Date,
                                    emailCount: p.EmailCount
                                }))
                            });
                        } catch (e) {
                            reject(new Error('Failed to parse response'));
                        }
                    } else if (res.statusCode === 404) {
                        resolve({
                            found: false,
                            pasteCount: 0,
                            pastes: []
                        });
                    } else {
                        reject(new Error(`API error: ${res.statusCode}`));
                    }
                });
            });

            req.on('error', reject);
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            req.end();
        });
    }

    // Get all known breaches (for reference)
    async getAllBreaches() {
        const cached = this.cache.get('all-breaches');
        if (cached && Date.now() - cached.timestamp < 86400000) { // 24 hour cache
            return cached.data;
        }

        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'haveibeenpwned.com',
                path: '/api/v3/breaches',
                method: 'GET',
                headers: {
                    'User-Agent': this.userAgent
                }
            };

            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        try {
                            const breaches = JSON.parse(data);
                            const result = {
                                total: breaches.length,
                                breaches: breaches.map(b => ({
                                    name: b.Name,
                                    domain: b.Domain,
                                    breachDate: b.BreachDate,
                                    compromisedData: b.DataClasses,
                                    compromisedAccounts: b.PwnCount,
                                    verified: b.IsVerified
                                }))
                            };
                            
                            this.cache.set('all-breaches', {
                                data: result,
                                timestamp: Date.now()
                            });
                            
                            resolve(result);
                        } catch (e) {
                            reject(new Error('Failed to parse response'));
                        }
                    } else {
                        reject(new Error(`API error: ${res.statusCode}`));
                    }
                });
            });

            req.on('error', reject);
            req.setTimeout(15000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            req.end();
        });
    }

    // Generate security report
    async generateReport(emails = [], passwords = []) {
        const report = {
            generatedAt: new Date().toISOString(),
            emails: [],
            passwords: [],
            summary: {
                totalBreaches: 0,
                compromisedEmails: 0,
                compromisedPasswords: 0,
                recommendations: []
            }
        };

        // Check emails
        for (const email of emails) {
            try {
                const result = await this.checkEmail(email);
                report.emails.push({
                    email: email.replace(/(.{2}).(@.*)/, '$1***$2'), // Partially mask
                    ...result
                });
                
                if (result.compromised) {
                    report.summary.compromisedEmails++;
                    report.summary.totalBreaches += result.breachCount;
                    report.summary.recommendations.push(
                        `Change password for ${email.replace(/(.{2}).(@.*)/, '$1***$2')}`
                    );
                }
            } catch (e) {
                report.emails.push({
                    email: email.replace(/(.{2}).(@.*)/, '$1***$2'),
                    error: e.message
                });
            }
        }

        // Check passwords
        for (const password of passwords) {
            try {
                const result = await this.checkPassword(password);
                report.passwords.push({
                    hash: crypto.createHash('sha256').update(password).digest('hex').substring(0, 8),
                    ...result
                });
                
                if (result.compromised) {
                    report.summary.compromisedPasswords++;
                    report.summary.recommendations.push(
                        `Password ending in ...${password.slice(-3)} is compromised`
                    );
                }
            } catch (e) {
                report.passwords.push({
                    hash: 'error',
                    error: e.message
                });
            }
        }

        return report;
    }

    // Monitor multiple credentials periodically
    startMonitoring(credentials, callback, intervalMs = 86400000) { // Daily by default
        const check = async () => {
            try {
                const report = await this.generateReport(
                    credentials.emails || [],
                    credentials.passwords || []
                );
                callback(report);
            } catch (e) {
                callback({ error: e.message });
            }
        };

        // Check immediately
        check();

        // Schedule periodic checks
        this.monitorInterval = setInterval(check, intervalMs);
        
        return this.monitorInterval;
    }

    stopMonitoring() {
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
            this.monitorInterval = null;
        }
    }
}

// Browser-compatible version (limited functionality)
class BrowserBreachMonitor {
    constructor() {
        this.cache = new Map();
    }

    async checkPassword(password) {
        // Use Web Crypto API
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const sha1 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        
        const prefix = sha1.substring(0, 5);
        const suffix = sha1.substring(5);

        try {
            const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
                headers: { 'User-Agent': 'TRAUMA-Security-Suite' }
            });
            
            const text = await response.text();
            const hashes = text.split('\r\n');
            const found = hashes.find(h => h.startsWith(suffix));
            
            if (found) {
                const count = parseInt(found.split(':')[1], 10);
                return {
                    compromised: true,
                    occurrences: count,
                    severity: this.getSeverity(count)
                };
            }
            
            return {
                compromised: false,
                occurrences: 0,
                severity: 'safe'
            };
        } catch (e) {
            return { error: e.message };
        }
    }

    getSeverity(count) {
        if (count === 0) return 'safe';
        if (count < 10) return 'low';
        if (count < 100) return 'medium';
        if (count < 1000) return 'high';
        return 'critical';
    }
}

// Export appropriate version
if (typeof window !== 'undefined') {
    module.exports = BrowserBreachMonitor;
} else {
    module.exports = BreachMonitor;
    module.exports.BrowserBreachMonitor = BrowserBreachMonitor;
}
