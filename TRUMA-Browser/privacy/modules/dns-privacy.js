/**
 * TRUMA Browser - DNS Privacy Module
 * Supports DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT)
 */

const { net } = require('electron');
const https = require('https');
const tls = require('tls');

class DNSPrivacy {
    constructor(config, manager) {
        this.config = config;
        this.manager = manager;
        this.enabled = config.enabled !== false;
        this.dnsCache = new Map();
        this.pendingQueries = new Map();
        
        // Predefined DNS providers
        this.providers = {
            cloudflare: {
                name: 'Cloudflare',
                doh: 'https://cloudflare-dns.com/dns-query',
                dot: '1.1.1.1',
                ips: ['1.1.1.1', '1.0.0.1']
            },
            google: {
                name: 'Google',
                doh: 'https://dns.google/dns-query',
                dot: '8.8.8.8',
                ips: ['8.8.8.8', '8.8.4.4']
            },
            quad9: {
                name: 'Quad9',
                doh: 'https://dns.quad9.net/dns-query',
                dot: '9.9.9.9',
                ips: ['9.9.9.9', '149.112.112.112']
            },
            nextdns: {
                name: 'NextDNS',
                doh: 'https://dns.nextdns.io/dns-query',
                dot: '45.90.28.0',
                ips: ['45.90.28.0', '45.90.30.0']
            },
            adguard: {
                name: 'AdGuard',
                doh: 'https://dns.adguard.com/dns-query',
                dot: '94.140.14.14',
                ips: ['94.140.14.14', '94.140.15.15']
            }
        };

        this.currentProvider = this.providers[config.provider] || this.providers.cloudflare;
    }

    /**
     * Initialize DNS privacy
     */
    async initialize() {
        if (!this.enabled) {
            console.log('[DNSPrivacy] Disabled');
            return;
        }

        console.log('[DNSPrivacy] Initialized with provider:', this.currentProvider.name);
        console.log('[DNSPrivacy] Mode:', this.config.mode);
    }

    /**
     * Resolve hostname using encrypted DNS
     */
    async resolve(hostname) {
        // Check cache first
        if (this.dnsCache.has(hostname)) {
            const cached = this.dnsCache.get(hostname);
            if (Date.now() - cached.timestamp < 300000) { // 5 min TTL
                return cached.ips;
            }
        }

        // Check pending queries
        if (this.pendingQueries.has(hostname)) {
            return this.pendingQueries.get(hostname);
        }

        // Create new query promise
        const queryPromise = this.performQuery(hostname);
        this.pendingQueries.set(hostname, queryPromise);

        try {
            const ips = await queryPromise;
            this.dnsCache.set(hostname, { ips, timestamp: Date.now() });
            return ips;
        } finally {
            this.pendingQueries.delete(hostname);
        }
    }

    /**
     * Perform DNS query
     */
    async performQuery(hostname) {
        if (this.config.mode === 'doh') {
            return this.queryDoH(hostname);
        } else if (this.config.mode === 'dot') {
            return this.queryDoT(hostname);
        }
        
        // Fallback to system DNS
        return this.querySystemDNS(hostname);
    }

    /**
     * DNS-over-HTTPS query
     */
    async queryDoH(hostname) {
        const url = `${this.currentProvider.doh}?name=${encodeURIComponent(hostname)}&type=A`;
        
        return new Promise((resolve, reject) => {
            const req = https.request(url, {
                method: 'GET',
                headers: {
                    'Accept': 'application/dns-json',
                    'User-Agent': 'TRUMA-Browser/1.0'
                }
            }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        this.manager.updateStat('dnsQueriesEncrypted');
                        
                        if (json.Answer) {
                            const ips = json.Answer
                                .filter(a => a.type === 1) // A records
                                .map(a => a.data);
                            resolve(ips);
                        } else {
                            resolve([]);
                        }
                    } catch (e) {
                        console.error('[DNSPrivacy] DoH parse error:', e);
                        resolve([]);
                    }
                });
            });

            req.on('error', (e) => {
                console.error('[DNSPrivacy] DoH error:', e);
                resolve([]);
            });

            req.setTimeout(5000, () => {
                req.destroy();
                resolve([]);
            });

            req.end();
        });
    }

    /**
     * DNS-over-TLS query
     */
    async queryDoT(hostname) {
        return new Promise((resolve, reject) => {
            const socket = tls.connect({
                host: this.currentProvider.dot,
                port: 853,
                servername: this.currentProvider.name.toLowerCase(),
                rejectUnauthorized: true
            }, () => {
                // Build DNS query packet
                const query = this.buildDNSQuery(hostname);
                socket.write(query);
            });

            socket.on('data', (data) => {
                try {
                    const ips = this.parseDNSResponse(data);
                    this.manager.updateStat('dnsQueriesEncrypted');
                    resolve(ips);
                } catch (e) {
                    console.error('[DNSPrivacy] DoT parse error:', e);
                    resolve([]);
                }
                socket.destroy();
            });

            socket.on('error', (e) => {
                console.error('[DNSPrivacy] DoT error:', e);
                resolve([]);
            });

            socket.setTimeout(5000, () => {
                socket.destroy();
                resolve([]);
            });
        });
    }

    /**
     * Build DNS query packet
     */
    buildDNSQuery(hostname) {
        const header = Buffer.alloc(12);
        // Transaction ID
        header.writeUInt16BE(0x1234, 0);
        // Flags: standard query
        header.writeUInt16BE(0x0100, 2);
        // Questions: 1
        header.writeUInt16BE(1, 4);
        // Other counts: 0
        header.writeUInt16BE(0, 6);
        header.writeUInt16BE(0, 8);
        header.writeUInt16BE(0, 10);

        // Build question
        const labels = hostname.split('.').map(label => {
            const labelBuffer = Buffer.alloc(label.length + 1);
            labelBuffer.writeUInt8(label.length, 0);
            labelBuffer.write(label, 1);
            return labelBuffer;
        });

        const question = Buffer.concat([
            ...labels,
            Buffer.from([0]), // End of labels
            Buffer.from([0, 1]), // Type A
            Buffer.from([0, 1])  // Class IN
        ]);

        // Length prefix for TCP
        const length = Buffer.alloc(2);
        length.writeUInt16BE(header.length + question.length, 0);

        return Buffer.concat([length, header, question]);
    }

    /**
     * Parse DNS response
     */
    parseDNSResponse(data) {
        // Skip length prefix for TCP
        const response = data.slice(2);
        
        const answerCount = response.readUInt16BE(6);
        const ips = [];

        // Find answer section (skip header and question)
        let offset = 12;
        
        // Skip question section
        while (response[offset] !== 0) {
            offset += response[offset] + 1;
        }
        offset += 5; // End marker + QTYPE + QCLASS

        // Parse answers
        for (let i = 0; i < answerCount && offset < response.length; i++) {
            // Skip name (might be compressed)
            if ((response[offset] & 0xc0) === 0xc0) {
                offset += 2; // Compressed name pointer
            } else {
                while (response[offset] !== 0) {
                    offset += response[offset] + 1;
                }
                offset += 1;
            }

            const type = response.readUInt16BE(offset);
            offset += 2;
            const cls = response.readUInt16BE(offset);
            offset += 2;
            const ttl = response.readUInt32BE(offset);
            offset += 4;
            const rdlength = response.readUInt16BE(offset);
            offset += 2;

            if (type === 1 && rdlength === 4) { // A record
                const ip = `${response[offset]}.${response[offset+1]}.${response[offset+2]}.${response[offset+3]}`;
                ips.push(ip);
            }

            offset += rdlength;
        }

        return ips;
    }

    /**
     * Fallback to system DNS
     */
    async querySystemDNS(hostname) {
        const dns = require('dns');
        return new Promise((resolve) => {
            dns.lookup(hostname, { all: true }, (err, addresses) => {
                if (err) {
                    resolve([]);
                } else {
                    resolve(addresses.map(a => a.address));
                }
            });
        });
    }

    /**
     * Set DNS provider
     */
    setProvider(providerName) {
        if (this.providers[providerName]) {
            this.currentProvider = this.providers[providerName];
            this.config.provider = providerName;
            this.dnsCache.clear();
            return true;
        }
        return false;
    }

    /**
     * Add custom provider
     */
    addCustomProvider(config) {
        if (config.name && (config.doh || config.dot)) {
            this.providers.custom = {
                name: config.name,
                doh: config.doh,
                dot: config.dot,
                ips: config.ips || []
            };
            return true;
        }
        return false;
    }

    /**
     * Get available providers
     */
    getProviders() {
        return Object.entries(this.providers).map(([id, provider]) => ({
            id,
            name: provider.name,
            hasDoH: !!provider.doh,
            hasDoT: !!provider.dot
        }));
    }

    /**
     * Clear DNS cache
     */
    clearCache() {
        this.dnsCache.clear();
    }

    /**
     * Update configuration
     */
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        this.enabled = this.config.enabled !== false;
        
        if (this.config.provider && this.providers[this.config.provider]) {
            this.currentProvider = this.providers[this.config.provider];
        }
    }

    /**
     * Cleanup
     */
    async cleanup() {
        this.dnsCache.clear();
        this.pendingQueries.clear();
    }
}

module.exports = DNSPrivacy;
