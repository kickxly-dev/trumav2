/**
 * TRUMA Browser - Cookie Isolation Module
 * Isolates cookies per-site to prevent cross-site tracking
 */

class CookieIsolation {
    constructor(config, manager) {
        this.config = config;
        this.manager = manager;
        this.enabled = config.enabled !== false;
        this.containers = new Map();
        this.currentContainer = null;
    }

    /**
     * Initialize cookie isolation
     */
    async initialize(sess) {
        this.session = sess;

        // Setup container-based isolation
        if (this.config.mode === 'strict') {
            // Each site gets its own container
            sess.webRequest.onBeforeSendHeaders({ urls: ['*://*/*'] }, (details, callback) => {
                if (!this.enabled) {
                    return callback({});
                }

                const url = new URL(details.url);
                const hostname = url.hostname;
                const containerId = this.getOrCreateContainer(hostname);

                // Modify cookies to be container-specific
                const headers = details.requestHeaders || [];
                const cookies = headers.find(h => h.name.toLowerCase() === 'cookie');
                
                if (cookies) {
                    // Filter cookies to only include those for this container
                    const containerCookies = this.getContainerCookies(containerId, hostname);
                    if (containerCookies) {
                        cookies.value = containerCookies;
                    } else {
                        // Remove cookie header entirely for cross-site requests
                        const index = headers.indexOf(cookies);
                        headers.splice(index, 1);
                        this.manager.updateStat('cookiesBlocked');
                    }
                }

                callback({ requestHeaders: headers });
            });

            // Intercept Set-Cookie headers
            sess.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, callback) => {
                if (!this.enabled) {
                    return callback({});
                }

                const headers = details.responseHeaders || {};
                const url = new URL(details.url);
                const hostname = url.hostname;
                const containerId = this.getOrCreateContainer(hostname);

                if (headers['set-cookie']) {
                    // Store cookies in container
                    const cookies = headers['set-cookie'];
                    this.storeContainerCookies(containerId, hostname, cookies);
                    
                    // Remove third-party cookies
                    const originUrl = details.firstPartyUrl || details.originUrl;
                    if (originUrl) {
                        const origin = new URL(originUrl).hostname;
                        if (!this.isFirstParty(hostname, origin)) {
                            delete headers['set-cookie'];
                            this.manager.updateStat('cookiesBlocked');
                        }
                    }
                }

                callback({ responseHeaders: headers });
            });
        }

        console.log('[CookieIsolation] Initialized with mode:', this.config.mode);
    }

    /**
     * Get or create container for a domain
     */
    getOrCreateContainer(hostname) {
        const baseDomain = this.getBaseDomain(hostname);
        
        if (!this.containers.has(baseDomain)) {
            this.containers.set(baseDomain, {
                id: `${this.config.containerPrefix}-${baseDomain}`,
                domain: baseDomain,
                cookies: new Map(),
                localStorage: new Map(),
                sessionStorage: new Map(),
                createdAt: Date.now()
            });
        }

        return this.containers.get(baseDomain);
    }

    /**
     * Get base domain from hostname
     */
    getBaseDomain(hostname) {
        const parts = hostname.split('.').reverse();
        if (parts.length >= 2) {
            // Handle special TLDs like co.uk
            const specialTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp'];
            const potentialSpecial = parts[1] + '.' + parts[0];
            if (specialTlds.includes(potentialSpecial)) {
                return parts[2] + '.' + potentialSpecial;
            }
            return parts[1] + '.' + parts[0];
        }
        return hostname;
    }

    /**
     * Check if two domains are first-party
     */
    isFirstParty(domain1, domain2) {
        return this.getBaseDomain(domain1) === this.getBaseDomain(domain2);
    }

    /**
     * Get cookies for a container
     */
    getContainerCookies(container, hostname) {
        if (container && container.cookies) {
            const domainCookies = container.cookies.get(hostname);
            if (domainCookies && domainCookies.length > 0) {
                return domainCookies.map(c => `${c.name}=${c.value}`).join('; ');
            }
        }
        return null;
    }

    /**
     * Store cookies in container
     */
    storeContainerCookies(container, hostname, cookies) {
        if (!container.cookies.has(hostname)) {
            container.cookies.set(hostname, []);
        }

        const parsedCookies = cookies.map(cookieStr => this.parseCookie(cookieStr));
        container.cookies.get(hostname).push(...parsedCookies);
    }

    /**
     * Parse a Set-Cookie string
     */
    parseCookie(cookieStr) {
        const parts = cookieStr.split(';').map(p => p.trim());
        const [nameValue, ...attributes] = parts;
        const [name, value] = nameValue.split('=');

        const cookie = {
            name: name.trim(),
            value: value ? value.trim() : '',
            attributes: {}
        };

        attributes.forEach(attr => {
            const [key, val] = attr.split('=');
            cookie.attributes[key.toLowerCase()] = val || true;
        });

        return cookie;
    }

    /**
     * Clear container for a specific domain
     */
    clearContainer(hostname) {
        const baseDomain = this.getBaseDomain(hostname);
        this.containers.delete(baseDomain);
    }

    /**
     * Clear all containers
     */
    clearAllContainers() {
        this.containers.clear();
    }

    /**
     * Get container stats
     */
    getStats() {
        let totalCookies = 0;
        let totalContainers = this.containers.size;

        this.containers.forEach(container => {
            container.cookies.forEach(cookies => {
                totalCookies += cookies.length;
            });
        });

        return {
            containers: totalContainers,
            cookies: totalCookies
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
        this.containers.clear();
    }
}

module.exports = CookieIsolation;
