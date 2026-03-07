/**
 * TRUMA Browser - Tracker Blocker Module
 * Blocks tracking scripts, ads, and third-party cookies
 */

class TrackerBlocker {
    constructor(config, manager) {
        this.config = config;
        this.manager = manager;
        this.enabled = config.enabled !== false;
        this.blockedDomains = new Set();
        this.blockedPatterns = [];
        this.allowedDomains = new Map(); // Per-site allowlist
        this.filterLists = [];
        
        this.loadDefaultFilters();
    }

    /**
     * Load default filter lists
     */
    loadDefaultFilters() {
        // Major tracking domains
        const trackingDomains = [
            // Google
            'googleadservices.com', 'googlesyndication.com', 'google-analytics.com',
            'doubleclick.net', 'googletagmanager.com', 'googletagservices.com',
            'pagead2.googlesyndication.com', 'googleads.g.doubleclick.net',
            
            // Facebook
            'connect.facebook.net', 'facebook.com/tr', 'facebook.net',
            'fbcdn.net', 'atlassolutions.com',
            
            // Amazon
            'adsystem.amazon.com', 'amazon-adsystem.com', 'amazon-ads.com',
            
            // Microsoft
            'ads.microsoft.com', 'bat.bing.com', 'bing.com',
            
            // Yahoo
            'ads.yahoo.com', 'advertising.yahoo.com', 'analytics.yahoo.com',
            
            // Major ad networks
            'adnxs.com', 'adsrvr.org', 'advertising.com', 'casalemedia.com',
            'openx.net', 'pubmatic.com', 'rubiconproject.com', 'lijit.com',
            'contextweb.com', 'criteo.com', 'criteo.net', 'outbrain.com',
            'taboola.com', 'scorecardresearch.com', 'quantserve.com',
            'adsafeprotected.com', 'moatads.com',
            
            // Data brokers
            'acxiom.com', 'experian.com', 'equifax.com', 'oracle.com',
            'bluekai.com', 'krux.com', 'lotame.com', 'addthis.com',
            
            // Fingerprinting
            'fingerprintjs.com', 'fpjs.io', 'clientjs.org',
            
            // Analytics
            'hotjar.com', 'mixpanel.com', 'amplitude.com', 'heap.io',
            'segment.com', 'optimizely.com', 'crazyegg.com', 'mouseflow.com',
            'clicktale.com', 'luckyorange.com', 'inspectlet.com',
            
            // Social trackers
            'twitter.com/i/adsct', 'pinterest.com', 'linkedin.com/pixel',
            'tiktok.com/pixel',
            
            // CNAME tracking
            'cname-tracking.com', 'eulerian.net', 'dnsdelegation.io'
        ];

        trackingDomains.forEach(d => this.blockedDomains.add(d));

        // URL patterns to block
        this.blockedPatterns = [
            /\/ads?\//i,
            /\/advertisement/i,
            /\/tracking\//i,
            /\/tracker\//i,
            /\/telemetry\//i,
            /\/beacon\//i,
            /\/pixel\//i,
            /\/collect\?/i,
            /\/analytics\.js$/i,
            /\/gtm\.js$/i,
            /\/fbevents\.js$/i,
            /\/ads\.js$/i,
            /\/tracker\.js$/i,
            /\/pixel\.gif\?/i,
            /\/__utm\.gif/i,
            /\/impression\//i,
            /\/conversion\//i,
            /\/retargeting\//i,
            /\/affiliates?\//i,
            /\/sponsor/i,
            /\/promoted/i,
            /gpt\.js$/i,
            /prebid/i,
            /adsbygoogle/i,
            /adsense/i,
            /doubleclick/i,
            /google_tag_manager/i,
            /google_analytics/i,
            /dataLayer/i,
            /fbq\(/i,
            /_fbp=/i,
            /_fbc=/i,
            /__ut[m,a,b,c,d]=/i,
            /_ga=/i,
            /_gid=/i,
            /msclkid=/i,
            /gclid=/i,
            /fbclid=/i,
            /dclid=/i,
            /yclid=/i,
            /mc_eid=/i
        ];
    }

    /**
     * Initialize the tracker blocker
     */
    async initialize(sess) {
        this.session = sess;

        // Block third-party cookies
        if (this.config.blockThirdPartyCookies) {
            const { session: electronSession } = require('electron');
            sess.webRequest.onHeadersReceived((details, callback) => {
                const headers = details.responseHeaders;
                const url = new URL(details.url);
                const firstParty = details.firstPartyUrl || details.url;
                
                // Check if third-party
                if (firstParty && !this.isFirstParty(url.hostname, new URL(firstParty).hostname)) {
                    // Remove Set-Cookie headers for third-party
                    if (headers['set-cookie']) {
                        this.manager.updateStat('cookiesBlocked');
                        delete headers['set-cookie'];
                    }
                }
                
                callback({ responseHeaders: headers });
            });
        }

        // Setup request blocking
        sess.webRequest.onBeforeRequest({ urls: ['*://*/*'] }, (details, callback) => {
            if (!this.enabled || this.config.level === 'off') {
                return callback({ cancel: false });
            }

            const url = details.url.toLowerCase();
            
            try {
                const urlObj = new URL(url);
                const hostname = urlObj.hostname;

                // Check if domain is allowed for this site
                const originUrl = details.firstPartyUrl || details.originUrl;
                if (originUrl) {
                    const origin = new URL(originUrl).hostname;
                    if (this.isDomainAllowed(hostname, origin)) {
                        return callback({ cancel: false });
                    }
                }

                // Check blocked domains
                for (const blockedDomain of this.blockedDomains) {
                    if (hostname === blockedDomain || hostname.endsWith('.' + blockedDomain)) {
                        console.log(`[TrackerBlocker] Blocked domain: ${hostname}`);
                        this.manager.updateStat('trackersBlocked');
                        return callback({ cancel: true });
                    }
                }

                // Strict mode - check patterns
                if (this.config.level === 'strict') {
                    for (const pattern of this.blockedPatterns) {
                        if (pattern.test(url)) {
                            console.log(`[TrackerBlocker] Blocked pattern: ${url.substring(0, 100)}`);
                            this.manager.updateStat('trackersBlocked');
                            return callback({ cancel: true });
                        }
                    }

                    // Block third-party scripts in strict mode
                    if (this.config.blockThirdPartyScripts) {
                        const type = details.type;
                        if (type === 'script' || type === 'sub_frame') {
                            const initiator = details.initiator || details.originUrl;
                            if (initiator && !this.isFirstParty(hostname, new URL(initiator).hostname)) {
                                // Allow if it looks like a legitimate script
                                if (!this.isLegitimateScript(url)) {
                                    console.log(`[TrackerBlocker] Blocked third-party script: ${hostname}`);
                                    this.manager.updateStat('trackersBlocked');
                                    return callback({ cancel: true });
                                }
                            }
                        }
                    }
                }
            } catch (e) {
                // Invalid URL, allow
            }

            callback({ cancel: false });
        });

        // Setup response header modification
        sess.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, callback) => {
            const headers = details.responseHeaders || {};

            // Add security headers
            headers['X-Content-Type-Options'] = ['nosniff'];
            headers['X-Frame-Options'] = ['SAMEORIGIN'];
            headers['X-XSS-Protection'] = ['1; mode=block'];
            
            // Referrer policy
            headers['Referrer-Policy'] = ['strict-origin-when-cross-origin'];

            // Permissions policy
            headers['Permissions-Policy'] = [
                'geolocation=(), microphone=(), camera=(), ' +
                'magnetometer=(), gyroscope=(), accelerometer=(), ' +
                'ambient-light-sensor=(), autoplay=(), encrypted-media=()'
            ];

            callback({ responseHeaders: headers });
        });

        console.log('[TrackerBlocker] Initialized with level:', this.config.level);
    }

    /**
     * Check if two domains are first-party to each other
     */
    isFirstParty(domain1, domain2) {
        if (!domain1 || !domain2) return true;
        
        // Get base domain (e.g., example.com from sub.example.com)
        const getBaseDomain = (d) => {
            const parts = d.split('.').reverse();
            if (parts.length >= 2) {
                return parts[1] + '.' + parts[0];
            }
            return d;
        };

        return getBaseDomain(domain1) === getBaseDomain(domain2);
    }

    /**
     * Check if a script looks legitimate
     */
    isLegitimateScript(url) {
        const legitimatePatterns = [
            /\.js$/i,
            /\/js\//i,
            /\/javascript\//i,
            /\/scripts?\//i,
            /\/assets\//i,
            /\/static\//i,
            /\/dist\//i,
            /\/build\//i,
            /\/vendor\//i,
            /\/lib\//i,
            /cdn\./i,
            /cdnjs\./i,
            /unpkg\./i,
            /jsdelivr\./i
        ];

        const suspiciousPatterns = [
            /analytics/i,
            /tracking/i,
            /tracker/i,
            /pixel/i,
            /beacon/i,
            /collect/i,
            /telemetry/i,
            /ads?\.js/i,
            /advert/i,
            /promo/i
        ];

        // Must match legitimate and not match suspicious
        const isLegit = legitimatePatterns.some(p => p.test(url));
        const isSuspicious = suspiciousPatterns.some(p => p.test(url));

        return isLegit && !isSuspicious;
    }

    /**
     * Check if domain is allowed for a specific origin
     */
    isDomainAllowed(domain, origin) {
        const allowed = this.allowedDomains.get(origin);
        return allowed && allowed.has(domain);
    }

    /**
     * Allow a domain for a specific origin
     */
    allowDomain(domain, origin) {
        if (!this.allowedDomains.has(origin)) {
            this.allowedDomains.set(origin, new Set());
        }
        this.allowedDomains.get(origin).add(domain);
    }

    /**
     * Remove domain from allowlist
     */
    disallowDomain(domain, origin) {
        const allowed = this.allowedDomains.get(origin);
        if (allowed) {
            allowed.delete(domain);
        }
    }

    /**
     * Add custom filter
     */
    addCustomFilter(filter) {
        if (typeof filter === 'string') {
            // Parse filter string (like EasyList format)
            if (filter.startsWith('||') && filter.endsWith('^')) {
                const domain = filter.slice(2, -1);
                this.blockedDomains.add(domain);
            } else {
                try {
                    this.blockedPatterns.push(new RegExp(filter, 'i'));
                } catch (e) {
                    console.error('[TrackerBlocker] Invalid filter pattern:', filter);
                }
            }
        }
        this.config.customFilters.push(filter);
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
        this.allowedDomains.clear();
    }
}

module.exports = TrackerBlocker;
