/**
 * TRUMA NET V2 - Client Protection Script
 * Add this script to ANY website for instant protection
 * 
 * Usage:
 * <script src="https://your-trauma-server.com/truma-net-client.js" data-site-id="YOUR_SITE_ID"></script>
 */

(function() {
    'use strict';

    // Configuration from script tag
    const scriptTag = document.currentScript || document.querySelector('script[data-site-id]');
    const SITE_ID = scriptTag?.dataset?.siteId || 'default';
    const API_URL = scriptTag?.src?.replace('/truma-net-client.js', '') || 'https://trauma-suite.onrender.com';

    // TRUMA NET Client
    const TRUMA_NET = {
        version: '2.0.0',
        siteId: SITE_ID,
        apiUrl: API_URL,
        
        // Collect visitor data
        collectVisitorData: function() {
            return {
                siteId: this.siteId,
                url: window.location.href,
                path: window.location.pathname,
                referrer: document.referrer || 'direct',
                userAgent: navigator.userAgent,
                language: navigator.language,
                cookiesEnabled: navigator.cookieEnabled,
                screenWidth: window.screen.width,
                screenHeight: window.screen.height,
                colorDepth: window.screen.colorDepth,
                devicePixelRatio: window.devicePixelRatio,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timestamp: new Date().toISOString(),
                // Behavioral data
                mouseMovements: 0,
                clicks: 0,
                scrollDepth: 0,
                timeOnPage: 0
            };
        },

        // Track behavior
        behaviorData: {
            mouseMovements: 0,
            clicks: 0,
            scrollDepth: 0,
            startTime: Date.now()
        },

        // Initialize tracking
        initTracking: function() {
            const self = this;
            
            // Mouse movement tracking
            document.addEventListener('mousemove', function() {
                self.behaviorData.mouseMovements++;
            }, { passive: true });

            // Click tracking
            document.addEventListener('click', function() {
                self.behaviorData.clicks++;
            }, { passive: true });

            // Scroll tracking
            window.addEventListener('scroll', function() {
                const scrollHeight = document.documentElement.scrollHeight - window.innerHeight;
                self.behaviorData.scrollDepth = Math.max(
                    self.behaviorData.scrollDepth,
                    Math.round((window.scrollY / scrollHeight) * 100)
                );
            }, { passive: true });

            // Time on page
            setInterval(function() {
                self.behaviorData.timeOnPage = Math.round((Date.now() - self.behaviorData.startTime) / 1000);
            }, 1000);
        },

        // Send visitor data to TRUMA NET
        reportVisitor: async function() {
            try {
                const data = this.collectVisitorData();
                data.mouseMovements = this.behaviorData.mouseMovements;
                data.clicks = this.behaviorData.clicks;
                data.scrollDepth = this.behaviorData.scrollDepth;
                data.timeOnPage = this.behaviorData.timeOnPage;

                const response = await fetch(`${this.apiUrl}/api/truma-net/visitor`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Truma-Site': this.siteId
                    },
                    body: JSON.stringify(data)
                });

                const result = await response.json();
                
                // If blocked, show message and stop
                if (result.blocked) {
                    this.showBlocked(result.reason);
                    return false;
                }

                return true;
            } catch (error) {
                console.warn('[TRUMA NET] Connection error:', error);
                return true; // Allow on error
            }
        },

        // Show blocked message
        showBlocked: function(reason) {
            document.body.innerHTML = `
                <div style="
                    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
                    background: #0a0a0a; color: #fff;
                    display: flex; flex-direction: column;
                    align-items: center; justify-content: center;
                    font-family: 'Courier New', monospace; z-index: 999999;
                ">
                    <div style="font-size: 4rem; margin-bottom: 1rem;">🛡️</div>
                    <h1 style="color: #dc143c; font-size: 2rem; margin-bottom: 1rem;">TRUMA NET V2</h1>
                    <p style="color: #ff4444; font-size: 1.2rem;">ACCESS DENIED</p>
                    <p style="color: #888; margin-top: 1rem;">${reason || 'Your IP has been blocked'}</p>
                    <p style="color: #555; margin-top: 2rem; font-size: 0.8rem;">Protected by TRUMA NET V2</p>
                </div>
            `;
        },

        // Check if current action is allowed
        checkRequest: async function(action, data) {
            try {
                const response = await fetch(`${this.apiUrl}/api/truma-net/check`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Truma-Site': this.siteId
                    },
                    body: JSON.stringify({ action, data })
                });

                const result = await response.json();
                return result.allowed !== false;
            } catch (error) {
                return true; // Allow on error
            }
        },

        // Report suspicious activity
        reportThreat: async function(threatType, details) {
            try {
                await fetch(`${this.apiUrl}/api/truma-net/threat`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Truma-Site': this.siteId
                    },
                    body: JSON.stringify({ threatType, details })
                });
            } catch (error) {
                console.warn('[TRUMA NET] Failed to report threat');
            }
        },

        // Form protection
        protectForms: function() {
            const self = this;
            
            document.querySelectorAll('form').forEach(form => {
                form.addEventListener('submit', async function(e) {
                    const formData = new FormData(form);
                    const data = {};
                    formData.forEach((value, key) => data[key] = value);

                    // Check for XSS patterns
                    const xssPattern = /<script|javascript:|on\w+\s*=|<iframe|eval\(|document\./i;
                    for (const [key, value] of Object.entries(data)) {
                        if (xssPattern.test(value)) {
                            e.preventDefault();
                            self.reportThreat('XSS_ATTEMPT', { field: key, value: value.substring(0, 100) });
                            alert('Invalid input detected');
                            return false;
                        }
                    }

                    // Check with server
                    const allowed = await self.checkRequest('form_submit', data);
                    if (!allowed) {
                        e.preventDefault();
                        self.showBlocked('Form submission blocked');
                        return false;
                    }
                });
            });
        },

        // Rate limit local actions
        rateLimiter: {
            actions: {},
            check: function(action, limit, window) {
                const now = Date.now();
                if (!this.actions[action]) {
                    this.actions[action] = [];
                }
                
                // Remove old actions
                this.actions[action] = this.actions[action].filter(t => now - t < window);
                
                if (this.actions[action].length >= limit) {
                    return false;
                }
                
                this.actions[action].push(now);
                return true;
            }
        },

        // Protect against rapid actions
        protectActions: function() {
            const self = this;
            
            // Rate limit clicks
            document.addEventListener('click', function(e) {
                if (!self.rateLimiter.check('click', 20, 1000)) {
                    e.stopPropagation();
                    e.preventDefault();
                }
            }, true);

            // Rate limit keypresses
            document.addEventListener('keydown', function(e) {
                if (!self.rateLimiter.check('key', 30, 1000)) {
                    e.stopPropagation();
                    e.preventDefault();
                }
            }, true);
        },

        // Initialize TRUMA NET protection
        init: async function() {
            console.log(`[TRUMA NET V2] Initializing protection for site: ${this.siteId}`);
            
            // Check visitor immediately
            const allowed = await this.reportVisitor();
            if (!allowed) return;

            // Initialize tracking
            this.initTracking();

            // Protect forms
            this.protectForms();

            // Protect actions
            this.protectActions();

            // Send heartbeat every 30 seconds
            setInterval(() => this.reportVisitor(), 30000);

            // Report on page unload
            window.addEventListener('beforeunload', () => {
                navigator.sendBeacon(`${this.apiUrl}/api/truma-net/heartbeat`, JSON.stringify({
                    siteId: this.siteId,
                    timeOnPage: this.behaviorData.timeOnPage,
                    scrollDepth: this.behaviorData.scrollDepth
                }));
            });

            console.log('[TRUMA NET V2] Protection active');
        }
    };

    // Auto-initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => TRUMA_NET.init());
    } else {
        TRUMA_NET.init();
    }

    // Expose to global scope for manual use
    window.TRUMA_NET = TRUMA_NET;

})();
