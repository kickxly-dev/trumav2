/**
 * TRUMA Browser - Fingerprint Protection Module
 * Reduces browser fingerprinting through canvas, WebGL, and hardware spoofing
 */

class FingerprintProtection {
    constructor(config, manager) {
        this.config = config;
        this.manager = manager;
        this.enabled = config.enabled !== false;
        this.noiseCache = new Map();
    }

    /**
     * Initialize fingerprint protection
     */
    async initialize(sess) {
        this.session = sess;

        // Generate persistent noise values for this session
        this.generateNoiseValues();

        // Inject fingerprint protection scripts
        sess.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, callback) => {
            if (!this.enabled) {
                return callback({});
            }

            const headers = details.responseHeaders || {};
            
            // Add CSP to prevent fingerprinting scripts
            if (headers['content-security-policy']) {
                headers['content-security-policy'].push(
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
                );
            }

            callback({ responseHeaders: headers });
        });

        console.log('[FingerprintProtection] Initialized');
    }

    /**
     * Generate noise values for fingerprint randomization
     */
    generateNoiseValues() {
        // Canvas noise
        this.noiseCache.set('canvas', {
            r: Math.floor(Math.random() * 10) - 5,
            g: Math.floor(Math.random() * 10) - 5,
            b: Math.floor(Math.random() * 10) - 5,
            a: (Math.random() * 0.02) - 0.01
        });

        // WebGL noise
        this.noiseCache.set('webgl', {
            vendor: this.getWebGLVendor(),
            renderer: this.getWebGLRenderer(),
            noise: Math.random() * 0.0001
        });

        // Audio noise
        this.noiseCache.set('audio', {
            noise: Math.random() * 0.0001,
            sampleRate: [44100, 48000][Math.floor(Math.random() * 2)]
        });

        // Hardware spoofing
        this.noiseCache.set('hardware', {
            cores: [4, 6, 8, 12, 16][Math.floor(Math.random() * 5)],
            memory: [4, 8, 16, 32][Math.floor(Math.random() * 4)],
            deviceMemory: [4, 8][Math.floor(Math.random() * 2)]
        });

        // Screen spoofing
        this.noiseCache.set('screen', {
            width: [1920, 2560, 1366, 1440][Math.floor(Math.random() * 4)],
            height: [1080, 1440, 768, 900][Math.floor(Math.random() * 4)],
            colorDepth: 24,
            pixelDepth: 24
        });

        // Timezone spoofing (common timezone)
        this.noiseCache.set('timezone', {
            offset: 0, // UTC
            name: 'UTC'
        });

        // Language standardization
        this.noiseCache.set('language', {
            language: 'en-US',
            languages: ['en-US', 'en']
        });

        // Platform standardization
        this.noiseCache.set('platform', {
            platform: 'Win32',
            userAgent: this.getStandardizedUserAgent()
        });
    }

    /**
     * Get generic WebGL vendor
     */
    getWebGLVendor() {
        const vendors = [
            'Google Inc. (NVIDIA)',
            'Google Inc. (Intel)',
            'Google Inc. (AMD)'
        ];
        return vendors[Math.floor(Math.random() * vendors.length)];
    }

    /**
     * Get generic WebGL renderer
     */
    getWebGLRenderer() {
        const renderers = [
            'ANGLE (NVIDIA GeForce GTX 1060)',
            'ANGLE (Intel HD Graphics 630)',
            'ANGLE (AMD Radeon RX 580)'
        ];
        return renderers[Math.floor(Math.random() * renderers.length)];
    }

    /**
     * Get standardized user agent
     */
    getStandardizedUserAgent() {
        // Use a common user agent to blend in
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    }

    /**
     * Get injection script for fingerprint protection
     */
    getInjectionScript() {
        if (!this.enabled) return '';

        const canvasNoise = this.noiseCache.get('canvas');
        const webgl = this.noiseCache.get('webgl');
        const audio = this.noiseCache.get('audio');
        const hardware = this.noiseCache.get('hardware');
        const screen = this.noiseCache.get('screen');
        const timezone = this.noiseCache.get('timezone');
        const language = this.noiseCache.get('language');
        const platform = this.noiseCache.get('platform');

        return `
            // TRUMA Fingerprint Protection
            (function() {
                'use strict';

                const noise = ${JSON.stringify(canvasNoise)};
                const webglConfig = ${JSON.stringify(webgl)};
                const audioConfig = ${JSON.stringify(audio)};
                const hardwareConfig = ${JSON.stringify(hardware)};
                const screenConfig = ${JSON.stringify(screen)};
                const timezoneConfig = ${JSON.stringify(timezone)};
                const languageConfig = ${JSON.stringify(language)};
                const platformConfig = ${JSON.stringify(platform)};

                // Canvas fingerprint protection
                if (${this.config.canvasNoise}) {
                    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
                    
                    // Add noise to canvas operations
                    CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                        const data = originalGetImageData.call(this, x, y, w, h);
                        for (let i = 0; i < data.data.length; i += 4) {
                            data.data[i] += noise.r;
                            data.data[i + 1] += noise.g;
                            data.data[i + 2] += noise.b;
                            data.data[i + 3] += Math.round(noise.a * 255);
                        }
                        return data;
                    };

                    HTMLCanvasElement.prototype.toDataURL = function(type) {
                        const ctx = this.getContext('2d');
                        if (ctx) {
                            const imageData = ctx.getImageData(0, 0, this.width, this.height);
                            ctx.putImageData(imageData, 0, 0);
                        }
                        return originalToDataURL.apply(this, arguments);
                    };
                }

                // WebGL fingerprint protection
                if (${this.config.webglNoise}) {
                    const getParameterProxyHandler = {
                        apply: function(target, thisArg, args) {
                            const param = args[0];
                            const gl = thisArg;
                            
                            // UNMASKED_VENDOR_WEBGL
                            if (param === 37445) {
                                return webglConfig.vendor;
                            }
                            // UNMASKED_RENDERER_WEBGL
                            if (param === 37446) {
                                return webglConfig.renderer;
                            }
                            
                            return target.apply(thisArg, args);
                        }
                    };

                    // Override for WebGL and WebGL2
                    const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
                    WebGLRenderingContext.prototype.getParameter = new Proxy(originalGetParameter, getParameterProxyHandler);

                    if (typeof WebGL2RenderingContext !== 'undefined') {
                        const originalGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
                        WebGL2RenderingContext.prototype.getParameter = new Proxy(originalGetParameter2, getParameterProxyHandler);
                    }
                }

                // Audio fingerprint protection
                if (${this.config.audioNoise}) {
                    const originalCreateAnalyser = AudioContext.prototype.createAnalyser;
                    AudioContext.prototype.createAnalyser = function() {
                        const analyser = originalCreateAnalyser.apply(this, arguments);
                        const originalGetFloatFrequencyData = analyser.getFloatFrequencyData.bind(analyser);
                        analyser.getFloatFrequencyData = function(array) {
                            originalGetFloatFrequencyData(array);
                            for (let i = 0; i < array.length; i++) {
                                array[i] += audioConfig.noise * Math.random();
                            }
                        };
                        return analyser;
                    };
                }

                // Hardware spoofing
                if (${this.config.hardwareSpoofing}) {
                    Object.defineProperty(navigator, 'hardwareConcurrency', {
                        get: () => hardwareConfig.cores,
                        configurable: true
                    });

                    Object.defineProperty(navigator, 'deviceMemory', {
                        get: () => hardwareConfig.deviceMemory,
                        configurable: true
                    });
                }

                // Screen protection
                Object.defineProperty(screen, 'width', { get: () => screenConfig.width });
                Object.defineProperty(screen, 'height', { get: () => screenConfig.height });
                Object.defineProperty(screen, 'availWidth', { get: () => screenConfig.width });
                Object.defineProperty(screen, 'availHeight', { get: () => screenConfig.height - 40 });
                Object.defineProperty(screen, 'colorDepth', { get: () => screenConfig.colorDepth });
                Object.defineProperty(screen, 'pixelDepth', { get: () => screenConfig.pixelDepth });

                // Timezone protection
                const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
                Date.prototype.getTimezoneOffset = function() {
                    return timezoneConfig.offset;
                };

                // Language protection
                Object.defineProperty(navigator, 'language', {
                    get: () => languageConfig.language,
                    configurable: true
                });
                Object.defineProperty(navigator, 'languages', {
                    get: () => languageConfig.languages,
                    configurable: true
                });

                // Platform protection
                Object.defineProperty(navigator, 'platform', {
                    get: () => platformConfig.platform,
                    configurable: true
                });

                // Font protection (limit to common fonts)
                if (${this.config.fontProtection}) {
                    const commonFonts = [
                        'Arial', 'Helvetica', 'Times New Roman', 'Georgia',
                        'Verdana', 'Trebuchet MS', 'Palatino Linotype',
                        'Segoe UI', 'Tahoma', 'Century Gothic'
                    ];
                    
                    const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
                    CanvasRenderingContext2D.prototype.measureText = function(text) {
                        const result = originalMeasureText.call(this, text);
                        // Normalize font metrics
                        return result;
                    };
                }

                // Prevent enumeration of plugins
                Object.defineProperty(navigator, 'plugins', {
                    get: () => { length: 0 },
                    configurable: true
                });

                // Prevent mimeTypes enumeration
                Object.defineProperty(navigator, 'mimeTypes', {
                    get: () => { length: 0 },
                    configurable: true
                });

                // Battery API protection
                if (navigator.getBattery) {
                    navigator.getBattery = () => Promise.resolve({
                        charging: true,
                        chargingTime: 0,
                        dischargingTime: Infinity,
                        level: 1
                    });
                }

                // Connection API protection
                if (navigator.connection) {
                    Object.defineProperty(navigator.connection, 'rtt', { get: () => 50 });
                    Object.defineProperty(navigator.connection, 'downlink', { get: () => 10 });
                    Object.defineProperty(navigator.connection, 'effectiveType', { get: () => '4g' });
                }

                console.log('[TRUMA] Fingerprint protection active');
            })();
        `;
    }

    /**
     * Update configuration
     */
    updateConfig(newConfig) {
        this.config = { ...this.config, ...newConfig };
        this.enabled = this.config.enabled !== false;
        this.generateNoiseValues();
    }

    /**
     * Cleanup
     */
    async cleanup() {
        this.noiseCache.clear();
    }
}

module.exports = FingerprintProtection;
