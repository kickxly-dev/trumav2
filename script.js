// Terminal Background Animation
class TerminalBackground {
    constructor() {
        this.terminalLines = document.querySelector('.terminal-lines');
        this.lines = [];
        this.init();
    }

    init() {
        this.generateTerminalLines();
        setInterval(() => this.updateTerminalLines(), 2000);
    }

    generateTerminalLines() {
        const commands = [
            'nmap -sS localhost',
            'ping -c 4 8.8.8.8',
            'netstat -tuln',
            'whois example.com',
            'dig +short A google.com',
            'curl -I https://example.com',
            'ss -tulpn',
            'lsof -i :80',
            'tcpdump -i eth0',
            'traceroute google.com',
            'nslookup google.com',
            'arp -a',
            'route -n',
            'iptables -L',
            'ufw status',
            'systemctl status firewall',
            'ps aux | grep nginx',
            'top -b -n 1',
            'free -m',
            'df -h'
        ];

        for (let i = 0; i < 15; i++) {
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.style.cssText = `
                position: absolute;
                left: ${Math.random() * 80}%;
                top: ${Math.random() * 100}%;
                color: rgba(220, 20, 60, ${Math.random() * 0.3 + 0.1});
                font-family: 'JetBrains Mono', monospace;
                font-size: ${Math.random() * 4 + 8}px;
                white-space: nowrap;
                animation: float ${Math.random() * 10 + 5}s linear infinite;
                opacity: 0;
            `;
            
            const command = commands[Math.floor(Math.random() * commands.length)];
            const prefix = Math.random() > 0.5 ? '$ ' : '# ';
            line.textContent = prefix + command;
            
            this.terminalLines.appendChild(line);
            this.lines.push(line);
            
            // Animate line appearance
            setTimeout(() => {
                line.style.opacity = '1';
                line.style.transition = 'opacity 2s ease-in-out';
            }, Math.random() * 2000);
        }

        // Add floating animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes float {
                0% { transform: translateY(0) translateX(0); }
                25% { transform: translateY(-20px) translateX(10px); }
                50% { transform: translateY(0) translateX(-10px); }
                75% { transform: translateY(20px) translateX(5px); }
                100% { transform: translateY(0) translateX(0); }
            }
        `;
        document.head.appendChild(style);
    }

    updateTerminalLines() {
        this.lines.forEach((line, index) => {
            if (Math.random() > 0.7) {
                line.style.opacity = '0';
                setTimeout(() => {
                    line.style.opacity = Math.random() * 0.3 + 0.1;
                }, 1000);
            }
        });
    }
}

// Smooth Scroll Navigation
class Navigation {
    constructor() {
        this.navbar = document.querySelector('.navbar');
        this.navLinks = document.querySelectorAll('.nav-link');
        this.init();
    }

    init() {
        this.setupSmoothScroll();
        this.setupScrollEffects();
    }

    setupSmoothScroll() {
        this.navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                const href = link.getAttribute('href');
                
                // Skip external links (like auth.html)
                if (href.startsWith('http') || href.includes('.html')) {
                    return; // Allow normal navigation
                }
                
                e.preventDefault();
                const targetSection = document.querySelector(href);
                
                if (targetSection) {
                    const offsetTop = targetSection.offsetTop - 80;
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                }
            });
        });
    }

    setupScrollEffects() {
        let lastScroll = 0;
        
        window.addEventListener('scroll', () => {
            const currentScroll = window.pageYOffset;
            
            // Navbar background effect
            if (currentScroll > 50) {
                this.navbar.style.background = 'rgba(0, 0, 0, 0.98)';
                this.navbar.style.boxShadow = '0 2px 20px rgba(220, 20, 60, 0.3)';
            } else {
                this.navbar.style.background = 'rgba(0, 0, 0, 0.95)';
                this.navbar.style.boxShadow = 'none';
            }
            
            lastScroll = currentScroll;
        });
    }
}

// Tool Card Interactions
class ToolCards {
    constructor() {
        this.toolCards = document.querySelectorAll('.tool-card');
        this.init();
    }

    init() {
        this.setupHoverEffects();
        this.setupClickEffects();
    }

    setupHoverEffects() {
        this.toolCards.forEach(card => {
            card.addEventListener('mouseenter', () => {
                this.addGlowEffect(card);
            });

            card.addEventListener('mouseleave', () => {
                this.removeGlowEffect(card);
            });
        });
    }

    setupClickEffects() {
        this.toolCards.forEach(card => {
            card.addEventListener('click', (e) => {
                if (!e.target.classList.contains('card-button')) {
                    this.createRippleEffect(card, e);
                }
            });
        });
    }

    addGlowEffect(card) {
        card.style.boxShadow = `
            0 0 30px rgba(220, 20, 60, 0.3),
            0 10px 40px rgba(220, 20, 60, 0.2),
            inset 0 0 20px rgba(220, 20, 60, 0.1)
        `;
    }

    removeGlowEffect(card) {
        card.style.boxShadow = 'none';
    }

    createRippleEffect(card, event) {
        const ripple = document.createElement('div');
        const rect = card.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;

        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: radial-gradient(circle, rgba(220, 20, 60, 0.3) 0%, transparent 70%);
            border-radius: 50%;
            transform: scale(0);
            animation: ripple 0.6s ease-out;
            pointer-events: none;
            z-index: 1;
        `;

        card.appendChild(ripple);

        setTimeout(() => {
            ripple.remove();
        }, 600);
    }
}

// Tool Launch Button Wiring (CSP-safe)
function wireToolLaunchButtons() {
    document.querySelectorAll('.card-button[data-tool]').forEach((btn) => {
        btn.addEventListener('click', () => {
            const toolName = btn.getAttribute('data-tool');
            if (toolName) {
                openTool(toolName);
            }
        });
    });
}

// Scroll Animations
class ScrollAnimations {
    constructor() {
        this.elements = document.querySelectorAll('.tool-card, .section-header');
        this.init();
    }

    init() {
        this.setupIntersectionObserver();
    }

    setupIntersectionObserver() {
        const options = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    this.animateElement(entry.target);
                }
            });
        }, options);

        this.elements.forEach(element => {
            observer.observe(element);
        });
    }

    animateElement(element) {
        element.style.opacity = '0';
        element.style.transform = 'translateY(30px)';
        element.style.transition = 'all 0.6s ease-out';

        setTimeout(() => {
            element.style.opacity = '1';
            element.style.transform = 'translateY(0)';
        }, 100);
    }
}

// Tool Launcher
class ToolLauncher {
    constructor() {
        this.modal = null;
        this.init();
    }

    init() {
        this.createModal();
    }

    createModal() {
        this.modal = document.createElement('div');
        this.modal.id = 'tool-modal';
        this.modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.95);
            backdrop-filter: blur(10px);
            z-index: 2000;
            display: none;
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: opacity 0.3s ease;
        `;

        this.modal.innerHTML = `
            <div class="modal-content" style="
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 2rem;
                max-width: 600px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
                position: relative;
                box-shadow: 0 20px 60px rgba(220, 20, 60, 0.3);
            ">
                <button class="modal-close" style="
                    position: absolute;
                    top: 1rem;
                    right: 1rem;
                    background: none;
                    border: none;
                    color: var(--text-secondary);
                    font-size: 1.5rem;
                    cursor: pointer;
                    transition: color 0.3s ease;
                ">&times;</button>
                <div class="modal-body"></div>
            </div>
        `;

        document.body.appendChild(this.modal);

        // Close modal handlers
        this.modal.querySelector('.modal-close').addEventListener('click', () => this.closeModal());
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.closeModal();
            }
        });

        // Escape key handler
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.modal.style.display === 'flex') {
                this.closeModal();
            }
        });
    }

    openTool(toolName) {
        const modalBody = this.modal.querySelector('.modal-body');
        modalBody.innerHTML = this.getToolContent(toolName);
        
        this.modal.style.display = 'flex';
        setTimeout(() => {
            this.modal.style.opacity = '1';
        }, 10);

        // Initialize tool-specific functionality
        this.initializeTool(toolName);
    }

    closeModal() {
        this.modal.style.opacity = '0';
        setTimeout(() => {
            this.modal.style.display = 'none';
        }, 300);
    }

    getToolContent(toolName) {
        const tools = {
            'ip-lookup': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">IP Information Lookup</h2>
                <p style="color: var(--text-secondary); margin-bottom: 2rem;">Get comprehensive IP address information for network analysis.</p>
                <div style="margin-bottom: 1.5rem;">
                    <label style="display: block; margin-bottom: 0.5rem; color: var(--text-secondary);">IP Address or Domain:</label>
                    <input type="text" id="ip-input" placeholder="Enter IP address or domain" style="
                        width: 100%;
                        padding: 0.75rem;
                        background: var(--bg-secondary);
                        border: 1px solid var(--border-color);
                        border-radius: 6px;
                        color: var(--text-primary);
                        font-family: 'JetBrains Mono', monospace;
                    ">
                </div>
                <button type="button" id="ip-lookup-btn" style="
                    background: var(--crimson-primary);
                    color: white;
                    border: none;
                    padding: 0.75rem 1.5rem;
                    border-radius: 6px;
                    cursor: pointer;
                    font-family: 'JetBrains Mono', monospace;
                    margin-bottom: 1.5rem;
                ">Lookup</button>
                <div id="ip-result" style="
                    background: var(--bg-secondary);
                    padding: 1rem;
                    border-radius: 6px;
                    border: 1px solid var(--border-color);
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 0.9rem;
                    min-height: 100px;
                "></div>
            `,
            'ping-tester': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">Ping / Latency Tester</h2>
                <p style="color: var(--text-secondary); margin-bottom: 2rem;">Test network connectivity and measure latency.</p>
                <div style="margin-bottom: 1.5rem;">
                    <label style="display: block; margin-bottom: 0.5rem; color: var(--text-secondary);">Target Host:</label>
                    <input type="text" id="ping-target" placeholder="Enter hostname or IP" value="8.8.8.8" style="
                        width: 100%;
                        padding: 0.75rem;
                        background: var(--bg-secondary);
                        border: 1px solid var(--border-color);
                        border-radius: 6px;
                        color: var(--text-primary);
                        font-family: 'JetBrains Mono', monospace;
                    ">
                </div>
                <button type="button" id="ping-btn" style="
                    background: var(--crimson-primary);
                    color: white;
                    border: none;
                    padding: 0.75rem 1.5rem;
                    border-radius: 6px;
                    cursor: pointer;
                    font-family: 'JetBrains Mono', monospace;
                    margin-bottom: 1.5rem;
                ">Start Ping</button>
                <div id="ping-result" style="
                    background: var(--bg-secondary);
                    padding: 1rem;
                    border-radius: 6px;
                    border: 1px solid var(--border-color);
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 0.9rem;
                    min-height: 100px;
                "></div>
            `,
            'dns-lookup': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">DNS Lookup</h2>
                <p style="color: var(--text-secondary); margin-bottom: 2rem;">Resolve common DNS record types.</p>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block;margin-bottom:0.5rem;color:var(--text-secondary);">Domain</label>
                    <input type="text" id="dns-domain" placeholder="example.com" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;">
                </div>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block;margin-bottom:0.5rem;color:var(--text-secondary);">Record Type</label>
                    <select id="dns-type" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;">
                        <option value="A">A</option>
                        <option value="AAAA">AAAA</option>
                        <option value="MX">MX</option>
                        <option value="TXT">TXT</option>
                        <option value="NS">NS</option>
                    </select>
                </div>
                <button type="button" id="dns-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.5rem;">Lookup</button>
                <div id="dns-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.9rem;min-height:100px;"></div>
            `,
            'whois-lookup': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">WHOIS Lookup</h2>
                <p style="color: var(--text-secondary); margin-bottom: 2rem;">Retrieve registration information for a domain.</p>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block;margin-bottom:0.5rem;color:var(--text-secondary);">Domain</label>
                    <input type="text" id="whois-domain" placeholder="example.com" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;">
                </div>
                <button type="button" id="whois-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.5rem;">Lookup</button>
                <pre id="whois-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.8rem;min-height:160px;white-space:pre-wrap;"></pre>
            `,
            'base64': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">Base64 Encoder/Decoder</h2>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block;margin-bottom:0.5rem;color:var(--text-secondary);">Action</label>
                    <select id="b64-action" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;">
                        <option value="encode">Encode</option>
                        <option value="decode">Decode</option>
                    </select>
                </div>
                <textarea id="b64-input" placeholder="Input" style="width:100%;min-height:120px;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;margin-bottom:1rem;"></textarea>
                <button type="button" id="b64-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.5rem;">Run</button>
                <textarea id="b64-output" readonly style="width:100%;min-height:120px;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;"></textarea>
            `,
            'hash-generator': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">Hash Generator</h2>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block;margin-bottom:0.5rem;color:var(--text-secondary);">Algorithm</label>
                    <select id="hash-algo" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;">
                        <option value="sha256">SHA-256</option>
                        <option value="sha1">SHA-1</option>
                        <option value="md5">MD5</option>
                    </select>
                </div>
                <textarea id="hash-input" placeholder="Text" style="width:100%;min-height:120px;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;margin-bottom:1rem;"></textarea>
                <button type="button" id="hash-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.5rem;">Generate</button>
                <input id="hash-output" readonly style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;" />
            `,
            'json-formatter': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">JSON Formatter</h2>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block;margin-bottom:0.5rem;color:var(--text-secondary);">Action</label>
                    <select id="json-action" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;">
                        <option value="format">Format</option>
                        <option value="minify">Minify</option>
                    </select>
                </div>
                <textarea id="json-input" placeholder="JSON" style="width:100%;min-height:160px;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;margin-bottom:1rem;"></textarea>
                <button type="button" id="json-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.5rem;">Run</button>
                <textarea id="json-output" readonly style="width:100%;min-height:160px;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;"></textarea>
            `,
            'password-checker': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">Password Strength Checker</h2>
                <input type="password" id="pw-input" placeholder="Password" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;margin-bottom:1rem;" />
                <button type="button" id="pw-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.5rem;">Check</button>
                <div id="pw-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.9rem;min-height:100px;"></div>
            `,

            'ssl-checker': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">SSL Certificate Checker</h2>
                <p style="color: var(--text-secondary); margin-bottom: 2rem;">Verify SSL/TLS certificates and check expiration dates.</p>
                <div style="margin-bottom: 1.5rem;">
                    <label style="display: block; margin-bottom: 0.5rem; color: var(--text-secondary);">Domain:</label>
                    <input type="text" id="ssl-domain" placeholder="example.com" style="
                        width: 100%;
                        padding: 0.75rem;
                        background: var(--bg-secondary);
                        border: 1px solid var(--border-color);
                        border-radius: 6px;
                        color: var(--text-primary);
                        font-family: 'JetBrains Mono', monospace;
                    ">
                </div>
                <button type="button" id="ssl-btn" style="
                    background: var(--crimson-primary);
                    color: white;
                    border: none;
                    padding: 0.75rem 1.5rem;
                    border-radius: 6px;
                    cursor: pointer;
                    font-family: 'JetBrains Mono', monospace;
                    margin-bottom: 1.5rem;
                ">Check SSL</button>
                <div id="ssl-result" style="
                    background: var(--bg-secondary);
                    padding: 1rem;
                    border-radius: 6px;
                    border: 1px solid var(--border-color);
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 0.9rem;
                    min-height: 150px;
                "></div>
            `,

            'url-encoder': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">URL Encoder/Decoder</h2>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block;margin-bottom:0.5rem;color:var(--text-secondary);">Action</label>
                    <select id="url-action" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;">
                        <option value="encode">Encode</option>
                        <option value="decode">Decode</option>
                    </select>
                </div>
                <textarea id="url-input" placeholder="Enter text to encode/decode" style="width:100%;min-height:120px;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;margin-bottom:1rem;"></textarea>
                <button type="button" id="url-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.5rem;">Run</button>
                <textarea id="url-output" readonly style="width:100%;min-height:120px;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;"></textarea>
            `,

            'jwt-decoder': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">JWT Decoder</h2>
                <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">Decode and inspect JWT tokens.</p>
                <textarea id="jwt-input" placeholder="Paste JWT token here" style="width:100%;min-height:100px;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;margin-bottom:1rem;"></textarea>
                <button type="button" id="jwt-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.5rem;">Decode</button>
                <div id="jwt-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.85rem;min-height:200px;overflow-x:auto;"></div>
            `,

            'network-scanner': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">Local Network Scanner</h2>
                <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">Lists discovered neighbors from the local ARP/neighbor table.</p>
                <button type="button" id="net-scan-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.25rem;">Scan</button>
                <pre id="net-scan-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.8rem;min-height:180px;white-space:pre-wrap;"></pre>
            `,

            'port-scanner': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">Port Scanner</h2>
                <p style="color: var(--text-secondary); margin-bottom: 1.25rem;">TCP connect scan (limited). Example ports: 22,80,443</p>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block;margin-bottom:0.5rem;color:var(--text-secondary);">Host</label>
                    <input type="text" id="ps-host" value="127.0.0.1" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;">
                </div>
                <div style="margin-bottom: 1rem;">
                    <label style="display:block;margin-bottom:0.5rem;color:var(--text-secondary);">Ports (comma-separated)</label>
                    <input type="text" id="ps-ports" value="22,80,443" style="width:100%;padding:0.75rem;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono', monospace;">
                </div>
                <button type="button" id="ps-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.25rem;">Scan</button>
                <pre id="ps-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.8rem;min-height:180px;white-space:pre-wrap;"></pre>
            `,

            'connections': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">Active Connections</h2>
                <p style="color: var(--text-secondary); margin-bottom: 1.25rem;">Shows active connections (netstat/ss output).</p>
                <button type="button" id="conn-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.25rem;">Refresh</button>
                <pre id="conn-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.75rem;min-height:220px;white-space:pre-wrap;"></pre>
            `,

            'firewall': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">Firewall Status</h2>
                <p style="color: var(--text-secondary); margin-bottom: 1.25rem;">Shows firewall configuration (platform dependent).</p>
                <button type="button" id="fw-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.25rem;">Refresh</button>
                <pre id="fw-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.75rem;min-height:220px;white-space:pre-wrap;"></pre>
            `,

            'system-info': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">System Information</h2>
                <button type="button" id="sys-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.25rem;">Refresh</button>
                <pre id="sys-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.8rem;min-height:180px;white-space:pre-wrap;"></pre>
            `,

            'process-monitor': `
                <h2 style="color: var(--crimson-primary); margin-bottom: 1rem;">Process Monitor</h2>
                <p style="color: var(--text-secondary); margin-bottom: 1.25rem;">Shows running processes (platform dependent).</p>
                <button type="button" id="proc-btn" style="background:var(--crimson-primary);color:white;border:none;padding:0.75rem 1.5rem;border-radius:6px;cursor:pointer;font-family:'JetBrains Mono', monospace;margin-bottom:1.25rem;">Refresh</button>
                <pre id="proc-result" style="background:var(--bg-secondary);padding:1rem;border-radius:6px;border:1px solid var(--border-color);font-family:'JetBrains Mono', monospace;font-size:0.75rem;min-height:220px;white-space:pre-wrap;"></pre>
            `,
            'default': `
                <div style="
                    background: var(--bg-secondary);
                    padding: 2rem;
                    border-radius: 6px;
                    border: 1px solid var(--border-color);
                    text-align: center;
                ">
                    <div style="font-size: 1.5rem; margin-bottom: 1rem;">Notice</div>
                    <p style="color: var(--text-dim);">This tool interface will be available in a future update.</p>
                </div>
            `
        };

        return tools[toolName] || tools['default'];
    }

    initializeTool(toolName) {
        if (toolName === 'ip-lookup') {
            const btn = document.getElementById('ip-lookup-btn');
            if (btn) btn.addEventListener('click', lookupIP);
        }

        if (toolName === 'ping-tester') {
            const btn = document.getElementById('ping-btn');
            if (btn) btn.addEventListener('click', startPing);
        }

        if (toolName === 'dns-lookup') {
            const btn = document.getElementById('dns-btn');
            if (btn) btn.addEventListener('click', async () => {
                const domain = document.getElementById('dns-domain').value;
                const recordType = document.getElementById('dns-type').value;
                const out = document.getElementById('dns-result');
                out.textContent = 'Working...';
                const res = await fetch('/api/dns-lookup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain, recordType })
                });
                const data = await res.json();
                out.textContent = res.ok ? JSON.stringify(data.records, null, 2) : (data.error || 'Request failed');
            });
        }

        if (toolName === 'whois-lookup') {
            const btn = document.getElementById('whois-btn');
            if (btn) btn.addEventListener('click', async () => {
                const domain = document.getElementById('whois-domain').value;
                const out = document.getElementById('whois-result');
                out.textContent = 'Working...';
                const res = await fetch('/api/whois', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain })
                });
                const data = await res.json();
                out.textContent = res.ok ? data.rawOutput : (data.error || 'Request failed');
            });
        }

        if (toolName === 'base64') {
            const btn = document.getElementById('b64-btn');
            if (btn) btn.addEventListener('click', async () => {
                const action = document.getElementById('b64-action').value;
                const text = document.getElementById('b64-input').value;
                const out = document.getElementById('b64-output');
                const res = await fetch('/api/base64', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action, text })
                });
                const data = await res.json();
                out.value = res.ok ? data.output : (data.error || 'Request failed');
            });
        }

        if (toolName === 'hash-generator') {
            const btn = document.getElementById('hash-btn');
            if (btn) btn.addEventListener('click', async () => {
                const algorithm = document.getElementById('hash-algo').value;
                const text = document.getElementById('hash-input').value;
                const out = document.getElementById('hash-output');
                const res = await fetch('/api/hash', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ algorithm, text })
                });
                const data = await res.json();
                out.value = res.ok ? data.hash : (data.error || 'Request failed');
            });
        }

        if (toolName === 'json-formatter') {
            const btn = document.getElementById('json-btn');
            if (btn) btn.addEventListener('click', async () => {
                const action = document.getElementById('json-action').value;
                const json = document.getElementById('json-input').value;
                const out = document.getElementById('json-output');
                const res = await fetch('/api/json-format', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action, json })
                });
                const data = await res.json();
                out.value = res.ok ? data.output : (data.error || 'Request failed');
            });
        }

        if (toolName === 'password-checker') {
            const btn = document.getElementById('pw-btn');
            if (btn) btn.addEventListener('click', async () => {
                const password = document.getElementById('pw-input').value;
                const out = document.getElementById('pw-result');
                const res = await fetch('/api/password-check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                out.textContent = res.ok ? `${data.strength} (${data.score}/${data.maxScore})\n${(data.feedback || []).join('\n')}` : (data.error || 'Request failed');
            });
        }

        if (toolName === 'ssl-checker') {
            const btn = document.getElementById('ssl-btn');
            if (btn) btn.addEventListener('click', async () => {
                const domain = document.getElementById('ssl-domain').value;
                const out = document.getElementById('ssl-result');
                out.innerHTML = '<div style="color: var(--success-color);">Checking SSL certificate...</div>';
                const res = await fetch('/api/ssl-check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain })
                });
                const data = await res.json();
                if (res.ok) {
                    const statusColor = data.expired ? 'var(--error-color)' : data.expiresSoon ? '#ffaa00' : 'var(--success-color)';
                    const statusText = data.expired ? 'EXPIRED' : data.expiresSoon ? 'Expires Soon' : 'Valid';
                    out.innerHTML = `
                        <div style="color: ${statusColor}; font-weight: bold; margin-bottom: 1rem;">${statusText}</div>
                        <div><strong>Subject:</strong> ${data.subject?.CN || 'N/A'}</div>
                        <div><strong>Issuer:</strong> ${data.issuer?.O || 'N/A'}</div>
                        <div><strong>Valid From:</strong> ${data.validFrom}</div>
                        <div><strong>Valid To:</strong> ${data.validTo}</div>
                        <div><strong>Days Remaining:</strong> ${data.daysRemaining}</div>
                        <div><strong>Serial Number:</strong> ${data.serialNumber}</div>
                        <div><strong>Fingerprint:</strong> ${data.fingerprint}</div>
                    `;
                } else {
                    out.innerHTML = `<span style="color: var(--error-color);">${data.error}</span>`;
                }
            });
        }

        if (toolName === 'url-encoder') {
            const btn = document.getElementById('url-btn');
            if (btn) btn.addEventListener('click', async () => {
                const action = document.getElementById('url-action').value;
                const text = document.getElementById('url-input').value;
                const out = document.getElementById('url-output');
                const res = await fetch('/api/url-encode', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text, action })
                });
                const data = await res.json();
                out.value = res.ok ? data.output : (data.error || 'Request failed');
            });
        }

        if (toolName === 'jwt-decoder') {
            const btn = document.getElementById('jwt-btn');
            if (btn) btn.addEventListener('click', async () => {
                const token = document.getElementById('jwt-input').value;
                const out = document.getElementById('jwt-result');
                const res = await fetch('/api/jwt-decode', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token })
                });
                const data = await res.json();
                if (res.ok) {
                    const statusColor = data.expired ? 'var(--error-color)' : 'var(--success-color)';
                    const statusText = data.expired ? 'EXPIRED' : data.expiresIn > 0 ? `Valid (expires in ${Math.floor(data.expiresIn / 60)} min)` : 'Valid';
                    out.innerHTML = `
                        <div style="color: ${statusColor}; font-weight: bold; margin-bottom: 1rem;">${statusText}</div>
                        <div style="margin-bottom: 1rem;">
                            <strong>Header:</strong>
                            <pre style="background: var(--bg-secondary); padding: 0.5rem; border-radius: 4px; overflow-x: auto;">${JSON.stringify(data.header, null, 2)}</pre>
                        </div>
                        <div>
                            <strong>Payload:</strong>
                            <pre style="background: var(--bg-secondary); padding: 0.5rem; border-radius: 4px; overflow-x: auto;">${JSON.stringify(data.payload, null, 2)}</pre>
                        </div>
                        <div style="margin-top: 1rem; color: var(--text-dim);">
                            <strong>Signature:</strong> ${data.signature}
                        </div>
                    `;
                } else {
                    out.innerHTML = `<span style="color: var(--error-color);">${data.error}</span>`;
                }
            });
        }

        if (toolName === 'network-scanner') {
            const btn = document.getElementById('net-scan-btn');
            if (btn) btn.addEventListener('click', async () => {
                const out = document.getElementById('net-scan-result');
                out.textContent = 'Working...';
                const res = await fetch('/api/network-scan');
                const data = await res.json();
                out.textContent = res.ok ? data.rawOutput : (data.error || 'Request failed');
            });
        }

        if (toolName === 'port-scanner') {
            const btn = document.getElementById('ps-btn');
            if (btn) btn.addEventListener('click', async () => {
                const host = document.getElementById('ps-host').value || '127.0.0.1';
                const portsRaw = document.getElementById('ps-ports').value || '';
                const ports = portsRaw.split(',').map(p => p.trim()).filter(Boolean).map(p => Number(p)).filter(n => Number.isFinite(n));
                const out = document.getElementById('ps-result');
                out.textContent = 'Working...';
                const res = await fetch('/api/port-scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ host, ports })
                });
                const data = await res.json();
                out.textContent = res.ok ? JSON.stringify(data.results, null, 2) : (data.error || 'Request failed');
            });
        }

        if (toolName === 'connections') {
            const btn = document.getElementById('conn-btn');
            if (btn) btn.addEventListener('click', async () => {
                const out = document.getElementById('conn-result');
                out.textContent = 'Working...';
                const res = await fetch('/api/connections');
                const data = await res.json();
                out.textContent = res.ok ? data.rawOutput : (data.error || 'Request failed');
            });
        }

        if (toolName === 'firewall') {
            const btn = document.getElementById('fw-btn');
            if (btn) btn.addEventListener('click', async () => {
                const out = document.getElementById('fw-result');
                out.textContent = 'Working...';
                const res = await fetch('/api/firewall');
                const data = await res.json();
                out.textContent = res.ok ? data.rawOutput : (data.error || 'Request failed');
            });
        }

        if (toolName === 'system-info') {
            const btn = document.getElementById('sys-btn');
            if (btn) btn.addEventListener('click', async () => {
                const out = document.getElementById('sys-result');
                out.textContent = 'Working...';
                const res = await fetch('/api/system-info');
                const data = await res.json();
                out.textContent = res.ok ? JSON.stringify(data, null, 2) : (data.error || 'Request failed');
            });
        }

        if (toolName === 'process-monitor') {
            const btn = document.getElementById('proc-btn');
            if (btn) btn.addEventListener('click', async () => {
                const out = document.getElementById('proc-result');
                out.textContent = 'Working...';
                const res = await fetch('/api/processes');
                const data = await res.json();
                out.textContent = res.ok ? data.rawOutput : (data.error || 'Request failed');
            });
        }
    }
}

// Global tool launcher instance
let toolLauncher;

// Tool functions
function openTool(toolName) {
    if (!toolLauncher) {
        toolLauncher = new ToolLauncher();
    }
    toolLauncher.openTool(toolName);
}

// Mock tool implementations - Updated to use real APIs
async function lookupIP() {
    const input = document.getElementById('ip-input');
    const result = document.getElementById('ip-result');
    
    if (!input.value.trim()) {
        result.innerHTML = '<span style="color: var(--error-color);">Please enter an IP address or domain.</span>';
        return;
    }

    result.innerHTML = '<div style="color: var(--success-color);">Looking up information...</div>';

    try {
        const response = await fetch('/api/ip-lookup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ target: input.value })
        });

        const data = await response.json();

        if (response.ok) {
            result.innerHTML = `
                <div style="color: var(--success-color); margin-bottom: 1rem;">Lookup complete</div>
                <div style="margin-top: 1rem;">
                    <div><strong>IP:</strong> ${data.ip}</div>
                    <div><strong>Country:</strong> ${data.country || 'Unknown'}</div>
                    <div><strong>Region:</strong> ${data.region || 'Unknown'}</div>
                    <div><strong>City:</strong> ${data.city || 'Unknown'}</div>
                    <div><strong>ISP:</strong> ${data.isp || 'Unknown'}</div>
                    <div><strong>Organization:</strong> ${data.org || 'Unknown'}</div>
                    <div><strong>ASN:</strong> ${data.as || 'Unknown'}</div>
                    <div><strong>Timezone:</strong> ${data.timezone || 'Unknown'}</div>
                </div>
            `;
        } else {
            result.innerHTML = `<span style="color: var(--error-color);">${data.error}</span>`;
        }
    } catch (error) {
        result.innerHTML = '<span style="color: var(--error-color);">Failed to connect to server</span>';
    }
}

async function startPing() {
    const target = document.getElementById('ping-target');
    const result = document.getElementById('ping-result');
    
    result.innerHTML = '<div style="color: var(--success-color);">Pinging target...</div>';

    try {
        const response = await fetch('/api/ping', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ target: target.value })
        });

        const data = await response.json();

        if (response.ok) {
            result.innerHTML = `
                <div style="color: var(--success-color); margin-bottom: 1rem;">Ping complete</div>
                <div style="margin-top: 1rem; font-family: 'JetBrains Mono', monospace;">
                    <div><strong>Target:</strong> ${data.target}</div>
                    <div><strong>Packet Loss:</strong> ${data.packetLoss}%</div>
                    <div><strong>Min Latency:</strong> ${data.minLatency}ms</div>
                    <div><strong>Max Latency:</strong> ${data.maxLatency}ms</div>
                    <div><strong>Avg Latency:</strong> ${data.avgLatency}ms</div>
                    <div style="margin-top: 1rem; padding: 1rem; background: var(--bg-secondary); border-radius: 4px;">
                        <pre style="margin: 0; font-size: 0.8rem; color: var(--text-secondary);">${data.rawOutput}</pre>
                    </div>
                </div>
            `;
        } else {
            result.innerHTML = `<span style="color: var(--error-color);">${data.error}</span>`;
        }
    } catch (error) {
        result.innerHTML = '<span style="color: var(--error-color);">Failed to connect to server</span>';
    }
}

// Add ripple animation style
const rippleStyle = document.createElement('style');
rippleStyle.textContent = `
    @keyframes ripple {
        to {
            transform: scale(4);
            opacity: 0;
        }
    }
`;
document.head.appendChild(rippleStyle);

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new TerminalBackground();
    new Navigation();
    new ToolCards();
    wireToolLaunchButtons();
    new ScrollAnimations();
});

// Add some terminal typing effect to the hero section
class HeroTypingEffect {
    constructor() {
        this.subtitle = document.querySelector('.hero-subtitle');
        this.originalText = this.subtitle.textContent;
        this.init();
    }

    init() {
        this.typeText();
    }

    typeText() {
        this.subtitle.textContent = '';
        let index = 0;

        const type = () => {
            if (index < this.originalText.length) {
                this.subtitle.textContent += this.originalText[index];
                index++;
                setTimeout(type, 50);
            }
        };

        setTimeout(type, 1000);
    }
}

// Initialize typing effect
document.addEventListener('DOMContentLoaded', () => {
    new HeroTypingEffect();
});
