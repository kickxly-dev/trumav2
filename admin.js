// Admin Dashboard System
class AdminDashboard {
    constructor() {
        this.token = localStorage.getItem('trauma_token');
        this.user = JSON.parse(localStorage.getItem('trauma_user') || 'null');
        this.currentSection = 'dashboard';
        this.init();
    }

    init() {
        // Check authentication
        if (!this.isAuthenticated()) {
            window.location.href = 'auth.html';
            return;
        }

        this.setupEventListeners();
        this.loadUserData();
        this.loadDashboardData();
        this.startRealTimeUpdates();
    }

    isAuthenticated() {
        return !!localStorage.getItem('trauma_token');
    }

    setupEventListeners() {
        // Backwards-compatible globals (admin.html still uses inline onclick)
        window.toggleSidebar = () => this.toggleSidebar();
        window.showSection = (section) => this.showSection(section);
        window.logout = () => this.logout();

        const menuToggle = document.querySelector('.mobile-menu-toggle');
        if (menuToggle) {
            menuToggle.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleSidebar();
            });
        }

        // Section navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const href = item.getAttribute('href') || '';
                const section = item.getAttribute('data-section') || href.replace('#', '');
                if (section) this.showSection(section);
            });
        });

        // Logout
        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.logout();
        });

        const saveSettingsBtn = document.getElementById('saveSettingsBtn');
        if (saveSettingsBtn) {
            saveSettingsBtn.addEventListener('click', async () => {
                await this.saveSettings();
            });
        }
    }

    toggleSidebar() {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) sidebar.classList.toggle('open');
    }

    showSection(section) {
        // Hide all sections (admin.html uses .admin-content)
        document.querySelectorAll('.admin-content').forEach(sec => {
            sec.classList.remove('active');
        });

        // Remove active class from all nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });

        const sectionEl = document.getElementById(section);
        if (sectionEl) sectionEl.classList.add('active');

        const navEl = document.querySelector(`[data-section="${section}"]`) || document.querySelector(`a[href="#${section}"]`);
        if (navEl) navEl.classList.add('active');

        this.currentSection = section;
        this.loadSectionData(section);

        // Close mobile sidebar
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.remove('open');
        }
    }

    loadUserData() {
        const userNameEl = document.getElementById('userName');
        const userAvatarEl = document.getElementById('userAvatar');

        if (!userNameEl || !userAvatarEl) return;

        const name = (this.user && this.user.name) ? this.user.name : 'Admin User';
        userNameEl.textContent = name;
        userAvatarEl.textContent = name.split(' ').map(p => p[0]).join('').slice(0, 2).toUpperCase();
    }

    async loadDashboardData() {
        try {
            // Load real statistics
            await this.loadStatistics();
            
            // Load real recent activity
            await this.loadRecentActivity();
            
            // Load real system health
            await this.loadSystemHealth();
        } catch (error) {
            console.error('Error loading dashboard data:', error);
            // Fallback to mock data
            this.loadMockStatistics();
            this.loadMockRecentActivity();
            this.loadMockSystemHealth();
        }
    }

    async loadStatistics() {
        try {
            const response = await this.apiCall('/api/admin/stats');
            const data = await response.json();

            if (response.ok) {
                const totalUsersEl = document.getElementById('totalUsers');
                const todayUsageEl = document.getElementById('todayUsage');
                const activeToolsEl = document.getElementById('activeTools');
                const systemHealthEl = document.getElementById('systemHealth');

                if (totalUsersEl) totalUsersEl.textContent = data.totalUsers || 0;
                if (todayUsageEl) todayUsageEl.textContent = data.todayUsage || 0;
                if (activeToolsEl) activeToolsEl.textContent = data.totalTools || 0;
                if (systemHealthEl) systemHealthEl.textContent = '98%';
            }
        } catch (error) {
            console.error('Failed to load statistics:', error);
            throw error;
        }
    }

    async loadRecentActivity() {
        try {
            const response = await this.apiCall('/api/admin/recent-activity');
            const data = await response.json();

            const tbody = document.getElementById('recentActivity');
            if (!tbody) return;

            const activities = (response.ok && data.activities) ? data.activities : [];
            tbody.innerHTML = activities.map(activity => `
                <tr>
                    <td>${activity.user}</td>
                    <td>${activity.action}</td>
                    <td>${activity.time}</td>
                    <td><span class="status-badge status-${activity.status}">${activity.status}</span></td>
                </tr>
            `).join('');
        } catch (error) {
            console.error('Failed to load recent activity:', error);
            throw error;
        }
    }

    async loadSystemHealth() {
        try {
            const response = await this.apiCall('/api/admin/system-health');
            const data = await response.json();

            if (response.ok) {
                const cpuEl = document.getElementById('cpuUsage');
                const memoryEl = document.getElementById('memoryUsage');
                const diskEl = document.getElementById('diskUsage');
                const statusEl = document.getElementById('systemStatus');
                
                if (cpuEl) cpuEl.textContent = data.cpu || '45%';
                if (memoryEl) memoryEl.textContent = data.memory || '62%';
                if (diskEl) diskEl.textContent = data.disk || '38%';
                if (statusEl) statusEl.textContent = data.status || 'healthy';
            }
        } catch (error) {
            console.error('Failed to load system health:', error);
            throw error;
        }
    }

    loadMockRecentActivity() {
        const activities = [
            { user: 'Admin', action: 'Logged in', time: '2 minutes ago', status: 'success' },
            { user: 'Admin', action: 'Viewed dashboard', time: '5 minutes ago', status: 'info' },
            { user: 'Admin', action: 'Updated settings', time: '1 hour ago', status: 'warning' }
        ];
        
        const tbody = document.querySelector('#recentActivityTable tbody');
        if (tbody) {
            tbody.innerHTML = activities.map(activity => `
                <tr>
                    <td>${activity.user}</td>
                    <td>${activity.action}</td>
                    <td>${activity.time}</td>
                    <td><span class="status-badge status-${activity.status}">${activity.status}</span></td>
                </tr>
            `).join('');
        }
    }

    loadMockSystemHealth() {
        const health = {
            cpu: '45%',
            memory: '62%',
            disk: '38%',
            status: 'healthy'
        };
        
        const cpuEl = document.getElementById('cpuUsage');
        const memoryEl = document.getElementById('memoryUsage');
        const diskEl = document.getElementById('diskUsage');
        const statusEl = document.getElementById('systemStatus');
        
        if (cpuEl) cpuEl.textContent = health.cpu;
        if (memoryEl) memoryEl.textContent = health.memory;
        if (diskEl) diskEl.textContent = health.disk;
        if (statusEl) statusEl.textContent = health.status;
    }

    loadSectionData(section) {
        // Load section-specific data
        switch(section) {
            case 'users':
                this.loadUsersData();
                break;
            case 'analytics':
                this.loadAnalyticsData();
                break;
            case 'tools':
                this.loadToolsData();
                break;
            case 'system':
                this.loadSystemData();
                break;
            case 'settings':
                this.loadSettingsData();
                break;
            case 'security':
                this.setupSecuritySection();
                break;
        }
    }

    async loadUsersData() {
        try {
            const response = await this.apiCall('/api/admin/users');
            const data = await response.json();

            if (response.ok && data.users) {
                const tbody = document.querySelector('#usersTable tbody');
                if (tbody) {
                    tbody.innerHTML = data.users.map(user => `
                        <tr>
                            <td>${user.id}</td>
                            <td>${user.name}</td>
                            <td>${user.email}</td>
                            <td>${user.role}</td>
                            <td><span class="status-badge status-${user.status}">${user.status}</span></td>
                            <td>${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</td>
                            <td>
                                <button class="btn btn-sm btn-primary" data-action="edit-user" data-user-id="${user.id}">Edit</button>
                                <button class="btn btn-sm btn-danger" data-action="delete-user" data-user-id="${user.id}">Delete</button>
                            </td>
                        </tr>
                    `).join('');

                    tbody.querySelectorAll('button[data-action="edit-user"]').forEach(btn => {
                        btn.addEventListener('click', () => {
                            const id = btn.getAttribute('data-user-id');
                            alert(`Edit user ${id} is not implemented yet.`);
                        });
                    });

                    tbody.querySelectorAll('button[data-action="delete-user"]').forEach(btn => {
                        btn.addEventListener('click', () => {
                            const id = btn.getAttribute('data-user-id');
                            alert(`Delete user ${id} is not implemented yet.`);
                        });
                    });
                }
            }
        } catch (error) {
            console.error('Failed to load users:', error);
            // Fallback to mock data
            this.loadMockUsersData();
        }
    }

    loadMockUsersData() {
        const users = [
            { id: 1, name: 'Admin User', email: 'admin@trauma-suite.com', role: 'admin', status: 'active', last_login: '2 minutes ago' }
        ];
        
        const tbody = document.querySelector('#usersTable tbody');
        if (tbody) {
            tbody.innerHTML = users.map(user => `
                <tr>
                    <td>${user.id}</td>
                    <td>${user.name}</td>
                    <td>${user.email}</td>
                    <td><span class="status-badge status-${user.status}">${user.status}</span></td>
                    <td>${user.last_login || 'Never'}</td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="editUser(${user.id})">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id})">Delete</button>
                    </td>
                </tr>
            `).join('');
        }
    }

    loadAnalyticsData() {
        // Mock analytics data
        console.log('Loading analytics data...');
    }

    async loadToolsData() {
        try {
            const response = await this.apiCall('/api/admin/tool-usage');
            const data = await response.json();

            if (response.ok && data.tools) {
                const tbody = document.querySelector('#toolsTable tbody');
                if (tbody) {
                    tbody.innerHTML = data.tools.map(tool => `
                        <tr>
                            <td>${tool.name}</td>
                            <td>${tool.uses || 0}</td>
                            <td>${tool.last_used || 'Never'}</td>
                            <td><span class="status-badge status-${tool.status || 'active'}">${tool.status || 'active'}</span></td>
                            <td>
                                <button class="btn btn-sm btn-primary" data-action="configure-tool" data-tool-name="${tool.name}">Configure</button>
                            </td>
                        </tr>
                    `).join('');

                    tbody.querySelectorAll('button[data-action="configure-tool"]').forEach(btn => {
                        btn.addEventListener('click', () => {
                            const toolName = btn.getAttribute('data-tool-name');
                            alert(`Configure ${toolName} is not implemented yet.`);
                        });
                    });
                }
            }
        } catch (error) {
            console.error('Failed to load tools data:', error);
            // Fallback to mock data
            this.loadMockToolsData();
        }
    }

    loadMockToolsData() {
        const tools = [
            { name: 'IP Lookup', uses: 245, last_used: '5 minutes ago', status: 'active' },
            { name: 'Ping Tool', uses: 189, last_used: '12 minutes ago', status: 'active' },
            { name: 'DNS Lookup', uses: 156, last_used: '1 hour ago', status: 'active' }
        ];
        
        const tbody = document.querySelector('#toolsTable tbody');
        if (tbody) {
            tbody.innerHTML = tools.map(tool => `
                <tr>
                    <td>${tool.name}</td>
                    <td>${tool.uses}</td>
                    <td>${tool.last_used}</td>
                    <td><span class="status-badge status-${tool.status}">${tool.status}</span></td>
                    <td>
                        <button class="btn btn-sm btn-primary" onclick="configureTool('${tool.name}')">Configure</button>
                    </td>
                </tr>
            `).join('');
        }
    }

    loadSystemData() {
        // System data already loaded in loadMockSystemHealth()
        console.log('System data loaded');
    }

    async loadSettingsData() {
        try {
            const response = await this.apiCall('/api/admin/settings', { method: 'GET' });
            const data = await response.json();

            if (response.ok && data.settings) {
                Object.keys(data.settings).forEach(key => {
                    const element = document.getElementById(key);
                    if (!element) return;

                    const value = data.settings[key];
                    if (element.type === 'checkbox') {
                        element.checked = Boolean(value);
                    } else {
                        element.value = value;
                    }
                });
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
            // Fallback to default settings
            this.loadDefaultSettings();
        }
    }

    async saveSettings() {
        try {
            const payload = {
                siteName: document.getElementById('siteName')?.value || 'TRAUMA Suite',
                adminEmail: document.getElementById('adminEmail')?.value || 'admin@trauma-suite.com',
                enableRegistration: Boolean(document.getElementById('enableRegistration')?.checked),
                maintenanceMode: Boolean(document.getElementById('maintenanceMode')?.checked)
            };

            const response = await this.apiCall('/api/admin/settings', {
                method: 'PUT',
                body: { settings: payload }
            });

            const data = await response.json();
            if (!response.ok) {
                alert(data.error || 'Failed to save settings');
                return;
            }

            alert('Settings saved');
        } catch (error) {
            console.error('Failed to save settings:', error);
            alert('Failed to save settings');
        }
    }

    setupSecuritySection() {
        const viewLogsBtn = document.getElementById('viewLogsBtn');
        const showThreatsOnlyBtn = document.getElementById('showThreatsOnlyBtn');
        const refreshLogsBtn = document.getElementById('refreshLogsBtn');

        if (viewLogsBtn) {
            viewLogsBtn.addEventListener('click', () => this.loadSecurityLogs(false));
        }
        if (showThreatsOnlyBtn) {
            showThreatsOnlyBtn.addEventListener('click', () => this.loadSecurityLogs(true));
        }
        if (refreshLogsBtn) {
            refreshLogsBtn.addEventListener('click', () => this.loadSecurityLogs(false));
        }

        // Load security stats
        this.loadSecurityStats();
    }

    async loadSecurityStats() {
        const code = document.getElementById('securityCode')?.value || 'TRUMA-SEC-2025';
        try {
            const response = await fetch('/api/admin/security-stats', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code })
            });
            const data = await response.json();
            
            if (response.ok && data.stats) {
                document.getElementById('totalVisitors').textContent = data.stats.totalVisitors || 0;
                document.getElementById('totalThreats').textContent = data.stats.totalThreats || 0;
                document.getElementById('uniqueIPs').textContent = data.stats.uniqueIPs || 0;
                document.getElementById('todayVisitorsSec').textContent = data.stats.todayVisitors || 0;
            }
        } catch (error) {
            console.error('Failed to load security stats:', error);
        }
    }

    async loadSecurityLogs(showThreatsOnly = false) {
        const code = document.getElementById('securityCode')?.value;
        if (!code) {
            alert('Please enter the security access code');
            return;
        }

        try {
            const response = await fetch('/api/admin/visitor-logs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code, limit: 100, showThreatsOnly })
            });
            const data = await response.json();
            
            if (response.ok && data.logs) {
                const tbody = document.getElementById('visitorLogsBody');
                const table = document.getElementById('visitorLogsTable');
                
                if (tbody && table) {
                    table.style.display = 'block';
                    tbody.innerHTML = data.logs.map(log => `
                        <tr>
                            <td>${log.ip_address || 'N/A'}</td>
                            <td>${log.country || 'Unknown'}${log.city ? `, ${log.city}` : ''}</td>
                            <td>${log.path || '/'}</td>
                            <td>${log.method || 'GET'}</td>
                            <td>${log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A'}</td>
                            <td>${log.is_threat ? `<span class="status-badge" style="background:rgba(255,68,68,0.2);color:#ff4444;">${log.threat_type || 'THREAT'}</span>` : '-'}</td>
                        </tr>
                    `).join('');
                }
            } else {
                alert(data.error || 'Failed to load logs');
            }
        } catch (error) {
            console.error('Failed to load visitor logs:', error);
            alert('Failed to load visitor logs');
        }
    }

    loadDefaultSettings() {
        const defaultSettings = {
            siteName: 'TRAUMA Suite',
            adminEmail: 'admin@trauma-suite.com',
            enableRegistration: false,
            maintenanceMode: false
        };

        Object.keys(defaultSettings).forEach(key => {
            const element = document.getElementById(key);
            if (element) {
                element.value = defaultSettings[key];
            }
        });
    }

    async apiCall(endpoint, options = {}) {
        const apiUrl = endpoint;
        const method = options.method || 'GET';
        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`
        };

        const fetchOptions = { method, headers };
        if (options.body) {
            fetchOptions.body = JSON.stringify(options.body);
        }

        const response = await fetch(apiUrl, fetchOptions);

        return response;
    }

    startRealTimeUpdates() {
        // Update dashboard every 30 seconds
        setInterval(async () => {
            if (this.currentSection === 'dashboard') {
                try {
                    await this.loadStatistics();
                    await this.loadSystemHealth();
                } catch (error) {
                    console.error('Real-time update failed:', error);
                }
            }
        }, 30000);
    }

    logout() {
        localStorage.removeItem('trauma_token');
        localStorage.removeItem('trauma_user');
        window.location.href = 'auth.html';
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    new AdminDashboard();
});
