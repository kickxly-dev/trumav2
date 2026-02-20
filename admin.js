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
        // Mobile menu toggle
        window.toggleSidebar = () => {
            const sidebar = document.getElementById('sidebar');
            sidebar.classList.toggle('open');
        };

        // Section navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const section = item.getAttribute('data-section');
                this.showSection(section);
            });
        });

        // Logout
        document.getElementById('logoutBtn').addEventListener('click', () => {
            this.logout();
        });
    }

    showSection(section) {
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(sec => {
            sec.classList.remove('active');
        });

        // Remove active class from all nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });

        // Show selected section
        document.getElementById(`${section}Section`).classList.add('active');
        document.querySelector(`[data-section="${section}"]`).classList.add('active');

        this.currentSection = section;
        this.loadSectionData(section);

        // Close mobile sidebar
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.remove('open');
        }
    }

    loadUserData() {
        // Set default admin user data
        document.getElementById('userName').textContent = 'Admin User';
        document.getElementById('userAvatar').textContent = 'A';
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
                document.getElementById('totalUsers').textContent = data.totalUsers || 0;
                document.getElementById('activeUsers').textContent = data.activeUsers || 0;
                document.getElementById('totalTools').textContent = data.totalTools || 0;
                document.getElementById('systemUptime').textContent = data.systemUptime || '99.9%';
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

            if (response.ok && data.activities) {
                const tbody = document.querySelector('#recentActivityTable tbody');
                if (tbody) {
                    tbody.innerHTML = data.activities.map(activity => `
                        <tr>
                            <td>${activity.user}</td>
                            <td>${activity.action}</td>
                            <td>${activity.time}</td>
                            <td><span class="status-badge status-${activity.status}">${activity.status}</span></td>
                        </tr>
                    `).join('');
                }
            }
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
                                <button class="btn btn-sm btn-primary" onclick="configureTool('${tool.name}')">Configure</button>
                            </td>
                        </tr>
                    `).join('');
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
            const response = await this.apiCall('/api/admin/settings');
            const data = await response.json();

            if (response.ok && data.settings) {
                // Load settings into form
                Object.keys(data.settings).forEach(key => {
                    const element = document.getElementById(key);
                    if (element) {
                        element.value = data.settings[key];
                    }
                });
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
            // Fallback to default settings
            this.loadDefaultSettings();
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

    async apiCall(endpoint) {
        const currentPort = window.location.port || '10000';
        const apiUrl = `http://localhost:${currentPort}${endpoint}`;
        
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            }
        });

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
