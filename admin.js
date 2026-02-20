// Admin Dashboard System
class AdminDashboard {
    constructor() {
        this.currentSection = 'dashboard';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadUserData();
        this.loadDashboardData();
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
            // Load mock statistics
            this.loadMockStatistics();
            
            // Load mock recent activity
            this.loadMockRecentActivity();
            
            // Load mock system health
            this.loadMockSystemHealth();
        } catch (error) {
            console.error('Error loading dashboard data:', error);
        }
    }

    loadMockStatistics() {
        const stats = {
            totalUsers: 1,
            activeUsers: 1,
            totalTools: 8,
            systemUptime: '99.9%'
        };
        
        document.getElementById('totalUsers').textContent = stats.totalUsers;
        document.getElementById('activeUsers').textContent = stats.activeUsers;
        document.getElementById('totalTools').textContent = stats.totalTools;
        document.getElementById('systemUptime').textContent = stats.systemUptime;
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

    loadUsersData() {
        // Mock users data
        const users = [
            { id: 1, name: 'Admin User', email: 'admin@trauma-suite.com', role: 'admin', status: 'active', lastLogin: '2 minutes ago' }
        ];
        
        const tbody = document.querySelector('#usersTable tbody');
        if (tbody) {
            tbody.innerHTML = users.map(user => `
                <tr>
                    <td>${user.id}</td>
                    <td>${user.name}</td>
                    <td>${user.email}</td>
                    <td><span class="status-badge status-${user.status}">${user.status}</span></td>
                    <td>${user.lastLogin}</td>
                    <td>
                        <button class="btn btn-sm btn-primary">Edit</button>
                        <button class="btn btn-sm btn-danger">Delete</button>
                    </td>
                </tr>
            `).join('');
        }
    }

    loadAnalyticsData() {
        // Mock analytics data
        console.log('Loading analytics data...');
    }

    loadToolsData() {
        // Mock tools data
        const tools = [
            { name: 'IP Lookup', uses: 245, lastUsed: '5 minutes ago', status: 'active' },
            { name: 'Ping Tool', uses: 189, lastUsed: '12 minutes ago', status: 'active' },
            { name: 'DNS Lookup', uses: 156, lastUsed: '1 hour ago', status: 'active' }
        ];
        
        const tbody = document.querySelector('#toolsTable tbody');
        if (tbody) {
            tbody.innerHTML = tools.map(tool => `
                <tr>
                    <td>${tool.name}</td>
                    <td>${tool.uses}</td>
                    <td>${tool.lastUsed}</td>
                    <td><span class="status-badge status-${tool.status}">${tool.status}</span></td>
                    <td>
                        <button class="btn btn-sm btn-primary">Configure</button>
                    </td>
                </tr>
            `).join('');
        }
    }

    loadSystemData() {
        // System data already loaded in loadMockSystemHealth()
        console.log('System data loaded');
    }

    loadSettingsData() {
        // Mock settings data
        console.log('Loading settings data...');
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
