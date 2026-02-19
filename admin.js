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

        // Initialize dashboard
        this.setupEventListeners();
        this.loadUserData();
        this.loadDashboardData();
        this.startRealTimeUpdates();
    }

    isAuthenticated() {
        return !!this.token && !!this.user;
    }

    setupEventListeners() {
        // Mobile menu toggle
        window.toggleSidebar = () => {
            const sidebar = document.getElementById('sidebar');
            sidebar.classList.toggle('open');
        };

        // Section navigation
        window.showSection = (section) => {
            this.showSection(section);
        };

        // Logout
        window.logout = () => {
            this.logout();
        };
    }

    showSection(section) {
        // Hide all sections
        document.querySelectorAll('.admin-content').forEach(content => {
            content.classList.remove('active');
        });

        // Remove active class from all nav items
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });

        // Show selected section
        document.getElementById(section).classList.add('active');
        
        // Add active class to clicked nav item
        event.target.closest('.nav-item').classList.add('active');

        this.currentSection = section;

        // Load section-specific data
        this.loadSectionData(section);

        // Close mobile sidebar
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.remove('open');
        }
    }

    loadUserData() {
        if (this.user) {
            document.getElementById('userName').textContent = this.user.name || 'Admin User';
            
            // Set avatar initials
            const initials = this.user.name
                ? this.user.name.split(' ').map(n => n[0]).join('').toUpperCase()
                : 'A';
            document.getElementById('userAvatar').textContent = initials;
        }
    }

    async loadDashboardData() {
        try {
            // Load statistics
            await this.loadStatistics();
            
            // Load recent activity
            await this.loadRecentActivity();
            
            // Load system health
            await this.loadSystemHealth();
        } catch (error) {
            console.error('Failed to load dashboard data:', error);
        }
    }

    async loadStatistics() {
        try {
            const response = await this.apiCall('/api/admin/stats');
            const data = await response.json();

            if (response.ok) {
                document.getElementById('totalUsers').textContent = data.totalUsers || 0;
                document.getElementById('todayUsage').textContent = data.todayUsage || 0;
                document.getElementById('activeTools').textContent = data.activeTools || 0;
                document.getElementById('systemHealth').textContent = data.systemHealth || '98%';
            }
        } catch (error) {
            // Fallback data
            document.getElementById('totalUsers').textContent = '127';
            document.getElementById('todayUsage').textContent = '1,842';
            document.getElementById('activeTools').textContent = '12';
            document.getElementById('systemHealth').textContent = '98%';
        }
    }

    async loadRecentActivity() {
        try {
            const response = await this.apiCall('/api/admin/recent-activity');
            const activities = await response.json();

            if (response.ok) {
                this.renderRecentActivity(activities);
            } else {
                this.renderRecentActivity(this.getMockActivity());
            }
        } catch (error) {
            this.renderRecentActivity(this.getMockActivity());
        }
    }

    renderRecentActivity(activities) {
        const tbody = document.getElementById('recentActivity');
        tbody.innerHTML = '';

        activities.forEach(activity => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${activity.user}</td>
                <td>${activity.tool}</td>
                <td>${new Date(activity.timestamp).toLocaleString()}</td>
                <td><span class="status-badge status-${activity.status}">${activity.status}</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    getMockActivity() {
        return [
            { user: 'John Doe', tool: 'IP Lookup', timestamp: new Date().toISOString(), status: 'active' },
            { user: 'Jane Smith', tool: 'Ping Test', timestamp: new Date(Date.now() - 300000).toISOString(), status: 'active' },
            { user: 'Bob Johnson', tool: 'DNS Lookup', timestamp: new Date(Date.now() - 600000).toISOString(), status: 'active' },
            { user: 'Alice Brown', tool: 'WHOIS', timestamp: new Date(Date.now() - 900000).toISOString(), status: 'pending' },
            { user: 'Charlie Wilson', tool: 'Hash Generator', timestamp: new Date(Date.now() - 1200000).toISOString(), status: 'active' }
        ];
    }

    async loadSystemHealth() {
        try {
            const response = await this.apiCall('/api/admin/system-health');
            const data = await response.json();

            if (response.ok) {
                document.getElementById('cpuUsage').textContent = data.cpu + '%';
                document.getElementById('memoryUsage').textContent = data.memory + 'GB';
                document.getElementById('diskUsage').textContent = data.disk + '%';
                document.getElementById('uptime').textContent = data.uptime + '%';
            }
        } catch (error) {
            // Fallback data
            document.getElementById('cpuUsage').textContent = '15%';
            document.getElementById('memoryUsage').textContent = '2.1GB';
            document.getElementById('diskUsage').textContent = '45%';
            document.getElementById('uptime').textContent = '99.9%';
        }
    }

    async loadSectionData(section) {
        switch (section) {
            case 'users':
                await this.loadUsers();
                break;
            case 'analytics':
                await this.loadAnalytics();
                break;
            case 'tools':
                await this.loadToolUsage();
                break;
            case 'system':
                await this.loadSystemHealth();
                break;
        }
    }

    async loadUsers() {
        try {
            const response = await this.apiCall('/api/admin/users');
            const users = await response.json();

            if (response.ok) {
                this.renderUsers(users);
            } else {
                this.renderUsers(this.getMockUsers());
            }
        } catch (error) {
            this.renderUsers(this.getMockUsers());
        }
    }

    renderUsers(users) {
        const tbody = document.getElementById('usersTable');
        tbody.innerHTML = '';

        users.forEach(user => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${user.id}</td>
                <td>${user.name}</td>
                <td>${user.email}</td>
                <td>${user.role}</td>
                <td><span class="status-badge status-${user.status}">${user.status}</span></td>
                <td>${new Date(user.joined).toLocaleDateString()}</td>
                <td>
                    <button class="table-btn" onclick="editUser(${user.id})">Edit</button>
                    <button class="table-btn" onclick="deleteUser(${user.id})">Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    getMockUsers() {
        return [
            { id: 1, name: 'John Doe', email: 'john@example.com', role: 'Admin', status: 'active', joined: '2024-01-15' },
            { id: 2, name: 'Jane Smith', email: 'jane@example.com', role: 'User', status: 'active', joined: '2024-01-20' },
            { id: 3, name: 'Bob Johnson', email: 'bob@example.com', role: 'User', status: 'inactive', joined: '2024-02-01' },
            { id: 4, name: 'Alice Brown', email: 'alice@example.com', role: 'User', status: 'active', joined: '2024-02-10' }
        ];
    }

    async loadAnalytics() {
        // Analytics data loading would go here
        console.log('Loading analytics data...');
    }

    async loadToolUsage() {
        try {
            const response = await this.apiCall('/api/admin/tool-usage');
            const tools = await response.json();

            if (response.ok) {
                this.renderToolUsage(tools);
            } else {
                this.renderToolUsage(this.getMockToolUsage());
            }
        } catch (error) {
            this.renderToolUsage(this.getMockToolUsage());
        }
    }

    renderToolUsage(tools) {
        const tbody = document.getElementById('toolsTable');
        tbody.innerHTML = '';

        tools.forEach(tool => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${tool.name}</td>
                <td>${tool.usage}</td>
                <td>${new Date(tool.lastUsed).toLocaleString()}</td>
                <td><span class="status-badge status-${tool.status}">${tool.status}</span></td>
                <td>${tool.performance}</td>
            `;
            tbody.appendChild(tr);
        });
    }

    getMockToolUsage() {
        return [
            { name: 'IP Lookup', usage: '1,234', lastUsed: new Date().toISOString(), status: 'active', performance: '142ms' },
            { name: 'Ping Test', usage: '987', lastUsed: new Date(Date.now() - 300000).toISOString(), status: 'active', performance: '89ms' },
            { name: 'DNS Lookup', usage: '756', lastUsed: new Date(Date.now() - 600000).toISOString(), status: 'active', performance: '234ms' },
            { name: 'WHOIS', usage: '432', lastUsed: new Date(Date.now() - 900000).toISOString(), status: 'active', performance: '567ms' },
            { name: 'Hash Generator', usage: '321', lastUsed: new Date(Date.now() - 1200000).toISOString(), status: 'active', performance: '12ms' }
        ];
    }

    async apiCall(endpoint, options = {}) {
        const url = endpoint.startsWith('http') ? endpoint : `${endpoint}`;
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            }
        };

        const response = await fetch(url, { ...defaultOptions, ...options });
        return response;
    }

    logout() {
        localStorage.removeItem('trauma_token');
        localStorage.removeItem('trauma_user');
        window.location.href = 'auth.html';
    }

    startRealTimeUpdates() {
        // Update dashboard data every 30 seconds
        setInterval(() => {
            if (this.currentSection === 'dashboard') {
                this.loadDashboardData();
            }
        }, 30000);

        // Update system health every 10 seconds
        setInterval(() => {
            if (this.currentSection === 'system') {
                this.loadSystemHealth();
            }
        }, 10000);
    }
}

// User management functions
window.editUser = (userId) => {
    console.log('Edit user:', userId);
    // Implement user editing modal
};

window.deleteUser = (userId) => {
    if (confirm('Are you sure you want to delete this user?')) {
        console.log('Delete user:', userId);
        // Implement user deletion
    }
};

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new AdminDashboard();
});

// Handle window resize
window.addEventListener('resize', () => {
    if (window.innerWidth > 768) {
        document.getElementById('sidebar').classList.remove('open');
    }
});
