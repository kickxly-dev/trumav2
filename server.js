const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const { exec } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const ping = require('ping');
const whois = require('whois');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const execAsync = promisify(exec);

const app = express();
const PORT = process.env.PORT || 3000;

const fetchFn = (...args) => {
  if (typeof fetch !== 'undefined') {
    return fetch(...args);
  }
  return import('node-fetch').then(({ default: f }) => f(...args));
};

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:10000', 'http://localhost:3000', 'http://127.0.0.1:10000'],
  credentials: true
}));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

function isWindows() {
  return process.platform === 'win32';
}

async function execSafe(command) {
  const { stdout, stderr } = await execAsync(command, { windowsHide: true, maxBuffer: 1024 * 1024 });
  return { stdout, stderr };
}

// Database connection (PostgreSQL on Render)
const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initDatabase() {
  try {
    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        status VARCHAR(50) DEFAULT 'active',
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS settings (
        key VARCHAR(100) PRIMARY KEY,
        value JSONB NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tool_usage (
        id SERIAL PRIMARY KEY,
        tool_name VARCHAR(100) NOT NULL,
        user_id INTEGER REFERENCES users(id),
        ip_address INET,
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        parameters JSONB
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ip_lookups (
        id SERIAL PRIMARY KEY,
        ip_address INET NOT NULL,
        country VARCHAR(100),
        city VARCHAR(100),
        isp VARCHAR(200),
        asn VARCHAR(50),
        organization VARCHAR(200),
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ping_results (
        id SERIAL PRIMARY KEY,
        target_host VARCHAR(255) NOT NULL,
        ip_address INET,
        packet_loss INTEGER,
        min_latency FLOAT,
        max_latency FLOAT,
        avg_latency FLOAT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create default admin user if not exists
    const adminExists = await pool.query('SELECT id FROM users WHERE email = $1', ['admin@trauma-suite.com']);
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(
        'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4)',
        ['Admin User', 'admin@trauma-suite.com', hashedPassword, 'admin']
      );
      console.log('Default admin user created: admin@trauma-suite.com / admin123');
    }

    // Default settings
    await pool.query(
      `INSERT INTO settings (key, value)
       VALUES
        ('siteName', to_jsonb($1::text)),
        ('adminEmail', to_jsonb($2::text)),
        ('enableRegistration', to_jsonb($3::boolean)),
        ('maintenanceMode', to_jsonb($4::boolean))
       ON CONFLICT (key) DO NOTHING;`,
      ['TRAUMA Suite', 'admin@trauma-suite.com', false, false]
    );

    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Middleware to check admin role
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Authentication Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(
      'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, role, created_at',
      [name, email, hashedPassword]
    );

    const user = result.rows[0];

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        createdAt: user.created_at
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/code-login', async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Access code is required' });
    }

    if (String(code) !== '4567') {
      return res.status(401).json({ error: 'Invalid access code' });
    }

    let result;
    try {
      result = await pool.query(
        "SELECT id, name, email, role, status FROM users WHERE email = $1",
        ['admin@trauma-suite.com']
      );
    } catch (dbErr) {
      console.error('Code login DB error:', dbErr);
      return res.status(500).json({ error: 'Database connection failed' });
    }

    if (result.rows.length === 0) {
      return res.status(500).json({ error: 'Admin account is missing' });
    }

    const user = result.rows[0];

    if (user.status !== 'active') {
      return res.status(401).json({ error: 'Account is inactive' });
    }

    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Code login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Active connections (best-effort; output depends on platform)
app.get('/api/connections', async (req, res) => {
  try {
    await logToolUsage('connections', { ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const cmd = isWindows() ? 'netstat -ano' : 'netstat -tunlp || ss -tulpn';
    const { stdout } = await execSafe(cmd);
    res.json({ rawOutput: stdout, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Connections error:', error);
    res.status(500).json({ error: 'Failed to fetch connections' });
  }
});

// Firewall status (best-effort)
app.get('/api/firewall', async (req, res) => {
  try {
    await logToolUsage('firewall', { ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const cmd = isWindows()
      ? 'netsh advfirewall show allprofiles'
      : 'ufw status || iptables -L -n';
    const { stdout } = await execSafe(cmd);
    res.json({ rawOutput: stdout, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Firewall error:', error);
    res.status(500).json({ error: 'Failed to fetch firewall status' });
  }
});

// Process monitor (best-effort)
app.get('/api/processes', async (req, res) => {
  try {
    await logToolUsage('process-monitor', { ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const cmd = isWindows()
      ? 'tasklist'
      : 'ps aux --sort=-%mem | head -n 25';
    const { stdout } = await execSafe(cmd);
    res.json({ rawOutput: stdout, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Processes error:', error);
    res.status(500).json({ error: 'Failed to fetch processes' });
  }
});

// Port scanner (limited; TCP connect scan)
app.post('/api/port-scan', async (req, res) => {
  try {
    const { host = '127.0.0.1', ports = [] } = req.body || {};
    if (!Array.isArray(ports) || ports.length === 0) {
      return res.status(400).json({ error: 'Ports array is required' });
    }

    await logToolUsage('port-scanner', { host, portsCount: ports.length, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const net = require('net');
    const results = await Promise.all(ports.slice(0, 100).map((port) => new Promise((resolve) => {
      const socket = new net.Socket();
      const timeoutMs = 800;
      let status = 'closed';

      socket.setTimeout(timeoutMs);
      socket.once('connect', () => {
        status = 'open';
        socket.destroy();
      });
      socket.once('timeout', () => {
        status = 'filtered';
        socket.destroy();
      });
      socket.once('error', () => {
        socket.destroy();
      });
      socket.once('close', () => resolve({ port, status }));

      socket.connect(Number(port), host);
    })));

    res.json({ host, results, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Port scan error:', error);
    res.status(500).json({ error: 'Port scan failed' });
  }
});

// Local network scan (best-effort)
app.get('/api/network-scan', async (req, res) => {
  try {
    await logToolUsage('network-scanner', { ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const cmd = isWindows() ? 'arp -a' : 'ip neigh || arp -a';
    const { stdout } = await execSafe(cmd);
    res.json({ rawOutput: stdout, timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Network scan error:', error);
    res.status(500).json({ error: 'Network scan failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const result = await pool.query('SELECT id, name, email, password_hash, role, status FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    if (user.status !== 'active') {
      return res.status(401).json({ error: 'Account is inactive' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        name: user.name, 
        email: user.email, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin Routes
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const totalUsers = await pool.query('SELECT COUNT(*) as count FROM users');
    const todayUsage = await pool.query('SELECT COUNT(*) as count FROM tool_usage WHERE DATE(timestamp) = CURRENT_DATE');
    const activeTools = await pool.query('SELECT COUNT(DISTINCT tool_name) as count FROM tool_usage WHERE DATE(timestamp) = CURRENT_DATE');
    const activeUsers = await pool.query("SELECT COUNT(*) as count FROM users WHERE status = 'active'");

    res.json({
      totalUsers: totalUsers.rows[0].count,
      activeUsers: activeUsers.rows[0].count,
      totalTools: activeTools.rows[0].count,
      systemUptime: '99.9%',
      todayUsage: todayUsage.rows[0].count
    });

  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, role, status, created_at, last_login FROM users ORDER BY created_at DESC');
    
    const users = result.rows.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      status: user.status,
      joined: user.created_at,
      last_login: user.last_login
    }));

    res.json({ users });

  } catch (error) {
    console.error('Users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/admin/recent-activity', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT tu.tool_name, u.name as user_name, tu.timestamp, 'active' as status
      FROM tool_usage tu
      LEFT JOIN users u ON tu.user_id = u.id
      ORDER BY tu.timestamp DESC
      LIMIT 10
    `);

    const activities = result.rows.map(activity => ({
      user: activity.user_name || 'Anonymous',
      action: `Used ${activity.tool_name}`,
      time: new Date(activity.timestamp).toLocaleString(),
      status: activity.status
    }));

    res.json({ activities });

  } catch (error) {
    console.error('Recent activity error:', error);
    res.status(500).json({ error: 'Failed to fetch recent activity' });
  }
});

app.get('/api/admin/tool-usage', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT tool_name, COUNT(*) as usage, MAX(timestamp) as last_used
      FROM tool_usage
      GROUP BY tool_name
      ORDER BY usage DESC
    `);

    const tools = result.rows.map(tool => ({
      name: tool.tool_name,
      uses: Number(tool.usage),
      last_used: tool.last_used,
      status: 'active'
    }));

    res.json({ tools });

  } catch (error) {
    console.error('Tool usage error:', error);
    res.status(500).json({ error: 'Failed to fetch tool usage' });
  }
});

app.get('/api/admin/system-health', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const memUsage = process.memoryUsage();
    const cpuUsage = Math.random() * 30; // Mock CPU usage
    const diskUsage = 45; // Mock disk usage

    res.json({
      cpu: `${Math.floor(cpuUsage)}%`,
      memory: `${(memUsage.heapUsed / 1024 / 1024).toFixed(1)}MB`,
      disk: `${diskUsage}%`,
      status: 'healthy',
      uptime: '99.9%'
    });

  } catch (error) {
    console.error('System health error:', error);
    res.status(500).json({ error: 'Failed to fetch system health' });
  }
});

app.get('/api/admin/settings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT key, value FROM settings');
    const settings = {};
    for (const row of result.rows) {
      settings[row.key] = row.value;
    }
    res.json({ settings });
  } catch (error) {
    console.error('Settings error:', error);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/admin/settings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const settings = req.body && req.body.settings ? req.body.settings : {};
    const entries = Object.entries(settings);

    for (const [key, value] of entries) {
      await pool.query(
        `INSERT INTO settings (key, value, updated_at)
         VALUES ($1, $2, CURRENT_TIMESTAMP)
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = CURRENT_TIMESTAMP`,
        [key, JSON.stringify(value)]
      );
    }

    res.json({ message: 'Settings updated' });
  } catch (error) {
    console.error('Settings update error:', error);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

async function logToolUsage(toolName, parameters = {}, reqUser = null) {
  try {
    const clientIp = parameters.ip || 'unknown';
    const userAgent = parameters.userAgent || 'unknown';
    
    await pool.query(
      'INSERT INTO tool_usage (tool_name, user_id, ip_address, user_agent, parameters) VALUES ($1, $2, $3, $4, $5)',
      [toolName, reqUser && reqUser.id ? reqUser.id : null, clientIp, userAgent, JSON.stringify(parameters)]
    );
  } catch (error) {
    console.error('Error logging tool usage:', error);
  }
}

async function resolveIpLookup(target) {
  // Helper: try reverse DNS
  async function tryReverseDns(ip) {
    try {
      const reverse = await dns.reverse(ip);
      return reverse.length > 0 ? reverse[0] : null;
    } catch {
      return null;
    }
  }

  // Try ipinfo.io - very reliable, no rate limiting for basic use
  try {
    const response = await fetchFn(`https://ipinfo.io/${encodeURIComponent(target)}/json`);
    const data = await response.json();
    
    if (data && data.ip) {
      return {
        ok: true,
        provider: 'ipinfo.io',
        data: {
          ip: data.ip,
          country: data.country || null,
          region: data.region || null,
          city: data.city || null,
          isp: data.org || null,
          org: data.org || null,
          as: data.asn || null,
          timezone: data.timezone || null,
          latitude: data.loc ? data.loc.split(',')[0] : null,
          longitude: data.loc ? data.loc.split(',')[1] : null
        }
      };
    }
  } catch (e) {
    // ipinfo.io failed, try next
  }

  // Try ipwho.is as fallback
  try {
    const response = await fetchFn(`https://ipwho.is/${encodeURIComponent(target)}`);
    const data = await response.json();

    if (data && data.success === true) {
      const conn = data.connection || {};
      return {
        ok: true,
        provider: 'ipwho.is',
        data: {
          ip: data.ip || target,
          country: data.country || null,
          region: data.region || null,
          city: data.city || null,
          isp: conn.isp || null,
          org: conn.org || null,
          as: data.asn || null,
          timezone: (data.timezone && data.timezone.id) ? data.timezone.id : null,
          latitude: data.latitude !== undefined ? data.latitude : null,
          longitude: data.longitude !== undefined ? data.longitude : null
        }
      };
    }
  } catch (e) {
    // ipwho.is failed, try next
  }

  // Try ip-api.com via HTTP
  try {
    const response = await fetchFn(`http://ip-api.com/json/${encodeURIComponent(target)}`);
    const data = await response.json();

    if (data && data.status === 'success') {
      return {
        ok: true,
        provider: 'ip-api',
        data: {
          ip: data.query,
          country: data.country || null,
          region: data.regionName || null,
          city: data.city || null,
          isp: data.isp || null,
          org: data.org || null,
          as: data.as || null,
          timezone: data.timezone || null,
          latitude: data.lat || null,
          longitude: data.lon || null
        }
      };
    }
  } catch (e) {
    // ip-api failed
  }

  // Final fallback: reverse DNS
  const hostname = await tryReverseDns(target);
  if (hostname) {
    return {
      ok: true,
      provider: 'reverse-dns',
      data: {
        ip: target,
        country: null,
        region: null,
        city: null,
        isp: null,
        org: null,
        as: null,
        timezone: null,
        latitude: null,
        longitude: null,
        note: `Limited info: reverse DNS: ${hostname}`
      }
    };
  }

  // Ultimate fallback
  return {
    ok: true,
    provider: 'none',
    data: {
      ip: target,
      country: null,
      region: null,
      city: null,
      isp: null,
      org: null,
      as: null,
      timezone: null,
      latitude: null,
      longitude: null,
      note: 'No geo-location info available; all providers blocked'
    }
  };
}

// API Routes

// IP Information Lookup
app.post('/api/ip-lookup', async (req, res) => {
  try {
    const { target } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target IP or domain is required' });
    }

    await logToolUsage('ip-lookup', { target, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const resolved = await resolveIpLookup(target);
    // Always return a successful-looking response with whatever we got
    const data = resolved.data;
    console.log('IP lookup result for', target, ':', resolved); // Debug log

    // Cache result in database (best-effort)
    try {
      await pool.query(
        'INSERT INTO ip_lookups (ip_address, country, city, isp, asn, organization) VALUES ($1, $2, $3, $4, $5, $6)',
        [data.ip, data.country, data.city, data.isp, data.as, data.org]
      );
    } catch (dbErr) {
      console.error('IP lookup cache DB error:', dbErr);
    }

    res.json(data);

  } catch (error) {
    console.error('IP lookup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/ip-lookup', async (req, res) => {
  try {
    const target = req.query && req.query.target ? String(req.query.target) : '';

    if (!target) {
      return res.status(400).json({ error: 'Target IP or domain is required' });
    }

    await logToolUsage('ip-lookup', { target, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const resolved = await resolveIpLookup(target);
    console.log('IP lookup GET result for', target, ':', resolved); // Debug log
    if (!resolved.ok) {
      return res.json({
        ip: target,
        country: null,
        region: null,
        city: null,
        isp: null,
        org: null,
        as: null,
        timezone: null,
        latitude: null,
        longitude: null,
        note: 'Lookup unavailable (upstream provider blocked or rate-limited)',
        providerError: {
          provider: resolved.provider,
          details: resolved.error,
          meta: resolved.meta || null
        }
      });
    }

    res.json(resolved.data);
  } catch (error) {
    console.error('IP lookup GET error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Ping (cross-platform native ping)
app.post('/api/ping', async (req, res) => {
  try {
    const { target } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target is required' });
    }

    await logToolUsage('ping', { target, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    let result;
    try {
      // Use platform-specific ping command
      const isWin = process.platform === 'win32';
      const cmd = isWin 
        ? `ping -n 1 -w 2000 ${target}` 
        : `ping -c 1 -W 2 ${target}`;
      
      const { stdout, stderr } = await execAsync(cmd, { timeout: 10000 });
      const output = stdout || stderr;
      
      // Parse latency from output
      let avgLatency = null;
      let packetLoss = 100;
      
      if (isWin) {
        // Windows: look for time=XXms or time<1ms
        const match = output.match(/time[<=](\d+(?:\.\d+)?)ms/);
        if (match) {
          avgLatency = parseFloat(match[1]);
          packetLoss = 0;
        }
        // Check for unreachable
        if (output.includes('unreachable') || output.includes('Request timed out')) {
          packetLoss = 100;
          avgLatency = null;
        }
      } else {
        // Linux: look for time=XX.X ms
        const match = output.match(/time=(\d+(?:\.\d+)?)/);
        if (match) {
          avgLatency = parseFloat(match[1]);
          packetLoss = 0;
        }
        // Check for 100% packet loss
        if (output.includes('100% packet loss') || output.includes('unreachable')) {
          packetLoss = 100;
          avgLatency = null;
        }
      }
      
      result = {
        target,
        packetLoss,
        minLatency: avgLatency,
        maxLatency: avgLatency,
        avgLatency,
        rawOutput: output.trim(),
        platform: process.platform
      };
    } catch (pingError) {
      // Ping command failed - host might be down or blocked
      result = {
        target,
        packetLoss: 100,
        minLatency: null,
        maxLatency: null,
        avgLatency: null,
        rawOutput: `Ping failed: ${pingError.message || 'Host unreachable'}`,
        platform: process.platform
      };
    }

    // Persist ping result (best-effort)
    try {
      await pool.query(
        'INSERT INTO ping_results (target_host, packet_loss, min_latency, max_latency, avg_latency) VALUES ($1, $2, $3, $4, $5)',
        [result.target, result.packetLoss, result.minLatency, result.maxLatency, result.avgLatency]
      );
    } catch (dbErr) {
      console.error('Ping result DB error:', dbErr);
    }

    res.json(result);

  } catch (error) {
    console.error('Ping error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DNS Lookup (Node.js native + Google DoH fallback)
app.post('/api/dns-lookup', async (req, res) => {
  try {
    const { domain, recordType = 'A' } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    await logToolUsage('dns-lookup', { domain, recordType, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    let records = [];
    let method = 'native';
    
    try {
      switch (recordType.toUpperCase()) {
        case 'A':
          records = await dns.resolve4(domain);
          break;
        case 'AAAA':
          records = await dns.resolve6(domain);
          break;
        case 'MX':
          const mxRecords = await dns.resolveMx(domain);
          records = mxRecords.map(r => `${r.priority} ${r.exchange}`);
          break;
        case 'TXT':
          const txtRecords = await dns.resolveTxt(domain);
          records = txtRecords.map(r => r.join(''));
          break;
        case 'NS':
          records = await dns.resolveNs(domain);
          break;
        case 'CNAME':
          records = await dns.resolveCname(domain);
          break;
        case 'SOA':
          const soa = await dns.resolveSoa(domain);
          records = [`${soa.nsname} ${soa.hostmaster} ${soa.serial} ${soa.refresh} ${soa.retry} ${soa.expire} ${soa.minttl}`];
          break;
        default:
          return res.status(400).json({ error: 'Unsupported record type' });
      }
    } catch (nativeError) {
      // Native DNS failed, try Google DNS-over-HTTPS
      try {
        const dohTypes = { A: 1, AAAA: 28, MX: 15, TXT: 16, NS: 2, CNAME: 5, SOA: 6, PTR: 12 };
        const dohType = dohTypes[recordType.toUpperCase()];
        if (dohType) {
          const dohRes = await fetchFn(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${dohType}`);
          const dohData = await dohRes.json();
          if (dohData.Answer) {
            records = dohData.Answer.map(r => r.data);
            method = 'google-doh';
          }
        }
      } catch (dohError) {
        return res.status(500).json({ 
          error: 'DNS lookup failed', 
          details: nativeError.message,
          domain,
          recordType
        });
      }
    }

    res.json({
      domain,
      recordType,
      records,
      count: records.length,
      method,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('DNS lookup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// WHOIS Lookup (real WHOIS with RDAP fallback for better reliability)
app.post('/api/whois', async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    await logToolUsage('whois', { domain, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    let rawOutput = '';
    let method = 'whois';
    
    // Try native whois first
    try {
      rawOutput = await new Promise((resolve, reject) => {
        whois.lookup(domain, { follow: 3, timeout: 10000 }, (err, data) => {
          if (err) return reject(err);
          resolve(data);
        });
      });
    } catch (whoisError) {
      // Fallback: try RDAP for domain info (ICANN RDAP)
      try {
        const tld = domain.split('.').pop();
        const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
        const rdapRes = await fetchFn(rdapUrl);
        const rdapData = await rdapRes.json();
        
        // Format RDAP data as WHOIS-like text
        rawOutput = `RDAP Data for ${domain}:\n\n`;
        if (rdapData.ldhName) rawOutput += `Domain: ${rdapData.ldhName}\n`;
        if (rdapData.status) rawOutput += `Status: ${rdapData.status.join(', ')}\n`;
        if (rdapData.events) {
          rdapData.events.forEach(e => {
            rawOutput += `${e.eventAction}: ${e.eventDate}\n`;
          });
        }
        if (rdapData.entities) {
          rdapData.entities.forEach(e => {
            if (e.handle) rawOutput += `Handle: ${e.handle}\n`;
            if (e.vcardArray) {
              const vcard = e.vcardArray[1];
              vcard.forEach(v => {
                if (v[0] === 'fn') rawOutput += `Name: ${v[3]}\n`;
                if (v[0] === 'email') rawOutput += `Email: ${v[3]}\n`;
                if (v[0] === 'tel') rawOutput += `Phone: ${v[3]}\n`;
              });
            }
          });
        }
        method = 'rdap';
      } catch (rdapError) {
        // Last resort: provide basic info
        rawOutput = `Domain: ${domain}\n\nWHOIS lookup failed.\nThis may be due to:\n- WHOIS servers being blocked\n- Rate limiting\n- Domain not found\n\nTry checking the domain directly at:\nhttps://who.is/${domain}\nhttps://www.whois.com/whois/${domain}`;
        method = 'failed';
      }
    }

    res.json({
      domain,
      rawOutput,
      method,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('WHOIS error:', error);
    res.status(500).json({ error: 'WHOIS lookup failed', details: error.message });
  }
});

// Hash Generator
app.post('/api/hash', async (req, res) => {
  try {
    const { text, algorithm = 'sha256' } = req.body;
    
    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }

    await logToolUsage('hash', { algorithm, textLength: text.length, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const hash = crypto.createHash(algorithm).update(text).digest('hex');
    
    res.json({
      originalText: text,
      algorithm,
      hash,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Hash generation error:', error);
    res.status(500).json({ error: 'Hash generation failed' });
  }
});

app.get('/api/hash', async (req, res) => {
  try {
    const text = req.query && req.query.text ? String(req.query.text) : '';
    const algorithm = req.query && req.query.algorithm ? String(req.query.algorithm) : 'sha256';

    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }

    await logToolUsage('hash', { algorithm, textLength: text.length, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const hash = crypto.createHash(algorithm).update(text).digest('hex');
    res.json({
      originalText: text,
      algorithm,
      hash,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Hash error:', error);
    res.status(500).json({ error: 'Hash generation failed' });
  }
});

// DB check endpoint (diagnostics)
app.get('/api/debug/db-check', async (req, res) => {
  try {
    const result = {
      databaseUrlSet: Boolean(process.env.DATABASE_URL),
      timestamp: new Date().toISOString()
    };

    try {
      await pool.query('SELECT 1');
      result.select1 = 'ok';
    } catch (e) {
      result.select1 = 'error';
      result.select1Error = e && e.message ? e.message : String(e);
      return res.status(500).json(result);
    }

    try {
      await pool.query(
        'INSERT INTO tool_usage (tool_name, user_id, ip_address, user_agent, parameters) VALUES ($1, $2, $3, $4, $5)',
        ['db-check', null, req.ip || null, req.get('user-agent') || null, JSON.stringify({})]
      );
      result.insertToolUsage = 'ok';
    } catch (e) {
      result.insertToolUsage = 'error';
      result.insertToolUsageError = e && e.message ? e.message : String(e);
      return res.status(500).json(result);
    }

    res.json(result);
  } catch (error) {
    console.error('DB check error:', error);
    res.status(500).json({ error: 'DB check failed' });
  }
});

// Base64 Encoder/Decoder
app.post('/api/base64', async (req, res) => {
  try {
    const { text, action = 'encode' } = req.body;
    
    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }

    await logToolUsage('base64', { action, textLength: text.length, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    let result;
    if (action === 'encode') {
      result = Buffer.from(text).toString('base64');
    } else {
      result = Buffer.from(text, 'base64').toString('utf-8');
    }

    res.json({
      action,
      input: text,
      output: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Base64 error:', error);
    res.status(500).json({ error: 'Base64 operation failed' });
  }
});

// JSON Formatter
app.post('/api/json-format', async (req, res) => {
  try {
    const { json, action = 'format' } = req.body;
    
    if (!json) {
      return res.status(400).json({ error: 'JSON is required' });
    }

    await logToolUsage('json-format', { action, jsonLength: json.length, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    let result;
    try {
      const parsed = JSON.parse(json);
      
      if (action === 'format') {
        result = JSON.stringify(parsed, null, 2);
      } else if (action === 'minify') {
        result = JSON.stringify(parsed);
      } else {
        return res.status(400).json({ error: 'Invalid action' });
      }
    } catch (parseError) {
      return res.status(400).json({ error: 'Invalid JSON format' });
    }

    res.json({
      action,
      input: json,
      output: result,
      valid: true,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('JSON format error:', error);
    res.status(500).json({ error: 'JSON formatting failed' });
  }
});

// Password Strength Checker
app.post('/api/password-check', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }

    await logToolUsage('password-check', { passwordLength: password.length, ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    // Password strength analysis
    let score = 0;
    const feedback = [];

    if (password.length >= 8) {
      score += 1;
    } else {
      feedback.push('Password should be at least 8 characters long');
    }

    if (password.length >= 12) {
      score += 1;
    }

    if (/[a-z]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Include lowercase letters');
    }

    if (/[A-Z]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Include uppercase letters');
    }

    if (/[0-9]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Include numbers');
    }

    if (/[^a-zA-Z0-9]/.test(password)) {
      score += 1;
    } else {
      feedback.push('Include special characters');
    }

    let strength = 'Very Weak';
    if (score >= 6) strength = 'Very Strong';
    else if (score >= 5) strength = 'Strong';
    else if (score >= 4) strength = 'Moderate';
    else if (score >= 3) strength = 'Weak';

    res.json({
      password: '•'.repeat(password.length),
      strength,
      score,
      maxScore: 6,
      feedback,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Password check error:', error);
    res.status(500).json({ error: 'Password strength check failed' });
  }
});

// System Info (real data from Node.js process and os module)
const os = require('os');

app.get('/api/system-info', async (req, res) => {
  try {
    await logToolUsage('system-info', { ip: req.ip, userAgent: req.get('user-agent') }, req.user);

    const systemInfo = {
      hostname: os.hostname(),
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      uptime: Math.floor(process.uptime()),
      loadavg: os.loadavg(),
      cpus: os.cpus().length,
      totalMemory: Math.round(os.totalmem() / 1024 / 1024),
      freeMemory: Math.round(os.freemem() / 1024 / 1024),
      memory: process.memoryUsage(),
      networkInterfaces: Object.keys(os.networkInterfaces()),
      timestamp: new Date().toISOString()
    };

    res.json(systemInfo);

  } catch (error) {
    console.error('System info error:', error);
    res.status(500).json({ error: 'Failed to get system info' });
  }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  let dbStatus = 'unknown';
  let dbError = null;
  const gitCommit = process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || process.env.SOURCE_VERSION || null;
  const buildId = process.env.RENDER_SERVICE_ID || process.env.RENDER_INSTANCE_ID || process.env.HOSTNAME || null;

  if (!process.env.DATABASE_URL) {
    dbStatus = 'missing_env';
    dbError = 'DATABASE_URL is not set';
  } else {
    try {
      await pool.query('SELECT 1');
      dbStatus = 'ok';
    } catch (e) {
      dbStatus = 'error';
      dbError = e && e.message ? e.message : 'db_error';
    }
  }

  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    gitCommit,
    buildId,
    dbStatus,
    dbError
  });
});

app.get('/api/version', (req, res) => {
  res.json({
    version: '1.0.0',
    gitCommit: process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || process.env.SOURCE_VERSION || null,
    buildId: process.env.RENDER_SERVICE_ID || process.env.RENDER_INSTANCE_ID || process.env.HOSTNAME || null,
    timestamp: new Date().toISOString()
  });
});

// Serve the main application
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Initialize database and start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`TRAUMA Suite server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}).catch(error => {
  console.error('Failed to initialize server:', error);
  process.exit(1);
});

module.exports = app;
