const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const fetch = require('node-fetch');
const { exec } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const execAsync = promisify(exec);

const app = express();
const PORT = process.env.PORT || 3000;

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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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

    res.json({
      totalUsers: totalUsers.rows[0].count,
      todayUsage: todayUsage.rows[0].count,
      activeTools: activeTools.rows[0].count,
      systemHealth: '98%'
    });

  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, role, status, created_at FROM users ORDER BY created_at DESC');
    
    const users = result.rows.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      status: user.status,
      joined: user.created_at
    }));

    res.json(users);

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
      tool: activity.tool_name,
      timestamp: activity.timestamp,
      status: activity.status
    }));

    res.json(activities);

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
      usage: tool.usage,
      lastUsed: tool.last_used,
      status: 'active',
      performance: Math.floor(Math.random() * 500) + 'ms' // Mock performance data
    }));

    res.json(tools);

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
      cpu: Math.floor(cpuUsage),
      memory: (memUsage.heapUsed / 1024 / 1024).toFixed(1),
      disk: diskUsage,
      uptime: '99.9'
    });

  } catch (error) {
    console.error('System health error:', error);
    res.status(500).json({ error: 'Failed to fetch system health' });
  }
});
async function logToolUsage(toolName, parameters = {}) {
  try {
    const clientIp = parameters.ip || 'unknown';
    const userAgent = parameters.userAgent || 'unknown';
    
    await pool.query(
      'INSERT INTO tool_usage (tool_name, ip_address, user_agent, parameters) VALUES ($1, $2, $3, $4)',
      [toolName, clientIp, userAgent, JSON.stringify(parameters)]
    );
  } catch (error) {
    console.error('Error logging tool usage:', error);
  }
}

// API Routes

// IP Information Lookup
app.post('/api/ip-lookup', async (req, res) => {
  try {
    const { target } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target IP or domain is required' });
    }

    await logToolUsage('ip-lookup', { target, ip: req.ip });

    // Use a free IP geolocation API
    const response = await fetch(`http://ip-api.com/json/${target}`);
    const data = await response.json();

    if (data.status === 'fail') {
      return res.status(404).json({ error: 'IP or domain not found' });
    }

    // Cache result in database
    await pool.query(
      'INSERT INTO ip_lookups (ip_address, country, city, isp, asn, organization) VALUES ($1, $2, $3, $4, $5, $6)',
      [data.query, data.country, data.city, data.isp, data.as, data.org]
    );

    res.json({
      ip: data.query,
      country: data.country,
      region: data.regionName,
      city: data.city,
      isp: data.isp,
      org: data.org,
      as: data.as,
      timezone: data.timezone,
      latitude: data.lat,
      longitude: data.lon
    });

  } catch (error) {
    console.error('IP lookup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Ping Test
app.post('/api/ping', async (req, res) => {
  try {
    const { target } = req.body;
    
    if (!target) {
      return res.status(400).json({ error: 'Target host is required' });
    }

    await logToolUsage('ping', { target, ip: req.ip });

    // Use Node.js ping library or system ping command
    try {
      const { stdout } = await execAsync(`ping -c 4 ${target}`);
      
      // Parse ping output
      const lines = stdout.split('\n');
      const statsLine = lines.find(line => line.includes('packet loss'));
      const rttLine = lines.find(line => line.includes('min/avg/max'));
      
      let packetLoss = 0;
      let minLatency = 0, maxLatency = 0, avgLatency = 0;

      if (statsLine) {
        const lossMatch = statsLine.match(/(\d+)% packet loss/);
        if (lossMatch) packetLoss = parseInt(lossMatch[1]);
      }

      if (rttLine) {
        const rttMatch = rttLine.match(/= (\d+\.?\d*)\/(\d+\.?\d*)\/(\d+\.?\d*)/);
        if (rttMatch) {
          minLatency = parseFloat(rttMatch[1]);
          avgLatency = parseFloat(rttMatch[2]);
          maxLatency = parseFloat(rttMatch[3]);
        }
      }

      // Store results in database
      await pool.query(
        'INSERT INTO ping_results (target_host, packet_loss, min_latency, max_latency, avg_latency) VALUES ($1, $2, $3, $4, $5)',
        [target, packetLoss, minLatency, maxLatency, avgLatency]
      );

      res.json({
        target,
        packetLoss,
        minLatency,
        maxLatency,
        avgLatency,
        rawOutput: stdout
      });

    } catch (pingError) {
      res.status(500).json({ error: 'Ping command failed', details: pingError.message });
    }

  } catch (error) {
    console.error('Ping error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DNS Lookup
app.post('/api/dns-lookup', async (req, res) => {
  try {
    const { domain, recordType = 'A' } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    await logToolUsage('dns-lookup', { domain, recordType, ip: req.ip });

    let records = [];
    
    switch (recordType.toUpperCase()) {
      case 'A':
        records = await dns.resolve4(domain);
        break;
      case 'AAAA':
        records = await dns.resolve6(domain);
        break;
      case 'MX':
        records = await dns.resolveMx(domain);
        break;
      case 'TXT':
        records = await dns.resolveTxt(domain);
        break;
      case 'NS':
        records = await dns.resolveNs(domain);
        break;
      default:
        return res.status(400).json({ error: 'Unsupported record type' });
    }

    res.json({
      domain,
      recordType,
      records,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('DNS lookup error:', error);
    res.status(500).json({ error: 'DNS lookup failed', details: error.message });
  }
});

// WHOIS Lookup
app.post('/api/whois', async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    await logToolUsage('whois', { domain, ip: req.ip });

    const { stdout } = await execAsync(`whois ${domain}`);
    
    // Parse WHOIS output
    const lines = stdout.split('\n');
    const parsed = {};
    
    lines.forEach(line => {
      if (line.includes(':')) {
        const [key, ...valueParts] = line.split(':');
        const value = valueParts.join(':').trim();
        if (key && value) {
          parsed[key.trim()] = value;
        }
      }
    });

    res.json({
      domain,
      rawOutput: stdout,
      parsed,
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

    await logToolUsage('hash', { algorithm, textLength: text.length, ip: req.ip });

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

// Base64 Encoder/Decoder
app.post('/api/base64', async (req, res) => {
  try {
    const { text, action = 'encode' } = req.body;
    
    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }

    await logToolUsage('base64', { action, textLength: text.length, ip: req.ip });

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

    await logToolUsage('json-format', { action, jsonLength: json.length, ip: req.ip });

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

    await logToolUsage('password-check', { passwordLength: password.length, ip: req.ip });

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

// System Info (basic)
app.get('/api/system-info', async (req, res) => {
  try {
    await logToolUsage('system-info', { ip: req.ip });

    const systemInfo = {
      platform: process.platform,
      nodeVersion: process.version,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString()
    };

    res.json(systemInfo);

  } catch (error) {
    console.error('System info error:', error);
    res.status(500).json({ error: 'Failed to get system info' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
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
