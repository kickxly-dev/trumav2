const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const fetch = require('node-fetch');
const { exec } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');
const path = require('path');
require('dotenv').config();

const execAsync = promisify(exec);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Database connection (PostgreSQL on Render)
const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Initialize database tables
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tool_usage (
        id SERIAL PRIMARY KEY,
        tool_name VARCHAR(100) NOT NULL,
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

    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Log tool usage
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
