/**
 * TRAUMA License Server
 * Remote license validation API
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.LICENSE_PORT || 3001;

// Config
const WEBHOOK_URL = process.env.WEBHOOK_URL; // Discord/Slack webhook for notifications

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // Serve static files

// Secret key - must match all TRAUMA tools
const SECRET_KEY = 'TRUMA-OSINT-SECRET-2024-SECURE-KEY-DO-NOT-SHARE';

// Data paths
const DATA_DIR = path.join(__dirname, 'data');
const LICENSES_FILE = path.join(DATA_DIR, 'licenses.json');
const ANALYTICS_FILE = path.join(DATA_DIR, 'analytics.json');
const API_KEYS_FILE = path.join(DATA_DIR, 'api_keys.json');
const REFERRALS_FILE = path.join(DATA_DIR, 'referrals.json');
const AUDIT_LOG_FILE = path.join(DATA_DIR, 'audit_logs.json');
const LICENSE_POOLS_FILE = path.join(DATA_DIR, 'license_pools.json');

// TRUMA-OSINT licenses directory (for CLI tool compatibility)
const OSINT_LICENSES_DIR = path.join(__dirname, '..', 'TRUMA-OSINT', 'licenses');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Helper functions
function loadData(file, defaultData = {}) {
    try {
        if (fs.existsSync(file)) {
            return JSON.parse(fs.readFileSync(file, 'utf8'));
        }
    } catch (e) {}
    return { ...defaultData };
}

function saveData(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// Audit logging
function logAudit(action, details) {
    const audit = loadData(AUDIT_LOG_FILE, { logs: [] });
    audit.logs.push({
        action,
        details,
        timestamp: new Date().toISOString(),
        actor: details.actor || 'system',
        ip: details.ip || 'unknown'
    });
    // Keep last 1000 logs
    if (audit.logs.length > 1000) {
        audit.logs = audit.logs.slice(-1000);
    }
    saveData(AUDIT_LOG_FILE, audit);
}

function generateSignature(user, timestamp, expiry) {
    const payload = `${user}|${timestamp}|${expiry}`;
    return crypto
        .createHmac('sha256', SECRET_KEY)
        .update(payload)
        .digest('hex')
        .substring(0, 32)
        .toUpperCase();
}

function generateLicenseKey(user, expiryDays = 365) {
    const timestamp = Date.now();
    const expiry = timestamp + (expiryDays * 24 * 60 * 60 * 1000);
    const signature = generateSignature(user, timestamp, expiry);
    
    return {
        key: `TRUMA-${signature.substring(0, 4)}-${signature.substring(4, 8)}-${signature.substring(8, 12)}-${signature.substring(12, 16)}-${signature.substring(16, 20)}-${signature.substring(20, 24)}`,
        user,
        timestamp,
        expiry: new Date(expiry).toISOString(),
        created: new Date(timestamp).toISOString()
    };
}

function verifyLicenseFormat(key) {
    if (!key || typeof key !== 'string') return false;
    return /^TRUMA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i.test(key);
}

function getHardwareId(req) {
    return req.body.hardwareId || req.headers['x-hardware-id'] || null;
}

function logAnalytics(event, data) {
    const analytics = loadData(ANALYTICS_FILE, { events: [] });
    analytics.events.push({
        event,
        data,
        timestamp: new Date().toISOString(),
        ip: data.ip || 'unknown'
    });
    saveData(ANALYTICS_FILE, analytics);
    
    // Send webhook notification for important events
    sendWebhookNotification(event, data);
}

// Send webhook notifications (Discord/Slack)
async function sendWebhookNotification(event, data) {
    if (!WEBHOOK_URL) return;
    
    const importantEvents = [
        'license_generated',
        'license_revoked',
        'license_expired',
        'activation_success',
        'referral_used',
        'api_key_generated'
    ];
    
    if (!importantEvents.includes(event)) return;
    
    const colors = {
        license_generated: 0x00ff88,
        license_revoked: 0xff4444,
        license_expired: 0xffaa00,
        activation_success: 0x00ff88,
        referral_used: 0x0088ff,
        api_key_generated: 0x9932cc
    };
    
    const titles = {
        license_generated: '🎫 License Generated',
        license_revoked: '🚫 License Revoked',
        license_expired: '⏰ License Expired',
        activation_success: '✅ License Activated',
        referral_used: '🎁 Referral Used',
        api_key_generated: '🔑 API Key Generated'
    };
    
    const embed = {
        title: titles[event] || `📋 ${event}`,
        color: colors[event] || 0xdc143c,
        fields: [],
        timestamp: new Date().toISOString(),
        footer: { text: 'TRAUMA License System' }
    };
    
    if (data.user) embed.fields.push({ name: 'User', value: data.user, inline: true });
    if (data.key) embed.fields.push({ name: 'Key', value: `\`${data.key.substring(0, 19)}...\``, inline: true });
    if (data.reason) embed.fields.push({ name: 'Reason', value: data.reason, inline: false });
    if (data.bonusDays) embed.fields.push({ name: 'Bonus Days', value: `${data.bonusDays} days`, inline: true });
    if (data.createdBy) embed.fields.push({ name: 'By', value: data.createdBy, inline: true });
    
    try {
        const https = require('https');
        const http = require('http');
        const protocol = WEBHOOK_URL.startsWith('https') ? https : http;
        
        const postData = JSON.stringify({ embeds: [embed] });
        
        const url = new URL(WEBHOOK_URL);
        const options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname + url.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        
        const req = protocol.request(options, (res) => {
            // Webhook sent successfully
        });
        
        req.on('error', (e) => {
            console.log('Webhook error:', e.message);
        });
        
        req.write(postData);
        req.end();
    } catch (e) {
        console.log('Webhook error:', e.message);
    }
}

// API Key middleware for protected routes
function requireApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    const apiKeys = loadData(API_KEYS_FILE, { keys: [] });
    
    const keyData = apiKeys.keys.find(k => k.key === apiKey && k.active);
    if (!keyData) {
        return res.status(401).json({ error: 'Invalid or missing API key' });
    }
    
    req.apiKey = keyData;
    next();
}

// ============================================================================
// PUBLIC ENDPOINTS
// ============================================================================

// Validate license
app.post('/api/license/validate', (req, res) => {
    const { key, tool, version } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    
    if (!key) {
        return res.status(400).json({ valid: false, error: 'License key required' });
    }
    
    if (!verifyLicenseFormat(key)) {
        logAnalytics('validation_failed', { key, reason: 'invalid_format', ip, tool });
        return res.status(400).json({ valid: false, error: 'Invalid license format' });
    }
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const license = licenses.licenses.find(l => l.key.toUpperCase() === key.toUpperCase());
    
    if (!license) {
        logAnalytics('validation_failed', { key, reason: 'not_found', ip, tool });
        return res.status(404).json({ valid: false, error: 'License not found' });
    }
    
    // Check if revoked
    if (license.revoked) {
        logAnalytics('validation_failed', { key, reason: 'revoked', ip, tool });
        return res.status(403).json({ valid: false, error: 'License revoked' });
    }
    
    // Check expiry
    if (new Date(license.expiry) < new Date()) {
        logAnalytics('validation_failed', { key, reason: 'expired', ip, tool });
        return res.status(403).json({ valid: false, error: 'License expired', expiry: license.expiry });
    }
    
    // Check hardware binding
    const hardwareId = getHardwareId(req);
    if (license.hardwareId && hardwareId && license.hardwareId !== hardwareId) {
        logAnalytics('validation_failed', { key, reason: 'hardware_mismatch', ip, tool });
        return res.status(403).json({ valid: false, error: 'License bound to different machine' });
    }
    
    // Update last validation
    license.lastValidation = new Date().toISOString();
    license.validationCount = (license.validationCount || 0) + 1;
    saveData(LICENSES_FILE, licenses);
    
    logAnalytics('validation_success', { key, user: license.user, ip, tool, version });
    
    res.json({
        valid: true,
        user: license.user,
        expires: license.expiry,
        daysRemaining: Math.ceil((new Date(license.expiry) - new Date()) / (1000 * 60 * 60 * 24)),
        features: license.features || ['all']
    });
});

// Activate license
app.post('/api/license/activate', (req, res) => {
    const { key, hardwareId, tool } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    
    if (!key) {
        return res.status(400).json({ success: false, error: 'License key required' });
    }
    
    if (!verifyLicenseFormat(key)) {
        return res.status(400).json({ success: false, error: 'Invalid license format' });
    }
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const license = licenses.licenses.find(l => l.key.toUpperCase() === key.toUpperCase());
    
    if (!license) {
        logAnalytics('activation_failed', { key, reason: 'not_found', ip, tool });
        return res.status(404).json({ success: false, error: 'License not found' });
    }
    
    if (license.revoked) {
        return res.status(403).json({ success: false, error: 'License revoked' });
    }
    
    // Check if already activated with different hardware
    if (license.hardwareId && hardwareId && license.hardwareId !== hardwareId) {
        logAnalytics('activation_failed', { key, reason: 'hardware_bound', ip, tool });
        return res.status(403).json({ 
            success: false, 
            error: 'License already activated on different machine',
            activatedOn: license.activatedOn
        });
    }
    
    // Bind hardware ID
    if (hardwareId && !license.hardwareId) {
        license.hardwareId = hardwareId;
        license.activatedOn = new Date().toISOString();
    }
    
    license.lastActivation = new Date().toISOString();
    license.activationCount = (license.activationCount || 0) + 1;
    saveData(LICENSES_FILE, licenses);
    
    // Also write to TRUMA-OSINT license.key file for CLI manager
    try {
        const OSINT_LICENSE_FILE = path.join(__dirname, '..', 'TRUMA-OSINT', 'license.key');
        const activeData = {
            key: license.key,
            user: license.user,
            created: license.created,
            expires: license.expiry,
            activated: new Date().toISOString(),
            hardwareId: hardwareId || null
        };
        fs.writeFileSync(OSINT_LICENSE_FILE, JSON.stringify(activeData, null, 2));
    } catch (e) {
        console.log('Warning: Could not sync to OSINT license.key:', e.message);
    }
    
    logAnalytics('activation_success', { key, user: license.user, ip, tool, hardwareId });
    
    res.json({
        success: true,
        message: 'License activated',
        user: license.user,
        expires: license.expiry,
        daysRemaining: Math.ceil((new Date(license.expiry) - new Date()) / (1000 * 60 * 60 * 24))
    });
});

// Deactivate license
app.post('/api/license/deactivate', (req, res) => {
    const { key, hardwareId } = req.body;
    
    if (!key) {
        return res.status(400).json({ success: false, error: 'License key required' });
    }
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const license = licenses.licenses.find(l => l.key.toUpperCase() === key.toUpperCase());
    
    if (!license) {
        return res.status(404).json({ success: false, error: 'License not found' });
    }
    
    // Only allow deactivation from same hardware
    if (license.hardwareId && hardwareId && license.hardwareId !== hardwareId) {
        return res.status(403).json({ success: false, error: 'Can only deactivate from registered machine' });
    }
    
    license.hardwareId = null;
    license.deactivatedOn = new Date().toISOString();
    saveData(LICENSES_FILE, licenses);
    
    logAnalytics('deactivation', { key, user: license.user });
    
    res.json({ success: true, message: 'License deactivated' });
});

// Check expiry warning
app.get('/api/license/warning/:key', (req, res) => {
    const { key } = req.params;
    
    if (!verifyLicenseFormat(key)) {
        return res.status(400).json({ error: 'Invalid license format' });
    }
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const license = licenses.licenses.find(l => l.key.toUpperCase() === key.toUpperCase());
    
    if (!license) {
        return res.status(404).json({ error: 'License not found' });
    }
    
    const daysRemaining = Math.ceil((new Date(license.expiry) - new Date()) / (1000 * 60 * 60 * 24));
    
    res.json({
        key: license.key,
        user: license.user,
        expires: license.expiry,
        daysRemaining,
        warning: daysRemaining <= 30,
        critical: daysRemaining <= 7
    });
});

// ============================================================================
// PROTECTED ENDPOINTS (require API key)
// ============================================================================

// Generate new license
app.post('/api/admin/license/generate', requireApiKey, (req, res) => {
    const { user, expiryDays = 365, features = ['all'], referralCode } = req.body;
    
    if (!user) {
        return res.status(400).json({ error: 'Username required' });
    }
    
    const licenseData = generateLicenseKey(user, expiryDays);
    
    const license = {
        ...licenseData,
        features,
        referralCode: referralCode || null,
        createdBy: req.apiKey.name,
        createdAt: new Date().toISOString(),
        validationCount: 0,
        activationCount: 0
    };
    
    // Save to license server database
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    licenses.licenses.push(license);
    saveData(LICENSES_FILE, licenses);
    
    // Also save to TRUMA-OSINT licenses folder for CLI compatibility
    try {
        if (!fs.existsSync(OSINT_LICENSES_DIR)) {
            fs.mkdirSync(OSINT_LICENSES_DIR, { recursive: true });
        }
        // Sanitize username for filename (remove special chars like <@...>)
        const safeName = user.replace(/[<>@#$/\\:*?"|]/g, '').substring(0, 30) || 'user';
        const osintLicenseFile = path.join(OSINT_LICENSES_DIR, `${safeName}_${license.timestamp}.json`);
        fs.writeFileSync(osintLicenseFile, JSON.stringify(license, null, 2));
    } catch (e) {
        console.log('Warning: Could not sync to OSINT licenses folder:', e.message);
    }
    
    logAnalytics('license_generated', { key: license.key, user, expiryDays, createdBy: req.apiKey.name });
    
    // Audit log
    logAudit('LICENSE_GENERATED', {
        actor: req.apiKey.name,
        key: license.key,
        user,
        expiryDays,
        ip: req.ip
    });
    
    res.json({ success: true, license });
});

// Revoke license
app.post('/api/admin/license/revoke', requireApiKey, (req, res) => {
    const { key, reason } = req.body;
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const license = licenses.licenses.find(l => l.key.toUpperCase() === key?.toUpperCase());
    
    if (!license) {
        return res.status(404).json({ error: 'License not found' });
    }
    
    license.revoked = true;
    license.revokedAt = new Date().toISOString();
    license.revokedBy = req.apiKey.name;
    license.revokedReason = reason || 'No reason provided';
    
    saveData(LICENSES_FILE, licenses);
    
    // Also delete from TRUMA-OSINT licenses folder
    try {
        if (fs.existsSync(OSINT_LICENSES_DIR)) {
            const files = fs.readdirSync(OSINT_LICENSES_DIR).filter(f => f.endsWith('.json'));
            for (const file of files) {
                const filePath = path.join(OSINT_LICENSES_DIR, file);
                try {
                    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                    if (data.key && data.key.toUpperCase() === key.toUpperCase()) {
                        fs.unlinkSync(filePath);
                        break;
                    }
                } catch (e) {}
            }
        }
    } catch (e) {
        console.log('Warning: Could not delete from OSINT licenses folder:', e.message);
    }
    
    logAnalytics('license_revoked', { key, user: license.user, reason, revokedBy: req.apiKey.name });
    
    // Audit log
    logAudit('LICENSE_REVOKED', {
        actor: req.apiKey.name,
        key,
        user: license.user,
        reason,
        ip: req.ip
    });
    
    res.json({ success: true, message: 'License revoked' });
});

// List all licenses
app.get('/api/admin/licenses', requireApiKey, (req, res) => {
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    res.json(licenses);
});

// Generate API key
app.post('/api/admin/apikey/generate', requireApiKey, (req, res) => {
    const { name, permissions = ['read'] } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Name required' });
    }
    
    const apiKey = {
        key: crypto.randomBytes(32).toString('hex'),
        name,
        permissions,
        active: true,
        createdAt: new Date().toISOString(),
        createdBy: req.apiKey.name
    };
    
    const apiKeys = loadData(API_KEYS_FILE, { keys: [] });
    apiKeys.keys.push(apiKey);
    saveData(API_KEYS_FILE, apiKeys);
    
    logAnalytics('api_key_generated', { name, permissions });
    
    logAudit('API_KEY_GENERATED', {
        actor: req.apiKey.name,
        keyName: name,
        permissions,
        ip: req.ip
    });
    
    res.json({ success: true, apiKey });
});

// ============================================================================
// AUDIT LOGS
// ============================================================================

// Get audit logs
app.get('/api/admin/audit', requireApiKey, (req, res) => {
    const audit = loadData(AUDIT_LOG_FILE, { logs: [] });
    const limit = parseInt(req.query.limit) || 100;
    const logs = audit.logs.slice(-limit);
    res.json({ logs, total: audit.logs.length });
});

// ============================================================================
// LICENSE POOLS
// ============================================================================

// Create a license pool (batch of keys)
app.post('/api/admin/pool/create', requireApiKey, (req, res) => {
    const { name, count = 10, expiryDays = 365, features = ['all'] } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Pool name required' });
    }
    
    if (count < 1 || count > 100) {
        return res.status(400).json({ error: 'Count must be between 1 and 100' });
    }
    
    const pools = loadData(LICENSE_POOLS_FILE, { pools: [] });
    
    const pool = {
        id: crypto.randomBytes(8).toString('hex'),
        name,
        keys: [],
        total: count,
        claimed: 0,
        features,
        expiryDays,
        createdAt: new Date().toISOString(),
        createdBy: req.apiKey.name
    };
    
    // Generate keys for the pool
    for (let i = 0; i < count; i++) {
        const licenseData = generateLicenseKey(`pool-${pool.id}-${i}`, expiryDays);
        const license = {
            ...licenseData,
            features,
            poolId: pool.id,
            claimed: false,
            claimedBy: null,
            claimedAt: null
        };
        
        pool.keys.push(license);
        
        // Also add to main licenses
        const licenses = loadData(LICENSES_FILE, { licenses: [] });
        licenses.licenses.push(license);
        saveData(LICENSES_FILE, licenses);
    }
    
    pools.pools.push(pool);
    saveData(LICENSE_POOLS_FILE, pools);
    
    logAudit('POOL_CREATED', {
        actor: req.apiKey.name,
        poolId: pool.id,
        poolName: name,
        keyCount: count,
        ip: req.ip
    });
    
    res.json({ 
        success: true, 
        pool: {
            id: pool.id,
            name: pool.name,
            total: pool.total,
            keys: pool.keys.map(k => k.key) // Return just the keys
        }
    });
});

// List all pools
app.get('/api/admin/pools', requireApiKey, (req, res) => {
    const pools = loadData(LICENSE_POOLS_FILE, { pools: [] });
    res.json({ 
        pools: pools.pools.map(p => ({
            id: p.id,
            name: p.name,
            total: p.total,
            claimed: p.claimed,
            remaining: p.total - p.claimed,
            createdAt: p.createdAt,
            createdBy: p.createdBy
        }))
    });
});

// Get pool details
app.get('/api/admin/pool/:id', requireApiKey, (req, res) => {
    const pools = loadData(LICENSE_POOLS_FILE, { pools: [] });
    const pool = pools.pools.find(p => p.id === req.params.id);
    
    if (!pool) {
        return res.status(404).json({ error: 'Pool not found' });
    }
    
    res.json({ pool });
});

// Claim a key from pool (public endpoint with pool ID)
app.post('/api/pool/claim', (req, res) => {
    const { poolId, user } = req.body;
    
    if (!poolId || !user) {
        return res.status(400).json({ error: 'Pool ID and username required' });
    }
    
    const pools = loadData(LICENSE_POOLS_FILE, { pools: [] });
    const pool = pools.pools.find(p => p.id === poolId);
    
    if (!pool) {
        return res.status(404).json({ error: 'Pool not found' });
    }
    
    // Find an unclaimed key
    const unclaimedKey = pool.keys.find(k => !k.claimed);
    
    if (!unclaimedKey) {
        return res.status(400).json({ error: 'No keys remaining in pool' });
    }
    
    // Claim the key
    unclaimedKey.claimed = true;
    unclaimedKey.claimedBy = user;
    unclaimedKey.claimedAt = new Date().toISOString();
    unclaimedKey.user = user;
    pool.claimed++;
    
    saveData(LICENSE_POOLS_FILE, pools);
    
    // Update main licenses too
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const license = licenses.licenses.find(l => l.key === unclaimedKey.key);
    if (license) {
        license.user = user;
        license.claimed = true;
        license.claimedBy = user;
        license.claimedAt = unclaimedKey.claimedAt;
        saveData(LICENSES_FILE, licenses);
    }
    
    logAudit('POOL_KEY_CLAIMED', {
        actor: user,
        poolId,
        key: unclaimedKey.key,
        ip: req.ip
    });
    
    res.json({ 
        success: true, 
        license: {
            key: unclaimedKey.key,
            user,
            expires: unclaimedKey.expiry,
            features: unclaimedKey.features
        }
    });
});

// Delete a pool
app.delete('/api/admin/pool/:id', requireApiKey, (req, res) => {
    const pools = loadData(LICENSE_POOLS_FILE, { pools: [] });
    const poolIndex = pools.pools.findIndex(p => p.id === req.params.id);
    
    if (poolIndex === -1) {
        return res.status(404).json({ error: 'Pool not found' });
    }
    
    const pool = pools.pools[poolIndex];
    
    // Remove pool
    pools.pools.splice(poolIndex, 1);
    saveData(LICENSE_POOLS_FILE, pools);
    
    logAudit('POOL_DELETED', {
        actor: req.apiKey.name,
        poolId: pool.id,
        poolName: pool.name,
        ip: req.ip
    });
    
    res.json({ success: true, message: 'Pool deleted' });
});

// Get analytics
app.get('/api/admin/analytics', requireApiKey, (req, res) => {
    const analytics = loadData(ANALYTICS_FILE, { events: [] });
    
    // Summary stats
    const stats = {
        totalEvents: analytics.events.length,
        validations: analytics.events.filter(e => e.event === 'validation_success').length,
        activations: analytics.events.filter(e => e.event === 'activation_success').length,
        failedValidations: analytics.events.filter(e => e.event === 'validation_failed').length,
        licensesGenerated: analytics.events.filter(e => e.event === 'license_generated').length
    };
    
    res.json({ stats, events: analytics.events.slice(-100) });
});

// Send announcement to Discord channel
app.post('/api/admin/announcement', requireApiKey, async (req, res) => {
    const { channelId, title, message, color = '#dc143c' } = req.body;
    
    if (!channelId || !title || !message) {
        return res.status(400).json({ error: 'Channel ID, title, and message required' });
    }
    
    try {
        // Get Discord client
        const client = require('./discord-bot');
        
        const channel = await client.channels.fetch(channelId);
        if (!channel) {
            return res.status(404).json({ error: 'Channel not found' });
        }
        
        const { EmbedBuilder } = require('discord.js');
        const colorInt = parseInt(color.replace('#', ''), 16);
        
        const embed = new EmbedBuilder()
            .setColor(colorInt)
            .setTitle(title)
            .setDescription(message)
            .setFooter({ text: 'TRAUMA License System' })
            .setTimestamp();
        
        await channel.send({ embeds: [embed] });
        
        logAudit('ANNOUNCEMENT_SENT', {
            actor: req.apiKey.name,
            channelId,
            title,
            ip: req.ip
        });
        
        res.json({ success: true, message: 'Announcement sent' });
    } catch (e) {
        res.status(500).json({ error: 'Failed to send announcement: ' + e.message });
    }
});

// ============================================================================
// BULK OPERATIONS
// ============================================================================

// Bulk generate licenses
app.post('/api/admin/bulk/generate', requireApiKey, (req, res) => {
    const { users, expiryDays = 365, features = ['all'] } = req.body;
    
    if (!users || !Array.isArray(users) || users.length === 0) {
        return res.status(400).json({ error: 'Users array required' });
    }
    
    if (users.length > 100) {
        return res.status(400).json({ error: 'Maximum 100 users at once' });
    }
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const generated = [];
    const failed = [];
    
    for (const user of users) {
        try {
            const licenseData = generateLicenseKey(user, expiryDays);
            const license = {
                ...licenseData,
                features,
                createdBy: req.apiKey.name,
                createdAt: new Date().toISOString(),
                validationCount: 0,
                activationCount: 0
            };
            
            licenses.licenses.push(license);
            generated.push({ user, key: license.key });
        } catch (e) {
            failed.push({ user, error: e.message });
        }
    }
    
    saveData(LICENSES_FILE, licenses);
    
    logAudit('BULK_GENERATE', {
        actor: req.apiKey.name,
        count: generated.length,
        failed: failed.length,
        ip: req.ip
    });
    
    res.json({ 
        success: true, 
        generated: generated.length,
        failed: failed.length,
        licenses: generated,
        errors: failed
    });
});

// Bulk revoke licenses
app.post('/api/admin/bulk/revoke', requireApiKey, (req, res) => {
    const { keys, reason = 'Bulk revocation' } = req.body;
    
    if (!keys || !Array.isArray(keys) || keys.length === 0) {
        return res.status(400).json({ error: 'Keys array required' });
    }
    
    if (keys.length > 100) {
        return res.status(400).json({ error: 'Maximum 100 keys at once' });
    }
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const revoked = [];
    const notFound = [];
    
    for (const key of keys) {
        const license = licenses.licenses.find(l => l.key.toUpperCase() === key?.toUpperCase());
        
        if (license) {
            if (!license.revoked) {
                license.revoked = true;
                license.revokedAt = new Date().toISOString();
                license.revokedBy = req.apiKey.name;
                license.revokedReason = reason;
                revoked.push({ key: license.key, user: license.user });
            }
        } else {
            notFound.push(key);
        }
    }
    
    saveData(LICENSES_FILE, licenses);
    
    logAudit('BULK_REVOKE', {
        actor: req.apiKey.name,
        count: revoked.length,
        reason,
        ip: req.ip
    });
    
    res.json({ 
        success: true, 
        revoked: revoked.length,
        notFound: notFound.length,
        licenses: revoked,
        missing: notFound
    });
});

// Bulk extend licenses
app.post('/api/admin/bulk/extend', requireApiKey, (req, res) => {
    const { keys, additionalDays = 30 } = req.body;
    
    if (!keys || !Array.isArray(keys) || keys.length === 0) {
        return res.status(400).json({ error: 'Keys array required' });
    }
    
    if (keys.length > 100) {
        return res.status(400).json({ error: 'Maximum 100 keys at once' });
    }
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const extended = [];
    const notFound = [];
    const alreadyRevoked = [];
    
    for (const key of keys) {
        const license = licenses.licenses.find(l => l.key.toUpperCase() === key?.toUpperCase());
        
        if (license) {
            if (license.revoked) {
                alreadyRevoked.push({ key: license.key, user: license.user });
            } else {
                const currentExpiry = new Date(license.expiry);
                const newExpiry = new Date(currentExpiry.getTime() + (additionalDays * 24 * 60 * 60 * 1000));
                license.expiry = newExpiry.toISOString();
                license.extendedAt = new Date().toISOString();
                license.extendedBy = req.apiKey.name;
                license.extensionDays = (license.extensionDays || 0) + additionalDays;
                extended.push({ 
                    key: license.key, 
                    user: license.user,
                    newExpiry: license.expiry
                });
            }
        } else {
            notFound.push(key);
        }
    }
    
    saveData(LICENSES_FILE, licenses);
    
    logAudit('BULK_EXTEND', {
        actor: req.apiKey.name,
        count: extended.length,
        additionalDays,
        ip: req.ip
    });
    
    res.json({ 
        success: true, 
        extended: extended.length,
        notFound: notFound.length,
        revoked: alreadyRevoked.length,
        licenses: extended,
        missing: notFound,
        skipped: alreadyRevoked
    });
});

// Bulk extend all expiring licenses
app.post('/api/admin/bulk/extend-expiring', requireApiKey, (req, res) => {
    const { days = 7, additionalDays = 30 } = req.body;
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const extended = [];
    
    for (const license of licenses.licenses) {
        if (license.revoked) continue;
        
        const daysUntilExpiry = Math.ceil((new Date(license.expiry) - new Date()) / (1000 * 60 * 60 * 24));
        
        if (daysUntilExpiry <= days && daysUntilExpiry > 0) {
            const currentExpiry = new Date(license.expiry);
            const newExpiry = new Date(currentExpiry.getTime() + (additionalDays * 24 * 60 * 60 * 1000));
            license.expiry = newExpiry.toISOString();
            license.extendedAt = new Date().toISOString();
            license.extendedBy = req.apiKey.name;
            extended.push({ 
                key: license.key, 
                user: license.user,
                newExpiry: license.expiry
            });
        }
    }
    
    saveData(LICENSES_FILE, licenses);
    
    logAudit('BULK_EXTEND_EXPIRING', {
        actor: req.apiKey.name,
        count: extended.length,
        withinDays: days,
        additionalDays,
        ip: req.ip
    });
    
    res.json({ 
        success: true, 
        extended: extended.length,
        licenses: extended
    });
});

// Bulk delete revoked licenses
app.post('/api/admin/bulk/cleanup', requireApiKey, (req, res) => {
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const originalCount = licenses.licenses.length;
    
    licenses.licenses = licenses.licenses.filter(l => !l.revoked);
    const removedCount = originalCount - licenses.licenses.length;
    
    saveData(LICENSES_FILE, licenses);
    
    logAudit('BULK_CLEANUP', {
        actor: req.apiKey.name,
        removed: removedCount,
        ip: req.ip
    });
    
    res.json({ 
        success: true, 
        removed: removedCount,
        remaining: licenses.licenses.length
    });
});

// ============================================================================
// REFERRAL SYSTEM
// ============================================================================

// Generate referral code
app.post('/api/referral/create', requireApiKey, (req, res) => {
    const { name, bonusDays = 30 } = req.body;
    
    const referral = {
        code: crypto.randomBytes(6).toString('hex').toUpperCase(),
        name,
        bonusDays,
        uses: 0,
        maxUses: 100,
        active: true,
        createdAt: new Date().toISOString()
    };
    
    const referrals = loadData(REFERRALS_FILE, { referrals: [] });
    referrals.referrals.push(referral);
    saveData(REFERRALS_FILE, referrals);
    
    res.json({ success: true, referral });
});

// Use referral code
app.post('/api/referral/use', (req, res) => {
    const { referralCode, key } = req.body;
    
    const referrals = loadData(REFERRALS_FILE, { referrals: [] });
    const referral = referrals.referrals.find(r => r.code.toUpperCase() === referralCode?.toUpperCase());
    
    if (!referral) {
        return res.status(404).json({ error: 'Referral code not found' });
    }
    
    if (!referral.active) {
        return res.status(403).json({ error: 'Referral code inactive' });
    }
    
    if (referral.uses >= referral.maxUses) {
        return res.status(403).json({ error: 'Referral code exhausted' });
    }
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    const license = licenses.licenses.find(l => l.key.toUpperCase() === key?.toUpperCase());
    
    if (!license) {
        return res.status(404).json({ error: 'License not found' });
    }
    
    // Extend license
    const currentExpiry = new Date(license.expiry);
    const newExpiry = new Date(currentExpiry.getTime() + (referral.bonusDays * 24 * 60 * 60 * 1000));
    license.expiry = newExpiry.toISOString();
    
    referral.uses++;
    referral.usedBy = referral.usedBy || [];
    referral.usedBy.push({ key, usedAt: new Date().toISOString() });
    
    saveData(LICENSES_FILE, licenses);
    saveData(REFERRALS_FILE, referrals);
    
    logAnalytics('referral_used', { referralCode, key, bonusDays: referral.bonusDays });
    
    res.json({
        success: true,
        message: `License extended by ${referral.bonusDays} days`,
        newExpiry: license.expiry
    });
});

// ============================================================================
// DARK WEB MONITOR (simulated - would need real API integration)
// ============================================================================

app.post('/api/breach/check', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email required' });
    }
    
    // In production, integrate with HaveIBeenPwned API
    // For now, return mock data
    res.json({
        email,
        breaches: [],
        pastes: [],
        lastChecked: new Date().toISOString(),
        note: 'Integrate with HaveIBeenPwned API for real breach data'
    });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║  TRAUMA LICENSE SERVER                                      ║
║  Running on port ${PORT}                                       ║
╠════════════════════════════════════════════════════════════╣
║  Endpoints:                                                 ║
║  POST /api/license/validate   - Validate license            ║
║  POST /api/license/activate   - Activate license            ║
║  POST /api/license/deactivate - Deactivate license          ║
║  GET  /api/license/warning/:key - Check expiry warning      ║
║  POST /api/admin/license/generate - Generate license (auth) ║
║  POST /api/admin/license/revoke - Revoke license (auth)     ║
║  GET  /api/admin/licenses - List all licenses (auth)        ║
║  POST /api/admin/apikey/generate - Generate API key (auth)  ║
║  GET  /api/admin/analytics - Get analytics (auth)           ║
║  POST /api/referral/create - Create referral code (auth)    ║
║  POST /api/referral/use - Use referral code                 ║
║  POST /api/breach/check - Check email breaches              ║
╚════════════════════════════════════════════════════════════╝
    `);
    
    // Create initial admin API key if none exists
    const apiKeys = loadData(API_KEYS_FILE, { keys: [] });
    if (apiKeys.keys.length === 0) {
        const adminKey = {
            key: crypto.randomBytes(32).toString('hex'),
            name: 'admin',
            permissions: ['read', 'write', 'admin'],
            active: true,
            createdAt: new Date().toISOString()
        };
        apiKeys.keys.push(adminKey);
        saveData(API_KEYS_FILE, apiKeys);
        console.log(`\n⚠️  ADMIN API KEY: ${adminKey.key}\n   Save this key securely!\n`);
    }
});

module.exports = app;
