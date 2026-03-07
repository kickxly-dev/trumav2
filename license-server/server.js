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

// Middleware
app.use(cors());
app.use(express.json());

// Secret key - must match all TRAUMA tools
const SECRET_KEY = 'TRUMA-OSINT-SECRET-2024-SECURE-KEY-DO-NOT-SHARE';

// Data paths
const DATA_DIR = path.join(__dirname, 'data');
const LICENSES_FILE = path.join(DATA_DIR, 'licenses.json');
const ANALYTICS_FILE = path.join(DATA_DIR, 'analytics.json');
const API_KEYS_FILE = path.join(DATA_DIR, 'api_keys.json');
const REFERRALS_FILE = path.join(DATA_DIR, 'referrals.json');

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
    } catch (e) {
        console.error(`Error loading ${file}:`, e.message);
    }
    return defaultData;
}

function saveData(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
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
    
    const licenses = loadData(LICENSES_FILE, { licenses: [] });
    licenses.licenses.push(license);
    saveData(LICENSES_FILE, licenses);
    
    logAnalytics('license_generated', { key: license.key, user, expiryDays, createdBy: req.apiKey.name });
    
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
    
    logAnalytics('license_revoked', { key, user: license.user, reason, revokedBy: req.apiKey.name });
    
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
    
    res.json({ success: true, apiKey });
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
