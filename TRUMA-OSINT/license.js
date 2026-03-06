#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Get correct directory for both dev and pkg EXE
const APP_DIR = process.pkg ? path.dirname(process.execPath) : __dirname;

// License configuration
const LICENSES_DIR = path.join(APP_DIR, 'licenses');
const LICENSE_FILE = path.join(APP_DIR, 'license.key');
const SECRET_KEY = 'TRUMA-OSINT-SECRET-2024-SECURE-KEY-DO-NOT-SHARE';

// Ensure licenses directory exists
if (!fs.existsSync(LICENSES_DIR)) {
  fs.mkdirSync(LICENSES_DIR, { recursive: true });
}

function generateLicenseKey(userInfo = 'User', expiryDays = 365) {
  const timestamp = Date.now();
  const expiry = timestamp + (expiryDays * 24 * 60 * 60 * 1000);
  const payload = `${userInfo}|${timestamp}|${expiry}`;
  
  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(payload)
    .digest('hex')
    .substring(0, 32)
    .toUpperCase();
  
  const key = `TRUMA-${signature.substring(0, 4)}-${signature.substring(4, 8)}-${signature.substring(8, 12)}-${signature.substring(12, 16)}-${signature.substring(16, 20)}-${signature.substring(20, 24)}`;
  
  return {
    key,
    payload,
    created: new Date(timestamp).toISOString(),
    expires: new Date(expiry).toISOString(),
    user: userInfo
  };
}

function verifyLicenseKey(key) {
  if (!key || typeof key !== 'string') return { valid: false, error: 'No key provided' };
  
  const parts = key.split('-');
  if (parts.length !== 7 || parts[0] !== 'TRUMA') {
    return { valid: false, error: 'Invalid key format' };
  }
  
  const signature = parts.slice(1).join('');
  if (signature.length !== 24) {
    return { valid: false, error: 'Invalid signature length' };
  }
  
  // Check if license file exists with stored payload
  if (fs.existsSync(LICENSE_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(LICENSE_FILE, 'utf8'));
      const expectedSig = crypto
        .createHmac('sha256', SECRET_KEY)
        .update(data.payload)
        .digest('hex')
        .substring(0, 32)
        .toUpperCase();
      
      if (signature === expectedSig.substring(0, 24)) {
        const expiry = new Date(data.expires);
        if (expiry < new Date()) {
          return { valid: false, error: 'License expired', expired: true };
        }
        return { 
          valid: true, 
          user: data.user,
          expires: data.expires,
          created: data.created
        };
      }
    } catch (e) {}
  }
  
  // For newly entered keys, verify format only (full verification needs payload)
  if (/^[A-Z0-9]{4}$/.test(parts[1]) && 
      /^[A-Z0-9]{4}$/.test(parts[2]) &&
      /^[A-Z0-9]{4}$/.test(parts[3]) &&
      /^[A-Z0-9]{4}$/.test(parts[4]) &&
      /^[A-Z0-9]{4}$/.test(parts[5]) &&
      /^[A-Z0-9]{4}$/.test(parts[6])) {
    return { valid: true, provisional: true };
  }
  
  return { valid: false, error: 'Invalid key signature' };
}

function saveLicense(key, payload) {
  fs.writeFileSync(LICENSE_FILE, JSON.stringify({ key, payload, verified: Date.now() }, null, 2));
}

function activateLicense(key) {
  const result = verifyLicenseKey(key);
  if (result.valid && result.provisional) {
    // Create new payload for new activation
    const timestamp = Date.now();
    const expiry = timestamp + (365 * 24 * 60 * 60 * 1000);
    const payload = `Activated|${timestamp}|${expiry}`;
    saveLicense(key, { key, payload, created: new Date(timestamp).toISOString(), expires: new Date(expiry).toISOString(), user: 'Activated' });
    return { success: true, message: 'License activated successfully' };
  }
  return { success: false, error: result.error };
}

function checkLicense() {
  if (!fs.existsSync(LICENSE_FILE)) {
    return { valid: false, error: 'No license file found' };
  }
  
  try {
    const data = JSON.parse(fs.readFileSync(LICENSE_FILE, 'utf8'));
    return verifyLicenseKey(data.key);
  } catch (e) {
    return { valid: false, error: 'Corrupted license file' };
  }
}

// CLI Interface for key generation (owner only)
if (process.argv.includes('--generate')) {
  const user = process.argv[process.argv.indexOf('--generate') + 1] || 'User';
  const days = parseInt(process.argv[process.argv.indexOf('--days') + 1]) || 365;
  
  const license = generateLicenseKey(user, days);
  
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║              TRUMA OSINT LICENSE GENERATOR                 ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║                                                            ║');
  console.log(`║  User: ${user.padEnd(50)}║`);
  console.log(`║  Created: ${license.created.substring(0, 19).padEnd(47)}║`);
  console.log(`║  Expires: ${license.expires.substring(0, 19).padEnd(47)}║`);
  console.log('║                                                            ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  LICENSE KEY:                                              ║');
  console.log(`║  ${license.key.padEnd(55)}║`);
  console.log('║                                                            ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');
  
  // Save to licenses directory
  const licensesDir = path.join(__dirname, 'licenses');
  if (!fs.existsSync(licensesDir)) fs.mkdirSync(licensesDir, { recursive: true });
  fs.writeFileSync(path.join(licensesDir, `${user}_${Date.now()}.json`), JSON.stringify(license, null, 2));
  
  process.exit(0);
}

module.exports = {
  generateLicenseKey,
  verifyLicenseKey,
  checkLicense,
  activateLicense,
  saveLicense
};
