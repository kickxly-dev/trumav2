/**
 * TRAUMA Unified License System
 * One license key works across all TRAUMA tools and websites
 * 
 * License Format: TRUMA-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
 */

const crypto = require('crypto');

// Shared secret key - SAME across all TRAUMA products
const TRAUMA_SECRET = 'TRUMA-OSINT-SECRET-2024-SECURE-KEY-DO-NOT-SHARE';

// License storage paths
const fs = require('fs');
const path = require('path');

function getLicenseDir() {
  // Works for both CLI and web
  const appDir = process.pkg ? path.dirname(process.execPath) : 
                 (typeof __dirname !== 'undefined' ? __dirname : process.cwd());
  return path.join(appDir, 'licenses');
}

function getLicenseFile() {
  const appDir = process.pkg ? path.dirname(process.execPath) : 
                 (typeof __dirname !== 'undefined' ? __dirname : process.cwd());
  return path.join(appDir, 'license.key');
}

/**
 * Generate a new TRAUMA license key
 */
function generateLicense(user = 'User', expiryDays = 365) {
  const timestamp = Date.now();
  const expiry = timestamp + (expiryDays * 24 * 60 * 60 * 1000);
  const payload = `${user}|${timestamp}|${expiry}`;
  
  const signature = crypto
    .createHmac('sha256', TRAUMA_SECRET)
    .update(payload)
    .digest('hex')
    .substring(0, 32)
    .toUpperCase();
  
  const key = `TRUMA-${signature.substring(0, 4)}-${signature.substring(4, 8)}-${signature.substring(8, 12)}-${signature.substring(12, 16)}-${signature.substring(16, 20)}-${signature.substring(20, 24)}`;
  
  const licenseData = {
    key,
    user,
    created: new Date(timestamp).toISOString(),
    expires: new Date(expiry).toISOString(),
    payload
  };
  
  // Save to licenses directory
  const licenseDir = getLicenseDir();
  if (!fs.existsSync(licenseDir)) fs.mkdirSync(licenseDir, { recursive: true });
  fs.writeFileSync(path.join(licenseDir, `${user}_${Date.now()}.json`), JSON.stringify(licenseData, null, 2));
  
  return licenseData;
}

/**
 * Verify a TRAUMA license key
 */
function verifyLicense(key) {
  if (!key || typeof key !== 'string') {
    return { valid: false, error: 'No license key provided' };
  }
  
  // Check format
  const parts = key.split('-');
  if (parts.length !== 7 || parts[0] !== 'TRUMA') {
    return { valid: false, error: 'Invalid license format' };
  }
  
  const signature = parts.slice(1).join('');
  if (signature.length !== 24 || !/^[A-Z0-9]+$/.test(signature)) {
    return { valid: false, error: 'Invalid license signature' };
  }
  
  // Check if license is stored/activated
  const licenseFile = getLicenseFile();
  if (fs.existsSync(licenseFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(licenseFile, 'utf8'));
      
      // Verify the stored key matches
      if (data.key === key) {
        // Check expiry
        const expiry = new Date(data.expires);
        if (expiry < new Date()) {
          return { valid: false, error: 'License expired', expired: true, expires: data.expires };
        }
        
        return {
          valid: true,
          user: data.user,
          expires: data.expires,
          created: data.created
        };
      }
    } catch (e) {
      // Continue to provisional check
    }
  }
  
  // Provisional valid (format correct, but not activated on this machine)
  return { valid: true, provisional: true, message: 'License format valid - activate to use' };
}

/**
 * Activate a license key on this machine
 */
function activateLicense(key) {
  const result = verifyLicense(key);
  
  if (!result.valid) {
    return { success: false, error: result.error };
  }
  
  // If already activated and matches
  if (!result.provisional) {
    return { success: true, message: 'License already activated', user: result.user };
  }
  
  // Activate new license
  const timestamp = Date.now();
  const expiry = timestamp + (365 * 24 * 60 * 60 * 1000); // 1 year from now
  
  const licenseData = {
    key,
    user: 'Licensed User',
    created: new Date(timestamp).toISOString(),
    expires: new Date(expiry).toISOString(),
    activated: timestamp
  };
  
  const licenseFile = getLicenseFile();
  fs.writeFileSync(licenseFile, JSON.stringify(licenseData, null, 2));
  
  return { 
    success: true, 
    message: 'License activated successfully',
    user: licenseData.user,
    expires: licenseData.expires
  };
}

/**
 * Check if current machine has active license
 */
function checkLicense() {
  const licenseFile = getLicenseFile();
  
  if (!fs.existsSync(licenseFile)) {
    return { valid: false, error: 'No license activated', needsActivation: true };
  }
  
  try {
    const data = JSON.parse(fs.readFileSync(licenseFile, 'utf8'));
    return verifyLicense(data.key);
  } catch (e) {
    return { valid: false, error: 'License file corrupted' };
  }
}

/**
 * Deactivate/remove license
 */
function deactivateLicense() {
  const licenseFile = getLicenseFile();
  if (fs.existsSync(licenseFile)) {
    fs.unlinkSync(licenseFile);
    return { success: true, message: 'License deactivated' };
  }
  return { success: false, error: 'No license to deactivate' };
}

/**
 * Get license info for display
 */
function getLicenseInfo() {
  const licenseFile = getLicenseFile();
  
  if (!fs.existsSync(licenseFile)) {
    return null;
  }
  
  try {
    return JSON.parse(fs.readFileSync(licenseFile, 'utf8'));
  } catch (e) {
    return null;
  }
}

// CLI interface for generating keys
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.includes('--generate') || args.includes('-g')) {
    const userIndex = args.indexOf('--user') !== -1 ? args.indexOf('--user') + 1 : 
                      args.indexOf('-u') !== -1 ? args.indexOf('-u') + 1 : -1;
    const daysIndex = args.indexOf('--days') !== -1 ? args.indexOf('--days') + 1 : 
                      args.indexOf('-d') !== -1 ? args.indexOf('-d') + 1 : -1;
    
    const user = userIndex !== -1 ? args[userIndex] : 'User';
    const days = daysIndex !== -1 ? parseInt(args[daysIndex]) : 365;
    
    const license = generateLicense(user, days);
    
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║           TRAUMA UNIFIED LICENSE GENERATOR                  ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║                                                            ║');
    console.log(`║  User: ${user.padEnd(50)}║`);
    console.log(`║  Created: ${license.created.substring(0, 19).padEnd(47)}║`);
    console.log(`║  Expires: ${license.expires.substring(0, 19).padEnd(47)}║`);
    console.log('║                                                            ║');
    console.log('╠════════════════════════════════════════════════════════════╣');
    console.log('║  LICENSE KEY (Works for ALL TRAUMA products):              ║');
    console.log(`║  ${license.key.padEnd(55)}║`);
    console.log('║                                                            ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');
    
    process.exit(0);
  }
  
  if (args.includes('--check') || args.includes('-c')) {
    const result = checkLicense();
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  }
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log('\nTRAUMA Unified License System');
    console.log('=============================\n');
    console.log('Commands:');
    console.log('  --generate, -g    Generate a new license key');
    console.log('  --user, -u        Username for license (with --generate)');
    console.log('  --days, -d        Expiry days (with --generate)');
    console.log('  --check, -c       Check if license is activated');
    console.log('  --help, -h        Show this help\n');
    process.exit(0);
  }
}

module.exports = {
  generateLicense,
  verifyLicense,
  activateLicense,
  checkLicense,
  deactivateLicense,
  getLicenseInfo,
  TRAUMA_SECRET
};
