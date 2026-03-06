#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const LICENSES_DIR = path.join(__dirname, 'licenses');
const LICENSE_FILE = path.join(__dirname, 'license.key');

const c = {
  r: '\x1b[31m', g: '\x1b[32m', y: '\x1b[33m', b: '\x1b[34m', m: '\x1b[35m', c: '\x1b[36m',
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m'
};

// Ensure licenses directory exists
if (!fs.existsSync(LICENSES_DIR)) {
  fs.mkdirSync(LICENSES_DIR, { recursive: true });
}

function getAllLicenses() {
  const licenses = [];
  const files = fs.readdirSync(LICENSES_DIR).filter(f => f.endsWith('.json'));
  
  for (const file of files) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(LICENSES_DIR, file), 'utf8'));
      data.filename = file;
      licenses.push(data);
    } catch (e) {}
  }
  
  return licenses.sort((a, b) => new Date(b.created) - new Date(a.created));
}

function getActiveLicense() {
  if (fs.existsSync(LICENSE_FILE)) {
    try {
      return JSON.parse(fs.readFileSync(LICENSE_FILE, 'utf8'));
    } catch (e) {}
  }
  return null;
}

function formatDate(dateStr) {
  const date = new Date(dateStr);
  return date.toISOString().substring(0, 19).replace('T', ' ');
}

function isExpired(expires) {
  return new Date(expires) < new Date();
}

function showLicenseList() {
  console.clear();
  
  console.log(`\n${c.r}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
  console.log(`${c.r}║  ${c.bold}${c.y}LICENSE MANAGEMENT - ALL LICENSES${c.reset}                                                                 ${c.r}║${c.reset}`);
  console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  
  const licenses = getAllLicenses();
  const active = getActiveLicense();
  
  if (licenses.length === 0) {
    console.log(`${c.r}║  ${c.dim}No licenses found. Generate one with generate-key.bat${c.reset}                              ${c.r}║${c.reset}`);
  } else {
    console.log(`${c.r}║  ${c.dim}Found ${licenses.length} license(s)${c.reset}                                                                    ${c.r}║${c.reset}`);
    console.log(`${c.r}║                                                                                                     ${c.r}║${c.reset}`);
    
    licenses.forEach((lic, i) => {
      const expired = isExpired(lic.expires);
      const isActive = active && active.key === lic.key;
      const status = isActive ? `${c.g}● ACTIVE${c.reset}` : expired ? `${c.r}● EXPIRED${c.reset}` : `${c.y}● INACTIVE${c.reset}`;
      const statusPlain = isActive ? 'ACTIVE' : expired ? 'EXPIRED' : 'INACTIVE';
      
      console.log(`${c.r}║  ${c.bold}[${i + 1}]${c.reset} ${lic.user.padEnd(20)} ${status} ${c.dim}${lic.key.substring(0, 19)}...${c.reset}         ${c.r}║${c.reset}`);
      console.log(`${c.r}║      ${c.dim}Created: ${formatDate(lic.created)}  |  Expires: ${formatDate(lic.expires)}${c.reset}            ${c.r}║${c.reset}`);
      console.log(`${c.r}║                                                                                                     ${c.r}║${c.reset}`);
    });
  }
  
  console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  console.log(`${c.r}║  ${c.y}[A]${c.reset} Activate a license    ${c.y}[D]${c.reset} Deactivate    ${c.y}[R]${c.reset} Revoke/Delete    ${c.y}[G]${c.reset} Generate    ${c.y}[Q]${c.reset} Quit  ${c.r}║${c.reset}`);
  console.log(`${c.r}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
}

function activateLicense(key) {
  const licenses = getAllLicenses();
  const lic = licenses.find(l => l.key === key);
  
  if (!lic) {
    console.log(`\n  ${c.r}✗ License key not found in database${c.reset}`);
    return false;
  }
  
  if (isExpired(lic.expires)) {
    console.log(`\n  ${c.r}✗ This license has expired${c.reset}`);
    return false;
  }
  
  const activeData = {
    key: lic.key,
    payload: lic.payload,
    created: lic.created,
    expires: lic.expires,
    user: lic.user,
    activated: new Date().toISOString()
  };
  
  fs.writeFileSync(LICENSE_FILE, JSON.stringify(activeData, null, 2));
  console.log(`\n  ${c.g}✓ License activated for: ${lic.user}${c.reset}`);
  console.log(`  ${c.dim}Key: ${lic.key}${c.reset}`);
  console.log(`  ${c.dim}Expires: ${formatDate(lic.expires)}${c.reset}`);
  return true;
}

function deactivateLicense() {
  if (fs.existsSync(LICENSE_FILE)) {
    fs.unlinkSync(LICENSE_FILE);
    console.log(`\n  ${c.g}✓ License deactivated${c.reset}`);
    return true;
  }
  console.log(`\n  ${c.y}⚠ No active license to deactivate${c.reset}`);
  return false;
}

function revokeLicense(filename) {
  const filepath = path.join(LICENSES_DIR, filename);
  if (fs.existsSync(filepath)) {
    fs.unlinkSync(filepath);
    console.log(`\n  ${c.g}✓ License revoked and deleted${c.reset}`);
    return true;
  }
  console.log(`\n  ${c.r}✗ License file not found${c.reset}`);
  return false;
}

function generateLicense(user, days) {
  const crypto = require('crypto');
  const SECRET_KEY = 'TRUMA-OSINT-SECRET-2024-SECURE-KEY-DO-NOT-SHARE';
  
  const timestamp = Date.now();
  const expiry = timestamp + (days * 24 * 60 * 60 * 1000);
  const payload = `${user}|${timestamp}|${expiry}`;
  
  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(payload)
    .digest('hex')
    .substring(0, 32)
    .toUpperCase();
  
  const key = `TRUMA-${signature.substring(0, 4)}-${signature.substring(4, 8)}-${signature.substring(8, 12)}-${signature.substring(12, 16)}-${signature.substring(16, 20)}-${signature.substring(20, 24)}`;
  
  const license = {
    key,
    payload,
    created: new Date(timestamp).toISOString(),
    expires: new Date(expiry).toISOString(),
    user
  };
  
  fs.writeFileSync(path.join(LICENSES_DIR, `${user}_${timestamp}.json`), JSON.stringify(license, null, 2));
  
  console.log(`\n${c.g}╔════════════════════════════════════════════════════════════╗${c.reset}`);
  console.log(`${c.g}║  ${c.bold}LICENSE GENERATED${c.reset}                                         ${c.g}║${c.reset}`);
  console.log(`${c.g}╠════════════════════════════════════════════════════════════╣${c.reset}`);
  console.log(`${c.g}║  User: ${user.padEnd(48)}${c.g}║${c.reset}`);
  console.log(`${c.g}║  Key: ${key.padEnd(49)}${c.g}║${c.reset}`);
  console.log(`${c.g}║  Expires: ${formatDate(license.expires).padEnd(43)}${c.g}║${c.reset}`);
  console.log(`${c.g}╚════════════════════════════════════════════════════════════╝${c.reset}`);
  
  return license;
}

async function prompt(rl, question) {
  return new Promise(resolve => rl.question(question, resolve));
}

async function main() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  
  while (true) {
    showLicenseList();
    
    const choice = await prompt(rl, `\n  ${c.y}▶${c.reset} Select option: `);
    
    if (choice.toLowerCase() === 'q') {
      console.log(`\n  ${c.dim}Goodbye!${c.reset}\n`);
      rl.close();
      process.exit(0);
    }
    
    if (choice.toLowerCase() === 'a') {
      const key = await prompt(rl, `  ${c.y}▶${c.reset} Enter license key to activate: `);
      await activateLicense(key.trim().toUpperCase());
      await prompt(rl, `  ${c.dim}Press Enter to continue...${c.reset}`);
    }
    
    if (choice.toLowerCase() === 'd') {
      deactivateLicense();
      await prompt(rl, `  ${c.dim}Press Enter to continue...${c.reset}`);
    }
    
    if (choice.toLowerCase() === 'r') {
      const licenses = getAllLicenses();
      if (licenses.length === 0) {
        console.log(`\n  ${c.y}⚠ No licenses to revoke${c.reset}`);
        await prompt(rl, `  ${c.dim}Press Enter to continue...${c.reset}`);
        continue;
      }
      
      const num = await prompt(rl, `  ${c.y}▶${c.reset} Enter license number to revoke: `);
      const idx = parseInt(num) - 1;
      
      if (idx >= 0 && idx < licenses.length) {
        const lic = licenses[idx];
        const confirm = await prompt(rl, `  ${c.r}⚠ Revoke license for "${lic.user}"? (y/n): ${c.reset}`);
        if (confirm.toLowerCase() === 'y') {
          revokeLicense(lic.filename);
        }
      } else {
        console.log(`\n  ${c.r}✗ Invalid selection${c.reset}`);
      }
      await prompt(rl, `  ${c.dim}Press Enter to continue...${c.reset}`);
    }
    
    if (choice.toLowerCase() === 'g') {
      const user = await prompt(rl, `  ${c.y}▶${c.reset} Enter username: `);
      const daysStr = await prompt(rl, `  ${c.y}▶${c.reset} Validity days (default 365): `);
      const days = parseInt(daysStr) || 365;
      
      if (user.trim()) {
        generateLicense(user.trim(), days);
      } else {
        console.log(`\n  ${c.r}✗ Username required${c.reset}`);
      }
      await prompt(rl, `  ${c.dim}Press Enter to continue...${c.reset}`);
    }
  }
}

main();
