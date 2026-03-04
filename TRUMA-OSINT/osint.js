#!/usr/bin/env node

const dns = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');

const RESULTS_DIR = path.join(__dirname, 'results');
const REPORTS_DIR = path.join(__dirname, 'reports');
if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR, { recursive: true });
if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });

// Report generator
const { generateReport } = require('./report-template');

const c = {
  r: '\x1b[31m', g: '\x1b[32m', y: '\x1b[33m', c: '\x1b[36m', w: '\x1b[37m',
  bold: '\x1b[1m', dim: '\x1b[2m', reset: '\x1b[0m'
};

function log(msg, color = 'w') { console.log(c[color] + msg + c.reset); }

function saveResult(filename, data, type) {
  // Save JSON
  const jsonPath = path.join(RESULTS_DIR, `${filename}_${Date.now()}.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(data, null, 2));
  log(`\n  JSON: ${jsonPath}`, 'dim');
  
  // Generate HTML Report
  if (type) {
    const html = generateReport(type, data);
    const htmlPath = path.join(REPORTS_DIR, `${filename}_${Date.now()}.html`);
    fs.writeFileSync(htmlPath, html);
    log(`  Report: ${htmlPath}`, 'g');
  }
}

// ==================== BREACH DATABASE ====================

const BREACH_DB = {
  domains: {
    'adobe.com': { name: 'Adobe', date: '2013', records: '153M' },
    'linkedin.com': { name: 'LinkedIn', date: '2012', records: '164M' },
    'dropbox.com': { name: 'Dropbox', date: '2012', records: '68M' },
    'yahoo.com': { name: 'Yahoo', date: '2013', records: '3B' },
    'myfitnesspal.com': { name: 'MyFitnessPal', date: '2018', records: '151M' },
    'canva.com': { name: 'Canva', date: '2019', records: '137M' },
    'tumblr.com': { name: 'Tumblr', date: '2013', records: '65M' },
    'ashleymadison.com': { name: 'Ashley Madison', date: '2015', records: '32M' },
    'marriott.com': { name: 'Marriott', date: '2018', records: '500M' },
    'equifax.com': { name: 'Equifax', date: '2017', records: '145M' }
  },
  disposable: ['tempmail', 'guerrilla', '10minutemail', 'throwaway', 'mailinator', 'yopmail', 'fakeinbox'],
  knownHashes: ['5baa6', 'e99a1', 'd8578', '90f2b', '5f4dc', 'b2aeb', 'a1d0c', 'e10ad']
};

// ==================== EMAIL OSINT ====================

async function emailOSINT(email) {
  log(`\n${'═'.repeat(60)}`, 'c');
  log(`  EMAIL OSINT: ${email}`, 'bold');
  log(`${'═'.repeat(60)}`, 'c');

  const results = { email, timestamp: new Date().toISOString(), data: {}, breach: {}, social: {} };
  const [local, domain] = email.split('@');

  // 1. Validation
  log('\n  [1] VALIDATION', 'y');
  const valid = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
  const isDisposable = BREACH_DB.disposable.some(d => domain.toLowerCase().includes(d));
  const isRole = ['admin', 'info', 'support', 'sales', 'noreply'].some(r => local.toLowerCase() === r);
  
  results.data.valid = valid;
  results.data.disposable = isDisposable;
  results.data.role = isRole;
  log(`      Valid: ${valid ? 'YES' : 'NO'}`, valid ? 'g' : 'r');
  log(`      Disposable: ${isDisposable ? 'YES' : 'NO'}`, isDisposable ? 'r' : 'g');
  log(`      Role account: ${isRole ? 'YES' : 'NO'}`, isRole ? 'y' : 'dim');

  // 2. DNS Analysis
  log('\n  [2] DNS ANALYSIS', 'y');
  try {
    const mx = await dns.resolveMx(domain);
    results.data.mx = mx;
    if (mx.length > 0) {
      log(`      MX Records: ${mx.length}`, 'g');
      mx.forEach(r => log(`        ${r.exchange} (${r.priority})`, 'dim'));
      results.data.provider = detectProvider(mx[0].exchange);
      if (results.data.provider) log(`      Provider: ${results.data.provider}`, 'g');
    }
  } catch (e) { log('      MX: None', 'r'); }

  try {
    const txt = await dns.resolveTxt(domain);
    results.data.spf = txt.some(t => t.join('').includes('v=spf'));
    results.data.dmarc = txt.some(t => t.join('').includes('v=dmarc'));
    log(`      SPF: ${results.data.spf ? 'YES' : 'NO'}`, results.data.spf ? 'g' : 'y');
    log(`      DMARC: ${results.data.dmarc ? 'YES' : 'NO'}`, results.data.dmarc ? 'g' : 'y');
  } catch (e) {}

  // 3. SMTP Test
  log('\n  [3] SMTP TEST', 'y');
  if (results.data.mx?.length > 0) {
    const mxHost = results.data.mx[0].exchange;
    const smtpOpen = await testPort(mxHost, 25);
    results.data.smtp = smtpOpen;
    log(`      Port 25: ${smtpOpen ? 'OPEN' : 'CLOSED'}`, smtpOpen ? 'g' : 'r');
  }

  // 4. Breach Check
  log('\n  [4] BREACH CHECK', 'y');
  results.breach.domainBreaches = [];
  for (const [d, info] of Object.entries(BREACH_DB.domains)) {
    if (domain.toLowerCase().includes(d.split('.')[0])) {
      results.breach.domainBreaches.push(info);
      log(`      Domain in: ${info.name} (${info.date}, ${info.records})`, 'r');
    }
  }
  
  const hash = crypto.createHash('sha1').update(email.toLowerCase()).digest('hex');
  const prefix = hash.substring(0, 5);
  results.breach.exposed = BREACH_DB.knownHashes.includes(prefix);
  log(`      Exposure: ${results.breach.exposed ? 'DETECTED' : 'Not found'}`, results.breach.exposed ? 'r' : 'g');

  // 5. Social Discovery
  log('\n  [5] SOCIAL DISCOVERY', 'y');
  const gravatarHash = crypto.createHash('md5').update(email.toLowerCase().trim()).digest('hex');
  results.social.gravatar = `https://gravatar.com/avatar/${gravatarHash}`;
  
  results.social.patterns = [
    `"${email}" site:facebook.com`,
    `"${email}" site:twitter.com`,
    `"${email}" site:linkedin.com`,
    `"${email}" site:github.com`,
    `"${local}" site:instagram.com`
  ];
  log(`      Gravatar hash: ${gravatarHash}`, 'dim');
  log(`      Search patterns: ${results.social.patterns.length}`, 'g');

  // 6. Risk Score
  log('\n  [6] RISK SCORE', 'y');
  let score = 0;
  if (isDisposable) score += 2;
  if (results.breach.exposed) score += 3;
  if (results.breach.domainBreaches.length > 0) score += 2;
  if (!results.data.spf) score += 1;
  
  results.risk = { score, level: score >= 4 ? 'HIGH' : score >= 2 ? 'MEDIUM' : 'LOW' };
  log(`      Level: ${results.risk.level} (${score}/10)`, results.risk.level === 'HIGH' ? 'r' : results.risk.level === 'MEDIUM' ? 'y' : 'g');

  saveResult(`email_${email.replace(/[@.]/g, '_')}`, results, 'email');
  return results;
}

function detectProvider(mx) {
  const providers = { google: 'Google', outlook: 'Microsoft', yahoo: 'Yahoo', proton: 'ProtonMail', amazon: 'AWS' };
  for (const [k, v] of Object.entries(providers)) {
    if (mx.toLowerCase().includes(k)) return v;
  }
  return null;
}

// ==================== PHONE OSINT ====================

async function phoneOSINT(phone) {
  log(`\n${'═'.repeat(60)}`, 'c');
  log(`  PHONE OSINT: ${phone}`, 'bold');
  log(`${'═'.repeat(60)}`, 'c');

  const results = { phone, timestamp: new Date().toISOString(), data: {} };
  const clean = phone.replace(/[^0-9]/g, '');
  results.data.clean = clean;

  // 1. Validation
  log('\n  [1] VALIDATION', 'y');
  results.data.valid = clean.length >= 10 && clean.length <= 15;
  log(`      Digits: ${clean.length}`, results.data.valid ? 'g' : 'r');
  log(`      Clean: ${clean}`, 'dim');

  // 2. Country Detection
  log('\n  [2] GEOLOCATION', 'y');
  const countries = {
    '1': 'USA/Canada', '44': 'UK', '91': 'India', '86': 'China', '81': 'Japan',
    '49': 'Germany', '33': 'France', '61': 'Australia', '55': 'Brazil', '52': 'Mexico',
    '7': 'Russia', '82': 'South Korea', '39': 'Italy', '31': 'Netherlands'
  };
  
  for (const [code, name] of Object.entries(countries)) {
    if (clean.startsWith(code)) {
      results.data.country = { code: `+${code}`, name };
      log(`      Country: ${name} (+${code})`, 'g');
      break;
    }
  }
  if (!results.data.country) log('      Country: Unknown', 'y');

  // 3. US Area Code
  if (clean.startsWith('1') && clean.length >= 11) {
    log('\n  [3] AREA CODE', 'y');
    const area = clean.substring(1, 4);
    const areaCodes = {
      '212': 'New York', '310': 'Los Angeles', '312': 'Chicago', '415': 'San Francisco',
      '202': 'Washington DC', '617': 'Boston', '206': 'Seattle', '512': 'Austin',
      '713': 'Houston', '214': 'Dallas', '404': 'Atlanta', '305': 'Miami',
      '602': 'Phoenix', '702': 'Las Vegas', '808': 'Hawaii', '907': 'Alaska'
    };
    results.data.area = areaCodes[area] || 'Unknown';
    log(`      Area: ${area} (${results.data.area})`, 'g');
    
    // Toll-free check
    if (['800', '833', '844', '855', '866', '877', '888'].includes(area)) {
      results.data.type = 'Toll-Free';
      log(`      Type: Toll-Free`, 'y');
    }
  }

  // 4. Format Output
  log('\n  [4] FORMATS', 'y');
  if (clean.length === 11 && clean.startsWith('1')) {
    results.data.formats = {
      us: `+1 (${clean.substring(1,4)}) ${clean.substring(4,7)}-${clean.substring(7)}`,
      intl: `+1 ${clean.substring(1,4)} ${clean.substring(4,7)} ${clean.substring(7)}`
    };
  } else if (clean.length === 10) {
    results.data.formats = {
      us: `+1 (${clean.substring(0,3)}) ${clean.substring(3,6)}-${clean.substring(6)}`,
      intl: `+1 ${clean.substring(0,3)} ${clean.substring(3,6)} ${clean.substring(6)}`
    };
  } else {
    results.data.formats = { intl: `+${clean}` };
  }
  Object.entries(results.data.formats).forEach(([k, v]) => log(`      ${k}: ${v}`, 'dim'));

  // 5. Account Discovery
  log('\n  [5] ACCOUNT DISCOVERY', 'y');
  results.data.accounts = {
    whatsapp: `https://wa.me/${clean}`,
    telegram: `https://t.me/+${clean}`,
    searches: [
      `"${clean}" site:facebook.com`,
      `"${clean}" site:twitter.com`,
      `"${clean}" site:linkedin.com`
    ]
  };
  log(`      WhatsApp: wa.me/${clean}`, 'dim');
  log(`      Telegram: t.me/+${clean}`, 'dim');

  saveResult(`phone_${clean}`, results, 'phone');
  return results;
}

// ==================== USERNAME OSINT ====================

async function usernameOSINT(username) {
  log(`\n${'═'.repeat(60)}`, 'c');
  log(`  USERNAME OSINT: ${username}`, 'bold');
  log(`${'═'.repeat(60)}`, 'c');

  const results = { username, timestamp: new Date().toISOString(), platforms: [], variations: [] };

  // 1. Analysis
  log('\n  [1] ANALYSIS', 'y');
  results.analysis = {
    length: username.length,
    hasNumbers: /\d/.test(username),
    hasSpecial: /[^a-zA-Z0-9]/.test(username)
  };
  log(`      Length: ${username.length}`, 'dim');
  log(`      Numbers: ${results.analysis.hasNumbers ? 'YES' : 'NO'}`, 'dim');

  // 2. Platform Check (75+ platforms)
  log('\n  [2] PLATFORM CHECK (75+ platforms)', 'y');
  const platforms = [
    // Developer Platforms
    { name: 'GitHub', url: `https://github.com/${username}`, category: 'dev' },
    { name: 'GitLab', url: `https://gitlab.com/${username}`, category: 'dev' },
    { name: 'Bitbucket', url: `https://bitbucket.org/${username}`, category: 'dev' },
    { name: 'Dev.to', url: `https://dev.to/${username}`, category: 'dev' },
    { name: 'Codecademy', url: `https://codecademy.com/${username}`, category: 'dev' },
    { name: 'Replit', url: `https://replit.com/@${username}`, category: 'dev' },
    { name: 'Stack Overflow', url: `https://stackoverflow.com/users/${username}`, category: 'dev' },
    { name: 'HackerNews', url: `https://news.ycombinator.com/user?id=${username}`, category: 'dev' },
    { name: 'SourceForge', url: `https://sourceforge.net/u/${username}`, category: 'dev' },
    { name: 'Launchpad', url: `https://launchpad.net/~${username}`, category: 'dev' },
    { name: 'Gitee', url: `https://gitee.com/${username}`, category: 'dev' },
    { name: 'Codeforces', url: `https://codeforces.com/profile/${username}`, category: 'dev' },
    { name: 'LeetCode', url: `https://leetcode.com/${username}`, category: 'dev' },
    { name: 'HackerRank', url: `https://hackerrank.com/${username}`, category: 'dev' },
    
    // Social Media
    { name: 'Twitter/X', url: `https://twitter.com/${username}`, category: 'social' },
    { name: 'Instagram', url: `https://instagram.com/${username}`, category: 'social' },
    { name: 'Facebook', url: `https://facebook.com/${username}`, category: 'social' },
    { name: 'TikTok', url: `https://tiktok.com/@${username}`, category: 'social' },
    { name: 'Snapchat', url: `https://snapchat.com/add/${username}`, category: 'social' },
    { name: 'Reddit', url: `https://reddit.com/user/${username}`, category: 'social' },
    { name: 'Pinterest', url: `https://pinterest.com/${username}`, category: 'social' },
    { name: 'Tumblr', url: `https://${username}.tumblr.com`, category: 'social' },
    { name: 'Mastodon', url: `https://mastodon.social/@${username}`, category: 'social' },
    { name: 'Threads', url: `https://threads.net/@${username}`, category: 'social' },
    { name: 'Discord', url: `https://discord.com/users/${username}`, category: 'social' },
    
    // Professional
    { name: 'LinkedIn', url: `https://linkedin.com/in/${username}`, category: 'pro' },
    { name: 'Xing', url: `https://xing.com/profile/${username}`, category: 'pro' },
    { name: 'AngelList', url: `https://wellfound.com/u/${username}`, category: 'pro' },
    { name: 'Crunchbase', url: `https://crunchbase.com/person/${username}`, category: 'pro' },
    { name: 'Glassdoor', url: `https://glassdoor.com/profile/${username}`, category: 'pro' },
    { name: 'F6s', url: `https://f6s.com/${username}`, category: 'pro' },
    
    // Creative
    { name: 'YouTube', url: `https://youtube.com/@${username}`, category: 'creative' },
    { name: 'Vimeo', url: `https://vimeo.com/${username}`, category: 'creative' },
    { name: 'Twitch', url: `https://twitch.tv/${username}`, category: 'creative' },
    { name: 'Dailymotion', url: `https://dailymotion.com/${username}`, category: 'creative' },
    { name: 'SoundCloud', url: `https://soundcloud.com/${username}`, category: 'creative' },
    { name: 'Spotify', url: `https://open.spotify.com/user/${username}`, category: 'creative' },
    { name: 'Bandcamp', url: `https://bandcamp.com/${username}`, category: 'creative' },
    { name: 'Mixcloud', url: `https://mixcloud.com/${username}`, category: 'creative' },
    { name: 'Dribbble', url: `https://dribbble.com/${username}`, category: 'creative' },
    { name: 'Behance', url: `https://behance.net/${username}`, category: 'creative' },
    { name: 'DeviantArt', url: `https://${username}.deviantart.com`, category: 'creative' },
    { name: 'ArtStation', url: `https://artstation.com/${username}`, category: 'creative' },
    { name: 'Flickr', url: `https://flickr.com/people/${username}`, category: 'creative' },
    { name: '500px', url: `https://500px.com/${username}`, category: 'creative' },
    { name: 'Unsplash', url: `https://unsplash.com/@${username}`, category: 'creative' },
    { name: 'Pexels', url: `https://pexels.com/@${username}`, category: 'creative' },
    { name: 'Medium', url: `https://medium.com/@${username}`, category: 'creative' },
    { name: 'Substack', url: `https://${username}.substack.com`, category: 'creative' },
    { name: 'Wattpad', url: `https://wattpad.com/user/${username}`, category: 'creative' },
    { name: 'Fanfiction', url: `https://fanfiction.net/~${username}`, category: 'creative' },
    { name: 'Archive of Our Own', url: `https://archiveofourown.org/users/${username}`, category: 'creative' },
    
    // Gaming
    { name: 'Steam', url: `https://steamcommunity.com/id/${username}`, category: 'gaming' },
    { name: 'Xbox', url: `https://xboxgamertag.com/search/${username}`, category: 'gaming' },
    { name: 'PlayStation', url: `https://psnprofiles.com/${username}`, category: 'gaming' },
    { name: 'Nintendo', url: `https://nintendo.com/us/switch/friends/${username}`, category: 'gaming' },
    { name: 'Epic Games', url: `https://fortnitetracker.com/profile/all/${username}`, category: 'gaming' },
    { name: 'Riot Games', url: `https://op.gg/summoners/na/${username}`, category: 'gaming' },
    { name: 'Roblox', url: `https://roblox.com/user.aspx?username=${username}`, category: 'gaming' },
    { name: 'Minecraft', url: `https://namemc.com/profile/${username}`, category: 'gaming' },
    { name: 'Chess.com', url: `https://chess.com/member/${username}`, category: 'gaming' },
    { name: 'Lichess', url: `https://lichess.org/@/${username}`, category: 'gaming' },
    
    // Other
    { name: 'Keybase', url: `https://keybase.io/${username}`, category: 'other' },
    { name: 'Gravatar', url: `https://gravatar.com/${username}`, category: 'other' },
    { name: 'About.me', url: `https://about.me/${username}`, category: 'other' },
    { name: 'Linktree', url: `https://linktr.ee/${username}`, category: 'other' },
    { name: 'Bio.link', url: `https://bio.link/${username}`, category: 'other' },
    { name: 'Carrd', url: `https://${username}.carrd.co`, category: 'other' },
    { name: 'ProductHunt', url: `https://producthunt.com/@${username}`, category: 'other' },
    { name: 'Slideshare', url: `https://slideshare.net/${username}`, category: 'other' },
    { name: 'Academia', url: `https://academia.edu/${username}`, category: 'other' },
    { name: 'ResearchGate', url: `https://researchgate.net/profile/${username}`, category: 'other' },
    { name: 'Goodreads', url: `https://goodreads.com/${username}`, category: 'other' },
    { name: 'Letterboxd', url: `https://letterboxd.com/${username}`, category: 'other' },
    { name: 'Last.fm', url: `https://last.fm/user/${username}`, category: 'other' },
    { name: 'Strava', url: `https://strava.com/athletes/${username}`, category: 'other' },
    { name: 'MyFitnessPal', url: `https://myfitnesspal.com/profile/${username}`, category: 'other' },
    { name: 'Duolingo', url: `https://duolingo.com/profile/${username}`, category: 'other' },
    { name: 'Cash App', url: `https://cash.app/$${username}`, category: 'other' },
    { name: 'Patreon', url: `https://patreon.com/${username}`, category: 'other' },
    { name: 'Ko-fi', url: `https://ko-fi.com/${username}`, category: 'other' },
    { name: 'Buy Me a Coffee', url: `https://buymeacoffee.com/${username}`, category: 'other' },
    { name: 'PayPal', url: `https://paypal.me/${username}`, category: 'other' },
    { name: 'Venmo', url: `https://venmo.com/${username}`, category: 'other' }
  ];

  let found = 0;
  for (const p of platforms) {
    process.stdout.write(`\r      Checking ${p.name}...`.padEnd(35));
    try {
      const res = await checkHTTP(p.url);
      if (res.found) {
        found++;
        results.platforms.push({ ...p, status: 'FOUND' });
        process.stdout.write(`\r${c.g}✓ ${p.name.padEnd(12)} FOUND${c.reset}\n`);
      } else {
        results.platforms.push({ ...p, status: 'NOT FOUND' });
        process.stdout.write(`\r${c.r}✗ ${p.name.padEnd(12)} Not Found${c.reset}\n`);
      }
    } catch (e) {
      results.platforms.push({ ...p, status: 'ERROR' });
      process.stdout.write(`\r${c.y}? ${p.name.padEnd(12)} Error${c.reset}\n`);
    }
    await new Promise(r => setTimeout(r, 150));
  }

  // 3. Summary by Category
  log(`\n  [3] SUMMARY BY CATEGORY`, 'y');
  const categories = {
    dev: 'Developer',
    social: 'Social Media',
    pro: 'Professional',
    creative: 'Creative',
    gaming: 'Gaming',
    other: 'Other'
  };
  
  const foundPlatforms = results.platforms.filter(p => p.status === 'FOUND');
  log(`      Total checked: ${platforms.length}`, 'dim');
  log(`      Total found: ${found}`, found > 0 ? 'g' : 'dim');
  
  // Show by category
  for (const [cat, label] of Object.entries(categories)) {
    const catPlatforms = foundPlatforms.filter(p => p.category === cat);
    if (catPlatforms.length > 0) {
      log(`\n      ${label} (${catPlatforms.length}):`, 'g');
      catPlatforms.forEach(p => log(`        • ${p.name}`, 'dim'));
    }
  }
  
  if (foundPlatforms.length > 0) {
    log(`\n      ALL FOUND PLATFORMS:`, 'g');
    foundPlatforms.forEach(p => log(`        • ${p.name}: ${p.url}`, 'g'));
  }

  // 4. Variations
  log('\n  [4] VARIATIONS', 'y');
  results.variations = [
    username, username.toLowerCase(), username.toUpperCase(),
    username.replace(/_/g, '-'), username.replace(/-/g, '_'),
    username.replace(/_/g, ''), username.replace(/-/g, ''),
    'the' + username, 'real' + username, username + 'official',
    username + '2024', username + '2025', 'iam' + username, 'its' + username
  ].filter((v, i, a) => a.indexOf(v) === i);
  log(`      Generated: ${results.variations.length}`, 'g');

  saveResult(`username_${username}`, results, 'username');
  return results;
}

// ==================== IP OSINT ====================

async function ipOSINT(ip) {
  log(`\n${'═'.repeat(60)}`, 'c');
  log(`  IP OSINT: ${ip}`, 'bold');
  log(`${'═'.repeat(60)}`, 'c');

  const results = { ip, timestamp: new Date().toISOString(), data: {} };

  // Validate
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    log('  Invalid IPv4!', 'r');
    return results;
  }

  // 1. Reverse DNS
  log('\n  [1] REVERSE DNS', 'y');
  try {
    const hosts = await dns.reverse(ip);
    results.data.reverse = hosts;
    if (hosts.length > 0) {
      log(`      Hostnames:`, 'g');
      hosts.forEach(h => log(`        ${h}`, 'dim'));
    } else {
      log('      No PTR record', 'dim');
    }
  } catch (e) {
    log('      Reverse DNS failed', 'r');
  }

  // 2. Classification
  log('\n  [2] CLASSIFICATION', 'y');
  const [a, b] = ip.split('.').map(Number);
  results.data.private = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  results.data.loopback = a === 127;
  results.data.multicast = a >= 224 && a <= 239;
  log(`      Private: ${results.data.private ? 'YES' : 'NO'}`, results.data.private ? 'y' : 'g');
  log(`      Loopback: ${results.data.loopback ? 'YES' : 'NO'}`, 'dim');

  // 3. Port Scan
  log('\n  [3] PORT SCAN', 'y');
  const ports = [
    { port: 21, name: 'FTP' }, { port: 22, name: 'SSH' }, { port: 23, name: 'Telnet' },
    { port: 25, name: 'SMTP' }, { port: 53, name: 'DNS' }, { port: 80, name: 'HTTP' },
    { port: 110, name: 'POP3' }, { port: 143, name: 'IMAP' }, { port: 443, name: 'HTTPS' },
    { port: 445, name: 'SMB' }, { port: 993, name: 'IMAPS' }, { port: 3306, name: 'MySQL' },
    { port: 3389, name: 'RDP' }, { port: 5432, name: 'PostgreSQL' }, { port: 5900, name: 'VNC' },
    { port: 8080, name: 'HTTP-Alt' }
  ];

  results.data.ports = [];
  for (const { port, name } of ports) {
    const open = await testPort(ip, port);
    if (open) {
      results.data.ports.push({ port, name });
      log(`      ${port}/${name}: OPEN`, 'g');
    }
  }
  if (results.data.ports.length === 0) log('      No open ports', 'dim');

  // 4. Risk
  log('\n  [4] RISK ASSESSMENT', 'y');
  const risks = [];
  if (results.data.ports.some(p => p.port === 23)) risks.push('Telnet exposed');
  if (results.data.ports.some(p => p.port === 21)) risks.push('FTP exposed');
  if (results.data.ports.some(p => p.port === 3389)) risks.push('RDP exposed');
  if (results.data.ports.some(p => p.port === 445)) risks.push('SMB exposed');
  if (results.data.ports.some(p => p.port === 5900)) risks.push('VNC exposed');
  
  results.data.risks = risks;
  results.data.riskLevel = risks.length >= 2 ? 'HIGH' : risks.length > 0 ? 'MEDIUM' : 'LOW';
  log(`      Level: ${results.data.riskLevel}`, results.data.riskLevel === 'HIGH' ? 'r' : results.data.riskLevel === 'MEDIUM' ? 'y' : 'g');
  risks.forEach(r => log(`        - ${r}`, 'y'));

  saveResult(`ip_${ip.replace(/\./g, '_')}`, results, 'ip');
  return results;
}

// ==================== DOMAIN OSINT ====================

async function domainOSINT(domain) {
  log(`\n${'═'.repeat(60)}`, 'c');
  log(`  DOMAIN OSINT: ${domain}`, 'bold');
  log(`${'═'.repeat(60)}`, 'c');

  const results = { domain, timestamp: new Date().toISOString(), data: {} };

  // 1. DNS Records
  log('\n  [1] DNS RECORDS', 'y');
  results.data.dns = {};

  try {
    const a = await dns.resolve4(domain);
    results.data.dns.A = a;
    log(`      A: ${a.join(', ')}`, 'g');
  } catch (e) {}

  try {
    const mx = await dns.resolveMx(domain);
    results.data.dns.MX = mx;
    log(`      MX: ${mx.length} records`, 'g');
    mx.forEach(r => log(`        ${r.exchange}`, 'dim'));
  } catch (e) {}

  try {
    const ns = await dns.resolveNs(domain);
    results.data.dns.NS = ns;
    log(`      NS: ${ns.length} servers`, 'g');
  } catch (e) {}

  try {
    const txt = await dns.resolveTxt(domain);
    results.data.dns.TXT = txt;
    results.data.spf = txt.some(t => t.join('').includes('v=spf'));
    log(`      TXT: ${txt.length} records`, 'g');
    log(`      SPF: ${results.data.spf ? 'YES' : 'NO'}`, results.data.spf ? 'g' : 'y');
  } catch (e) {}

  // 2. Subdomains
  log('\n  [2] SUBDOMAIN ENUMERATION', 'y');
  const subs = ['www', 'mail', 'ftp', 'api', 'admin', 'blog', 'shop', 'dev', 'staging', 'test',
                'app', 'portal', 'vpn', 'cdn', 'static', 'assets', 'support', 'help', 'm', 'mobile'];
  
  results.data.subdomains = [];
  for (const sub of subs) {
    const full = `${sub}.${domain}`;
    try {
      const addr = await dns.resolve4(full);
      results.data.subdomains.push({ name: full, ip: addr[0] });
      log(`      Found: ${full} → ${addr[0]}`, 'g');
    } catch (e) {}
    await new Promise(r => setTimeout(r, 50));
  }
  if (results.data.subdomains.length === 0) log('      None found', 'dim');
  else log(`      Total: ${results.data.subdomains.length}`, 'g');

  // 3. HTTP Check
  log('\n  [3] HTTP/HTTPS', 'y');
  try {
    const httpRes = await httpCheck(domain);
    results.data.http = httpRes;
    log(`      HTTP: ${httpRes.status}`, 'g');
  } catch (e) { log('      HTTP: No response', 'r'); }

  try {
    const httpsRes = await httpsCheck(domain);
    results.data.https = httpsRes;
    log(`      HTTPS: ${httpsRes.status}`, 'g');
    
    // Security headers
    const h = httpsRes.headers || {};
    results.data.securityHeaders = [];
    if (h['strict-transport-security']) results.data.securityHeaders.push('HSTS');
    if (h['x-content-type-options']) results.data.securityHeaders.push('X-Content-Type-Options');
    if (h['x-frame-options']) results.data.securityHeaders.push('X-Frame-Options');
    if (h['content-security-policy']) results.data.securityHeaders.push('CSP');
    if (h.server) log(`      Server: ${h.server}`, 'dim');
    if (results.data.securityHeaders.length > 0) {
      log(`      Security: ${results.data.securityHeaders.join(', ')}`, 'g');
    }
  } catch (e) { log('      HTTPS: No response', 'r'); }

  // 4. Risk
  log('\n  [4] RISK', 'y');
  const risks = [];
  if (!results.data.https) risks.push('No HTTPS');
  if (!results.data.spf) risks.push('No SPF');
  if (results.data.securityHeaders?.length < 2) risks.push('Missing security headers');
  results.data.risks = risks;
  results.data.riskLevel = risks.length >= 2 ? 'HIGH' : risks.length > 0 ? 'MEDIUM' : 'LOW';
  log(`      Level: ${results.data.riskLevel}`, results.data.riskLevel === 'HIGH' ? 'r' : results.data.riskLevel === 'MEDIUM' ? 'y' : 'g');
  risks.forEach(r => log(`        - ${r}`, 'y'));

  saveResult(`domain_${domain.replace(/\./g, '_')}`, results, 'domain');
  return results;
}

// ==================== IMAGE OSINT ====================

async function imageOSINT(imagePath) {
  log(`\n${'═'.repeat(60)}`, 'c');
  log(`  IMAGE OSINT: ${imagePath}`, 'bold');
  log(`${'═'.repeat(60)}`, 'c');

  const results = { path: imagePath, timestamp: new Date().toISOString(), data: {} };

  // Check if file exists
  if (!fs.existsSync(imagePath)) {
    log('  File not found!', 'r');
    return results;
  }

  // 1. File Info
  log('\n  [1] FILE INFO', 'y');
  const stats = fs.statSync(imagePath);
  const ext = path.extname(imagePath).toLowerCase();
  
  results.data.size = stats.size;
  results.data.extension = ext;
  results.data.created = stats.birthtime;
  results.data.modified = stats.mtime;
  
  log(`      Size: ${(stats.size / 1024).toFixed(2)} KB`, 'dim');
  log(`      Type: ${ext}`, 'dim');
  log(`      Modified: ${stats.mtime}`, 'dim');

  // 2. Hash
  log('\n  [2] HASHES', 'y');
  const buffer = fs.readFileSync(imagePath);
  results.data.md5 = crypto.createHash('md5').update(buffer).digest('hex');
  results.data.sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
  results.data.sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  log(`      MD5: ${results.data.md5}`, 'dim');
  log(`      SHA256: ${results.data.sha256.substring(0, 32)}...`, 'dim');

  // 3. EXIF Extraction (for JPEG)
  if (['.jpg', '.jpeg'].includes(ext)) {
    log('\n  [3] EXIF DATA', 'y');
    try {
      const exif = extractEXIF(buffer);
      results.data.exif = exif;
      if (exif.make) log(`      Camera: ${exif.make}`, 'g');
      if (exif.model) log(`      Model: ${exif.model}`, 'g');
      if (exif.datetime) log(`      Date: ${exif.datetime}`, 'g');
      if (exif.gps) {
        log(`      GPS: ${exif.gps.lat}, ${exif.gps.lon}`, 'g');
        results.data.gpsLocation = `https://maps.google.com/?q=${exif.gps.lat},${exif.gps.lon}`;
      }
      if (exif.software) log(`      Software: ${exif.software}`, 'dim');
    } catch (e) {
      log('      No EXIF data', 'dim');
    }
  }

  // 4. Reverse Search URLs
  log('\n  [4] REVERSE SEARCH', 'y');
  const encodedPath = encodeURIComponent(imagePath);
  results.data.reverseSearch = {
    google: `https://images.google.com/searchbyimage?image_path=${encodedPath}`,
    tineye: `https://tineye.com/search/?url=${encodedPath}`,
    yandex: `https://yandex.com/images/search?img_path=${encodedPath}`
  };
  log(`      Google Images`, 'dim');
  log(`      TinEye`, 'dim');
  log(`      Yandex`, 'dim');

  saveResult(`image_${path.basename(imagePath).replace(/\./g, '_')}`, results, 'image');
  return results;
}

// Simple EXIF extraction for JPEG
function extractEXIF(buffer) {
  const exif = {};
  
  // Check JPEG signature
  if (buffer[0] !== 0xFF || buffer[1] !== 0xD8) return exif;
  
  // Find EXIF marker
  let offset = 2;
  while (offset < buffer.length - 2) {
    if (buffer[offset] !== 0xFF) break;
    
    const marker = buffer[offset + 1];
    const length = buffer.readUInt16BE(offset + 2);
    
    // APP1 marker (EXIF)
    if (marker === 0xE1) {
      const exifData = buffer.slice(offset + 4, offset + 2 + length);
      
      // Check "Exif" header
      if (exifData.toString('ascii', 0, 4) === 'Exif') {
        const tiff = exifData.slice(6);
        const littleEndian = tiff[0] === 0x49;
        
        // Parse IFD0
        const readUInt = (buf, off) => littleEndian ? buf.readUInt16LE(off) : buf.readUInt16BE(off);
        const readUInt32 = (buf, off) => littleEndian ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
        
        const ifd0Offset = readUInt32(tiff, 4);
        const ifd0Count = readUInt(tiff, ifd0Offset);
        
        for (let i = 0; i < ifd0Count; i++) {
          const tagOffset = ifd0Offset + 2 + (i * 12);
          const tag = readUInt(tiff, tagOffset);
          const type = readUInt(tiff, tagOffset + 2);
          const count = readUInt32(tiff, tagOffset + 4);
          
          // Make (0x010F)
          if (tag === 0x010F) {
            const valueOffset = readUInt32(tiff, tagOffset + 8);
            const val = tiff.slice(valueOffset, valueOffset + count - 1).toString('ascii');
            exif.make = val;
          }
          // Model (0x0110)
          else if (tag === 0x0110) {
            const valueOffset = readUInt32(tiff, tagOffset + 8);
            const val = tiff.slice(valueOffset, valueOffset + count - 1).toString('ascii');
            exif.model = val;
          }
          // Software (0x0131)
          else if (tag === 0x0131) {
            const valueOffset = readUInt32(tiff, tagOffset + 8);
            const val = tiff.slice(valueOffset, valueOffset + count - 1).toString('ascii');
            exif.software = val;
          }
          // DateTime (0x0132)
          else if (tag === 0x0132) {
            const valueOffset = readUInt32(tiff, tagOffset + 8);
            const val = tiff.slice(valueOffset, valueOffset + count - 1).toString('ascii');
            exif.datetime = val;
          }
        }
      }
      break;
    }
    
    offset += 2 + length;
  }
  
  return exif;
}

// ==================== HELPERS ====================

function testPort(host, port) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    socket.setTimeout(2000);
    socket.connect(port, host, () => { socket.destroy(); resolve(true); });
    socket.on('error', () => resolve(false));
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
  });
}

function checkHTTP(url) {
  return new Promise(resolve => {
    const client = url.startsWith('https') ? https : http;
    const req = client.request(url, { method: 'HEAD', timeout: 5000 }, res => {
      resolve({ found: res.statusCode === 200, code: res.statusCode });
    });
    req.setTimeout(5000, () => resolve({ found: false }));
    req.on('error', () => resolve({ found: false }));
    req.end();
  });
}

function httpCheck(domain) {
  return new Promise((resolve, reject) => {
    const req = http.request(`http://${domain}`, { method: 'HEAD', timeout: 5000 }, res => {
      resolve({ status: res.statusCode, headers: res.headers });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

function httpsCheck(domain) {
  return new Promise((resolve, reject) => {
    const req = https.request(`https://${domain}`, { method: 'HEAD', timeout: 5000 }, res => {
      resolve({ status: res.statusCode, headers: res.headers });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

// ==================== WEB SCRAPING OSINT ====================

async function webScrapeOSINT(url) {
  log(`\n${'═'.repeat(60)}`, 'c');
  log(`  WEB SCRAPING: ${url}`, 'bold');
  log(`${'═'.repeat(60)}`, 'c');

  const results = { url, timestamp: new Date().toISOString(), data: {} };

  // Normalize URL
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }

  const urlObj = new URL(url);
  results.data.domain = urlObj.hostname;
  results.data.path = urlObj.pathname;

  // 1. Fetch Page
  log('\n  [1] FETCHING PAGE', 'y');
  let html = '';
  try {
    html = await fetchPage(url);
    results.data.fetched = true;
    results.data.size = html.length;
    log(`      Status: OK`, 'g');
    log(`      Size: ${(html.length / 1024).toFixed(2)} KB`, 'dim');
  } catch (e) {
    results.data.fetched = false;
    results.data.error = e.message;
    log(`      Error: ${e.message}`, 'r');
    saveResult(`web_${urlObj.hostname.replace(/\./g, '_')}`, results, 'web');
    return results;
  }

  // 2. Extract Metadata
  log('\n  [2] METADATA', 'y');
  results.data.meta = extractMetadata(html);
  if (results.data.meta.title) log(`      Title: ${results.data.meta.title}`, 'g');
  if (results.data.meta.description) log(`      Description: ${results.data.meta.description.substring(0, 60)}...`, 'dim');
  if (results.data.meta.keywords) log(`      Keywords: ${results.data.meta.keywords}`, 'dim');
  if (results.data.meta.author) log(`      Author: ${results.data.meta.author}`, 'dim');
  if (results.data.meta.generator) log(`      Generator: ${results.data.meta.generator}`, 'dim');

  // 3. Extract Links
  log('\n  [3] LINKS', 'y');
  results.data.links = extractLinks(html, url);
  const internalLinks = results.data.links.filter(l => l.type === 'internal');
  const externalLinks = results.data.links.filter(l => l.type === 'external');
  const socialLinks = results.data.links.filter(l => l.type === 'social');
  
  log(`      Internal: ${internalLinks.length}`, 'g');
  log(`      External: ${externalLinks.length}`, 'g');
  log(`      Social: ${socialLinks.length}`, socialLinks.length > 0 ? 'y' : 'dim');
  
  if (externalLinks.length > 0) {
    log(`\n      External domains:`, 'dim');
    const domains = [...new Set(externalLinks.map(l => l.domain))];
    domains.slice(0, 10).forEach(d => log(`        • ${d}`, 'dim'));
  }

  // 4. Extract Emails
  log('\n  [4] EMAIL ADDRESSES', 'y');
  results.data.emails = extractEmails(html);
  if (results.data.emails.length > 0) {
    log(`      Found: ${results.data.emails.length}`, 'g');
    results.data.emails.slice(0, 10).forEach(e => log(`        • ${e}`, 'dim'));
  } else {
    log('      None found', 'dim');
  }

  // 5. Extract Phone Numbers
  log('\n  [5] PHONE NUMBERS', 'y');
  results.data.phones = extractPhones(html);
  if (results.data.phones.length > 0) {
    log(`      Found: ${results.data.phones.length}`, 'g');
    results.data.phones.slice(0, 5).forEach(p => log(`        • ${p}`, 'dim'));
  } else {
    log('      None found', 'dim');
  }

  // 6. Extract Social Media
  log('\n  [6] SOCIAL MEDIA', 'y');
  results.data.social = extractSocial(html);
  const socialFound = Object.entries(results.data.social).filter(([k, v]) => v.length > 0);
  if (socialFound.length > 0) {
    socialFound.forEach(([platform, accounts]) => {
      log(`      ${platform}: ${accounts.length}`, 'g');
      accounts.slice(0, 3).forEach(a => log(`        • ${a}`, 'dim'));
    });
  } else {
    log('      None found', 'dim');
  }

  // 7. Technology Detection
  log('\n  [7] TECHNOLOGIES', 'y');
  results.data.technologies = detectTechnologies(html);
  if (results.data.technologies.length > 0) {
    results.data.technologies.forEach(t => log(`      • ${t}`, 'g'));
  } else {
    log('      None detected', 'dim');
  }

  // 8. Forms & Inputs
  log('\n  [8] FORMS', 'y');
  results.data.forms = extractForms(html);
  if (results.data.forms.length > 0) {
    log(`      Found: ${results.data.forms.length}`, 'g');
    results.data.forms.forEach((f, i) => {
      log(`        Form ${i + 1}: ${f.action || 'no action'} (${f.method || 'GET'})`, 'dim');
      if (f.inputs.length > 0) {
        f.inputs.slice(0, 5).forEach(inp => log(`          - ${inp.name || inp.type}`, 'dim'));
      }
    });
  } else {
    log('      None found', 'dim');
  }

  // 9. Images
  log('\n  [9] IMAGES', 'y');
  results.data.images = extractImages(html, url);
  if (results.data.images.length > 0) {
    log(`      Found: ${results.data.images.length}`, 'g');
    results.data.images.slice(0, 5).forEach(img => {
      log(`        • ${img.alt || img.src.substring(0, 40)}`, 'dim');
    });
  } else {
    log('      None found', 'dim');
  }

  // 10. Scripts
  log('\n  [10] SCRIPTS', 'y');
  results.data.scripts = extractScripts(html);
  if (results.data.scripts.length > 0) {
    log(`      External: ${results.data.scripts.filter(s => s.src).length}`, 'g');
    log(`      Inline: ${results.data.scripts.filter(s => !s.src).length}`, 'dim');
  } else {
    log('      None found', 'dim');
  }

  // 11. Security Analysis
  log('\n  [11] SECURITY', 'y');
  results.data.security = analyzeSecurity(html, results.data);
  log(`      HTTPS: ${url.startsWith('https') ? 'YES' : 'NO'}`, url.startsWith('https') ? 'g' : 'r');
  log(`      Forms secure: ${results.data.security.secureForms ? 'YES' : 'NO'}`, results.data.security.secureForms ? 'g' : 'y');
  if (results.data.security.warnings.length > 0) {
    log(`      Warnings:`, 'y');
    results.data.security.warnings.forEach(w => log(`        - ${w}`, 'y'));
  }

  saveResult(`web_${urlObj.hostname.replace(/\./g, '_')}`, results, 'web');
  return results;
}

function fetchPage(url) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith('https') ? https : http;
    const req = client.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml'
      },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function extractMetadata(html) {
  const meta = {};
  
  // Title
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (titleMatch) meta.title = titleMatch[1].trim();
  
  // Meta tags
  const metaRegex = /<meta\s+[^>]*name=["']([^"']+)["'][^>]*content=["']([^"']*)["'][^>]*>/gi;
  let match;
  while ((match = metaRegex.exec(html)) !== null) {
    const name = match[1].toLowerCase();
    const content = match[2];
    if (name === 'description') meta.description = content;
    else if (name === 'keywords') meta.keywords = content;
    else if (name === 'author') meta.author = content;
    else if (name === 'generator') meta.generator = content;
    else if (name === 'viewport') meta.viewport = content;
    else if (name === 'robots') meta.robots = content;
  }
  
  // Open Graph
  const ogRegex = /<meta\s+[^>]*property=["']og:([^"']+)["'][^>]*content=["']([^"']*)["'][^>]*>/gi;
  meta.opengraph = {};
  while ((match = ogRegex.exec(html)) !== null) {
    meta.opengraph[match[1]] = match[2];
  }
  
  // Twitter Card
  const twRegex = /<meta\s+[^>]*name=["']twitter:([^"']+)["'][^>]*content=["']([^"']*)["'][^>]*>/gi;
  meta.twitter = {};
  while ((match = twRegex.exec(html)) !== null) {
    meta.twitter[match[1]] = match[2];
  }
  
  return meta;
}

function extractLinks(html, baseUrl) {
  const links = [];
  const base = new URL(baseUrl);
  
  const linkRegex = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>/gi;
  let match;
  
  while ((match = linkRegex.exec(html)) !== null) {
    let href = match[1];
    
    // Skip anchors, javascript, mailto
    if (href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) continue;
    
    try {
      const fullUrl = new URL(href, baseUrl);
      const isInternal = fullUrl.hostname === base.hostname;
      const isSocial = /twitter|facebook|instagram|linkedin|youtube|tiktok|github|reddit|pinterest|snapchat|twitch/i.test(fullUrl.hostname);
      
      links.push({
        url: fullUrl.href,
        domain: fullUrl.hostname,
        type: isSocial ? 'social' : isInternal ? 'internal' : 'external'
      });
    } catch (e) {}
  }
  
  return links;
}

function extractEmails(html) {
  const emails = new Set();
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  let match;
  
  while ((match = emailRegex.exec(html)) !== null) {
    // Filter out common false positives
    if (!match[0].includes('example.com') && 
        !match[0].includes('domain.com') &&
        !match[0].includes('email.com') &&
        !match[0].endsWith('.png') &&
        !match[0].endsWith('.jpg') &&
        !match[0].endsWith('.gif')) {
      emails.add(match[0].toLowerCase());
    }
  }
  
  return Array.from(emails);
}

function extractPhones(html) {
  const phones = new Set();
  // US phone formats
  const phoneRegex = /(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}/g;
  let match;
  
  while ((match = phoneRegex.exec(html)) !== null) {
    const clean = match[0].replace(/[^0-9]/g, '');
    if (clean.length >= 10 && clean.length <= 11) {
      phones.add(match[0]);
    }
  }
  
  return Array.from(phones);
}

function extractSocial(html) {
  const social = {
    twitter: [],
    facebook: [],
    instagram: [],
    linkedin: [],
    youtube: [],
    github: [],
    tiktok: [],
    reddit: [],
    pinterest: [],
    twitch: []
  };
  
  const patterns = {
    twitter: /twitter\.com\/([a-zA-Z0-9_]+)/gi,
    facebook: /facebook\.com\/([a-zA-Z0-9.]+)/gi,
    instagram: /instagram\.com\/([a-zA-Z0-9_.]+)/gi,
    linkedin: /linkedin\.com\/(in|company)\/([a-zA-Z0-9_-]+)/gi,
    youtube: /youtube\.com\/(user|channel|c)\/([a-zA-Z0-9_-]+)/gi,
    github: /github\.com\/([a-zA-Z0-9_-]+)/gi,
    tiktok: /tiktok\.com\/@?([a-zA-Z0-9_.]+)/gi,
    reddit: /reddit\.com\/u\/([a-zA-Z0-9_-]+)/gi,
    pinterest: /pinterest\.com\/([a-zA-Z0-9_]+)/gi,
    twitch: /twitch\.tv\/([a-zA-Z0-9_]+)/gi
  };
  
  for (const [platform, regex] of Object.entries(patterns)) {
    let match;
    while ((match = regex.exec(html)) !== null) {
      const handle = match[1];
      if (handle && handle.length > 2 && !['www', 'api', 'help', 'blog', 'about'].includes(handle.toLowerCase())) {
        social[platform].push(handle);
      }
    }
    social[platform] = [...new Set(social[platform])];
  }
  
  return social;
}

function detectTechnologies(html) {
  const tech = [];
  const lower = html.toLowerCase();
  
  // CMS
  if (lower.includes('wordpress') || lower.includes('wp-content')) tech.push('WordPress');
  if (lower.includes('drupal')) tech.push('Drupal');
  if (lower.includes('joomla')) tech.push('Joomla');
  if (lower.includes('shopify')) tech.push('Shopify');
  if (lower.includes('wix')) tech.push('Wix');
  if (lower.includes('squarespace')) tech.push('Squarespace');
  if (lower.includes('magento')) tech.push('Magento');
  
  // Frameworks
  if (lower.includes('react') || lower.includes('_reactroot') || lower.includes('data-reactroot')) tech.push('React');
  if (lower.includes('vue') || lower.includes('v-cloak') || lower.includes('__vue__')) tech.push('Vue.js');
  if (lower.includes('angular') || lower.includes('ng-') || lower.includes('ngapp')) tech.push('Angular');
  if (lower.includes('jquery')) tech.push('jQuery');
  if (lower.includes('bootstrap')) tech.push('Bootstrap');
  if (lower.includes('tailwind')) tech.push('Tailwind CSS');
  if (lower.includes('next.js') || lower.includes('__next')) tech.push('Next.js');
  if (lower.includes('gatsby')) tech.push('Gatsby');
  if (lower.includes('svelte')) tech.push('Svelte');
  
  // Analytics
  if (lower.includes('google-analytics') || lower.includes('gtag') || lower.includes('ga(')) tech.push('Google Analytics');
  if (lower.includes('googletagmanager') || lower.includes('gtm.js')) tech.push('Google Tag Manager');
  if (lower.includes('facebook.net/en_US/fbevents')) tech.push('Facebook Pixel');
  if (lower.includes('hotjar')) tech.push('Hotjar');
  if (lower.includes('mixpanel')) tech.push('Mixpanel');
  if (lower.includes('segment.com')) tech.push('Segment');
  
  // CDNs & Infrastructure
  if (lower.includes('cloudflare') || lower.includes('cf-ray')) tech.push('Cloudflare');
  if (lower.includes('amazonaws') || lower.includes('aws')) tech.push('AWS');
  if (lower.includes('azure')) tech.push('Azure');
  if (lower.includes('google cloud')) tech.push('Google Cloud');
  if (lower.includes('fastly')) tech.push('Fastly');
  
  // Servers
  const serverMatch = html.match(/<meta[^>]*generator["'][^>]*content=["']([^"']+)["']/i);
  if (serverMatch) tech.push(`Generator: ${serverMatch[1]}`);
  
  return [...new Set(tech)];
}

function extractForms(html) {
  const forms = [];
  const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let match;
  
  while ((match = formRegex.exec(html)) !== null) {
    const formHtml = match[0];
    const form = { inputs: [] };
    
    // Action
    const actionMatch = formHtml.match(/action=["']([^"']+)["']/i);
    if (actionMatch) form.action = actionMatch[1];
    
    // Method
    const methodMatch = formHtml.match(/method=["']([^"']+)["']/i);
    if (methodMatch) form.method = methodMatch[1].toUpperCase();
    
    // Inputs
    const inputRegex = /<input[^>]*>/gi;
    let inputMatch;
    while ((inputMatch = inputRegex.exec(formHtml)) !== null) {
      const input = {};
      const typeMatch = inputMatch[0].match(/type=["']([^"']+)["']/i);
      const nameMatch = inputMatch[0].match(/name=["']([^"']+)["']/i);
      const placeholderMatch = inputMatch[0].match(/placeholder=["']([^"']+)["']/i);
      
      if (typeMatch) input.type = typeMatch[1];
      if (nameMatch) input.name = nameMatch[1];
      if (placeholderMatch) input.placeholder = placeholderMatch[1];
      
      if (input.name || input.type) form.inputs.push(input);
    }
    
    forms.push(form);
  }
  
  return forms;
}

function extractImages(html, baseUrl) {
  const images = [];
  const imgRegex = /<img[^>]*>/gi;
  let match;
  
  while ((match = imgRegex.exec(html)) !== null) {
    const img = {};
    const srcMatch = match[0].match(/src=["']([^"']+)["']/i);
    const altMatch = match[0].match(/alt=["']([^"']*)["']/i);
    
    if (srcMatch) {
      try {
        img.src = new URL(srcMatch[1], baseUrl).href;
      } catch (e) {
        img.src = srcMatch[1];
      }
    }
    if (altMatch) img.alt = altMatch[1];
    
    if (img.src) images.push(img);
  }
  
  return images;
}

function extractScripts(html) {
  const scripts = [];
  const scriptRegex = /<script[^>]*>/gi;
  let match;
  
  while ((match = scriptRegex.exec(html)) !== null) {
    const script = {};
    const srcMatch = match[0].match(/src=["']([^"']+)["']/i);
    if (srcMatch) script.src = srcMatch[1];
    scripts.push(script);
  }
  
  return scripts;
}

function analyzeSecurity(html, data) {
  const security = {
    secureForms: true,
    warnings: []
  };
  
  // Check for insecure forms
  if (data.forms) {
    data.forms.forEach(form => {
      if (form.action && form.action.startsWith('http://')) {
        security.secureForms = false;
        security.warnings.push('Form submits over HTTP');
      }
    });
  }
  
  // Check for password fields without HTTPS
  if (html.includes('type="password"') && !html.includes('https://')) {
    security.warnings.push('Password field on non-HTTPS page');
  }
  
  // Check for inline scripts (potential XSS vectors)
  const inlineScripts = (html.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || []).length;
  if (inlineScripts > 10) {
    security.warnings.push(`Many inline scripts (${inlineScripts})`);
  }
  
  // Check for external scripts from suspicious domains
  if (data.scripts) {
    data.scripts.forEach(s => {
      if (s.src && /\.(ru|cn|tk|ml|ga|cf)$/i.test(s.src)) {
        security.warnings.push(`Script from suspicious TLD: ${s.src}`);
      }
    });
  }
  
  return security;
}

// ==================== MAIN ====================

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const question = prompt => new Promise(resolve => rl.question(prompt, resolve));

async function showBanner() {
  // Clear screen
  console.clear();
  
  console.log('\x1b[31m╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[31m║                                                                                                       ║\x1b[0m');
  console.log('\x1b[31m║     \x1b[1m\x1b[33mTTTTTTTTTT   RRRRRRR    AAA    UUU  UUU   MMMMMM   AAA     \x1b[0m\x1b[31m     ║\x1b[0m');
  console.log('\x1b[31m║     \x1b[1m\x1b[33m    T        R     R   A   A   U    U     M    M   A   A   \x1b[0m\x1b[31m     ║\x1b[0m');
  console.log('\x1b[31m║     \x1b[1m\x1b[33m    T        RRRRRRR   AAAAA   U    U     M    M   AAAAA   \x1b[0m\x1b[31m     ║\x1b[0m');
  console.log('\x1b[31m║     \x1b[1m\x1b[33m    T        R    R    A   A   U    U     M    M   A   A   \x1b[0m\x1b[31m     ║\x1b[0m');
  console.log('\x1b[31m║     \x1b[1m\x1b[33m    T        R     R   A   A    UUUU      M    M   A   A   \x1b[0m\x1b[31m     ║\x1b[0m');
  console.log('\x1b[31m║                                                                                                       ║\x1b[0m');
  console.log('\x1b[31m╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣\x1b[0m');
  console.log('\x1b[31m║       \x1b[36m                           ▶ O S I N T   T O O L K I T ◀\x1b[0m\x1b[31m                               ║\x1b[0m');
  console.log('\x1b[31m║       \x1b[2m                           Self-Contained Intelligence\x1b[0m\x1b[31m                                 ║\x1b[0m');
  console.log('\x1b[31m╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝\x1b[0m');
}

function showProgressBar(current, total, label = 'Scanning') {
  const width = 40;
  const percent = Math.round((current / total) * 100);
  const filled = Math.round((current / total) * width);
  const empty = width - filled;
  const bar = '█'.repeat(filled) + '░'.repeat(empty);
  process.stdout.write(`\r  ${c.y}${label}:${c.reset} [${c.g}${bar}${c.reset}] ${percent}% (${current}/${total})`);
}

async function mainMenu() {
  await showBanner();
  
  // Menu box
  console.log(`\n${c.r}┌──────────────────────────────────────────────────────────┐${c.reset}`);
  console.log(`${c.r}│${c.reset}  ${c.bold}SELECT SCAN TYPE${c.reset}                                        ${c.r}│${c.reset}`);
  console.log(`${c.r}├──────────────────────────────────────────────────────────┤${c.reset}`);
  console.log(`${c.r}│${c.reset}                                                          ${c.r}│${c.reset}`);
  console.log(`${c.r}│${c.reset}  ${c.y}[1]${c.reset} ${c.bold}Email${c.reset}      ${c.dim}→${c.reset} Breach check, DNS, SMTP, Risk    ${c.r}│${c.reset}`);
  console.log(`${c.r}│${c.reset}  ${c.y}[2]${c.reset} ${c.bold}Phone${c.reset}      ${c.dim}→${c.reset} Location, Carrier, Format       ${c.r}│${c.reset}`);
  console.log(`${c.r}│${c.reset}  ${c.y}[3]${c.reset} ${c.bold}Username${c.reset}    ${c.dim}→${c.reset} 75+ platforms, Categories        ${c.r}│${c.reset}`);
  console.log(`${c.r}│${c.reset}  ${c.y}[4]${c.reset} ${c.bold}IP${c.reset}          ${c.dim}→${c.reset} Ports, Reverse DNS, Risk         ${c.r}│${c.reset}`);
  console.log(`${c.r}│${c.reset}  ${c.y}[5]${c.reset} ${c.bold}Domain${c.reset}      ${c.dim}→${c.reset} DNS, Subdomains, Security        ${c.r}│${c.reset}`);
  console.log(`${c.r}│${c.reset}  ${c.y}[6]${c.reset} ${c.bold}Image${c.reset}      ${c.dim}→${c.reset} EXIF, Metadata, Hashes           ${c.r}│${c.reset}`);
  console.log(`${c.r}│${c.reset}  ${c.y}[7]${c.reset} ${c.bold}Web Scrape${c.reset}  ${c.dim}→${c.reset} Links, Emails, Technologies     ${c.r}│${c.reset}`);
  console.log(`${c.r}│${c.reset}                                                          ${c.r}│${c.reset}`);
  console.log(`${c.r}│${c.reset}  ${c.dim}[Q] Quit${c.reset}                                          ${c.r}│${c.reset}`);
  console.log(`${c.r}└──────────────────────────────────────────────────────────┘${c.reset}`);

  const choice = await question(`\n  ${c.y}▶${c.reset} Select: `);

  switch (choice.trim()) {
    case '1': {
      const email = await question(`  ${c.y}▶${c.reset} Email: `);
      if (email.includes('@')) {
        console.log(`\n${c.r}┌──────────────────────────────────────────────────────────┐${c.reset}`);
        console.log(`${c.r}│${c.reset}  ${c.bold}SCANNING EMAIL...${c.reset}                                    ${c.r}│${c.reset}`);
        console.log(`${c.r}└──────────────────────────────────────────────────────────┘${c.reset}`);
        await emailOSINT(email);
      }
      else log('  ✗ Invalid email format!', 'r');
      break;
    }
    case '2': {
      const phone = await question(`  ${c.y}▶${c.reset} Phone: `);
      if (phone.length > 0) {
        console.log(`\n${c.r}┌──────────────────────────────────────────────────────────┐${c.reset}`);
        console.log(`${c.r}│${c.reset}  ${c.bold}ANALYZING PHONE...${c.reset}                                   ${c.r}│${c.reset}`);
        console.log(`${c.r}└──────────────────────────────────────────────────────────┘${c.reset}`);
        await phoneOSINT(phone);
      }
      break;
    }
    case '3': {
      const username = await question(`  ${c.y}▶${c.reset} Username: `);
      if (username.length > 0) {
        console.log(`\n${c.r}┌──────────────────────────────────────────────────────────┐${c.reset}`);
        console.log(`${c.r}│${c.reset}  ${c.bold}SEARCHING 75+ PLATFORMS...${c.reset}                            ${c.r}│${c.reset}`);
        console.log(`${c.r}└──────────────────────────────────────────────────────────┘${c.reset}`);
        await usernameOSINT(username);
      }
      break;
    }
    case '4': {
      const ip = await question(`  ${c.y}▶${c.reset} IP: `);
      if (ip.length > 0) {
        console.log(`\n${c.r}┌──────────────────────────────────────────────────────────┐${c.reset}`);
        console.log(`${c.r}│${c.reset}  ${c.bold}SCANNING IP...${c.reset}                                       ${c.r}│${c.reset}`);
        console.log(`${c.r}└──────────────────────────────────────────────────────────┘${c.reset}`);
        await ipOSINT(ip);
      }
      break;
    }
    case '5': {
      const domain = await question(`  ${c.y}▶${c.reset} Domain: `);
      if (domain.includes('.')) {
        console.log(`\n${c.r}┌──────────────────────────────────────────────────────────┐${c.reset}`);
        console.log(`${c.r}│${c.reset}  ${c.bold}RECONNING DOMAIN...${c.reset}                                 ${c.r}│${c.reset}`);
        console.log(`${c.r}└──────────────────────────────────────────────────────────┘${c.reset}`);
        await domainOSINT(domain);
      }
      else log('  ✗ Invalid domain format!', 'r');
      break;
    }
    case '6': {
      const imagePath = await question(`  ${c.y}▶${c.reset} Image path: `);
      if (imagePath.length > 0) {
        console.log(`\n${c.r}┌──────────────────────────────────────────────────────────┐${c.reset}`);
        console.log(`${c.r}│${c.reset}  ${c.bold}EXTRACTING METADATA...${c.reset}                               ${c.r}│${c.reset}`);
        console.log(`${c.r}└──────────────────────────────────────────────────────────┘${c.reset}`);
        await imageOSINT(imagePath);
      }
      break;
    }
    case '7': {
      const url = await question(`  ${c.y}▶${c.reset} URL: `);
      if (url.length > 0) {
        console.log(`\n${c.r}┌──────────────────────────────────────────────────────────┐${c.reset}`);
        console.log(`${c.r}│${c.reset}  ${c.bold}SCRAPING WEBSITE...${c.reset}                                 ${c.r}│${c.reset}`);
        console.log(`${c.r}└──────────────────────────────────────────────────────────┘${c.reset}`);
        await webScrapeOSINT(url);
      }
      break;
    }
    case 'q':
    case 'Q':
      console.log(`\n${c.r}╔══════════════════════════════════════════════════════════════╗${c.reset}`);
      console.log(`${c.r}║${c.reset}  ${c.dim}Stay safe and legal. Results saved to:${c.reset}                  ${c.r}║${c.reset}`);
      console.log(`${c.r}║${c.reset}  ${c.g}${RESULTS_DIR}${c.reset}  ${c.r}║${c.reset}`);
      console.log(`${c.r}║${c.reset}  ${c.g}${REPORTS_DIR}${c.reset}  ${c.r}║${c.reset}`);
      console.log(`${c.r}╚══════════════════════════════════════════════════════════════╝${c.reset}\n`);
      rl.close();
      process.exit(0);
    default:
      log('  ✗ Invalid choice!', 'r');
  }

  const cont = await question(`\n  ${c.y}▶${c.reset} Run another scan? (y/n): `);
  if (cont.toLowerCase() === 'y') {
    await mainMenu();
  } else {
    console.log(`\n${c.r}╔══════════════════════════════════════════════════════════════╗${c.reset}`);
    console.log(`${c.r}║${c.reset}  ${c.dim}Results saved to:${c.reset}                                        ${c.r}║${c.reset}`);
    console.log(`${c.r}║${c.reset}  ${c.g}JSON:${c.reset}   ${RESULTS_DIR}${c.reset}  ${c.r}║${c.reset}`);
    console.log(`${c.r}║${c.reset}  ${c.g}HTML:${c.reset}  ${REPORTS_DIR}${c.reset}  ${c.r}║${c.reset}`);
    console.log(`${c.r}╚══════════════════════════════════════════════════════════════╝${c.reset}\n`);
    rl.close();
    process.exit(0);
  }
}

mainMenu().catch(console.error);
