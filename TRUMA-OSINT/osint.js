#!/usr/bin/env node

const dns = require('dns').promises;
const net = require('net');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const os = require('os');

// Get the correct directory for both dev and pkg EXE
const APP_DIR = process.pkg ? path.dirname(process.execPath) : __dirname;

// License System - with error handling for EXE
let licenseModule = {};
let remoteValidator = null;
try {
  // Try remote license validator first (preferred)
  remoteValidator = new (require('../shared-remote-license'))('osint');
} catch (e) {}
try {
  // Try shared license first (unified across all TRAUMA tools)
  licenseModule = require('../shared-license');
} catch (e) {
  try {
    licenseModule = require('./license');
  } catch (e2) {
    try {
      licenseModule = require(path.join(APP_DIR, 'license.js'));
    } catch (e3) {
      console.log('Warning: license module not found');
      licenseModule = { 
        checkLicense: () => ({ valid: false, message: 'License module not found' }),
        activateLicense: () => false,
        generateLicenseKey: () => null
      };
    }
  }
}
const { checkLicense, activateLicense, generateLicenseKey } = licenseModule;

// API Integration - with error handling
let apiModule = { API_CONFIG: {}, isAPIConfigured: () => false, apiRequest: async () => ({ error: 'Not configured' }) };
try {
  apiModule = require('./api-config');
} catch (e) {
  try {
    apiModule = require(path.join(APP_DIR, 'api-config.js'));
  } catch (e2) {
    // API optional, continue without
  }
}
const { API_CONFIG, isAPIConfigured, apiRequest } = apiModule;

// Directories - use APP_DIR for EXE compatibility
const RESULTS_DIR = path.join(APP_DIR, 'results');
const REPORTS_DIR = path.join(APP_DIR, 'reports');
const CACHE_DIR = path.join(APP_DIR, 'cache');
const LICENSES_DIR = path.join(APP_DIR, 'licenses');

// Create directories if they don't exist
[RESULTS_DIR, REPORTS_DIR, CACHE_DIR, LICENSES_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Report generator - with error handling
let generateReport = (type, data) => `<html><body><pre>${JSON.stringify(data, null, 2)}</pre></body></html>`;
try {
  const reportMod = require('./report-template');
  generateReport = reportMod.generateReport || generateReport;
} catch (e) {
  try {
    const reportMod = require(path.join(APP_DIR, 'report-template.js'));
    generateReport = reportMod.generateReport || generateReport;
  } catch (e2) {
    // Use default simple report
  }
}

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
    'adobe.com': { name: 'Adobe', date: '2013', records: '153M', severity: 'high' },
    'linkedin.com': { name: 'LinkedIn', date: '2012', records: '164M', severity: 'high' },
    'dropbox.com': { name: 'Dropbox', date: '2012', records: '68M', severity: 'medium' },
    'yahoo.com': { name: 'Yahoo', date: '2013', records: '3B', severity: 'critical' },
    'myfitnesspal.com': { name: 'MyFitnessPal', date: '2018', records: '151M', severity: 'high' },
    'canva.com': { name: 'Canva', date: '2019', records: '137M', severity: 'medium' },
    'tumblr.com': { name: 'Tumblr', date: '2013', records: '65M', severity: 'medium' },
    'ashleymadison.com': { name: 'Ashley Madison', date: '2015', records: '32M', severity: 'critical' },
    'marriott.com': { name: 'Marriott', date: '2018', records: '500M', severity: 'critical' },
    'equifax.com': { name: 'Equifax', date: '2017', records: '145M', severity: 'critical' },
    'facebook.com': { name: 'Facebook', date: '2019', records: '540M', severity: 'critical' },
    'twitter.com': { name: 'Twitter', date: '2020', records: '330M', severity: 'high' },
    'samsung.com': { name: 'Samsung', date: '2020', records: '150M', severity: 'high' },
    'spotify.com': { name: 'Spotify', date: '2020', records: '300K', severity: 'medium' },
    'zoom.us': { name: 'Zoom', date: '2020', records: '500K', severity: 'medium' },
    'epicgames.com': { name: 'Epic Games', date: '2020', records: '350K', severity: 'medium' },
    'dubsmash.com': { name: 'Dubsmash', date: '2019', records: '162M', severity: 'high' },
    'myheritage.com': { name: 'MyHeritage', date: '2018', records: '92M', severity: 'high' },
    'zomato.com': { name: 'Zomato', date: '2019', records: '17M', severity: 'medium' },
    'quora.com': { name: 'Quora', date: '2018', records: '100M', severity: 'medium' },
    'deezer.com': { name: 'Deezer', date: '2019', records: '250M', severity: 'high' },
    'gfy.com': { name: 'Gfy', date: '2020', records: '870M', severity: 'critical' },
    'wattpad.com': { name: 'Wattpad', date: '2020', records: '270M', severity: 'high' },
    'linkedin.com': { name: 'LinkedIn (2021)', date: '2021', records: '700M', severity: 'critical' },
    'twitch.tv': { name: 'Twitch', date: '2021', records: '135M', severity: 'high' },
    'panerabread.com': { name: 'Panera', date: '2018', records: '37M', severity: 'medium' },
    'underarmour.com': { name: 'Under Armour', date: '2018', records: '150M', severity: 'high' },
    'shein.com': { name: 'SHEIN', date: '2020', records: '39M', severity: 'medium' },
    'wish.com': { name: 'Wish', date: '2020', records: '300M', severity: 'high' }
  },
  disposable: ['tempmail', 'guerrilla', '10minutemail', 'throwaway', 'mailinator', 'yopmail', 'fakeinbox', 'sharklasers', 'guerrillamail', 'grrrr', 'trashmail', 'getairmail', 'maildrop', 'mailnesia', 'tempail', 'mohammadjavad', 'emailfake', 'emailtemp', 'fakeemail', 'tempmailo', 'dispostable', 'mailcatch', 'spambox', 'spamfree', 'spambox', 'jetable', 'yopmail', 'fastmail', 'protonmail', 'tutanota'],
  knownHashes: ['5baa6', 'e99a1', 'd8578', '90f2b', '5f4dc', 'b2aeb', 'a1d0c', 'e10ad', 'c4ca4', 'c81e7', 'eccbc', 'a87ff', 'e4da3', '16790', '45c48', 'c9f0f', 'b2aeb'],
  spamKeywords: ['promo', 'newsletter', 'marketing', 'noreply', 'no-reply', 'donotreply', 'notifications', 'alerts', 'updates']
};

// Extended IP Geolocation Database
const IP_GEO_DB = {
  ranges: {
    '1.0': { country: 'Australia', city: 'Sydney', isp: 'Telstra' },
    '1.1': { country: 'Australia', city: 'Melbourne', isp: 'Telstra' },
    '1.2': { country: 'Australia', city: 'Brisbane', isp: 'Telstra' },
    '1.3': { country: 'Australia', city: 'Perth', isp: 'Telstra' },
    '2.0': { country: 'France', city: 'Paris', isp: 'Orange' },
    '2.1': { country: 'France', city: 'Lyon', isp: 'Orange' },
    '3.0': { country: 'USA', city: 'New York', isp: 'Verizon' },
    '3.1': { country: 'USA', city: 'Los Angeles', isp: 'Verizon' },
    '3.2': { country: 'USA', city: 'Chicago', isp: 'Verizon' },
    '4.0': { country: 'UK', city: 'London', isp: 'BT' },
    '4.1': { country: 'UK', city: 'Manchester', isp: 'BT' },
    '5.0': { country: 'Germany', city: 'Berlin', isp: 'Deutsche Telekom' },
    '5.1': { country: 'Germany', city: 'Munich', isp: 'Deutsche Telekom' },
    '6.0': { country: 'Japan', city: 'Tokyo', isp: 'NTT' },
    '6.1': { country: 'Japan', city: 'Osaka', isp: 'NTT' },
    '7.0': { country: 'Russia', city: 'Moscow', isp: 'Rostelecom' },
    '8.0': { country: 'USA', city: 'Various', isp: 'Level3' },
    '8.1': { country: 'USA', city: 'Various', isp: 'Level3' },
    '8.8': { country: 'USA', city: 'Mountain View', isp: 'Google DNS' },
    '8.26': { country: 'USA', city: 'Various', isp: 'Level3' },
    '9.0': { country: 'USA', city: 'Various', isp: 'IBM' },
    '10.0': { country: 'Private', city: 'LAN', isp: 'Private Network' },
    '11.0': { country: 'USA', city: 'Various', isp: 'DoD' },
    '12.0': { country: 'USA', city: 'Various', isp: 'AT&T' },
    '13.0': { country: 'USA', city: 'Various', isp: 'Xerox' },
    '14.0': { country: 'USA', city: 'Various', isp: 'HP' },
    '15.0': { country: 'USA', city: 'Various', isp: 'HP' },
    '16.0': { country: 'USA', city: 'Various', isp: 'DEC' },
    '17.0': { country: 'USA', city: 'Cupertino', isp: 'Apple' },
    '18.0': { country: 'USA', city: 'Cambridge', isp: 'MIT' },
    '19.0': { country: 'USA', city: 'Various', isp: 'Ford' },
    '20.0': { country: 'USA', city: 'Various', isp: 'Microsoft' },
    '23.0': { country: 'USA', city: 'Various', isp: 'Akamai' },
    '24.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '31.0': { country: 'UK', city: 'London', isp: 'BT' },
    '32.0': { country: 'USA', city: 'Various', isp: 'AT&T' },
    '34.0': { country: 'USA', city: 'Various', isp: 'Google Cloud' },
    '35.0': { country: 'USA', city: 'Various', isp: 'Google Cloud' },
    '37.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '40.0': { country: 'USA', city: 'Various', isp: 'Microsoft Azure' },
    '44.0': { country: 'USA', city: 'Various', isp: 'Ham Radio' },
    '45.0': { country: 'USA', city: 'Various', isp: 'Various' },
    '46.0': { country: 'Germany', city: 'Various', isp: 'Hetzner' },
    '47.0': { country: 'USA', city: 'Various', isp: 'NordVPN' },
    '50.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '51.0': { country: 'UK', city: 'London', isp: 'Sky' },
    '52.0': { country: 'USA', city: 'Various', isp: 'Microsoft Azure' },
    '54.0': { country: 'USA', city: 'Various', isp: 'Amazon AWS' },
    '64.0': { country: 'USA', city: 'Various', isp: 'Various' },
    '66.0': { country: 'USA', city: 'Various', isp: 'AT&T' },
    '67.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '68.0': { country: 'USA', city: 'Various', isp: 'AT&T' },
    '69.0': { country: 'USA', city: 'Various', isp: 'Various' },
    '70.0': { country: 'USA', city: 'Various', isp: 'Various' },
    '71.0': { country: 'USA', city: 'Various', isp: 'Verizon' },
    '72.0': { country: 'USA', city: 'Various', isp: 'AT&T' },
    '73.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '74.0': { country: 'USA', city: 'Various', isp: 'Verizon' },
    '75.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '76.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '77.0': { country: 'UK', city: 'London', isp: 'TalkTalk' },
    '78.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '79.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '80.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '81.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '82.0': { country: 'UK', city: 'Various', isp: 'Sky' },
    '83.0': { country: 'UK', city: 'Various', isp: 'Sky' },
    '84.0': { country: 'Germany', city: 'Various', isp: 'Deutsche Telekom' },
    '85.0': { country: 'Germany', city: 'Various', isp: 'Deutsche Telekom' },
    '86.0': { country: 'Germany', city: 'Various', isp: 'Deutsche Telekom' },
    '87.0': { country: 'Germany', city: 'Various', isp: 'Deutsche Telekom' },
    '88.0': { country: 'Germany', city: 'Various', isp: 'Deutsche Telekom' },
    '89.0': { country: 'Germany', city: 'Various', isp: 'Deutsche Telekom' },
    '91.0': { country: 'Russia', city: 'Various', isp: 'MTS' },
    '92.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '93.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '94.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '95.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '96.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '97.0': { country: 'Germany', city: 'Various', isp: 'Vodafone' },
    '98.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '99.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '100.0': { country: 'USA', city: 'Various', isp: 'Various' },
    '104.0': { country: 'USA', city: 'Various', isp: 'Cloudflare' },
    '108.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '109.0': { country: 'UK', city: 'London', isp: 'Virgin Media' },
    '111.0': { country: 'Australia', city: 'Various', isp: 'Telstra' },
    '112.0': { country: 'China', city: 'Beijing', isp: 'China Telecom' },
    '113.0': { country: 'China', city: 'Shanghai', isp: 'China Telecom' },
    '114.0': { country: 'China', city: 'Guangzhou', isp: 'China Telecom' },
    '115.0': { country: 'China', city: 'Shenzhen', isp: 'China Telecom' },
    '116.0': { country: 'China', city: 'Beijing', isp: 'China Unicom' },
    '117.0': { country: 'China', city: 'Shanghai', isp: 'China Unicom' },
    '118.0': { country: 'China', city: 'Various', isp: 'China Mobile' },
    '119.0': { country: 'China', city: 'Various', isp: 'China Mobile' },
    '120.0': { country: 'China', city: 'Various', isp: 'China Mobile' },
    '121.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '122.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '123.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '124.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '125.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '126.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '127.0': { country: 'Localhost', city: 'Local', isp: 'Loopback' },
    '128.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '129.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '130.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '131.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '132.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '133.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '134.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '135.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '136.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '137.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '138.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '139.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '140.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '141.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '142.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '143.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '144.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '145.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '146.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '147.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '148.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '149.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '150.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '151.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '152.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '153.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '154.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '155.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '156.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '157.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '158.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '159.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '160.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '161.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '162.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '163.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '164.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '165.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '166.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '167.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '168.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '169.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '170.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '171.0': { country: 'USA', city: 'Various', isp: 'Various Universities' },
    '172.0': { country: 'Private', city: 'LAN', isp: 'Private Network' },
    '173.0': { country: 'USA', city: 'Various', isp: 'Comcast' },
    '174.0': { country: 'USA', city: 'Various', isp: 'Various' },
    '175.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '176.0': { country: 'Germany', city: 'Various', isp: 'Deutsche Telekom' },
    '177.0': { country: 'Brazil', city: 'Sao Paulo', isp: 'Claro' },
    '178.0': { country: 'Germany', city: 'Various', isp: 'Deutsche Telekom' },
    '179.0': { country: 'Germany', city: 'Various', isp: 'Deutsche Telekom' },
    '180.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '181.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '182.0': { country: 'India', city: 'Mumbai', isp: 'Airtel' },
    '183.0': { country: 'India', city: 'Delhi', isp: 'Airtel' },
    '184.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '185.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '186.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '187.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '188.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '189.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '190.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '191.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '192.0': { country: 'Private', city: 'LAN', isp: 'Private Network' },
    '193.0': { country: 'UK', city: 'London', isp: 'BT' },
    '194.0': { country: 'UK', city: 'Various', isp: 'BT' },
    '195.0': { country: 'UK', city: 'Various', isp: 'BT' },
    '196.0': { country: 'South Africa', city: 'Johannesburg', isp: 'Telkom' },
    '197.0': { country: 'South Africa', city: 'Cape Town', isp: 'Telkom' },
    '198.0': { country: 'USA', city: 'Various', isp: 'Various' },
    '199.0': { country: 'USA', city: 'Various', isp: 'Various' },
    '200.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '201.0': { country: 'Brazil', city: 'Various', isp: 'Claro' },
    '202.0': { country: 'India', city: 'Various', isp: 'Airtel' },
    '203.0': { country: 'Australia', city: 'Various', isp: 'Telstra' },
    '210.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '211.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '212.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '213.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '216.0': { country: 'USA', city: 'Various', isp: 'Various' },
    '217.0': { country: 'UK', city: 'Various', isp: 'Sky' },
    '218.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '219.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '220.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '221.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '222.0': { country: 'China', city: 'Various', isp: 'China Telecom' },
    '223.0': { country: 'China', city: 'Various', isp: 'China Telecom' }
  }
};

// ==================== EMAIL OSINT ====================

async function emailOSINT(email) {
  log(`\n${'═'.repeat(60)}`, 'c');
  log(`  EMAIL OSINT: ${email}`, 'bold');
  log(`${'═'.repeat(60)}`, 'c');

  const results = { email, timestamp: new Date().toISOString(), data: {}, breach: {}, social: {}, reputation: {} };
  const [local, domain] = email.split('@');

  // 1. Validation & Analysis
  log('\n  [1] VALIDATION & ANALYSIS', 'y');
  const valid = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
  const isDisposable = BREACH_DB.disposable.some(d => domain.toLowerCase().includes(d));
  const isRole = ['admin', 'info', 'support', 'sales', 'noreply', 'no-reply', 'donotreply', 'help', 'contact', 'webmaster', 'postmaster', 'hostmaster'].some(r => local.toLowerCase() === r);
  const isSpamKeyword = BREACH_DB.spamKeywords.some(k => local.toLowerCase().includes(k));
  
  // Analyze local part patterns
  const hasNumbers = /\d/.test(local);
  const hasSpecial = /[^a-zA-Z0-9]/.test(local);
  const localLength = local.length;
  const looksRandom = localLength > 8 && hasNumbers && hasSpecial && !local.match(/[a-zA-Z]{4,}/);
  
  results.data.valid = valid;
  results.data.disposable = isDisposable;
  results.data.role = isRole;
  results.data.spamKeyword = isSpamKeyword;
  results.data.localAnalysis = { hasNumbers, hasSpecial, localLength, looksRandom };
  
  log(`      Valid: ${valid ? 'YES' : 'NO'}`, valid ? 'g' : 'r');
  log(`      Disposable: ${isDisposable ? 'YES' : 'NO'}`, isDisposable ? 'r' : 'g');
  log(`      Role account: ${isRole ? 'YES' : 'NO'}`, isRole ? 'y' : 'dim');
  log(`      Spam keyword: ${isSpamKeyword ? 'YES' : 'NO'}`, isSpamKeyword ? 'y' : 'dim');
  log(`      Looks random: ${looksRandom ? 'YES' : 'NO'}`, looksRandom ? 'y' : 'dim');

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
      
      // Check for enterprise email providers
      const enterpriseProviders = ['google', 'outlook', 'microsoft', 'amazon', 'googlemail'];
      const isEnterprise = enterpriseProviders.some(p => mx[0].exchange.toLowerCase().includes(p));
      results.data.enterpriseEmail = isEnterprise;
      if (isEnterprise) log(`      Enterprise Email: YES`, 'g');
    }
  } catch (e) { log('      MX: None', 'r'); }

  try {
    const txt = await dns.resolveTxt(domain);
    results.data.spf = txt.some(t => t.join('').includes('v=spf'));
    results.data.dmarc = txt.some(t => t.join('').includes('v=dmarc'));
    results.data.dkim = txt.some(t => t.join('').includes('v=dkim'));
    log(`      SPF: ${results.data.spf ? 'YES' : 'NO'}`, results.data.spf ? 'g' : 'y');
    log(`      DMARC: ${results.data.dmarc ? 'YES' : 'NO'}`, results.data.dmarc ? 'g' : 'y');
    log(`      DKIM: ${results.data.dkim ? 'YES' : 'NO'}`, results.data.dkim ? 'g' : 'y');
  } catch (e) {}

  // 3. SMTP Test
  log('\n  [3] SMTP TEST', 'y');
  if (results.data.mx?.length > 0) {
    const mxHost = results.data.mx[0].exchange;
    const smtpOpen = await testPort(mxHost, 25);
    const smtpsOpen = await testPort(mxHost, 465);
    const smtpTlsOpen = await testPort(mxHost, 587);
    results.data.smtp = { port25: smtpOpen, port465: smtpsOpen, port587: smtpTlsOpen };
    log(`      Port 25: ${smtpOpen ? 'OPEN' : 'CLOSED'}`, smtpOpen ? 'g' : 'r');
    log(`      Port 465 (SMTPS): ${smtpsOpen ? 'OPEN' : 'CLOSED'}`, smtpsOpen ? 'g' : 'r');
    log(`      Port 587 (TLS): ${smtpTlsOpen ? 'OPEN' : 'CLOSED'}`, smtpTlsOpen ? 'g' : 'r');
  }

  // 4. Breach Check (Enhanced)
  log('\n  [4] BREACH CHECK', 'y');
  results.breach.domainBreaches = [];
  let criticalBreaches = 0;
  let highBreaches = 0;
  
  for (const [d, info] of Object.entries(BREACH_DB.domains)) {
    if (domain.toLowerCase().includes(d.split('.')[0])) {
      results.breach.domainBreaches.push(info);
      if (info.severity === 'critical') criticalBreaches++;
      else if (info.severity === 'high') highBreaches++;
      const severityColor = info.severity === 'critical' ? 'r' : info.severity === 'high' ? 'y' : 'dim';
      log(`      [${info.severity.toUpperCase()}] ${info.name} (${info.date}, ${info.records})`, severityColor);
    }
  }
  
  const hash = crypto.createHash('sha1').update(email.toLowerCase()).digest('hex');
  const prefix = hash.substring(0, 5);
  results.breach.exposed = BREACH_DB.knownHashes.includes(prefix);
  log(`      Known exposure: ${results.breach.exposed ? 'DETECTED' : 'Not found'}`, results.breach.exposed ? 'r' : 'g');
  
  results.breach.summary = { total: results.breach.domainBreaches.length, critical: criticalBreaches, high: highBreaches };

  // 5. Social Discovery (Enhanced)
  log('\n  [5] SOCIAL DISCOVERY', 'y');
  const gravatarHash = crypto.createHash('md5').update(email.toLowerCase().trim()).digest('hex');
  results.social.gravatar = `https://gravatar.com/avatar/${gravatarHash}`;
  results.social.gravatarProfile = `https://gravatar.com/${gravatarHash}`;
  
  // Generate username variations from email
  const usernameVariations = [
    local,
    local.toLowerCase(),
    local.replace(/[._]/g, ''),
    local.replace(/[._]/g, '-'),
    local.split(/[._]/)[0],
    local.split(/[._]/).pop()
  ].filter((v, i, a) => v && v.length > 2 && a.indexOf(v) === i);
  
  results.social.usernameVariations = usernameVariations;
  results.social.patterns = [
    `"${email}" site:facebook.com`,
    `"${email}" site:twitter.com`,
    `"${email}" site:linkedin.com`,
    `"${email}" site:github.com`,
    `"${email}" site:instagram.com`,
    `"${email}" site:reddit.com`,
    `"${email}" site:pastebin.com`,
    `"${email}" filetype:pdf`,
    `"${email}" filetype:doc`,
    `"${local}" site:facebook.com`,
    `"${local}" site:twitter.com`
  ];
  log(`      Gravatar hash: ${gravatarHash}`, 'dim');
  log(`      Username variations: ${usernameVariations.length}`, 'g');
  log(`      Search patterns: ${results.social.patterns.length}`, 'g');

  // 6. Reputation Score (New)
  log('\n  [6] REPUTATION SCORE', 'y');
  let repScore = 100;
  const repFactors = [];
  
  if (isDisposable) { repScore -= 40; repFactors.push('Disposable email (-40)'); }
  if (isRole) { repScore -= 10; repFactors.push('Role account (-10)'); }
  if (isSpamKeyword) { repScore -= 15; repFactors.push('Spam keyword in local part (-15)'); }
  if (looksRandom) { repScore -= 20; repFactors.push('Looks like random/generated (-20)'); }
  if (results.breach.exposed) { repScore -= 30; repFactors.push('Found in breach database (-30)'); }
  if (criticalBreaches > 0) { repScore -= criticalBreaches * 15; repFactors.push(`Critical breach domain (-${criticalBreaches * 15})`); }
  if (highBreaches > 0) { repScore -= highBreaches * 10; repFactors.push(`High severity breaches (-${highBreaches * 10})`); }
  if (!results.data.spf) { repScore -= 5; repFactors.push('No SPF record (-5)'); }
  if (!results.data.dmarc) { repScore -= 5; repFactors.push('No DMARC record (-5)'); }
  if (results.data.enterpriseEmail) { repScore += 10; repFactors.push('Enterprise email provider (+10)'); }
  
  repScore = Math.max(0, Math.min(100, repScore));
  results.reputation.score = repScore;
  results.reputation.factors = repFactors;
  results.reputation.level = repScore >= 80 ? 'EXCELLENT' : repScore >= 60 ? 'GOOD' : repScore >= 40 ? 'FAIR' : repScore >= 20 ? 'POOR' : 'VERY POOR';
  
  const repColor = repScore >= 60 ? 'g' : repScore >= 40 ? 'y' : 'r';
  log(`      Score: ${repScore}/100`, repColor);
  log(`      Level: ${results.reputation.level}`, repColor);
  repFactors.forEach(f => log(`        • ${f}`, 'dim'));

  // 7. Risk Score
  log('\n  [7] RISK SCORE', 'y');
  let score = 0;
  if (isDisposable) score += 2;
  if (results.breach.exposed) score += 3;
  if (results.breach.domainBreaches.length > 0) score += 2;
  if (!results.data.spf) score += 1;
  if (looksRandom) score += 2;
  if (isSpamKeyword) score += 1;
  
  results.risk = { score, level: score >= 6 ? 'CRITICAL' : score >= 4 ? 'HIGH' : score >= 2 ? 'MEDIUM' : 'LOW' };
  const riskColor = results.risk.level === 'CRITICAL' ? 'r' : results.risk.level === 'HIGH' ? 'r' : results.risk.level === 'MEDIUM' ? 'y' : 'g';
  log(`      Level: ${results.risk.level} (${score}/10)`, riskColor);

  // 8. API Integrations
  log('\n  [8] API INTEGRATIONS', 'y');
  results.apiData = {};
  
  // HaveIBeenPwned API
  if (isAPIConfigured('haveibeenpwned')) {
    log('      Checking HaveIBeenPwned...', 'dim');
    const hibpRes = await apiRequest('haveibeenpwned', 'breachedaccount', { email });
    if (!hibpRes.error && hibpRes.data) {
      results.apiData.haveibeenpwned = hibpRes.data;
      log(`      HaveIBeenPwned: ${Array.isArray(hibpRes.data) ? hibpRes.data.length + ' breaches' : 'Found'}`, 'r');
    } else {
      log(`      HaveIBeenPwned: No breaches found`, 'g');
    }
  } else {
    log('      HaveIBeenPwned: API key not configured', 'dim');
  }
  
  // Hunter.io API
  if (isAPIConfigured('hunter')) {
    log('      Checking Hunter.io...', 'dim');
    const hunterRes = await apiRequest('hunter', 'verify', { email });
    if (!hunterRes.error && hunterRes.data?.data) {
      results.apiData.hunter = hunterRes.data.data;
      const status = hunterRes.data.data.status;
      log(`      Hunter.io: ${status}`, status === 'valid' ? 'g' : status === 'invalid' ? 'r' : 'y');
    }
  } else {
    log('      Hunter.io: API key not configured', 'dim');
  }

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

  const results = { ip, timestamp: new Date().toISOString(), data: {}, geo: {}, security: {} };

  // Validate IPv4
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
    // Check for IPv6
    if (/^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':')) {
      log('  IPv6 detected - limited support', 'y');
      results.data.ipv6 = true;
    } else {
      log('  Invalid IP address!', 'r');
      return results;
    }
  }

  const [a, b, c, d] = ip.split('.').map(Number);

  // 1. Geolocation (Using internal DB)
  log('\n  [1] GEOLOCATION', 'y');
  const prefix = `${a}.${b}`;
  const geoInfo = IP_GEO_DB.ranges[prefix] || IP_GEO_DB.ranges[`${a}.0`];
  
  if (geoInfo) {
    results.geo = geoInfo;
    log(`      Country: ${geoInfo.country}`, 'g');
    if (geoInfo.city !== 'Various' && geoInfo.city !== 'LAN' && geoInfo.city !== 'Local') {
      log(`      City: ${geoInfo.city}`, 'g');
    }
    log(`      ISP: ${geoInfo.isp}`, 'g');
  } else {
    log(`      Country: Unknown`, 'y');
    log(`      ISP: Unknown`, 'y');
  }

  // 2. Reverse DNS
  log('\n  [2] REVERSE DNS', 'y');
  try {
    const hosts = await dns.reverse(ip);
    results.data.reverse = hosts;
    if (hosts.length > 0) {
      log(`      Hostnames:`, 'g');
      hosts.forEach(h => {
        log(`        ${h}`, 'dim');
        // Analyze hostname for info
        if (h.includes('cloud') || h.includes('aws') || h.includes('azure') || h.includes('gcp')) {
          results.data.cloudHosted = true;
          log(`          → Cloud hosted`, 'y');
        }
        if (h.includes('cdn') || h.includes('cloudflare') || h.includes('akamai')) {
          results.data.cdn = true;
          log(`          → CDN detected`, 'y');
        }
        if (h.includes('mail') || h.includes('smtp') || h.includes('mx')) {
          results.data.mailServer = true;
          log(`          → Mail server`, 'y');
        }
      });
    } else {
      log('      No PTR record', 'dim');
    }
  } catch (e) {
    log('      Reverse DNS failed', 'r');
  }

  // 3. Classification
  log('\n  [3] CLASSIFICATION', 'y');
  results.data.private = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  results.data.loopback = a === 127;
  results.data.multicast = a >= 224 && a <= 239;
  results.data.linkLocal = a === 169 && b === 254;
  results.data.documentation = (a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);
  results.data.shared = a === 100 && b >= 64 && b <= 127;
  results.data.benchmark = a === 198 && b === 18;
  
  const ipType = results.data.private ? 'PRIVATE' : 
                 results.data.loopback ? 'LOOPBACK' : 
                 results.data.multicast ? 'MULTICAST' : 
                 results.data.linkLocal ? 'LINK-LOCAL' : 
                 results.data.documentation ? 'DOCUMENTATION' : 'PUBLIC';
  results.data.type = ipType;
  
  log(`      Type: ${ipType}`, ipType === 'PUBLIC' ? 'g' : 'y');
  log(`      Private: ${results.data.private ? 'YES' : 'NO'}`, results.data.private ? 'y' : 'g');
  log(`      Loopback: ${results.data.loopback ? 'YES' : 'NO'}`, 'dim');
  log(`      Link-local: ${results.data.linkLocal ? 'YES' : 'NO'}`, 'dim');
  if (results.data.cloudHosted) log(`      Cloud: YES`, 'y');
  if (results.data.cdn) log(`      CDN: YES`, 'y');
  if (results.data.mailServer) log(`      Mail Server: YES`, 'y');

  // 4. Port Scan (Enhanced)
  log('\n  [4] PORT SCAN', 'y');
  const ports = [
    { port: 21, name: 'FTP', risk: 'medium' }, 
    { port: 22, name: 'SSH', risk: 'low' }, 
    { port: 23, name: 'Telnet', risk: 'high' },
    { port: 25, name: 'SMTP', risk: 'low' }, 
    { port: 53, name: 'DNS', risk: 'low' }, 
    { port: 80, name: 'HTTP', risk: 'low' },
    { port: 110, name: 'POP3', risk: 'low' }, 
    { port: 143, name: 'IMAP', risk: 'low' }, 
    { port: 443, name: 'HTTPS', risk: 'low' },
    { port: 445, name: 'SMB', risk: 'high' }, 
    { port: 993, name: 'IMAPS', risk: 'low' }, 
    { port: 1433, name: 'MSSQL', risk: 'medium' },
    { port: 3306, name: 'MySQL', risk: 'medium' },
    { port: 3389, name: 'RDP', risk: 'high' }, 
    { port: 5432, name: 'PostgreSQL', risk: 'medium' }, 
    { port: 5900, name: 'VNC', risk: 'high' },
    { port: 6379, name: 'Redis', risk: 'medium' },
    { port: 8080, name: 'HTTP-Alt', risk: 'low' },
    { port: 8443, name: 'HTTPS-Alt', risk: 'low' },
    { port: 9200, name: 'Elasticsearch', risk: 'medium' },
    { port: 27017, name: 'MongoDB', risk: 'high' }
  ];

  results.data.ports = [];
  const openPortsByRisk = { high: [], medium: [], low: [] };
  
  for (const { port, name, risk } of ports) {
    const open = await testPort(ip, port);
    if (open) {
      results.data.ports.push({ port, name, risk });
      openPortsByRisk[risk].push({ port, name });
      const riskColor = risk === 'high' ? 'r' : risk === 'medium' ? 'y' : 'g';
      log(`      ${port}/${name}: OPEN [${risk.toUpperCase()}]`, riskColor);
    }
  }
  if (results.data.ports.length === 0) log('      No open ports', 'dim');
  else log(`      Total open: ${results.data.ports.length}`, 'g');

  // 5. Security Analysis
  log('\n  [5] SECURITY ANALYSIS', 'y');
  const securityIssues = [];
  
  // Check for dangerous services
  if (results.data.ports.some(p => p.port === 23)) securityIssues.push({ issue: 'Telnet exposed (unencrypted)', severity: 'critical' });
  if (results.data.ports.some(p => p.port === 21)) securityIssues.push({ issue: 'FTP exposed (unencrypted)', severity: 'high' });
  if (results.data.ports.some(p => p.port === 3389)) securityIssues.push({ issue: 'RDP exposed (brute force target)', severity: 'high' });
  if (results.data.ports.some(p => p.port === 445)) securityIssues.push({ issue: 'SMB exposed (ransomware vector)', severity: 'critical' });
  if (results.data.ports.some(p => p.port === 5900)) securityIssues.push({ issue: 'VNC exposed (remote access)', severity: 'high' });
  if (results.data.ports.some(p => p.port === 27017)) securityIssues.push({ issue: 'MongoDB exposed (data leak risk)', severity: 'critical' });
  if (results.data.ports.some(p => p.port === 9200)) securityIssues.push({ issue: 'Elasticsearch exposed', severity: 'high' });
  if (results.data.ports.some(p => p.port === 6379)) securityIssues.push({ issue: 'Redis exposed', severity: 'high' });
  
  // Check for database exposure
  const dbPorts = results.data.ports.filter(p => ['MySQL', 'MSSQL', 'PostgreSQL', 'MongoDB', 'Redis'].includes(p.name));
  if (dbPorts.length > 0) {
    securityIssues.push({ issue: `${dbPorts.length} database(s) exposed`, severity: 'high' });
  }
  
  results.security.issues = securityIssues;
  results.security.score = Math.max(0, 100 - securityIssues.reduce((acc, i) => acc + (i.severity === 'critical' ? 30 : i.severity === 'high' ? 20 : 10), 0));
  results.security.level = securityIssues.filter(i => i.severity === 'critical').length > 0 ? 'CRITICAL' : 
                           securityIssues.filter(i => i.severity === 'high').length > 0 ? 'HIGH' :
                           securityIssues.length > 0 ? 'MEDIUM' : 'SECURE';
  
  const secColor = results.security.level === 'CRITICAL' ? 'r' : results.security.level === 'HIGH' ? 'r' : results.security.level === 'MEDIUM' ? 'y' : 'g';
  log(`      Security Score: ${results.security.score}/100`, secColor);
  log(`      Level: ${results.security.level}`, secColor);
  securityIssues.forEach(i => {
    const sevColor = i.severity === 'critical' ? 'r' : i.severity === 'high' ? 'y' : 'dim';
    log(`        [${i.severity.toUpperCase()}] ${i.issue}`, sevColor);
  });

  // 6. Risk Assessment
  log('\n  [6] RISK ASSESSMENT', 'y');
  const risks = [];
  if (results.data.ports.some(p => p.port === 23)) risks.push('Telnet exposed');
  if (results.data.ports.some(p => p.port === 21)) risks.push('FTP exposed');
  if (results.data.ports.some(p => p.port === 3389)) risks.push('RDP exposed');
  if (results.data.ports.some(p => p.port === 445)) risks.push('SMB exposed');
  if (results.data.ports.some(p => p.port === 5900)) risks.push('VNC exposed');
  if (results.data.ports.some(p => p.port === 27017)) risks.push('MongoDB exposed');
  if (!results.data.reverse || results.data.reverse.length === 0) risks.push('No reverse DNS');
  
  results.data.risks = risks;
  results.data.riskLevel = risks.length >= 3 ? 'CRITICAL' : risks.length >= 2 ? 'HIGH' : risks.length > 0 ? 'MEDIUM' : 'LOW';
  const riskColor = results.data.riskLevel === 'CRITICAL' ? 'r' : results.data.riskLevel === 'HIGH' ? 'r' : results.data.riskLevel === 'MEDIUM' ? 'y' : 'g';
  log(`      Level: ${results.data.riskLevel}`, riskColor);
  risks.forEach(r => log(`        - ${r}`, 'y'));

  // 7. Summary
  log('\n  [7] SUMMARY', 'y');
  log(`      IP Type: ${results.data.type}`, 'g');
  if (results.geo.country) log(`      Location: ${results.geo.country}${results.geo.city ? ', ' + results.geo.city : ''}`, 'g');
  if (results.geo.isp) log(`      ISP: ${results.geo.isp}`, 'g');
  log(`      Open Ports: ${results.data.ports.length}`, results.data.ports.length > 0 ? 'y' : 'g');
  log(`      Security: ${results.security.level}`, secColor);

  // 8. API Integrations
  log('\n  [8] API INTEGRATIONS', 'y');
  results.apiData = {};
  
  // Shodan API
  if (isAPIConfigured('shodan')) {
    log('      Checking Shodan...', 'dim');
    const shodanRes = await apiRequest('shodan', 'host', { ip });
    if (!shodanRes.error && shodanRes.data) {
      results.apiData.shodan = shodanRes.data;
      if (shodanRes.data.ports) {
        log(`      Shodan: ${shodanRes.data.ports.length} ports found`, 'g');
      }
      if (shodanRes.data.vulns) {
        log(`      Shodan Vulnerabilities: ${Object.keys(shodanRes.data.vulns).length}`, 'r');
        results.security.vulnerabilities = Object.keys(shodanRes.data.vulns);
      }
      if (shodanRes.data.org) {
        log(`      Shodan Org: ${shodanRes.data.org}`, 'g');
        results.geo.org = shodanRes.data.org;
      }
      if (shodanRes.data.city) {
        log(`      Shodan City: ${shodanRes.data.city}`, 'g');
        results.geo.city = shodanRes.data.city;
      }
    } else {
      log(`      Shodan: No data or error`, 'y');
    }
  } else {
    log('      Shodan: API key not configured', 'dim');
  }
  
  // AbuseIPDB API
  if (isAPIConfigured('abuseipdb')) {
    log('      Checking AbuseIPDB...', 'dim');
    const abuseRes = await apiRequest('abuseipdb', 'check', { ipAddress: ip });
    if (!abuseRes.error && abuseRes.data?.data) {
      results.apiData.abuseipdb = abuseRes.data.data;
      const abuseScore = abuseRes.data.data.abuseConfidenceScore || 0;
      log(`      AbuseIPDB: ${abuseScore}% abuse score`, abuseScore > 50 ? 'r' : abuseScore > 0 ? 'y' : 'g');
      if (abuseRes.data.data.usageType) {
        log(`        Usage: ${abuseRes.data.data.usageType}`, 'dim');
      }
    }
  } else {
    log('      AbuseIPDB: API key not configured', 'dim');
  }
  
  // VirusTotal API
  if (isAPIConfigured('virustotal')) {
    log('      Checking VirusTotal...', 'dim');
    const vtRes = await apiRequest('virustotal', 'ip', { ip });
    if (!vtRes.error && vtRes.data?.data) {
      results.apiData.virustotal = vtRes.data.data;
      const stats = vtRes.data.data.attributes?.last_analysis_stats;
      if (stats) {
        log(`      VirusTotal: ${stats.malicious || 0} malicious, ${stats.suspicious || 0} suspicious`, 
            (stats.malicious > 0 || stats.suspicious > 0) ? 'r' : 'g');
      }
    }
  } else {
    log('      VirusTotal: API key not configured', 'dim');
  }
  
  // Free IP-API (no key required)
  if (isAPIConfigured('ipapi')) {
    log('      Checking IP-API...', 'dim');
    const ipapiRes = await apiRequest('ipapi', 'query', { ip });
    if (!ipapiRes.error && ipapiRes.data && ipapiRes.data.status === 'success') {
      results.apiData.ipapi = ipapiRes.data;
      if (!results.geo.country || results.geo.country === 'Unknown') {
        results.geo.country = ipapiRes.data.country;
        results.geo.city = ipapiRes.data.city;
        results.geo.isp = ipapiRes.data.isp;
        log(`      IP-API: ${ipapiRes.data.country}, ${ipapiRes.data.city}`, 'g');
      }
    }
  }

  saveResult(`ip_${ip.replace(/\./g, '_')}`, results, 'ip');
  return results;
}

// ==================== DOMAIN OSINT ====================

async function domainOSINT(domain) {
  log(`\n${'═'.repeat(60)}`, 'c');
  log(`  DOMAIN OSINT: ${domain}`, 'bold');
  log(`${'═'.repeat(60)}`, 'c');

  const results = { domain, timestamp: new Date().toISOString(), data: {}, security: {}, whois: {}, tech: {} };

  // 1. DNS Records (Enhanced)
  log('\n  [1] DNS RECORDS', 'y');
  results.data.dns = {};

  try {
    const a = await dns.resolve4(domain);
    results.data.dns.A = a;
    log(`      A: ${a.join(', ')}`, 'g');
  } catch (e) {}

  try {
    const aaaa = await dns.resolve6(domain);
    results.data.dns.AAAA = aaaa;
    log(`      AAAA (IPv6): ${aaaa.join(', ')}`, 'g');
    results.data.hasIPv6 = true;
  } catch (e) { results.data.hasIPv6 = false; }

  try {
    const mx = await dns.resolveMx(domain);
    results.data.dns.MX = mx;
    log(`      MX: ${mx.length} records`, 'g');
    mx.forEach(r => log(`        ${r.exchange} (priority: ${r.priority})`, 'dim'));
    if (mx.length > 0) {
      results.data.emailProvider = detectProvider(mx[0].exchange);
      if (results.data.emailProvider) log(`      Email Provider: ${results.data.emailProvider}`, 'g');
    }
  } catch (e) {}

  try {
    const ns = await dns.resolveNs(domain);
    results.data.dns.NS = ns;
    log(`      NS: ${ns.length} servers`, 'g');
    ns.forEach(n => log(`        ${n}`, 'dim'));
    // Detect DNS provider
    const dnsProvider = detectDNSProvider(ns);
    if (dnsProvider) {
      results.data.dnsProvider = dnsProvider;
      log(`      DNS Provider: ${dnsProvider}`, 'g');
    }
  } catch (e) {}

  try {
    const txt = await dns.resolveTxt(domain);
    results.data.dns.TXT = txt;
    results.data.spf = txt.some(t => t.join('').includes('v=spf'));
    results.data.dmarc = txt.some(t => t.join('').includes('v=dmarc'));
    results.data.dkim = txt.some(t => t.join('').includes('v=dkim'));
    results.data.googleSiteVerify = txt.some(t => t.join('').includes('google-site-verification'));
    results.data.hasDMARC = results.data.dmarc;
    
    log(`      TXT: ${txt.length} records`, 'g');
    log(`      SPF: ${results.data.spf ? 'YES' : 'NO'}`, results.data.spf ? 'g' : 'y');
    log(`      DMARC: ${results.data.dmarc ? 'YES' : 'NO'}`, results.data.dmarc ? 'g' : 'r');
    
    // Check for interesting TXT records
    txt.forEach(t => {
      const record = t.join('');
      if (record.includes('aws')) log(`        AWS verification found`, 'dim');
      if (record.includes('azure')) log(`        Azure verification found`, 'dim');
      if (record.includes('hubspot')) log(`        HubSpot found`, 'dim');
      if (record.includes('mailgun')) log(`        Mailgun found`, 'dim');
      if (record.includes('sendgrid')) log(`        SendGrid found`, 'dim');
    });
  } catch (e) {}

  try {
    const cname = await dns.resolveCname(domain);
    results.data.dns.CNAME = cname;
    log(`      CNAME: ${cname.join(', ')}`, 'g');
    results.data.isAlias = true;
  } catch (e) { results.data.isAlias = false; }

  try {
    const soa = await dns.resolveSoa(domain);
    results.data.dns.SOA = soa;
    log(`      SOA: ${soa.nsname}`, 'dim');
  } catch (e) {}

  // 2. Subdomain Enumeration (Enhanced)
  log('\n  [2] SUBDOMAIN ENUMERATION', 'y');
  const subs = [
    // Common
    'www', 'mail', 'ftp', 'api', 'admin', 'blog', 'shop', 'dev', 'staging', 'test',
    'app', 'portal', 'vpn', 'cdn', 'static', 'assets', 'support', 'help', 'm', 'mobile',
    // Infrastructure
    'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap', 'email', 'webmail', 'owa',
    // Development
    'git', 'svn', 'ci', 'jenkins', 'build', 'deploy', 'demo', 'sandbox', 'beta', 'alpha',
    // Internal
    'internal', 'intranet', 'extranet', 'portal', 'secure', 'login', 'sso', 'auth',
    // Services
    'cpanel', 'whm', 'webdisk', 'autodiscover', 'autoconfig', 'phpmyadmin', 'mysql',
    // Media
    'img', 'images', 'video', 'media', 'files', 'downloads', 'upload', 'cdn1', 'cdn2',
    // Business
    'store', 'ecommerce', 'payments', 'billing', 'crm', 'erp', 'dashboard', 'panel',
    // Security
    'firewall', 'fw', 'security', 'ssl', 'secure', 'vpn', 'remote', 'gateway'
  ];
  
  results.data.subdomains = [];
  const subdomainsByType = { infrastructure: [], dev: [], services: [], other: [] };
  
  for (const sub of subs) {
    const full = `${sub}.${domain}`;
    try {
      const addr = await dns.resolve4(full);
      const subdomain = { name: full, ip: addr[0] };
      results.data.subdomains.push(subdomain);
      log(`      Found: ${full} → ${addr[0]}`, 'g');
      
      // Categorize
      if (['ns1', 'ns2', 'dns', 'mx', 'smtp', 'email'].includes(sub)) subdomainsByType.infrastructure.push(full);
      else if (['git', 'ci', 'jenkins', 'staging', 'dev', 'test', 'beta'].includes(sub)) subdomainsByType.dev.push(full);
      else if (['cpanel', 'phpmyadmin', 'webmail', 'admin', 'portal'].includes(sub)) subdomainsByType.services.push(full);
      else subdomainsByType.other.push(full);
    } catch (e) {}
    await new Promise(r => setTimeout(r, 30));
  }
  
  if (results.data.subdomains.length === 0) log('      None found', 'dim');
  else {
    log(`      Total: ${results.data.subdomains.length}`, 'g');
    if (subdomainsByType.infrastructure.length > 0) log(`      Infrastructure: ${subdomainsByType.infrastructure.length}`, 'y');
    if (subdomainsByType.dev.length > 0) log(`      Development: ${subdomainsByType.dev.length}`, 'y');
    if (subdomainsByType.services.length > 0) log(`      Services: ${subdomainsByType.services.length}`, 'y');
  }

  // 3. HTTP/HTTPS Analysis (Enhanced)
  log('\n  [3] HTTP/HTTPS ANALYSIS', 'y');
  try {
    const httpRes = await httpCheck(domain);
    results.data.http = httpRes;
    log(`      HTTP: ${httpRes.status}`, 'g');
    if (httpRes.headers?.server) {
      results.tech.server = httpRes.headers.server;
      log(`      Server: ${httpRes.headers.server}`, 'dim');
    }
  } catch (e) { log('      HTTP: No response', 'r'); }

  try {
    const httpsRes = await httpsCheck(domain);
    results.data.https = httpsRes;
    log(`      HTTPS: ${httpsRes.status}`, 'g');
    
    // Security headers analysis
    const h = httpsRes.headers || {};
    results.data.securityHeaders = [];
    results.data.missingHeaders = [];
    
    const securityHeaderChecks = [
      { name: 'HSTS', header: 'strict-transport-security', critical: true },
      { name: 'X-Frame-Options', header: 'x-frame-options', critical: false },
      { name: 'X-Content-Type-Options', header: 'x-content-type-options', critical: false },
      { name: 'X-XSS-Protection', header: 'x-xss-protection', critical: false },
      { name: 'CSP', header: 'content-security-policy', critical: true },
      { name: 'Referrer-Policy', header: 'referrer-policy', critical: false },
      { name: 'Permissions-Policy', header: 'permissions-policy', critical: false }
    ];
    
    securityHeaderChecks.forEach(check => {
      if (h[check.header]) {
        results.data.securityHeaders.push(check.name);
      } else {
        results.data.missingHeaders.push({ name: check.name, critical: check.critical });
      }
    });
    
    if (h.server) {
      results.tech.server = h.server;
      log(`      Server: ${h.server}`, 'dim');
    }
    
    // Tech detection from headers
    results.tech.stack = [];
    if (h['x-powered-by']) {
      results.tech.stack.push(h['x-powered-by']);
      log(`      Powered by: ${h['x-powered-by']}`, 'dim');
    }
    if (h['set-cookie']?.includes('PHPSESSID')) results.tech.stack.push('PHP');
    if (h['set-cookie']?.includes('JSESSIONID')) results.tech.stack.push('Java');
    if (h['set-cookie']?.includes('ASP.NET')) results.tech.stack.push('ASP.NET');
    if (h.server?.includes('nginx')) results.tech.stack.push('Nginx');
    if (h.server?.includes('Apache')) results.tech.stack.push('Apache');
    if (h.server?.includes('cloudflare')) results.tech.stack.push('Cloudflare');
    
    log(`      Security Headers: ${results.data.securityHeaders.length}/${securityHeaderChecks.length}`, 
        results.data.securityHeaders.length >= 5 ? 'g' : results.data.securityHeaders.length >= 3 ? 'y' : 'r');
    if (results.data.missingHeaders.length > 0) {
      results.data.missingHeaders.forEach(mh => {
        log(`        Missing: ${mh.name}${mh.critical ? ' [CRITICAL]' : ''}`, mh.critical ? 'r' : 'y');
      });
    }
    
    // SSL/TLS info
    results.security.https = true;
    results.security.hsts = !!h['strict-transport-security'];
  } catch (e) { 
    log('      HTTPS: No response', 'r'); 
    results.security.https = false;
  }

  // 4. Security Assessment
  log('\n  [4] SECURITY ASSESSMENT', 'y');
  const securityIssues = [];
  
  if (!results.data.https) securityIssues.push({ issue: 'No HTTPS (unencrypted)', severity: 'critical' });
  if (!results.data.spf) securityIssues.push({ issue: 'No SPF record (email spoofing risk)', severity: 'high' });
  if (!results.data.dmarc) securityIssues.push({ issue: 'No DMARC record', severity: 'high' });
  if (!results.data.hasIPv6) securityIssues.push({ issue: 'No IPv6 support', severity: 'low' });
  if (results.data.missingHeaders?.some(h => h.critical)) securityIssues.push({ issue: 'Missing critical security headers', severity: 'medium' });
  if (subdomainsByType.dev.length > 0) securityIssues.push({ issue: 'Development subdomains exposed', severity: 'medium' });
  if (subdomainsByType.services.length > 0) securityIssues.push({ issue: 'Admin panels exposed', severity: 'medium' });
  
  results.security.issues = securityIssues;
  results.security.score = Math.max(0, 100 - securityIssues.reduce((acc, i) => 
    acc + (i.severity === 'critical' ? 30 : i.severity === 'high' ? 20 : i.severity === 'medium' ? 10 : 5), 0));
  results.security.level = securityIssues.filter(i => i.severity === 'critical').length > 0 ? 'CRITICAL' : 
                           securityIssues.filter(i => i.severity === 'high').length > 0 ? 'HIGH' :
                           securityIssues.length > 0 ? 'MEDIUM' : 'SECURE';
  
  const secColor = results.security.level === 'CRITICAL' ? 'r' : results.security.level === 'HIGH' ? 'r' : results.security.level === 'MEDIUM' ? 'y' : 'g';
  log(`      Security Score: ${results.security.score}/100`, secColor);
  log(`      Level: ${results.security.level}`, secColor);
  securityIssues.forEach(i => {
    const sevColor = i.severity === 'critical' ? 'r' : i.severity === 'high' ? 'y' : 'dim';
    log(`        [${i.severity.toUpperCase()}] ${i.issue}`, sevColor);
  });

  // 5. Technology Stack
  log('\n  [5] TECHNOLOGY STACK', 'y');
  if (results.tech.stack?.length > 0) {
    results.tech.stack.forEach(t => log(`      • ${t}`, 'g'));
  } else {
    log('      No technologies detected', 'dim');
  }

  // 6. Summary
  log('\n  [6] SUMMARY', 'y');
  log(`      DNS Records: ${Object.keys(results.data.dns).length} types`, 'g');
  log(`      Subdomains: ${results.data.subdomains.length} found`, results.data.subdomains.length > 0 ? 'y' : 'dim');
  log(`      HTTPS: ${results.data.https ? 'YES' : 'NO'}`, results.data.https ? 'g' : 'r');
  log(`      Security: ${results.security.level}`, secColor);

  // 7. API Integrations
  log('\n  [7] API INTEGRATIONS', 'y');
  results.apiData = {};
  
  // Shodan DNS API
  if (isAPIConfigured('shodan')) {
    log('      Checking Shodan DNS...', 'dim');
    const shodanRes = await apiRequest('shodan', 'dns', { domain });
    if (!shodanRes.error && shodanRes.data) {
      results.apiData.shodan = shodanRes.data;
      if (shodanRes.data.subdomains) {
        log(`      Shodan Subdomains: ${shodanRes.data.subdomains?.length || 0} found`, 'g');
        // Add any new subdomains
        shodanRes.data.subdomains?.forEach(sub => {
          const full = `${sub}.${domain}`;
          if (!results.data.subdomains.find(s => s.name === full)) {
            results.data.subdomains.push({ name: full, source: 'shodan' });
          }
        });
      }
    }
  } else {
    log('      Shodan: API key not configured', 'dim');
  }
  
  // VirusTotal API
  if (isAPIConfigured('virustotal')) {
    log('      Checking VirusTotal...', 'dim');
    const vtRes = await apiRequest('virustotal', 'domain', { domain });
    if (!vtRes.error && vtRes.data?.data) {
      results.apiData.virustotal = vtRes.data.data;
      const stats = vtRes.data.data.attributes?.last_analysis_stats;
      if (stats) {
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        log(`      VirusTotal: ${malicious} malicious, ${suspicious} suspicious`, 
            (malicious > 0 || suspicious > 0) ? 'r' : 'g');
        results.security.virusTotal = { malicious, suspicious };
      }
      // Reputation
      const reputation = vtRes.data.data.attributes?.reputation;
      if (reputation !== undefined) {
        log(`      VirusTotal Reputation: ${reputation}`, reputation < 0 ? 'r' : 'g');
      }
    }
  } else {
    log('      VirusTotal: API key not configured', 'dim');
  }
  
  // SecurityTrails API
  if (isAPIConfigured('securitytrails')) {
    log('      Checking SecurityTrails...', 'dim');
    const stRes = await apiRequest('securitytrails', 'subdomains', { domain });
    if (!stRes.error && stRes.data?.subdomains) {
      results.apiData.securitytrails = stRes.data;
      log(`      SecurityTrails: ${stRes.data.subdomains.length} subdomains`, 'g');
      stRes.data.subdomains.forEach(sub => {
        const full = `${sub}.${domain}`;
        if (!results.data.subdomains.find(s => s.name === full)) {
          results.data.subdomains.push({ name: full, source: 'securitytrails' });
        }
      });
    }
  } else {
    log('      SecurityTrails: API key not configured', 'dim');
  }
  
  // Hunter.io Domain Search
  if (isAPIConfigured('hunter')) {
    log('      Checking Hunter.io...', 'dim');
    const hunterRes = await apiRequest('hunter', 'domain', { domain });
    if (!hunterRes.error && hunterRes.data?.data) {
      results.apiData.hunter = hunterRes.data.data;
      const emails = hunterRes.data.data.emails || [];
      log(`      Hunter.io: ${emails.length} emails found`, emails.length > 0 ? 'g' : 'dim');
      if (emails.length > 0) {
        results.data.emails = emails.map(e => e.value);
      }
    }
  } else {
    log('      Hunter.io: API key not configured', 'dim');
  }

  saveResult(`domain_${domain.replace(/\./g, '_')}`, results, 'domain');
  return results;
}

function detectDNSProvider(nsRecords) {
  const providers = {
    'cloudflare': 'Cloudflare',
    'awsdns': 'AWS Route53',
    'googledomains': 'Google Domains',
    'namecheap': 'Namecheap',
    'godaddy': 'GoDaddy',
    'digitalocean': 'DigitalOcean',
    'linode': 'Linode',
    'he.net': 'Hurricane Electric',
    'azure': 'Azure DNS',
    'dnsmadeeasy': 'DNS Made Easy',
    'nsone': 'NS1',
    'dynect': 'Dyn'
  };
  
  for (const ns of nsRecords) {
    for (const [key, provider] of Object.entries(providers)) {
      if (ns.toLowerCase().includes(key)) return provider;
    }
  }
  return null;
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

// ==================== NEW OSINT TOOLS ====================

// MAC Address Lookup
const MAC_VENDORS = {
  '00:50:56': 'VMware, Inc.',
  '00:0C:29': 'VMware, Inc.',
  '00:1A:11': 'Intel Corporate',
  '00:1B:63': 'Apple, Inc.',
  '00:03:FF': 'Microsoft Corporation',
  '00:05:69': 'Cisco Systems',
  '00:0D:3A': 'Microsoft Corporation',
  '00:15:5D': 'Microsoft Corporation',
  '00:16:3E': 'Xensource, Inc.',
  '00:17:F2': 'Apple, Inc.',
  '00:1C:42': 'Parallels, Inc.',
  '00:1E:C1': 'Dell Inc.',
  '00:22:48': 'Intel Corporate',
  '00:25:00': 'Apple, Inc.',
  '00:26:08': 'Intel Corporate',
  '00:26:4D': 'Intel Corporate',
  '00:26:B0': 'Apple, Inc.',
  '00:27:10': 'Microsoft Corporation',
  '00:30:05': 'Apple, Inc.',
  '00:50:56': 'VMware, Inc.',
  '00:A0:40': 'Intel Corporate',
  '04:1E:64': 'Apple, Inc.',
  '08:00:27': 'Oracle VirtualBox',
  '0A:00:27': 'Oracle VirtualBox',
  '10:9A:DD': 'Apple, Inc.',
  '14:10:9F': 'Apple, Inc.',
  '14:7D:C5': 'Apple, Inc.',
  '18:65:90': 'Apple, Inc.',
  '18:A6:F7': 'Apple, Inc.',
  '1C:1B:0D': 'Apple, Inc.',
  '1C:AB:A7': 'Apple, Inc.',
  '20:C9:D0': 'Apple, Inc.',
  '24:A0:74': 'Apple, Inc.',
  '28:5A:EB': 'Apple, Inc.',
  '28:E3:1F': 'Apple, Inc.',
  '2C:F0:EE': 'Apple, Inc.',
  '30:10:E4': 'Apple, Inc.',
  '34:12:F9': 'Apple, Inc.',
  '34:A3:95': 'Apple, Inc.',
  '38:C9:86': 'Apple, Inc.',
  '3C:07:54': 'Apple, Inc.',
  '3C:15:C2': 'Apple, Inc.',
  '40:30:04': 'Apple, Inc.',
  '40:A6:D9': 'Apple, Inc.',
  '44:D8:84': 'Apple, Inc.',
  '48:A1:95': 'Apple, Inc.',
  '4C:8D:5E': 'Apple, Inc.',
  '50:BC:96': 'Apple, Inc.',
  '54:26:96': 'Apple, Inc.',
  '58:55:CA': 'Apple, Inc.',
  '5C:95:AA': 'Apple, Inc.',
  '60:03:08': 'Apple, Inc.',
  '60:A1:0A': 'Apple, Inc.',
  '60:C5:47': 'Apple, Inc.',
  '64:00:6A': 'Apple, Inc.',
  '64:20:0C': 'Apple, Inc.',
  '64:4B:F0': 'Apple, Inc.',
  '64:9C:F6': 'Apple, Inc.',
  '64:A5:E3': 'Apple, Inc.',
  '68:A8:6D': 'Apple, Inc.',
  '6C:19:C0': 'Apple, Inc.',
  '6C:3E:6D': 'Apple, Inc.',
  '70:03:49': 'Apple, Inc.',
  '70:11:24': 'Apple, Inc.',
  '70:3E:97': 'Apple, Inc.',
  '70:56:81': 'Apple, Inc.',
  '70:CD:D4': 'Apple, Inc.',
  '74:81:14': 'Apple, Inc.',
  '78:31:C1': 'Apple, Inc.',
  '78:A3:E4': 'Apple, Inc.',
  '78:CA:39': 'Apple, Inc.',
  '7C:01:91': 'Apple, Inc.',
  '7C:6D:62': 'Apple, Inc.',
  '7C:C3:A1': 'Apple, Inc.',
  '80:BE:05': 'Apple, Inc.',
  '84:3B:4D': 'Apple, Inc.',
  '84:FC:FE': 'Apple, Inc.',
  '88:1F:A1': 'Apple, Inc.',
  '88:66:5A': 'Apple, Inc.',
  '88:AE:1D': 'Apple, Inc.',
  '88:E9:FE': 'Apple, Inc.',
  '8C:00:6D': 'Apple, Inc.',
  '8C:2D:AA': 'Apple, Inc.',
  '8C:58:77': 'Apple, Inc.',
  '8C:85:90': 'Apple, Inc.',
  '90:8C:20': 'Apple, Inc.',
  '90:B2:1F': 'Apple, Inc.',
  '90:B7:67': 'Apple, Inc.',
  '90:DD:5D': 'Apple, Inc.',
  '94:94:26': 'Apple, Inc.',
  '94:B8:60': 'Apple, Inc.',
  '94:E9:6A': 'Apple, Inc.',
  '98:01:A7': 'Apple, Inc.',
  '98:5A:EB': 'Apple, Inc.',
  '98:B8:E3': 'Apple, Inc.',
  '98:E0:D8': 'Apple, Inc.',
  '9C:04:EB': 'Apple, Inc.',
  '9C:20:07': 'Apple, Inc.',
  '9C:35:EB': 'Apple, Inc.',
  '9C:84:BF': 'Apple, Inc.',
  '9C:99:A0': 'Apple, Inc.',
  'A0:99:9B': 'Apple, Inc.',
  'A4:31:35': 'Apple, Inc.',
  'A4:5E:60': 'Apple, Inc.',
  'A4:83:E7': 'Apple, Inc.',
  'A4:B1:97': 'Apple, Inc.',
  'A4:C3:F0': 'Apple, Inc.',
  'A4:D1:D2': 'Apple, Inc.',
  'A8:20:66': 'Apple, Inc.',
  'A8:5B:78': 'Apple, Inc.',
  'A8:66:AA': 'Apple, Inc.',
  'A8:88:08': 'Apple, Inc.',
  'A8:96:8A': 'Apple, Inc.',
  'AC:1F:74': 'Apple, Inc.',
  'AC:29:29': 'Apple, Inc.',
  'AC:3A:7A': 'Apple, Inc.',
  'AC:5A:F0': 'Apple, Inc.',
  'AC:87:A3': 'Apple, Inc.',
  'AC:BC:30': 'Apple, Inc.',
  'B0:34:95': 'Apple, Inc.',
  'B0:65:BD': 'Apple, Inc.',
  'B0:70:2D': 'Apple, Inc.',
  'B0:9F:BA': 'Apple, Inc.',
  'B0:CA:68': 'Apple, Inc.',
  'B4:18:25': 'Apple, Inc.',
  'B4:50:6E': 'Apple, Inc.',
  'B4:8C:9D': 'Apple, Inc.',
  'B4:B6:76': 'Apple, Inc.',
  'B4:C4:FC': 'Apple, Inc.',
  'B4:E6:22': 'Apple, Inc.',
  'B8:09:8A': 'Apple, Inc.',
  'B8:17:C2': 'Apple, Inc.',
  'B8:31:B5': 'Apple, Inc.',
  'B8:41:A4': 'Apple, Inc.',
  'B8:53:AC': 'Apple, Inc.',
  'B8:78:2E': 'Apple, Inc.',
  'B8:8C:25': 'Apple, Inc.',
  'B8:95:2A': 'Apple, Inc.',
  'B8:C1:11': 'Apple, Inc.',
  'B8:C8:5A': 'Apple, Inc.',
  'B8:E8:56': 'Apple, Inc.',
  'BC:09:1B': 'Apple, Inc.',
  'BC:3B:29': 'Apple, Inc.',
  'BC:52:B7': 'Apple, Inc.',
  'BC:6C:21': 'Apple, Inc.',
  'BC:79:AD': 'Apple, Inc.',
  'BC:9F:EF': 'Apple, Inc.',
  'BC:A9:F8': 'Apple, Inc.',
  'BC:D0:74': 'Apple, Inc.',
  'BC:E4:22': 'Apple, Inc.',
  'C0:63:15': 'Apple, Inc.',
  'C4:2C:03': 'Apple, Inc.',
  'C4:B1:99': 'Apple, Inc.',
  'C4:D3:6F': 'Apple, Inc.',
  'C8:1E:7B': 'Apple, Inc.',
  'C8:33:4B': 'Apple, Inc.',
  'C8:69:CD': 'Apple, Inc.',
  'C8:85:50': 'Apple, Inc.',
  'C8:A0:30': 'Apple, Inc.',
  'C8:B5:4F': 'Apple, Inc.',
  'C8:BC:C8': 'Apple, Inc.',
  'C8:D0:83': 'Apple, Inc.',
  'C8:D3:A3': 'Apple, Inc.',
  'C8:E2:B2': 'Apple, Inc.',
  'CC:08:FB': 'Apple, Inc.',
  'CC:25:47': 'Apple, Inc.',
  'CC:29:0B': 'Apple, Inc.',
  'CC:61:E5': 'Apple, Inc.',
  'CC:78:5F': 'Apple, Inc.',
  'CC:8C:16': 'Apple, Inc.',
  'CC:95:D7': 'Apple, Inc.',
  'CC:B0:2A': 'Apple, Inc.',
  'CC:C7:60': 'Apple, Inc.',
  'D0:03:4B': 'Apple, Inc.',
  'D0:13:25': 'Apple, Inc.',
  'D0:23:DB': 'Apple, Inc.',
  'D0:25:36': 'Apple, Inc.',
  'D0:33:11': 'Apple, Inc.',
  'D0:4F:7B': 'Apple, Inc.',
  'D0:52:05': 'Apple, Inc.',
  'D0:67:E5': 'Apple, Inc.',
  'D0:81:8A': 'Apple, Inc.',
  'D0:87:37': 'Apple, Inc.',
  'D0:A6:37': 'Apple, Inc.',
  'D0:A8:E9': 'Apple, Inc.',
  'D0:C0:ED': 'Apple, Inc.',
  'D0:C5:F3': 'Apple, Inc.',
  'D0:D2:B0': 'Apple, Inc.',
  'D4:61:9D': 'Apple, Inc.',
  'D4:90:90': 'Apple, Inc.',
  'D4:A3:3D': 'Apple, Inc.',
  'D4:AE:05': 'Apple, Inc.',
  'D8:00:4D': 'Apple, Inc.',
  'D8:1C:79': 'Apple, Inc.',
  'D8:30:62': 'Apple, Inc.',
  'D8:3B:BF': 'Apple, Inc.',
  'D8:5C:F0': 'Apple, Inc.',
  'D8:9E:3F': 'Apple, Inc.',
  'D8:A2:5E': 'Apple, Inc.',
  'D8:BB:20': 'Apple, Inc.',
  'DC:08:5F': 'Apple, Inc.',
  'DC:2B:2A': 'Apple, Inc.',
  'DC:37:44': 'Apple, Inc.',
  'DC:41:E9': 'Apple, Inc.',
  'DC:54:D7': 'Apple, Inc.',
  'DC:56:97': 'Apple, Inc.',
  'DC:9B:9C': 'Apple, Inc.',
  'DC:A2:1A': 'Apple, Inc.',
  'DC:A6:32': 'Apple, Inc.',
  'DC:C3:4F': 'Apple, Inc.',
  'DC:D3:A2': 'Apple, Inc.',
  'DC:E8:80': 'Apple, Inc.',
  'E0:06:E6': 'Apple, Inc.',
  'E0:33:8E': 'Apple, Inc.',
  'E0:4F:43': 'Apple, Inc.',
  'E0:88:5D': 'Apple, Inc.',
  'E0:9F:16': 'Apple, Inc.',
  'E0:A3:0E': 'Apple, Inc.',
  'E0:B5:2D': 'Apple, Inc.',
  'E0:B9:A5': 'Apple, Inc.',
  'E0:C2:6E': 'Apple, Inc.',
  'E0:C7:67': 'Apple, Inc.',
  'E0:CC:7A': 'Apple, Inc.',
  'E0:EA:0A': 'Apple, Inc.',
  'E4:25:7D': 'Apple, Inc.',
  'E4:8B:7F': 'Apple, Inc.',
  'E4:C1:46': 'Apple, Inc.',
  'E4:C9:82': 'Apple, Inc.',
  'E4:CE:8F': 'Apple, Inc.',
  'E4:D9:31': 'Apple, Inc.',
  'E4:F0:42': 'Apple, Inc.',
  'E8:04:0B': 'Apple, Inc.',
  'E8:06:88': 'Apple, Inc.',
  'E8:21:45': 'Apple, Inc.',
  'E8:39:35': 'Apple, Inc.',
  'E8:3B:35': 'Apple, Inc.',
  'E8:40:BE': 'Apple, Inc.',
  'E8:80:2D': 'Apple, Inc.',
  'E8:9D:87': 'Apple, Inc.',
  'E8:B2:58': 'Apple, Inc.',
  'E8:C9:2A': 'Apple, Inc.',
  'E8:D9:1F': 'Apple, Inc.',
  'EC:35:86': 'Apple, Inc.',
  'EC:9B:8B': 'Apple, Inc.',
  'EC:C3:0A': 'Apple, Inc.',
  'EC:E1:32': 'Apple, Inc.',
  'EC:F0:0B': 'Apple, Inc.',
  'EC:F4:BB': 'Apple, Inc.',
  'F0:0F:1C': 'Apple, Inc.',
  'F0:18:98': 'Apple, Inc.',
  'F0:24:1C': 'Apple, Inc.',
  'F0:27:2D': 'Apple, Inc.',
  'F0:4D:96': 'Apple, Inc.',
  'F0:51:4F': 'Apple, Inc.',
  'F0:59:AF': 'Apple, Inc.',
  'F0:6E:0B': 'Apple, Inc.',
  'F0:79:30': 'Apple, Inc.',
  'F0:7B:CB': 'Apple, Inc.',
  'F0:98:9D': 'Apple, Inc.',
  'F0:B4:79': 'Apple, Inc.',
  'F0:C7:7C': 'Apple, Inc.',
  'F0:D1:A9': 'Apple, Inc.',
  'F0:D7:AF': 'Apple, Inc.',
  'F0:DC:E2': 'Apple, Inc.',
  'F0:F6:1C': 'Apple, Inc.',
  'F4:1B:1B': 'Apple, Inc.',
  'F4:37:B7': 'Apple, Inc.',
  'F4:5C:89': 'Apple, Inc.',
  'F4:7E:75': 'Apple, Inc.',
  'F4:8A:5B': 'Apple, Inc.',
  'F4:9F:F3': 'Apple, Inc.',
  'F4:B7:43': 'Apple, Inc.',
  'F4:C8:8B': 'Apple, Inc.',
  'F4:D9:6F': 'Apple, Inc.',
  'F4:DE:9F': 'Apple, Inc.',
  'F4:F1:5A': 'Apple, Inc.',
  'F8:27:93': 'Apple, Inc.',
  'F8:3B:59': 'Apple, Inc.',
  'F8:77:B8': 'Apple, Inc.',
  'F8:95:C7': 'Apple, Inc.',
  'F8:A2:D8': 'Apple, Inc.',
  'F8:A9:63': 'Apple, Inc.',
  'F8:CF:C5': 'Apple, Inc.',
  'F8:E0:79': 'Apple, Inc.',
  'FC:25:3F': 'Apple, Inc.',
  'FC:2A:7A': 'Apple, Inc.',
  'FC:44:8B': 'Apple, Inc.',
  'FC:5A:3E': 'Apple, Inc.',
  'FC:64:BA': 'Apple, Inc.',
  'FC:6B:79': 'Apple, Inc.',
  'FC:8A:8B': 'Apple, Inc.',
  'FC:9D:99': 'Apple, Inc.',
  'FC:A6:67': 'Apple, Inc.',
  'FC:B4:E6': 'Apple, Inc.',
  'FC:C2:3D': 'Apple, Inc.',
  'FC:D6:BD': 'Apple, Inc.',
  'FC:E9:98': 'Apple, Inc.',
  'FC:F1:36': 'Apple, Inc.',
  'FC:F5:28': 'Apple, Inc.'
};

async function macOSINT(mac) {
  const startTime = Date.now();
  const result = { mac, vendor: null, type: null, details: {}, risk: { score: 0, level: 'Low', indicators: [] } };
  
  // Normalize MAC address
  const normalized = mac.toUpperCase().replace(/[:\-\.]/g, '');
  
  if (normalized.length < 12) {
    result.error = 'Invalid MAC address format';
    return result;
  }
  
  // Get OUI (first 6 characters)
  const oui = normalized.substring(0, 6);
  const ouiWithColons = oui.match(/.{2}/g).join(':');
  
  // Lookup vendor
  for (const [prefix, vendor] of Object.entries(MAC_VENDORS)) {
    if (oui === prefix.replace(/:/g, '')) {
      result.vendor = vendor;
      break;
    }
  }
  
  // Determine type
  if (result.vendor) {
    if (result.vendor.includes('VMware') || result.vendor.includes('VirtualBox') || result.vendor.includes('Parallels')) {
      result.type = 'Virtual Machine';
      result.risk.indicators.push('Virtual machine MAC address');
    } else if (result.vendor.includes('Apple')) {
      result.type = 'Apple Device';
    } else if (result.vendor.includes('Microsoft')) {
      result.type = 'Microsoft/Azure';
    } else if (result.vendor.includes('Cisco')) {
      result.type = 'Network Equipment';
    } else if (result.vendor.includes('Intel')) {
      result.type = 'Intel Hardware';
    } else if (result.vendor.includes('Dell')) {
      result.type = 'Dell Hardware';
    } else {
      result.type = 'Physical Device';
    }
  }
  
  // Check for locally administered addresses
  const secondChar = parseInt(oui[1], 16);
  if (secondChar & 0x02) {
    result.details.locallyAdministered = true;
    result.risk.indicators.push('Locally administered MAC (may be spoofed)');
    result.risk.score += 20;
  }
  
  // Check for multicast
  if (secondChar & 0x01) {
    result.details.multicast = true;
    result.details.type = 'Multicast';
  }
  
  // Calculate risk
  if (result.risk.indicators.length > 0) {
    result.risk.level = result.risk.score >= 40 ? 'Medium' : 'Low';
  }
  
  result.scanTime = Date.now() - startTime;
  
  // Display results
  console.log(`\n${c.cyan}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
  console.log(`${c.cyan}║${c.reset}  ${c.bold}MAC ADDRESS ANALYSIS RESULTS${c.reset}                                                                    ${c.cyan}║${c.reset}`);
  console.log(`${c.cyan}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  console.log(`${c.cyan}║${c.reset}  MAC Address: ${c.y}${mac}${' '.repeat(81 - mac.length)}${c.cyan}║${c.reset}`);
  console.log(`${c.cyan}║${c.reset}  OUI: ${c.y}${ouiWithColons}${' '.repeat(89 - ouiWithColons.length)}${c.cyan}║${c.reset}`);
  console.log(`${c.cyan}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  
  if (result.vendor) {
    console.log(`${c.cyan}║${c.reset}  ${c.g}✓${c.reset} Vendor: ${result.vendor}${' '.repeat(86 - result.vendor.length)}${c.cyan}║${c.reset}`);
    console.log(`${c.cyan}║${c.reset}  ${c.g}✓${c.reset} Type: ${result.type}${' '.repeat(88 - result.type.length)}${c.cyan}║${c.reset}`);
  } else {
    console.log(`${c.cyan}║${c.reset}  ${c.y}⚠${c.reset} Vendor not found in database${' '.repeat(66)}${c.cyan}║${c.reset}`);
  }
  
  if (result.details.locallyAdministered) {
    console.log(`${c.cyan}║${c.reset}  ${c.y}⚠${c.reset} ${c.y}Locally Administered Address${c.reset}${' '.repeat(66)}${c.cyan}║${c.reset}`);
  }
  
  console.log(`${c.cyan}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  console.log(`${c.cyan}║${c.reset}  Risk Level: ${result.risk.level === 'Low' ? c.g : c.y}${result.risk.level}${c.reset}${' '.repeat(85 - result.risk.level.length)}${c.cyan}║${c.reset}`);
  console.log(`${c.cyan}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
  
  // Save result
  const filename = `mac_${mac.replace(/[:\-\.]/g, '_')}_${Date.now()}.json`;
  fs.writeFileSync(path.join(RESULTS_DIR, filename), JSON.stringify(result, null, 2));
  console.log(`\n  ${c.dim}Results saved to: ${RESULTS_DIR}/${filename}${c.reset}`);
  
  return result;
}

// Hash Identification & Analysis
const HASH_PATTERNS = {
  'MD5': { regex: /^[a-f0-9]{32}$/i, length: 32, description: 'MD5 - 128-bit hash' },
  'MD4': { regex: /^[a-f0-9]{32}$/i, length: 32, description: 'MD4 - 128-bit hash (legacy)' },
  'NTLM': { regex: /^[a-f0-9]{32}$/i, length: 32, description: 'NTLM - Windows LAN Manager hash' },
  'SHA-1': { regex: /^[a-f0-9]{40}$/i, length: 40, description: 'SHA-1 - 160-bit hash' },
  'SHA-224': { regex: /^[a-f0-9]{56}$/i, length: 56, description: 'SHA-224 - 224-bit hash' },
  'SHA-256': { regex: /^[a-f0-9]{64}$/i, length: 64, description: 'SHA-256 - 256-bit hash' },
  'SHA-384': { regex: /^[a-f0-9]{96}$/i, length: 96, description: 'SHA-384 - 384-bit hash' },
  'SHA-512': { regex: /^[a-f0-9]{128}$/i, length: 128, description: 'SHA-512 - 512-bit hash' },
  'SHA3-224': { regex: /^[a-f0-9]{56}$/i, length: 56, description: 'SHA3-224 - 224-bit hash' },
  'SHA3-256': { regex: /^[a-f0-9]{64}$/i, length: 64, description: 'SHA3-256 - 256-bit hash' },
  'SHA3-384': { regex: /^[a-f0-9]{96}$/i, length: 96, description: 'SHA3-384 - 384-bit hash' },
  'SHA3-512': { regex: /^[a-f0-9]{128}$/i, length: 128, description: 'SHA3-512 - 512-bit hash' },
  'BLAKE2s-256': { regex: /^[a-f0-9]{64}$/i, length: 64, description: 'BLAKE2s-256 - 256-bit hash' },
  'BLAKE2b-256': { regex: /^[a-f0-9]{64}$/i, length: 64, description: 'BLAKE2b-256 - 256-bit hash' },
  'BLAKE2b-512': { regex: /^[a-f0-9]{128}$/i, length: 128, description: 'BLAKE2b-512 - 512-bit hash' },
  'RIPEMD-128': { regex: /^[a-f0-9]{32}$/i, length: 32, description: 'RIPEMD-128 - 128-bit hash' },
  'RIPEMD-160': { regex: /^[a-f0-9]{40}$/i, length: 40, description: 'RIPEMD-160 - 160-bit hash' },
  'RIPEMD-256': { regex: /^[a-f0-9]{64}$/i, length: 64, description: 'RIPEMD-256 - 256-bit hash' },
  'RIPEMD-320': { regex: /^[a-f0-9]{80}$/i, length: 80, description: 'RIPEMD-320 - 320-bit hash' },
  'Whirlpool': { regex: /^[a-f0-9]{128}$/i, length: 128, description: 'Whirlpool - 512-bit hash' },
  'Tiger-128': { regex: /^[a-f0-9]{32}$/i, length: 32, description: 'Tiger-128 - 128-bit hash' },
  'Tiger-160': { regex: /^[a-f0-9]{40}$/i, length: 40, description: 'Tiger-160 - 160-bit hash' },
  'Tiger-192': { regex: /^[a-f0-9]{48}$/i, length: 48, description: 'Tiger-192 - 192-bit hash' },
  'HAVAL-128': { regex: /^[a-f0-9]{32}$/i, length: 32, description: 'HAVAL-128 - 128-bit hash' },
  'HAVAL-160': { regex: /^[a-f0-9]{40}$/i, length: 40, description: 'HAVAL-160 - 160-bit hash' },
  'HAVAL-192': { regex: /^[a-f0-9]{48}$/i, length: 48, description: 'HAVAL-192 - 192-bit hash' },
  'HAVAL-224': { regex: /^[a-f0-9]{56}$/i, length: 56, description: 'HAVAL-224 - 224-bit hash' },
  'HAVAL-256': { regex: /^[a-f0-9]{64}$/i, length: 64, description: 'HAVAL-256 - 256-bit hash' },
  'GOST R 34.11-94': { regex: /^[a-f0-9]{64}$/i, length: 64, description: 'GOST R 34.11-94 - Russian standard' },
  'FNV-132': { regex: /^[a-f0-9]{8}$/i, length: 8, description: 'FNV-132 - 32-bit hash' },
  'FNV-164': { regex: /^[a-f0-9]{16}$/i, length: 16, description: 'FNV-164 - 64-bit hash' },
  'CRC-16': { regex: /^[a-f0-9]{4}$/i, length: 4, description: 'CRC-16 - 16-bit checksum' },
  'CRC-32': { regex: /^[a-f0-9]{8}$/i, length: 8, description: 'CRC-32 - 32-bit checksum' },
  'Adler-32': { regex: /^[a-f0-9]{8}$/i, length: 8, description: 'Adler-32 - 32-bit checksum' },
  'MySQL323': { regex: /^[a-f0-9]{16}$/i, length: 16, description: 'MySQL323 - Old MySQL password hash' },
  'MySQL5': { regex: /^\*[a-f0-9]{40}$/i, length: 41, description: 'MySQL5 - SHA1(SHA1(password))' },
  'PostgreSQL MD5': { regex: /^md5[a-f0-9]{32}$/i, length: 35, description: 'PostgreSQL MD5 password hash' },
  'MSSQL 2000': { regex: /^0x0100[a-f0-9]{48}$/i, length: 54, description: 'MSSQL 2000 password hash' },
  'MSSQL 2005': { regex: /^0x0100[a-f0-9]{80}$/i, length: 86, description: 'MSSQL 2005+ password hash' },
  'Oracle 10g': { regex: /^[a-f0-9]{16}$/i, length: 16, description: 'Oracle 10g password hash' },
  'Oracle 11g': { regex: /^S:[a-f0-9]{60}$/i, length: 62, description: 'Oracle 11g password hash' },
  'LM Hash': { regex: /^[a-f0-9]{32}$/i, length: 32, description: 'LM Hash - Legacy Windows' },
  'bcrypt': { regex: /^\$2[aby]\$[0-9]{2}\$[a-zA-Z0-9\/\.]{53}$/, length: 60, description: 'bcrypt - Adaptive hash function' },
  'scrypt': { regex: /^\$7\$[A-Za-z0-9\/\.]+$/, length: null, description: 'scrypt - Memory-hard hash' },
  'Argon2': { regex: /^\$argon2[id]?\$[a-z0-9=]+\$[A-Za-z0-9\/\.+=]+$/, length: null, description: 'Argon2 - Memory-hard hash' },
  'PBKDF2': { regex: /^\$pbkdf2[a-z0-9]*\$[0-9]+\$[A-Za-z0-9\/\.]+\$[A-Za-z0-9\/\.]+$/, length: null, description: 'PBKDF2 - Key derivation' },
  'JWT': { regex: /^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*$/, length: null, description: 'JSON Web Token' },
  'Base64': { regex: /^[A-Za-z0-9+\/]+=*$/, length: null, description: 'Base64 encoded data' },
  'Hex': { regex: /^[a-f0-9]+$/i, length: null, description: 'Hexadecimal data' }
};

async function hashOSINT(hash) {
  const startTime = Date.now();
  const result = { hash, possibleTypes: [], analysis: {}, risk: { score: 0, level: 'Low', indicators: [] } };
  
  const cleanHash = hash.trim();
  
  // Identify possible hash types
  for (const [name, pattern] of Object.entries(HASH_PATTERNS)) {
    if (pattern.regex.test(cleanHash)) {
      result.possibleTypes.push({ name, description: pattern.description, length: pattern.length });
    }
  }
  
  // Additional analysis
  result.analysis = {
    length: cleanHash.length,
    charset: /[a-f0-9]/i.test(cleanHash) && !/[g-z]/i.test(cleanHash) ? 'Hexadecimal' : 'Mixed',
    entropy: calculateEntropy(cleanHash),
    hasSalt: cleanHash.includes('$') || cleanHash.includes('*'),
    format: cleanHash.startsWith('$') ? 'Unix-style' : cleanHash.startsWith('0x') ? 'Hex prefix' : 'Plain'
  };
  
  // Risk assessment
  if (result.possibleTypes.some(t => t.name.includes('MD5') || t.name.includes('MD4') || t.name.includes('LM'))) {
    result.risk.indicators.push('Weak/cryptographically broken hash algorithm detected');
    result.risk.score += 30;
  }
  
  if (result.possibleTypes.some(t => t.name.includes('SHA-1'))) {
    result.risk.indicators.push('SHA-1 is considered weak for cryptographic purposes');
    result.risk.score += 15;
  }
  
  if (result.analysis.entropy < 3) {
    result.risk.indicators.push('Low entropy - may be simple/short input');
    result.risk.score += 10;
  }
  
  if (!result.analysis.hasSalt && result.possibleTypes.length > 0) {
    result.risk.indicators.push('Unsalted hash - vulnerable to rainbow tables');
    result.risk.score += 20;
  }
  
  // Set risk level
  if (result.risk.score >= 50) result.risk.level = 'High';
  else if (result.risk.score >= 25) result.risk.level = 'Medium';
  
  result.scanTime = Date.now() - startTime;
  
  // Display results
  console.log(`\n${c.magenta}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
  console.log(`${c.magenta}║${c.reset}  ${c.bold}HASH ANALYSIS RESULTS${c.reset}                                                                         ${c.magenta}║${c.reset}`);
  console.log(`${c.magenta}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  console.log(`${c.magenta}║${c.reset}  Hash: ${c.y}${cleanHash.substring(0, 60)}${cleanHash.length > 60 ? '...' : ''}${' '.repeat(Math.max(0, 85 - Math.min(cleanHash.length, 60) - 3))}${c.magenta}║${c.reset}`);
  console.log(`${c.magenta}║${c.reset}  Length: ${result.analysis.length} characters${' '.repeat(80 - result.analysis.length.toString().length)}${c.magenta}║${c.reset}`);
  console.log(`${c.magenta}║${c.reset}  Charset: ${result.analysis.charset}${' '.repeat(85 - result.analysis.charset.length)}${c.magenta}║${c.reset}`);
  console.log(`${c.magenta}║${c.reset}  Entropy: ${result.analysis.entropy.toFixed(2)} bits/char${' '.repeat(76 - result.analysis.entropy.toFixed(2).length)}${c.magenta}║${c.reset}`);
  console.log(`${c.magenta}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  
  if (result.possibleTypes.length > 0) {
    console.log(`${c.magenta}║${c.reset}  ${c.bold}Possible Hash Types:${c.reset}${' '.repeat(75)}${c.magenta}║${c.reset}`);
    result.possibleTypes.slice(0, 6).forEach(type => {
      console.log(`${c.magenta}║${c.reset}    ${c.g}●${c.reset} ${type.name}: ${c.dim}${type.description}${' '.repeat(Math.max(0, 83 - type.name.length - type.description.length))}${c.magenta}║${c.reset}`);
    });
    if (result.possibleTypes.length > 6) {
      console.log(`${c.magenta}║${c.reset}    ${c.y}... and ${result.possibleTypes.length - 6} more possibilities${' '.repeat(55)}${c.magenta}║${c.reset}`);
    }
  } else {
    console.log(`${c.magenta}║${c.reset}  ${c.y}⚠${c.reset} No recognized hash format detected${' '.repeat(62)}${c.magenta}║${c.reset}`);
  }
  
  console.log(`${c.magenta}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  console.log(`${c.magenta}║${c.reset}  Risk Level: ${result.risk.level === 'High' ? c.r : result.risk.level === 'Medium' ? c.y : c.g}${result.risk.level}${c.reset}${' '.repeat(85 - result.risk.level.length)}${c.magenta}║${c.reset}`);
  
  if (result.risk.indicators.length > 0) {
    result.risk.indicators.forEach(ind => {
      console.log(`${c.magenta}║${c.reset}  ${c.y}⚠${c.reset} ${ind}${' '.repeat(Math.max(0, 87 - ind.length))}${c.magenta}║${c.reset}`);
    });
  }
  
  console.log(`${c.magenta}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
  
  // Save result
  const filename = `hash_${Date.now()}.json`;
  fs.writeFileSync(path.join(RESULTS_DIR, filename), JSON.stringify(result, null, 2));
  console.log(`\n  ${c.dim}Results saved to: ${RESULTS_DIR}/${filename}${c.reset}`);
  
  return result;
}

function calculateEntropy(str) {
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ==================== MAIN ====================

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const question = prompt => new Promise(resolve => rl.question(prompt, resolve));

// License authentication
let LICENSE_INFO = null;

async function showLicenseScreen() {
  console.clear();
  
  // Animated header
  const lines = [
    '╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗',
    '║                                                                                                       ║',
    '║   TTTTTTTTTT   RRRRRRRRR    AAA       UUU    UUU   MMMM      MMMM    AAA                             ║',
    '║   TTTTTTTTTT   RRRRRRRRR   AAAAA      UUU    UUU   MMMM      MMMM   AAAAA                            ║',
    '║       TT       RR     RR  AA   AA     UUU    UUU   MM  MM  MM  MM  AA   AA                           ║',
    '║       TT       RR     RR  AA   AA     UUU    UUU   MM  MM  MM  MM  AA   AA                           ║',
    '║       TT       RRRRRRRRR  AAAAAAA     UUU    UUU   MM   MMM   MM  AAAAAAA                           ║',
    '║       TT       RRRRRRRR   AAAAAAA     UUU    UUU   MM   MMM   MM  AAAAAAA                           ║',
    '║       TT       RR  RRR    AA   AA     UUU    UUU   MM   MMM   MM  AA   AA                           ║',
    '║       TT       RR   RR    AA   AA     UUU    UUU   MM  MM  MM  MM  AA   AA                           ║',
    '║       TT       RR    RR   AA   AA     UUUUUUUUU    MMMM      MMMM   AA   AA                          ║',
    '║       TT       RR     RR  AA   AA      UUUUUUU     MMMM      MMMM   AA   AA                          ║',
    '║       TT       RR      RR AA   AA       UUUUU      MMMM      MMMM   AA   AA                          ║',
    '║                                                                                                       ║',
    '╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣',
    '║                     ▶ O S I N T   T O O L K I T   v2.0 ◀                                              ║',
    '║                        Advanced Intelligence Platform                                                 ║',
    '╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝'
  ];
  
  lines.forEach((line, i) => {
    setTimeout(() => console.log('\x1b[31m' + line + '\x1b[0m'), i * 30);
  });
  
  await new Promise(r => setTimeout(r, 500));
  
  console.log('\n');
  console.log('\x1b[33m┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐\x1b[0m');
  console.log('\x1b[33m│  \x1b[1mLICENSE AUTHENTICATION REQUIRED\x1b[0m                                                                         │\x1b[0m');
  console.log('\x1b[33m├─────────────────────────────────────────────────────────────────────────────────────────────────────┤\x1b[0m');
  console.log('\x1b[33m│                                                                                                     │\x1b[0m');
  console.log('\x1b[33m│  \x1b[36mEnter your TRUMA OSINT license key to activate.\x1b[0m                                                             │\x1b[0m');
  console.log('\x1b[33m│  \x1b[2mFormat: TRUMA-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX\x1b[0m                                                                  │\x1b[0m');
  console.log('\x1b[33m│                                                                                                     │\x1b[0m');
  console.log('\x1b[33m└─────────────────────────────────────────────────────────────────────────────────────────────────────┘\x1b[0m');
  
  const key = await question(`\n  \x1b[33m▶\x1b[0m License Key: `);
  
  const result = checkLicense();
  
  if (!result.valid) {
    // Try to activate new key
    const activation = activateLicense(key.trim().toUpperCase());
    if (activation.success) {
      console.log('\n  \x1b[32m✓ License activated successfully!\x1b[0m');
      console.log('  \x1b[2mLicensed to: Activated User\x1b[0m');
      await new Promise(r => setTimeout(r, 1500));
      return true;
    } else {
      console.log(`\n  \x1b[31m✗ ${activation.error || 'Invalid license key'}\x1b[0m`);
      console.log('  \x1b[2mContact administrator for a valid license key.\x1b[0m');
      await new Promise(r => setTimeout(r, 2000));
      rl.close();
      process.exit(1);
    }
  }
  
  LICENSE_INFO = result;
  console.log('\n  \x1b[32m✓ License verified!\x1b[0m');
  if (result.user) console.log(`  \x1b[2mLicensed to: ${result.user}\x1b[0m`);
  await new Promise(r => setTimeout(r, 1000));
  return true;
}

async function showBanner() {
  console.clear();
  
  console.log('\x1b[31m╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗\x1b[0m');
  console.log('\x1b[31m║                                                                                                       ║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33mTTTTTTTTTT   RRRRRRRRR    AAA       UUU    UUU   MMMM      MMMM    AAA                             \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33mTTTTTTTTTT   RRRRRRRRR   AAAAA      UUU    UUU   MMMM      MMMM   AAAAA                            \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33m    TT       RR     RR  AA   AA     UUU    UUU   MM  MM  MM  MM  AA   AA                           \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33m    TT       RR     RR  AA   AA     UUU    UUU   MM  MM  MM  MM  AA   AA                           \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33m    TT       RRRRRRRRR  AAAAAAA     UUU    UUU   MM   MMM   MM  AAAAAAA                           \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33m    TT       RRRRRRRR   AAAAAAA     UUU    UUU   MM   MMM   MM  AAAAAAA                           \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33m    TT       RR  RRR    AA   AA     UUU    UUU   MM   MMM   MM  AA   AA                           \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33m    TT       RR   RR    AA   AA     UUU    UUU   MM  MM  MM  MM  AA   AA                           \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33m    TT       RR    RR   AA   AA     UUUUUUUUU    MMMM      MMMM   AA   AA                          \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33m    TT       RR     RR  AA   AA      UUUUUUU     MMMM      MMMM   AA   AA                          \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║   \x1b[1m\x1b[33m    TT       RR      RR AA   AA       UUUUU      MMMM      MMMM   AA   AA                          \x1b[0m\x1b[31m║\x1b[0m');
  console.log('\x1b[31m║                                                                                                       ║\x1b[0m');
  console.log('\x1b[31m╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣\x1b[0m');
  console.log('\x1b[31m║       \x1b[36m▶ O S I N T   T O O L K I T   v2.0 ◀\x1b[0m                                                              \x1b[31m║\x1b[0m');
  console.log('\x1b[31m║       \x1b[2mAdvanced Intelligence Platform\x1b[0m                                                                    \x1b[31m║\x1b[0m');
  if (LICENSE_INFO) {
    console.log('\x1b[31m║       \x1b[32m● Licensed\x1b[0m                                                                            \x1b[31m║\x1b[0m');
  }
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
  
  // Improved menu design
  console.log(`\n${c.r}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
  console.log(`${c.r}║  ${c.bold}${c.y}SELECT SCAN TYPE${c.reset}                                                                              ${c.r}║${c.reset}`);
  console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  console.log(`${c.r}║                                                                                                     ${c.r}║${c.reset}`);
  console.log(`${c.r}║  ${c.y}[1]${c.reset} ${c.bold}📧 Email${c.reset}           ${c.dim}Breach check, DNS records, SMTP validation, Risk assessment${c.reset}      ${c.r}║${c.reset}`);
  console.log(`${c.r}║  ${c.y}[2]${c.reset} ${c.bold}📱 Phone${c.reset}           ${c.dim}Location lookup, Carrier detection, Format validation${c.reset}         ${c.r}║${c.reset}`);
  console.log(`${c.r}║  ${c.y}[3]${c.reset} ${c.bold}👤 Username${c.reset}         ${c.dim}Search 75+ platforms, Social media discovery, Categories${c.reset}     ${c.r}║${c.reset}`);
  console.log(`${c.r}║  ${c.y}[4]${c.reset} ${c.bold}🌐 IP Address${c.reset}       ${c.dim}Port scanning, Reverse DNS, Geolocation, Risk analysis${c.reset}       ${c.r}║${c.reset}`);
  console.log(`${c.r}║  ${c.y}[5]${c.reset} ${c.bold}🔗 Domain${c.reset}          ${c.dim}DNS reconnaissance, Subdomain enumeration, Security audit${c.reset}    ${c.r}║${c.reset}`);
  console.log(`${c.r}║  ${c.y}[6]${c.reset} ${c.bold}🖼️  Image${c.reset}           ${c.dim}EXIF extraction, Metadata analysis, Hash calculation${c.reset}         ${c.r}║${c.reset}`);
  console.log(`${c.r}║  ${c.y}[7]${c.reset} ${c.bold}🕷️  Web Scrape${c.reset}       ${c.dim}Link extraction, Email harvesting, Technology detection${c.reset}      ${c.r}║${c.reset}`);
  console.log(`${c.r}║  ${c.y}[8]${c.reset} ${c.bold}💻 MAC Address${c.reset}       ${c.dim}OUI vendor lookup, Device type classification, Risk analysis${c.reset}     ${c.r}║${c.reset}`);
  console.log(`${c.r}║  ${c.y}[9]${c.reset} ${c.bold}🔐 Hash Analysis${c.reset}      ${c.dim}Hash identification, Entropy calculation, Algorithm detection${c.reset}    ${c.r}║${c.reset}`);
  console.log(`${c.r}║                                                                                                     ${c.r}║${c.reset}`);
  console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
  console.log(`${c.r}║  ${c.dim}[Q] Quit${c.reset}                                                                                   ${c.r}║${c.reset}`);
  console.log(`${c.r}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);

  const choice = await question(`\n  ${c.y}▶${c.reset} Select: `);

  switch (choice.trim()) {
    case '1': {
      const email = await question(`  ${c.y}▶${c.reset} Email: `);
      if (email.includes('@')) {
        console.log(`\n${c.r}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
        console.log(`${c.r}║  ${c.bold}${c.y}📧 EMAIL OSINT SCAN${c.reset}                                                                        ${c.r}║${c.reset}`);
        console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
        console.log(`${c.r}║  ${c.dim}Analyzing: ${email}${' '.repeat(85 - email.length)}${c.r}║${c.reset}`);
        console.log(`${c.r}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
        await emailOSINT(email);
      }
      else log('  ✗ Invalid email format!', 'r');
      break;
    }
    case '2': {
      const phone = await question(`  ${c.y}▶${c.reset} Phone: `);
      if (phone.length > 0) {
        console.log(`\n${c.r}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
        console.log(`${c.r}║  ${c.bold}${c.y}📱 PHONE OSINT SCAN${c.reset}                                                                        ${c.r}║${c.reset}`);
        console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
        console.log(`${c.r}║  ${c.dim}Analyzing: ${phone}${' '.repeat(85 - phone.length)}${c.r}║${c.reset}`);
        console.log(`${c.r}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
        await phoneOSINT(phone);
      }
      break;
    }
    case '3': {
      const username = await question(`  ${c.y}▶${c.reset} Username: `);
      if (username.length > 0) {
        console.log(`\n${c.r}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
        console.log(`${c.r}║  ${c.bold}${c.y}👤 USERNAME OSINT SCAN${c.reset}                                                                      ${c.r}║${c.reset}`);
        console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
        console.log(`${c.r}║  ${c.dim}Searching 75+ platforms for: ${username}${' '.repeat(68 - username.length)}${c.r}║${c.reset}`);
        console.log(`${c.r}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
        await usernameOSINT(username);
      }
      break;
    }
    case '4': {
      const ip = await question(`  ${c.y}▶${c.reset} IP: `);
      if (ip.length > 0) {
        console.log(`\n${c.r}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
        console.log(`${c.r}║  ${c.bold}${c.y}🌐 IP ADDRESS OSINT SCAN${c.reset}                                                                    ${c.r}║${c.reset}`);
        console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
        console.log(`${c.r}║  ${c.dim}Scanning: ${ip}${' '.repeat(86 - ip.length)}${c.r}║${c.reset}`);
        console.log(`${c.r}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
        await ipOSINT(ip);
      }
      break;
    }
    case '5': {
      const domain = await question(`  ${c.y}▶${c.reset} Domain: `);
      if (domain.includes('.')) {
        console.log(`\n${c.r}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
        console.log(`${c.r}║  ${c.bold}${c.y}🔗 DOMAIN OSINT SCAN${c.reset}                                                                        ${c.r}║${c.reset}`);
        console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
        console.log(`${c.r}║  ${c.dim}Reconnaissance: ${domain}${' '.repeat(81 - domain.length)}${c.r}║${c.reset}`);
        console.log(`${c.r}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
        await domainOSINT(domain);
      }
      else log('  ✗ Invalid domain format!', 'r');
      break;
    }
    case '6': {
      const imagePath = await question(`  ${c.y}▶${c.reset} Image path: `);
      if (imagePath.length > 0) {
        console.log(`\n${c.r}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
        console.log(`${c.r}║  ${c.bold}${c.y}🖼️  IMAGE METADATA EXTRACTION${c.reset}                                                                 ${c.r}║${c.reset}`);
        console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
        console.log(`${c.r}║  ${c.dim}Extracting metadata from image...${' '.repeat(63)}${c.r}║${c.reset}`);
        console.log(`${c.r}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
        await imageOSINT(imagePath);
      }
      break;
    }
    case '7': {
      const url = await question(`  ${c.y}▶${c.reset} URL: `);
      if (url.length > 0) {
        console.log(`\n${c.r}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
        console.log(`${c.r}║  ${c.bold}${c.y}🕷️  WEB SCRAPER OSINT${c.reset}                                                                        ${c.r}║${c.reset}`);
        console.log(`${c.r}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
        console.log(`${c.r}║  ${c.dim}Scraping: ${url}${' '.repeat(86 - Math.min(url.length, 86))}${c.r}║${c.reset}`);
        console.log(`${c.r}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
        await webScrapeOSINT(url);
      }
      break;
    }
    case '8': {
      const mac = await question(`  ${c.y}▶${c.reset} MAC Address: `);
      if (mac.length > 0) {
        console.log(`\n${c.cyan}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
        console.log(`${c.cyan}║  ${c.bold}${c.y}💻 MAC ADDRESS OSINT SCAN${c.reset}                                                                    ${c.cyan}║${c.reset}`);
        console.log(`${c.cyan}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
        console.log(`${c.cyan}║  ${c.dim}Looking up vendor for: ${mac}${' '.repeat(72 - mac.length)}${c.cyan}║${c.reset}`);
        console.log(`${c.cyan}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
        await macOSINT(mac);
      }
      break;
    }
    case '9': {
      const hash = await question(`  ${c.y}▶${c.reset} Hash: `);
      if (hash.length > 0) {
        console.log(`\n${c.magenta}╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗${c.reset}`);
        console.log(`${c.magenta}║  ${c.bold}${c.y}🔐 HASH ANALYSIS OSINT${c.reset}                                                                      ${c.magenta}║${c.reset}`);
        console.log(`${c.magenta}╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣${c.reset}`);
        console.log(`${c.magenta}║  ${c.dim}Identifying hash algorithm...${' '.repeat(68)}${c.magenta}║${c.reset}`);
        console.log(`${c.magenta}╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝${c.reset}`);
        await hashOSINT(hash);
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

// Initialize with license check
async function init() {
  let licenseResult = null;
  
  // Try remote validation first
  if (remoteValidator) {
    try {
      const key = getStoredLicenseKey();
      if (key) {
        licenseResult = await remoteValidator.validate(key);
        if (licenseResult.valid) {
          console.log(chalk.green('\n  ✓ License validated remotely'));
        }
      }
    } catch (e) {
      console.log(chalk.yellow('  Remote validation unavailable, using local...'));
    }
  }
  
  // Fallback to local validation
  if (!licenseResult || !licenseResult.valid) {
    licenseResult = checkLicense();
  }
  
  if (!licenseResult.valid) {
    await showLicenseScreen();
  } else {
    LICENSE_INFO = licenseResult;
  }
  
  await mainMenu();
}

// Helper to get stored license key
function getStoredLicenseKey() {
  try {
    const keyFile = path.join(APP_DIR, 'license.key');
    if (fs.existsSync(keyFile)) {
      const data = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      return data.key;
    }
  } catch (e) {}
  return null;
}

init().catch(console.error);
