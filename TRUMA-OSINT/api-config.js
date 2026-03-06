/**
 * TRAUMA OSINT - API Configuration
 * 
 * Add your API keys below to enable external API integrations.
 * All keys are stored locally and never shared.
 * 
 * Get your free API keys from:
 * - Shodan: https://account.shodan.io/api
 * - HaveIBeenPwned: https://haveibeenpwned.com/API/Key
 * - Hunter.io: https://hunter.io/api
 * - IPGeolocation: https://ipgeolocation.io/api
 * - VirusTotal: https://virustotal.com/api
 * - AbuseIPDB: https://abuseipdb.com/api
 * - SecurityTrails: https://securitytrails.com/api
 */

const API_CONFIG = {
  // Shodan - IP/Device intelligence, port scanning, vulnerabilities
  shodan: {
    enabled: true,
    apiKey: '', // Add your Shodan API key here
    baseUrl: 'https://api.shodan.io',
    endpoints: {
      host: '/shodan/host/{ip}',
      dns: '/dns/domain/{domain}',
      search: '/shodan/host/search',
      ports: '/shodan/ports',
      honeypot: '/labs/honeypot/{ip}'
    }
  },

  // HaveIBeenPwned - Breach database
  haveibeenpwned: {
    enabled: true,
    apiKey: '', // Add your HIBP API key here
    baseUrl: 'https://haveibeenpwned.com/api/v3',
    endpoints: {
      breaches: '/breaches',
      breach: '/breach/{name}',
      breachedaccount: '/breachedaccount/{email}',
      pasteaccount: '/pasteaccount/{email}'
    }
  },

  // Hunter.io - Email finder and verification
  hunter: {
    enabled: true,
    apiKey: '', // Add your Hunter.io API key here
    baseUrl: 'https://api.hunter.io/v2',
    endpoints: {
      verify: '/email-verifier',
      finder: '/email-finder',
      domain: '/domain-search'
    }
  },

  // IPGeolocation - Accurate IP location
  ipgeolocation: {
    enabled: true,
    apiKey: '', // Add your IPGeolocation API key here
    baseUrl: 'https://api.ipgeolocation.io',
    endpoints: {
      ipgeo: '/ipgeo',
      useragent: '/user-agent'
    }
  },

  // VirusTotal - URL/IP/Domain reputation
  virustotal: {
    enabled: true,
    apiKey: '', // Add your VirusTotal API key here
    baseUrl: 'https://www.virustotal.io/api/v3',
    endpoints: {
      ip: '/ip_addresses/{ip}',
      domain: '/domains/{domain}',
      url: '/urls/{url}',
      file: '/files/{hash}'
    }
  },

  // AbuseIPDB - IP abuse database
  abuseipdb: {
    enabled: true,
    apiKey: '', // Add your AbuseIPDB API key here
    baseUrl: 'https://api.abuseipdb.com/api/v2',
    endpoints: {
      check: '/check',
      blacklist: '/blacklist',
      report: '/report'
    }
  },

  // SecurityTrails - Domain and IP history
  securitytrails: {
    enabled: false,
    apiKey: '', // Add your SecurityTrails API key here
    baseUrl: 'https://api.securitytrails.com/v1',
    endpoints: {
      domain: '/domain/{domain}',
      subdomains: '/domain/{domain}/subdomains',
      history: '/history/{domain}/dns/a',
      ips: '/ips/nearby/{ip}'
    }
  },

  // ip-api.com - Free IP geolocation (no key required)
  ipapi: {
    enabled: true,
    apiKey: null, // No key required for free tier
    baseUrl: 'http://ip-api.com',
    endpoints: {
      query: '/json/{ip}'
    }
  },

  // ipapi.co - Another free IP geolocation
  ipapico: {
    enabled: true,
    apiKey: null,
    baseUrl: 'https://ipapi.co',
    endpoints: {
      query: '/{ip}/json/'
    }
  }
};

/**
 * Check if an API is configured (has API key or doesn't require one)
 */
function isAPIConfigured(apiName) {
  const api = API_CONFIG[apiName];
  if (!api) return false;
  if (!api.enabled) return false;
  if (api.apiKey === null) return true; // No key required
  return api.apiKey && api.apiKey.length > 0;
}

/**
 * Get API configuration
 */
function getAPIConfig(apiName) {
  return API_CONFIG[apiName] || null;
}

/**
 * Make API request with proper headers
 */
async function apiRequest(apiName, endpoint, params = {}) {
  const api = API_CONFIG[apiName];
  if (!api || !api.enabled) {
    return { error: 'API not enabled', data: null };
  }

  if (api.apiKey && !api.apiKey) {
    return { error: 'API key not configured', data: null };
  }

  const https = require('https');
  const http = require('http');
  const client = api.baseUrl.startsWith('https') ? https : http;

  let url = api.baseUrl + api.endpoints[endpoint];
  
  // Replace placeholders in URL
  Object.keys(params).forEach(key => {
    url = url.replace(`{${key}}`, encodeURIComponent(params[key]));
  });

  // Add query parameters
  const queryParams = [];
  if (api.apiKey) {
    if (apiName === 'shodan') queryParams.push(`key=${api.apiKey}`);
    else if (apiName === 'hunter') queryParams.push(`api_key=${api.apiKey}`);
    else if (apiName === 'ipgeolocation') queryParams.push(`apiKey=${api.apiKey}`);
    else if (apiName === 'virustotal') {
      // VT uses header auth
    }
    else if (apiName === 'abuseipdb') {
      // Uses header auth
    }
    else if (apiName === 'securitytrails') {
      // Uses header auth
    }
    else if (apiName === 'haveibeenpwned') {
      // Uses header auth
    }
  }
  
  // Add custom params
  Object.keys(params).forEach(key => {
    if (key !== 'ip' && key !== 'domain' && key !== 'email' && key !== 'url') {
      queryParams.push(`${key}=${encodeURIComponent(params[key])}`);
    }
  });

  if (queryParams.length > 0) {
    url += '?' + queryParams.join('&');
  }

  return new Promise((resolve) => {
    const headers = {
      'User-Agent': 'TRAUMA-OSINT/2.0'
    };

    // Add API key headers where needed
    if (api.apiKey) {
      if (apiName === 'virustotal') headers['x-apikey'] = api.apiKey;
      else if (apiName === 'abuseipdb') headers['Key'] = api.apiKey;
      else if (apiName === 'securitytrails') headers['APIKEY'] = api.apiKey;
      else if (apiName === 'haveibeenpwned') {
        headers['hibp-api-key'] = api.apiKey;
        headers['User-Agent'] = 'TRAUMA-OSINT';
      }
    }

    const req = client.request(url, { method: 'GET', headers, timeout: 10000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ error: null, data: json, status: res.statusCode });
        } catch (e) {
          resolve({ error: 'Parse error', data: data, status: res.statusCode });
        }
      });
    });

    req.on('error', (e) => resolve({ error: e.message, data: null }));
    req.on('timeout', () => { req.destroy(); resolve({ error: 'Timeout', data: null }); });
    req.end();
  });
}

module.exports = {
  API_CONFIG,
  isAPIConfigured,
  getAPIConfig,
  apiRequest
};
