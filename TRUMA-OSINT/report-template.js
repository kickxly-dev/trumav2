// HTML Report Generator for TRUMA-OSINT

function generateReport(type, data) {
  const timestamp = new Date().toISOString();
  const date = new Date().toLocaleString();
  
  const baseStyles = `
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #1a0000 0%, #330000 100%); padding: 30px; border-radius: 10px; margin-bottom: 20px; text-align: center; border: 1px solid #ff3333; }
    .header h1 { color: #ff4444; font-size: 2.5em; margin-bottom: 10px; text-shadow: 0 0 20px rgba(255,68,68,0.5); }
    .header .subtitle { color: #888; font-size: 1.1em; }
    .header .target { color: #fff; font-size: 1.3em; margin-top: 15px; padding: 10px 20px; background: rgba(255,68,68,0.1); border-radius: 5px; display: inline-block; }
    .meta { display: flex; justify-content: center; gap: 30px; margin-top: 15px; color: #666; font-size: 0.9em; }
    .section { background: #111; border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #222; }
    .section h2 { color: #ff4444; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #333; display: flex; align-items: center; gap: 10px; }
    .section h2 .icon { font-size: 1.2em; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
    .card { background: #1a1a1a; border-radius: 8px; padding: 15px; border: 1px solid #333; }
    .card h3 { color: #ff6666; margin-bottom: 10px; font-size: 1em; }
    .stat { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #222; }
    .stat:last-child { border-bottom: none; }
    .stat-label { color: #888; }
    .stat-value { color: #fff; font-weight: bold; }
    .stat-value.good { color: #00ff00; }
    .stat-value.bad { color: #ff4444; }
    .stat-value.warning { color: #ffaa00; }
    .tag { display: inline-block; padding: 3px 10px; border-radius: 15px; font-size: 0.85em; margin: 3px; }
    .tag.good { background: rgba(0,255,0,0.1); color: #00ff00; border: 1px solid rgba(0,255,0,0.3); }
    .tag.bad { background: rgba(255,0,0,0.1); color: #ff4444; border: 1px solid rgba(255,0,0,0.3); }
    .tag.warning { background: rgba(255,170,0,0.1); color: #ffaa00; border: 1px solid rgba(255,170,0,0.3); }
    .tag.info { background: rgba(68,68,255,0.1); color: #4444ff; border: 1px solid rgba(68,68,255,0.3); }
    .list { list-style: none; }
    .list li { padding: 8px 12px; margin: 5px 0; background: #1a1a1a; border-radius: 5px; border-left: 3px solid #ff4444; }
    .list li a { color: #4488ff; text-decoration: none; }
    .list li a:hover { text-decoration: underline; }
    .progress-bar { background: #222; border-radius: 10px; height: 20px; overflow: hidden; margin: 10px 0; }
    .progress-fill { height: 100%; transition: width 0.5s ease; }
    .progress-fill.low { background: linear-gradient(90deg, #00ff00, #00cc00); }
    .progress-fill.medium { background: linear-gradient(90deg, #ffaa00, #ff8800); }
    .progress-fill.high { background: linear-gradient(90deg, #ff4444, #cc0000); }
    .chart-container { display: flex; align-items: flex-end; justify-content: space-around; height: 150px; padding: 20px 0; }
    .chart-bar { width: 40px; background: linear-gradient(180deg, #ff4444 0%, #aa0000 100%); border-radius: 5px 5px 0 0; position: relative; transition: height 0.5s ease; }
    .chart-bar:hover { background: linear-gradient(180deg, #ff6666 0%, #cc0000 100%); }
    .chart-bar .label { position: absolute; bottom: -25px; left: 50%; transform: translateX(-50%); font-size: 0.7em; color: #888; white-space: nowrap; }
    .chart-bar .value { position: absolute; top: -25px; left: 50%; transform: translateX(-50%); font-size: 0.8em; color: #fff; }
    .pie-chart { width: 200px; height: 200px; border-radius: 50%; margin: 20px auto; position: relative; }
    .pie-legend { display: flex; flex-wrap: wrap; justify-content: center; gap: 15px; margin-top: 20px; }
    .pie-legend-item { display: flex; align-items: center; gap: 8px; font-size: 0.9em; }
    .pie-legend-color { width: 15px; height: 15px; border-radius: 3px; }
    .risk-meter { text-align: center; padding: 30px; }
    .risk-circle { width: 150px; height: 150px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 2em; font-weight: bold; border: 5px solid; }
    .risk-circle.low { border-color: #00ff00; color: #00ff00; background: rgba(0,255,0,0.1); }
    .risk-circle.medium { border-color: #ffaa00; color: #ffaa00; background: rgba(255,170,0,0.1); }
    .risk-circle.high { border-color: #ff4444; color: #ff4444; background: rgba(255,0,0,0.1); }
    .risk-circle.critical { border-color: #ff0000; color: #ff0000; background: rgba(255,0,0,0.2); animation: pulse 1s infinite; }
    @keyframes pulse { 0%, 100% { box-shadow: 0 0 0 0 rgba(255,0,0,0.4); } 50% { box-shadow: 0 0 0 20px rgba(255,0,0,0); } }
    .footer { text-align: center; padding: 20px; color: #444; font-size: 0.9em; border-top: 1px solid #222; margin-top: 20px; }
    .print-btn { position: fixed; top: 20px; right: 20px; padding: 10px 20px; background: #ff4444; color: #fff; border: none; border-radius: 5px; cursor: pointer; font-size: 1em; }
    .print-btn:hover { background: #ff6666; }
    @media print { .print-btn { display: none; } body { background: #fff; color: #000; } .section { border: 1px solid #ccc; } }
  `;

  let content = '';
  
  switch(type) {
    case 'email':
      content = generateEmailReport(data);
      break;
    case 'phone':
      content = generatePhoneReport(data);
      break;
    case 'username':
      content = generateUsernameReport(data);
      break;
    case 'ip':
      content = generateIPReport(data);
      break;
    case 'domain':
      content = generateDomainReport(data);
      break;
    case 'web':
      content = generateWebReport(data);
      break;
    case 'image':
      content = generateImageReport(data);
      break;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TRUMA OSINT Report - ${data.email || data.phone || data.username || data.ip || data.domain || data.url || 'Scan Results'}</title>
  <style>${baseStyles}</style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">📄 Export PDF</button>
  <div class="container">
    <div class="header">
      <h1>🔴 TRUMA OSINT</h1>
      <div class="subtitle">Open Source Intelligence Report</div>
      <div class="target">${data.email || data.phone || data.username || data.ip || data.domain || data.url || 'Scan Target'}</div>
      <div class="meta">
        <span>📅 ${date}</span>
        <span>⏱️ ${timestamp}</span>
        <span>🔧 v3.0</span>
      </div>
    </div>
    ${content}
    <div class="footer">
      Generated by TRUMA OSINT v3.0 | For educational and legal use only
    </div>
  </div>
</body>
</html>`;
}

function generateEmailReport(data) {
  const riskLevel = data.risk?.level || 'LOW';
  const riskScore = data.risk?.score || 0;
  
  return `
    <div class="grid">
      <div class="section">
        <h2><span class="icon">📧</span> Email Analysis</h2>
        <div class="card">
          <h3>Validation</h3>
          <div class="stat"><span class="stat-label">Format Valid</span><span class="stat-value ${data.data?.valid ? 'good' : 'bad'}">${data.data?.valid ? '✓ YES' : '✗ NO'}</span></div>
          <div class="stat"><span class="stat-label">Disposable</span><span class="stat-value ${data.data?.disposable ? 'bad' : 'good'}">${data.data?.disposable ? '✗ YES' : '✓ NO'}</span></div>
          <div class="stat"><span class="stat-label">Role Account</span><span class="stat-value">${data.data?.role ? 'YES' : 'NO'}</span></div>
        </div>
        <div class="card" style="margin-top: 15px;">
          <h3>DNS Configuration</h3>
          <div class="stat"><span class="stat-label">MX Records</span><span class="stat-value">${data.data?.mx?.length || 0}</span></div>
          <div class="stat"><span class="stat-label">SPF Record</span><span class="stat-value ${data.data?.spf ? 'good' : 'warning'}">${data.data?.spf ? '✓ YES' : '✗ NO'}</span></div>
          <div class="stat"><span class="stat-label">DMARC</span><span class="stat-value ${data.data?.dmarc ? 'good' : 'warning'}">${data.data?.dmarc ? '✓ YES' : '✗ NO'}</span></div>
          <div class="stat"><span class="stat-label">SMTP Reachable</span><span class="stat-value ${data.data?.smtp ? 'good' : 'bad'}">${data.data?.smtp ? '✓ YES' : '✗ NO'}</span></div>
        </div>
      </div>
      
      <div class="section">
        <h2><span class="icon">⚠️</span> Risk Assessment</h2>
        <div class="risk-meter">
          <div class="risk-circle ${riskLevel.toLowerCase()}">${riskLevel}</div>
          <div class="progress-bar">
            <div class="progress-fill ${riskLevel.toLowerCase()}" style="width: ${Math.min(riskScore * 10, 100)}%"></div>
          </div>
          <p style="margin-top: 10px; color: #888;">Risk Score: ${riskScore}/10</p>
        </div>
        ${data.risk?.factors?.length ? `
        <div class="card" style="margin-top: 15px;">
          <h3>Risk Factors</h3>
          <ul class="list">
            ${data.risk.factors.map(f => `<li>${f}</li>`).join('')}
          </ul>
        </div>
        ` : ''}
      </div>
    </div>
    
    ${data.breach?.domainBreaches?.length ? `
    <div class="section">
      <h2><span class="icon">🔓</span> Breach Database</h2>
      <div class="grid">
        ${data.breach.domainBreaches.map(b => `
          <div class="card">
            <h3>${b.name}</h3>
            <div class="stat"><span class="stat-label">Date</span><span class="stat-value">${b.date}</span></div>
            <div class="stat"><span class="stat-label">Records</span><span class="stat-value bad">${b.records}</span></div>
          </div>
        `).join('')}
      </div>
    </div>
    ` : ''}
    
    ${data.social?.patterns?.length ? `
    <div class="section">
      <h2><span class="icon">🔍</span> Search Patterns</h2>
      <ul class="list">
        ${data.social.patterns.slice(0, 5).map(p => `<li><code>${p}</code></li>`).join('')}
      </ul>
    </div>
    ` : ''}
  `;
}

function generatePhoneReport(data) {
  const country = data.data?.country;
  const formats = data.data?.formats || {};
  
  return `
    <div class="grid">
      <div class="section">
        <h2><span class="icon">📱</span> Phone Analysis</h2>
        <div class="card">
          <h3>Validation</h3>
          <div class="stat"><span class="stat-label">Clean Number</span><span class="stat-value">${data.data?.clean || 'N/A'}</span></div>
          <div class="stat"><span class="stat-label">Digits</span><span class="stat-value">${(data.data?.clean || '').length}</span></div>
          <div class="stat"><span class="stat-label">Valid Format</span><span class="stat-value ${data.data?.valid ? 'good' : 'bad'}">${data.data?.valid ? '✓ YES' : '✗ NO'}</span></div>
        </div>
        ${country ? `
        <div class="card" style="margin-top: 15px;">
          <h3>Geolocation</h3>
          <div class="stat"><span class="stat-label">Country</span><span class="stat-value">${country.name}</span></div>
          <div class="stat"><span class="stat-label">Code</span><span class="stat-value">${country.code}</span></div>
        </div>
        ` : ''}
      </div>
      
      <div class="section">
        <h2><span class="icon">📝</span> Formatted Output</h2>
        <div class="card">
          ${Object.entries(formats).map(([name, value]) => `
            <div class="stat"><span class="stat-label">${name}</span><span class="stat-value">${value}</span></div>
          `).join('')}
        </div>
        ${data.data?.accounts ? `
        <div class="card" style="margin-top: 15px;">
          <h3>Quick Links</h3>
          <ul class="list">
            <li><a href="${data.data.accounts.whatsapp}" target="_blank">WhatsApp</a></li>
            <li><a href="${data.data.accounts.telegram}" target="_blank">Telegram</a></li>
          </ul>
        </div>
        ` : ''}
      </div>
    </div>
    
    ${data.data?.risks?.length ? `
    <div class="section">
      <h2><span class="icon">⚠️</span> Risk Factors</h2>
      <ul class="list">
        ${data.data.risks.map(r => `<li>${r}</li>`).join('')}
      </ul>
    </div>
    ` : ''}
  `;
}

function generateUsernameReport(data) {
  const platforms = data.platforms || [];
  const found = platforms.filter(p => p.status === 'FOUND');
  const notFound = platforms.filter(p => p.status === 'NOT FOUND');
  
  return `
    <div class="grid">
      <div class="section">
        <h2><span class="icon">👤</span> Username Analysis</h2>
        <div class="card">
          <h3>Statistics</h3>
          <div class="stat"><span class="stat-label">Length</span><span class="stat-value">${data.analysis?.length || 0}</span></div>
          <div class="stat"><span class="stat-label">Has Numbers</span><span class="stat-value">${data.analysis?.hasNumbers ? 'YES' : 'NO'}</span></div>
          <div class="stat"><span class="stat-label">Has Special Chars</span><span class="stat-value">${data.analysis?.hasSpecial ? 'YES' : 'NO'}</span></div>
        </div>
      </div>
      
      <div class="section">
        <h2><span class="icon">📊</span> Platform Results</h2>
        <div class="chart-container">
          <div class="chart-bar" style="height: ${(found.length / platforms.length) * 100}px; background: linear-gradient(180deg, #00ff00 0%, #00aa00 100%);">
            <span class="value">${found.length}</span>
            <span class="label">Found</span>
          </div>
          <div class="chart-bar" style="height: ${(notFound.length / platforms.length) * 100}px; background: linear-gradient(180deg, #ff4444 0%, #aa0000 100%);">
            <span class="value">${notFound.length}</span>
            <span class="label">Not Found</span>
          </div>
        </div>
        <div style="text-align: center; margin-top: 30px;">
          <span class="tag good">${found.length} Found</span>
          <span class="tag bad">${notFound.length} Not Found</span>
        </div>
      </div>
    </div>
    
    ${found.length > 0 ? `
    <div class="section">
      <h2><span class="icon">✅</span> Confirmed Presence</h2>
      <ul class="list">
        ${found.map(p => `<li><a href="${p.url}" target="_blank">${p.name}</a></li>`).join('')}
      </ul>
    </div>
    ` : ''}
    
    ${data.variations?.length ? `
    <div class="section">
      <h2><span class="icon">🔄</span> Username Variations</h2>
      <div style="display: flex; flex-wrap: wrap; gap: 5px;">
        ${data.variations.slice(0, 20).map(v => `<span class="tag info">${v}</span>`).join('')}
      </div>
    </div>
    ` : ''}
  `;
}

function generateIPReport(data) {
  const ports = data.data?.ports || [];
  const risks = data.data?.risks || [];
  const riskLevel = data.data?.riskLevel || 'LOW';
  
  return `
    <div class="grid">
      <div class="section">
        <h2><span class="icon">🌐</span> IP Analysis</h2>
        <div class="card">
          <h3>Classification</h3>
          <div class="stat"><span class="stat-label">Private IP</span><span class="stat-value ${data.data?.private ? 'warning' : 'good'}">${data.data?.private ? 'YES' : 'NO'}</span></div>
          <div class="stat"><span class="stat-label">Loopback</span><span class="stat-value">${data.data?.loopback ? 'YES' : 'NO'}</span></div>
          <div class="stat"><span class="stat-label">Multicast</span><span class="stat-value">${data.data?.multicast ? 'YES' : 'NO'}</span></div>
        </div>
        ${data.data?.reverse?.length ? `
        <div class="card" style="margin-top: 15px;">
          <h3>Reverse DNS</h3>
          <ul class="list">
            ${data.data.reverse.map(h => `<li>${h}</li>`).join('')}
          </ul>
        </div>
        ` : ''}
      </div>
      
      <div class="section">
        <h2><span class="icon">⚠️</span> Risk Assessment</h2>
        <div class="risk-meter">
          <div class="risk-circle ${riskLevel.toLowerCase()}">${riskLevel}</div>
        </div>
        ${risks.length > 0 ? `
        <ul class="list">
          ${risks.map(r => `<li>${r}</li>`).join('')}
        </ul>
        ` : '<p style="text-align: center; color: #00ff00;">No significant risks detected</p>'}
      </div>
    </div>
    
    ${ports.length > 0 ? `
    <div class="section">
      <h2><span class="icon">🔌</span> Open Ports (${ports.length})</h2>
      <div class="grid">
        ${ports.map(p => `
          <div class="card">
            <h3>Port ${p.port}</h3>
            <div class="stat"><span class="stat-label">Service</span><span class="stat-value">${p.name}</span></div>
            <div class="stat"><span class="stat-label">Status</span><span class="stat-value good">OPEN</span></div>
          </div>
        `).join('')}
      </div>
    </div>
    ` : ''}
  `;
}

function generateDomainReport(data) {
  const subdomains = data.data?.subdomains || [];
  const tech = data.data?.technologies || [];
  const risks = data.data?.risks || [];
  
  return `
    <div class="grid">
      <div class="section">
        <h2><span class="icon">📡</span> DNS Records</h2>
        <div class="card">
          <h3>Record Counts</h3>
          <div class="stat"><span class="stat-label">A Records</span><span class="stat-value">${(data.data?.dns?.A || []).length}</span></div>
          <div class="stat"><span class="stat-label">MX Records</span><span class="stat-value">${(data.data?.dns?.MX || []).length}</span></div>
          <div class="stat"><span class="stat-label">NS Records</span><span class="stat-value">${(data.data?.dns?.NS || []).length}</span></div>
          <div class="stat"><span class="stat-label">TXT Records</span><span class="stat-value">${(data.data?.dns?.TXT || []).length}</span></div>
          <div class="stat"><span class="stat-label">SPF</span><span class="stat-value ${data.data?.spf ? 'good' : 'warning'}">${data.data?.spf ? '✓ YES' : '✗ NO'}</span></div>
        </div>
      </div>
      
      <div class="section">
        <h2><span class="icon">🔒</span> Security</h2>
        <div class="card">
          <h3>HTTPS</h3>
          <div class="stat"><span class="stat-label">HTTP Status</span><span class="stat-value">${data.data?.http?.status || 'N/A'}</span></div>
          <div class="stat"><span class="stat-label">HTTPS Status</span><span class="stat-value ${data.data?.https ? 'good' : 'bad'}">${data.data?.https?.status || 'N/A'}</span></div>
        </div>
        ${data.data?.securityHeaders?.length ? `
        <div style="margin-top: 15px;">
          <h4 style="color: #ff6666; margin-bottom: 10px;">Security Headers</h4>
          ${data.data.securityHeaders.map(h => `<span class="tag good">${h}</span>`).join('')}
        </div>
        ` : ''}
      </div>
    </div>
    
    ${subdomains.length > 0 ? `
    <div class="section">
      <h2><span class="icon">🔍</span> Subdomains (${subdomains.length})</h2>
      <ul class="list">
        ${subdomains.slice(0, 20).map(s => `<li><strong>${s.name}</strong> → ${s.ip}</li>`).join('')}
      </ul>
    </div>
    ` : ''}
    
    ${tech.length > 0 ? `
    <div class="section">
      <h2><span class="icon">⚙️</span> Technologies Detected</h2>
      <div style="display: flex; flex-wrap: wrap; gap: 5px;">
        ${tech.map(t => `<span class="tag info">${t}</span>`).join('')}
      </div>
    </div>
    ` : ''}
    
    ${risks.length > 0 ? `
    <div class="section">
      <h2><span class="icon">⚠️</span> Risk Factors</h2>
      <ul class="list">
        ${risks.map(r => `<li>${r}</li>`).join('')}
      </ul>
    </div>
    ` : ''}
  `;
}

function generateWebReport(data) {
  const links = data.data?.links || [];
  const emails = data.data?.emails || [];
  const phones = data.data?.phones || [];
  const tech = data.data?.technologies || [];
  const internal = links.filter(l => l.type === 'internal');
  const external = links.filter(l => l.type === 'external');
  const social = links.filter(l => l.type === 'social');
  
  return `
    <div class="grid">
      <div class="section">
        <h2><span class="icon">📄</span> Page Info</h2>
        <div class="card">
          <h3>Metadata</h3>
          ${data.data?.meta?.title ? `<div class="stat"><span class="stat-label">Title</span><span class="stat-value">${data.data.meta.title}</span></div>` : ''}
          ${data.data?.meta?.description ? `<div class="stat"><span class="stat-label">Description</span><span class="stat-value">${data.data.meta.description.substring(0, 100)}...</span></div>` : ''}
          ${data.data?.meta?.author ? `<div class="stat"><span class="stat-label">Author</span><span class="stat-value">${data.data.meta.author}</span></div>` : ''}
        </div>
      </div>
      
      <div class="section">
        <h2><span class="icon">🔗</span> Links Analysis</h2>
        <div class="chart-container">
          <div class="chart-bar" style="height: ${Math.min(internal.length, 100)}px;">
            <span class="value">${internal.length}</span>
            <span class="label">Internal</span>
          </div>
          <div class="chart-bar" style="height: ${Math.min(external.length, 100)}px; background: linear-gradient(180deg, #ffaa00 0%, #aa7700 100%);">
            <span class="value">${external.length}</span>
            <span class="label">External</span>
          </div>
          <div class="chart-bar" style="height: ${Math.min(social.length * 10, 100)}px; background: linear-gradient(180deg, #4488ff 0%, #2255aa 100%);">
            <span class="value">${social.length}</span>
            <span class="label">Social</span>
          </div>
        </div>
      </div>
    </div>
    
    ${emails.length > 0 ? `
    <div class="section">
      <h2><span class="icon">📧</span> Email Addresses (${emails.length})</h2>
      <div style="display: flex; flex-wrap: wrap; gap: 5px;">
        ${emails.map(e => `<span class="tag info">${e}</span>`).join('')}
      </div>
    </div>
    ` : ''}
    
    ${phones.length > 0 ? `
    <div class="section">
      <h2><span class="icon">📱</span> Phone Numbers (${phones.length})</h2>
      <div style="display: flex; flex-wrap: wrap; gap: 5px;">
        ${phones.map(p => `<span class="tag info">${p}</span>`).join('')}
      </div>
    </div>
    ` : ''}
    
    ${tech.length > 0 ? `
    <div class="section">
      <h2><span class="icon">⚙️</span> Technologies (${tech.length})</h2>
      <div style="display: flex; flex-wrap: wrap; gap: 5px;">
        ${tech.map(t => `<span class="tag info">${t}</span>`).join('')}
      </div>
    </div>
    ` : ''}
    
    ${data.data?.security?.warnings?.length ? `
    <div class="section">
      <h2><span class="icon">⚠️</span> Security Warnings</h2>
      <ul class="list">
        ${data.data.security.warnings.map(w => `<li>${w}</li>`).join('')}
      </ul>
    </div>
    ` : ''}
  `;
}

function generateImageReport(data) {
  return `
    <div class="grid">
      <div class="section">
        <h2><span class="icon">🖼️</span> File Information</h2>
        <div class="card">
          <h3>Basic Info</h3>
          <div class="stat"><span class="stat-label">Size</span><span class="stat-value">${(data.data?.size / 1024).toFixed(2)} KB</span></div>
          <div class="stat"><span class="stat-label">Type</span><span class="stat-value">${data.data?.extension || 'Unknown'}</span></div>
          <div class="stat"><span class="stat-label">Modified</span><span class="stat-value">${data.data?.modified || 'N/A'}</span></div>
        </div>
      </div>
      
      <div class="section">
        <h2><span class="icon">🔐</span> Hashes</h2>
        <div class="card">
          <div class="stat"><span class="stat-label">MD5</span><span class="stat-value" style="font-size: 0.8em;">${data.data?.md5 || 'N/A'}</span></div>
          <div class="stat"><span class="stat-label">SHA256</span><span class="stat-value" style="font-size: 0.8em;">${(data.data?.sha256 || '').substring(0, 40)}...</span></div>
        </div>
      </div>
    </div>
    
    ${data.data?.exif ? `
    <div class="section">
      <h2><span class="icon">📍</span> EXIF Data</h2>
      <div class="grid">
        ${Object.entries(data.data.exif).filter(([k, v]) => v).map(([key, value]) => `
          <div class="card">
            <h3>${key.charAt(0).toUpperCase() + key.slice(1)}</h3>
            <div class="stat-value">${value}</div>
          </div>
        `).join('')}
      </div>
    </div>
    ` : ''}
  `;
}

module.exports = { generateReport };
