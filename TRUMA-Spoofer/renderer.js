const btnRefresh = document.getElementById('btn-refresh');
const btnSpoofAllMAC = document.getElementById('btn-spoof-all-mac');
const btnSpoofAllVol = document.getElementById('btn-spoof-all-vol');
const btnSpoofGuid = document.getElementById('btn-spoof-guid');
const btnSpoofUuid = document.getElementById('btn-spoof-uuid');
const adaptersEl = document.getElementById('adapters');
const volumesEl = document.getElementById('volumes');
const machineIdsEl = document.getElementById('machine-ids');
const adapterCountEl = document.getElementById('adapter-count');
const statusTextEl = document.getElementById('status-text');
const footerStatusEl = document.getElementById('footer-status');
const adminBadgeEl = document.getElementById('admin-badge');

// Generator elements
const btnGenMAC = document.getElementById('btn-gen-mac');
const btnCopyMAC = document.getElementById('btn-copy-mac');
const genMACInput = document.getElementById('gen-mac');

const btnGenSerial = document.getElementById('btn-gen-serial');
const btnCopySerial = document.getElementById('btn-copy-serial');
const genSerialInput = document.getElementById('gen-serial');

const btnGenGUID = document.getElementById('btn-gen-guid');
const btnCopyGUID = document.getElementById('btn-copy-guid');
const genGUIDInput = document.getElementById('gen-guid');

// Modal elements
const modalEl = document.getElementById('modal');
const customMACInput = document.getElementById('custom-mac-input');
const btnModalCancel = document.getElementById('btn-modal-cancel');
const btnModalConfirm = document.getElementById('btn-modal-confirm');

let currentAdapters = [];
let currentVolumes = [];
let currentMachineIds = null;
let pendingAdapter = null;

function setStatus(text) {
  statusTextEl.textContent = text;
  footerStatusEl.textContent = text;
}

async function checkAdmin() {
  const isAdmin = await window.trumaSpoofer.checkAdmin();
  if (!isAdmin) {
    adminBadgeEl.classList.remove('hidden');
    setStatus('⚠ Run as Administrator for MAC spoofing');
  } else {
    adminBadgeEl.classList.add('hidden');
  }
  return isAdmin;
}

async function loadAdapters() {
  setStatus('Loading network adapters...');
  try {
    currentAdapters = await window.trumaSpoofer.getAdapters();
    renderAdapters();
    adapterCountEl.textContent = currentAdapters.length;
    setStatus('Ready');
  } catch (e) {
    adaptersEl.innerHTML = '<div class="muted">Failed to load adapters. Run as Administrator.</div>';
    setStatus('Error loading adapters');
  }
}

async function loadVolumes() {
  setStatus('Loading volumes...');
  try {
    currentVolumes = await window.trumaSpoofer.getVolumes();
    renderVolumes();
    setStatus('Ready');
  } catch (e) {
    volumesEl.innerHTML = '<div class="muted">Failed to load volumes.</div>';
    setStatus('Error loading volumes');
  }
}

async function loadMachineIds() {
  try {
    const ids = await window.trumaSpoofer.getMachineIds();
    renderMachineIds(ids);
  } catch (e) {
    machineIdsEl.innerHTML = '<div class="muted">Failed to load machine IDs.</div>';
  }
}

function renderAdapters() {
  adaptersEl.innerHTML = '';
  
  if (currentAdapters.length === 0) {
    adaptersEl.innerHTML = '<div class="muted">No network adapters found.</div>';
    return;
  }
  
  currentAdapters.forEach(adapter => {
    const item = document.createElement('div');
    item.className = 'item';
    item.dataset.name = adapter.Name;
    
    const status = adapter.Status === 'Up' ? 'Connected' : 'Disconnected';
    const statusClass = adapter.Status === 'Up' ? '' : 'warn';
    
    item.innerHTML = `
      <div class="item-info">
        <div class="item-name">${adapter.Name}</div>
        <div class="item-detail">${adapter.MacAddress || 'N/A'}</div>
        <div class="item-detail">${adapter.InterfaceDescription || ''}</div>
        <div class="item-status ${statusClass}">${status} • ${adapter.LinkSpeed || 'Unknown speed'}</div>
      </div>
      <div class="item-spoofed hidden">✓ SPOOFED</div>
      <div class="item-actions">
        <button class="btn btn-ghost btn-spoof" data-adapter="${adapter.Name}">Spoof</button>
        <button class="btn btn-ghost btn-restore" data-adapter="${adapter.Name}" disabled>Restore</button>
        <button class="btn btn-ghost btn-custom" data-adapter="${adapter.Name}">Custom</button>
      </div>
    `;
    
    adaptersEl.appendChild(item);
  });
  
  // Add event listeners
  adaptersEl.querySelectorAll('.btn-spoof').forEach(btn => {
    btn.addEventListener('click', () => spoofAdapter(btn.dataset.adapter));
  });
  
  adaptersEl.querySelectorAll('.btn-restore').forEach(btn => {
    btn.addEventListener('click', () => restoreAdapter(btn.dataset.adapter));
  });
  
  adaptersEl.querySelectorAll('.btn-custom').forEach(btn => {
    btn.addEventListener('click', () => showCustomMACModal(btn.dataset.adapter));
  });
}

function renderVolumes() {
  volumesEl.innerHTML = '';
  
  if (currentVolumes.length === 0) {
    volumesEl.innerHTML = '<div class="muted">No volumes found.</div>';
    return;
  }
  
  currentVolumes.forEach(vol => {
    const item = document.createElement('div');
    item.className = 'item';
    item.dataset.drive = vol.DriveLetter;
    
    const sizeGB = (vol.Size / 1024 / 1024 / 1024).toFixed(1);
    const freeGB = (vol.SizeRemaining / 1024 / 1024 / 1024).toFixed(1);
    
    item.innerHTML = `
      <div class="item-info">
        <div class="item-name">${vol.DriveLetter}: ${vol.FileSystemLabel || 'Local Disk'}</div>
        <div class="item-detail">Serial: ${vol.serialNumber || 'Unknown'}</div>
        <div class="item-detail">${sizeGB} GB total, ${freeGB} GB free</div>
      </div>
      <div class="item-spoofed hidden">✓ SPOOFED</div>
      <div class="item-actions">
        <button class="btn btn-ghost btn-spoof-vol" data-drive="${vol.DriveLetter}">Spoof</button>
        <button class="btn btn-ghost btn-restore-vol" data-drive="${vol.DriveLetter}" disabled>Restore</button>
      </div>
    `;
    
    volumesEl.appendChild(item);
  });
  
  volumesEl.querySelectorAll('.btn-spoof-vol').forEach(btn => {
    btn.addEventListener('click', () => spoofVolume(btn.dataset.drive));
  });
  
  volumesEl.querySelectorAll('.btn-restore-vol').forEach(btn => {
    btn.addEventListener('click', () => restoreVolume(btn.dataset.drive));
  });
}

function renderMachineIds(ids) {
  machineIdsEl.innerHTML = '';
  currentMachineIds = ids;
  
  const rows = [
    { label: 'Machine GUID', value: ids.machineGuid, key: 'machine_guid', id: 'guid' },
    { label: 'System UUID', value: ids.systemUuid || 'N/A', key: 'system_uuid', id: 'uuid' },
    { label: 'Product ID', value: ids.productId },
    { label: 'Computer Name', value: ids.computerName }
  ];
  
  rows.forEach(row => {
    const div = document.createElement('div');
    div.className = 'id-row';
    div.dataset.key = row.key || '';
    div.id = row.id ? `row-${row.id}` : '';
    
    const isSpoofed = row.key && window.trumaSpoofer.getOriginal ? true : false;
    const spoofedBadge = row.key ? '<span class="spoofed-badge hidden">✓ SPOOFED</span>' : '';
    
    div.innerHTML = `
      <div class="id-label">${row.label} ${spoofedBadge}</div>
      <div class="id-value">${row.value}</div>
    `;
    machineIdsEl.appendChild(div);
  });
}

async function spoofAdapter(name) {
  setStatus(`Spoofing ${name}...`);
  
  try {
    const result = await window.trumaSpoofer.spoofMAC(name);
    
    if (result.success) {
      setStatus(`${name} spoofed successfully`);
      const item = adaptersEl.querySelector(`[data-name="${name}"]`);
      if (item) {
        item.classList.add('spoofed');
        item.querySelector('.item-spoofed').classList.remove('hidden');
        item.querySelector('.btn-restore').disabled = false;
        item.querySelector('.item-detail').textContent = result.newMAC;
      }
    } else {
      setStatus(`Failed to spoof ${name}: ${result.error || 'Unknown error'}`);
    }
  } catch (e) {
    setStatus(`Error: ${e.message}`);
  }
  
  setTimeout(() => setStatus('Ready'), 3000);
}

async function spoofAllAdapters() {
  if (!currentAdapters || currentAdapters.length === 0) {
    setStatus('No adapters loaded. Click Refresh first.');
    return;
  }
  
  setStatus(`Spoofing ${currentAdapters.length} adapters...`);
  
  let successCount = 0;
  let failCount = 0;
  
  for (const adapter of currentAdapters) {
    try {
      setStatus(`Spoofing ${adapter.Name}... (${successCount + failCount + 1}/${currentAdapters.length})`);
      const result = await window.trumaSpoofer.spoofMAC(adapter.Name);
      
      if (result.success) {
        successCount++;
        const item = adaptersEl.querySelector(`[data-name="${adapter.Name}"]`);
        if (item) {
          item.classList.add('spoofed');
          item.querySelector('.item-spoofed').classList.remove('hidden');
          item.querySelector('.btn-restore').disabled = false;
          item.querySelector('.item-detail').textContent = result.newMAC;
        }
      } else {
        failCount++;
        console.error(`Failed to spoof ${adapter.Name}:`, result.error);
      }
    } catch (e) {
      failCount++;
      console.error(`Error spoofing ${adapter.Name}:`, e);
    }
    
    await new Promise(r => setTimeout(r, 800));
  }
  
  setStatus(`Done: ${successCount} succeeded, ${failCount} failed`);
  setTimeout(() => setStatus('Ready'), 5000);
}

async function spoofVolume(drive) {
  setStatus(`Spoofing ${drive}: drive...`);
  
  try {
    const result = await window.trumaSpoofer.spoofVolume(drive);
    
    if (result.success) {
      setStatus(`${drive}: spoofed successfully`);
      const item = volumesEl.querySelector(`[data-drive="${drive}"]`);
      if (item) {
        item.classList.add('spoofed');
        item.querySelector('.item-spoofed').classList.remove('hidden');
        item.querySelector('.btn-restore-vol').disabled = false;
        item.querySelector('.item-detail').textContent = `Serial: ${result.newSerial}`;
      }
    } else {
      setStatus(`Failed to spoof ${drive}: ${result.error || 'Unknown error'}`);
    }
  } catch (e) {
    setStatus(`Error: ${e.message}`);
  }
  
  setTimeout(() => setStatus('Ready'), 3000);
}

async function spoofMachineGuid() {
  setStatus('Spoofing Machine GUID...');
  
  try {
    const result = await window.trumaSpoofer.spoofMachineGuid();
    
    if (result.success) {
      setStatus('Machine GUID spoofed successfully');
      // Update UI
      const guidRow = document.getElementById('row-guid');
      if (guidRow) {
        guidRow.querySelector('.id-value').textContent = result.newGuid;
        const badge = guidRow.querySelector('.spoofed-badge');
        if (badge) badge.classList.remove('hidden');
        guidRow.style.borderLeft = '3px solid var(--success)';
      }
      // Reload machine IDs
      setTimeout(async () => {
        const ids = await window.trumaSpoofer.getMachineIds();
        renderMachineIds(ids);
      }, 500);
    } else {
      setStatus(`Failed to spoof Machine GUID: ${result.error || 'Unknown error'}`);
    }
  } catch (e) {
    setStatus(`Error: ${e.message}`);
  }
  
  setTimeout(() => setStatus('Ready'), 3000);
}

async function spoofSystemUuid() {
  setStatus('Spoofing System UUID...');
  
  try {
    const result = await window.trumaSpoofer.spoofSystemUuid();
    
    if (result.success) {
      setStatus('System UUID spoofed successfully');
      // Update UI
      const uuidRow = document.getElementById('row-uuid');
      if (uuidRow) {
        uuidRow.querySelector('.id-value').textContent = result.newUuid;
        const badge = uuidRow.querySelector('.spoofed-badge');
        if (badge) badge.classList.remove('hidden');
        uuidRow.style.borderLeft = '3px solid var(--success)';
      }
      // Reload machine IDs
      setTimeout(async () => {
        const ids = await window.trumaSpoofer.getMachineIds();
        renderMachineIds(ids);
      }, 500);
    } else {
      setStatus(`Failed to spoof System UUID: ${result.error || 'Unknown error'}`);
    }
  } catch (e) {
    setStatus(`Error: ${e.message}`);
  }
  
  setTimeout(() => setStatus('Ready'), 3000);
}

async function restoreAdapter(name) {
  setStatus(`Restoring ${name}...`);
  
  try {
    const result = await window.trumaSpoofer.restore(`mac_${name}`);
    
    if (result.success) {
      setStatus(`${name} restored successfully`);
      const item = adaptersEl.querySelector(`[data-name="${name}"]`);
      if (item) {
        item.classList.remove('spoofed');
        item.querySelector('.item-spoofed').classList.add('hidden');
        item.querySelector('.btn-restore').disabled = true;
        item.querySelector('.item-detail').textContent = result.newMAC;
      }
    } else {
      setStatus(`Failed to restore ${name}: ${result.error || 'Unknown error'}`);
    }
  } catch (e) {
    setStatus(`Error: ${e.message}`);
  }
  
  setTimeout(() => setStatus('Ready'), 3000);
}

async function restoreVolume(drive) {
  setStatus(`Restoring ${drive}: drive...`);
  
  try {
    const result = await window.trumaSpoofer.restore(`vol_${drive}`);
    
    if (result.success) {
      setStatus(`${drive}: restored successfully`);
      const item = volumesEl.querySelector(`[data-drive="${drive}"]`);
      if (item) {
        item.classList.remove('spoofed');
        item.querySelector('.item-spoofed').classList.add('hidden');
        item.querySelector('.btn-restore-vol').disabled = true;
      }
    } else {
      setStatus(`Failed to restore ${drive}: ${result.error || 'Unknown error'}`);
    }
  } catch (e) {
    setStatus(`Error: ${e.message}`);
  }
  
  setTimeout(() => setStatus('Ready'), 3000);
}

// Modal handling
function showCustomMACModal(adapterName) {
  pendingAdapter = adapterName;
  customMACInput.value = '';
  modalEl.classList.remove('hidden');
  customMACInput.focus();
}

function hideModal() {
  modalEl.classList.add('hidden');
  pendingAdapter = null;
}

async function confirmCustomMAC() {
  if (!pendingAdapter) return;
  
  let mac = customMACInput.value.trim();
  if (mac && !/^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$/.test(mac)) {
    setStatus('Invalid MAC format. Use XX:XX:XX:XX:XX:XX');
    return;
  }
  
  hideModal();
  
  setStatus(`Spoofing ${pendingAdapter} with custom MAC...`);
  
  try {
    const result = await window.trumaSpoofer.spoofMAC(pendingAdapter, mac || null);
    
    if (result.success) {
      setStatus(`${pendingAdapter} spoofed with ${result.newMAC}`);
      const item = adaptersEl.querySelector(`[data-name="${pendingAdapter}"]`);
      if (item) {
        item.classList.add('spoofed');
        item.querySelector('.item-spoofed').classList.remove('hidden');
        item.querySelector('.btn-restore').disabled = false;
        item.querySelector('.item-detail').textContent = result.newMAC;
      }
    } else {
      setStatus(`Failed to spoof: ${result.error || 'Unknown error'}`);
    }
  } catch (e) {
    setStatus(`Error: ${e.message}`);
  }
  
  setTimeout(() => setStatus('Ready'), 3000);
}

// Generator functions
async function generateMAC() {
  const mac = await window.trumaSpoofer.generateMAC();
  genMACInput.value = mac;
}

async function generateSerial() {
  const serial = await window.trumaSpoofer.generateSerial();
  genSerialInput.value = serial;
}

async function generateGUID() {
  const guid = await window.trumaSpoofer.generateGUID();
  genGUIDInput.value = guid;
}

function copyToClipboard(text, label) {
  navigator.clipboard.writeText(text).then(() => {
    setStatus(`${label} copied to clipboard`);
    setTimeout(() => setStatus('Ready'), 2000);
  }).catch(() => {
    setStatus('Failed to copy');
  });
}

// Event listeners
btnRefresh.addEventListener('click', async () => {
  await Promise.all([loadAdapters(), loadVolumes(), loadMachineIds()]);
});

btnSpoofAllMAC.addEventListener('click', spoofAllAdapters);
// btnSpoofAllVol.addEventListener('click', spoofAllVolumes);

btnGenMAC.addEventListener('click', generateMAC);
btnCopyMAC.addEventListener('click', () => copyToClipboard(genMACInput.value, 'MAC'));

btnGenSerial.addEventListener('click', generateSerial);
btnCopySerial.addEventListener('click', () => copyToClipboard(genSerialInput.value, 'Serial'));

btnGenGUID.addEventListener('click', generateGUID);
btnCopyGUID.addEventListener('click', () => copyToClipboard(genGUIDInput.value, 'GUID'));

btnSpoofGuid.addEventListener('click', spoofMachineGuid);
btnSpoofUuid.addEventListener('click', spoofSystemUuid);

btnModalCancel.addEventListener('click', hideModal);
btnModalConfirm.addEventListener('click', confirmCustomMAC);

modalEl.querySelector('.modal-overlay').addEventListener('click', hideModal);

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') hideModal();
});

// Initialize
checkAdmin().then(() => {
  loadAdapters();
  loadVolumes();
  loadMachineIds();
  generateMAC();
  generateSerial();
  generateGUID();
});
