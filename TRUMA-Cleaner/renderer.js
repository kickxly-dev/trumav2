const btnScan = document.getElementById('btn-scan');
const btnClean = document.getElementById('btn-clean');
const btnSelectRecommended = document.getElementById('btn-select-recommended');
const btnSelectNone = document.getElementById('btn-select-none');
const targetsEl = document.getElementById('targets');
const largestEl = document.getElementById('largest');
const summaryBytesEl = document.getElementById('summary-bytes');
const summaryStatusEl = document.getElementById('summary-status');
const selectedBytesEl = document.getElementById('selected-bytes');
const statusTextEl = document.getElementById('status-text');

const reportSummaryEl = document.getElementById('report-summary');
const reportEl = document.getElementById('report');

const modalEl = document.getElementById('modal');
const modalBodyEl = document.getElementById('modal-body');
const btnModalCancel = document.getElementById('btn-modal-cancel');
const btnModalConfirm = document.getElementById('btn-modal-confirm');

let lastScan = null;
let appSettings = null;

function fmtBytes(bytes) {
  const b = Number(bytes || 0);
  if (b <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = b;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

function setStatus(text) {
  statusTextEl.textContent = text;
}

function selectedRootIds() {
  const ids = [];
  targetsEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    if (cb.checked) ids.push(cb.dataset.id);
  });
  return ids;
}

function updateCleanEnabled() {
  const ids = selectedRootIds();
  btnClean.disabled = ids.length === 0;
}

function selectedBytes() {
  if (!lastScan || !Array.isArray(lastScan.roots)) return 0;
  const idSet = new Set(selectedRootIds().map(String));
  let total = 0;
  for (const r of lastScan.roots) {
    if (idSet.has(String(r.id))) total += Number(r.totalBytes || 0);
  }
  return total;
}

function updateSelectedBytesUi() {
  selectedBytesEl.textContent = fmtBytes(selectedBytes());
}

function showModal(text, isHtml = false) {
  if (isHtml) {
    modalBodyEl.innerHTML = text;
  } else {
    modalBodyEl.textContent = text;
  }
  modalEl.classList.remove('hidden');
}

function hideModal() {
  modalEl.classList.add('hidden');
}

function render(scan) {
  lastScan = scan;

  summaryBytesEl.textContent = fmtBytes(scan.totalBytes);
  summaryStatusEl.textContent = 'Scanned';
  reportEl.innerHTML = '';

  targetsEl.innerHTML = '';
  for (const r of scan.roots) {
    const row = document.createElement('div');
    row.className = 'target';

    const badges = [];
    if (r.recommended) badges.push('<span class="badge rec">RECOMMENDED</span>');
    if (r.caution) badges.push('<span class="badge warn">CAUTION</span>');
    if (r.warning) badges.push('<span class="badge warn">⚠ ' + r.warning + '</span>');

    row.innerHTML = `
      <div class="target-left">
        <div class="target-check">
          <input type="checkbox" ${r.recommended ? 'checked' : ''} data-id="${r.id}" />
        </div>
        <div>
          <div class="target-name">${r.label}</div>
          <div class="target-path">${r.rootPath}</div>
          <div class="badges">${badges.join('')}</div>
        </div>
      </div>
      <div class="target-meta">
        <div><strong>${fmtBytes(r.totalBytes)}</strong></div>
        <div>${r.fileCount} files</div>
      </div>
    `;

    targetsEl.appendChild(row);
  }

  targetsEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    cb.addEventListener('change', () => {
      updateCleanEnabled();
      updateSelectedBytesUi();
    });
  });

  updateCleanEnabled();
  updateSelectedBytesUi();

  // Apply default selection from settings
  if (appSettings && appSettings.defaultSelection) {
    applyDefaultSelection(appSettings.defaultSelection);
  }

  // Largest files preview
  const allLargest = [];
  for (const r of scan.roots) {
    for (const f of (r.largest || [])) {
      allLargest.push({ rootId: r.id, ...f });
    }
  }
  allLargest.sort((a, b) => (b.size || 0) - (a.size || 0));

  largestEl.innerHTML = '';
  const top = allLargest.slice(0, 12);
  if (top.length === 0) {
    largestEl.innerHTML = '<div class="muted">No preview available.</div>';
    return;
  }

  for (const f of top) {
    const r = document.createElement('div');
    r.className = 'row';
    r.innerHTML = `
      <div class="path">${f.path}</div>
      <div class="size">${fmtBytes(f.size)}</div>
    `;
    largestEl.appendChild(r);
  }
}

function applyDefaultSelection(mode) {
  if (!lastScan) return;
  targetsEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    const root = (lastScan.roots || []).find(r => String(r.id) === String(cb.dataset.id));
    if (!root) return;
    
    switch (mode) {
      case 'recommended':
        cb.checked = !!root.recommended;
        break;
      case 'all':
        cb.checked = true;
        break;
      case 'none':
        cb.checked = false;
        break;
    }
  });
  updateCleanEnabled();
  updateSelectedBytesUi();
}

async function doScan() {
  if (!window.trumaCleaner) return;
  summaryStatusEl.textContent = 'Scanning...';
  setStatus('Scanning safe temp targets...');
  btnScan.disabled = true;
  btnClean.disabled = true;

  try {
    const scan = await window.trumaCleaner.scan();
    // Also load settings
    appSettings = scan.settings || await window.trumaCleaner.getSettings();
    render(scan);
    setStatus('Scan complete');
  } catch (_) {
    summaryStatusEl.textContent = 'Error';
    setStatus('Scan failed');
  } finally {
    btnScan.disabled = false;
  }
}

async function doCleanConfirmed() {
  if (!window.trumaCleaner) return;
  const ids = selectedRootIds();
  if (ids.length === 0) return;

  summaryStatusEl.textContent = 'Cleaning...';
  setStatus('Cleaning selected targets...');
  btnScan.disabled = true;
  btnClean.disabled = true;

  reportEl.innerHTML = '';
  reportSummaryEl.textContent = 'Cleaning...';

  try {
    const res = await window.trumaCleaner.clean(ids);
    const cleaned = Array.isArray(res.cleaned) ? res.cleaned : [];
    const totalFailed = cleaned.reduce((a, c) => a + Number(c.failed || 0), 0);

    reportEl.innerHTML = '';
    for (const c of cleaned) {
      const rep = document.createElement('div');
      rep.className = 'rep';
      const failedPaths = Array.isArray(c.failedPaths) ? c.failedPaths : [];
      const failedBlock = failedPaths.length
        ? `<div class="rep-failed">Locked/failed:\n${failedPaths.map(p => `- ${p}`).join('\n')}</div>`
        : '';

      rep.innerHTML = `
        <div class="rep-title">${c.label}</div>
        <div class="rep-meta">Deleted: ${Number(c.deletedFiles || 0)} files, ${Number(c.deletedDirs || 0)} folders</div>
        <div class="rep-meta">Failures: ${Number(c.failed || 0)}</div>
        ${failedBlock}
      `;
      reportEl.appendChild(rep);
    }

    reportSummaryEl.textContent = totalFailed
      ? `Completed with ${totalFailed} locked/failed items.`
      : 'Clean completed successfully.';

    setStatus(totalFailed ? `Cleaned with ${totalFailed} failures (some files were locked)` : 'Clean complete');
  } catch (_) {
    setStatus('Clean failed');
    reportSummaryEl.textContent = 'Clean failed.';
  } finally {
    btnScan.disabled = false;
    await doScan();
  }
}

function confirmClean() {
  const ids = selectedRootIds();
  if (!lastScan || ids.length === 0) return;

  const idSet = new Set(ids.map(String));
  const selectedRoots = (lastScan.roots || []).filter(r => idSet.has(String(r.id)));
  const total = selectedRoots.reduce((a, r) => a + Number(r.totalBytes || 0), 0);
  const hasCaution = selectedRoots.some(r => r.caution);
  const hasWarning = selectedRoots.some(r => r.warning);

  let html = '';
  html += `<div style="margin-bottom:12px;"><strong>Targets:</strong> ${selectedRoots.length}</div>`;
  html += `<div style="margin-bottom:12px;"><strong>Estimated reclaimable:</strong> ${fmtBytes(total)}</div>`;
  
  if (hasCaution || hasWarning) {
    html += `<div style="margin:12px 0;padding:10px;border-radius:10px;border:1px solid rgba(255,180,0,0.4);background:rgba(255,180,0,0.08);color:#ffcc66;">`;
    html += `<strong>⚠ CAUTION</strong><br/>`;
    selectedRoots.forEach(r => {
      if (r.warning) {
        html += `• ${r.label}: ${r.warning}<br/>`;
      } else if (r.caution) {
        html += `• ${r.label}: May affect recent items or diagnostics<br/>`;
      }
    });
    html += `</div>`;
  }
  
  html += `<div style="margin-top:12px;color:#888;font-size:12px;">TRUMA Cleaner deletes contents inside the target folders only. This action cannot be undone.</div>`;

  showModal(html, true);
}

btnScan.addEventListener('click', doScan);
btnClean.addEventListener('click', confirmClean);

btnModalCancel.addEventListener('click', hideModal);
btnModalConfirm.addEventListener('click', async () => {
  hideModal();
  await doCleanConfirmed();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') hideModal();
});

btnSelectRecommended.addEventListener('click', () => {
  if (!lastScan) return;
  targetsEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    const root = (lastScan.roots || []).find(r => String(r.id) === String(cb.dataset.id));
    cb.checked = !!(root && root.recommended);
  });
  updateCleanEnabled();
  updateSelectedBytesUi();
});

btnSelectNone.addEventListener('click', () => {
  targetsEl.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    cb.checked = false;
  });
  updateCleanEnabled();
  updateSelectedBytesUi();
});

// Listen for scheduled clean due notification
if (window.trumaCleaner && window.trumaCleaner.onScheduledDue) {
  window.trumaCleaner.onScheduledDue(() => {
    setStatus('Scheduled clean is due! Click Clean Selected to run.');
    summaryStatusEl.textContent = 'Scheduled Due';
  });
}

// initial scan
setTimeout(async () => {
  // Load settings first
  if (window.trumaCleaner) {
    appSettings = await window.trumaCleaner.getSettings();
    
    // Auto-scan on launch if enabled
    if (appSettings.autoScanOnLaunch) {
      await doScan();
    }
  }
}, 100);

// Settings panel functionality
const btnSettings = document.getElementById('btn-settings');
const settingsModal = document.getElementById('settings-modal');
const btnSettingsCancel = document.getElementById('btn-settings-cancel');
const btnSettingsSave = document.getElementById('btn-settings-save');
const settingAutoScan = document.getElementById('setting-auto-scan');
const settingDefaultSelection = document.getElementById('setting-default-selection');
const settingScheduled = document.getElementById('setting-scheduled');
const settingScheduleInterval = document.getElementById('setting-schedule-interval');
const scheduleIntervalRow = document.getElementById('schedule-interval-row');
const lastCleanInfo = document.getElementById('last-clean-info');

function showSettingsModal() {
  if (!appSettings) return;
  
  // Populate current settings
  settingAutoScan.checked = appSettings.autoScanOnLaunch;
  settingDefaultSelection.value = appSettings.defaultSelection || 'recommended';
  settingScheduled.checked = appSettings.scheduledClean;
  settingScheduleInterval.value = appSettings.scheduleInterval || 'weekly';
  
  // Update schedule interval row opacity
  scheduleIntervalRow.style.opacity = appSettings.scheduledClean ? '1' : '0.5';
  settingScheduleInterval.disabled = !appSettings.scheduledClean;
  
  // Update last clean info
  if (appSettings.lastCleanDate) {
    const date = new Date(appSettings.lastCleanDate);
    lastCleanInfo.textContent = `Last clean: ${date.toLocaleDateString()} at ${date.toLocaleTimeString()}`;
  } else {
    lastCleanInfo.textContent = 'No clean recorded yet.';
  }
  
  settingsModal.classList.remove('hidden');
}

function hideSettingsModal() {
  settingsModal.classList.add('hidden');
}

async function saveSettings() {
  const newSettings = {
    autoScanOnLaunch: settingAutoScan.checked,
    defaultSelection: settingDefaultSelection.value,
    scheduledClean: settingScheduled.checked,
    scheduleInterval: settingScheduleInterval.value
  };
  
  if (window.trumaCleaner) {
    appSettings = await window.trumaCleaner.saveSettings(newSettings);
    setStatus('Settings saved');
  }
  
  hideSettingsModal();
  
  // Re-apply default selection if scan exists
  if (lastScan && appSettings.defaultSelection) {
    applyDefaultSelection(appSettings.defaultSelection);
  }
}

btnSettings.addEventListener('click', showSettingsModal);
btnSettingsCancel.addEventListener('click', hideSettingsModal);
btnSettingsSave.addEventListener('click', saveSettings);

settingScheduled.addEventListener('change', () => {
  scheduleIntervalRow.style.opacity = settingScheduled.checked ? '1' : '0.5';
  settingScheduleInterval.disabled = !settingScheduled.checked;
});

// Close on overlay click
settingsModal.querySelector('.modal-overlay').addEventListener('click', hideSettingsModal);

// Escape key to close
settingsModal.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') hideSettingsModal();
});
