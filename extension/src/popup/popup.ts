// Popup script for Zero Phishing AI extension

interface AuthStatus {
  google: boolean;
  microsoft: boolean;
}

interface Stats {
  analyzed: number;
  safe: number;
  flagged: number;
}

async function loadStatus(): Promise<void> {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_AUTH_STATUS' });
    updateAuthUI(response.google, response.microsoft);
  } catch (e) {
    console.error('Failed to load auth status:', e);
  }
}

function updateAuthUI(google: boolean, microsoft: boolean): void {
  const gmailStatus = document.getElementById('gmail-status')!;
  const gmailConnect = document.getElementById('gmail-connect') as HTMLButtonElement;
  const outlookStatus = document.getElementById('outlook-status')!;
  const outlookConnect = document.getElementById('outlook-connect') as HTMLButtonElement;

  gmailConnect.disabled = false;
  outlookConnect.disabled = false;

  gmailStatus.textContent = google ? 'Connected' : 'Disconnected';
  gmailStatus.className = `badge ${google ? 'badge--connected' : 'badge--disconnected'}`;
  gmailConnect.textContent = google ? 'Disconnect' : 'Connect';
  gmailConnect.onclick = google ? disconnectGmail : connectGmail;

  outlookStatus.textContent = microsoft ? 'Connected' : 'Disconnected';
  outlookStatus.className = `badge ${microsoft ? 'badge--connected' : 'badge--disconnected'}`;
  outlookConnect.textContent = microsoft ? 'Disconnect' : 'Connect';
  outlookConnect.onclick = microsoft ? disconnectOutlook : connectOutlook;
}

async function connectGmail(): Promise<void> {
  const btn = document.getElementById('gmail-connect') as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = 'Connecting...';

  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_AUTH_TOKEN', payload: { provider: 'google', interactive: true } });
    if (response && !response.success && response.error) {
      console.warn('[ZeroPhish] Gmail connect response:', response.error);
    }
  } catch (e) {
    console.error('Gmail connect failed:', e);
  } finally {
    await loadStatus();
  }
}

async function connectOutlook(): Promise<void> {
  const btn = document.getElementById('outlook-connect') as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = 'Connecting...';

  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_AUTH_TOKEN', payload: { provider: 'microsoft', interactive: true } });
    if (response && !response.success && response.error) {
      console.warn('[ZeroPhish] Outlook connect response:', response.error);
    }
  } catch (e) {
    console.error('Outlook connect failed:', e);
  } finally {
    await loadStatus();
  }
}

async function disconnectGmail(): Promise<void> {
  await chrome.runtime.sendMessage({ type: 'SIGN_OUT', payload: { provider: 'google' } });
  await loadStatus();
}

async function disconnectOutlook(): Promise<void> {
  await chrome.runtime.sendMessage({ type: 'SIGN_OUT', payload: { provider: 'microsoft' } });
  await loadStatus();
}

async function loadStats(): Promise<void> {
  try {
    // Load from local storage
    const result = await chrome.storage.local.get(['zp_stats']);
    const stats = result.zp_stats || { analyzed: 0, safe: 0, flagged: 0 };
    updateStatsUI(stats);
  } catch (e) {
    console.error('Failed to load stats:', e);
  }
}

function updateStatsUI(stats: Stats): void {
  (document.getElementById('stat-analyzed')!).textContent = stats.analyzed.toString();
  (document.getElementById('stat-safe')!).textContent = stats.safe.toString();
  (document.getElementById('stat-flagged')!).textContent = stats.flagged.toString();
}

async function incrementStat(key: 'analyzed' | 'safe' | 'flagged'): Promise<void> {
  const result = await chrome.storage.local.get(['zp_stats']);
  const stats = result.zp_stats || { analyzed: 0, safe: 0, flagged: 0 };
  stats[key]++;
  await chrome.storage.local.set({ zp_stats: stats });
  updateStatsUI(stats);
}

async function analyzeCurrentEmail(): Promise<void> {
  const btn = document.getElementById('analyze-current') as HTMLButtonElement;
  btn.disabled = true;
  btn.innerHTML = '<span class="loading"></span> Analyzing...';

  try {
    // Send message to content script to trigger analysis
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      const isOutlook = tab.url ? /outlook\.(live|office|office365)\.com/.test(tab.url) : false;
      const provider = isOutlook ? 'outlook' : 'gmail';
      await chrome.tabs.sendMessage(tab.id, {
        type: 'ANALYZE_EMAIL_REQUEST',
        payload: { provider }
      });
      await incrementStat('analyzed');
    }
  } catch (e) {
    console.error('Analysis failed:', e);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Analyze Current Email';
  }
}

function openDashboard(): void {
  chrome.tabs.create({ url: 'https://zero-phishing.ai/dashboard' });
}

async function clearAllData(): Promise<void> {
  if (!confirm('This will remove all cached verdicts, feedback, and OAuth tokens. Continue?')) return;

  await chrome.storage.local.clear();
  await chrome.runtime.sendMessage({ type: 'SIGN_OUT' });
  await loadStatus();
  await loadStats();
  showToast('All local data cleared');
}

function showToast(message: string): void {
  const existing = document.querySelector('.zp-toast');
  existing?.remove();

  const toast = document.createElement('div');
  toast.className = 'zp-toast';
  toast.style.cssText = `
    position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
    padding: 10px 20px; background: #202124; color: white; border-radius: 6px;
    font-size: 12px; z-index: 10000; animation: slideUp 0.2s ease-out;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => toast.remove(), 2500);
}

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  // Set version
  const manifest = chrome.runtime.getManifest();
  document.getElementById('version')!.textContent = `v${manifest.version}`;

  await loadStatus();
  await loadStats();

  document.getElementById('analyze-current')!.addEventListener('click', analyzeCurrentEmail);
  document.getElementById('open-dashboard')!.addEventListener('click', openDashboard);
  document.getElementById('clear-data')!.addEventListener('click', clearAllData);
});