// Background service worker for Zero Phishing AI extension
// Handles OAuth, message routing, API calls, and caching

import { getAccessToken, revokeToken, onTokenChanged, clearAllTokens } from './oauth.js';
import { extractEmailData as extractGmailEmail } from '../content/gmail/extractor.js';
import { extractEmailData as extractOutlookEmail } from '../content/outlook/extractor.js';
import { toAnalysisBody } from '../utils/analysis.js';
import { recordVerdict } from '../utils/stats.js';
import { API_BASE_URL } from '../config.js';

export interface AnalysisRequest {
  messageId: string;
  provider: 'gmail' | 'outlook';
  headersRaw: string;
  bodyText: string;
  bodyHtml: string | null;
  urls: string[];
}

// What content scripts send; the service worker reads the email itself
export interface AnalyzeEmailMessage {
  messageId: string;
  provider: 'gmail' | 'outlook';
}

export interface VerdictResponse {
  verdict: 'safe' | 'suspicious' | 'dangerous';
  score: number;
  reasons: Array<{
    category: string;
    detail: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
  analysisId: string;
}

interface CacheEntry {
  verdict: VerdictResponse;
  timestamp: number;
  messageHash: string;
}

const CACHE_DB_NAME = 'zp-verdict-cache';
const CACHE_STORE_NAME = 'verdicts';
const CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days

// Initialize IndexedDB for verdict caching
async function initCacheDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(CACHE_DB_NAME, 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(CACHE_STORE_NAME)) {
        const store = db.createObjectStore(CACHE_STORE_NAME, { keyPath: 'messageHash' });
        store.createIndex('timestamp', 'timestamp', { unique: false });
      }
    };
  });
}

async function getCachedVerdict(messageHash: string): Promise<VerdictResponse | null> {
  const db = await initCacheDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(CACHE_STORE_NAME, 'readonly');
    const store = transaction.objectStore(CACHE_STORE_NAME);
    const request = store.get(messageHash);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const entry = request.result as CacheEntry | undefined;
      if (entry && Date.now() - entry.timestamp < CACHE_TTL) {
        resolve(entry.verdict);
      } else {
        resolve(null);
      }
    };
  });
}

async function setCachedVerdict(messageHash: string, verdict: VerdictResponse): Promise<void> {
  const db = await initCacheDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(CACHE_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(CACHE_STORE_NAME);
    const entry: CacheEntry = {
      verdict,
      timestamp: Date.now(),
      messageHash
    };
    const request = store.put(entry);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

function hashMessage(messageId: string, provider: string): string {
  // Simple hash for cache key - in production use crypto.subtle.digest
  let hash = 0;
  const str = `${provider}:${messageId}`;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}

// Analyze email via backend API
async function analyzeEmail(request: AnalyzeEmailMessage): Promise<VerdictResponse> {
  const messageHash = hashMessage(request.messageId, request.provider);

  // Check cache first
  const cached = await getCachedVerdict(messageHash);
  if (cached) {
    console.log('[ZeroPhish] Returning cached verdict for', request.messageId);
    return cached;
  }

  // Get OAuth token for the provider
  const oauthProvider = request.provider === 'gmail' ? 'google' : 'microsoft';
  const token = await getAccessToken(oauthProvider);
  if (!token) {
    throw new Error(`No valid ${request.provider} OAuth token`);
  }

  // The service worker holds the OAuth token, so it reads the email itself
  const emailData = request.provider === 'gmail'
    ? await extractGmailEmail(request.messageId, token)
    : await extractOutlookEmail(request.messageId, token);

  const response = await fetch(`${API_BASE_URL}/analyze`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(toAnalysisBody(request.provider, emailData))
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Unknown error' }));
    throw new Error(`Analysis failed: ${error.message || response.statusText}`);
  }

  const verdict = await response.json();
  await setCachedVerdict(messageHash, verdict);
  return verdict;
}

// Message handlers
async function handleAnalyzeEmail(message: AnalyzeEmailMessage, sendResponse: (response: VerdictResponse | { error: string }) => void) {
  try {
    const verdict = await analyzeEmail(message);
    // Count only successful verdicts; failures never reach this point
    try {
      await recordVerdict(verdict.verdict);
    } catch (statsError) {
      console.error('[ZeroPhish] Failed to update stats:', statsError);
    }
    sendResponse(verdict);
  } catch (error) {
    console.error('[ZeroPhish] Analysis error:', error);
    sendResponse({ error: error instanceof Error ? error.message : 'Analysis failed' });
  }
}

async function handleGetAuthStatus(_: unknown, sendResponse: (response: { google: boolean; microsoft: boolean }) => void) {
  const [googleToken, microsoftToken] = await Promise.all([
    getAccessToken('google'),
    getAccessToken('microsoft')
  ]);
  sendResponse({
    google: !!googleToken,
    microsoft: !!microsoftToken
  });
}

async function handleGetAuthToken(
  message: { provider: 'google' | 'microsoft'; interactive?: boolean },
  sendResponse: (response: { success: boolean; token?: string; error?: string }) => void
) {
  try {
    const provider = message.provider;
    const interactive = message.interactive ?? true;

    // Get scopes from manifest for the provider
    const scopes = provider === 'google'
      ? ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.email']
      : ['https://graph.microsoft.com/Mail.Read', 'https://graph.microsoft.com/User.Read'];

    chrome.identity.getAuthToken({ interactive, scopes }, (token) => {
      if (chrome.runtime.lastError) {
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
        return;
      }
      if (!token) {
        sendResponse({ success: false, error: 'User denied authorization' });
        return;
      }
      sendResponse({ success: true, token });
    });
  } catch (error) {
    sendResponse({ success: false, error: error instanceof Error ? error.message : 'Auth failed' });
  }
}

async function handleSignOut(message: { provider?: 'google' | 'microsoft' }, sendResponse: (response: { success: boolean }) => void) {
  try {
    if (message?.provider) {
      const token = await getAccessToken(message.provider);
      if (token && message.provider === 'google') {
        await new Promise<void>((resolve) => {
          chrome.identity.removeCachedAuthToken({ token }, () => resolve());
        });
      }
      await revokeToken(message.provider);
    } else {
      const [googleToken] = await Promise.all([
        getAccessToken('google'),
        getAccessToken('microsoft')
      ]);
      if (googleToken) {
        await new Promise<void>((resolve) => {
          chrome.identity.removeCachedAuthToken({ token: googleToken }, () => resolve());
        });
      }
      await Promise.all([
        revokeToken('google'),
        revokeToken('microsoft')
      ]);
      await clearAllTokens();
    }
    sendResponse({ success: true });
  } catch (error) {
    console.error('[ZeroPhish] Sign out error:', error);
    sendResponse({ success: false });
  }
}

async function handlePing(_: unknown, sendResponse: (response: { pong: true }) => void) {
  sendResponse({ pong: true });
}

// Message routing
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const { type, payload } = message;

  switch (type) {
    case 'ANALYZE_EMAIL':
      handleAnalyzeEmail(payload, sendResponse);
      return true; // Async response
    case 'GET_AUTH_STATUS':
      handleGetAuthStatus(payload, sendResponse);
      return true;
    case 'GET_AUTH_TOKEN':
      handleGetAuthToken(payload, sendResponse);
      return true;
    case 'SIGN_OUT':
      handleSignOut(payload, sendResponse);
      return true;
    case 'PING':
      handlePing(payload, sendResponse);
      return true;
    default:
      sendResponse({ error: 'Unknown message type' });
  }
});

// Handle extension install/update
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('[ZeroPhish] Extension installed');
    // Open welcome page or show notification
    chrome.tabs.create({ url: 'https://zero-phishing.ai/welcome' });
  } else if (details.reason === 'update') {
    console.log('[ZeroPhish] Extension updated to', chrome.runtime.getManifest().version);
  }
});

// Keep service worker alive for message handling
chrome.runtime.onConnect.addListener((port) => {
  console.log('[ZeroPhish] Port connected:', port.name);
  port.onDisconnect.addListener(() => {
    console.log('[ZeroPhish] Port disconnected:', port.name);
  });
});

console.log('[ZeroPhish] Background service worker loaded');