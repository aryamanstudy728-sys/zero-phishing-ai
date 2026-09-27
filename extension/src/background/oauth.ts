// Chrome Identity API wrapper for OAuth token management
// Uses Chrome Identity API for secure token storage and refresh

interface TokenData {
  accessToken: string;
  expiresAt: number; // Unix timestamp in ms
  provider: 'google' | 'microsoft';
}

const TOKEN_STORAGE_KEY = 'zp_oauth_tokens';
const ENCRYPTION_KEY_NAME = 'zp_encryption_key';

async function getOrCreateEncryptionKey(): Promise<CryptoKey> {
  const keyData = await chrome.storage.local.get(ENCRYPTION_KEY_NAME);
  if (keyData[ENCRYPTION_KEY_NAME]) {
    return crypto.subtle.importKey(
      'raw',
      new Uint8Array(keyData[ENCRYPTION_KEY_NAME]),
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  }

  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const exported = await crypto.subtle.exportKey('raw', key);
  await chrome.storage.local.set({ [ENCRYPTION_KEY_NAME]: Array.from(new Uint8Array(exported)) });
  return key;
}

async function encrypt(data: string): Promise<string> {
  const key = await getOrCreateEncryptionKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(data);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decrypt(encryptedData: string): Promise<string> {
  const key = await getOrCreateEncryptionKey();
  const combined = new Uint8Array(atob(encryptedData).split('').map(c => c.charCodeAt(0)));
  const iv = combined.slice(0, 12);
  const encrypted = combined.slice(12);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );
  return new TextDecoder().decode(decrypted);
}

export async function getStoredTokens(): Promise<Map<string, TokenData>> {
  const result = await chrome.storage.local.get(TOKEN_STORAGE_KEY);
  if (!result[TOKEN_STORAGE_KEY]) return new Map();

  const decrypted = await decrypt(result[TOKEN_STORAGE_KEY]);
  const parsed = JSON.parse(decrypted) as Record<string, TokenData>;
  const map = new Map<string, TokenData>();
  for (const [provider, data] of Object.entries(parsed)) {
    map.set(provider, data);
  }
  return map;
}

export async function setStoredTokens(tokens: Map<string, TokenData>): Promise<void> {
  const obj = Object.fromEntries(tokens);
  const encrypted = await encrypt(JSON.stringify(obj));
  await chrome.storage.local.set({ [TOKEN_STORAGE_KEY]: encrypted });
}

export async function getAccessToken(provider: 'google' | 'microsoft', interactive = false): Promise<string | null> {
  const tokens = await getStoredTokens();
  const tokenData = tokens.get(provider);

  // Check if token is still valid (with 5 min buffer)
  if (tokenData && tokenData.expiresAt > Date.now() + 5 * 60 * 1000) {
    return tokenData.accessToken;
  }

  // Need to get new token via Chrome Identity API
  return await fetchTokenInteractive(provider, interactive);
}

async function fetchTokenInteractive(provider: 'google' | 'microsoft', interactive: boolean): Promise<string | null> {
  return new Promise((resolve) => {
    const config: chrome.identity.TokenDetails = {
      interactive,
      scopes: provider === 'google'
        ? ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/userinfo.email']
        : ['https://graph.microsoft.com/Mail.Read', 'https://graph.microsoft.com/User.Read']
    };

    chrome.identity.getAuthToken(config, async (token) => {
      if (chrome.runtime.lastError || !token) {
        console.warn(`[ZeroPhish] Failed to get ${provider} token:`, chrome.runtime.lastError);
        resolve(null);
        return;
      }

      // Get token info to find expiry
      let expiresAt = Date.now() + 55 * 60 * 1000; // Default 55 min

      try {
        const response = await fetch(
          provider === 'google'
            ? `https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=${token}`
            : `https://graph.microsoft.com/v1.0/me?access_token=${token}`
        );
        if (response.ok) {
          const data = await response.json();
          if (data.expires_in) {
            expiresAt = Date.now() + (data.expires_in - 300) * 1000; // 5 min buffer
          }
        }
      } catch {
        // Use default expiry
      }

      const tokens = await getStoredTokens();
      tokens.set(provider, { accessToken: token, expiresAt, provider });
      await setStoredTokens(tokens);

      resolve(token);
    });
  });
}

export async function revokeToken(provider: 'google' | 'microsoft'): Promise<void> {
  const tokens = await getStoredTokens();
  const tokenData = tokens.get(provider);
  if (tokenData) {
    try {
      await fetch(
        provider === 'google'
          ? `https://oauth2.googleapis.com/revoke?token=${tokenData.accessToken}`
          : `https://login.microsoftonline.com/common/oauth2/v2.0/logout`,
        { method: 'POST' }
      );
    } catch {
      // Ignore revocation errors
    }
    tokens.delete(provider);
    await setStoredTokens(tokens);
  }
}

export async function clearAllTokens(): Promise<void> {
  await chrome.storage.local.remove([TOKEN_STORAGE_KEY]);
}

export function onTokenChanged(callback: (provider: 'google' | 'microsoft', token: string | null) => void): () => void {
  const listener = (changes: { [key: string]: chrome.storage.StorageChange }, area: string) => {
    if (area === 'local' && changes[TOKEN_STORAGE_KEY]) {
      getStoredTokens().then(tokens => {
        callback('google', tokens.get('google')?.accessToken ?? null);
        callback('microsoft', tokens.get('microsoft')?.accessToken ?? null);
      });
    }
  };
  chrome.storage.onChanged.addListener(listener);
  return () => chrome.storage.onChanged.removeListener(listener);
}