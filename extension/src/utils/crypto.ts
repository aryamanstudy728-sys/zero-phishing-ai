// Encryption utilities for secure token storage

const ENCRYPTION_KEY_NAME = 'zp_encryption_key';

async function getOrCreateKey(): Promise<CryptoKey> {
  const stored = await chrome.storage.local.get(ENCRYPTION_KEY_NAME);
  if (stored[ENCRYPTION_KEY_NAME]) {
    return crypto.subtle.importKey(
      'raw',
      new Uint8Array(stored[ENCRYPTION_KEY_NAME]),
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

export async function encrypt(data: string): Promise<string> {
  const key = await getOrCreateKey();
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

export async function decrypt(encryptedData: string): Promise<string> {
  const key = await getOrCreateKey();
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