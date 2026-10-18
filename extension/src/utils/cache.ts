// Local verdict cache using IndexedDB

interface CacheEntry {
  verdict: any;
  timestamp: number;
  messageHash: string;
}

const CACHE_DB_NAME = 'zp-verdict-cache';
const CACHE_STORE_NAME = 'verdicts';
const CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days

let dbPromise: Promise<IDBDatabase> | null = null;

function getDb(): Promise<IDBDatabase> {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
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
  return dbPromise;
}

export function hashMessage(messageId: string, provider: string): string {
  let hash = 0;
  const str = `${provider}:${messageId}`;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}

export async function getCachedVerdict(messageId: string, provider: string): Promise<any | null> {
  const messageHash = hashMessage(messageId, provider);
  const db = await getDb();

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

export async function setCachedVerdict(messageId: string, provider: string, verdict: any): Promise<void> {
  const messageHash = hashMessage(messageId, provider);
  const db = await getDb();

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

export async function clearCache(): Promise<void> {
  const db = await getDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(CACHE_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(CACHE_STORE_NAME);
    const request = store.clear();
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve();
  });
}

export async function getCacheSize(): Promise<number> {
  const db = await getDb();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(CACHE_STORE_NAME, 'readonly');
    const store = transaction.objectStore(CACHE_STORE_NAME);
    const request = store.count();
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}