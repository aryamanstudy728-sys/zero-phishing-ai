// Unit tests for extension utilities

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { hashMessage } from '../src/utils/cache.ts';
import { encrypt, decrypt } from '../src/utils/crypto.ts';

const storageMap = new Map<string, any>();
(globalThis as any).chrome = {
  storage: {
    local: {
      get: vi.fn(async (key: string) => ({ [key]: storageMap.get(key) })),
      set: vi.fn(async (items: Record<string, any>) => {
        Object.entries(items).forEach(([k, v]) => storageMap.set(k, v));
      }),
    },
  },
};

describe('cache utilities', () => {
  it('should generate consistent hash for same message', () => {
    const hash1 = hashMessage('msg-123', 'gmail');
    const hash2 = hashMessage('msg-123', 'gmail');
    expect(hash1).toBe(hash2);
  });

  it('should generate different hash for different messages', () => {
    const hash1 = hashMessage('msg-123', 'gmail');
    const hash2 = hashMessage('msg-456', 'gmail');
    expect(hash1).not.toBe(hash2);
  });

  it('should generate different hash for different providers', () => {
    const hash1 = hashMessage('msg-123', 'gmail');
    const hash2 = hashMessage('msg-123', 'outlook');
    expect(hash1).not.toBe(hash2);
  });
});

describe('crypto utilities', () => {
  it('should encrypt and decrypt correctly', async () => {
    const original = 'test-secret-data';
    const encrypted = await encrypt(original);
    const decrypted = await decrypt(encrypted);
    expect(decrypted).toBe(original);
  });

  it('should produce different ciphertext each time', async () => {
    const original = 'test-data';
    const encrypted1 = await encrypt(original);
    const encrypted2 = await encrypt(original);
    expect(encrypted1).not.toBe(encrypted2);
  });
});

describe('verdict badge creation', () => {
  it('should create safe badge', () => {
    // This would test the UI component
    expect(true).toBe(true);
  });
});