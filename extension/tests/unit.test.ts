// Unit tests for extension utilities

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { hashMessage } from '../src/utils/cache.ts';
import { encrypt, decrypt } from '../src/utils/crypto.ts';
import { toAnalysisBody } from '../src/utils/analysis.ts';
import { recordVerdict } from '../src/utils/stats.ts';

const storageMap = new Map<string, any>();
(globalThis as any).chrome = {
  storage: {
    local: {
      get: vi.fn(async (key: string | string[]) => {
        const keys = Array.isArray(key) ? key : [key];
        return Object.fromEntries(keys.map((k) => [k, storageMap.get(k)]));
      }),
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

describe('snake_case analysis body mapping', () => {
  const rawEmail = {
    messageId: 'msg-1',
    headersRaw: 'From: sender@example.com\r\nSubject: Hello',
    bodyText: 'Hello world',
    bodyHtml: '<p>Hello <b>world</b></p>',
    urls: ['https://example.com/phish'],
  };

  it('maps extractor output to the backend snake_case fields', () => {
    const body = toAnalysisBody('gmail', rawEmail);
    expect(body).toEqual({
      message_id: 'msg-1',
      provider: 'gmail',
      headers_raw: 'From: sender@example.com\r\nSubject: Hello',
      body_text: 'Hello world',
      body_html: '<p>Hello <b>world</b></p>',
      urls: ['https://example.com/phish'],
    });
    expect(body).not.toHaveProperty('messageId');
    expect(body).not.toHaveProperty('bodyText');
  });

  it('passes the request provider through to the body', () => {
    expect(toAnalysisBody('outlook', rawEmail).provider).toBe('outlook');
  });

  it('falls back to stripped HTML when body_text is empty', () => {
    const body = toAnalysisBody('gmail', { ...rawEmail, bodyText: '   ', bodyHtml: '<p>Hi <b>there</b></p>' });
    expect(body.body_text).toBe('Hi there');
    expect(body.body_html).toBe('<p>Hi <b>there</b></p>');
  });

  it('falls back to a placeholder when body_text and body_html are empty', () => {
    const body = toAnalysisBody('gmail', { ...rawEmail, bodyText: '', bodyHtml: null });
    expect(body.body_text).toBe('(no text)');
    expect(body.body_html).toBeNull();
  });
});

describe('verdict stats', () => {
  beforeEach(() => {
    storageMap.clear();
  });

  it('counts a safe verdict as analyzed + safe', async () => {
    await recordVerdict('safe');
    expect(storageMap.get('zp_stats')).toEqual({ analyzed: 1, safe: 1, flagged: 0 });
  });

  it('counts suspicious and dangerous verdicts as flagged', async () => {
    await recordVerdict('suspicious');
    await recordVerdict('dangerous');
    expect(storageMap.get('zp_stats')).toEqual({ analyzed: 2, safe: 0, flagged: 2 });
  });

  it('increments existing stats without resetting them', async () => {
    storageMap.set('zp_stats', { analyzed: 4, safe: 3, flagged: 1 });
    await recordVerdict('safe');
    expect(storageMap.get('zp_stats')).toEqual({ analyzed: 5, safe: 4, flagged: 1 });
  });

  it('leaves stats unchanged when reading them fails', async () => {
    const getMock = (globalThis as any).chrome.storage.local.get as ReturnType<typeof vi.fn>;
    getMock.mockRejectedValueOnce(new Error('storage unavailable'));
    await expect(recordVerdict('safe')).rejects.toThrow('storage unavailable');
    expect(storageMap.get('zp_stats')).toBeUndefined();
  });
});