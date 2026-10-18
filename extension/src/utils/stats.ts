// Local verdict statistics stored in chrome.storage.local under zp_stats

export interface Stats {
  analyzed: number;
  safe: number;
  flagged: number;
}

const STATS_STORAGE_KEY = 'zp_stats';

export async function recordVerdict(verdict: 'safe' | 'suspicious' | 'dangerous'): Promise<void> {
  const result = await chrome.storage.local.get([STATS_STORAGE_KEY]);
  const stats: Stats = result[STATS_STORAGE_KEY] || { analyzed: 0, safe: 0, flagged: 0 };
  stats.analyzed += 1;
  if (verdict === 'safe') {
    stats.safe += 1;
  } else {
    stats.flagged += 1;
  }
  await chrome.storage.local.set({ [STATS_STORAGE_KEY]: stats });
}
