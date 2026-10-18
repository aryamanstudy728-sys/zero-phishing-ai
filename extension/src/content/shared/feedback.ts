// Local feedback storage for "mark incorrect" feature

interface FeedbackEntry {
  emailId: string;
  originalVerdict: 'safe' | 'suspicious' | 'dangerous';
  correction: 'safe' | 'suspicious' | 'dangerous';
  note?: string;
  timestamp: number;
}

const FEEDBACK_STORE = 'zp_feedback';

async function getFeedback(): Promise<FeedbackEntry[]> {
  const result = await chrome.storage.local.get(FEEDBACK_STORE);
  return result[FEEDBACK_STORE] || [];
}

async function saveFeedback(entries: FeedbackEntry[]): Promise<void> {
  await chrome.storage.local.set({ [FEEDBACK_STORE]: entries });
}

export async function addFeedback(entry: Omit<FeedbackEntry, 'timestamp'>): Promise<void> {
  const feedback = await getFeedback();
  feedback.push({ ...entry, timestamp: Date.now() });
  await saveFeedback(feedback);
}

export async function getFeedbackForEmail(emailId: string): Promise<FeedbackEntry | null> {
  const feedback = await getFeedback();
  return feedback.find(f => f.emailId === emailId) || null;
}

export async function getAllFeedback(): Promise<FeedbackEntry[]> {
  return getFeedback();
}

export async function clearFeedback(): Promise<void> {
  await chrome.storage.local.remove(FEEDBACK_STORE);
}

export function getCorrectionLabel(correction: 'safe' | 'suspicious' | 'dangerous'): string {
  return correction.charAt(0).toUpperCase() + correction.slice(1);
}