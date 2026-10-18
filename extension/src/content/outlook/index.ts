// Outlook content script entry point

import { extractEmailData } from './extractor.js';
import { injectVerdict, injectLoading, updateVerdict, removeInjected } from './injector.js';

interface AnalysisResult {
  verdict: any;
  error?: string;
}

let currentMessageId: string | null = null;
let currentContainer: HTMLElement | null = null;
let analysisInProgress = false;

async function analyzeCurrentEmail(): Promise<void> {
  if (!currentMessageId || !currentContainer || analysisInProgress) return;

  analysisInProgress = true;
  injectLoading(currentContainer);

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'ANALYZE_EMAIL',
      payload: {
        provider: 'outlook',
        messageId: currentMessageId
      }
    });

    if (response.error) {
      console.error('[ZeroPhish] Analysis error:', response.error);
      removeInjected(currentContainer);
      return;
    }

    updateVerdict(currentContainer, response);
  } catch (error) {
    console.error('[ZeroPhish] Analysis failed:', error);
    removeInjected(currentContainer);
  } finally {
    analysisInProgress = false;
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'EMAIL_OPENED' && message.payload?.provider === 'outlook') {
    const { messageId } = message.payload;

    const container = document.querySelector(`[data-message-id="${messageId}"], [data-item-key="${messageId}"]`) as HTMLElement;
    if (container) {
      currentMessageId = messageId;
      currentContainer = container;
      analyzeCurrentEmail();
    }
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'ANALYZE_EMAIL_REQUEST' && (!message.payload?.provider || message.payload.provider === 'outlook')) {
    analyzeCurrentEmail();
    sendResponse({ success: true });
    return true;
  }

  return false;
});

let lastUrl = window.location.href;
setInterval(() => {
  if (window.location.href !== lastUrl) {
    lastUrl = window.location.href;
    currentMessageId = null;
    currentContainer = null;
    analysisInProgress = false;
  }
}, 500);

console.log('[ZeroPhish] Outlook content script loaded');