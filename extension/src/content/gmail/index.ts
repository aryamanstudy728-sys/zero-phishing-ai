// Gmail content script entry point

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
        provider: 'gmail',
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

// Listen for email open events and direct analysis requests
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'EMAIL_OPENED' && message.payload?.provider === 'gmail') {
    const { messageId } = message.payload;

    // Find the container for this message
    const container = document.querySelector(`[data-legacy-message-id="${messageId}"], [data-message-id="${messageId}"]`) as HTMLElement;
    if (container) {
      currentMessageId = messageId;
      currentContainer = container;
      analyzeCurrentEmail();
    }
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'ANALYZE_EMAIL_REQUEST' && (!message.payload?.provider || message.payload.provider === 'gmail')) {
    analyzeCurrentEmail();
    sendResponse({ success: true });
    return true;
  }

  return false;
});

// Handle Gmail navigation
let lastHash = window.location.hash;
setInterval(() => {
  if (window.location.hash !== lastHash) {
    lastHash = window.location.hash;
    currentMessageId = null;
    currentContainer = null;
    analysisInProgress = false;
  }
}, 500);

console.log('[ZeroPhish] Gmail content script loaded');