// Gmail content script entry point

// Email extraction now happens in the background service worker (it holds the OAuth token)
import { injectVerdict, injectLoading, updateVerdict, removeInjected } from './injector.js';

interface AnalysisResult {
  verdict: any;
  error?: string;
}

let currentMessageId: string | null = null;
let currentContainer: HTMLElement | null = null;
let analysisInProgress = false;

function findCurrentEmailContainer(): { messageId: string; container: HTMLElement } | null {
  // Try to find the currently open email in Gmail
  const messageElements = document.querySelectorAll('[data-legacy-message-id], [data-message-id]');
  for (const el of messageElements) {
    const messageId = el.getAttribute('data-legacy-message-id') || el.getAttribute('data-message-id');
    if (messageId) {
      return { messageId, container: el as HTMLElement };
    }
  }
  // Fallback: try to find the main email container
  const mainContainer = document.querySelector('[role="main"] .aD, [role="main"] .gt, [data-legacy-thread-id]') as HTMLElement;
  if (mainContainer) {
    const messageId = mainContainer.getAttribute('data-legacy-message-id') || mainContainer.getAttribute('data-message-id');
    if (messageId) {
      return { messageId, container: mainContainer };
    }
  }
  return null;
}

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

// Single merged message listener handling both EMAIL_OPENED and ANALYZE_EMAIL_REQUEST
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

  if (message.type === 'ANALYZE_EMAIL_REQUEST') {
    const payload = message.payload;
    if (!payload) {
      sendResponse({ success: false, error: 'No email data' });
      return true;
    }

    // If we don't have current email state, try to find the open email in DOM
    if (!currentMessageId || !currentContainer) {
      const found = findCurrentEmailContainer();
      if (found) {
        currentMessageId = found.messageId;
        currentContainer = found.container;
      }
    }

    if (!currentMessageId || !currentContainer) {
      sendResponse({ success: false, error: 'No email data' });
      return true;
    }

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