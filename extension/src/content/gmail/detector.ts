// Gmail email open detection

interface EmailMetadata {
  messageId: string;
  threadId: string;
  element: HTMLElement;
}

let currentEmail: EmailMetadata | null = null;
let observer: MutationObserver | null = null;

function extractMessageIdFromUrl(): string | null {
  // Gmail URLs: https://mail.google.com/mail/u/0/#inbox/FMfcgxw...
  const match = window.location.hash.match(/[#&]message-id=([^&]+)/);
  if (match) return decodeURIComponent(match[1]);

  // Alternative: data-legacy-thread-id on the main element
  const main = document.querySelector('[role="main"] [data-legacy-thread-id]');
  if (main) return main.getAttribute('data-legacy-thread-id') || null;

  return null;
}

function findEmailContainer(): HTMLElement | null {
  // Gmail's email body container
  return document.querySelector('[role="main"] .aD, [role="main"] .gt, [data-legacy-thread-id]') as HTMLElement;
}

function findSenderElement(container: HTMLElement): HTMLElement | null {
  // Find the sender display area
  return container.querySelector('.gD, .go, [email], .yX span[name]') as HTMLElement;
}

function extractEmailData(container: HTMLElement): { messageId: string; threadId: string } | null {
  // Try to get message ID from various attributes
  const messageId = container.getAttribute('data-legacy-message-id') ||
                    container.getAttribute('data-message-id') ||
                    extractMessageIdFromUrl();

  const threadId = container.getAttribute('data-legacy-thread-id') ||
                   container.getAttribute('data-thread-id');

  if (!messageId) return null;

  return { messageId, threadId: threadId || messageId };
}

function onEmailOpened(container: HTMLElement): void {
  const data = extractEmailData(container);
  if (!data) return;

  // Avoid duplicate processing
  if (currentEmail?.messageId === data.messageId) return;

  currentEmail = { ...data, element: container };
  console.log('[ZeroPhish] Gmail email opened:', data.messageId);

  // Notify background to start analysis
  chrome.runtime.sendMessage({
    type: 'EMAIL_OPENED',
    payload: {
      provider: 'gmail',
      messageId: data.messageId,
      threadId: data.threadId
    }
  });
}

function onEmailClosed(): void {
  if (currentEmail) {
    console.log('[ZeroPhish] Gmail email closed:', currentEmail.messageId);
    currentEmail = null;
  }
}

function setupObserver(): void {
  const main = document.querySelector('[role="main"]');
  if (!main) return;

  observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const el = node as HTMLElement;
            // Check if this is an email container
            if (el.matches('.aD, .gt, [data-legacy-thread-id]') || el.querySelector('.aD, .gt, [data-legacy-thread-id]')) {
              const container = el.matches('.aD, .gt, [data-legacy-thread-id]') ? el : el.querySelector('.aD, .gt, [data-legacy-thread-id]');
              if (container) onEmailOpened(container as HTMLElement);
            }
          }
        }
        for (const node of mutation.removedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const el = node as HTMLElement;
            if (currentEmail?.element && (el === currentEmail.element || el.contains(currentEmail.element))) {
              onEmailClosed();
            }
          }
        }
      }
    }
  });

  observer.observe(main, { childList: true, subtree: true });
  console.log('[ZeroPhish] Gmail observer started');
}

function cleanup(): void {
  if (observer) {
    observer.disconnect();
    observer = null;
  }
  currentEmail = null;
}

// Initialize when Gmail is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', setupObserver);
} else {
  setupObserver();
}

// Handle SPA navigation
let lastUrl = window.location.href;
new MutationObserver(() => {
  const url = window.location.href;
  if (url !== lastUrl) {
    lastUrl = url;
    cleanup();
    setTimeout(setupObserver, 500); // Wait for Gmail to render
  }
}).observe(document, { subtree: true, childList: true });

export { onEmailOpened, onEmailClosed, extractEmailData };