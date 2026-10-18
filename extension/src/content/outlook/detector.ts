// Outlook email open detection

interface EmailMetadata {
  messageId: string;
  element: HTMLElement;
}

let currentEmail: EmailMetadata | null = null;
let observer: MutationObserver | null = null;

function findEmailContainer(): HTMLElement | null {
  // Outlook Web message body container
  return document.querySelector('[data-test-id="message-body"], [role="main"] [data-content-type="message"]') as HTMLElement;
}

function findMessageListItem(): HTMLElement | null {
  // Message list item in inbox view
  return document.querySelector('[data-test-id="message-list-item"], [role="listitem"][data-item-key]') as HTMLElement;
}

function extractMessageId(container: HTMLElement): string | null {
  // Try various attributes
  return container.getAttribute('data-message-id') ||
         container.getAttribute('data-item-key') ||
         container.getAttribute('data-conversation-id') ||
         null;
}

function onEmailOpened(container: HTMLElement): void {
  const messageId = extractMessageId(container);
  if (!messageId) return;

  if (currentEmail?.messageId === messageId) return;

  currentEmail = { messageId, element: container };
  console.log('[ZeroPhish] Outlook email opened:', messageId);

  chrome.runtime.sendMessage({
    type: 'EMAIL_OPENED',
    payload: {
      provider: 'outlook',
      messageId,
      threadId: messageId // Outlook uses same ID for thread
    }
  });
}

function onEmailClosed(): void {
  if (currentEmail) {
    console.log('[ZeroPhish] Outlook email closed:', currentEmail.messageId);
    currentEmail = null;
  }
}

function setupObserver(): void {
  const main = document.querySelector('[role="main"], #readingPane, .reading-pane');
  if (!main) return;

  observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const el = node as HTMLElement;
            if (el.matches('[data-test-id="message-body"], [data-content-type="message"]') ||
                el.querySelector('[data-test-id="message-body"], [data-content-type="message"]')) {
              const container = el.matches('[data-test-id="message-body"], [data-content-type="message"]')
                ? el
                : el.querySelector('[data-test-id="message-body"], [data-content-type="message"]');
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
  console.log('[ZeroPhish] Outlook observer started');
}

function cleanup(): void {
  if (observer) {
    observer.disconnect();
    observer = null;
  }
  currentEmail = null;
}

// Initialize
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
    setTimeout(setupObserver, 500);
  }
}).observe(document, { subtree: true, childList: true });

export { onEmailOpened, onEmailClosed, extractMessageId };