// Shared UI components for verdict badge and panel

import type { VerdictResponse } from '../../background/service-worker.js';

export function createVerdictBadge(verdict: VerdictResponse['verdict'], isLoading = false): HTMLElement {
  const container = document.createElement('div');
  container.className = 'zp-badge-container';
  container.setAttribute('role', 'button');
  container.setAttribute('tabindex', '0');
  container.setAttribute('aria-label', `Zero Phishing AI: ${isLoading ? 'Analyzing...' : verdict}`);

  const badge = document.createElement('span');
  badge.className = `zp-badge zp-badge--${isLoading ? 'loading' : verdict}`;
  badge.setAttribute('data-verdict', verdict);

  const icon = document.createElement('span');
  icon.className = 'zp-badge__icon';
  icon.innerHTML = getVerdictIcon(verdict);

  const text = document.createElement('span');
  text.className = 'zp-badge__text';
  text.textContent = isLoading ? 'Analyzing...' : verdict.charAt(0).toUpperCase() + verdict.slice(1);

  badge.appendChild(icon);
  badge.appendChild(text);
  container.appendChild(badge);

  return container;
}

export function createWhyPanel(verdict: VerdictResponse, onFeedback: (correction: 'safe' | 'suspicious' | 'dangerous', note?: string) => void): HTMLElement {
  const panel = document.createElement('div');
  panel.className = 'zp-panel';
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'Zero Phishing AI Analysis Details');

  panel.innerHTML = `
    <div class="zp-panel__header">
      <h3 class="zp-panel__title">
        <span class="zp-badge__icon">${getVerdictIcon(verdict.verdict)}</span>
        Analysis Details
      </h3>
      <button class="zp-panel__close" aria-label="Close panel">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="zp-panel__body">
      ${verdict.reasons.map(reason => `
        <div class="zp-panel__section">
          <div class="zp-panel__reason zp-panel__reason--${reason.severity}">
            <span class="zp-panel__reason-icon">${getSeverityIcon(reason.severity)}</span>
            <div class="zp-panel__reason-content">
              <div class="zp-panel__reason-category">${reason.category}</div>
              <div class="zp-panel__reason-detail">${escapeHtml(reason.detail)}</div>
            </div>
          </div>
        </div>
      `).join('')}
    </div>
    <div class="zp-panel__footer">
      <button class="zp-panel__feedback" data-action="feedback">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
        Mark as incorrect
      </button>
      <span class="zp-panel__timestamp">Analyzed ${formatTimestamp(Date.now())}</span>
    </div>
  `;

  const closeBtn = panel.querySelector('.zp-panel__close') as HTMLButtonElement;
  closeBtn?.addEventListener('click', () => panel.remove());

  const feedbackBtn = panel.querySelector('.zp-panel__feedback') as HTMLButtonElement;
  feedbackBtn?.addEventListener('click', () => {
    const correction = prompt(
      'What should the verdict be?\n1. Safe\n2. Suspicious\n3. Dangerous\n\nEnter 1, 2, or 3:',
      '1'
    );

    const correctionMap: Record<string, 'safe' | 'suspicious' | 'dangerous'> = {
      '1': 'safe',
      '2': 'suspicious',
      '3': 'dangerous'
    };

    if (correction && correctionMap[correction]) {
      const note = prompt('Optional note about why this is incorrect:') || undefined;
      onFeedback(correctionMap[correction], note);
    }
  });

  return panel;
}

function getVerdictIcon(verdict: VerdictResponse['verdict']): string {
  switch (verdict) {
    case 'safe':
      return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>`;
    case 'suspicious':
      return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    case 'dangerous':
      return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    default:
      return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>`;
  }
}

function getSeverityIcon(severity: string): string {
  switch (severity) {
    case 'critical': return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    case 'high': return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    case 'medium': return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>`;
    default: return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
  }
}

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatTimestamp(ts: number): string {
  const date = new Date(ts);
  return date.toLocaleString(undefined, { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' });
}

export function createEngagementTag(tag: string): HTMLElement {
  const span = document.createElement('span');
  span.className = `zp-engagement-tag zp-engagement-tag--${tag}`;
  span.textContent = tag.charAt(0).toUpperCase() + tag.slice(1);
  return span;
}

export function showToast(message: string): void {
  const existing = document.querySelector('.zp-feedback-toast');
  existing?.remove();

  const toast = document.createElement('div');
  toast.className = 'zp-feedback-toast';
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => toast.remove(), 3000);
}