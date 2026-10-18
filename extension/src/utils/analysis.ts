// Maps extracted email data to the backend's snake_case analysis body

import type { RawEmailData } from '../content/gmail/extractor.js';

export interface AnalysisBody {
  message_id: string;
  provider: 'gmail' | 'outlook';
  headers_raw: string;
  body_text: string;
  body_html: string | null;
  urls: string[];
}

function stripHtmlTags(html: string): string {
  return html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

export function toAnalysisBody(provider: 'gmail' | 'outlook', email: RawEmailData): AnalysisBody {
  // The backend requires a non-empty body_text: prefer the plain-text body,
  // fall back to the HTML with tags stripped, then to a placeholder.
  let bodyText = email.bodyText.trim() === '' ? '' : email.bodyText;
  if (bodyText === '' && email.bodyHtml) {
    bodyText = stripHtmlTags(email.bodyHtml);
  }
  if (bodyText === '') {
    bodyText = '(no text)';
  }

  return {
    message_id: email.messageId,
    provider,
    headers_raw: email.headersRaw,
    body_text: bodyText,
    body_html: email.bodyHtml ?? null,
    urls: email.urls
  };
}
