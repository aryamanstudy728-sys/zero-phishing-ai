// Gmail email content extraction

interface RawEmailData {
  messageId: string;
  headersRaw: string;
  bodyText: string;
  bodyHtml: string | null;
  urls: string[];
}

async function fetchRawEmail(messageId: string, accessToken: string): Promise<string> {
  const response = await fetch(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=raw`,
    {
      headers: { Authorization: `Bearer ${accessToken}` }
    }
  );

  if (!response.ok) {
    throw new Error(`Failed to fetch raw email: ${response.statusText}`);
  }

  const data = await response.json();
  return data.raw;
}

function decodeBase64Url(str: string): string {
  // Gmail uses base64url encoding
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad) base64 += '='.repeat(4 - pad);
  return atob(base64);
}

function parseRawEmail(raw: string): { headers: string; bodyText: string; bodyHtml: string | null } {
  const decoded = decodeBase64Url(raw);
  const headerEnd = decoded.indexOf('\r\n\r\n');
  if (headerEnd === -1) return { headers: '', bodyText: decoded, bodyHtml: null };

  const headers = decoded.slice(0, headerEnd);
  const body = decoded.slice(headerEnd + 4);

  // Simple MIME parsing - in production use a proper MIME parser
  let bodyText = body;
  let bodyHtml: string | null = null;

  if (headers.includes('multipart/')) {
    // Very basic multipart handling
    const boundaryMatch = headers.match(/boundary="([^"]+)"/);
    if (boundaryMatch) {
      const boundary = '--' + boundaryMatch[1];
      const parts = body.split(boundary);
      for (const part of parts) {
        if (part.includes('text/plain')) {
          const contentStart = part.indexOf('\r\n\r\n');
          if (contentStart !== -1) bodyText = part.slice(contentStart + 4).trim();
        } else if (part.includes('text/html')) {
          const contentStart = part.indexOf('\r\n\r\n');
          if (contentStart !== -1) bodyHtml = part.slice(contentStart + 4).trim();
        }
      }
    }
  } else if (headers.includes('text/html')) {
    bodyHtml = body;
    // Strip HTML for text version
    bodyText = body.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  } else {
    bodyHtml = null;
  }

  return { headers, bodyText, bodyHtml };
}

function extractUrls(html: string | null): string[] {
  if (!html) return [];
  const urls: string[] = [];
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  const links = doc.querySelectorAll('a[href]');
  links.forEach(link => {
    const href = link.getAttribute('href');
    if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
      urls.push(href);
    }
  });
  return [...new Set(urls)];
}

export async function extractEmailData(messageId: string, accessToken: string): Promise<RawEmailData> {
  const raw = await fetchRawEmail(messageId, accessToken);
  const { headers, bodyText, bodyHtml } = parseRawEmail(raw);
  const urls = extractUrls(bodyHtml);

  return {
    messageId,
    headersRaw: headers,
    bodyText,
    bodyHtml,
    urls
  };
}

// Also extract from DOM as fallback
export function extractFromDOM(container: HTMLElement): Partial<RawEmailData> {
  const bodyText = container.innerText || '';
  const bodyHtml = container.innerHTML || null;
  const urls = extractUrls(bodyHtml);

  return { bodyText, bodyHtml, urls };
}