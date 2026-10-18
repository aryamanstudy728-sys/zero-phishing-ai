// Outlook email content extraction via Microsoft Graph API

interface RawEmailData {
  messageId: string;
  headersRaw: string;
  bodyText: string;
  bodyHtml: string | null;
  urls: string[];
}

interface GraphMessage {
  id: string;
  internetMessageHeaders: Array<{ name: string; value: string }>;
  body: { content: string; contentType: 'html' | 'text' };
  from: { emailAddress: { address: string; name?: string } };
  sender: { emailAddress: { address: string; name?: string } };
  receivedDateTime: string;
}

async function fetchGraphMessage(messageId: string, accessToken: string): Promise<GraphMessage> {
  const response = await fetch(
    `https://graph.microsoft.com/v1.0/me/messages/${messageId}?$select=internetMessageHeaders,body,from,sender,receivedDateTime`,
    {
      headers: { Authorization: `Bearer ${accessToken}` }
    }
  );

  if (!response.ok) {
    throw new Error(`Graph API error: ${response.statusText}`);
  }

  return response.json();
}

function buildRawHeaders(headers: Array<{ name: string; value: string }>): string {
  return headers.map(h => `${h.name}: ${h.value}`).join('\r\n');
}

function extractUrls(html: string | null): string[] {
  if (!html) return [];
  const urls: string[] = [];

  if (typeof DOMParser === 'undefined') {
    // No DOM in the MV3 service worker: fall back to scanning hrefs directly
    const hrefRegex = /href=["'](https?:\/\/[^"']+)["']/gi;
    for (const match of html.matchAll(hrefRegex)) {
      urls.push(match[1]);
    }
    return [...new Set(urls)];
  }

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
  const message = await fetchGraphMessage(messageId, accessToken);

  const headersRaw = buildRawHeaders(message.internetMessageHeaders || []);
  const bodyHtml = message.body.contentType === 'html' ? message.body.content : null;
  const bodyText = message.body.contentType === 'text'
    ? message.body.content
    : bodyHtml ? bodyHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() : '';
  const urls = extractUrls(bodyHtml);

  return {
    messageId,
    headersRaw,
    bodyText,
    bodyHtml,
    urls
  };
}

// DOM fallback extraction
export function extractFromDOM(container: HTMLElement): Partial<RawEmailData> {
  const bodyHtml = container.innerHTML || null;
  const bodyText = container.innerText || '';
  const urls = extractUrls(bodyHtml);

  return { bodyText, bodyHtml, urls };
}