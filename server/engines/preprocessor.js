/**
 * Text Preprocessing and Extraction Engine
 */

const URL_REGEX = /(?:https?|hxxps?):\/\/[^\s<>"{}|\\^`[\]]+|(?:www\.)[^\s<>"{}|\\^`[\]]+|[a-zA-Z0-9.-]+\.(?:com|org|net|io|co|xyz|top|ru|cn|biz|info|online|security|bank|live|club|app)[^\s<>"{}|\\^`[\]]*/gi;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi;
const IP_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 
  'adf.ly', 'rebrand.ly', 'shorturl.at', 'cutt.ly', 'tiny.cc'
]);

export function preprocessInput(rawText) {
  if (typeof rawText !== 'string') {
    rawText = rawText ? String(rawText) : '';
  }

  const cleanText = rawText.trim();
  
  // Extract URLs
  const rawUrls = cleanText.match(URL_REGEX) || [];
  const urls = rawUrls.map(u => normalizeAndDeconstructUrl(u)).filter(Boolean);

  // Extract Emails
  const rawEmails = cleanText.match(EMAIL_REGEX) || [];
  const emails = [...new Set(rawEmails.map(e => e.toLowerCase()))].map(email => {
    const [local, domain] = email.split('@');
    return {
      email,
      local,
      domain
    };
  });

  // Tokenization & sentences
  const sentences = cleanText
    .split(/(?<=[.?!])\s+/)
    .map(s => s.trim())
    .filter(s => s.length > 0);

  const tokens = cleanText
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .split(/\s+/)
    .filter(t => t.length > 1);

  return {
    rawText,
    cleanText,
    charCount: cleanText.length,
    wordCount: tokens.length,
    sentences,
    tokens,
    urls,
    emails
  };
}

export function normalizeAndDeconstructUrl(rawUrl) {
  try {
    let normalized = rawUrl.trim();
    // Normalize defanged URLs (e.g. hxxp -> http)
    normalized = normalized.replace(/^hxxp(s?):/i, 'http$1:');
    
    // Add protocol if missing
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'http://' + normalized;
    }

    // Clean trailing punctuation
    normalized = normalized.replace(/[.,;!?)]+$/, '');

    const parsed = new URL(normalized);
    const hostname = parsed.hostname.toLowerCase();
    const isIP = IP_REGEX.test(hostname);
    const isShortener = URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(hostname.replace(/^www\./, ''));
    const isHttps = parsed.protocol === 'https:';
    const pathLength = parsed.pathname.length;
    const totalLength = normalized.length;

    // Check for suspicious chars in hostname/path
    const hasSuspiciousChars = /[@_%\\]/.test(parsed.pathname) || parsed.username !== '';
    const hasPunycode = hostname.startsWith('xn--');

    return {
      original: rawUrl,
      normalized,
      protocol: parsed.protocol,
      hostname,
      pathname: parsed.pathname,
      search: parsed.search,
      isHttps,
      isIP,
      isShortener,
      hasSuspiciousChars,
      hasPunycode,
      totalLength,
      pathLength
    };
  } catch (err) {
    return {
      original: rawUrl,
      normalized: rawUrl,
      protocol: 'unknown',
      hostname: rawUrl,
      pathname: '',
      search: '',
      isHttps: false,
      isIP: false,
      isShortener: false,
      hasSuspiciousChars: false,
      hasPunycode: false,
      totalLength: rawUrl.length,
      pathLength: 0,
      invalid: true
    };
  }
}
