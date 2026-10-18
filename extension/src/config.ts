// Central build-time configuration for the extension.
// VITE_API_BASE_URL is provided by Vite env files (extension/.env.development
// for local testing); the production URL is the fallback.

export const API_BASE_URL: string =
  import.meta.env.VITE_API_BASE_URL || 'https://api.zero-phishing.ai/api/v1';
