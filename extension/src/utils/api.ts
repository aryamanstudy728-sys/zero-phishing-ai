// API client for backend communication

import type { AnalysisRequest, VerdictResponse } from '../background/service-worker.js';
import { API_BASE_URL } from '../config.js';

interface ApiClientOptions {
  getToken: (provider: 'gmail' | 'outlook') => Promise<string | null>;
}

export function createApiClient(options: ApiClientOptions) {
  async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${API_BASE_URL}${endpoint}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Unknown error' }));
      throw new Error(error.message || `HTTP ${response.status}`);
    }

    return response.json();
  }

  return {
    async analyzeEmail(analysisRequest: AnalysisRequest): Promise<VerdictResponse> {
      const token = await options.getToken(analysisRequest.provider);
      if (!token) {
        throw new Error(`No valid ${analysisRequest.provider} OAuth token`);
      }

      return request<VerdictResponse>('/analyze', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(analysisRequest)
      });
    },

    async submitFeedback(emailId: string, correction: 'safe' | 'suspicious' | 'dangerous', note?: string): Promise<void> {
      const token = await options.getToken('gmail'); // Feedback uses any valid token
      if (!token) throw new Error('No valid OAuth token');

      await request('/feedback', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ emailId, correction, note })
      });
    },

    async getEngagementStats(): Promise<Record<string, string>> {
      const token = await options.getToken('gmail');
      if (!token) throw new Error('No valid OAuth token');

      return request<Record<string, string>>('/engagement/stats', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
    }
  };
}