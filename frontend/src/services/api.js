/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * API Service Helper for Phishing Detector Frontend
 * Axios instance configured for FastAPI backend communication
 * Includes Cloudflare Turnstile bot protection
 */

import axios from 'axios';
import { API_BASE_URL, getApiUrl } from '../constants/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 90000, // 90 seconds - must be > backend timeout (60s)
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Scan URL endpoint with Cloudflare Turnstile protection
 * @param {string} url - URL to scan
 * @param {boolean} deepAnalysis - Enable deep analysis
 * @param {string} turnstileToken - Cloudflare Turnstile verification token
 */
export const scanUrl = async (url, deepAnalysis = true, turnstileToken = null, language = 'en') => {
  try {
    // Prepare headers with Turnstile token
    const headers = {
      'Content-Type': 'application/json',
    };

    // Add Turnstile token to headers if provided
    if (turnstileToken) {
      headers['cf-turnstile-response'] = turnstileToken;
    }

    const response = await api.post('/scan', {
      url,
      include_osint: true,
      deep_analysis: deepAnalysis,
      language: language
    }, { headers });

    return {
      success: true,
      data: response.data,
    };
  } catch (error) {
    // Handle specific error cases
    if (error.response) {
      const status = error.response.status;
      const detail = error.response.data?.detail;

      if (status === 408) {
        return { success: false, error: '⏳ Scan timed out. The server is slow.', code: 'TIMEOUT' };
      }
      if (status === 400) {
        return { success: false, error: '🚫 Invalid URL format.', code: 'BAD_REQUEST' };
      }
      if (status === 403) {
        return {
          success: false,
          error: '🛡️ Access to this domain is restricted.',
          code: 'TURNSTILE_REQUIRED',
          needsRefresh: true
        };
      }
      if (status === 500) {
        return { success: false, error: '🔥 Server internal error.', code: 'SERVER_ERROR' };
      }
      return {
        success: false,
        error: typeof detail === 'string' ? detail : (detail?.message || 'Server error occurred'),
        code: 'SERVER_ERROR'
      };
    } else if (error.request) {
      // Network or timeout error
      const isTimeout = error.code === 'ECONNABORTED' || error.message?.includes('timeout');
      return {
        success: false,
        error: isTimeout 
          ? 'Scan is taking longer than expected. The site may be slow or unresponsive. Please try again.'
          : `Cannot reach server at ${API_BASE_URL}. Please check your connection.`,
        code: isTimeout ? 'TIMEOUT_ERROR' : 'NETWORK_ERROR'
      };
    } else {
      // Unexpected error
      return {
        success: false,
        error: 'An unexpected error occurred. Please try again.',
        code: 'UNKNOWN_ERROR'
      };
    }
  }
};

/**
 * Scan URL with NDJSON streaming: consumes real-time log lines and final result.
 * @param {string} url - URL to scan
 * @param {boolean} deepAnalysis - Enable deep analysis
 * @param {string|null} turnstileToken - Cloudflare Turnstile token
 * @param {string} language - Language code (en/vi)
 * @param {object} callbacks - { onLog, onResult, onError } — onError(message) called when stream yields type: "error"
 * @returns {Promise<object>} Resolves with final scan result; rejects on stream error or type: "error"
 */
export const scanUrlStream = async (url, deepAnalysis = true, turnstileToken = null, language = 'en', callbacks = {}) => {
  const { onLog = () => {}, onResult = () => {}, onError = () => {} } = callbacks;
  const headers = {
    'Content-Type': 'application/json',
  };
  if (turnstileToken) {
    headers['cf-turnstile-response'] = turnstileToken;
  }
  const res = await fetch(getApiUrl('scan/stream'), {
    method: 'POST',
    headers,
    body: JSON.stringify({
      url,
      include_osint: true,
      deep_analysis: deepAnalysis,
      language,
    }),
  });
  if (!res.ok) {
    const errBody = await res.text();
    let message = errBody || 'Server error';
    let isTokenExpired = false;
    try {
      const data = JSON.parse(errBody);
      const d = data.detail || data;
      if (d && typeof d === 'object') {
        message = d.message || d.detail || message;
        if (d.error === 'token_expired') isTokenExpired = true;
      }
    } catch (_) { /* ignore */ }
    if (res.status === 408) message = '⏳ Scan timed out. The server is slow.';
    else if (res.status === 400) message = '🚫 Invalid URL format.';
    else if (res.status === 403) message = '🛡️ Access to this domain is restricted.';
    else if (res.status === 500) message = '🔥 Server internal error.';
    else if (res.status === 503) message = 'Server busy, please try again in a few seconds.';
    else if (res.status === 403 && !message.includes('verification')) message = 'Security verification failed. Please complete the verification again.';
    const err = new Error(message);
    err.isTokenExpired = isTokenExpired;
    err.status = res.status;
    throw err;
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const obj = JSON.parse(trimmed);
        if (obj.type === 'log' && obj.message != null) {
          onLog(obj.message);
        } else if (obj.type === 'result' && obj.data != null) {
          onResult(obj.data);
          return obj.data;
        } else if (obj.type === 'error') {
          const msg = obj.message || 'Scan failed';
          onError(msg);
          throw new Error(msg);
        }
      } catch (e) {
        if (e instanceof SyntaxError) continue;
        throw e;
      }
    }
  }
  if (buffer.trim()) {
    try {
      const obj = JSON.parse(buffer.trim());
      if (obj.type === 'result' && obj.data != null) {
        onResult(obj.data);
        return obj.data;
      }
      if (obj.type === 'error') {
        const msg = obj.message || 'Scan failed';
        onError(msg);
        throw new Error(msg);
      }
    } catch (e) {
      if (e instanceof SyntaxError) {
        throw new Error('Stream ended without result');
      }
      throw e;
    }
  }
  throw new Error('Stream ended without result');
};

/**
 * Submit community feedback (false positive / false negative).
 * @param {{ url: string, predicted_verdict: 'SAFE'|'PHISHING', user_correction: 'SAFE'|'PHISHING', reason?: string }} payload
 */
export const submitFeedback = async (payload) => {
  const response = await api.post('/feedback', payload);
  return response.data;
};

/** Fetch shared scan result by scan_id (from ScanLog). PUBLIC endpoint, no auth. */
export const fetchShareResult = async (scanId) => {
  const res = await fetch(getApiUrl(`share/${scanId}`));
  if (!res.ok) {
    const message = res.status === 404 ? 'Scan not found' : res.status >= 500 ? 'Server error' : 'Failed to load';
    const err = new Error(message);
    err.status = res.status;
    throw err;
  }
  return res.json();
};

/** Single scan for batch: POST /scan (stream or non-stream). Returns { url, verdict, score } or throws. */
export const scanOneUrl = async (url, turnstileToken = null) => {
  const headers = { 'Content-Type': 'application/json' };
  if (turnstileToken) headers['cf-turnstile-response'] = turnstileToken;
  const r = await fetch(getApiUrl('scan'), {
    method: 'POST',
    headers,
    body: JSON.stringify({ url, include_osint: true, deep_analysis: false, language: 'en' }),
  });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    const msg = d.detail || (r.status === 408 ? 'Timeout' : r.status === 400 ? 'Invalid URL' : 'Error');
    throw new Error(msg);
  }
  const data = await r.json();
  const verdict = data.verdict?.level || (data.is_phishing ? 'PHISHING' : 'SAFE');
  const score = data.verdict?.score ?? data.confidence_score ?? 0;
  return { url, verdict, score: Number(score) };
};

export default api;
