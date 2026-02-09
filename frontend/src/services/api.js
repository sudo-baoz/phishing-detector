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

// Create axios instance with default configuration
// Use environment variable for API URL (supports HTTPS in production)
const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const api = axios.create({
  baseURL: API_URL,
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

      // Handle 403 Forbidden (Turnstile verification failed)
      if (status === 403) {
        return {
          success: false,
          error: 'Security check failed. Please complete the verification and try again.',
          code: 'TURNSTILE_REQUIRED',
          needsRefresh: true
        };
      }

      // Handle other server errors
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
          : `Cannot reach server at ${API_URL}. Please check your connection.`,
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
  const baseURL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
  const res = await fetch(`${baseURL}/scan/stream`, {
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
    if (res.status === 403 && !message.includes('verification')) message = 'Security verification failed. Please complete the verification again.';
    if (res.status === 503) message = 'Server busy, please try again in a few seconds.';
    const err = new Error(message);
    err.isTokenExpired = isTokenExpired;
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

export default api;
