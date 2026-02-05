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
  timeout: 30000,
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
export const scanUrl = async (url, deepAnalysis = true, turnstileToken = null) => {
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
      deep_analysis: deepAnalysis
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
      // Network error
      return {
        success: false,
        error: `Cannot reach server at ${API_URL}. Please check your connection.`,
        code: 'NETWORK_ERROR'
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

export default api;
