/**
 * API Service Helper for Phishing Detector Frontend
 * Axios instance configured for FastAPI backend communication
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

// Scan URL endpoint with deep analysis
export const scanUrl = async (url, deepAnalysis = true) => {
  try {
    const response = await api.post('/scan', {
      url,
      include_osint: true,
      deep_analysis: deepAnalysis
    });
    return {
      success: true,
      data: response.data,
    };
  } catch (error) {
    if (error.response) {
      return {
        success: false,
        error: error.response.data.detail || 'Server error occurred',
      };
    } else if (error.request) {
      return {
        success: false,
        error: `Server is not responding. Please make sure the backend is running at ${API_URL}`,
      };
    } else {
      return {
        success: false,
        error: 'An unexpected error occurred',
      };
    }
  }
};

export default api;

