/**
 * Centralized API configuration – single source of truth.
 * Priority: 1. Environment Variable → 2. Hardcoded Production Fallback
 */
export const API_BASE_URL =
  import.meta.env.VITE_API_URL || "https://api.baodarius.me";

/**
 * Build full API URL for an endpoint (no double slashes).
 * @param {string} endpoint - e.g. "tools/news", "scan/stream"
 * @returns {string} full URL
 */
export const getApiUrl = (endpoint) => {
  const cleanBase = API_BASE_URL.replace(/\/$/, "");
  const cleanEndpoint = (endpoint || "").replace(/^\//, "");
  return `${cleanBase}/${cleanEndpoint}`;
};
