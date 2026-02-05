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

import { useState, useRef, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Turnstile } from '@marsidev/react-turnstile';
import { scanUrl } from '../services/api';
import AnalysisReport from './AnalysisReport';
import ChatWidget from './ChatWidget';
import { Shield, AlertTriangle, Search, RefreshCw } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const MatrixRain = () => {
    return (
        <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
            {[...Array(20)].map((_, i) => (
                <div
                    key={i}
                    className="absolute animate-matrix-fall text-cyan-500/20 text-xs font-mono"
                    style={{
                        left: `${Math.random() * 100}%`,
                        animationDelay: `${Math.random() * 5}s`,
                        animationDuration: `${10 + Math.random() * 10}s`,
                    }}
                >
                    {Array.from({ length: 20 }, () =>
                        String.fromCharCode(33 + Math.random() * 94)
                    ).join('\n')}
                </div>
            ))}
        </div>
    );
};

// Circular gauge component for visual score display
const CircularGauge = ({ value, max = 100, isPhishing }) => {
    const radius = 70;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (value / max) * circumference;

    const getColor = () => {
        if (!isPhishing) return '#10b981'; // Green for safe
        if (value >= 80) return '#ef4444'; // Red for critical
        if (value >= 60) return '#f97316'; // Orange for high
        if (value >= 40) return '#f59e0b'; // Yellow for medium
        return '#84cc16'; // Light green for low
    };

    return (
        <div className="relative inline-flex items-center justify-center">
            <svg className="transform -rotate-90" width="160" height="160">
                {/* Background circle */}
                <circle
                    cx="80"
                    cy="80"
                    r={radius}
                    stroke="currentColor"
                    strokeWidth="12"
                    fill="none"
                    className="text-gray-700"
                />
                {/* Progress circle */}
                <circle
                    cx="80"
                    cy="80"
                    r={radius}
                    stroke={getColor()}
                    strokeWidth="12"
                    fill="none"
                    strokeDasharray={circumference}
                    strokeDashoffset={offset}
                    strokeLinecap="round"
                    className="transition-all duration-1000 ease-out drop-shadow-[0_0_8px_currentColor]"
                />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-bold" style={{ color: getColor() }}>
                    {value}%
                </span>
                <span className="text-xs text-gray-400 uppercase tracking-wider">
                    {isPhishing ? 'Threat' : 'Safe'}
                </span>
            </div>
        </div>
    );
};

const Scanner = () => {
    const { t, i18n } = useTranslation();
    const [url, setUrl] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);

    // Cloudflare Turnstile state
    const [turnstileToken, setTurnstileToken] = useState(null);
    const [turnstileError, setTurnstileError] = useState(false);
    const turnstileRef = useRef(null);

    // Get Turnstile site key from environment
    const TURNSTILE_SITE_KEY = import.meta.env.VITE_CLOUDFLARE_SITE_KEY || '1x00000000000000000000AA';

    const sanitizeUrl = (inputUrl) => {
        let sanitized = inputUrl.trim();

        // Return null if empty
        if (!sanitized) {
            return null;
        }

        // Fix common typos in protocol
        if (sanitized.match(/^htps:\/\//i)) {
            sanitized = sanitized.replace(/^htps:\/\//i, 'https://');
        } else if (sanitized.match(/^htp:\/\//i)) {
            sanitized = sanitized.replace(/^htp:\/\//i, 'http://');
        } else if (sanitized.match(/^ttp:\/\//i)) {
            sanitized = sanitized.replace(/^ttp:\/\//i, 'http://');
        }

        // Add https:// if no protocol
        if (!sanitized.match(/^https?:\/\//i)) {
            sanitized = 'https://' + sanitized;
        }

        // Validate URL format
        try {
            const urlObj = new URL(sanitized);

            // Check if hostname is valid (contains at least one dot or is localhost)
            const hostname = urlObj.hostname.toLowerCase();
            const isValidHostname =
                hostname === 'localhost' ||
                hostname.includes('.') ||
                /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname); // IP address

            if (!isValidHostname) {
                return null; // Invalid hostname
            }

            return sanitized;
        } catch (error) {
            // Invalid URL format
            return null;
        }
    };

    const handleSubmit = async (e) => {
        // CRITICAL: Prevent default form submission to stop page reload
        e.preventDefault();

        // Early validation: Check if URL is provided
        if (!url.trim()) {
            setError('Please enter a URL to scan.');
            return;
        }

        // CRITICAL: Verify Turnstile token before proceeding
        if (!turnstileToken) {
            setError('Please complete the security verification first.');
            setTurnstileError(true);
            return;
        }

        // Use try-catch-finally to guarantee loading state cleanup
        try {
            // Set loading state FIRST - disable button and show spinner
            setLoading(true);
            setError(null);
            setResult(null);
            setTurnstileError(false);

            // Sanitize and validate URL before sending
            const sanitizedUrl = sanitizeUrl(url);

            // Check if URL is valid after sanitization
            if (!sanitizedUrl) {
                setLoading(false);
                setError(t('scanner.invalid_url') || 'Invalid URL format. Please enter a valid domain (e.g., google.com or https://example.com)');
                return;
            }

            // Call API with Turnstile token and Language
            // The API has 30s timeout configured in api.js
            const currentLang = i18n.language?.startsWith('vi') ? 'vi' : 'en';
            const response = await scanUrl(sanitizedUrl, true, turnstileToken, currentLang);

            // Handle successful response
            if (response.success) {
                // Defensive check: Ensure response.data exists and is valid
                if (!response.data) {
                    console.error('API returned success but no data:', response);
                    setError('Server returned invalid response. Please try again.');
                    return;
                }

                // Log successful response for debugging
                console.log('✅ Scan completed successfully:', response.data);

                // CRITICAL: Only setResult if data is valid
                // This prevents React from crashing on malformed data
                try {
                    setResult(response.data);
                    console.log('✅ Result state updated successfully');
                } catch (renderError) {
                    console.error('Failed to render result:', renderError);
                    setError('Failed to display scan results. Please try again.');
                    setResult(null);
                    return;
                }

                // IMPORTANT: Delay Turnstile reset to prevent interference with result rendering
                // Immediate reset can cause widget reload that triggers state changes
                // Wait for results to fully render before resetting the widget
                setTimeout(() => {
                    if (turnstileRef.current) {
                        console.log('🔄 Resetting Turnstile widget for next scan');
                        turnstileRef.current.reset();
                    }
                    setTurnstileToken(null);
                }, 500);  // 500ms delay to ensure results are displayed first
            } else {
                // Handle API errors with specific messages
                let errorMessage = response.error || 'An error occurred while scanning the URL.';

                // Add helpful context for common errors
                if (response.code === 'NETWORK_ERROR') {
                    errorMessage += ' Please check your internet connection and try again.';
                } else if (response.code === 'TURNSTILE_REQUIRED') {
                    errorMessage = 'Security verification failed. Please complete the verification again.';
                }

                setError(errorMessage);

                // If Turnstile verification failed, reset for retry
                if (response.code === 'TURNSTILE_REQUIRED' || response.needsRefresh) {
                    if (turnstileRef.current) {
                        turnstileRef.current.reset();
                    }
                    setTurnstileToken(null);
                    setTurnstileError(true);
                }
            }
        } catch (error) {
            // Catch any unexpected errors (e.g., timeout, network issues)
            console.error('Unexpected error during URL scan:', error);

            // User-friendly error message
            let errorMessage = 'An unexpected error occurred. ';

            if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
                errorMessage = 'The request took too long to complete. The URL might be slow or unreachable. Please try again.';
            } else if (error.message?.includes('Network Error')) {
                errorMessage = 'Cannot reach the server. Please check your internet connection and try again.';
            } else {
                errorMessage += 'Please try again or contact support if the issue persists.';
            }

            setError(errorMessage);

            // Reset Turnstile on unexpected errors
            if (turnstileRef.current) {
                turnstileRef.current.reset();
            }
            setTurnstileToken(null);
        } finally {
            // CRITICAL: Always reset loading state, even if errors occur
            // This prevents the UI from getting stuck in a loading state
            setLoading(false);
        }
    };

    // Handle Turnstile success
    const handleTurnstileSuccess = (token) => {
        setTurnstileToken(token);
        setTurnstileError(false);
        setError(null);
    };

    // Handle Turnstile error
    const handleTurnstileError = () => {
        setTurnstileError(true);
        setError('Security verification failed. Please try again.');
    };

    // Handle Turnstile expiration
    const handleTurnstileExpire = () => {
        setTurnstileToken(null);
        setTurnstileError(true);
        setError('Security verification expired. Please verify again.');
    };

    const getRiskLevel = (confidence, isPhishing) => {
        if (!isPhishing) return 'safe';
        if (confidence >= 80) return 'critical';
        if (confidence >= 60) return 'high';
        if (confidence >= 40) return 'medium';
        return 'low';
    };

    return (
        <div className="min-h-screen bg-linear-to-br from-gray-950 via-gray-900 to-black text-white">
            <MatrixRain />

            <div className="relative z-10 container mx-auto px-3 sm:px-4 py-4 sm:py-6 md:py-8 max-w-7xl">
                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.5 }}
                    className="text-center mb-6 sm:mb-8 md:mb-12"
                >
                    <h1 className="text-2xl sm:text-3xl md:text-5xl lg:text-6xl font-black mb-2 sm:mb-3 bg-linear-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent px-2">
                        {t('app_title')}
                    </h1>
                    <p className="text-sm sm:text-base md:text-lg text-gray-400 font-medium px-4">
                        {t('app_subtitle')}
                    </p>
                    <div className="mt-4 flex items-center justify-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                        <span className="text-sm text-green-400 font-mono">{t('chat.status_online')}</span>
                    </div>
                </motion.div>

                {/* Scanner Card - Glassmorphism */}
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.5, delay: 0.2 }}
                    className="mb-8"
                >
                    <div className="relative bg-gray-900/40 backdrop-blur-xl border border-cyan-500/30 rounded-xl sm:rounded-2xl p-4 sm:p-6 md:p-8 shadow-2xl shadow-cyan-500/10">
                        {/* Neon glow effect */}
                        <div className="absolute inset-0 bg-linear-to-r from-cyan-500/5 to-purple-500/5 rounded-2xl blur-xl" />

                        <form onSubmit={handleSubmit} className="relative space-y-6">
                            <div>
                                <label className="block text-xs sm:text-sm font-bold mb-2 sm:mb-3 text-cyan-400 uppercase tracking-wider">
                                    {t('scanner.title')}
                                </label>
                                <div className="relative">
                                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-500 w-5 h-5" />
                                    <input
                                        type="text"
                                        value={url}
                                        onChange={(e) => setUrl(e.target.value)}
                                        placeholder={t('scanner.placeholder')}
                                        required
                                        className="w-full bg-gray-950/50 backdrop-blur-sm border-2 border-cyan-500/30 
                      rounded-lg sm:rounded-xl pl-10 sm:pl-12 pr-3 sm:pr-4 py-3 sm:py-4 text-sm sm:text-base text-white placeholder-gray-500
                      focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20
                      transition-all duration-300
                      shadow-lg shadow-cyan-500/10"
                                        style={{
                                            boxShadow: '0 0 20px rgba(6, 182, 212, 0.1), inset 0 0 20px rgba(6, 182, 212, 0.02)'
                                        }}
                                    />
                                </div>
                                <p className="mt-2 text-xs text-gray-500">{t('scanner.example')}</p>
                            </div>

                            {/* Cloudflare Turnstile Widget */}
                            <div className="flex flex-col items-center gap-2 sm:gap-3">
                                <div className={`flex items-center justify-center p-2 sm:p-4 rounded-lg sm:rounded-xl border-2 transition-all duration-300 w-full max-w-[320px] min-h-[65px] ${turnstileError
                                    ? 'border-red-500/50 bg-red-950/20'
                                    : turnstileToken
                                        ? 'border-green-500/50 bg-green-950/20'
                                        : 'border-cyan-500/30 bg-gray-950/30 backdrop-blur-sm'
                                    }`}>
                                    <Turnstile
                                        ref={turnstileRef}
                                        siteKey={TURNSTILE_SITE_KEY}
                                        onSuccess={handleTurnstileSuccess}
                                        onError={handleTurnstileError}
                                        onExpire={handleTurnstileExpire}
                                        options={{
                                            theme: 'dark',
                                            size: 'normal',
                                        }}
                                        scriptOptions={{
                                            defer: true,           // Defer script loading
                                            async: true,           // Load script asynchronously
                                            appendTo: 'body',      // Append to body instead of head
                                            loadAsync: 'true',     // Cloudflare async mode
                                        }}
                                    />
                                </div>

                                {turnstileToken && (
                                    <motion.div
                                        initial={{ opacity: 0, scale: 0.8 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        className="flex items-center gap-2 text-green-400 text-sm font-medium"
                                    >
                                        <Shield className="w-4 h-4" />
                                        <span>✓ Security verification complete</span>
                                    </motion.div>
                                )}

                                {turnstileError && (
                                    <motion.div
                                        initial={{ opacity: 0, scale: 0.8 }}
                                        animate={{ opacity: 1, scale: 1 }}
                                        className="flex items-center gap-2 text-red-400 text-sm font-medium"
                                    >
                                        <AlertTriangle className="w-4 h-4" />
                                        <span>Please complete verification</span>
                                    </motion.div>
                                )}
                            </div>

                            <button
                                type="submit"
                                disabled={loading || !turnstileToken}
                                className={`w-full font-bold py-3 sm:py-4 px-4 sm:px-6 rounded-lg sm:rounded-xl uppercase tracking-wider transition-all duration-300 transform shadow-lg text-sm sm:text-base min-h-[48px]
                  ${loading || !turnstileToken
                                        ? 'bg-linear-to-r from-gray-700 to-gray-600 opacity-50 cursor-not-allowed'
                                        : 'bg-linear-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 sm:hover:scale-105 active:scale-95 shadow-cyan-500/30 hover:shadow-cyan-500/50'
                                    }`}
                            >
                                {loading ? (
                                    <span className="flex items-center justify-center gap-3">
                                        <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                        </svg>
                                        {t('scanner.scanning')}
                                    </span>
                                ) : (
                                    t('scanner.scan_button')
                                )}
                            </button>
                        </form>
                    </div>
                </motion.div>

                {/* Error Display */}
                <AnimatePresence>
                    {error && (
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="mb-8 bg-red-950/50 backdrop-blur-md border border-red-500/50 rounded-xl p-6"
                        >
                            <div className="flex items-center gap-4">
                                <AlertTriangle className="w-6 h-6 text-red-400 shrink-0" />
                                <div>
                                    <h3 className="text-lg font-bold text-red-400">Error</h3>
                                    <p className="text-red-200">{error}</p>
                                </div>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Results Display */}
                {result && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.5 }}
                        className="mb-8"
                    >
                        <AnalysisReport data={result} loading={false} />
                    </motion.div>
                )}

                {/* AI Chat Widget - Always visible */}
                <ChatWidget scanResult={result} />
            </div>
        </div>
    );
};

export default Scanner;
