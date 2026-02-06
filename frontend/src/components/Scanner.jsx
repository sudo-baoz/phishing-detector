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
import { scanUrlStream } from '../services/api';
import AnalysisReport from './AnalysisReport';
import ChatWidget from './ChatWidget';
import ScanTerminal from './ScanTerminal';
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
    const [logs, setLogs] = useState([]);

    // Cloudflare Turnstile state + key-remount to force fresh widget after each use (prevents zombie token)
    const [turnstileToken, setTurnstileToken] = useState(null);
    const [turnstileError, setTurnstileError] = useState(false);
    const [widgetKey, setWidgetKey] = useState(0);
    const turnstileRef = useRef(null);

    // Get Turnstile site key from environment
    const TURNSTILE_SITE_KEY = import.meta.env.VITE_CLOUDFLARE_SITE_KEY || '1x00000000000000000000AA';
    // Dev mode: placeholder/test key → don't load Turnstile (avoids 404 / PAT console noise)
    const isTurnstileDevMode = !TURNSTILE_SITE_KEY || TURNSTILE_SITE_KEY === '1x00000000000000000000AA';

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
        e.preventDefault();

        // 1. Guard clauses
        if (loading) return;
        if (!url.trim()) {
            setError('Please enter a URL to scan.');
            return;
        }
        if (!isTurnstileDevMode && !turnstileToken) {
            setError('Please complete the security verification first.');
            setTurnstileError(true);
            return;
        }

        // 2. SNAPSHOT & CLEAR — kill state immediately so no reuse / zombie token
        const tokenToSend = isTurnstileDevMode ? null : turnstileToken;
        setTurnstileToken(null);
        setLoading(true);
        setError(null);
        setResult(null);
        setLogs([]);
        setTurnstileError(false);

        const sanitizedUrl = sanitizeUrl(url);
        if (!sanitizedUrl) {
            setLoading(false);
            setWidgetKey((k) => k + 1);
            setError(t('scanner.invalid_url') || 'Invalid URL format. Please enter a valid domain (e.g., google.com or https://example.com)');
            return;
        }

        const currentLang = i18n.language?.startsWith('vi') ? 'vi' : 'en';

        try {
            await scanUrlStream(
                sanitizedUrl,
                true,
                tokenToSend,
                currentLang,
                {
                    onLog: (message) => setLogs((prev) => [...prev, message]),
                    onResult: (scanData) => setResult(scanData),
                    onError: (message) => {
                        setError(message);
                        const lower = (message || '').toLowerCase();
                        if (lower.includes('expired') || lower.includes('already used') || lower.includes('security') || lower.includes('verification')) {
                            setTurnstileError(true);
                        }
                    },
                }
            );
        } catch (error) {
            console.error('Error during URL scan:', error);
            const errorMessage = error?.message || 'An unexpected error occurred. Please try again.';
            const lower = (errorMessage || '').toLowerCase();
            const isCaptchaError = error?.isTokenExpired || lower.includes('expired') || lower.includes('already used') || lower.includes('security') || lower.includes('verification');
            if (isCaptchaError) setTurnstileError(true);
            setError(errorMessage);
        } finally {
            setLoading(false);
            // 3. NUCLEAR RESET — remount widget so next scan always gets a fresh token (no zombie loop)
            setWidgetKey((prev) => prev + 1);
            setTurnstileToken(null);
        }
    };

    // Handle Turnstile success
    const handleTurnstileSuccess = (token) => {
        setTurnstileToken(token);
        setTurnstileError(false);
        setError(null);
    };

    // Handle Turnstile error (widget failed) — clear token and remount widget so user can retry
    const handleTurnstileError = () => {
        setTurnstileToken(null);
        setTurnstileError(true);
        setError('Security verification failed. Please try again.');
        setWidgetKey((k) => k + 1);
    };

    // Handle Turnstile expiration — clear token and remount widget for a fresh challenge
    const handleTurnstileExpire = () => {
        setTurnstileToken(null);
        setTurnstileError(true);
        setError('Security verification expired. Please verify again.');
        setWidgetKey((k) => k + 1);
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

                            {/* Cloudflare Turnstile Widget (hidden in dev mode to avoid 404/PAT console errors) */}
                            <div className="flex flex-col items-center gap-2 sm:gap-3">
                                {isTurnstileDevMode ? (
                                    <div className="flex items-center justify-center p-2 sm:p-4 rounded-lg sm:rounded-xl border-2 border-amber-500/40 bg-amber-950/20 w-full max-w-[320px] min-h-[65px]">
                                        <span className="text-amber-400/90 text-sm">Dev mode — verification skipped</span>
                                    </div>
                                ) : (
                                    <>
                                        <div className={`flex items-center justify-center p-2 sm:p-4 rounded-lg sm:rounded-xl border-2 transition-all duration-300 w-full max-w-[320px] min-h-[65px] ${turnstileError
                                            ? 'border-red-500/50 bg-red-950/20'
                                            : turnstileToken
                                                ? 'border-green-500/50 bg-green-950/20'
                                                : 'border-cyan-500/30 bg-gray-950/30 backdrop-blur-sm'
                                            }`}>
                                            <Turnstile
                                                key={widgetKey}
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
                                                    defer: true,
                                                    async: true,
                                                    appendTo: 'body',
                                                    loadAsync: 'true',
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
                                    </>
                                )}
                            </div>

                            <button
                                type="submit"
                                disabled={loading || (!isTurnstileDevMode && !turnstileToken)}
                                className={`w-full font-bold py-3 sm:py-4 px-4 sm:px-6 rounded-lg sm:rounded-xl uppercase tracking-wider transition-all duration-300 transform shadow-lg text-sm sm:text-base min-h-[48px]
                  ${loading || (!isTurnstileDevMode && !turnstileToken)
                                        ? 'bg-linear-to-r from-gray-700 to-gray-600 opacity-50 cursor-not-allowed'
                                        : 'bg-linear-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 sm:hover:scale-105 active:scale-95 shadow-cyan-500/30 hover:shadow-cyan-500/50'
                                    }`}
                            >
                                {loading ? (
                                    <span className="flex items-center justify-center gap-2">
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

                {/* Live Terminal Loader – shows as soon as user clicks Scan */}
                {loading && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="mb-8"
                    >
                        <ScanTerminal logs={logs} />
                    </motion.div>
                )}

                {/* Results Display */}
                {result && !loading && (
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
