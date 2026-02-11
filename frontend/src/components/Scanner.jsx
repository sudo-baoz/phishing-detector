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
import { scanUrlStream } from '../services/api';
import ScanResult from './ScanResult';
import ChatWidget from './ChatWidget';
import ScanTerminal from './ScanTerminal';
import EthicsModal from './EthicsModal';
import ScanForm from './ScanForm';
import { addToScanHistory } from './ScanHistory';
import { AlertTriangle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useTheme } from '../context/ThemeContext';

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
    const { theme } = useTheme();
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
    // Only skip verification in dev when using placeholder key (use import.meta.env.PROD, not NODE_ENV)
    const isTurnstileDevMode = !import.meta.env.PROD && (!TURNSTILE_SITE_KEY || TURNSTILE_SITE_KEY === '1x00000000000000000000AA');

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
                    onResult: (scanData) => {
                        setResult(scanData);
                        const shareId = scanData.share_id ?? scanData.id;
                        const verdict = scanData.verdict?.level ?? (scanData.is_phishing ? 'PHISHING' : 'SAFE');
                        if (shareId != null) addToScanHistory(shareId, scanData.url, verdict, scanData.scanned_at);
                    },
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

    const isDark = theme === 'dark';
    return (
        <div className="min-h-screen bg-transparent text-gray-900 dark:text-gray-50">
            {isDark && <MatrixRain />}

            <div className="relative z-10 min-h-screen flex flex-col container mx-auto px-3 sm:px-4 py-4 sm:py-6 md:py-8 max-w-7xl overflow-x-visible">
                {/* Hero: full-bleed ScanForm (break-out) – no restrictive wrapper */}
                <section className="flex-1 w-full">
                    <ScanForm
                        url={url}
                        setUrl={setUrl}
                        loading={loading}
                        onSubmit={handleSubmit}
                        turnstileToken={turnstileToken}
                        setTurnstileToken={setTurnstileToken}
                        turnstileError={turnstileError}
                        setTurnstileError={setTurnstileError}
                        widgetKey={widgetKey}
                        setWidgetKey={setWidgetKey}
                        turnstileRef={turnstileRef}
                        isTurnstileDevMode={isTurnstileDevMode}
                        TURNSTILE_SITE_KEY={TURNSTILE_SITE_KEY}
                    />
                </section>

                {/* Error Display – solid background for readability */}
                <AnimatePresence>
                    {error && (
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, y: -20 }}
                            className="mx-auto w-full max-w-xl mb-6 rounded-xl p-4 sm:p-6 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800"
                        >
                            <div className="flex items-center gap-4">
                                <AlertTriangle className="w-6 h-6 text-red-600 dark:text-red-400 shrink-0" />
                                <div>
                                    <h3 className="text-lg font-bold text-red-900 dark:text-red-100">Error</h3>
                                    <p className="text-red-700 dark:text-red-300">{error}</p>
                                </div>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {loading && (
                    <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="mb-8 w-full max-w-4xl mx-auto"
                    >
                        <ScanTerminal logs={logs} />
                    </motion.div>
                )}

                {result && !loading && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.5 }}
                        className="mb-8"
                    >
                        <ScanResult data={result} loading={false} />
                    </motion.div>
                )}

                <ChatWidget scanResult={result} />

                <footer className="mt-12 sm:mt-16 pb-8 flex flex-col items-center gap-4">
                    <EthicsModal />
                </footer>
            </div>
        </div>
    );
};

export default Scanner;
