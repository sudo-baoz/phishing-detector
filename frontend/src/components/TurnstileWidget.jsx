/**
 * Cloudflare Turnstile Widget Component
 * Reusable human verification widget that integrates with Cloudflare Turnstile
 */

import { Turnstile } from '@marsidev/react-turnstile';
import { useTheme } from '../context/ThemeContext';
import { Shield, AlertCircle } from 'lucide-react';
import { useState } from 'react';

export default function TurnstileWidget({ onVerify, onExpire, onError }) {
    const { theme } = useTheme();
    const isDark = theme === 'dark';
    const [error, setError] = useState(null);

    // Get site key from environment variables
    const siteKey = import.meta.env.VITE_CLOUDFLARE_SITE_KEY;

    // Show error if site key is not configured
    if (!siteKey || siteKey === '1x00000000000000000000AA') {
        return (
            <div
                className={`rounded-lg border p-4 ${isDark
                        ? 'bg-yellow-900/20 border-yellow-600/30 text-yellow-300'
                        : 'bg-yellow-50 border-yellow-200 text-yellow-800'
                    }`}
            >
                <div className="flex items-start gap-3">
                    <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
                    <div>
                        <h3 className="font-semibold mb-1">Turnstile Not Configured</h3>
                        <p className="text-sm opacity-90">
                            The Cloudflare Turnstile site key is not configured. Please add{' '}
                            <code className="px-1 py-0.5 rounded bg-black/20">
                                VITE_CLOUDFLARE_SITE_KEY
                            </code>{' '}
                            to your <code className="px-1 py-0.5 rounded bg-black/20">.env</code> file.
                        </p>
                    </div>
                </div>
            </div>
        );
    }

    const handleSuccess = (token) => {
        setError(null);
        if (onVerify) {
            onVerify(token);
        }
    };

    const handleExpire = () => {
        setError('Verification expired. Please complete the challenge again.');
        if (onExpire) {
            onExpire();
        }
    };

    const handleError = (err) => {
        const errorMessage = err?.message || 'Verification failed. Please try again.';
        setError(errorMessage);
        if (onError) {
            onError(err);
        }
    };

    return (
        <div className="space-y-3">
            {/* Header */}
            <div className="flex items-center gap-2">
                <Shield className={`w-5 h-5 ${isDark ? 'text-cyan-400' : 'text-cyan-600'}`} />
                <h3 className={`font-semibold ${isDark ? 'text-slate-200' : 'text-gray-900'}`}>
                    Human Verification
                </h3>
            </div>

            {/* Turnstile Widget Container */}
            <div
                className={`rounded-lg border p-4 ${isDark
                        ? 'bg-gray-900 border-gray-700'
                        : 'bg-gray-50 border-gray-200'
                    }`}
            >
                <Turnstile
                    siteKey={siteKey}
                    onSuccess={handleSuccess}
                    onExpire={handleExpire}
                    onError={handleError}
                    options={{
                        theme: isDark ? 'dark' : 'light',
                        size: 'normal',
                        // Retry if verification fails
                        retry: 'auto',
                        // Timeout after 5 minutes
                        'retry-interval': 8000,
                    }}
                />

                {/* Info Text */}
                <p className={`text-xs mt-3 ${isDark ? 'text-slate-400' : 'text-gray-500'}`}>
                    This verification helps protect against automated abuse and ensures fair access
                    to our scanning service.
                </p>
            </div>

            {/* Error Display */}
            {error && (
                <div
                    className={`rounded-lg border p-3 ${isDark
                            ? 'bg-red-900/20 border-red-600/30 text-red-300'
                            : 'bg-red-50 border-red-200 text-red-700'
                        }`}
                >
                    <div className="flex items-start gap-2">
                        <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                        <p className="text-sm">{error}</p>
                    </div>
                </div>
            )}
        </div>
    );
}
