/**
 * Cloudflare Turnstile Widget Component
 * Dark Mode Only - No Light Mode
 * Reusable human verification widget that integrates with Cloudflare Turnstile
 */

import { Turnstile } from '@marsidev/react-turnstile';
import { Shield, AlertCircle } from 'lucide-react';
import { useState } from 'react';

export default function TurnstileWidget({ onVerify, onExpire, onError }) {
    const [error, setError] = useState(null);

    // Get site key from environment variables
    const siteKey = import.meta.env.VITE_CLOUDFLARE_SITE_KEY;

    // Show error if site key is not configured
    if (!siteKey || siteKey === '1x00000000000000000000AA') {
        return (
            <div className="rounded-lg border p-4 bg-yellow-900/20 border-yellow-600/30 text-yellow-300">
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
                <Shield className="w-5 h-5 text-cyan-400" />
                <h3 className="font-semibold text-slate-200">
                    Human Verification
                </h3>
            </div>

            {/* Turnstile Widget Container */}
            <div className="rounded-lg border p-4 bg-gray-900 border-gray-700">
                <Turnstile
                    siteKey={siteKey}
                    onSuccess={handleSuccess}
                    onExpire={handleExpire}
                    onError={handleError}
                    options={{
                        theme: 'dark',
                        size: 'normal',
                        retry: 'auto',
                        'retry-interval': 8000,
                    }}
                />

                {/* Info Text */}
                <p className="text-xs mt-3 text-slate-400">
                    This verification helps protect against automated abuse and ensures fair access
                    to our scanning service.
                </p>
            </div>

            {/* Error Display */}
            {error && (
                <div className="rounded-lg border p-3 bg-red-900/20 border-red-600/30 text-red-300">
                    <div className="flex items-start gap-2">
                        <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                        <p className="text-sm">{error}</p>
                    </div>
                </div>
            )}
        </div>
    );
}
