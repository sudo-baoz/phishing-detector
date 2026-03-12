/**
 * Batch Scan: one POST to /scan/batch_process with all URLs and one captcha token.
 * Backend verifies captcha once and loops through URLs server-side (no 403 on subsequent URLs).
 */

import { useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { getApiUrl } from '../constants/api';
import { FileDown, Loader2, AlertCircle, Globe, Shield, Zap } from 'lucide-react';
import { Turnstile } from '@marsidev/react-turnstile';
import { motion } from 'framer-motion';

export default function BatchScanPage() {
  const [urlsText, setUrlsText] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [captchaToken, setCaptchaToken] = useState(null);
  const { theme } = useTheme();
  const { token } = useAuth();
  const isDark = theme === 'dark';

  const runBatch = async () => {
    const lines = urlsText
      .split(/\n/)
      .map((u) => u.trim())
      .filter(Boolean);
    if (!lines.length) {
      setError('Enter at least one URL.');
      return;
    }
    setError('');
    setResults([]);
    setLoading(true);
    setProgress({ current: 0, total: lines.length });

    const headers = {
      'Content-Type': 'application/json',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    if (captchaToken) {
      headers['cf-turnstile-response'] = captchaToken;
    }

    try {
      const res = await fetch(getApiUrl('scan/batch_process'), {
        method: 'POST',
        headers,
        body: JSON.stringify({ urls: lines }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg =
          (typeof body.detail === 'string' ? body.detail : body.detail?.message) ||
          (res.status === 403 ? 'Forbidden (403) – verification or auth' : `Error ${res.status}`);
        setError(msg);
        setResults([]);
        setLoading(false);
        setProgress({ current: 0, total: 0 });
        setCaptchaToken(null);
        return;
      }

      const data = await res.json();
      const rawResults = data.results || [];
      // Map backend status (safe/phishing/error) to display verdict (SAFE/PHISHING/ERROR)
      const mapped = rawResults.map((r) => ({
        url: r.url,
        verdict: (r.status === 'safe' ? 'SAFE' : r.status === 'phishing' ? 'PHISHING' : 'ERROR').toUpperCase(),
        score: Number(r.score ?? 0),
        error: r.error || null,
      }));
      setResults(mapped);
    } catch (err) {
      const message = err?.message || 'Request failed';
      setError(message);
      setResults([]);
    } finally {
      setLoading(false);
      setProgress({ current: 0, total: 0 });
      setCaptchaToken(null);
    }
  };

  const exportCsv = () => {
    const headers = 'URL,Verdict,Score,Error\n';
    const rows = results
      .map((r) => {
        const err = r.error ? `"${String(r.error).replace(/"/g, '""')}"` : '';
        return `${r.url},${r.verdict},${r.score},${err}`;
      })
      .join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cybersentinel-batch-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  // ============================================
  // Glassmorphism Styles - Match HomePage (ScanForm)
  // ============================================

  // Page background
  const pageContainer = isDark
    ? 'min-h-screen bg-transparent text-gray-50'
    : 'min-h-screen bg-transparent text-gray-900';

  // Glass card - same as ScanForm
  const glassCard = `
    rounded-2xl sm:rounded-3xl
    border backdrop-blur-xl shadow-2xl
    ${isDark ? 'bg-gray-900/60 border-white/10 shadow-black/20' : 'bg-white/30 border-white/40 shadow-blue-500/10'}
  `;

  // Textarea - similar to input in ScanForm
  const textareaClass = `
    w-full rounded-xl sm:rounded-2xl
    pl-4 pr-4 py-4
    text-sm sm:text-base
    border focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500
    transition-all shadow-lg
    ${isDark ? 'bg-gray-950/80 border-white/10 text-white placeholder-gray-400' : 'bg-white/90 border-gray-200/80 text-gray-900 placeholder-gray-500'}
  `;

  // Primary button - same as ScanForm
  const primaryButton = `
    w-full font-bold py-3.5 sm:py-4 px-4 sm:px-6
    rounded-xl sm:rounded-2xl
    uppercase tracking-wider transition-all text-sm sm:text-base
    min-h-[52px] shadow-lg
    ${loading
      ? 'bg-blue-600/80 text-white cursor-wait'
      : !captchaToken
        ? 'bg-gray-300 dark:bg-gray-700 text-gray-500 dark:text-gray-400 cursor-not-allowed'
        : 'bg-cyan-600 hover:bg-cyan-500 text-white'
    }
  `;

  // Secondary button for export
  const secondaryButton = `
    flex items-center justify-center gap-2 px-4 py-2.5
    rounded-xl border border-white/10 bg-white/5
    hover:bg-white/10 hover:border-cyan-500/30
    text-slate-300 hover:text-cyan-300
    transition-all duration-300
  `;

  return (
    <div className={pageContainer}>
      <div className="relative z-10 container mx-auto px-3 sm:px-4 py-8 max-w-7xl">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-8"
        >
          <div className="flex items-center justify-center gap-3 mb-2">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
              <Zap className="w-6 h-6 text-cyan-400" />
            </div>
            <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-gray-900 dark:text-gray-50">
              Batch Scan
            </h1>
          </div>
          <p className="text-sm sm:text-base text-gray-500 dark:text-gray-400 max-w-xl mx-auto">
            Enter one URL per line. One request sends all URLs to the server;
            captcha is verified once for the whole batch.
          </p>
        </motion.div>

        {/* Glassmorphism Form Container - Match ScanForm */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className={`relative p-5 sm:p-6 md:p-8 ${glassCard}`}
        >
          {/* Turnstile Captcha - Minimal style like Home page */}
          <div className="mb-6 flex justify-center">
            <div className={`
              flex items-center justify-center p-2 sm:p-3 rounded-xl
              border-2 w-full max-w-[340px] min-h-[65px] transition-colors
              ${captchaToken
                ? 'border-green-500/50 bg-green-500/10'
                : isDark ? 'border-slate-700/50 bg-slate-900/30' : 'border-gray-300 bg-gray-50'
              }
            `}>
              <Turnstile
                siteKey={import.meta.env.VITE_CLOUDFLARE_SITE_KEY || '1x00000000000000000000AA'}
                onSuccess={(token) => {
                  setCaptchaToken(token);
                  setError('');
                }}
                onExpire={() => {
                  setCaptchaToken(null);
                  setError('Verification expired. Please complete the challenge again.');
                }}
                onError={() => {
                  setCaptchaToken(null);
                  setError('Verification failed. Please try again.');
                }}
                options={{
                  theme: isDark ? 'dark' : 'light',
                  size: 'normal',
                }}
                scriptOptions={{ defer: true, async: true, appendTo: 'body', loadAsync: 'true' }}
              />
            </div>
          </div>

          {/* URL Textarea */}
          <textarea
            value={urlsText}
            onChange={(e) => setUrlsText(e.target.value)}
            placeholder="https://example.com&#10;https://another.com&#10;https://suspicious-site.com"
            rows={6}
            className={textareaClass}
          />

          {/* Error Message */}
          {error && (
            <p className="text-red-400 text-sm mt-3 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {error}
            </p>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3 mt-6 items-center">
            <button
              type="button"
              onClick={runBatch}
              disabled={loading || !captchaToken}
              className={primaryButton}
              title={!captchaToken && !loading ? 'Please complete the verification challenge first' : ''}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="w-5 h-5 animate-spin shrink-0" />
                  <span className="animate-pulse">Scanning...</span>
                </span>
              ) : (
                <span className="flex items-center justify-center gap-2">
                  <Shield className="w-5 h-5 shrink-0" />
                  Start Batch Scan
                </span>
              )}
            </button>

            {results.length > 0 && (
              <button
                type="button"
                onClick={exportCsv}
                className={secondaryButton}
              >
                <FileDown className="w-5 h-5" />
                Export CSV
              </button>
            )}
          </div>
        </motion.div>

        {/* Results Table */}
        {results.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="mt-8 overflow-hidden rounded-2xl border border-white/10 shadow-xl"
          >
            <div className="bg-gray-900/60 backdrop-blur-xl border-b border-white/5 px-6 py-4">
              <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
                <Globe className="w-5 h-5 text-cyan-400" />
                Scan Results ({results.length} URLs)
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-950/50">
                  <tr>
                    <th className="text-left p-4 text-gray-400 font-medium">URL</th>
                    <th className="text-left p-4 text-gray-400 font-medium">Verdict</th>
                    <th className="text-left p-4 text-gray-400 font-medium">Score</th>
                    <th className="text-left p-4 text-gray-400 font-medium">Error</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {results.map((r, i) => (
                    <tr key={i} className="hover:bg-white/5 transition-colors">
                      <td className="p-4 max-w-xs truncate text-gray-300" title={r.url}>
                        {r.url}
                      </td>
                      <td className="p-4">
                        <span
                          className={
                            r.verdict === 'ERROR'
                              ? 'text-red-400 bg-red-400/10 px-2 py-1 rounded-md text-xs font-medium'
                              : r.verdict === 'PHISHING'
                                ? 'text-orange-400 bg-orange-400/10 px-2 py-1 rounded-md text-xs font-medium'
                                : 'text-green-400 bg-green-400/10 px-2 py-1 rounded-md text-xs font-medium'
                          }
                        >
                          {r.verdict}
                        </span>
                      </td>
                      <td className="p-4 text-gray-300">{r.score}</td>
                      <td className="p-4 max-w-xs text-red-400/80 text-xs truncate" title={r.error || ''}>
                        {r.error || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
