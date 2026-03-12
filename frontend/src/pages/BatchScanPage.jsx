/**
 * Batch Scan: one POST to /scan/batch_process with all URLs and one captcha token.
 * Backend verifies captcha once and loops through URLs server-side (no 403 on subsequent URLs).
 */

import { useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { getApiUrl } from '../constants/api';
import { FileDown, Loader2, AlertCircle, Globe, Shield, Zap } from 'lucide-react';
import TurnstileWidget from '../components/TurnstileWidget';

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
  // Glassmorphism Styles
  // ============================================
  const pageContainer = isDark
    ? 'min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-slate-200'
    : 'min-h-screen bg-gradient-to-br from-gray-100 via-gray-50 to-gray-100 text-gray-900';

  // Main form container - Glassmorphism
  const glassContainer = `
    bg-slate-900/40 backdrop-blur-md
    border border-white/10
    rounded-2xl
    shadow-xl shadow-black/20
    p-6
  `;

  // Textarea glass style
  const textareaStyles = `
    w-full rounded-xl border border-white/10
    bg-slate-950/50
    text-slate-200 placeholder-slate-500
    p-4 font-mono text-sm
    focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-400
    transition-all duration-300
    ${isDark ? 'bg-slate-950/50' : 'bg-gray-900/50 text-gray-800'}
  `;

  // Captcha container glass
  const captchaContainer = `
    bg-slate-950/30
    border border-white/5
    rounded-lg
    p-4
    mb-6
  `;

  // Button styles
  const primaryButton = `
    px-6 py-2.5 rounded-xl
    bg-cyan-600 hover:bg-cyan-500
    text-white font-medium
    disabled:opacity-50 disabled:cursor-not-allowed
    flex items-center gap-2
    transition-all duration-300
    hover:shadow-lg hover:shadow-cyan-500/25
  `;

  const secondaryButton = `
    flex items-center gap-2 px-4 py-2.5 rounded-xl
    border border-white/10 bg-white/5
    hover:bg-white/10 hover:border-cyan-500/30
    transition-all duration-300
  `;

  return (
    <div className={pageContainer}>
      <div className="max-w-4xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
              <Zap className="w-6 h-6 text-cyan-400" />
            </div>
            <h1 className="text-2xl font-bold text-slate-100">Batch Scan</h1>
          </div>
          <p className="text-slate-400 text-sm max-w-xl">
            Enter one URL per line. One request sends all URLs to the server;
            captcha is verified once for the whole batch.
          </p>
        </div>

        {/* Glassmorphism Form Container */}
        <div className={glassContainer}>
          {/* Turnstile Human Verification Widget */}
          <div className={captchaContainer}>
            <TurnstileWidget
              onVerify={(token) => {
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
            />
          </div>

          {/* URL Textarea */}
          <textarea
            value={urlsText}
            onChange={(e) => setUrlsText(e.target.value)}
            placeholder="https://example.com&#10;https://another.com&#10;https://suspicious-site.com"
            rows={6}
            className={textareaStyles}
          />

          {/* Error Message */}
          {error && (
            <p className="text-red-400 text-sm mt-3 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {error}
            </p>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3 mt-5 items-center">
            <button
              type="button"
              onClick={runBatch}
              disabled={loading || !captchaToken}
              className={primaryButton}
              title={!captchaToken && !loading ? 'Please complete the verification challenge first' : ''}
            >
              {loading ? (
                <Loader2 className="w-5 h-5 animate-spin shrink-0" />
              ) : (
                <Shield className="w-5 h-5 shrink-0" />
              )}
              {loading ? 'Scanning...' : 'Start Batch Scan'}
            </button>

            {results.length > 0 && (
              <button
                type="button"
                onClick={exportCsv}
                className={secondaryButton}
              >
                <FileDown className="w-5 h-5 text-slate-300" />
                <span className="text-slate-300">Export CSV</span>
              </button>
            )}
          </div>
        </div>

        {/* Results Table */}
        {results.length > 0 && (
          <div className="mt-8 overflow-hidden rounded-2xl border border-white/10 shadow-xl">
            <div className="bg-slate-900/60 backdrop-blur-sm border-b border-white/5 px-4 py-3">
              <h2 className="text-lg font-semibold text-slate-200 flex items-center gap-2">
                <Globe className="w-5 h-5 text-cyan-400" />
                Scan Results ({results.length} URLs)
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-slate-950/50">
                  <tr>
                    <th className="text-left p-4 text-slate-400 font-medium">URL</th>
                    <th className="text-left p-4 text-slate-400 font-medium">Verdict</th>
                    <th className="text-left p-4 text-slate-400 font-medium">Score</th>
                    <th className="text-left p-4 text-slate-400 font-medium">Error</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {results.map((r, i) => (
                    <tr key={i} className="hover:bg-white/5 transition-colors">
                      <td className="p-4 max-w-xs truncate text-slate-300" title={r.url}>
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
                      <td className="p-4 text-slate-300">{r.score}</td>
                      <td className="p-4 max-w-xs text-red-400/80 text-xs truncate" title={r.error || ''}>
                        {r.error || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
