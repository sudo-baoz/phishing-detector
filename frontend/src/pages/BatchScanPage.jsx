/**
 * Batch Scan: textarea URLs, process sequentially with delay to avoid 403/WAF.
 * Uses JWT when available; throttles one request at a time with 1s delay.
 */

import { useState } from 'react';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { getApiUrl } from '../constants/api';
import { FileDown, Loader2, AlertCircle } from 'lucide-react';
import TurnstileWidget from '../components/TurnstileWidget';

const DELAY_MS = 1000;

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

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
    // Add Turnstile token for human verification
    if (captchaToken) {
      headers['cf-turnstile-response'] = captchaToken;
    }

    for (let i = 0; i < lines.length; i++) {
      const url = lines[i];
      setProgress((p) => ({ ...p, current: i + 1 }));

      try {
        await delay(DELAY_MS);
        const res = await fetch(getApiUrl('scan'), {
          method: 'POST',
          headers,
          body: JSON.stringify({
            url,
            include_osint: true,
            deep_analysis: false,
            language: 'en',
          }),
        });

        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          const msg =
            (typeof body.detail === 'string' ? body.detail : body.detail?.message) ||
            (res.status === 403 ? 'Forbidden (403) – rate limit or auth' : `Error ${res.status}`);
          setResults((prev) => [
            ...prev,
            { url, verdict: 'ERROR', score: 0, error: msg },
          ]);
          continue;
        }

        const data = await res.json();
        const verdict =
          data.verdict?.level || (data.is_phishing ? 'PHISHING' : 'SAFE');
        const score =
          data.verdict?.score ?? data.confidence_score ?? 0;
        setResults((prev) => [
          ...prev,
          { url, verdict, score: Number(score), error: null },
        ]);
      } catch (err) {
        const message = err?.message || 'Request failed';
        setResults((prev) => [
          ...prev,
          { url, verdict: 'ERROR', score: 0, error: message },
        ]);
      }
    }

    setLoading(false);
    setProgress({ current: 0, total: 0 });
    // Reset captcha token after scan completion to require re-verification
    setCaptchaToken(null);
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

  return (
    <div
      className={
        isDark
          ? 'min-h-screen bg-black text-slate-200'
          : 'min-h-screen bg-gray-50 text-gray-900'
      }
    >
      <div className="max-w-4xl mx-auto px-4 py-8">
        <h1 className="text-2xl font-bold mb-2">Batch Scan</h1>
        <p className={isDark ? 'text-slate-400 mb-6' : 'text-gray-500 mb-6'}>
          Enter one URL per line. Scans run one at a time with a 1s delay to
          avoid rate limits (403).
        </p>

        {/* Turnstile Human Verification Widget */}
        <div className="mb-6">
          <TurnstileWidget
            onVerify={(token) => {
              setCaptchaToken(token);
              setError(''); // Clear any previous errors
            }}
            onExpire={() => {
              setCaptchaToken(null);
              setError('Verification expired. Please complete the challenge again.');
            }}
            onError={(err) => {
              setCaptchaToken(null);
              setError('Verification failed. Please try again.');
            }}
          />
        </div>
        <textarea
          value={urlsText}
          onChange={(e) => setUrlsText(e.target.value)}
          placeholder="https://example.com&#10;https://another.com"
          rows={6}
          className={`w-full rounded-xl border p-4 font-mono text-sm ${isDark
              ? 'bg-gray-900 border-gray-700 text-white'
              : 'bg-white border-gray-200'
            }`}
        />
        {error && (
          <p className="text-red-400 text-sm mt-2 flex items-center gap-1">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error}
          </p>
        )}
        <div className="flex gap-3 mt-4 items-center">
          <button
            type="button"
            onClick={runBatch}
            disabled={loading || !captchaToken}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            title={!captchaToken && !loading ? 'Please complete the verification challenge first' : ''}
          >
            {loading ? (
              <Loader2 className="w-5 h-5 animate-spin shrink-0" />
            ) : null}
            {loading
              ? `Scanning ${progress.current} / ${progress.total}…`
              : 'Start Batch'}
          </button>
          {results.length > 0 && (
            <button
              type="button"
              onClick={exportCsv}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-600 hover:bg-white/5"
            >
              <FileDown className="w-5 h-5" />
              Export CSV
            </button>
          )}
        </div>
        {results.length > 0 && (
          <div className="mt-8 overflow-x-auto rounded-xl border border-gray-700">
            <table className="w-full text-sm">
              <thead className={isDark ? 'bg-gray-800' : 'bg-gray-100'}>
                <tr>
                  <th className="text-left p-3">URL</th>
                  <th className="text-left p-3">Verdict</th>
                  <th className="text-left p-3">Score</th>
                  <th className="text-left p-3">Error</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr
                    key={i}
                    className={
                      isDark
                        ? 'border-t border-gray-700'
                        : 'border-t border-gray-200'
                    }
                  >
                    <td className="p-3 max-w-xs truncate" title={r.url}>
                      {r.url}
                    </td>
                    <td className="p-3">
                      <span
                        className={
                          r.verdict === 'ERROR'
                            ? 'text-red-400'
                            : r.verdict === 'PHISHING'
                              ? 'text-orange-400'
                              : 'text-green-400'
                        }
                      >
                        {r.verdict}
                      </span>
                    </td>
                    <td className="p-3">{r.score}</td>
                    <td className="p-3 max-w-xs text-red-400 text-xs truncate" title={r.error || ''}>
                      {r.error || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
