/**
 * Security Suite - Link Unshortener
 * Resolve short URLs to final destination; optional suspicious domain warning.
 */

import { useState } from 'react';
import { Link2, AlertTriangle } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const SUSPICIOUS_PATTERNS = [
  /bit\.ly/i, /tinyurl\.com/i, /t\.co/i, /goo\.gl/i,
  /(?:free|gift|win|claim|verify|account|login|secure)\.(?:tk|ml|ga|cf|gq)/i,
  /[a-z0-9-]+\.(tk|ml|ga|cf|gq|xyz|top|club|work)(?:\/|$)/i,
];

function isSuspiciousDomain(url) {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return SUSPICIOUS_PATTERNS.some((p) => p.test(host));
  } catch {
    return false;
  }
}

export default function LinkExpander() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleUnshorten = async () => {
    const trimmed = url.trim();
    if (!trimmed) return;
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/tools/unshorten`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || `Error ${res.status}`);
      }
      const data = await res.json();
      setResult(data);
    } catch (e) {
      setError(e.message || 'Unshorten failed.');
    } finally {
      setLoading(false);
    }
  };

  const suspicious = result?.final_url ? isSuspiciousDomain(result.final_url) : false;

  return (
    <div className="w-full bg-transparent">
      <p className="text-slate-400 text-sm mb-4">Resolve short URLs to their final destination.</p>
      <div className="flex flex-wrap gap-2 mb-4">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://bit.ly/..."
          className="flex-1 min-w-[200px] px-3 py-2 rounded-lg bg-slate-800 border border-slate-600 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        />
        <button
          type="button"
          onClick={handleUnshorten}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium flex items-center gap-2"
        >
          <Link2 className="w-4 h-4" />
          {loading ? 'Resolving…' : 'Unshorten'}
        </button>
      </div>
      {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
      {result && (
        <div className="rounded-lg border border-slate-700 bg-slate-800/50 p-4 space-y-2">
          <p className="text-slate-400 text-xs">Destination URL</p>
          <a
            href={result.final_url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyan-400 break-all hover:underline block"
          >
            {result.final_url}
          </a>
          {suspicious && (
            <div className="flex items-center gap-2 text-amber-400 text-sm mt-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>Domain may be suspicious. Open with caution.</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
