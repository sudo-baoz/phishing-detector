/**
 * Security Suite - Data Breach Checker
 * Powered by XposedOrNot. We do not store your email.
 */

import { useState } from 'react';
import { Shield, ShieldAlert, Loader2 } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function BreachChecker() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleCheck = async () => {
    const trimmed = email.trim();
    if (!trimmed) return;
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/tools/breach-check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: trimmed }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || `Error ${res.status}`);
      }
      const data = await res.json();
      setResult(data);
    } catch (e) {
      setError(e.message || 'Check failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full bg-transparent">
      <p className="text-slate-400 text-sm mb-4">Check if your email appeared in known breaches.</p>
      <div className="flex flex-wrap gap-2 mb-4">
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="user@example.com"
          className="flex-1 min-w-[200px] px-3 py-2 rounded-lg bg-slate-800 border border-slate-600 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        />
        <button
          type="button"
          onClick={handleCheck}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium flex items-center gap-2"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
          Check Now
        </button>
      </div>
      {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
      {result && (
        <div className="rounded-lg border border-slate-700 bg-slate-800/50 p-4">
          {result.status === 'SAFE' && (
            <div className="flex items-center gap-3 text-green-400">
              <Shield className="w-8 h-8 shrink-0" />
              <span className="font-medium">Good news! No breaches found.</span>
            </div>
          )}
          {result.status === 'LEAKED' && (
            <div>
              <div className="flex items-center gap-3 text-red-400 mb-2">
                <ShieldAlert className="w-8 h-8 shrink-0" />
                <span className="font-medium">Oh no! Found in {result.count} breach(es).</span>
              </div>
              {result.breaches?.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {result.breaches.map((b, i) => (
                    <span key={i} className="px-2 py-1 rounded bg-red-500/20 border border-red-500/40 text-red-300 text-sm">
                      {b}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
      <p className="text-slate-500 text-xs mt-4">Powered by XposedOrNot. We do not store your email.</p>
    </div>
  );
}
