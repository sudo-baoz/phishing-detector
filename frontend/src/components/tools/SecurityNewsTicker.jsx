/**
 * SOC-style Security News Ticker. Fixed height required for MainLayout (40px).
 * Root MUST be h-10 overflow-hidden – do not allow dynamic height or layout breaks.
 */
import { useState, useEffect } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function SecurityNewsTicker() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`${API_BASE}/tools/news`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('Failed to load news'))))
      .then((data) => {
        if (!cancelled) setItems(Array.isArray(data) ? data : []);
      })
      .catch((e) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  const staticLabel =
    error && items.length === 0
      ? `News feed unavailable: ${error}`
      : loading && items.length === 0
        ? 'Loading threat intel…'
        : null;

  const linkFragment = (keyPrefix) =>
    items.map((item, i) => (
      <a
        key={`${keyPrefix}-${i}`}
        href={item.link || '#'}
        target="_blank"
        rel="noopener noreferrer"
        className="text-slate-400 hover:text-cyan-400 transition-colors px-4"
      >
        {item.title || 'No title'}
      </a>
    ));

  return (
    <div
      className="h-10 overflow-hidden flex items-center border-b border-gray-800 bg-black/80 shrink-0"
      style={{ fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace' }}
    >
      <div className="shrink-0 flex items-center gap-2 h-full px-3 sm:px-4 bg-gray-900/80 border-r border-gray-800">
        <span className="text-red-500 text-xs" aria-hidden>🔴</span>
        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
          Threat Intel:
        </span>
      </div>
      <div className="flex-1 min-w-0 py-1.5 overflow-hidden">
        {staticLabel ? (
          <span className="pl-4 text-xs sm:text-sm text-slate-500">{staticLabel}</span>
        ) : (
          <div className="flex animate-ticker gap-8 whitespace-nowrap text-xs sm:text-sm">
            {linkFragment('a')}
            {linkFragment('b')}
          </div>
        )}
      </div>
      <style>{`
        @keyframes ticker {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
        .animate-ticker {
          animation: ticker 50s linear infinite;
        }
      `}</style>
    </div>
  );
}
