/**
 * Security Suite - Security News Ticker
 * Fetches GET /tools/news (The Hacker News RSS), marquee-style.
 */

import { useState, useEffect } from 'react';
import { Newspaper } from 'lucide-react';

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

  if (loading && items.length === 0) {
    return (
      <div className="rounded-xl border border-slate-700 bg-slate-900/80 p-4 flex items-center gap-2 text-slate-400">
        <Newspaper className="w-5 h-5" />
        <span>Loading security news…</span>
      </div>
    );
  }

  if (error && items.length === 0) {
    return (
      <div className="rounded-xl border border-slate-700 bg-slate-900/80 p-4 text-amber-400">
        News ticker unavailable: {error}
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-red-500/30 bg-slate-900 overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2 bg-red-500/20 border-b border-red-500/30">
        <span className="px-2 py-0.5 rounded bg-red-500 text-white text-xs font-bold uppercase tracking-wider">
          Breaking News
        </span>
        <Newspaper className="w-4 h-4 text-red-400" />
      </div>
      <div className="relative py-3 overflow-hidden">
        <div className="flex animate-ticker gap-8 whitespace-nowrap">
          {items.map((item, i) => (
            <a
              key={i}
              href={item.link || '#'}
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-200 hover:text-cyan-400 transition-colors px-4"
            >
              {item.title || 'No title'}
            </a>
          ))}
          {items.length > 0 && items.map((item, i) => (
            <a
              key={`dup-${i}`}
              href={item.link || '#'}
              target="_blank"
              rel="noopener noreferrer"
              className="text-slate-200 hover:text-cyan-400 transition-colors px-4"
            >
              {item.title || 'No title'}
            </a>
          ))}
        </div>
      </div>
      <style>{`
        @keyframes ticker {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
        .animate-ticker {
          animation: ticker 40s linear infinite;
        }
      `}</style>
    </div>
  );
}
