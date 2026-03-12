/**
 * History Page – Scan history in a modern card table with status badges and empty state.
 * Dark Mode Only - No Light Mode
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { History, Trash2, Shield, Share2 } from 'lucide-react';

const STORAGE_KEY = 'cybersentinel-scan-history';
const MAX = 100;

function loadHistory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveHistory(list) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(list.slice(0, MAX)));
  } catch (_) {}
}

function formatDate(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, { dateStyle: 'short' }) + ' ' + d.toLocaleTimeString(undefined, { timeStyle: 'short' });
  } catch {
    return iso || '—';
  }
}

function VerdictBadge({ verdict }) {
  const v = (verdict || '').toUpperCase();
  const isSafe = v === 'SAFE' || v === 'LOW';
  const isPhishing = v === 'PHISHING' || v === 'HIGH' || v === 'CRITICAL';
  const isUncertain = !isSafe && !isPhishing;

  if (isSafe) {
    return (
      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-900/30 text-green-400">
        Safe
      </span>
    );
  }
  if (isPhishing) {
    return (
      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-900/30 text-red-400">
        Phishing
      </span>
    );
  }
  if (isUncertain) {
    return (
      <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-yellow-900/30 text-yellow-400">
        Uncertain
      </span>
    );
  }
  return (
    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-700 text-gray-300">
      {verdict || '—'}
    </span>
  );
}

export default function HistoryPage() {
  const [items, setItems] = useState(loadHistory());
  const [toast, setToast] = useState('');

  useEffect(() => {
    setItems(loadHistory());
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(''), 2000);
    return () => clearTimeout(t);
  }, [toast]);

  const clear = () => {
    localStorage.removeItem(STORAGE_KEY);
    setItems([]);
  };

  const copyShareLink = (scanId) => {
    const link = `${window.location.origin}/share/${scanId}`;
    navigator.clipboard.writeText(link).then(
      () => setToast('Link copied!'),
      () => setToast('Failed to copy')
    );
  };

  const cardClass = 'bg-gray-900 rounded-xl border border-gray-800 overflow-hidden';
  const theadClass = 'uppercase text-xs font-semibold text-gray-400 bg-gray-800/80';
  const rowClass = 'transition-colors hover:bg-gray-800/50 border-t border-gray-800';

  return (
    <div className="min-h-screen bg-transparent">
      {toast && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-[9999] px-4 py-2 rounded-lg bg-gray-800 text-white text-sm font-medium shadow-lg border border-gray-700">
          {toast}
        </div>
      )}
      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold text-slate-200 flex items-center gap-2">
            <History className="w-7 h-7 text-cyan-500" />
            Scan History
          </h1>
          {items.length > 0 && (
            <button
              type="button"
              onClick={clear}
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-red-400 hover:bg-red-900/20 transition-colors"
            >
              <Trash2 className="w-4 h-4" />
              Clear History
            </button>
          )}
        </div>

        <div className={cardClass}>
          {items.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
              <div className="w-16 h-16 rounded-full bg-gray-800 flex items-center justify-center mb-4">
                <History className="w-8 h-8 text-gray-500" />
              </div>
              <h2 className="text-lg font-semibold text-slate-200 mb-1">No scan history yet</h2>
              <p className="text-sm text-gray-400 mb-6 max-w-sm">
                Your recent scans will appear here. Run a URL scan to get started.
              </p>
              <Link
                to="/"
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition-colors"
              >
                <Shield className="w-4 h-4" />
                Start Scanning
              </Link>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr>
                    <th className={`text-left py-3 px-4 ${theadClass}`}>URL</th>
                    <th className={`text-left py-3 px-4 ${theadClass}`}>Status</th>
                    <th className={`text-left py-3 px-4 ${theadClass}`}>Date</th>
                    <th className={`text-right py-3 px-4 ${theadClass}`}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item, i) => (
                    <tr key={`${item.id}-${i}`} className={rowClass}>
                      <td className="py-3 px-4 max-w-xs truncate text-slate-200" title={item.url}>
                        {item.url}
                      </td>
                      <td className="py-3 px-4">
                        <VerdictBadge verdict={item.verdict} />
                      </td>
                      <td className="py-3 px-4 text-gray-400 whitespace-nowrap">
                        {formatDate(item.date)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        {item.id != null && (
                          <div className="flex items-center justify-end gap-2">
                            <Link
                              to={`/share/${item.id}`}
                              className="text-cyan-400 hover:underline font-medium"
                            >
                              View
                            </Link>
                            <button
                              type="button"
                              onClick={() => copyShareLink(item.id)}
                              className="p-2 rounded-lg text-blue-400 hover:bg-blue-900/30 transition-colors"
                              title="Copy share link"
                            >
                              <Share2 className="w-4 h-4" />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
