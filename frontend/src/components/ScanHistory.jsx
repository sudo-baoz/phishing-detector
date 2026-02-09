/**
 * Last 20 scans from localStorage. List/table + Clear History.
 */

import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useTheme } from '../context/ThemeContext';
import { History, Trash2 } from 'lucide-react';

const STORAGE_KEY = 'cybersentinel-scan-history';
const MAX = 20;

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

export function addToScanHistory(scanId, url, verdict, date) {
  const list = loadHistory();
  list.unshift({ id: scanId, url, verdict, date: date || new Date().toISOString() });
  saveHistory(list);
}

export default function ScanHistory({ onClear }) {
  const [items, setItems] = useState(loadHistory());
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  useEffect(() => {
    setItems(loadHistory());
  }, []);

  const clear = () => {
    localStorage.removeItem(STORAGE_KEY);
    setItems([]);
    onClear?.();
  };

  if (items.length === 0) return null;

  return (
    <div className={`rounded-xl border p-4 ${isDark ? 'bg-gray-900/50 border-gray-700' : 'bg-white border-gray-200'}`}>
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-semibold flex items-center gap-2">
          <History className="w-4 h-4" />
          Recent scans
        </h3>
        <button
          type="button"
          onClick={clear}
          className="text-sm text-red-400 hover:text-red-300 flex items-center gap-1"
        >
          <Trash2 className="w-3 h-3" />
          Clear History
        </button>
      </div>
      <ul className="space-y-2 max-h-60 overflow-y-auto">
        {items.map((item, i) => (
          <li key={`${item.id}-${i}`} className="flex items-center justify-between gap-2 text-sm">
            <span className="truncate flex-1" title={item.url}>{item.url}</span>
            <span className={item.verdict === 'PHISHING' || item.verdict === 'HIGH' ? 'text-red-400' : 'text-green-400'}>
              {item.verdict}
            </span>
            {item.id != null && (
              <Link
                to={`/share/${item.id}`}
                className="text-cyan-400 hover:underline shrink-0"
              >
                Share
              </Link>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
