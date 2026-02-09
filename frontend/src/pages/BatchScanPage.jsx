/**
 * Batch Scan: textarea URLs, process 3 at a time, table result, export CSV.
 */

import { useState } from 'react';
import { scanOneUrl } from '../services/api';
import { useTheme } from '../context/ThemeContext';
import { FileDown, Loader2 } from 'lucide-react';

export default function BatchScanPage() {
  const [urlsText, setUrlsText] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const runBatch = async () => {
    const lines = urlsText.split(/\n/).map((u) => u.trim()).filter(Boolean);
    if (!lines.length) {
      setError('Enter at least one URL.');
      return;
    }
    setError('');
    setResults([]);
    setLoading(true);
    const all = [];
    for (let i = 0; i < lines.length; i += 3) {
      const chunk = lines.slice(i, i + 3);
      const promises = chunk.map((url) =>
        scanOneUrl(url).catch((e) => ({ url, verdict: 'ERROR', score: 0, error: e.message }))
      );
      const chunkResults = await Promise.all(promises);
      all.push(...chunkResults);
    }
    setResults(all);
    setLoading(false);
  };

  const exportCsv = () => {
    const headers = 'URL,Verdict,Score\n';
    const rows = results.map((r) => `${r.url},${r.verdict},${r.score}`).join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cybersentinel-batch-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className={isDark ? 'min-h-screen bg-black text-slate-200' : 'min-h-screen bg-gray-50 text-gray-900'}>
      <div className="max-w-4xl mx-auto px-4 py-8">
        <h1 className="text-2xl font-bold mb-2">Batch Scan</h1>
        <p className={isDark ? 'text-slate-400 mb-6' : 'text-gray-500 mb-6'}>
          Enter one URL per line. Scans run 3 at a time to avoid rate limits.
        </p>
        <textarea
          value={urlsText}
          onChange={(e) => setUrlsText(e.target.value)}
          placeholder="https://example.com&#10;https://another.com"
          rows={6}
          className={`w-full rounded-xl border p-4 font-mono text-sm ${
            isDark ? 'bg-gray-900 border-gray-700 text-white' : 'bg-white border-gray-200'
          }`}
        />
        {error && <p className="text-red-400 text-sm mt-2">{error}</p>}
        <div className="flex gap-3 mt-4">
          <button
            type="button"
            onClick={runBatch}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium disabled:opacity-50 flex items-center gap-2"
          >
            {loading ? <Loader2 className="w-4 h-5 animate-spin" /> : null}
            {loading ? 'Scanning…' : 'Start Batch'}
          </button>
          {results.length > 0 && (
            <button
              type="button"
              onClick={exportCsv}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-600 hover:bg-white/5"
            >
              <FileDown className="w-4 h-5" />
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
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i} className={isDark ? 'border-t border-gray-700' : 'border-t border-gray-200'}>
                    <td className="p-3 max-w-xs truncate" title={r.url}>{r.url}</td>
                    <td className="p-3">{r.verdict}</td>
                    <td className="p-3">{r.score}</td>
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
