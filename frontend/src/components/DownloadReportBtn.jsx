/**
 * Phishing Detector - Download Forensic Report Button
 * Copyright (c) 2026 BaoZ
 *
 * Triggers GET /report/{scan_id}/download and saves the PDF with loading state.
 */

import { useState } from 'react';
import { FileDown, Loader2 } from 'lucide-react';
import { getApiUrl } from '../constants/api';

export default function DownloadReportBtn({ scanId, className = '' }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleDownload = async () => {
    if (!scanId || loading) return;
    setError(null);
    setLoading(true);
    try {
      const res = await fetch(getApiUrl(`report/${scanId}/download`), {
        method: 'GET',
        credentials: 'include',
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(res.status === 404 ? 'Report not found.' : text || 'Download failed.');
      }
      const blob = await res.blob();
      const disposition = res.headers.get('Content-Disposition');
      const match = disposition && disposition.match(/filename="?([^";]+)"?/);
      const filename = match ? match[1].trim() : `forensic-report-${scanId}.pdf`;
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (e) {
      setError(e.message || 'Download failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={className}>
      <button
        type="button"
        onClick={handleDownload}
        disabled={!scanId || loading}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium transition-colors shadow-lg shadow-cyan-500/20"
      >
        {loading ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <FileDown className="w-4 h-4" />
        )}
        {loading ? 'Generating…' : 'Download Forensic Report'}
      </button>
      {error && (
        <p className="mt-2 text-sm text-red-400">{error}</p>
      )}
    </div>
  );
}
