/**
 * Share view: GET /share/:scanId, render result read-only.
 * Fetches from API_BASE/share/:scanId (public, no auth). Handles 404 vs 5xx in UI.
 */

import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { fetchShareResult } from '../services/api';
import AnalysisReport from '../components/AnalysisReport';
import { VERSION_BADGE } from '../constants/appInfo';

export default function ShareResultPage() {
  const { scanId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [errorStatus, setErrorStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) {
      setError('Missing scan ID');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    setErrorStatus(null);
    fetchShareResult(scanId)
      .then(setData)
      .catch((e) => {
        setError(e.message || 'Failed to load');
        setErrorStatus(e.status ?? null);
      })
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-cyan-400 font-mono">Loading shared result…</div>
      </div>
    );
  }
  if (error || !data) {
    const is404 = errorStatus === 404;
    const is5xx = errorStatus >= 500;
    const title = is404 ? 'Scan not found' : is5xx ? 'Server error' : 'Error';
    const message = is404
      ? 'This scan may have been removed or the link is invalid.'
      : is5xx
        ? 'Something went wrong on our side. Please try again later.'
        : error || 'Scan not found';
    return (
      <div className="min-h-screen bg-black flex items-center justify-center px-4">
        <div className="text-center max-w-md">
          <p className="text-red-400 font-mono font-semibold text-lg">{title}</p>
          <p className="text-slate-400 font-mono text-sm mt-2">{message}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-slate-200">
      <div className="max-w-4xl mx-auto px-4 py-6">
        <p className="text-slate-500 text-sm mb-4">Shared scan result (read-only)</p>
        <AnalysisReport data={data} readOnly />
        <p className="mt-6 text-slate-500 text-xs">{VERSION_BADGE}</p>
      </div>
    </div>
  );
}
