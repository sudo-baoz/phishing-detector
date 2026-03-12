/**
 * Share view: GET /share/:scanId, read-only result.
 * Dark Mode Only - No Light Mode
 */
import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { fetchShareResult } from '../services/api';
import ScanResult from '../components/ScanResult';
import VersionBadge from '../components/VersionBadge';

export default function ShareResultPage() {
  const { scanId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [errorStatus, setErrorStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  const textMuted = 'text-slate-400';
  const textPrimary = 'text-slate-200';
  const textAccent = 'text-cyan-400';
  const textError = 'text-red-400';

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
      <div className="min-h-[60vh] bg-transparent flex items-center justify-center">
        <div className={`font-mono ${textAccent}`}>Loading shared result…</div>
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
      <div className="min-h-[60vh] bg-transparent flex items-center justify-center px-4">
        <div className="text-center max-w-md">
          <p className={`font-mono font-semibold text-lg ${textError}`}>{title}</p>
          <p className={`font-mono text-sm mt-2 ${textMuted}`}>{message}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-[60vh] bg-transparent text-slate-200">
      <div className="max-w-7xl mx-auto px-4 pt-6 pb-2">
        <p className="text-slate-400 text-sm mb-4">Shared scan result (read-only)</p>
      </div>
      <ScanResult data={data} loading={false} readOnly />
      <div className="max-w-7xl mx-auto px-4 py-6">
        <p className="text-slate-400 text-xs">
          <VersionBadge />
        </p>
      </div>
    </div>
  );
}
