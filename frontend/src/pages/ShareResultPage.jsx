/**
 * Share view: GET /share/:scanId, read-only result.
 * Uses MainLayout (theme/background). Version from env (Ver: {version} ({hash})).
 */
import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useTheme } from '../context/ThemeContext';
import { fetchShareResult } from '../services/api';
import ScanResult from '../components/ScanResult';
import VersionBadge from '../components/VersionBadge';

export default function ShareResultPage() {
  const { scanId } = useParams();
  const { theme } = useTheme();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [errorStatus, setErrorStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  const isDark = theme === 'dark';
  const bg = 'bg-transparent';
  const textMuted = isDark ? 'text-slate-400' : 'text-gray-500';
  const textPrimary = isDark ? 'text-slate-200' : 'text-gray-900';
  const textAccent = isDark ? 'text-cyan-400' : 'text-blue-600';
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
      <div className={`min-h-[60vh] ${bg} flex items-center justify-center`}>
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
      <div className={`min-h-[60vh] ${bg} flex items-center justify-center px-4`}>
        <div className="text-center max-w-md">
          <p className={`font-mono font-semibold text-lg ${textError}`}>{title}</p>
          <p className={`font-mono text-sm mt-2 ${textMuted}`}>{message}</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-[60vh] ${bg} ${textPrimary}`}>
      <div className="max-w-7xl mx-auto px-4 pt-6 pb-2">
        <p className={`${textMuted} text-sm mb-4`}>Shared scan result (read-only)</p>
      </div>
      <ScanResult data={data} loading={false} readOnly />
      <div className="max-w-7xl mx-auto px-4 py-6">
        <p className={`${textMuted} text-xs`}>
          <VersionBadge />
        </p>
      </div>
    </div>
  );
}
