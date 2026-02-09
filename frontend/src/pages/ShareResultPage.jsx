/**
 * Share view: GET /share/:scanId, render result read-only.
 */

import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { fetchShareResult } from '../services/api';
import AnalysisReport from '../components/AnalysisReport';
import { MODEL_VERSION } from '../constants/modelVersion';

export default function ShareResultPage() {
  const { scanId } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) {
      setError('Missing scan ID');
      setLoading(false);
      return;
    }
    fetchShareResult(scanId)
      .then(setData)
      .catch((e) => setError(e.message))
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
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-red-400 font-mono">{error || 'Not found'}</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-slate-200">
      <div className="max-w-4xl mx-auto px-4 py-6">
        <p className="text-slate-500 text-sm mb-4">Shared scan result (read-only)</p>
        <AnalysisReport data={data} readOnly />
        <p className="mt-6 text-slate-500 text-xs">{MODEL_VERSION}</p>
      </div>
    </div>
  );
}
