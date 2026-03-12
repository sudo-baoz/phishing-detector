/**
 * Scan Result – Full-bleed (100vw) wrapper; outer background stays transparent.
 * Threat/Safe styling is applied only to the inner card (border, glow shadow, subtle bg).
 * Dark Mode Only - No Light Mode
 */

import AnalysisReport from './AnalysisReport';

function getCardWrapperClasses(data, loading) {
  if (loading || !data) {
    return 'rounded-xl border border-white/10';
  }
  const verdict = data.verdict || {};
  const score = verdict.score ?? 0;
  const level = verdict.level || 'LOW';
  const isUncertain = level === 'UNCERTAIN';
  const isPhishing = !isUncertain && score >= 50;

  if (isUncertain) {
    return 'rounded-xl border border-white/10';
  }
  if (isPhishing) {
    return [
      'rounded-xl border border-red-500/50',
      'bg-red-950/20',
      'shadow-[0_0_40px_-10px_rgba(239,68,68,0.4)]',
    ].join(' ');
  }
  return [
    'rounded-xl border border-emerald-500/50',
    'bg-emerald-950/30',
    'shadow-[0_0_30px_-5px_rgba(16,185,129,0.3)]',
  ].join(' ');
}

export default function ScanResult({ data, loading, ...rest }) {
  const cardClass = getCardWrapperClasses(data, loading);

  return (
    <div
      className="w-screen relative left-[50%] right-[50%] -ml-[50vw] px-4 py-6 sm:py-8 bg-transparent"
      data-scan-result-full-bleed
    >
      <div className="max-w-7xl mx-auto">
        <div className={cardClass}>
          <AnalysisReport data={data} loading={loading} {...rest} />
        </div>
      </div>
    </div>
  );
}
