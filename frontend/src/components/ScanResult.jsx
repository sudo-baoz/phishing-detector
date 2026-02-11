/**
 * Scan Result – Full-bleed (100vw) layout wrapper for the report panel.
 * Background spans entire screen width; inner content stays centered (max-w-7xl).
 * Light mode: threat = bg-red-50, safe = bg-emerald-50. Dark: subtle tint.
 */

import { useTheme } from '../context/ThemeContext';
import AnalysisReport from './AnalysisReport';

function getWrapperBackground(data, loading, theme) {
  if (loading || !data) {
    return 'bg-gray-50 dark:bg-gray-950';
  }
  const verdict = data.verdict || {};
  const score = verdict.score ?? 0;
  const level = verdict.level || 'LOW';
  const isUncertain = level === 'UNCERTAIN';
  const isPhishing = !isUncertain && score >= 50;

  if (theme === 'light') {
    if (isPhishing) return 'bg-red-50';
    return 'bg-emerald-50';
  }
  if (isPhishing) return 'dark:bg-red-950/30';
  return 'dark:bg-emerald-950/20';
}

export default function ScanResult({ data, loading, ...rest }) {
  const { theme } = useTheme();
  const bgClass = getWrapperBackground(data, loading, theme);

  return (
    <div
      className={`w-screen relative left-[50%] right-[50%] -ml-[50vw] px-4 py-6 sm:py-8 ${bgClass}`}
      data-scan-result-full-bleed
    >
      <div className="max-w-7xl mx-auto">
        <AnalysisReport data={data} loading={loading} {...rest} />
      </div>
    </div>
  );
}
