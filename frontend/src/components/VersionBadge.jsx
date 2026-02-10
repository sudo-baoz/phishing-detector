/**
 * Build-time version badge: Model {version} ({commit}), tooltip = Built at: {buildTime}.
 * Uses VITE_APP_VERSION, VITE_COMMIT_HASH, VITE_BUILD_TIME from generate-version.js.
 */
import { useTheme } from '../context/ThemeContext';

export default function VersionBadge() {
  const { theme } = useTheme();
  const version = import.meta.env.VITE_APP_VERSION ?? '0.0.0';
  const commit = import.meta.env.VITE_COMMIT_HASH ?? 'dev';
  const buildTime = import.meta.env.VITE_BUILD_TIME ?? '';

  const isDark = theme === 'dark';
  const badgeClass = isDark
    ? 'bg-gray-800 text-gray-400'
    : 'bg-gray-200 text-gray-600';

  return (
    <span
      className={`inline-flex items-center text-xs px-2 py-1 rounded font-mono ${badgeClass}`}
      title={buildTime ? `Built at: ${buildTime}` : undefined}
    >
      Ver: {version} ({commit})
    </span>
  );
}
