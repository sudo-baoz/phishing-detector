/**
 * Build-time version badge: Model {version} ({commit}), tooltip = Built at: {buildTime}.
 * Dark Mode Only - No Light Mode
 * Uses VITE_APP_VERSION, VITE_COMMIT_HASH, VITE_BUILD_TIME from generate-version.js.
 */

export default function VersionBadge() {
  const version = import.meta.env.VITE_APP_VERSION ?? '0.0.0';
  const commit = import.meta.env.VITE_COMMIT_HASH ?? 'dev';
  const buildTime = import.meta.env.VITE_BUILD_TIME ?? '';

  const badgeClass = 'bg-gray-800 text-gray-400';

  return (
    <span
      className={`inline-flex items-center text-xs px-2 py-1 rounded font-mono ${badgeClass}`}
      title={buildTime ? `Built at: ${buildTime}` : undefined}
    >
      Ver: {version} ({commit})
    </span>
  );
}
