/**
 * Seamless footer: spacing only (no dividers). Version from build-time env.
 */
import VersionBadge from './VersionBadge';

export default function Footer() {
  return (
    <footer className="mt-16 pt-8 pb-4 text-center text-xs bg-transparent text-gray-500">
      <VersionBadge />
    </footer>
  );
}
