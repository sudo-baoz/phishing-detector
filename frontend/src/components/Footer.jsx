/**
 * Seamless footer: transparent, subtle border, muted text. Blends with body background.
 */
import { useTheme } from '../context/ThemeContext';
import VersionBadge from './VersionBadge';

export default function Footer() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const borderClass = isDark ? 'border-t border-white/5' : 'border-t border-gray-200/50';

  return (
    <footer
      className={`py-4 text-center text-xs bg-transparent text-gray-500 ${borderClass}`}
    >
      <VersionBadge />
    </footer>
  );
}
