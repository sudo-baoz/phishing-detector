/**
 * Fixed Header Wrapper Pattern – single master layout.
 * Ticker h-10 (40px) + Navbar h-16 (64px) = 104px. Content uses pt-[104px] so nothing slides under.
 */
import { Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useTheme } from '../context/ThemeContext';
import SecurityNewsTicker from '../components/tools/SecurityNewsTicker';
import Navbar from '../components/Navbar';
import VersionBadge from '../components/VersionBadge';

export default function MainLayout() {
  const { i18n } = useTranslation();
  const { theme } = useTheme();
  const language = i18n.language && String(i18n.language).toLowerCase().startsWith('vi') ? 'vi' : 'en';
  const isDark = theme === 'dark';

  const headerBg = isDark
    ? 'bg-black/95 backdrop-blur-md border-b border-white/10'
    : 'bg-white/95 backdrop-blur-md border-b border-gray-200';

  return (
    <div className={`min-h-screen ${isDark ? 'bg-black' : 'bg-gray-50'}`}>
      <header
        className={`fixed top-0 left-0 right-0 z-50 w-full flex flex-col ${headerBg}`}
      >
        <SecurityNewsTicker />
        <Navbar language={language} />
      </header>

      <main className="pt-[104px]">
        <Outlet />
      </main>

      <footer className={`py-4 text-center text-xs ${isDark ? 'text-slate-500' : 'text-gray-500'}`}>
        <VersionBadge />
      </footer>
    </div>
  );
}
