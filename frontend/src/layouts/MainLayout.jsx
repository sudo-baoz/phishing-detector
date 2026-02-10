/**
 * Fixed Header Wrapper. Background comes from body (global theme); layout is transparent/inherit.
 * Header: glassmorphism matching base (gray-950/80 dark, white/80 light).
 */
import { Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useTheme } from '../context/ThemeContext';
import SecurityNewsTicker from '../components/tools/SecurityNewsTicker';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

export default function MainLayout() {
  const { i18n } = useTranslation();
  const { theme } = useTheme();
  const language = i18n.language && String(i18n.language).toLowerCase().startsWith('vi') ? 'vi' : 'en';

  const headerBg = theme === 'dark'
    ? 'bg-gray-950/80 backdrop-blur-md border-b border-white/10'
    : 'bg-white/80 backdrop-blur-md border-b border-gray-200';

  return (
    <div className="min-h-screen flex flex-col bg-transparent">
      <header className={`fixed top-0 left-0 right-0 z-50 w-full flex flex-col ${headerBg}`}>
        <SecurityNewsTicker />
        <Navbar language={language} />
      </header>

      <main className="pt-[104px] flex-1 bg-transparent">
        <Outlet />
      </main>

      <Footer />
    </div>
  );
}
