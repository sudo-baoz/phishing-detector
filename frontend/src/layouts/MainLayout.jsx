/**
 * Main layout: min-h-screen flex flex-col. No divide-y, border-t, or border-b.
 * Content uses w-full; pages may use max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 where needed.
 */
import { Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useTheme } from '../context/ThemeContext';
import AmbientBackground from '../components/ui/AmbientBackground';
import SecurityNewsTicker from '../components/tools/SecurityNewsTicker';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

export default function MainLayout() {
  const { i18n } = useTranslation();
  const { theme } = useTheme();
  const language = i18n.language && String(i18n.language).toLowerCase().startsWith('vi') ? 'vi' : 'en';

  const headerBg =
    theme === 'dark'
      ? 'bg-gray-950/70 backdrop-blur-xl'
      : 'bg-white/60 backdrop-blur-xl';

  return (
    <div className="min-h-screen flex flex-col bg-transparent w-full">
      <AmbientBackground />
      <header className={`fixed top-0 left-0 right-0 z-50 w-full flex flex-col ${headerBg}`}>
        <SecurityNewsTicker />
        <Navbar language={language} />
      </header>

      <main className="pt-[104px] flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 bg-transparent">
        <Outlet />
      </main>

      <Footer />
    </div>
  );
}
