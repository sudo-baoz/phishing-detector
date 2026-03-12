/**
 * Main layout: min-h-screen flex flex-col. No divide-y, border-t, or border-b.
 * Dark Mode Only - No Light Mode
 */
import { Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import AmbientBackground from '../components/ui/AmbientBackground';
import SecurityNewsTicker from '../components/tools/SecurityNewsTicker';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';

export default function MainLayout() {
  const { i18n } = useTranslation();
  const language = i18n.language && String(i18n.language).toLowerCase().startsWith('vi') ? 'vi' : 'en';

  return (
    <div className="min-h-screen flex flex-col bg-[#0b1120] w-full">
      <AmbientBackground />
      <header className="fixed top-0 left-0 right-0 z-50 w-full flex flex-col bg-gray-950/70 backdrop-blur-xl">
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
