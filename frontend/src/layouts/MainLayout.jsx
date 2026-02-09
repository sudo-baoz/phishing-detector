/**
 * Fixed Header Wrapper Pattern: single master header (Ticker + Navbar), content with offset.
 * Ticker h-10 (40px) + Navbar h-16 (64px) = 104px.
 */
import { useTheme } from '../context/ThemeContext';
import SecurityNewsTicker from '../components/tools/SecurityNewsTicker';
import Navbar from '../components/Navbar';

const HEADER_OFFSET_PX = 104; // h-10 (40) + h-16 (64)

export default function MainLayout({ children, language = 'en' }) {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const headerBg = isDark
    ? 'bg-black/95 backdrop-blur-md border-b border-white/10'
    : 'bg-white/95 backdrop-blur-md border-b border-gray-200';

  return (
    <>
      <header
        className={`fixed top-0 left-0 right-0 w-full z-50 flex flex-col ${headerBg}`}
      >
        <SecurityNewsTicker />
        <Navbar language={language} />
      </header>

      <div style={{ paddingTop: HEADER_OFFSET_PX }}>
        {children}
      </div>
    </>
  );
}
