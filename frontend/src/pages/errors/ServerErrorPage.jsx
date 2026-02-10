/**
 * 500 – System Malfunction / Mainframe Breach. Amber theme. Reload + Go Home.
 */
import { ServerCrash } from 'lucide-react';
import { Home, RefreshCw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import ErrorCard from '../../components/ErrorCard';
import { useTheme } from '../../context/ThemeContext';

export default function ServerErrorPage() {
  const navigate = useNavigate();
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const btnBase = 'inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium transition-all';
  const reloadClass = isDark
    ? 'bg-amber-500/20 border border-amber-500/50 text-amber-400 hover:bg-amber-500/30'
    : 'bg-amber-500/10 border border-amber-500/40 text-amber-600 hover:bg-amber-500/20';
  const homeClass = isDark
    ? 'bg-cyan-500/20 border border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/30'
    : 'bg-cyan-500/10 border border-cyan-500/40 text-cyan-600 hover:bg-cyan-500/20';

  const action = (
    <>
      <button
        type="button"
        onClick={() => window.location.reload()}
        className={`${btnBase} ${reloadClass}`}
      >
        <RefreshCw className="w-4 h-4" />
        Reload System
      </button>
      <button
        type="button"
        onClick={() => navigate('/')}
        className={`${btnBase} ${homeClass}`}
      >
        <Home className="w-4 h-4" />
        Go Home
      </button>
    </>
  );

  return (
    <div className="min-h-[60vh] flex items-center justify-center px-4 py-12">
      <ErrorCard
        code="500"
        title="System Malfunction"
        description="Our servers are experiencing a critical anomaly. We are deploying a fix."
        icon={ServerCrash}
        accentClass="text-amber-400"
        action={action}
      />
    </div>
  );
}
