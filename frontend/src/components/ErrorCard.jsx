/**
 * Reusable error card: glassmorphism, icon, code, title, description, optional action.
 * Dark Mode Only - No Light Mode
 */
import { useNavigate } from 'react-router-dom';
import { Home } from 'lucide-react';

export default function ErrorCard({
  code,
  title,
  description,
  icon: Icon,
  accentClass = 'text-cyan-400',
  action,
}) {
  const navigate = useNavigate();

  const cardBg = 'bg-white/5 backdrop-blur-md';
  const borderGlow = 'border border-white/10 shadow-[0_0_24px_rgba(34,211,238,0.08)]';
  const titleClass = 'text-slate-100';
  const descClass = 'text-slate-400';

  const defaultAction = (
    <button
      type="button"
      onClick={() => navigate('/')}
      className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium transition-all bg-cyan-500/20 border border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/30"
    >
      <Home className="w-4 h-4" />
      Go Home
    </button>
  );

  return (
    <div className={`max-w-lg mx-auto rounded-2xl p-8 sm:p-10 ${cardBg} ${borderGlow}`}>
      <div className="flex flex-col items-center text-center">
        <div className={`mb-4 p-4 rounded-2xl ${accentClass}`}>
          {Icon && <Icon className="w-16 h-16 sm:w-20 sm:h-20" strokeWidth={1.5} />}
        </div>
        <span className="text-4xl sm:text-5xl font-bold font-mono mb-2 text-cyan-400">{code}</span>
        <h1 className={`text-xl sm:text-2xl font-bold mb-3 ${titleClass}`}>{title}</h1>
        <p className={`text-sm sm:text-base mb-6 ${descClass}`}>{description}</p>
        <div className="flex flex-wrap items-center justify-center gap-3">
          {action ?? defaultAction}
        </div>
      </div>
    </div>
  );
}
