/**
 * Security Toolbox – Centered 2x2 grid of tool cards.
 */
import BreachChecker from '../components/tools/BreachChecker';
import LinkExpander from '../components/tools/LinkExpander';
import PasswordGenerator from '../components/tools/PasswordGenerator';
import { Shield, Link2, KeyRound } from 'lucide-react';
import { getTranslations } from '../constants/translations';
import { useTheme } from '../context/ThemeContext';

const TOOL_KEYS = [
  { id: 'breach', icon: Shield, titleKey: 'breach_title', descKey: 'breach_desc', Component: BreachChecker },
  { id: 'unshorten', icon: Link2, titleKey: 'unshorten_title', descKey: 'unshorten_desc', Component: LinkExpander },
  { id: 'password', icon: KeyRound, titleKey: 'pass_title', descKey: 'pass_desc', Component: PasswordGenerator },
];

const cardClassDark = 'rounded-xl border border-white/10 bg-gray-900/60 hover:border-blue-500/50 transition-colors';
const cardClassLight = 'rounded-xl border border-gray-200 bg-white shadow-sm hover:border-blue-400 transition-colors';

function FeatureCard({ icon: Icon, title, description, children, isDark }) {
  const cardClass = isDark ? cardClassDark : cardClassLight;
  const titleColor = isDark ? 'text-slate-200' : 'text-gray-900';
  const descColor = isDark ? 'text-slate-400' : 'text-gray-600';
  const borderColor = isDark ? 'border-gray-800' : 'border-gray-100';
  const iconBg = isDark ? 'bg-blue-500/10 border-blue-500/30 text-blue-400' : 'bg-blue-500/10 border-blue-400/30 text-blue-600';

  return (
    <article className={`${cardClass} p-6 h-full flex flex-col`}>
      <header className="mb-5">
        <div className="flex items-center gap-3 mb-2">
          <div className={`p-2 rounded-lg border ${iconBg}`}>
            <Icon className="w-5 h-5" />
          </div>
          <h2 className={`text-lg font-bold ${titleColor}`}>{title}</h2>
        </div>
        <p className={`${descColor} text-sm leading-relaxed pl-11`}>{description}</p>
      </header>
      <div className={`pt-2 border-t ${borderColor} flex-1 min-h-0`}>{children}</div>
    </article>
  );
}

export default function ToolsPage({ language = 'en' }) {
  const { theme } = useTheme();
  const isDark = theme === 'dark';
  const t = getTranslations(language).tools;
  const pageTitle = isDark ? 'text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-emerald-400' : 'text-gray-900';
  const subtitle = isDark ? 'text-slate-400' : 'text-gray-600';

  return (
    <div className="min-h-screen bg-transparent">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 py-8 sm:py-10">
        <header className="mb-8 sm:mb-10 text-center">
          <h1 className={`text-3xl sm:text-4xl font-bold mb-2 ${pageTitle}`}>
            {t.title}
          </h1>
          <p className={`${subtitle} text-base sm:text-lg`}>{t.subtitle}</p>
        </header>

        <section className="grid grid-cols-1 md:grid-cols-2 gap-6 justify-center">
          {TOOL_KEYS.map(({ id, icon, titleKey, descKey, Component }) => (
            <FeatureCard
              key={id}
              icon={icon}
              title={t[titleKey]}
              description={t[descKey]}
              isDark={isDark}
            >
              <Component />
            </FeatureCard>
          ))}
        </section>
      </div>
    </div>
  );
}
