/**
 * Security Toolbox – Single-column list view, i18n via translations[language].
 */

import BreachChecker from '../components/tools/BreachChecker';
import LinkExpander from '../components/tools/LinkExpander';
import PasswordGenerator from '../components/tools/PasswordGenerator';
import { Shield, Link2, KeyRound } from 'lucide-react';
import { getTranslations } from '../constants/translations';

const TOOL_KEYS = [
  { id: 'breach', icon: Shield, titleKey: 'breach_title', descKey: 'breach_desc', Component: BreachChecker },
  { id: 'unshorten', icon: Link2, titleKey: 'unshorten_title', descKey: 'unshorten_desc', Component: LinkExpander },
  { id: 'password', icon: KeyRound, titleKey: 'pass_title', descKey: 'pass_desc', Component: PasswordGenerator },
];

function FeatureCard({ icon: Icon, title, description, children }) {
  return (
    <article className="rounded-xl border border-gray-700 bg-gray-900/50 p-6">
      <header className="mb-5">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/30 text-blue-400">
            <Icon className="w-5 h-5" />
          </div>
          <h2 className="text-lg font-bold text-slate-200">{title}</h2>
        </div>
        <p className="text-slate-400 text-sm leading-relaxed pl-11">{description}</p>
      </header>
      <div className="pt-2 border-t border-gray-800">{children}</div>
    </article>
  );
}

export default function ToolsPage({ language = 'en' }) {
  const t = getTranslations(language).tools;

  return (
    <div className="min-h-screen bg-black text-slate-200">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8 sm:py-10">
        <header className="mb-8 sm:mb-10">
          <h1 className="text-3xl sm:text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-emerald-400 mb-2">
            {t.title}
          </h1>
          <p className="text-slate-400 text-base sm:text-lg">{t.subtitle}</p>
        </header>

        <section className="flex flex-col gap-6">
          {TOOL_KEYS.map(({ id, icon, titleKey, descKey, Component }) => (
            <FeatureCard
              key={id}
              icon={icon}
              title={t[titleKey]}
              description={t[descKey]}
            >
              <Component />
            </FeatureCard>
          ))}
        </section>
      </div>
    </div>
  );
}
