/**
 * About page – Hero + Mission + Contact grid. i18n via translations[language].
 * Cyberpunk/Professional glassmorphism, glowing borders.
 */

import { User, Mail, Phone, Send, Github } from 'lucide-react';
import { getTranslations } from '../constants/translations';

const CONTACT = [
  { label: 'Author', value: 'Mai Quoc Bao', icon: User, href: null },
  { label: 'Email', value: 'maibao123bao@gmail.com', icon: Mail, href: 'mailto:maibao123bao@gmail.com' },
  { label: 'Phone', value: '+84 395818082', icon: Phone, href: 'tel:+84395818082' },
  { label: 'Telegram', value: '@darius_baoz', icon: Send, href: 'https://t.me/darius_baoz' },
  { label: 'GitHub', value: 'sudo-baoz/phishing-detector', icon: Github, href: 'https://github.com/sudo-baoz/phishing-detector' },
];

export default function AboutPage({ language = 'en' }) {
  const t = getTranslations(language).about;

  return (
    <div className="min-h-screen bg-black text-slate-200">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-10 sm:py-14">
        {/* Hero */}
        <header className="mb-12 sm:mb-16">
          <h1 className="text-3xl sm:text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-emerald-400 mb-3">
            {t.title}
          </h1>
          <p className="text-cyan-400/90 text-lg sm:text-xl font-medium mb-4">
            {t.subtitle}
          </p>
          <p className="text-slate-400 text-base sm:text-lg leading-relaxed max-w-3xl">
            {t.description}
          </p>
        </header>

        {/* Mission */}
        <section className="rounded-xl border border-cyan-500/20 bg-gray-900/50 backdrop-blur-sm p-6 sm:p-8 mb-10 shadow-[0_0_24px_rgba(34,211,238,0.08)]">
          <h2 className="text-xl font-bold text-slate-200 mb-3">{t.mission_title}</h2>
          <p className="text-slate-400 leading-relaxed">{t.mission_desc}</p>
        </section>

        {/* Contact */}
        <section>
          <h2 className="text-xl font-bold text-slate-200 mb-6">{t.contact_title}</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {CONTACT.map(({ label, value, icon: Icon, href }) => (
              <div
                key={label}
                className="rounded-xl border border-gray-700/80 bg-gray-900/50 backdrop-blur-sm p-5 transition-all hover:border-cyan-500/40 hover:shadow-lg hover:shadow-cyan-500/10"
              >
                <div className="flex items-start gap-4">
                  <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
                    <Icon className="w-5 h-5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">
                      {label}
                    </div>
                    {href ? (
                      <a
                        href={href}
                        target={href.startsWith('http') ? '_blank' : undefined}
                        rel={href.startsWith('http') ? 'noopener noreferrer' : undefined}
                        className="text-cyan-400 hover:text-cyan-300 break-all transition-colors"
                      >
                        {value}
                      </a>
                    ) : (
                      <span className="text-slate-200">{value}</span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-6">
            <a
              href="https://github.com/sudo-baoz/phishing-detector"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gray-800/80 border border-gray-600 hover:border-cyan-500/50 text-slate-200 hover:text-cyan-400 transition-all"
            >
              <Github className="w-5 h-5" />
              {t.github_btn}
            </a>
          </div>
        </section>
      </div>
    </div>
  );
}
