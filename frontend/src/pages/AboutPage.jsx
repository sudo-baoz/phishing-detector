/**
 * About page – Hero + Mission + Contact.
 * Dark Mode Only - No Light Mode
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

const cardClass = 'rounded-xl border border-white/10 bg-gray-900/60 hover:border-blue-500/50 transition-colors';

export default function AboutPage({ language = 'en' }) {
  const t = getTranslations(language).about;

  const titleClass = 'text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-emerald-400';
  const subtitleClass = 'text-cyan-400/90';
  const descClass = 'text-slate-400';
  const headingClass = 'text-slate-200';
  const iconBg = 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400';
  const linkClass = 'text-cyan-400 hover:text-cyan-300';
  const valueClass = 'text-slate-200';
  const labelClass = 'text-slate-500';
  const btnClass = 'bg-gray-800/80 border-gray-600 hover:border-cyan-500/50 text-slate-200 hover:text-cyan-400';

  return (
    <div className="min-h-screen bg-transparent">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-10 sm:py-14">
        <header className="mb-12 sm:mb-16">
          <h1 className={`text-3xl sm:text-4xl font-bold mb-3 ${titleClass}`}>
            {t.title}
          </h1>
          <p className={`${subtitleClass} text-lg sm:text-xl font-medium mb-4`}>
            {t.subtitle}
          </p>
          <p className={`${descClass} text-base sm:text-lg leading-relaxed max-w-3xl`}>
            {t.description}
          </p>
        </header>

        <section className={`rounded-xl border p-6 sm:p-8 mb-10 ${cardClass}`}>
          <h2 className={`text-xl font-bold mb-3 ${headingClass}`}>{t.mission_title}</h2>
          <p className={`${descClass} leading-relaxed`}>{t.mission_desc}</p>
        </section>

        <section>
          <h2 className={`text-xl font-bold mb-6 ${headingClass}`}>{t.contact_title}</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {CONTACT.map(({ label, value, icon: Icon, href }) => (
              <div
                key={label}
                className={`rounded-xl border p-5 ${cardClass}`}
              >
                <div className="flex items-start gap-4">
                  <div className={`p-2.5 rounded-lg border shrink-0 ${iconBg}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className={`text-xs font-medium uppercase tracking-wider mb-1 ${labelClass}`}>
                      {label}
                    </div>
                    {href ? (
                      <a
                        href={href}
                        target={href.startsWith('http') ? '_blank' : undefined}
                        rel={href.startsWith('http') ? 'noopener noreferrer' : undefined}
                        className={`break-all transition-colors ${linkClass}`}
                      >
                        {value}
                      </a>
                    ) : (
                      <span className={valueClass}>{value}</span>
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
              className={`inline-flex items-center gap-2 px-5 py-2.5 rounded-lg border transition-all ${btnClass}`}
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
