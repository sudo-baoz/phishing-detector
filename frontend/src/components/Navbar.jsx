/**
 * Modern Glassmorphism Navbar – i18n via translations[language].
 * Left (Logo), Center (Links), Right (Lang + GitHub + Ethics).
 */

import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Wrench, Menu, X, Github, Scale } from 'lucide-react';
import LanguageSwitcher from './LanguageSwitcher';
import EthicsModal from './EthicsModal';
import { getTranslations } from '../constants/translations';

const GITHUB_URL = import.meta.env.VITE_GITHUB_REPO || 'https://github.com';

export default function Navbar({ language = 'en' }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [ethicsOpen, setEthicsOpen] = useState(false);
  const t = getTranslations(language).nav;

  const linkClass = ({ isActive }) =>
    `flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all ${
      isActive
        ? 'text-cyan-400 bg-white/10 shadow-[0_0_12px_rgba(34,211,238,0.2)]'
        : 'text-slate-300 hover:text-white hover:bg-white/10'
    }`;

  const rightSection = (
    <div className="flex items-center gap-2">
      <LanguageSwitcher embedded />
      <a
        href={GITHUB_URL}
        target="_blank"
        rel="noopener noreferrer"
        className="p-2.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-all"
        aria-label="GitHub"
      >
        <Github className="w-5 h-5" />
      </a>
      <button
        type="button"
        onClick={() => setEthicsOpen(true)}
        className="flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium text-slate-300 hover:text-white hover:bg-white/10 transition-all"
      >
        <Scale className="w-4 h-4" />
        {t.ethics}
      </button>
    </div>
  );

  return (
    <>
      <nav className="sticky top-0 z-50 backdrop-blur-md bg-black/60 border-b border-white/10">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="flex items-center justify-between h-14 sm:h-16">
            <NavLink to="/" className="flex items-center gap-2 shrink-0" onClick={() => setMobileOpen(false)}>
              <span className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-emerald-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.3)]">
                CyberSentinel
              </span>
            </NavLink>

            <div className="hidden md:flex items-center gap-1 absolute left-1/2 -translate-x-1/2">
              <NavLink to="/" end className={linkClass}>
                <Shield className="w-4 h-4" />
                {t.home}
              </NavLink>
              <NavLink to="/tools" className={linkClass}>
                <Wrench className="w-4 h-4" />
                {t.tools}
              </NavLink>
              <NavLink to="/about" className={linkClass}>
                {t.about}
              </NavLink>
            </div>

            <div className="hidden md:flex items-center gap-2 shrink-0">
              {rightSection}
            </div>

            <div className="flex md:hidden items-center gap-2">
              {rightSection}
              <button
                type="button"
                onClick={() => setMobileOpen((o) => !o)}
                className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-white/10"
                aria-label="Toggle menu"
              >
                {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>

          {mobileOpen && (
            <div className="md:hidden py-3 border-t border-white/10 flex flex-col gap-1">
              <NavLink to="/" end className={linkClass} onClick={() => setMobileOpen(false)}>
                <Shield className="w-4 h-4" />
                {t.home}
              </NavLink>
              <NavLink to="/tools" className={linkClass} onClick={() => setMobileOpen(false)}>
                <Wrench className="w-4 h-4" />
                {t.tools}
              </NavLink>
              <NavLink to="/about" className={linkClass} onClick={() => setMobileOpen(false)}>
                {t.about}
              </NavLink>
            </div>
          )}
        </div>
      </nav>

      <EthicsModal open={ethicsOpen} onClose={() => setEthicsOpen(false)} hideTrigger language={language} />
    </>
  );
}
