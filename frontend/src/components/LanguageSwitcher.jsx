/**
 * Language switcher. In embedded mode: trigger is in layout flow (relative);
 * dropdown is absolute and floats above content (z-50).
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Globe } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function LanguageSwitcher(props = {}) {
  const { i18n } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);

  const languages = [
    { code: 'en', label: 'English', flag: '🇺🇸' },
    { code: 'vi', label: 'Tiếng Việt', flag: '🇻🇳' },
  ];

  const currentLanguage = languages.find((lang) => lang.code === i18n.language) || languages[0];
  const isEmbedded = !!props.embedded;
  const theme = props.theme || 'dark';
  const isDark = theme === 'dark';

  const changeLanguage = (lng) => {
    i18n.changeLanguage(lng);
    setIsOpen(false);
  };

  // Trigger: static/relative, takes physical space in flex (no min-h that breaks h-16)
  const triggerClass = isEmbedded
    ? isDark
      ? 'flex items-center gap-1.5 px-2.5 py-2 rounded-lg border border-cyan-500/30 hover:border-cyan-500/60 hover:bg-white/10 text-gray-200 h-10'
      : 'flex items-center gap-1.5 px-2.5 py-2 rounded-lg border border-gray-300 hover:border-blue-400 hover:bg-gray-100 text-gray-700 h-10'
    : 'flex items-center gap-2 px-3 py-2 rounded-lg border border-cyan-500/30 hover:bg-gray-800/90 text-gray-200';

  const iconClass = isDark ? 'text-cyan-400' : 'text-blue-600';
  const codeClass = isDark ? 'text-cyan-400 text-xs font-semibold' : 'text-blue-600 text-xs font-semibold';

  // Dropdown: absolute, z-50 (floats over content)
  const dropdownClass = isDark
    ? 'absolute top-full right-0 mt-2 w-48 z-50 bg-gray-900 border border-white/10 rounded-lg shadow-xl overflow-hidden'
    : 'absolute top-full right-0 mt-2 w-48 z-50 bg-white border border-gray-200 rounded-lg shadow-xl overflow-hidden';

  const itemClass = isDark
    ? 'w-full px-4 py-3 flex items-center gap-3 hover:bg-white/10 text-gray-200'
    : 'w-full px-4 py-3 flex items-center gap-3 hover:bg-gray-100 text-gray-700';

  if (!isEmbedded) {
    return (
      <div className="fixed top-3 right-3 sm:top-6 sm:right-6 z-40 hidden sm:flex items-center">
        <button type="button" onClick={() => setIsOpen(!isOpen)} className={triggerClass}>
          <Globe className={`w-4 h-4 ${iconClass}`} />
          <span className={codeClass}>{currentLanguage.code.toUpperCase()}</span>
        </button>
        <AnimatePresence>
          {isOpen && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className={dropdownClass}
            >
              {languages.map((lang) => (
                <button
                  key={lang.code}
                  type="button"
                  onClick={() => changeLanguage(lang.code)}
                  className={`${itemClass} ${i18n.language === lang.code ? (isDark ? 'bg-cyan-500/20' : 'bg-blue-50') : ''}`}
                >
                  <span className="text-xl">{lang.flag}</span>
                  <div className="text-left flex-1">
                    <div className="font-medium text-sm">{lang.label}</div>
                    <div className={`text-xs ${codeClass}`}>{lang.code.toUpperCase()}</div>
                  </div>
                  {i18n.language === lang.code && <div className="w-2 h-2 bg-cyan-500 rounded-full shrink-0" />}
                </button>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    );
  }

  // Embedded: wrapper is relative + inline-flex so it only takes trigger space in navbar flex
  return (
    <div className="relative inline-flex items-center shrink-0">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={triggerClass}
        aria-expanded={isOpen}
        aria-haspopup="listbox"
        aria-label="Select language"
      >
        <Globe className={`w-4 h-4 shrink-0 ${iconClass}`} />
        <span className={`shrink-0 ${codeClass}`}>{currentLanguage.code.toUpperCase()}</span>
      </button>
      <AnimatePresence>
        {isOpen && (
          <>
            <div className="fixed inset-0 z-[49]" onClick={() => setIsOpen(false)} aria-hidden />
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
              className={dropdownClass}
              role="listbox"
            >
              {languages.map((lang) => (
                <button
                  key={lang.code}
                  type="button"
                  role="option"
                  aria-selected={i18n.language === lang.code}
                  onClick={() => changeLanguage(lang.code)}
                  className={`${itemClass} ${i18n.language === lang.code ? (isDark ? 'bg-cyan-500/20' : 'bg-blue-50') : ''}`}
                >
                  <span className="text-xl shrink-0">{lang.flag}</span>
                  <div className="text-left flex-1 min-w-0">
                    <div className="font-medium text-sm truncate">{lang.label}</div>
                    <div className={`text-xs ${codeClass}`}>{lang.code.toUpperCase()}</div>
                  </div>
                  {i18n.language === lang.code && <div className="w-2 h-2 bg-cyan-500 rounded-full shrink-0" />}
                </button>
              ))}
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
