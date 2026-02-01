import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Globe } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const LanguageSwitcher = () => {
    const { i18n } = useTranslation();
    const [isOpen, setIsOpen] = useState(false);

    const languages = [
        { code: 'en', label: 'English', flag: '🇺🇸' },
        { code: 'vi', label: 'Tiếng Việt', flag: '🇻🇳' }
    ];

    const currentLanguage = languages.find(lang => lang.code === i18n.language) || languages[0];

    const changeLanguage = (lng) => {
        i18n.changeLanguage(lng);
        setIsOpen(false);
    };

    return (
        <div className="fixed top-6 right-6 z-50">
            <motion.button
                onClick={() => setIsOpen(!isOpen)}
                className="flex items-center gap-2 px-4 py-2 
          bg-gray-900/80 backdrop-blur-md
          border border-cyan-500/30 rounded-lg
          hover:border-cyan-500/60 hover:bg-gray-800/90
          transition-all duration-300
          shadow-lg shadow-cyan-500/20"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
            >
                <Globe className="w-5 h-5 text-cyan-400" />
                <span className="text-white font-medium">{currentLanguage.flag}</span>
                <span className="text-cyan-400 text-sm font-semibold">
                    {currentLanguage.code.toUpperCase()}
                </span>
            </motion.button>

            <AnimatePresence>
                {isOpen && (
                    <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        transition={{ duration: 0.2 }}
                        className="absolute top-full right-0 mt-2 w-48
              bg-gray-900/95 backdrop-blur-md
              border border-cyan-500/30 rounded-lg
              shadow-xl shadow-cyan-500/20
              overflow-hidden"
                    >
                        {languages.map((language) => (
                            <button
                                key={language.code}
                                onClick={() => changeLanguage(language.code)}
                                className={`w-full px-4 py-3 flex items-center gap-3
                  hover:bg-cyan-500/10 transition-colors duration-200
                  ${i18n.language === language.code ? 'bg-cyan-500/20' : ''}
                `}
                            >
                                <span className="text-2xl">{language.flag}</span>
                                <div className="text-left flex-1">
                                    <div className="text-white font-medium">{language.label}</div>
                                    <div className="text-cyan-400 text-xs">{language.code.toUpperCase()}</div>
                                </div>
                                {i18n.language === language.code && (
                                    <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse" />
                                )}
                            </button>
                        ))}
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};

export default LanguageSwitcher;
