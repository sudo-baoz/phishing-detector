/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

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
        <div className="fixed top-3 right-3 sm:top-6 sm:right-6 z-40">
            <motion.button
                onClick={() => setIsOpen(!isOpen)}
                className="flex items-center gap-1.5 sm:gap-2 px-3 py-2 sm:px-4 
          bg-gray-900/80 backdrop-blur-md
          border border-cyan-500/30 rounded-lg
          hover:border-cyan-500/60 hover:bg-gray-800/90
          transition-all duration-300
          shadow-lg shadow-cyan-500/20
          min-h-[44px]"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
            >
                <Globe className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />
                <span className="text-white font-medium">{currentLanguage.flag}</span>
                <span className="text-cyan-400 text-xs sm:text-sm font-semibold">
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
