/**
 * Phishing Detector - Ethics & Compliance Modal (Trust Center)
 * Copyright (c) 2026 BaoZ
 *
 * Reassures users and authorities: legal, ethical, no unauthorized crawling,
 * privacy-first, passive analysis only. Supports i18n (en/vi).
 */

import { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { Shield, Server, EyeOff, ShieldAlert } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { getTranslations } from '../constants/translations';

const CARD_ICONS = [
  { icon: Server, iconColor: 'text-blue-400', iconBg: 'bg-blue-500/10 border-blue-500/30' },
  { icon: EyeOff, iconColor: 'text-purple-400', iconBg: 'bg-purple-500/10 border-purple-500/30' },
  { icon: ShieldAlert, iconColor: 'text-amber-400', iconBg: 'bg-amber-500/10 border-amber-500/30' },
];

const EthicsModal = ({ open: controlledOpen, onClose, hideTrigger = false, language: languageProp }) => {
  const { i18n } = useTranslation();
  const [internalOpen, setInternalOpen] = useState(false);
  const scrollYRef = useRef(0);
  const isControlled = controlledOpen !== undefined && controlledOpen !== null;
  const open = isControlled ? controlledOpen : internalOpen;
  const handleClose = () => {
    const currentScroll = scrollYRef.current;
    isControlled ? onClose?.() : setInternalOpen(false);
    // Restore scroll position after state update
    setTimeout(() => {
      window.scrollTo(0, currentScroll);
    }, 0);
  };
  const handleOpen = () => {
    scrollYRef.current = window.scrollY;
    if (!isControlled) setInternalOpen(true);
  };

  // Lock body scroll when modal is open
  useEffect(() => {
    if (open) {
      const originalStyle = window.getComputedStyle(document.body).overflow;
      document.body.style.overflow = 'hidden';
      return () => {
        document.body.style.overflow = originalStyle;
      };
    }
  }, [open]);

  const language =
    languageProp ?? (i18n.language && String(i18n.language).toLowerCase().startsWith('vi') ? 'vi' : 'en');
  const t = getTranslations(language).ethics;
  const cards = t.cards.map((card, i) => ({ ...card, ...CARD_ICONS[i] }));

  // Portal content
  const modalContent = (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-[65] bg-black/80 backdrop-blur-sm"
            onClick={handleClose}
            aria-hidden="true"
          />
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: -20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: -20 }}
            transition={{ duration: 0.25, ease: [0.25, 0.46, 0.45, 0.94] }}
            className="fixed inset-0 z-[70] flex items-center justify-center p-4 pointer-events-none"
            style={{ transform: 'translateZ(0)', willChange: 'opacity, transform', contain: 'layout paint' }}
          >
            <div
              className="w-full max-w-4xl max-h-[90vh] overflow-y-auto scrollbar-thin scrollbar-thumb-gray-700 scrollbar-track-transparent pointer-events-auto bg-gray-950 border border-gray-800 rounded-2xl shadow-2xl shadow-black/50"
              onClick={(e) => e.stopPropagation()}
              role="dialog"
              aria-modal="true"
            >
              <div className="sticky top-0 z-10 flex items-center justify-between p-5 sm:p-6 border-b border-gray-800 bg-gray-950/95 backdrop-blur-md">
                <h2 className="text-xl font-bold text-white flex items-center gap-2">
                  <Shield className="w-6 h-6 text-cyan-400" />
                  {t.title}
                </h2>
                <button
                  type="button"
                  onClick={handleClose}
                  className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-gray-800 transition-colors"
                  aria-label="Close"
                >
                  <span className="text-xl leading-none">×</span>
                </button>
              </div>

              <div className="p-5 sm:p-6 grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6">
                {cards.map((card, i) => {
                  const Icon = card.icon;
                  return (
                    <motion.div
                      key={card.title}
                      initial={{ opacity: 0, y: 12 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.05 * i, duration: 0.3 }}
                      className="rounded-xl border border-gray-800 bg-gray-900/80 backdrop-blur-sm p-5 flex flex-col h-full"
                    >
                      <div
                        className={`inline-flex w-12 h-12 items-center justify-center rounded-xl border ${card.iconBg} mb-4 shrink-0`}
                      >
                        <Icon className={`w-6 h-6 ${card.iconColor}`} />
                      </div>
                      <h3 className="text-lg font-semibold text-white mb-2">{card.title}</h3>
                      <p className="text-slate-400 text-sm leading-relaxed flex-1">{card.text}</p>
                    </motion.div>
                  );
                })}
              </div>

              <div className="p-5 sm:p-6 pt-0 flex justify-end border-t border-gray-800/80">
                <button
                  type="button"
                  onClick={handleClose}
                  className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition-colors"
                >
                  {t.acknowledge}
                </button>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );

  return (
    <>
      {!hideTrigger && (
        <button
          type="button"
          onClick={handleOpen}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium text-slate-400 hover:text-cyan-400 border border-slate-700 hover:border-cyan-500/50 bg-slate-900/50 backdrop-blur-sm transition-all duration-200"
        >
          <Shield className="w-4 h-4" />
          {t.trigger}
        </button>
      )}

      {typeof document !== 'undefined' && createPortal(modalContent, document.body)}
    </>
  );
};

export default EthicsModal;
