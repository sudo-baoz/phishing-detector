/**
 * Phishing Detector - Ethics & Compliance Modal (Trust Center)
 * Copyright (c) 2026 BaoZ
 *
 * Reassures users and authorities: legal, ethical, no unauthorized crawling,
 * privacy-first, passive analysis only. Dark mode, glassmorphism, lucide-react.
 */

import { useState } from 'react';
import { Shield, Server, EyeOff, ShieldAlert } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const POLICY_CARDS = [
  {
    icon: Server,
    iconColor: 'text-blue-400',
    iconBg: 'bg-blue-500/10 border-blue-500/30',
    title: 'No Unauthorized Crawling',
    text: 'We strictly adhere to robots.txt protocols. This tool performs On-Demand Analysis only. We do not engage in mass scanning or unauthorized data scraping of legitimate websites.',
  },
  {
    icon: EyeOff,
    iconColor: 'text-purple-400',
    iconBg: 'bg-purple-500/10 border-purple-500/30',
    title: 'Anonymous & Ephemeral',
    text: 'We prioritize privacy. We employ Anonymous Logging. Personal Identifiable Information (PII) like emails, passwords, or body content is NEVER stored. Data is ephemeral and used solely for session analysis.',
  },
  {
    icon: ShieldAlert,
    iconColor: 'text-amber-400',
    iconBg: 'bg-amber-500/10 border-amber-500/30',
    title: 'Passive Analysis Only',
    text: 'This is a defensive security tool. We generally DO NOT host, distribute, or share malicious source code (Phishing Kits). Detected threats are reported as metadata/hashes only to aid the security community.',
  },
];

const EthicsModal = ({ open: controlledOpen, onClose, hideTrigger = false }) => {
  const [internalOpen, setInternalOpen] = useState(false);
  const isControlled = controlledOpen !== undefined && controlledOpen !== null;
  const open = isControlled ? controlledOpen : internalOpen;
  const handleClose = () => (isControlled ? onClose?.() : setInternalOpen(false));
  const handleOpen = () => { if (!isControlled) setInternalOpen(true); };

  return (
    <>
      {/* Trigger: pill-shaped button for footer (hidden when hideTrigger) */}
      {!hideTrigger && (
        <button
          type="button"
          onClick={handleOpen}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium text-slate-400 hover:text-cyan-400 border border-slate-700 hover:border-cyan-500/50 bg-slate-900/50 backdrop-blur-sm transition-all duration-200"
        >
          <Shield className="w-4 h-4" />
          🛡️ Ethics & Safety Policy
        </button>
      )}

      <AnimatePresence>
        {open && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="fixed inset-0 z-[60] bg-black/80 backdrop-blur-sm"
              onClick={handleClose}
              aria-hidden="true"
            />
            {/* Modal - z-[60] so above navbar z-50 */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.25, ease: [0.25, 0.46, 0.45, 0.94] }}
              className="fixed inset-0 z-[60] flex items-center justify-center p-4 pointer-events-none"
            >
              <div
                className="w-full max-w-4xl max-h-[90vh] overflow-y-auto pointer-events-auto bg-gray-950 border border-gray-800 rounded-2xl shadow-2xl shadow-black/50"
                onClick={(e) => e.stopPropagation()}
              >
                {/* Header */}
                <div className="sticky top-0 z-10 flex items-center justify-between p-5 sm:p-6 border-b border-gray-800 bg-gray-950/95 backdrop-blur-md">
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <Shield className="w-6 h-6 text-cyan-400" />
                    Ethics & Safety Policy
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

                {/* Grid of 3 Policy Cards */}
                <div className="p-5 sm:p-6 grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6">
                  {POLICY_CARDS.map((card, i) => {
                    const Icon = card.icon;
                    return (
                      <motion.div
                        key={card.title}
                        initial={{ opacity: 0, y: 12 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.05 * i, duration: 0.3 }}
                        className="rounded-xl border border-gray-800 bg-gray-900/80 backdrop-blur-sm p-5 flex flex-col"
                      >
                        <div
                          className={`inline-flex w-12 h-12 items-center justify-center rounded-xl border ${card.iconBg} mb-4`}
                        >
                          <Icon className={`w-6 h-6 ${card.iconColor}`} />
                        </div>
                        <h3 className="text-lg font-semibold text-white mb-2">
                          {card.title}
                        </h3>
                        <p className="text-slate-400 text-sm leading-relaxed flex-1">
                          {card.text}
                        </p>
                      </motion.div>
                    );
                  })}
                </div>

                {/* Dismiss / Acknowledge */}
                <div className="p-5 sm:p-6 pt-0 flex justify-end border-t border-gray-800/80">
                  <button
                    type="button"
                    onClick={handleClose}
                    className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium transition-colors"
                  >
                    Acknowledge
                  </button>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
};

export default EthicsModal;
