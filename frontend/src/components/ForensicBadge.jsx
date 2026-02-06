/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 *
 * Forensic Evidence Card – Shows Phishing Kit detection (Kit Detector module).
 * Only renders when apiData.phishing_kit.detected === true.
 * Yellow/black diagonal stripe border, fingerprint icon, kit name and details.
 */

import { Fingerprint } from 'lucide-react';

const ForensicBadge = ({ kit }) => {
  if (!kit || kit.detected !== true) return null;

  const kitName = kit.kit_name || 'Unknown Kit';
  const confidence = kit.confidence || 'N/A';
  const matched = kit.matched_signatures || [];

  return (
    <div
      className="relative rounded-lg p-4 sm:p-5 bg-slate-900/95 overflow-hidden"
      style={{
        border: '3px solid transparent',
        backgroundImage: `
          linear-gradient(white, white),
          repeating-linear-gradient(
            -45deg,
            #eab308 0,
            #eab308 8px,
            #0a0a0a 8px,
            #0a0a0a 16px
          )
        `,
        backgroundOrigin: 'border-box',
        backgroundClip: 'padding-box, border-box',
      }}
    >
      <div className="flex items-start gap-4">
        <div className="p-2.5 rounded-lg bg-amber-500/20 border border-amber-500/40 shrink-0">
          <Fingerprint className="w-8 h-8 text-amber-400" aria-hidden="true" />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-amber-400 font-black text-sm sm:text-base uppercase tracking-wider flex items-center gap-2">
            ⚠️ Phishing Kit Detected
          </h3>
          <p className="mt-1 text-white font-semibold text-lg sm:text-xl">
            {kitName}
          </p>
          <p className="mt-2 text-slate-400 text-sm">
            Signature matched in HTML source code. Confidence: <span className="text-amber-400 font-medium">{confidence}</span>
          </p>
          {matched.length > 0 && (
            <p className="mt-2 text-slate-500 text-xs font-mono">
              Matched: {matched.slice(0, 5).join(', ')}
              {matched.length > 5 ? ` +${matched.length - 5} more` : ''}
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

export default ForensicBadge;
