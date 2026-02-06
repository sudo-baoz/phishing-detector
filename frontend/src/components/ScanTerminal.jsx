/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 *
 * Live Terminal Loader – Cyberpunk-style scanning simulation.
 * Replaces the default spinner while the scan API is in progress.
 */

import { useState, useEffect } from 'react';

const LOG_LINES = [
  '[*] Initializing God Mode AI...',
  '[+] Intercepting network traffic...',
  '[!] Scanning for Z118/16Shop signatures...',
  '[+] Tracing redirect chain...',
  '[*] Analyzing SSL Certificates...',
  '[+] Checking RAG threat database...',
  '[*] Running YARA pattern match...',
  '[+] OSINT enrichment in progress...',
  '[*] Building threat graph...',
  '[.] Awaiting verdict...',
];

const ScanTerminal = () => {
  const [visibleLines, setVisibleLines] = useState([]);
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentIndex((i) => {
        if (i < LOG_LINES.length) {
          setVisibleLines((prev) => [...prev, LOG_LINES[i]]);
          return i + 1;
        }
        return i;
      });
    }, 400);

    return () => clearInterval(interval);
  }, []);

  // Cycle back to start for long scans
  useEffect(() => {
    if (currentIndex >= LOG_LINES.length) {
      const reset = setTimeout(() => {
        setVisibleLines([]);
        setCurrentIndex(0);
      }, 800);
      return () => clearTimeout(reset);
    }
  }, [currentIndex]);

  return (
    <div className="w-full max-w-2xl mx-auto rounded-lg border-2 border-green-500/50 bg-black shadow-[0_0_20px_rgba(0,255,0,0.15)] overflow-hidden font-mono">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-green-500/30 bg-slate-900/80">
        <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
        <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
        <span className="w-2.5 h-2.5 rounded-full bg-green-500" />
        <span className="text-green-500/80 text-xs ml-2">scan_session</span>
      </div>
      <div className="p-4 min-h-[180px] text-green-400 text-sm sm:text-base" style={{ color: '#00ff00' }}>
        {visibleLines.length === 0 && (
          <span className="animate-pulse">Connecting...</span>
        )}
        {visibleLines.map((line, i) => (
          <div key={i} className="animate-fadeIn">
            <span className="text-green-500/70 select-none">{'> '}</span>
            {line}
          </div>
        ))}
        <span className="inline-block w-2 h-4 ml-0.5 bg-green-400 animate-blink" aria-hidden="true" />
      </div>
    </div>
  );
};

export default ScanTerminal;
