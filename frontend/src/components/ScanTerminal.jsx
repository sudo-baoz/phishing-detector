/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 *
 * Live Terminal – Displays real-time log lines (from NDJSON stream or fallback).
 * Accepts `logs` prop (array of strings); auto-scrolls to bottom when new logs arrive.
 */

import { useEffect, useRef } from 'react';

const ScanTerminal = ({ logs = [] }) => {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="w-full max-w-2xl mx-auto rounded-lg border-2 border-green-500/50 bg-black shadow-[0_0_20px_rgba(0,255,0,0.15)] overflow-hidden font-mono">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-green-500/30 bg-slate-900/80">
        <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
        <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
        <span className="w-2.5 h-2.5 rounded-full bg-green-500" />
        <span className="text-green-500/80 text-xs ml-2">scan_session</span>
      </div>
      <div className="p-4 min-h-[180px] max-h-[320px] overflow-y-auto text-green-400 text-sm sm:text-base" style={{ color: '#00ff00' }}>
        {logs.length === 0 && (
          <span className="animate-pulse">Connecting...</span>
        )}
        {logs.map((line, i) => (
          <div key={i} className="animate-fadeIn">
            <span className="text-green-500/70 select-none">{'> '}</span>
            {line}
          </div>
        ))}
        <span ref={bottomRef} className="inline-block w-2 h-4 ml-0.5 bg-green-400 animate-blink" aria-hidden="true" />
      </div>
    </div>
  );
};

export default ScanTerminal;
