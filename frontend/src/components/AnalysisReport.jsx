/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 */

import { useState, useEffect } from 'react';
import {
  Shield, ShieldAlert, Globe, Network, Search, FileText,
  Terminal, BarChart3, AlertTriangle, CheckCircle, XCircle,
  Lock, Unlock, ExternalLink, ChevronRight, Activity, Zap,
  FileCode, Shuffle, Eye, Code, Server
} from 'lucide-react';

const AnalysisReport = ({ data, loading }) => {
  const [circumference, setCircumference] = useState(0);
  const [showJson, setShowJson] = useState(false);

  useEffect(() => {
    setCircumference(2 * Math.PI * 70);
  }, []);

  if (loading) {
    return (
      <div className="w-full max-w-7xl mx-auto p-6 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="bg-slate-900 rounded-lg border border-cyan-500/30 p-6 animate-pulse">
              <div className="h-40 bg-slate-800 rounded"></div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  const { verdict, network, forensics, content, advanced, intelligence, technical_details, rag_matches } = data;
  const score = verdict?.score || 0;
  const level = verdict?.level || 'LOW';
  const isPhishing = score >= 50;
  const riskFactors = verdict?.risk_factors || [];

  const getRiskColor = () => {
    if (level === 'CRITICAL') return 'text-red-500 border-red-500';
    if (level === 'HIGH') return 'text-orange-500 border-orange-500';
    if (level === 'MEDIUM') return 'text-yellow-500 border-yellow-500';
    return 'text-green-500 border-green-500';
  };

  const getRiskBg = () => {
    if (level === 'CRITICAL') return 'bg-red-500/10';
    if (level === 'HIGH') return 'bg-orange-500/10';
    if (level === 'MEDIUM') return 'bg-yellow-500/10';
    return 'bg-green-500/10';
  };

  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="w-full max-w-7xl mx-auto p-3 sm:p-4 md:p-6 space-y-4 sm:space-y-6 font-mono relative">

      {/* JSON Toggle Button */}
      <div className="absolute top-0 right-6 z-10">
        <button
          onClick={() => setShowJson(!showJson)}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-slate-400 text-xs hover:text-cyan-400 hover:border-cyan-400 transition-colors"
        >
          <Code className="w-4 h-4" />
          {showJson ? 'Hide Raw Data' : 'View Raw Data'}
        </button>
      </div>

      {/* JSON Viewer Modal */}
      {showJson && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-cyan-500/30 rounded-lg w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl">
            <div className="p-4 border-b border-white/10 flex justify-between items-center bg-slate-950">
              <h3 className="text-cyan-400 font-bold flex items-center gap-2">
                <Terminal className="w-4 h-4" /> Raw JSON Response
              </h3>
              <button
                onClick={() => setShowJson(false)}
                className="text-slate-400 hover:text-white"
              >
                <XCircle className="w-6 h-6" />
              </button>
            </div>
            <div className="p-4 overflow-auto font-mono text-xs text-green-400 bg-black">
              <pre>{JSON.stringify(data, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}

      {/* Section 1: THE VERDICT - Hero Section */}
      <div className={`bg-slate-900 rounded-lg border-2 ${getRiskColor()} p-4 sm:p-6 md:p-8 shadow-2xl ${getRiskBg()} transition-all duration-500`}>
        <div className="flex flex-col lg:flex-row items-center justify-between mb-6 gap-6">
          <div className="flex items-center gap-6">
            {isPhishing ? (
              <ShieldAlert className="w-16 h-16 md:w-20 md:h-20 text-red-500 animate-pulse" />
            ) : (
              <Shield className="w-16 h-16 md:w-20 md:h-20 text-green-500 drop-shadow-[0_0_15px_rgba(34,197,94,0.5)]" />
            )}
            <div>
              <h2 className={`text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-extrabold tracking-tight drop-shadow-md ${isPhishing ? 'text-red-500' : 'text-green-500'}`}>
                {isPhishing ? 'THREAT DETECTED' : 'SAFE SITE'}
              </h2>
              <div className="flex flex-wrap items-center gap-3 mt-2">
                <span className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-widest border ${getRiskColor()} bg-opacity-20`}>
                  {level} RISK
                </span>
                {verdict?.threat_type && (
                  <span className="text-slate-400 text-sm font-semibold uppercase">
                    TYPE: <span className="text-white">{verdict.threat_type.replace(/_/g, ' ')}</span>
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Score Gauge */}
          <div className="relative w-32 h-32 md:w-40 md:h-40 shrink-0">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 192 192">
              <circle cx="96" cy="96" r="70" stroke="currentColor" strokeWidth="12" fill="none" className="text-slate-800" />
              <circle cx="96" cy="96" r="70" stroke="currentColor" strokeWidth="12" fill="none"
                strokeDasharray={circumference} strokeDashoffset={strokeDashoffset}
                className={`${getRiskColor()} transition-all duration-1000 ease-out`} strokeLinecap="round" />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={`text-4xl font-bold ${getRiskColor()}`}>{score}</span>
              <span className="text-[10px] text-slate-500 uppercase tracking-widest">SCORE</span>
            </div>
          </div>
        </div>

        {/* AI Conclusion Narrative */}
        {verdict?.ai_conclusion && (
          <div className="mb-6 p-4 rounded-lg bg-orange-500/5 border border-orange-500/20">
            <div className="flex items-start gap-3">
              <Zap className="w-5 h-5 text-orange-400 shrink-0 mt-1" />
              <p className="text-slate-300 text-sm md:text-base leading-relaxed">
                <span className="text-orange-400 font-bold mb-1 block uppercase text-xs">AI Analysis Conclusion</span>
                {verdict.ai_conclusion}
              </p>
            </div>
          </div>
        )}

        {/* SECTION C: RISK FACTORS */}
        {riskFactors.length > 0 && (
          <div className="bg-slate-950/50 rounded-lg p-4 border border-red-500/20">
            <h3 className="text-red-400 text-xs font-bold uppercase tracking-widest mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" /> Risk Factors Identified
            </h3>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {riskFactors.map((factor, idx) => (
                <li key={idx} className="flex items-start gap-2 text-sm text-slate-300">
                  <AlertTriangle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
                  <span>{factor.replace('⚠️ ', '')}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* SECTION A: THREAT INTELLIGENCE (RAG) */}
      {rag_matches && rag_matches.length > 0 && (
        <div className="bg-slate-900 rounded-lg border border-red-500 shadow-lg shadow-red-900/20 overflow-hidden relative">
          <div className="absolute top-0 right-0 p-2 opacity-10">
            <Activity className="w-24 h-24 text-red-500" />
          </div>
          <div className="p-4 sm:p-6 pb-2 border-b border-red-500/30 flex items-center gap-3">
            <ShieldAlert className="w-6 h-6 text-red-500" />
            <h3 className="text-lg font-bold text-red-500 uppercase tracking-wider">Known Threat Pattern Detected</h3>
          </div>
          <div className="p-4 sm:p-6 grid gap-4">
            {rag_matches.map((match, i) => (
              <div key={i} className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-red-500/5 p-4 rounded border border-red-500/20">
                <div>
                  <span className="text-xs text-red-400 uppercase font-bold block mb-1">Targeting</span>
                  <span className="text-xl text-white font-bold">{match.target || 'Unknown'} users</span>
                </div>
                <div>
                  <span className="text-xs text-red-400 uppercase font-bold block mb-1">Similarity Match</span>
                  <div className="flex items-center gap-2">
                    <div className="w-32 h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div className="h-full bg-red-500" style={{ width: `${(match.similarity_score || 0) * 100}%` }}></div>
                    </div>
                    <span className="text-xl text-white font-bold">{((match.similarity_score || 0) * 100).toFixed(0)}%</span>
                  </div>
                </div>
                <div className="md:text-right">
                  <span className="text-xs text-red-400 uppercase font-bold block mb-1">Technique</span>
                  <span className="text-slate-300 text-sm font-mono">{match.similar_url ? 'URL Pattern Match' : 'Content Signature'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SECTION B: TECHNICAL FORENSICS (DEEP TECH) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SSL Age Card */}
        <div className={`bg-slate-900 p-4 rounded-lg border ${(technical_details?.ssl_age_hours || 0) < 24 ? 'border-red-500 shadow-[0_0_10px_rgba(239,68,68,0.2)] animate-pulse' :
            (technical_details?.ssl_age_hours || 0) > 8760 ? 'border-green-500/50' : 'border-slate-700'
          }`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-xs uppercase font-bold">SSL Certificate Age</span>
            <Lock className={`w-4 h-4 ${(technical_details?.ssl_age_hours || 0) < 24 ? 'text-red-500' :
                (technical_details?.ssl_age_hours || 0) > 8760 ? 'text-green-500' : 'text-slate-400'
              }`} />
          </div>
          <div className="flex items-baseline gap-1">
            <span className={`text-2xl font-bold ${(technical_details?.ssl_age_hours || 0) < 24 ? 'text-red-500' :
                (technical_details?.ssl_age_hours || 0) > 8760 ? 'text-green-500' : 'text-white'
              }`}>
              {technical_details?.ssl_age_hours?.toFixed(1) || 'N/A'}
            </span>
            <span className="text-xs text-slate-500">hours</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 truncate">
            Issuer: {technical_details?.ssl_issuer || 'Unknown'}
          </div>
        </div>

        {/* Code Entropy Card */}
        <div
          className="bg-slate-900 p-4 rounded-lg border border-purple-500/30 group relative"
          title="High entropy (> 5.5) indicates that the code has been obfuscated to bypass antivirus."
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-xs uppercase font-bold">Code Entropy</span>
            <FileCode className="w-4 h-4 text-purple-500" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-2xl font-bold ${(technical_details?.entropy_score || 0) > 5.5 ? 'text-purple-400' : 'text-white'}`}>
              {technical_details?.entropy_score?.toFixed(2) || '0.00'}
            </span>
            {(technical_details?.entropy_score || 0) > 5.5 && (
              <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 text-[10px] uppercase font-bold border border-purple-500/30">
                Obfuscated
              </span>
            )}
          </div>
          <div className="mt-2 text-xs text-slate-500">
            Shannon Entropy Analysis
          </div>
        </div>

        {/* Redirects Card */}
        <div className="bg-slate-900 p-4 rounded-lg border border-yellow-500/30">
          <div className="flex items-center justify-between mb-2">
            <span className="text-slate-400 text-xs uppercase font-bold">Redirect Chain</span>
            <Shuffle className="w-4 h-4 text-yellow-500" />
          </div>
          <div className="flex items-baseline gap-1">
            <span className="text-2xl font-bold text-white">
              {technical_details?.redirect_chain ? technical_details.redirect_chain.length : 0}
            </span>
            <span className="text-xs text-slate-500">hops</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 flex -space-x-1">
            {technical_details?.redirect_chain?.slice(0, 3).map((_, i) => (
              <div key={i} className="w-4 h-4 rounded-full bg-slate-700 border border-slate-900 flex items-center justify-center text-[8px] text-white">
                {i + 1}
              </div>
            ))}
            {technical_details?.redirect_chain?.length > 3 && (
              <div className="w-4 h-4 rounded-full bg-slate-700 border border-slate-900 flex items-center justify-center text-[8px] text-white">+</div>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
        {/* Network Infrastructure (Simplified) */}
        <div className="bg-slate-900 rounded-lg border border-cyan-500/30 p-4 sm:p-6 shadow-xl">
          <div className="flex items-center gap-2 mb-4 border-b border-cyan-500/20 pb-2">
            <Network className="w-5 h-5 text-cyan-400" />
            <h3 className="text-cyan-400 font-bold uppercase tracking-wider text-sm">Network Data</h3>
          </div>
          <div className="space-y-3 font-mono text-sm">
            <div className="flex justify-between">
              <span className="text-slate-400">IP Address</span>
              <span className="text-cyan-400">{network?.ip || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Location</span>
              <span className="text-white">{network?.country || 'Unknown'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Registrar</span>
              <span className="text-white truncate">{network?.registrar || 'N/A'}</span>
            </div>
          </div>
        </div>

        {/* Content & Forensics (Combined/Simplified) */}
        <div className="bg-slate-900 rounded-lg border border-blue-500/30 p-4 sm:p-6 shadow-xl">
          <div className="flex items-center gap-2 mb-4 border-b border-blue-500/20 pb-2">
            <FileText className="w-5 h-5 text-blue-400" />
            <h3 className="text-blue-400 font-bold uppercase tracking-wider text-sm">Content Forensics</h3>
          </div>

          <div className="space-y-4">
            {/* Screenshot Thumb */}
            {content?.screenshot_url ? (
              <div className="w-full h-32 bg-slate-800 rounded overflow-hidden relative group">
                <img src={content.screenshot_url} className="w-full h-full object-cover opacity-70 group-hover:opacity-100 transition-opacity" />
              </div>
            ) : (
              <div className="w-full h-20 bg-slate-800/50 rounded flex items-center justify-center text-xs text-slate-500">
                Screenshot Unavailable
              </div>
            )}

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className={`p-2 rounded border text-center ${content?.has_login_form ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-green-500/10 border-green-500/30 text-green-400'}`}>
                {content?.has_login_form ? 'Login Form Detected' : 'No Login Form'}
              </div>
              <div className={`p-2 rounded border text-center ${advanced?.telegram_bot_detected ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-slate-800 border-slate-700 text-slate-400'}`}>
                {advanced?.telegram_bot_detected ? 'Telegram API' : 'No Bot API'}
              </div>
            </div>
          </div>
        </div>
      </div>

    </div>
  );
};

export default AnalysisReport;
