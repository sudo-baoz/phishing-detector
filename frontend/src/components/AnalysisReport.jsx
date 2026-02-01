import { useState, useEffect } from 'react';
import { 
  Shield, ShieldAlert, Globe, Network, Search, FileText, 
  Terminal, BarChart3, AlertTriangle, CheckCircle, XCircle,
  Lock, Unlock, ExternalLink, ChevronRight, Activity, Zap
} from 'lucide-react';

const AnalysisReport = ({ data, loading }) => {
  const [circumference, setCircumference] = useState(0);

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

  const { verdict, network, forensics, content, advanced, intelligence } = data;
  const score = verdict?.score || 0;
  const level = verdict?.level || 'LOW';
  const isPhishing = score >= 50;

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
    <div className="w-full max-w-7xl mx-auto p-6 space-y-6 font-mono">
      {/* Section 1: THE VERDICT - Hero Section */}
      <div className={`bg-slate-900 rounded-lg border-2 ${getRiskColor()} p-8 shadow-2xl ${getRiskBg()}`}>
        <div className="flex flex-col lg:flex-row items-center justify-between mb-6 gap-4">
          <div className="flex items-center gap-4">
            {isPhishing ? (
              <ShieldAlert className="w-16 h-16 text-red-500 animate-pulse" />
            ) : (
              <Shield className="w-16 h-16 text-green-500 drop-shadow-[0_0_10px_rgba(34,197,94,0.5)]" />
            )}
            <div>
              <h2 className={`text-5xl font-extrabold tracking-wider drop-shadow-lg ${
                isPhishing ? 'text-red-500' : 'text-green-500'
              }`}>
                {isPhishing ? '⚠️ THREAT DETECTED' : '✓ SAFE SITE'}
              </h2>
              <p className="text-slate-400 text-sm mt-2 tracking-wide">
                {isPhishing ? 'MALICIOUS URL IDENTIFIED' : 'VERIFIED LEGITIMATE WEBSITE'}
              </p>
            </div>
          </div>
          <div className={`px-8 py-4 rounded-lg border-2 ${getRiskColor()} ${getRiskBg()}`}>
            <div className="text-center">
              <span className="text-slate-400 text-xs uppercase block mb-1">Risk Level</span>
              <span className={`text-3xl font-bold ${getRiskColor()}`}>{level}</span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-center">
          {/* Circular Progress Gauge */}
          <div className="flex justify-center lg:justify-start">
            <div className="relative w-48 h-48">
              <svg className="w-48 h-48 transform -rotate-90">
                <circle
                  cx="96"
                  cy="96"
                  r="70"
                  stroke="currentColor"
                  strokeWidth="12"
                  fill="none"
                  className="text-slate-700"
                />
                <circle
                  cx="96"
                  cy="96"
                  r="70"
                  stroke="currentColor"
                  strokeWidth="12"
                  fill="none"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  className={`${getRiskColor()} transition-all duration-1000 ease-out`}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-5xl font-bold ${getRiskColor()}`}>{score}</span>
                <span className="text-slate-400 text-sm mt-1">RISK SCORE</span>
              </div>
            </div>
          </div>

          {/* Threat Details */}
          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center gap-4">
              <span className="text-cyan-400 text-sm uppercase tracking-wider">URL:</span>
              <span className="text-white text-lg break-all">{data.url}</span>
            </div>
            
            {verdict?.target_brand && (
              <div className="flex items-center gap-4">
                <span className="text-cyan-400 text-sm uppercase tracking-wider">Target Brand:</span>
                <div className="px-4 py-2 bg-red-500/20 border border-red-500 rounded-lg">
                  <span className="text-red-400 text-xl font-bold uppercase">{verdict.target_brand}</span>
                </div>
              </div>
            )}

            {verdict?.threat_type && (
              <div className="flex items-center gap-4">
                <span className="text-cyan-400 text-sm uppercase tracking-wider">Threat Type:</span>
                <div className="px-4 py-2 bg-orange-500/20 border border-orange-500 rounded-lg flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-orange-400" />
                  <span className="text-orange-400 font-bold uppercase">{verdict.threat_type.replace('_', ' ')}</span>
                </div>
              </div>
            )}

            <div className="flex items-center gap-4 text-sm text-slate-400">
              <Activity className="w-4 h-4" />
              <span>Scanned at: {new Date(data.scanned_at).toLocaleString()}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Section 2: NETWORK INFRASTRUCTURE */}
        <div className="bg-slate-900 rounded-lg border border-cyan-500/30 p-6 shadow-xl hover:border-cyan-500/60 transition-all">
          <div className="flex items-center gap-3 mb-6 pb-3 border-b border-cyan-500/30">
            <Network className="w-6 h-6 text-cyan-400" />
            <h3 className="text-xl font-bold text-cyan-400 uppercase tracking-wider">Network Infrastructure</h3>
          </div>

          <div className="space-y-4">
            {/* Domain Age */}
            <div className="flex justify-between items-center p-3 bg-slate-800/50 rounded-lg border border-slate-700">
              <span className="text-slate-400 uppercase text-sm">Domain Age</span>
              <span className={`font-bold text-lg ${
                network?.domain_age && network.domain_age.includes('day') && parseInt(network.domain_age) < 7
                  ? 'text-red-500 animate-pulse'
                  : 'text-green-400'
              }`}>
                {network?.domain_age || 'Unknown'}
              </span>
            </div>

            {/* Registrar */}
            <div className="flex justify-between items-center p-3 bg-slate-800/50 rounded-lg border border-slate-700">
              <span className="text-slate-400 uppercase text-sm">Registrar</span>
              <span className="text-white font-bold">{network?.registrar || 'N/A'}</span>
            </div>

            {/* ISP */}
            <div className="flex justify-between items-center p-3 bg-slate-800/50 rounded-lg border border-slate-700">
              <span className="text-slate-400 uppercase text-sm">ISP</span>
              <span className="text-white font-bold">{network?.isp || 'N/A'}</span>
            </div>

            {/* Country & IP */}
            <div className="flex justify-between items-center p-3 bg-slate-800/50 rounded-lg border border-slate-700">
              <span className="text-slate-400 uppercase text-sm">Location</span>
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                <span className="text-white font-bold">{network?.country || 'Unknown'}</span>
              </div>
            </div>

            <div className="flex justify-between items-center p-3 bg-slate-800/50 rounded-lg border border-slate-700">
              <span className="text-slate-400 uppercase text-sm">IP Address</span>
              <span className="text-cyan-400 font-mono font-bold">{network?.ip || 'N/A'}</span>
            </div>
          </div>
        </div>

        {/* Section 3: URL FORENSICS */}
        <div className="bg-slate-900 rounded-lg border border-purple-500/30 p-6 shadow-xl hover:border-purple-500/60 transition-all">
          <div className="flex items-center gap-3 mb-6 pb-3 border-b border-purple-500/30">
            <Search className="w-6 h-6 text-purple-400" />
            <h3 className="text-xl font-bold text-purple-400 uppercase tracking-wider">URL Forensics</h3>
          </div>

          <div className="space-y-4">
            {/* Typosquatting */}
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 uppercase text-sm">Typosquatting</span>
                {forensics?.typosquatting ? (
                  <div className="flex items-center gap-2 px-3 py-1 bg-red-500/20 border border-red-500 rounded-full">
                    <XCircle className="w-4 h-4 text-red-500" />
                    <span className="text-red-500 font-bold text-sm">DETECTED</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 px-3 py-1 bg-green-500/20 border border-green-500 rounded-full">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    <span className="text-green-500 font-bold text-sm">CLEAN</span>
                  </div>
                )}
              </div>
            </div>

            {/* Obfuscation */}
            {forensics?.obfuscation && (
              <div className="p-4 bg-orange-500/10 rounded-lg border border-orange-500">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-5 h-5 text-orange-500" />
                  <span className="text-orange-500 font-bold uppercase text-sm">Obfuscation Detected</span>
                </div>
                <p className="text-orange-300 text-sm ml-7">{forensics.obfuscation}</p>
              </div>
            )}

            {/* Redirect Chain */}
            {forensics?.redirect_chain && forensics.redirect_chain.length > 0 ? (
              <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="flex items-center gap-2 mb-3">
                  <ExternalLink className="w-5 h-5 text-yellow-500" />
                  <span className="text-yellow-500 font-bold uppercase text-sm">Redirect Chain</span>
                </div>
                <div className="space-y-2 ml-7">
                  {forensics.redirect_chain.map((url, index) => (
                    <div key={index} className="flex items-center gap-2 text-sm">
                      <span className="text-cyan-400 font-bold">#{index + 1}</span>
                      <ChevronRight className="w-4 h-4 text-slate-500" />
                      <span className="text-slate-300 break-all">{url}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400 uppercase text-sm">Redirect Chain</span>
                  <span className="text-green-500 font-bold text-sm">No Redirects</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Section 4: CONTENT ANALYSIS */}
        <div className="bg-slate-900 rounded-lg border border-blue-500/30 p-6 shadow-xl hover:border-blue-500/60 transition-all">
          <div className="flex items-center gap-3 mb-6 pb-3 border-b border-blue-500/30">
            <FileText className="w-6 h-6 text-blue-400" />
            <h3 className="text-xl font-bold text-blue-400 uppercase tracking-wider">Content Analysis</h3>
          </div>

          <div className="space-y-4">
            {/* Screenshot */}
            <div className="aspect-video bg-slate-800/50 rounded-lg border border-slate-700 overflow-hidden">
              {content?.screenshot_url ? (
                <img 
                  src={content.screenshot_url} 
                  alt="Website Screenshot" 
                  className="w-full h-full object-cover"
                />
              ) : (
                <div className="w-full h-full flex items-center justify-center">
                  <div className="text-center space-y-3">
                    <div className="w-16 h-16 mx-auto border-4 border-slate-600 border-t-blue-500 rounded-full animate-spin"></div>
                    <span className="text-slate-500 text-sm">Screenshot Not Available</span>
                  </div>
                </div>
              )}
            </div>

            {/* Login Form Detection */}
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {content?.has_login_form ? (
                    <Unlock className="w-5 h-5 text-red-500" />
                  ) : (
                    <Lock className="w-5 h-5 text-green-500" />
                  )}
                  <span className="text-slate-400 uppercase text-sm">Login Form</span>
                </div>
                {content?.has_login_form === true ? (
                  <span className="text-red-500 font-bold text-sm">DETECTED</span>
                ) : content?.has_login_form === false ? (
                  <span className="text-green-500 font-bold text-sm">NOT FOUND</span>
                ) : (
                  <span className="text-slate-500 font-bold text-sm">N/A</span>
                )}
              </div>
            </div>

            {/* External Resources */}
            {content?.external_resources && content.external_resources.length > 0 && (
              <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
                <span className="text-slate-400 uppercase text-sm block mb-2">External Resources</span>
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {content.external_resources.map((resource, index) => (
                    <div key={index} className="text-xs text-cyan-400 font-mono">{resource}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Section 5: ADVANCED INDICATORS */}
        <div className="bg-slate-900 rounded-lg border border-green-500/30 p-6 shadow-xl hover:border-green-500/60 transition-all">
          <div className="flex items-center gap-3 mb-6 pb-3 border-b border-green-500/30">
            <Terminal className="w-6 h-6 text-green-400" />
            <h3 className="text-xl font-bold text-green-400 uppercase tracking-wider">Advanced Indicators</h3>
          </div>

          <div className="space-y-4">
            {/* Terminal-style Blackbox */}
            <div className="bg-black/80 rounded-lg border border-green-500/30 p-4 font-mono text-sm">
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-green-500/20">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-red-500"></div>
                  <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                  <div className="w-3 h-3 rounded-full bg-green-500"></div>
                </div>
                <span className="text-green-400 text-xs">SECURITY SCAN</span>
              </div>
              
              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-green-400">$</span>
                  <span className="text-slate-400">Checking for malicious indicators...</span>
                </div>
                
                {advanced?.telegram_bot_detected && (
                  <div className="flex items-center gap-2 text-red-400">
                    <Zap className="w-3 h-3" />
                    <span>[!] Telegram Bot API Detected</span>
                  </div>
                )}

                {advanced?.discord_webhook_detected && (
                  <div className="flex items-center gap-2 text-red-400">
                    <Zap className="w-3 h-3" />
                    <span>[!] Discord Webhook Detected</span>
                  </div>
                )}

                {!advanced?.telegram_bot_detected && !advanced?.discord_webhook_detected && (
                  <div className="flex items-center gap-2 text-green-400">
                    <CheckCircle className="w-3 h-3" />
                    <span>[✓] No bot APIs detected</span>
                  </div>
                )}

                <div className="flex items-center gap-2">
                  <span className="text-green-400">$</span>
                  <span className="text-slate-400">Scan complete.</span>
                </div>
              </div>
            </div>

            {/* SSL Certificate */}
            <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700">
              <div className="flex items-center gap-2 mb-3">
                <Lock className="w-5 h-5 text-green-400" />
                <span className="text-green-400 font-bold uppercase text-sm">SSL Certificate</span>
              </div>
              <div className="space-y-2 ml-7 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-400">Issuer:</span>
                  <span className="text-white font-bold">{advanced?.ssl_issuer || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Validity:</span>
                  <span className={`font-bold ${
                    advanced?.ssl_validity?.includes('Expired') 
                      ? 'text-red-500' 
                      : 'text-green-400'
                  }`}>
                    {advanced?.ssl_validity || 'N/A'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Section 6: THREAT INTELLIGENCE */}
      <div className="bg-slate-900 rounded-lg border border-red-500/30 p-6 shadow-xl hover:border-red-500/60 transition-all">
        <div className="flex items-center gap-3 mb-6 pb-3 border-b border-red-500/30">
          <BarChart3 className="w-6 h-6 text-red-400" />
          <h3 className="text-xl font-bold text-red-400 uppercase tracking-wider">Threat Intelligence</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* VirusTotal */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 uppercase text-sm font-bold">VirusTotal</span>
              <span className="text-cyan-400 font-mono text-sm">{intelligence?.virustotal_score || 'N/A'}</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden">
              <div 
                className="bg-gradient-to-r from-green-500 to-red-500 h-full rounded-full transition-all duration-500"
                style={{ width: intelligence?.virustotal_score ? '50%' : '0%' }}
              ></div>
            </div>
            {!intelligence?.virustotal_score && (
              <p className="text-xs text-slate-500 italic">Integration pending</p>
            )}
          </div>

          {/* Google Safe Browsing */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 uppercase text-sm font-bold">Google Safe Browsing</span>
              <span className={`font-bold text-sm ${
                intelligence?.google_safebrowsing === 'Malware' || intelligence?.google_safebrowsing === 'Phishing'
                  ? 'text-red-500'
                  : intelligence?.google_safebrowsing === 'Safe'
                  ? 'text-green-500'
                  : 'text-slate-400'
              }`}>
                {intelligence?.google_safebrowsing || 'N/A'}
              </span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden">
              <div 
                className={`h-full rounded-full transition-all duration-500 ${
                  intelligence?.google_safebrowsing === 'Malware' || intelligence?.google_safebrowsing === 'Phishing'
                    ? 'bg-red-500'
                    : intelligence?.google_safebrowsing === 'Safe'
                    ? 'bg-green-500'
                    : 'bg-slate-700'
                }`}
                style={{ width: intelligence?.google_safebrowsing ? '100%' : '0%' }}
              ></div>
            </div>
            {!intelligence?.google_safebrowsing && (
              <p className="text-xs text-slate-500 italic">Integration pending</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AnalysisReport;
