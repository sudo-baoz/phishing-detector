import { useState } from 'react';
import { scanUrl } from '../services/api';

const Scanner = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    const response = await scanUrl(url);

    if (response.success) {
      setResult(response.data);
    } else {
      setError(response.error);
    }

    setLoading(false);
  };

  const getThreatColor = (threatType) => {
    const colors = {
      credential_theft: 'text-red-500',
      malware: 'text-purple-500',
      scam: 'text-orange-500',
      financial_fraud: 'text-yellow-500',
      phishing: 'text-red-400',
    };
    return colors[threatType] || 'text-red-500';
  };

  return (
    <div className="min-h-screen bg-black text-green-400 p-8 font-mono">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-5xl font-bold mb-4 text-green-400 glitch" data-text="PHISHING DETECTOR">
            PHISHING DETECTOR
          </h1>
          <p className="text-xl text-green-300/70">
            [SYSTEM v1.0] - THREAT ANALYSIS ENGINE
          </p>
          <div className="mt-4 flex items-center justify-center gap-2">
            <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
            <span className="text-sm text-green-500">ONLINE</span>
          </div>
        </div>

        {/* Scanner Form */}
        <div className="bg-gray-900 border-2 border-green-500 rounded-lg p-8 shadow-2xl shadow-green-500/20">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-semibold mb-2 text-green-400">
                &gt; ENTER TARGET URL
              </label>
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://suspicious-website.com"
                required
                className="w-full bg-black border-2 border-green-500/50 rounded px-4 py-3 text-green-400 placeholder-green-700 focus:outline-none focus:border-green-400 focus:shadow-lg focus:shadow-green-500/50 transition-all"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-green-500 hover:bg-green-400 text-black font-bold py-4 px-6 rounded uppercase tracking-wider transition-all transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-green-500/50"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  SCANNING...
                </span>
              ) : (
                '[ INITIATE SCAN ]'
              )}
            </button>
          </form>
        </div>

        {/* Error Display */}
        {error && (
          <div className="mt-8 bg-red-950 border-2 border-red-500 rounded-lg p-6 animate-pulse">
            <div className="flex items-center gap-3">
              <span className="text-3xl">⚠️</span>
              <div>
                <h3 className="text-xl font-bold text-red-400 mb-1">ERROR</h3>
                <p className="text-red-300">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Result Display */}
        {result && (
          <div className="mt-8 space-y-6 animate-fadeIn">
            {/* Main Verdict */}
            <div className={`border-2 rounded-lg p-8 shadow-2xl ${
              result.is_phishing 
                ? 'bg-red-950 border-red-500 shadow-red-500/20' 
                : 'bg-green-950 border-green-500 shadow-green-500/20'
            }`}>
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-4">
                  <span className="text-6xl">
                    {result.is_phishing ? '☠️' : '🛡️'}
                  </span>
                  <div>
                    <h2 className={`text-3xl font-bold ${
                      result.is_phishing ? 'text-red-400' : 'text-green-400'
                    }`}>
                      {result.is_phishing ? '[ MALICIOUS DETECTED ]' : '[ SAFE WEBSITE ]'}
                    </h2>
                    {result.threat_type && (
                      <p className={`text-lg mt-1 uppercase ${getThreatColor(result.threat_type)}`}>
                        Threat Type: {result.threat_type.replace(/_/g, ' ')}
                      </p>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  <div className={`text-5xl font-bold ${
                    result.is_phishing ? 'text-red-400' : 'text-green-400'
                  }`}>
                    {Math.round(result.confidence_score)}%
                  </div>
                  <div className="text-sm text-gray-400 mt-1">CONFIDENCE</div>
                </div>
              </div>

              {/* Confidence Bar */}
              <div className="relative h-6 bg-gray-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-1000 ${
                    result.is_phishing 
                      ? 'bg-gradient-to-r from-red-600 to-red-400' 
                      : 'bg-gradient-to-r from-green-600 to-green-400'
                  }`}
                  style={{ width: `${result.confidence_score}%` }}
                >
                  <div className="absolute inset-0 bg-white/20 animate-pulse"></div>
                </div>
              </div>
            </div>

            {/* URL Info */}
            <div className="bg-gray-900 border-2 border-gray-700 rounded-lg p-6">
              <h3 className="text-lg font-bold text-green-400 mb-3">&gt; SCANNED URL</h3>
              <p className="text-green-300 break-all bg-black p-3 rounded border border-green-500/30">
                {result.url}
              </p>
              <div className="mt-4 flex items-center gap-4 text-sm text-gray-400">
                <div>ID: #{result.id}</div>
                <div>|</div>
                <div>Scanned: {new Date(result.scanned_at).toLocaleString()}</div>
              </div>
            </div>

            {/* Threat Details */}
            {result.is_phishing && (
              <div className="bg-red-950/50 border-2 border-red-500/50 rounded-lg p-6">
                <h3 className="text-lg font-bold text-red-400 mb-4">&gt; THREAT ANALYSIS</h3>
                <ul className="space-y-2 text-red-300">
                  {result.threat_type === 'credential_theft' && (
                    <>
                      <li className="flex items-start gap-2">
                        <span className="text-red-500 mt-1">▸</span>
                        <span>Attempts to steal login credentials or personal information</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-500 mt-1">▸</span>
                        <span>May impersonate legitimate login pages</span>
                      </li>
                    </>
                  )}
                  {result.threat_type === 'malware' && (
                    <>
                      <li className="flex items-start gap-2">
                        <span className="text-red-500 mt-1">▸</span>
                        <span>May contain malicious downloads or executables</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-500 mt-1">▸</span>
                        <span>Could install unwanted software on your device</span>
                      </li>
                    </>
                  )}
                  {result.threat_type === 'scam' && (
                    <>
                      <li className="flex items-start gap-2">
                        <span className="text-red-500 mt-1">▸</span>
                        <span>Fraudulent prize or gift claim scheme detected</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-500 mt-1">▸</span>
                        <span>May request personal information or payments</span>
                      </li>
                    </>
                  )}
                  {result.threat_type === 'financial_fraud' && (
                    <>
                      <li className="flex items-start gap-2">
                        <span className="text-red-500 mt-1">▸</span>
                        <span>Targets financial or banking information</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-500 mt-1">▸</span>
                        <span>May impersonate banks or payment services</span>
                      </li>
                    </>
                  )}
                  <li className="flex items-start gap-2">
                    <span className="text-red-500 mt-1">▸</span>
                    <span className="font-bold">DO NOT enter any personal information on this site</span>
                  </li>
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Scanner;
