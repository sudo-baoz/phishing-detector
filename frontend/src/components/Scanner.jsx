import { useState } from 'react';
import { scanUrl } from '../services/api';
import AnalysisReport from './AnalysisReport';

const Scanner = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const sanitizeUrl = (inputUrl) => {
    let sanitized = inputUrl.trim();
    
    // Fix common typos in protocol
    if (sanitized.match(/^ttps:\/\//i)) {
      sanitized = sanitized.replace(/^ttps:\/\//i, 'https://');
    } else if (sanitized.match(/^ttp:\/\//i)) {
      sanitized = sanitized.replace(/^ttp:\/\//i, 'http://');
    } else if (sanitized.match(/^htp:\/\//i)) {
      sanitized = sanitized.replace(/^htp:\/\//i, 'http://');
    } else if (sanitized.match(/^htps:\/\//i)) {
      sanitized = sanitized.replace(/^htps:\/\//i, 'https://');
    }
    
    // Add https:// if no protocol
    if (!sanitized.match(/^https?:\/\//i)) {
      sanitized = 'https://' + sanitized;
    }
    
    return sanitized;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    // Sanitize URL before sending
    const sanitizedUrl = sanitizeUrl(url);

    const response = await scanUrl(sanitizedUrl);

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
          <div className="mt-8 animate-fadeIn">
            <AnalysisReport data={result} loading={false} />
          </div>
        )}
      </div>
    </div>
  );
};

export default Scanner;
