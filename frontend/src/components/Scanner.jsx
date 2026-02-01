import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { scanUrl } from '../services/api';
import AnalysisReport from './AnalysisReport';
import ChatWidget from './ChatWidget';
import { Shield, AlertTriangle, Search } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const MatrixRain = () => {
  return (
    <div className="fixed inset-0 opacity-10 pointer-events-none overflow-hidden">
      <div className="matrix-rain">
        {Array.from({ length: 30 }).map((_, i) => (
          <div
            key={i}
            className="matrix-column"
            style={{
              left: `${(i / 30) * 100}%`,
              animationDelay: `${Math.random() * 5}s`,
              animationDuration: `${5 + Math.random() * 10}s`
            }}
          >
            {Array.from({ length: 20 }).map((_, j) => (
              <span key={j} className="matrix-char">
                {String.fromCharCode(33 + Math.floor(Math.random() * 94))}
              </span>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
};

const CircularGauge = ({ percentage = 0, isPhishing }) => {
  const radius = 70;
  const stroke = 8;
  const normalizedRadius = radius - stroke * 2;
  const circumference = normalizedRadius * 2 * Math.PI;
  const safePercentage = Number(percentage) || 0;
  const strokeDashoffset = circumference - (safePercentage / 100) * circumference;

  return (
    <motion.div
      initial={{ scale: 0, rotate: -180 }}
      animate={{ scale: 1, rotate: 0 }}
      transition={{ type: 'spring', stiffness: 100, damping: 15 }}
      className="relative inline-flex items-center justify-center"
    >
      <svg height={radius * 2} width={radius * 2} className="transform -rotate-90">
        {/* Background circle */}
        <circle
          strokeWidth={stroke}
          stroke="rgba(6, 182, 212, 0.1)"
          fill="transparent"
          r={normalizedRadius}
          cx={radius}
          cy={radius}
        />
        {/* Progress circle */}
        <motion.circle
          strokeWidth={stroke}
          strokeLinecap="round"
          stroke={isPhishing ? '#ef4444' : '#22c55e'}
          fill="transparent"
          r={normalizedRadius}
          cx={radius}
          cy={radius}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset }}
          transition={{ duration: 1, ease: 'easeInOut' }}
          style={{
            strokeDasharray: `${circumference} ${circumference}`,
            filter: `drop-shadow(0 0 8px ${isPhishing ? '#ef4444' : '#22c55e'})`
          }}
        />
      </svg>
      <div className="absolute text-center">
        <div className={`text-3xl font-bold ${isPhishing ? 'text-red-500' : 'text-green-500'}`}>
          {Math.round(safePercentage)}%
        </div>
      </div>
    </motion.div>
  );
};

const Scanner = () => {
  const { t } = useTranslation();
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

  const getRiskLevel = (confidence, isPhishing) => {
    if (!isPhishing) return 'safe';
    if (confidence >= 80) return 'critical';
    if (confidence >= 60) return 'high';
    if (confidence >= 40) return 'medium';
    return 'low';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-950 via-gray-900 to-black text-white">
      <MatrixRain />

      <div className="relative z-10 container mx-auto px-4 py-8 max-w-7xl">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="text-center mb-12"
        >
          <h1 className="text-5xl md:text-6xl font-black mb-3 bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent">
            {t('app_title')}
          </h1>
          <p className="text-lg text-gray-400 font-medium">
            {t('app_subtitle')}
          </p>
          <div className="mt-4 flex items-center justify-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-sm text-green-400 font-mono">{t('chat.status_online')}</span>
          </div>
        </motion.div>

        {/* Scanner Card - Glassmorphism */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="mb-8"
        >
          <div className="relative bg-gray-900/40 backdrop-blur-xl border border-cyan-500/30 rounded-2xl p-8 shadow-2xl shadow-cyan-500/10">
            {/* Neon glow effect */}
            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 to-purple-500/5 rounded-2xl blur-xl" />

            <form onSubmit={handleSubmit} className="relative space-y-6">
              <div>
                <label className="block text-sm font-bold mb-3 text-cyan-400 uppercase tracking-wider">
                  {t('scanner.title')}
                </label>
                <div className="relative">
                  <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-500 w-5 h-5" />
                  <input
                    type="url"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder={t('scanner.placeholder')}
                    required
                    className="w-full bg-gray-950/50 backdrop-blur-sm border-2 border-cyan-500/30 
                      rounded-xl pl-12 pr-4 py-4 text-white placeholder-gray-500
                      focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20
                      transition-all duration-300
                      shadow-lg shadow-cyan-500/10"
                    style={{
                      boxShadow: '0 0 20px rgba(6, 182, 212, 0.1), inset 0 0 20px rgba(6, 182, 212, 0.02)'
                    }}
                  />
                </div>
                <p className="mt-2 text-xs text-gray-500">{t('scanner.example')}</p>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500
                  disabled:from-gray-700 disabled:to-gray-600
                  text-white font-bold py-4 px-6 rounded-xl uppercase tracking-wider
                  transition-all duration-300 transform hover:scale-105 active:scale-95
                  disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none
                  shadow-lg shadow-cyan-500/30 hover:shadow-cyan-500/50"
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-3">
                    <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    {t('scanner.scanning')}
                  </span>
                ) : (
                  t('scanner.scan_button')
                )}
              </button>
            </form>
          </div>
        </motion.div>

        {/* Error Display */}
        <AnimatePresence>
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="mb-8 bg-red-950/50 backdrop-blur-md border border-red-500/50 rounded-xl p-6"
            >
              <div className="flex items-center gap-4">
                <AlertTriangle className="w-8 h-8 text-red-500" />
                <div>
                  <h3 className="text-xl font-bold text-red-400 mb-1">{t('errors.scan_failed')}</h3>
                  <p className="text-red-300">{error}</p>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Result Display */}
        <AnimatePresence>
          {result && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.5 }}
              className="space-y-6"
            >
              {/* Verdict Card with Circular Gauge */}
              <div className="bg-gray-900/40 backdrop-blur-xl border border-cyan-500/30 rounded-2xl p-8 shadow-xl">
                <div className="grid md:grid-cols-2 gap-8 items-center">
                  {/* Left: Circular Gauge */}
                  <div className="flex flex-col items-center justify-center">
                    <CircularGauge
                      percentage={result.verdict?.confidence_score || 0}
                      isPhishing={result.verdict.is_phishing}
                    />
                    <motion.h2
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.5 }}
                      className={`mt-6 text-3xl font-black uppercase ${result.verdict.is_phishing ? 'text-red-500' : 'text-green-500'
                        }`}
                    >
                      {result.verdict.is_phishing ? t('verdict.phishing') : t('verdict.safe')}
                    </motion.h2>
                    <p className="mt-2 text-gray-400">
                      {t('details.confidence')}: {(result.verdict.confidence_score || 0).toFixed(1)}%
                    </p>
                  </div>

                  {/* Right: Details */}
                  <div className="space-y-4">
                    <div className="flex items-start gap-3">
                      <Shield className={`w-6 h-6 mt-1 ${result.verdict.is_phishing ? 'text-red-500' : 'text-green-500'}`} />
                      <div className="flex-1">
                        <h3 className="text-lg font-bold text-cyan-400">{t('details.threat_type')}</h3>
                        <p className="text-white">
                          {result.verdict.threat_type ? t(`threat_types.${result.verdict.threat_type}`) : t('verdict.safe')}
                        </p>
                      </div>
                    </div>

                    <div className="pt-4 border-t border-gray-700">
                      <div className="flex items-center justify-between py-2">
                        <span className="text-gray-400">{t('risk_levels.safe').split(' ')[0]}:</span>
                        <span className={`font-bold uppercase ${result.verdict.is_phishing ? 'text-red-400' : 'text-green-400'
                          }`}>
                          {t(`risk_levels.${getRiskLevel(result.verdict.confidence_score, result.verdict.is_phishing)}`)}
                        </span>
                      </div>
                      <div className="py-2 border-t border-gray-800">
                        <span className="text-gray-400 text-sm">{t('details.url')}:</span>
                        <p className="text-cyan-400 font-mono text-sm break-all mt-1">{result.verdict.url}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Analysis Report */}
              <AnalysisReport data={result} loading={false} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Chat Widget - Always visible, context-aware */}
      <ChatWidget scanResult={result} />

      {/* Matrix Rain CSS */}
      <style>{`
        .matrix-rain {
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
        }

        .matrix-column {
          position: absolute;
          top: -100%;
          width: 20px;
          color: #0f9;
          text-shadow: 0 0 5px #0f9;
          font-family: 'Courier New', monospace;
          font-size: 14px;
          animation: fall linear infinite;
        }

        .matrix-char {
          display: block;
          opacity: 0.8;
        }

        @keyframes fall {
          to {
            transform: translateY(100vh);
          }
        }
      `}</style>
    </div>
  );
};

export default Scanner;
