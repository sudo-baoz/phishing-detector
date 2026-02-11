/**
 * URL Scanner – Full-width Hero Section (edge-to-edge).
 * Background spans 100vw; content centered in max-w-4xl. Transparent so ambient glow shows through.
 */

import { useTranslation } from 'react-i18next';
import { Turnstile } from '@marsidev/react-turnstile';
import { Search, Shield, AlertTriangle } from 'lucide-react';
import { motion } from 'framer-motion';
import { useTheme } from '../context/ThemeContext';

export default function ScanForm({
  url,
  setUrl,
  loading,
  onSubmit,
  turnstileToken,
  setTurnstileToken,
  turnstileError,
  setTurnstileError,
  widgetKey,
  setWidgetKey,
  turnstileRef,
  isTurnstileDevMode,
  TURNSTILE_SITE_KEY,
}) {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const handleSuccess = (token) => {
    setTurnstileToken(token);
    setTurnstileError(false);
  };
  const handleError = () => {
    setTurnstileToken(null);
    setTurnstileError(true);
    setWidgetKey((k) => k + 1);
  };
  const handleExpire = () => {
    setTurnstileToken(null);
    setTurnstileError(true);
    setWidgetKey((k) => k + 1);
  };

  /* Input: slightly more opaque than glass card for readability and contrast */
  const inputBase =
    'w-full rounded-xl sm:rounded-2xl pl-10 sm:pl-12 pr-4 sm:pr-5 py-3.5 sm:py-4 text-sm sm:text-base border focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all shadow-lg';
  const inputLight = 'bg-white/90 border-gray-200/80 text-gray-900 placeholder-gray-500';
  const inputDark = 'dark:bg-gray-950/80 dark:border-white/10 dark:text-white dark:placeholder-gray-400';
  const inputClass = `${inputBase} ${inputLight} ${inputDark}`;

  /* Glassmorphism: translucent pane + backdrop blur + reflective edges + depth shadow */
  const glassCard =
    'rounded-2xl sm:rounded-3xl border backdrop-blur-xl shadow-2xl ' +
    (isDark
      ? 'bg-gray-900/60 border-white/10 shadow-black/20'
      : 'bg-white/30 border-white/40 shadow-blue-500/10');
  const labelColor = isDark ? 'text-cyan-400' : 'text-gray-900';
  const hintColor = isDark ? 'text-gray-400' : 'text-gray-600';

  const heroBg = 'border-b border-gray-200/50 dark:border-white/5';

  return (
    <div
      className={`w-screen relative left-[50%] right-[50%] -ml-[50vw] py-16 px-4 bg-transparent ${heroBg}`}
      data-scan-hero-full-bleed
    >
      <div className="relative max-w-4xl mx-auto text-center">
        <motion.h2
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-gray-900 dark:text-gray-50 mb-2"
        >
          Analyze Suspicious URLs Instantly
        </motion.h2>
        <motion.p
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.05 }}
          className={`text-sm sm:text-base md:text-lg ${hintColor} mb-8`}
        >
          {t('app_subtitle')}
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className={`relative p-5 sm:p-6 md:p-8 ${glassCard}`}
        >
          <form onSubmit={onSubmit} className="relative space-y-6 text-left">
            <div>
              <label className={`block text-xs sm:text-sm font-bold mb-2 sm:mb-3 uppercase tracking-wider ${labelColor}`}>
                {t('scanner.title')}
              </label>
              <div className="relative">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-cyan-500" />
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder={t('scanner.placeholder')}
                  required
                  className={inputClass}
                />
              </div>
              <p className={`mt-2 text-xs ${hintColor}`}>{t('scanner.example')}</p>
            </div>

            <div className="flex flex-col items-center gap-2 sm:gap-3">
              {isTurnstileDevMode ? (
                <div className="flex items-center justify-center p-2 sm:p-4 rounded-xl border-2 border-amber-500/40 bg-amber-100 dark:bg-amber-900/20 w-full max-w-[320px] min-h-[65px]">
                  <span className="text-amber-700 dark:text-amber-400 text-sm">Dev mode — verification skipped</span>
                </div>
              ) : (
                <>
                  <div
                    className={`flex items-center justify-center p-2 sm:p-4 rounded-xl border-2 w-full max-w-[320px] min-h-[65px] transition-colors ${
                      turnstileError
                        ? 'border-red-500/60 bg-red-50 dark:bg-red-900/20'
                        : turnstileToken
                          ? 'border-green-500/50 bg-green-50 dark:bg-green-900/20'
                          : 'border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-950'
                    }`}
                  >
                    <Turnstile
                      key={widgetKey}
                      ref={turnstileRef}
                      siteKey={TURNSTILE_SITE_KEY}
                      onSuccess={handleSuccess}
                      onError={handleError}
                      onExpire={handleExpire}
                      options={{ theme: isDark ? 'dark' : 'light', size: 'normal' }}
                      scriptOptions={{ defer: true, async: true, appendTo: 'body', loadAsync: 'true' }}
                    />
                  </div>
                  {turnstileToken && (
                    <motion.div
                      initial={{ opacity: 0, scale: 0.98 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="flex items-center gap-2 text-green-600 dark:text-green-400 text-sm font-medium"
                    >
                      <Shield className="w-4 h-4" />
                      <span>✓ Security verification complete</span>
                    </motion.div>
                  )}
                  {turnstileError && (
                    <motion.div
                      initial={{ opacity: 0, scale: 0.98 }}
                      animate={{ opacity: 1, scale: 1 }}
                      className="flex items-center gap-2 text-red-600 dark:text-red-400 text-sm font-medium"
                    >
                      <AlertTriangle className="w-4 h-4" />
                      <span>Please complete verification</span>
                    </motion.div>
                  )}
                </>
              )}
            </div>

            <button
              type="submit"
              disabled={loading || (!isTurnstileDevMode && !turnstileToken)}
              className={`w-full font-bold py-3.5 sm:py-4 px-4 sm:px-6 rounded-xl sm:rounded-2xl uppercase tracking-wider transition-all text-sm sm:text-base min-h-[52px] shadow-lg ${
                loading || (!isTurnstileDevMode && !turnstileToken)
                  ? 'bg-gray-300 dark:bg-gray-700 text-gray-500 dark:text-gray-400 cursor-not-allowed'
                  : 'bg-cyan-600 hover:bg-cyan-500 text-white'
              }`}
            >
              {loading ? t('scanner.scanning') : t('scanner.scan_button')}
            </button>
          </form>
        </motion.div>

        <div className="mt-4 flex items-center justify-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="text-sm text-green-600 dark:text-green-400 font-mono">{t('chat.status_online')}</span>
        </div>
      </div>
    </div>
  );
}
