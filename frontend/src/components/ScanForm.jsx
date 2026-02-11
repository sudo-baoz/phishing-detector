/**
 * URL Scanner form – High-contrast input and card. No backdrop-blur on text containers.
 * Light: bg-white border-gray-300 text-gray-900. Dark: bg-gray-950 border-gray-700 text-white.
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

  const inputBase =
    'w-full rounded-lg sm:rounded-xl pl-10 sm:pl-12 pr-3 sm:pr-4 py-3 sm:py-4 text-sm sm:text-base border focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-colors';
  const inputLight = 'bg-white border-gray-300 text-gray-900 placeholder-gray-500';
  const inputDark = 'dark:bg-gray-950 dark:border-gray-700 dark:text-white dark:placeholder-gray-400';
  const inputClass = `${inputBase} ${inputLight} ${inputDark}`;

  const cardBg = isDark ? 'bg-gray-900 border-gray-800' : 'bg-white border-gray-200';
  const labelColor = isDark ? 'text-cyan-400' : 'text-gray-900';
  const hintColor = isDark ? 'text-gray-400' : 'text-gray-600';

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
      className="w-full max-w-xl"
    >
      <div className={`relative rounded-xl sm:rounded-2xl p-4 sm:p-6 md:p-8 shadow-sm border ${cardBg}`}>
        <form onSubmit={onSubmit} className="relative space-y-6">
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
              <div className="flex items-center justify-center p-2 sm:p-4 rounded-lg sm:rounded-xl border-2 border-amber-500/40 bg-amber-100 dark:bg-amber-900/20 w-full max-w-[320px] min-h-[65px]">
                <span className="text-amber-700 dark:text-amber-400 text-sm">Dev mode — verification skipped</span>
              </div>
            ) : (
              <>
                <div
                  className={`flex items-center justify-center p-2 sm:p-4 rounded-lg sm:rounded-xl border-2 w-full max-w-[320px] min-h-[65px] transition-colors ${
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
            className={`w-full font-bold py-3 sm:py-4 px-4 sm:px-6 rounded-lg sm:rounded-xl uppercase tracking-wider transition-all text-sm sm:text-base min-h-[48px] ${
              loading || (!isTurnstileDevMode && !turnstileToken)
                ? 'bg-gray-300 dark:bg-gray-700 text-gray-500 dark:text-gray-400 cursor-not-allowed'
                : 'bg-cyan-600 hover:bg-cyan-500 text-white'
            }`}
          >
            {loading ? t('scanner.scanning') : t('scanner.scan_button')}
          </button>
        </form>
      </div>
    </motion.div>
  );
}
