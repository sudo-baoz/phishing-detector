/**
 * Ambient Background – Subtle radial glows behind the app (modern SaaS style).
 * Fixed behind content (-z-10), does not scroll. No grid/dot patterns.
 */

import { useTheme } from '../../context/ThemeContext';

export default function AmbientBackground() {
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  const orbBase = 'absolute rounded-full pointer-events-none';
  const orbSize = 'w-[min(80vw,400px)] h-[min(80vw,400px)] sm:w-[500px] sm:h-[500px]';

  return (
    <div className="fixed inset-0 -z-10 overflow-hidden" aria-hidden>
      {/* Orb 1: Top-left (off-screen slightly) */}
      <div
        className={`${orbBase} ${orbSize} -top-24 -left-24 sm:-top-32 sm:-left-32 ${
          isDark ? 'bg-cyan-500/10 blur-[120px]' : 'bg-blue-500/25 blur-[100px]'
        }`}
      />
      {/* Orb 2: Top-right (off-screen slightly) */}
      <div
        className={`${orbBase} ${orbSize} -top-24 -right-24 sm:-top-32 sm:-right-32 ${
          isDark ? 'bg-indigo-500/10 blur-[120px]' : 'bg-purple-500/20 blur-[100px]'
        }`}
      />
      {/* Orb 3: Bottom-center (very faint) */}
      <div
        className={`${orbBase} ${orbSize} bottom-0 left-1/2 -translate-x-1/2 translate-y-1/3 ${
          isDark ? 'bg-cyan-500/5 blur-[140px]' : 'bg-blue-400/10 blur-[120px]'
        }`}
      />
      {/* Optional: very faint noise overlay for texture */}
      <div
        className="absolute inset-0 opacity-[0.02] pointer-events-none mix-blend-overlay"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E")`,
          backgroundRepeat: 'repeat',
        }}
      />
    </div>
  );
}
