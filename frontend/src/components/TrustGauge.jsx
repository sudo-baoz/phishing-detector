/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 *
 * Trust Score Gauge – Semi-circle (donut) risk display.
 * 0–49: Red (High Risk), 50–79: Orange/Yellow (Suspicious), 80–100: Green/Cyan (Safe).
 * Pure SVG/CSS, no chart libraries.
 */

const R = 72;
const CX = 80;
const CY = 88;
const STROKE = 12;
const SEMI_CIRCLE_LENGTH = Math.PI * R;

function getGaugeColor(score) {
  if (score >= 80) return { stroke: '#22d3ee', glow: 'rgba(34, 211, 238, 0.5)', label: 'Safe' };
  if (score >= 50) return { stroke: '#fbbf24', glow: 'rgba(251, 191, 36, 0.4)', label: 'Suspicious' };
  return { stroke: '#ef4444', glow: 'rgba(239, 68, 68, 0.5)', label: 'High Risk' };
}

const TrustGauge = ({ score = 0, className = '' }) => {
  const clamped = Math.max(0, Math.min(100, Number(score)));
  const { stroke, glow, label } = getGaugeColor(clamped);
  const offset = SEMI_CIRCLE_LENGTH * (1 - clamped / 100);

  return (
    <div className={`relative inline-flex flex-col items-center ${className}`}>
      <svg
        width="160"
        height="100"
        viewBox="0 0 160 100"
        className="drop-shadow-lg"
      >
        <defs>
          <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {/* Background arc (semi-circle) */}
        <path
          d={`M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`}
          fill="none"
          stroke="rgba(30, 41, 59, 0.9)"
          strokeWidth={STROKE}
          strokeLinecap="round"
        />
        {/* Progress arc */}
        <path
          d={`M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`}
          fill="none"
          stroke={stroke}
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={SEMI_CIRCLE_LENGTH}
          strokeDashoffset={offset}
          style={{
            filter: `drop-shadow(0 0 6px ${glow})`,
            transition: 'stroke-dashoffset 0.8s ease-out, stroke 0.3s ease',
          }}
        />
      </svg>
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 flex flex-col items-center">
        <span
          className="text-3xl font-bold tabular-nums"
          style={{ color: stroke }}
        >
          {Math.round(clamped)}
        </span>
        <span className="text-[10px] uppercase tracking-widest text-slate-500">
          {label}
        </span>
      </div>
    </div>
  );
};

export default TrustGauge;
