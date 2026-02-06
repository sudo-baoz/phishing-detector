/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 *
 * Risk Meter Gauge – Semi-circle (donut) showing risk score.
 * 0–30: SAFE (green), 31–79: SUSPICIOUS (orange), 80–100: CRITICAL (red).
 * High score = high risk. Pure SVG, no chart libraries.
 */

const R = 72;
const CX = 80;
const CY = 88;
const STROKE = 12;
const SEMI_CIRCLE_LENGTH = Math.PI * R;

function getRiskStyle(score) {
  if (score <= 30) return { stroke: '#22c55e', glow: 'rgba(34, 197, 94, 0.5)', label: 'SAFE' };
  if (score <= 79) return { stroke: '#f59e0b', glow: 'rgba(245, 158, 11, 0.5)', label: 'SUSPICIOUS' };
  return { stroke: '#ef4444', glow: 'rgba(239, 68, 68, 0.5)', label: 'CRITICAL' };
}

const TrustGauge = ({ score = 0, className = '' }) => {
  const clamped = Math.max(0, Math.min(100, Number(score)));
  const { stroke, glow, label } = getRiskStyle(clamped);
  const offset = SEMI_CIRCLE_LENGTH * (1 - clamped / 100);

  return (
    <div
      className={`relative inline-flex flex-col items-center ${className}`}
      style={{
        filter: `drop-shadow(0 0 12px ${glow})`,
      }}
    >
      <svg
        width="160"
        height="100"
        viewBox="0 0 160 100"
        className="drop-shadow-lg"
      >
        <defs>
          <filter id="trust-gauge-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        {/* Background arc (semi-circle track) */}
        <path
          d={`M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`}
          fill="none"
          stroke="rgba(30, 41, 59, 0.9)"
          strokeWidth={STROKE}
          strokeLinecap="round"
        />
        {/* Filled arc: length = score %, color = risk level */}
        <path
          d={`M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`}
          fill="none"
          stroke={stroke}
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={SEMI_CIRCLE_LENGTH}
          strokeDashoffset={offset}
          style={{
            filter: `drop-shadow(0 0 8px ${glow})`,
            transition: 'stroke-dashoffset 0.8s ease-out, stroke 0.3s ease',
          }}
        />
      </svg>
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 flex flex-col items-center">
        <span
          className="text-3xl font-bold tabular-nums"
          style={{ color: stroke, textShadow: `0 0 12px ${glow}` }}
        >
          {Math.round(clamped)}
        </span>
        <span
          className="text-[10px] font-bold uppercase tracking-widest"
          style={{ color: stroke }}
        >
          {label}
        </span>
      </div>
    </div>
  );
};

export default TrustGauge;
