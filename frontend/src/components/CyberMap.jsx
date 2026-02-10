/**
 * Phishing Detector - Live Cyber Attack Map
 * Copyright (c) 2026 BaoZ
 *
 * Dark-themed world map. WebSocket receives scan events (source -> target).
 * Renders animated arcs (red = PHISHING, green = SAFE) and ping at target.
 * Uses react-simple-maps (2D) + d3-geo for projection.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ComposableMap, Geographies, Geography, ZoomableGroup } from 'react-simple-maps';
import { geoMercator } from 'd3-geo';
import { API_BASE_URL } from '../constants/api';

const MAP_WIDTH = 800;
const MAP_HEIGHT = 500;
const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

function getWsUrl() {
  const base = API_BASE_URL.replace(/^http/, 'ws').replace(/\/+$/, '');
  return `${base}/live-map`;
}

// One scan event: source/target may have null lat/lon (use fallback for display)
function ArcLayer({ arcs, projection }) {
  if (!projection || !arcs.length) return null;
  return (
    <g className="arcs">
      {arcs.map((arc, i) => {
        const src = arc.source?.lat != null && arc.source?.lon != null
          ? projection([arc.source.lon, arc.source.lat])
          : null;
        const tgt = arc.target?.lat != null && arc.target?.lon != null
          ? projection([arc.target.lon, arc.target.lat])
          : null;
        if (!tgt) return null;
        const isRed = arc.type === 'PHISHING';
        const color = isRed ? '#ef4444' : '#22c55e';
        const x1 = src ? src[0] : MAP_WIDTH / 2;
        const y1 = src ? src[1] : MAP_HEIGHT / 2;
        const x2 = tgt[0];
        const y2 = tgt[1];
        return (
          <g key={arc.id ?? i}>
            <line
              x1={x1}
              y1={y1}
              x2={x2}
              y2={y2}
              stroke={color}
              strokeWidth={1.5}
              strokeOpacity={0.9}
              className="arc-line"
              style={{
                strokeDasharray: 400,
                animation: 'arc-draw 1.2s ease-out forwards',
              }}
            />
            <circle
              cx={x2}
              cy={y2}
              r={4}
              fill={color}
              className="target-dot"
            />
          </g>
        );
      })}
    </g>
  );
}

function PingLayer({ arcs, projection }) {
  if (!projection || !arcs.length) return null;
  return (
    <g className="pings">
      {arcs.map((arc, i) => {
        if (arc.target?.lat == null || arc.target?.lon == null) return null;
        const tgt = projection([arc.target.lon, arc.target.lat]);
        const isRed = arc.type === 'PHISHING';
        const color = isRed ? '#ef4444' : '#22c55e';
        return (
          <g key={`ping-${arc.id ?? i}`} transform={`translate(${tgt[0]}, ${tgt[1]})`}>
            <circle
              r={8}
              fill="none"
              stroke={color}
              strokeWidth={1.5}
              className="ping-circle"
              style={{ animation: 'ping-expand 1.5s ease-out forwards' }}
            />
          </g>
        );
      })}
    </g>
  );
}

export default function CyberMap({ className = '' }) {
  const [arcs, setArcs] = useState([]);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const idRef = useRef(0);

  const projection = useMemo(
    () => geoMercator().scale(147).translate([MAP_WIDTH / 2, MAP_HEIGHT / 2]),
    []
  );

  const addArc = useCallback((payload) => {
    const { source, target, type } = payload;
    if (target?.lat == null || target?.lon == null) return;
    setArcs((prev) => {
      const next = [...prev.slice(-49), { id: ++idRef.current, source, target, type }];
      return next;
    });
  }, []);

  useEffect(() => {
    const url = getWsUrl();
    function connect() {
      try {
        const ws = new WebSocket(url);
        ws.onopen = () => {
          wsRef.current = ws;
        };
        ws.onmessage = (ev) => {
          try {
            const data = JSON.parse(ev.data);
            if (data?.target && (data.target.lat != null && data.target.lon != null)) {
              addArc(data);
            }
          } catch (_) {}
        };
        ws.onclose = () => {
          wsRef.current = null;
          reconnectTimeoutRef.current = setTimeout(connect, 3000);
        };
        ws.onerror = () => {};
        return ws;
      } catch (e) {
        reconnectTimeoutRef.current = setTimeout(connect, 3000);
      }
    }
    connect();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [addArc]);

  return (
    <div className={`rounded-xl overflow-hidden border border-slate-700 bg-slate-950 ${className}`}>
      <style>{`
        @keyframes arc-draw {
          from { stroke-dashoffset: 400; }
          to { stroke-dashoffset: 0; }
        }
        @keyframes ping-expand {
          from { transform: scale(1); opacity: 0.8; }
          to { transform: scale(4); opacity: 0; }
        }
      `}</style>
      <ComposableMap
        width={MAP_WIDTH}
        height={MAP_HEIGHT}
        projection="geoMercator"
        projectionConfig={{ scale: 147 }}
      >
        <ZoomableGroup center={[0, 20]}>
          <Geographies geography={GEO_URL}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#334155"
                  stroke="#475569"
                  strokeWidth={0.5}
                />
              ))
            }
          </Geographies>
          <ArcLayer arcs={arcs} projection={projection} />
          <PingLayer arcs={arcs} projection={projection} />
        </ZoomableGroup>
      </ComposableMap>
      <div className="flex items-center justify-center gap-4 py-2 px-3 bg-slate-900/80 border-t border-slate-700 text-xs text-slate-400">
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-red-500" /> PHISHING
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-green-500" /> SAFE
        </span>
        <span>Live scan events</span>
      </div>
    </div>
  );
}
