/**
 * Phishing Detector - AI-Powered Threat Intelligence System
 * Copyright (c) 2026 BaoZ
 * 
 * Threat Graph Modal - Visualizes attack chain using React Flow
 */

import { useCallback, useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { X, Network } from 'lucide-react';

// Custom node styles based on node type
const getNodeStyle = (nodeType) => {
  const styles = {
    user: {
      background: 'linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%)',
      border: '2px solid #60a5fa',
      color: '#fff',
    },
    url: {
      background: 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)',
      border: '2px solid #f87171',
      color: '#fff',
    },
    ip: {
      background: 'linear-gradient(135deg, #8b5cf6 0%, #6d28d9 100%)',
      border: '2px solid #a78bfa',
      color: '#fff',
    },
    asn: {
      background: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
      border: '2px solid #fbbf24',
      color: '#fff',
    },
    registrar: {
      background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
      border: '2px solid #34d399',
      color: '#fff',
    },
    default: {
      background: 'linear-gradient(135deg, #6b7280 0%, #4b5563 100%)',
      border: '2px solid #9ca3af',
      color: '#fff',
    },
  };
  return styles[nodeType] || styles.default;
};

// Transform backend nodes to React Flow format
const transformNodes = (nodes) => {
  if (!nodes || !Array.isArray(nodes)) return [];
  
  return nodes.map((node, index) => {
    const nodeType = node.type || 'default';
    const style = getNodeStyle(nodeType);
    
    // Calculate position in a grid/tree layout
    const row = Math.floor(index / 3);
    const col = index % 3;
    
    return {
      id: node.id,
      data: { 
        label: (
          <div className="flex flex-col items-center gap-1 px-2 py-1">
            <span className="text-xs opacity-70 uppercase">{nodeType}</span>
            <span className="font-bold text-sm truncate max-w-[150px]" title={node.label}>
              {node.label}
            </span>
          </div>
        )
      },
      position: node.position || { x: 150 + col * 250, y: 50 + row * 150 },
      style: {
        ...style,
        borderRadius: '12px',
        padding: '8px 16px',
        fontSize: '12px',
        fontWeight: 500,
        boxShadow: '0 4px 15px rgba(0,0,0,0.3)',
        minWidth: '120px',
        textAlign: 'center',
      },
    };
  });
};

// Transform backend edges to React Flow format
const transformEdges = (edges) => {
  if (!edges || !Array.isArray(edges)) return [];
  
  return edges.map((edge, index) => ({
    id: edge.id || `edge-${index}`,
    source: edge.source,
    target: edge.target,
    label: edge.label || '',
    animated: edge.animated !== false,
    style: { 
      stroke: edge.style?.stroke || '#64748b',
      strokeWidth: 2,
    },
    labelStyle: {
      fill: '#94a3b8',
      fontSize: 10,
      fontWeight: 500,
    },
    labelBgStyle: {
      fill: '#1e293b',
      fillOpacity: 0.9,
    },
    labelBgPadding: [4, 4],
    labelBgBorderRadius: 4,
  }));
};

const ThreatGraphModal = ({ isOpen, onClose, threatGraph }) => {
  const initialNodes = useMemo(() => transformNodes(threatGraph?.nodes), [threatGraph?.nodes]);
  const initialEdges = useMemo(() => transformEdges(threatGraph?.edges), [threatGraph?.edges]);
  
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const onInit = useCallback((reactFlowInstance) => {
    reactFlowInstance.fitView({ padding: 0.2 });
  }, []);

  if (!isOpen) return null;

  const hasGraphData = nodes.length > 0 || edges.length > 0;

  return (
    <div className="fixed inset-0 bg-black/90 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-cyan-500/30 rounded-xl w-full max-w-6xl h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-white/10 flex justify-between items-center bg-slate-950">
          <h3 className="text-cyan-400 font-bold flex items-center gap-3 text-lg">
            <Network className="w-6 h-6" />
            Attack Chain Visualization
          </h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors p-2 hover:bg-slate-800 rounded-lg"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Legend */}
        <div className="px-4 py-2 bg-slate-950/50 border-b border-white/5 flex flex-wrap gap-4 text-xs">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-blue-500"></div>
            <span className="text-slate-400">User</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <span className="text-slate-400">Phishing URL</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-purple-500"></div>
            <span className="text-slate-400">IP Address</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-amber-500"></div>
            <span className="text-slate-400">ASN/Hosting</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
            <span className="text-slate-400">Registrar</span>
          </div>
        </div>

        {/* Graph Container */}
        <div className="flex-1 bg-slate-950">
          {hasGraphData ? (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onInit={onInit}
              fitView
              attributionPosition="bottom-left"
              minZoom={0.2}
              maxZoom={2}
            >
              <Background color="#334155" gap={20} size={1} />
              <Controls 
                className="!bg-slate-800 !border-slate-700 !shadow-lg"
                showInteractive={false}
              />
              <MiniMap 
                nodeColor={(node) => {
                  const type = node.style?.background?.includes('ef4444') ? 'url' :
                               node.style?.background?.includes('3b82f6') ? 'user' :
                               node.style?.background?.includes('8b5cf6') ? 'ip' :
                               node.style?.background?.includes('f59e0b') ? 'asn' : 'default';
                  const colors = { user: '#3b82f6', url: '#ef4444', ip: '#8b5cf6', asn: '#f59e0b', default: '#6b7280' };
                  return colors[type];
                }}
                maskColor="rgba(0,0,0,0.8)"
                className="!bg-slate-900 !border-slate-700"
              />
            </ReactFlow>
          ) : (
            <div className="h-full flex items-center justify-center text-slate-500">
              <div className="text-center">
                <Network className="w-16 h-16 mx-auto mb-4 opacity-30" />
                <p>No threat graph data available</p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 bg-slate-950 border-t border-white/10 text-xs text-slate-500 text-center">
          Drag nodes to rearrange • Scroll to zoom • Click and drag background to pan
        </div>
      </div>
    </div>
  );
};

export default ThreatGraphModal;
