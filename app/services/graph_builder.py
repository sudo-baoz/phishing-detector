"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

"""
Threat Graph Builder Service
Generates React Flow compatible graph data for visual threat analysis
"""

import logging
import hashlib
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ThreatGraphBuilder:
    """
    Builds visual threat graph data compatible with React Flow.
    Nodes represent entities (URLs, IPs, ASNs), edges represent relationships.
    """
    
    # Node type colors (React Flow compatible)
    NODE_COLORS = {
        'user': '#3B82F6',           # Blue - User/Origin
        'shortener': '#F59E0B',      # Amber - URL Shorteners
        'phishing': '#EF4444',       # Red - Phishing URLs
        'safe': '#10B981',           # Green - Safe URLs
        'suspicious': '#F97316',     # Orange - Suspicious URLs
        'server': '#6366F1',         # Indigo - Server/IP
        'asn': '#8B5CF6',            # Purple - ASN Provider
        'dns': '#06B6D4',            # Cyan - DNS
        'registrar': '#EC4899',      # Pink - Registrar
    }
    
    # Known URL shorteners
    SHORTENERS = {
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'short.link', 'rebrand.ly', 'cutt.ly'
    }
    
    def __init__(self):
        self.node_id_counter = 0
        
    def _generate_node_id(self, prefix: str = "node") -> str:
        """Generate unique node ID"""
        self.node_id_counter += 1
        return f"{prefix}_{self.node_id_counter}"
    
    def _hash_id(self, value: str) -> str:
        """Generate consistent hash-based ID for deduplication"""
        return hashlib.md5(value.encode()).hexdigest()[:8]
    
    def _is_shortener(self, url: str) -> bool:
        """Check if URL is from a known shortener"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
            return domain in self.SHORTENERS
        except Exception:
            return False
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or url
        except Exception:
            return url
    
    def build_threat_graph(
        self,
        url: str,
        redirect_chain: Optional[List[str]] = None,
        dns_data: Optional[Dict[str, Any]] = None,
        deep_tech_data: Optional[Dict[str, Any]] = None,
        is_phishing: bool = False,
        confidence_score: float = 0.0
    ) -> Dict[str, Any]:
        """
        Build React Flow compatible threat graph.
        
        Args:
            url: Original scanned URL
            redirect_chain: List of URLs in redirect chain
            dns_data: DNS/OSINT data (IP, ASN, registrar, etc.)
            deep_tech_data: Technical analysis data
            is_phishing: Whether URL is flagged as phishing
            confidence_score: Confidence score (0-100)
            
        Returns:
            Dict with nodes and edges arrays for React Flow
        """
        self.node_id_counter = 0
        nodes = []
        edges = []
        
        try:
            # ===== NODE 1: User/Origin =====
            user_node_id = "user_origin"
            nodes.append({
                "id": user_node_id,
                "type": "input",
                "data": {
                    "label": "🔍 Scanner",
                    "description": "Scan initiated"
                },
                "position": {"x": 0, "y": 0},
                "style": {
                    "background": self.NODE_COLORS['user'],
                    "color": "white",
                    "border": "2px solid #1E40AF",
                    "borderRadius": "8px",
                    "padding": "10px"
                }
            })
            
            # ===== NODE 2+: Redirect Chain =====
            previous_node_id = user_node_id
            x_position = 200
            
            if redirect_chain and len(redirect_chain) > 0:
                for i, redirect_url in enumerate(redirect_chain):
                    is_shortener = self._is_shortener(redirect_url)
                    is_final = (i == len(redirect_chain) - 1)
                    
                    # Determine node type and color
                    if is_shortener:
                        node_type = 'shortener'
                        icon = "🔗"
                    elif is_final and is_phishing:
                        node_type = 'phishing'
                        icon = "⚠️"
                    elif is_final and confidence_score > 50:
                        node_type = 'suspicious'
                        icon = "❓"
                    else:
                        node_type = 'safe'
                        icon = "✅"
                    
                    domain = self._extract_domain(redirect_url)
                    node_id = f"url_{self._hash_id(redirect_url)}"
                    
                    nodes.append({
                        "id": node_id,
                        "type": "default",
                        "data": {
                            "label": f"{icon} {domain[:30]}{'...' if len(domain) > 30 else ''}",
                            "url": redirect_url,
                            "isShortener": is_shortener,
                            "isFinal": is_final,
                            "step": i + 1
                        },
                        "position": {"x": x_position, "y": i * 100},
                        "style": {
                            "background": self.NODE_COLORS[node_type],
                            "color": "white",
                            "border": f"2px solid {self.NODE_COLORS[node_type]}",
                            "borderRadius": "8px",
                            "padding": "10px",
                            "minWidth": "150px"
                        }
                    })
                    
                    # Edge from previous node
                    edges.append({
                        "id": f"edge_{previous_node_id}_{node_id}",
                        "source": previous_node_id,
                        "target": node_id,
                        "label": "Redirects to" if i > 0 else "Requests",
                        "animated": is_phishing and is_final,
                        "style": {
                            "stroke": self.NODE_COLORS['phishing'] if is_phishing else "#6B7280"
                        },
                        "labelStyle": {"fontSize": "10px"}
                    })
                    
                    previous_node_id = node_id
                    x_position += 50
            else:
                # No redirect chain - just the original URL
                domain = self._extract_domain(url)
                node_type = 'phishing' if is_phishing else ('suspicious' if confidence_score > 50 else 'safe')
                icon = "⚠️" if is_phishing else ("❓" if confidence_score > 50 else "✅")
                
                url_node_id = f"url_{self._hash_id(url)}"
                nodes.append({
                    "id": url_node_id,
                    "type": "default",
                    "data": {
                        "label": f"{icon} {domain[:30]}{'...' if len(domain) > 30 else ''}",
                        "url": url,
                        "isFinal": True
                    },
                    "position": {"x": 200, "y": 0},
                    "style": {
                        "background": self.NODE_COLORS[node_type],
                        "color": "white",
                        "borderRadius": "8px",
                        "padding": "10px"
                    }
                })
                
                edges.append({
                    "id": f"edge_{user_node_id}_{url_node_id}",
                    "source": user_node_id,
                    "target": url_node_id,
                    "label": "Scans",
                    "animated": is_phishing
                })
                
                previous_node_id = url_node_id
            
            # ===== INFRASTRUCTURE NODES (DNS/OSINT Data) =====
            infra_y = 200
            
            if dns_data:
                # Server IP Node
                server_ip = dns_data.get('ip') or dns_data.get('server_ip')
                if server_ip:
                    ip_node_id = f"ip_{self._hash_id(server_ip)}"
                    nodes.append({
                        "id": ip_node_id,
                        "type": "default",
                        "data": {
                            "label": f"🖥️ {server_ip}",
                            "type": "server",
                            "ip": server_ip
                        },
                        "position": {"x": 400, "y": infra_y},
                        "style": {
                            "background": self.NODE_COLORS['server'],
                            "color": "white",
                            "borderRadius": "8px",
                            "padding": "10px"
                        }
                    })
                    
                    edges.append({
                        "id": f"edge_{previous_node_id}_{ip_node_id}",
                        "source": previous_node_id,
                        "target": ip_node_id,
                        "label": "Hosted on",
                        "style": {"stroke": "#6366F1"}
                    })
                    
                    # ASN Provider Node
                    asn = dns_data.get('asn') or dns_data.get('asn_description')
                    if asn:
                        asn_node_id = f"asn_{self._hash_id(str(asn))}"
                        nodes.append({
                            "id": asn_node_id,
                            "type": "output",
                            "data": {
                                "label": f"🌐 {str(asn)[:25]}{'...' if len(str(asn)) > 25 else ''}",
                                "type": "asn",
                                "asn": asn
                            },
                            "position": {"x": 600, "y": infra_y},
                            "style": {
                                "background": self.NODE_COLORS['asn'],
                                "color": "white",
                                "borderRadius": "8px",
                                "padding": "10px"
                            }
                        })
                        
                        edges.append({
                            "id": f"edge_{ip_node_id}_{asn_node_id}",
                            "source": ip_node_id,
                            "target": asn_node_id,
                            "label": "Managed by",
                            "style": {"stroke": "#8B5CF6"}
                        })
                
                # Registrar Node
                registrar = dns_data.get('registrar')
                if registrar:
                    reg_node_id = f"reg_{self._hash_id(registrar)}"
                    nodes.append({
                        "id": reg_node_id,
                        "type": "output",
                        "data": {
                            "label": f"📋 {registrar[:20]}{'...' if len(registrar) > 20 else ''}",
                            "type": "registrar",
                            "registrar": registrar
                        },
                        "position": {"x": 400, "y": infra_y + 100},
                        "style": {
                            "background": self.NODE_COLORS['registrar'],
                            "color": "white",
                            "borderRadius": "8px",
                            "padding": "10px"
                        }
                    })
                    
                    edges.append({
                        "id": f"edge_{previous_node_id}_{reg_node_id}",
                        "source": previous_node_id,
                        "target": reg_node_id,
                        "label": "Registered with",
                        "style": {"stroke": "#EC4899", "strokeDasharray": "5,5"}
                    })
            
            # ===== Add Technical Risk Indicators =====
            if deep_tech_data and is_phishing:
                risk_score = deep_tech_data.get('technical_risk_score', 0)
                if risk_score > 50:
                    risk_node_id = "risk_indicator"
                    nodes.append({
                        "id": risk_node_id,
                        "type": "output",
                        "data": {
                            "label": f"🚨 Risk: {risk_score}%",
                            "type": "risk",
                            "score": risk_score
                        },
                        "position": {"x": 0, "y": 150},
                        "style": {
                            "background": "#DC2626",
                            "color": "white",
                            "borderRadius": "50%",
                            "padding": "15px",
                            "fontWeight": "bold"
                        }
                    })
            
            logger.info(f"[GraphBuilder] Built graph with {len(nodes)} nodes and {len(edges)} edges")
            
            return {
                "nodes": nodes,
                "edges": edges,
                "metadata": {
                    "total_nodes": len(nodes),
                    "total_edges": len(edges),
                    "is_phishing": is_phishing,
                    "confidence_score": confidence_score
                }
            }
            
        except Exception as e:
            logger.error(f"[GraphBuilder] Failed to build threat graph: {e}")
            return {
                "nodes": [],
                "edges": [],
                "error": str(e)
            }


# Singleton instance
graph_builder = ThreatGraphBuilder()


def build_threat_graph(
    url: str,
    redirect_chain: Optional[List[str]] = None,
    dns_data: Optional[Dict[str, Any]] = None,
    deep_tech_data: Optional[Dict[str, Any]] = None,
    is_phishing: bool = False,
    confidence_score: float = 0.0
) -> Dict[str, Any]:
    """
    Convenience function to build threat graph.
    
    Returns React Flow compatible graph data.
    """
    return graph_builder.build_threat_graph(
        url, redirect_chain, dns_data, deep_tech_data, is_phishing, confidence_score
    )
