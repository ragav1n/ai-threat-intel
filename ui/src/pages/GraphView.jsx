import React, { useState, useEffect, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import axios from 'axios';
import { Loader, X, ShieldAlert, FileText, Globe, Server, Hash } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api';

export default function GraphView() {
    const [data, setData] = useState({ nodes: [], links: [] });
    const [loading, setLoading] = useState(true);
    const [selectedNode, setSelectedNode] = useState(null);
    const graphRef = useRef();

    useEffect(() => {
        fetchGraphData();
    }, []);

    const fetchGraphData = async () => {
        try {
            const res = await axios.get(`${API_BASE}/summaries?limit=100`);
            const summaries = res.data.summaries || [];

            const nodes = [];
            const links = [];

            // We will link nodes based on shared KEYWORDS to find "Campaigns"
            const keywords = ['phishing', 'ransomware', 'malware', 'botnet', 'ddos', 'apt', 'c2'];
            const keywordGroups = {};

            summaries.forEach((s) => {
                // Threat Node
                nodes.push({
                    id: s.input,
                    group: s.severity,
                    val: s.severity === 'High' ? 15 : 8,
                    fullData: s
                });

                // Link by Severity (Cluster high priorities)
                if (s.severity === 'High') {
                    const sevId = 'CLUSTER_HIGH_RISK';
                    if (!nodes.find(n => n.id === sevId)) {
                        nodes.push({ id: sevId, group: 'META', val: 20, label: 'HIGH RISK ZONE' });
                    }
                    links.push({ source: sevId, target: s.input });
                }

                // Link by Content Keywords (The "Intelligence" part)
                const lowerSummary = s.summary.toLowerCase();
                keywords.forEach(kw => {
                    if (lowerSummary.includes(kw)) {
                        if (!keywordGroups[kw]) keywordGroups[kw] = [];
                        keywordGroups[kw].push(s.input);
                    }
                });
            });

            // Create links for keyword clusters (Campaign detection)
            Object.entries(keywordGroups).forEach(([kw, inputs]) => {
                if (inputs.length > 1) {
                    const tagId = `TAG_${kw.toUpperCase()}`;
                    nodes.push({ id: tagId, group: 'TAG', val: 10, label: kw.toUpperCase() });

                    inputs.forEach(input => {
                        links.push({ source: tagId, target: input });
                    });
                }
            });

            // Dedup nodes
            const uniqueNodes = Array.from(new Map(nodes.map(node => [node.id, node])).values());

            setData({ nodes: uniqueNodes, links });
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const getNodeColor = (node) => {
        if (node.group === 'META') return '#ff0055'; // High risk hub
        if (node.group === 'TAG') return '#00f3ff';  // Keywords
        if (node.group === 'High') return '#ff4444';
        if (node.group === 'Medium') return '#ffaa00';
        if (node.group === 'Low') return '#00ff9d';
        return '#888';
    };

    const getNodeLabel = (node) => {
        return node.label || node.id;
    }

    if (loading) return <div className="container" style={{ padding: 50, textAlign: 'center' }}><Loader className="spin" /> Loading Intelligence Network...</div>;

    return (
        <div style={{
            height: 'calc(100vh - 70px)',
            background: '#050508',
            backgroundImage: `
          radial-gradient(circle at 50% 50%, rgba(112, 0, 255, 0.2), transparent 60%),
          linear-gradient(rgba(0, 243, 255, 0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0, 243, 255, 0.03) 1px, transparent 1px)
        `,
            backgroundSize: '100% 100%, 30px 30px, 30px 30px',
            position: 'relative',
            overflow: 'hidden'
        }}>
            <ForceGraph2D
                ref={graphRef}
                graphData={data}
                nodeLabel={getNodeLabel}
                nodeColor={getNodeColor}
                nodeRelSize={6}
                linkColor={() => 'rgba(255,255,255,0.15)'}
                backgroundColor="rgba(0,0,0,0)"
                onNodeClick={node => {
                    if (node.fullData) {
                        setSelectedNode(node.fullData);
                        // Focus camera
                        graphRef.current.centerAt(node.x, node.y, 1000);
                        graphRef.current.zoom(6, 2000);
                    }
                }}
                nodeCanvasObject={(node, ctx, globalScale) => {
                    const label = node.label || node.id;
                    const fontSize = 12 / globalScale;
                    ctx.font = `${fontSize}px Sans-Serif`;
                    const textWidth = ctx.measureText(label).width;
                    const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

                    ctx.fillStyle = 'rgba(0, 0, 0, 0.8)';
                    if (node.group === 'META' || node.group === 'TAG') {
                        ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, ...bckgDimensions);
                    }

                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = getNodeColor(node);
                    ctx.fillText(label, node.x, node.y);

                    node.__bckgDimensions = bckgDimensions; // to re-use in nodePointerAreaPaint
                }}
            />

            {/* --- INSTRUCTION OVERLAY --- */}
            {!selectedNode && (
                <div style={{ position: 'absolute', top: 20, left: 20, pointerEvents: 'none' }}>
                    <div className="glass-panel" style={{ padding: '15px 25px' }}>
                        <h3 style={{ margin: '0 0 5px 0', color: 'var(--primary)' }}>Intelligence Graph</h3>
                        <p style={{ margin: 0, fontSize: '0.9rem', color: '#aaa' }}>
                            Click on any node to view full threat details.<br />
                            Clusters indicate shared campaign attributes.
                        </p>
                    </div>
                </div>
            )}

            {/* --- DETAIL SIDEBAR --- */}
            {selectedNode && (
                <div className="animate-fade-in" style={{
                    position: 'absolute',
                    top: 20,
                    right: 20,
                    width: '400px',
                    maxHeight: 'calc(100vh - 110px)',
                    overflowY: 'auto',
                    zIndex: 10
                }}>
                    <div className="glass-panel" style={{ padding: '25px', border: '1px solid var(--primary)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '15px' }}>
                            <h2 className="mono" style={{ margin: 0, fontSize: '1.2rem', wordBreak: 'break-all', color: 'var(--primary)' }}>
                                {selectedNode.input}
                            </h2>
                            <button
                                onClick={() => setSelectedNode(null)}
                                style={{ background: 'none', border: 'none', color: '#fff', cursor: 'pointer' }}
                            >
                                <X size={20} />
                            </button>
                        </div>

                        <div style={{ marginBottom: '20px', display: 'flex', gap: '10px' }}>
                            <span className={`badge badge-${selectedNode.severity.toLowerCase()}`}>
                                {selectedNode.severity}
                            </span>
                            <span style={{ fontSize: '0.8rem', color: '#888', display: 'flex', alignItems: 'center' }}>
                                {new Date(selectedNode.timestamp).toLocaleString()}
                            </span>
                        </div>

                        <div style={{ lineHeight: '1.6', fontSize: '0.95rem', color: '#ddd', whiteSpace: 'pre-wrap' }}>
                            {selectedNode.summary}
                        </div>

                        <div style={{ marginTop: '20px', paddingTop: '20px', borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                            <h4 style={{ margin: '0 0 10px 0', color: '#aaa' }}>Quick Actions</h4>
                            <div style={{ display: 'flex', gap: '10px' }}>
                                <button className="btn" style={{ fontSize: '0.8rem', padding: '8px 12px', background: '#333' }}>
                                    Copy IOC
                                </button>
                                <button className="btn" style={{ fontSize: '0.8rem', padding: '8px 12px' }}>
                                    Generate Report
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
