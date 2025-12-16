import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { AlertTriangle, CheckCircle, Clock, Server, ShieldAlert, Globe, FileText, Hash } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api';

export default function Dashboard() {
    const [summaries, setSummaries] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchSummaries();
        const interval = setInterval(fetchSummaries, 8000);
        return () => clearInterval(interval);
    }, []);

    const fetchSummaries = async () => {
        try {
            const res = await axios.get(`${API_BASE}/summaries?limit=50`);
            if (res.data.summaries) {
                setSummaries(res.data.summaries);
            }
        } catch (err) {
            console.error("Failed to fetch summaries", err);
        } finally {
            setLoading(false);
        }
    };

    const getIconForInput = (input) => {
        if (input.includes('http')) return <Globe size={16} />;
        if (input.match(/^\d+\.\d+\.\d+\.\d+/)) return <Server size={16} />;
        if (input.length > 30 && !input.includes(' ')) return <Hash size={16} />;
        return <FileText size={16} />;
    };

    const SeverityBadge = ({ severity }) => {
        const cls = `badge badge-${severity?.toLowerCase() || 'low'}`;
        return (
            <span className={cls}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor', boxShadow: '0 0 8px currentColor' }}></span>
                {severity}
            </span>
        );
    };

    if (loading && summaries.length === 0) {
        return (
            <div className="container" style={{ padding: '100px', textAlign: 'center', color: 'var(--text-muted)' }}>
                <div className="spin" style={{ display: 'inline-block', marginBottom: 20 }}>
                    <Server size={32} color="var(--primary)" />
                </div>
                <p>Establishing secure connection to threat feed...</p>
            </div>
        );
    }

    return (
        <div className="container" style={{ padding: '60px 20px' }}>
            <header style={{ marginBottom: '50px', display: 'flex', justifyContent: 'space-between', alignItems: 'end' }}>
                <div>
                    <h1 className="glow-text" style={{ fontSize: '3rem', margin: '0 0 10px 0', letterSpacing: '-1px' }}>Threat Monitor</h1>
                    <p style={{ color: 'var(--text-muted)', maxWidth: '600px', lineHeight: '1.5' }}>
                        Live intelligence feed monitoring global IOCs. Powered by <span style={{ color: 'var(--primary)' }}>Llama 3.2</span> AI analysis.
                    </p>
                </div>
                <div className="glass-panel" style={{ padding: '15px 25px', display: 'flex', gap: '20px' }}>
                    <div style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>Monitored</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--text-main)' }}>{summaries.length}</div>
                    </div>
                    <div style={{ width: 1, background: 'var(--border-color)' }}></div>
                    <div style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>High Risk</div>
                        <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--danger)' }}>
                            {summaries.filter(s => s.severity === 'High').length}
                        </div>
                    </div>
                </div>
            </header>

            <div style={{ display: 'grid', gap: '20px' }}>
                {summaries.map((item, idx) => (
                    <div
                        key={idx}
                        className="card animate-fade-in"
                        style={{
                            animationDelay: `${idx * 0.05}s`,
                            borderLeft: item.severity === 'High' ? '4px solid var(--danger)' : '1px solid var(--border-color)'
                        }}
                    >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
                            <div style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
                                <div style={{
                                    background: 'rgba(255,255,255,0.05)',
                                    padding: '10px',
                                    borderRadius: '10px',
                                    color: 'var(--primary)'
                                }}>
                                    {getIconForInput(item.input)}
                                </div>
                                <div>
                                    <div className="mono" style={{ fontSize: '1.1rem', color: 'var(--text-main)', marginBottom: '4px' }}>
                                        {item.input}
                                    </div>
                                    <div style={{ display: 'flex', gap: '15px', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                                        <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                                            <Clock size={12} /> {new Date(item.timestamp).toLocaleTimeString()}
                                        </span>
                                        {item.corrected && (
                                            <span style={{ display: 'flex', alignItems: 'center', gap: '5px', color: 'var(--success)' }}>
                                                <CheckCircle size={12} /> Auto-Verified
                                            </span>
                                        )}
                                    </div>
                                </div>
                            </div>
                            <SeverityBadge severity={item.severity} />
                        </div>

                        <div style={{
                            lineHeight: '1.7',
                            color: '#d0d0e0',
                            whiteSpace: 'pre-line',
                            fontSize: '0.95rem',
                            paddingLeft: '56px' // align with text above
                        }}>
                            {item.summary}
                        </div>
                    </div>
                ))}

                {summaries.length === 0 && (
                    <div className="glass-panel" style={{ textAlign: 'center', padding: '80px', color: 'var(--text-muted)' }}>
                        <ShieldAlert size={48} style={{ marginBottom: '20px', opacity: 0.3 }} />
                        <p style={{ fontSize: '1.2rem' }}>No active threats detected in the feed.</p>
                    </div>
                )}
            </div>
        </div>
    );
}
