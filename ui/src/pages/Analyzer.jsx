import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import { Send, Terminal, Loader, Zap } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api';

const TypingEffect = ({ text, speed = 10 }) => {
    const [displayed, setDisplayed] = useState('');

    useEffect(() => {
        let i = 0;
        setDisplayed('');
        const timer = setInterval(() => {
            setDisplayed(text.slice(0, i + 1));
            i++;
            if (i > text.length) clearInterval(timer);
        }, speed);
        return () => clearInterval(timer);
    }, [text]);

    return <span>{displayed}</span>;
}

export default function Analyzer() {
    const [history, setHistory] = useState([
        { role: 'system', content: 'ENTER IOC OR DESCRIPTION BELOW.', anim: true }
    ]);
    const [input, setInput] = useState('');
    const [processing, setProcessing] = useState(false);
    const bottomRef = useRef(null);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [history]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!input.trim() || processing) return;

        const userCmd = input;
        setInput('');
        setProcessing(true);

        setHistory(prev => [...prev, { role: 'user', content: userCmd }]);

        try {
            const res = await axios.post(`${API_BASE}/summarize`, {
                ioc: userCmd,
                model: "llama3.2:latest"
            });

            const data = res.data;
            const formattedResponse = `
[ANALYSIS COMPLETE]
► SEVERITY: ${data.severity.toUpperCase()} ${data.corrected ? '(AUTO-CORRECTED)' : ''}
► TIME: ${data.timestamp}

${data.summary}
      `.trim();

            setHistory(prev => [...prev, {
                role: 'system',
                content: formattedResponse,
                severity: data.severity,
                anim: true
            }]);

        } catch (err) {
            setHistory(prev => [...prev, { role: 'error', content: `EXECUTION ERROR: ${err.message}`, anim: true }]);
        } finally {
            setProcessing(false);
        }
    };

    return (
        <div className="container" style={{ height: 'calc(100vh - 80px)', display: 'flex', flexDirection: 'column', paddingTop: '30px', paddingBottom: '30px' }}>

            <div className="glass-panel" style={{
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                padding: 0,
                overflow: 'hidden',
                background: 'rgba(5, 5, 8, 0.9)',
                backgroundImage: `
          linear-gradient(rgba(0, 243, 255, 0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0, 243, 255, 0.03) 1px, transparent 1px)
        `,
                backgroundSize: '30px 30px',
                boxShadow: '0 20px 50px rgba(0,0,0,0.5)',
                border: '1px solid rgba(0, 243, 255, 0.2)'
            }}>
                <div style={{
                    padding: '12px 20px',
                    background: 'rgba(0, 243, 255, 0.05)',
                    borderBottom: '1px solid rgba(0, 243, 255, 0.1)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    fontSize: '0.8rem',
                    color: 'var(--primary)',
                    letterSpacing: '1px'
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <Terminal size={14} />
                        <span className="mono">SECURE_SHELL // THREAT_ANALYZER</span>
                    </div>
                    <div style={{ display: 'flex', gap: '6px' }}>
                        <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ff5f56' }}></div>
                        <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ffbd2e' }}></div>
                        <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#27c93f' }}></div>
                    </div>
                </div>

                <div style={{ flex: 1, padding: '30px', overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: '1rem' }}>
                    {history.map((msg, i) => (
                        <div key={i} style={{ marginBottom: '20px', lineHeight: '1.6' }}>
                            {msg.role === 'user' && (
                                <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                                    <span style={{ color: 'var(--success)' }}>➜</span>
                                    <span style={{ color: '#fff' }}>{msg.content}</span>
                                </div>
                            )}

                            {msg.role === 'system' && (
                                <div style={{
                                    marginLeft: '25px',
                                    whiteSpace: 'pre-wrap',
                                    color: msg.severity === 'High' ? '#ffaabb' : 'var(--text-muted)',
                                    borderLeft: msg.severity ? `2px solid ${msg.severity === 'High' ? 'var(--danger)' : 'var(--success)'}` : 'none',
                                    paddingLeft: msg.severity ? '15px' : '0'
                                }}>
                                    {msg.anim ? <TypingEffect text={msg.content} speed={5} /> : msg.content}
                                </div>
                            )}

                            {msg.role === 'error' && (
                                <div style={{ marginLeft: '25px', color: 'var(--danger)' }}>
                                    <TypingEffect text={msg.content} />
                                </div>
                            )}
                        </div>
                    ))}

                    {processing && (
                        <div style={{ marginLeft: '25px', color: 'var(--primary)', display: 'flex', alignItems: 'center', gap: '10px', marginTop: '10px' }}>
                            <Zap className="pulse-red" size={16} />
                            <span>ANALYZING SIGNATURE...</span>
                        </div>
                    )}
                    <div ref={bottomRef} />
                </div>

                <div style={{ padding: '20px', background: 'rgba(0,0,0,0.3)', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                    <form onSubmit={handleSubmit} style={{ position: 'relative' }}>
                        <input
                            type="text"
                            className="input-glow mono"
                            autoFocus
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            placeholder="Enter IOC hash, IP, or description..."
                            style={{ paddingRight: '50px', background: 'rgba(0,0,0,0.5)' }}
                        />
                        <button
                            type="submit"
                            style={{
                                position: 'absolute',
                                right: '10px',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                background: 'transparent',
                                border: 'none',
                                color: input.trim() ? 'var(--primary)' : '#444',
                                cursor: 'pointer',
                                transition: 'color 0.2s'
                            }}
                            disabled={!input.trim()}
                        >
                            <Send size={20} />
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}
