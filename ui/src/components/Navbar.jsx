import React from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, Activity, Terminal, Network } from 'lucide-react';

export default function Navbar() {
  return (
    <nav style={{
      borderBottom: '1px solid rgba(255,255,255,0.05)',
      background: 'rgba(10, 10, 15, 0.8)',
      backdropFilter: 'blur(10px)',
      position: 'sticky',
      top: 0,
      zIndex: 100
    }}>
      <div className="container" style={{
        height: '70px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Shield color="var(--primary)" size={28} />
          <span style={{ fontSize: '1.2rem', fontWeight: 'bold', letterSpacing: '1px' }}>
            THREAT<span className="text-primary">INTEL</span>.AI
          </span>
        </div>

        <div style={{ display: 'flex', gap: '30px' }}>
          <NavLink
            to="/"
            className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
            style={({ isActive }) => ({
              color: isActive ? 'var(--primary)' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 500
            })}
          >
            <Activity size={18} /> Dashboard
          </NavLink>
          <NavLink
            to="/analyzer"
            className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
            style={({ isActive }) => ({
              color: isActive ? 'var(--primary)' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 500
            })}
          >
            <Terminal size={18} /> Analyzer
          </NavLink>
          <NavLink
            to="/graph"
            className={({ isActive }) => isActive ? "nav-link active" : "nav-link"}
            style={({ isActive }) => ({
              color: isActive ? 'var(--primary)' : 'var(--text-muted)',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontWeight: 500
            })}
          >
            <Network size={18} /> Graph
          </NavLink>
        </div>
      </div>
    </nav>
  );
}
