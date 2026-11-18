import React, { useState, useEffect } from 'react';
import { checkDbHealth } from '../api';

export default function Settings() {
  const [dbStatus, setDbStatus] = useState('checking');
  const [dbMsg, setDbMsg] = useState('');

  useEffect(() => {
    async function checkDb() {
      try {
        const resp = await checkDbHealth();
        setDbStatus(resp.status);
        setDbMsg(resp.message || 'Connected to MongoDB');
      } catch (err) {
        setDbStatus('offline');
        setDbMsg('Database offline. In-memory resilience mode active.');
      }
    }
    checkDb();
  }, []);

  return (
    <div className="settings-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Platform Configuration & System Health</h1>
          <p className="page-subtitle">VTU 7th Semester Information Network and Security (INS) Mini Project</p>
        </div>
      </div>

      <div className="two-column-grid">
        {/* System Health Status */}
        <div className="glass-panel">
          <div className="panel-header">
            <h3 className="panel-title">Component Telemetry Health</h3>
            <span className="badge-pill">Live Status</span>
          </div>

          <div className="health-items-list mt-3">
            <div className="health-item">
              <div className="health-info">
                <span className="health-name">Backend API Server</span>
                <span className="health-desc">Flask 3.0 &bull; RESTful Endpoints</span>
              </div>
              <span className="badge-status status-online">● ONLINE (PORT 5000)</span>
            </div>

            <div className="health-item">
              <div className="health-info">
                <span className="health-name">Heuristic Engine</span>
                <span className="health-desc">10 Heuristic Vector Weights &bull; Zero Execution</span>
              </div>
              <span className="badge-status status-online">● ACTIVE</span>
            </div>

            <div className="health-item">
              <div className="health-info">
                <span className="health-name">Database Subsystem</span>
                <span className="health-desc">MongoDB <code>phishguard.scan_history</code></span>
              </div>
              <span className={`badge-status ${dbStatus === 'connected' ? 'status-online' : 'status-warning'}`}>
                {dbStatus === 'connected' ? '● MONGODB CONNECTED' : '● RESILIENT IN-MEMORY'}
              </span>
            </div>

            <div className="health-item">
              <div className="health-info">
                <span className="health-name">External Threat Feed</span>
                <span className="health-desc">Google Safe Browsing v4 API</span>
              </div>
              <span className="badge-status status-info">OPTIONAL KEY SUPPORT</span>
            </div>
          </div>
        </div>

        {/* Heuristic Thresholds Matrix */}
        <div className="glass-panel">
          <div className="panel-header">
            <h3 className="panel-title">Detection Sensitivity Thresholds</h3>
            <span className="badge-pill">Calibrated</span>
          </div>
          <div className="thresholds-list mt-3">
            <div className="threshold-card border-emerald">
              <div className="threshold-header">
                <span className="text-emerald font-bold">SAFE CLASSIFICATION</span>
                <span className="threshold-score">Score 0 – 2</span>
              </div>
              <p className="threshold-desc">Minimal or standard URL structure. No obvious phishing indicators triggered.</p>
            </div>

            <div className="threshold-card border-amber">
              <div className="threshold-header">
                <span className="text-amber font-bold">SUSPICIOUS CLASSIFICATION</span>
                <span className="threshold-score">Score 3 – 4</span>
              </div>
              <p className="threshold-desc">Multiple anomalous indicators (e.g. shortener + sensitive keywords or unusual TLD).</p>
            </div>

            <div className="threshold-card border-rose">
              <div className="threshold-header">
                <span className="text-rose font-bold">PHISHING CLASSIFICATION</span>
                <span className="threshold-score">Score 5 – 10+</span>
              </div>
              <p className="threshold-desc">High-confidence malicious threat markers detected (brand spoofing, raw IP host, or multiple deceptive vectors).</p>
            </div>
          </div>
        </div>
      </div>

      {/* Project Academic Info */}
      <div className="glass-panel mt-6">
        <h3 className="section-title">Academic Project Credentials</h3>
        <div className="academic-grid mt-4">
          <div>
            <span className="academic-label">PROJECT TITLE</span>
            <div className="academic-val">PhishGuard – Intelligent Phishing URL Detection and Risk Analysis System</div>
          </div>
          <div>
            <span className="academic-label">CURRICULUM</span>
            <div className="academic-val">VTU 7th Semester &bull; Information Network and Security (INS) Mini Project</div>
          </div>
          <div>
            <span className="academic-label">ARCHITECTURE</span>
            <div className="academic-val">Decoupled React 19 Frontend + Python Flask RESTful Microservice + MongoDB Audit Ledger</div>
          </div>
          <div>
            <span className="academic-label">SECURITY DESIGN</span>
            <div className="academic-val">Pure Static URL Heuristics &bull; Zero Browser Execution &bull; QR Code Decode Protection</div>
          </div>
        </div>
      </div>
    </div>
  );
}
