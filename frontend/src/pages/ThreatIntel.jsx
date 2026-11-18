import React, { useState, useEffect } from 'react';
import { analyze, getThreatIntelStatus } from '../api';

export default function ThreatIntel() {
  const [probeUrl, setProbeUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [probeResult, setProbeResult] = useState(null);
  const [apiStatus, setApiStatus] = useState(null);
  const [statusLoading, setStatusLoading] = useState(true);

  useEffect(() => {
    async function loadApiStatus() {
      try {
        setStatusLoading(true);
        const data = await getThreatIntelStatus();
        setApiStatus(data);
      } catch (err) {
        console.error("API status check error", err);
        setApiStatus({ configured: false, status: 'unavailable', message: err.message });
      } finally {
        setStatusLoading(false);
      }
    }
    loadApiStatus();
  }, []);

  const handleProbe = async (targetUrl = probeUrl) => {
    const scanTarget = (typeof targetUrl === 'string' ? targetUrl : probeUrl).trim();
    if (!scanTarget) return;
    setLoading(true);
    try {
      const data = await analyze(scanTarget);
      setProbeResult(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const isConnected = apiStatus?.configured || apiStatus?.status === 'connected';

  return (
    <div className="threat-intel-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat Intelligence Correlation</h1>
          <p className="page-subtitle">Multi-layered defense: Deep Heuristic Analysis + Global Threat Intelligence Feeds</p>
        </div>
      </div>

      {/* Live API Status Banner */}
      <div className={`glass-panel mb-6 border-${isConnected ? 'emerald' : 'amber'}`}>
        <div className="panel-header">
          <div className="flex items-center gap-3">
            <span className={`pulse-dot ${isConnected ? 'bg-emerald' : 'bg-amber'}`} />
            <div>
              <h3 className="panel-title" style={{ fontSize: '1.05rem', margin: 0 }}>
                Google Safe Browsing v4 Threat Match Feed
              </h3>
              <p className="panel-sub">
                {isConnected
                  ? `Connected & Active • Key: ${apiStatus.api_key_masked || 'Configured in backend/.env'}`
                  : 'API Key Unconfigured • Heuristics operating independently'}
              </p>
            </div>
          </div>
          <span className={`badge-pill ${isConnected ? 'pill-safe' : 'pill-suspicious'}`}>
            {isConnected ? 'LIVE FEED CONNECTED' : 'OFFLINE FALLBACK'}
          </span>
        </div>

        <div className="metrics-grid mt-3" style={{ marginBottom: 0 }}>
          <div className="metric-card" style={{ padding: '14px' }}>
            <span className="metric-label">FEED PROVIDER</span>
            <div style={{ fontSize: '1rem', fontWeight: 'bold', color: '#fff', marginTop: '4px' }}>
              Google Safe Browsing API
            </div>
            <span className="text-cyan text-xs">v4 Lookup API</span>
          </div>

          <div className="metric-card" style={{ padding: '14px' }}>
            <span className="metric-label">MONITORED THREAT TYPES</span>
            <div style={{ fontSize: '0.85rem', fontWeight: '600', color: '#cbd5e1', marginTop: '4px' }}>
              Malware &bull; Social Engineering &bull; Harmful Apps
            </div>
            <span className="text-emerald text-xs">Multi-Threat Protection</span>
          </div>

          <div className="metric-card" style={{ padding: '14px' }}>
            <span className="metric-label">INDEPENDENT HEURISTIC SHIELD</span>
            <div style={{ fontSize: '1rem', fontWeight: 'bold', color: '#10b981', marginTop: '4px' }}>
              100% Autonomous
            </div>
            <span className="text-emerald text-xs">Zero Dependency Local Engine</span>
          </div>
        </div>
      </div>

      {/* Intelligence Architecture Diagram Card */}
      <div className="glass-panel">
        <h3 className="section-title">
          <span className="text-cyan">⚙</span> Dual-Engine Inspection Pipeline
        </h3>
        <p className="section-subtitle">
          PhishGuard combines a high-speed zero-dependency rule engine with Google Safe Browsing API correlation.
        </p>

        <div className="pipeline-grid mt-4">
          <div className="pipeline-node node-input">
            <span className="node-num">1</span>
            <h4>Input Ingestion</h4>
            <p>Single URL, CSV batch, or QR code image decoded safely without execution</p>
          </div>
          <div className="pipeline-node node-heuristic">
            <span className="node-num">2</span>
            <h4>Autonomous Heuristic Engine</h4>
            <p>10 weighted lexical and structural rules (brand spoofing, IP hosts, suspicious TLDs, hex paths)</p>
          </div>
          <div className="pipeline-node node-api">
            <span className="node-num">3</span>
            <h4>Global Threat Feeds</h4>
            <p>Google Safe Browsing v4 threat match lookup (malware, social engineering, harmful software)</p>
          </div>
          <div className="pipeline-node node-output">
            <span className="node-num">4</span>
            <h4>Unified Verdict & Audit</h4>
            <p>Explainable risk gauge (0-100), automated audit trail in MongoDB, printable PDF reports</p>
          </div>
        </div>
      </div>

      {/* Live Side-by-Side Correlation Tool */}
      <div className="glass-panel mt-6">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">Live Engine Comparison Test</h3>
            <p className="panel-sub">Observe how Heuristic rules and External API results are evaluated independently</p>
          </div>
        </div>

        <form onSubmit={(e) => { e.preventDefault(); handleProbe(); }} className="quick-scan-form mt-2">
          <div className="input-with-icon">
            <svg className="url-input-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <input
              type="text"
              className="quick-input"
              placeholder="Test a URL (or pick a sample below)..."
              value={probeUrl}
              onChange={(e) => setProbeUrl(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-scan" disabled={loading}>
            {loading ? 'Correlating...' : 'Compare Engines'}
          </button>
        </form>

        {/* Quick Correlation Test Presets */}
        <div className="test-presets mt-3">
          <span className="presets-label">Quick Test Feeds:</span>
          <button
            type="button"
            className="preset-pill text-rose"
            onClick={() => {
              const u = 'http://malware.testing.google.test/testing/malware/';
              setProbeUrl(u);
              handleProbe(u);
            }}
          >
            Google Safe Browsing Malware Test URL
          </button>
          <button
            type="button"
            className="preset-pill"
            onClick={() => {
              const u = 'https://google.com';
              setProbeUrl(u);
              handleProbe(u);
            }}
          >
            Safe Site (google.com)
          </button>
          <button
            type="button"
            className="preset-pill text-amber"
            onClick={() => {
              const u = 'https://secure-login.portal-update.xyz/verify';
              setProbeUrl(u);
              handleProbe(u);
            }}
          >
            Heuristic Suspicious URL
          </button>
        </div>

        {probeResult && (
          <div className="engine-comparison-grid mt-6">
            {/* Heuristic Column */}
            <div className="engine-card heuristic-side">
              <div className="engine-card-header">
                <span className="engine-pill">Primary Engine</span>
                <h4>PhishGuard Rule Heuristics</h4>
              </div>
              <div className="engine-metrics">
                <div>
                  <span className="em-label">Verdict</span>
                  <span className={`verdict-badge ${probeResult.verdict?.toLowerCase()}`}>
                    {probeResult.verdict}
                  </span>
                </div>
                <div>
                  <span className="em-label">Calculated Score</span>
                  <span className="em-val">{probeResult.score} / 10</span>
                </div>
              </div>
              <div className="engine-details mt-3">
                <span className="em-label">Triggered Heuristics ({probeResult.triggered_rules?.length || 0})</span>
                {probeResult.triggered_rules?.length ? (
                  <ul className="engine-rules-list">
                    {probeResult.triggered_rules.map((r, i) => (
                      <li key={i}>{r.name} (+{r.weight})</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-emerald text-sm">No heuristic indicators triggered.</p>
                )}
              </div>
            </div>

            {/* External Safe Browsing Column */}
            <div className="engine-card api-side">
              <div className="engine-card-header">
                <span className="engine-pill pill-violet">External API</span>
                <h4>Google Safe Browsing v4</h4>
              </div>
              <div className="engine-metrics">
                <div>
                  <span className="em-label">API Status</span>
                  <span className="em-val text-cyan">
                    {probeResult.google_safe_browsing?.status === 'connected' || isConnected
                      ? '● CONNECTED'
                      : 'Unconfigured / Offline'}
                  </span>
                </div>
                <div>
                  <span className="em-label">Threat Matches</span>
                  <span className={`em-val ${probeResult.google_safe_browsing?.matches?.length ? 'text-rose' : 'text-emerald'}`}>
                    {probeResult.google_safe_browsing?.matches?.length || 0}
                  </span>
                </div>
              </div>
              <div className="engine-details mt-3">
                <span className="em-label">API Correlation Note</span>
                <p className="text-sm text-slate">
                  {probeResult.google_safe_browsing?.matches?.length ? (
                    <span className="text-rose">
                      🚨 Google Safe Browsing Flagged This URL! Threat type: {probeResult.google_safe_browsing.matches.map(m => m.threatType).join(', ')}
                    </span>
                  ) : (
                    <span className="text-emerald">
                      ✓ Google Safe Browsing verified: No active blacklist matches found for this URL.
                    </span>
                  )}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Threat Taxonomy Reference */}
      <div className="glass-panel mt-6">
        <h3 className="section-title">Heuristic Feature Taxonomy & Weight Matrix</h3>
        <div className="taxonomy-table-wrapper mt-3">
          <table className="threats-table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Indicator Name</th>
                <th>Weight</th>
                <th>Attack Vector Detected</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><code>brand_spoof</code></td>
                <td>Brand Impersonation / Typosquatting</td>
                <td><span className="score-pill score-phishing">+3</span></td>
                <td>Social engineering simulating PayPal, Google, Microsoft, Apple, or Bank portals</td>
              </tr>
              <tr>
                <td><code>ip_host</code></td>
                <td>Raw IPv4 Host Address</td>
                <td><span className="score-pill score-phishing">+3</span></td>
                <td>Bypassing domain registration controls and reputation watchlists</td>
              </tr>
              <tr>
                <td><code>suspicious_tld</code></td>
                <td>Abused Top-Level Domain</td>
                <td><span className="score-pill score-suspicious">+2</span></td>
                <td>Disposable TLDs (.xyz, .top, .cam, .zip, .tk, .ml) frequently abused for phishing</td>
              </tr>
              <tr>
                <td><code>at_symbol</code></td>
                <td>'@' Redirection Trick</td>
                <td><span className="score-pill score-suspicious">+2</span></td>
                <td>Masking destination via HTTP Basic Auth URI syntax</td>
              </tr>
              <tr>
                <td><code>shortener</code></td>
                <td>URL Shortener Obfuscation</td>
                <td><span className="score-pill score-suspicious">+2</span></td>
                <td>Hiding ultimate target URL behind Bitly, TinyURL, or t.co redirects</td>
              </tr>
              <tr>
                <td><code>many_subdomains</code></td>
                <td>Excessive Subdomains (3+)</td>
                <td><span className="score-pill score-suspicious">+2</span></td>
                <td>Deep subdomain nesting to simulate legitimate corporate domains</td>
              </tr>
              <tr>
                <td><code>suspicious_path</code></td>
                <td>Credential Harvesting Keywords</td>
                <td><span className="score-pill score-safe">+1</span></td>
                <td>Path containing 'login', 'verify', 'account', 'confirm', or 'secure'</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
