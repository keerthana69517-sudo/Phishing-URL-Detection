import React, { useState, useEffect } from 'react';
import { getStats, analyze, clearHistory } from '../api';

export default function Dashboard({ setActiveTab, onScanResult }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [quickUrl, setQuickUrl] = useState('');
  const [quickLoading, setQuickLoading] = useState(false);
  const [quickError, setQuickError] = useState('');
  const [resetMsg, setResetMsg] = useState('');

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      setLoading(true);
      const data = await getStats();
      setStats(data);
    } catch (err) {
      console.error("Failed to load stats", err);
    } finally {
      setLoading(false);
    }
  };

  const handleResetDatabase = async () => {
    if (!window.confirm("Clear all previous scan records from MongoDB and reset total scans to 0?")) {
      return;
    }
    try {
      setLoading(true);
      await clearHistory();
      await loadStats();
      setResetMsg('Database wiped clean. Total scans reset to 0.');
      setTimeout(() => setResetMsg(''), 4000);
    } catch (err) {
      alert("Failed to reset database: " + (err.message || 'Error'));
    } finally {
      setLoading(false);
    }
  };

  const handleQuickScan = async (e) => {
    e.preventDefault();
    if (!quickUrl.trim()) {
      setQuickError('Please enter a target URL');
      return;
    }
    setQuickError('');
    setQuickLoading(true);
    try {
      const res = await analyze(quickUrl.trim());
      if (onScanResult) {
        onScanResult(res);
      }
      setActiveTab('scanner');
    } catch (err) {
      setQuickError(err.message || 'Quick scan failed');
    } finally {
      setQuickLoading(false);
    }
  };

  const total = stats?.total_scans || 0;
  const safe = stats?.safe_count || 0;
  const suspicious = stats?.suspicious_count || 0;
  const phishing = stats?.phishing_count || 0;

  return (
    <div className="dashboard-page">
      {/* Top Banner Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Cyber Intelligence Command Center</h1>
          <p className="page-subtitle">Real-time heuristics telemetry &bull; Heuristic engine v2.0 &bull; Indian Standard Time (IST)</p>
        </div>
        <div className="header-actions">
          <button
            className="btn-secondary text-rose"
            onClick={handleResetDatabase}
            title="Wipe previous MongoDB tests and reset to 0"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="3 6 5 6 21 6"></polyline>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            </svg>
            Reset Scans to 0
          </button>
          <button className="btn-secondary" onClick={loadStats} title="Refresh telemetry">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M23 4v6h-6"></path>
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
            </svg>
            Refresh
          </button>
          <button className="btn-primary" onClick={() => setActiveTab('scanner')}>
            Launch Scanner
          </button>
        </div>
      </div>

      {resetMsg && (
        <div className="scanner-alert alert-info mb-4">
          ✓ {resetMsg}
        </div>
      )}

      {/* Metrics Cards Grid */}
      <div className="metrics-grid">
        <div className="metric-card cyan-glow">
          <div className="metric-header">
            <span className="metric-label">TOTAL URLS SCANNED</span>
            <div className="metric-icon cyan">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="2" y1="12" x2="22" y2="12"></line>
                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
              </svg>
            </div>
          </div>
          <div className="metric-value">{loading ? '...' : total}</div>
          <div className="metric-footer text-cyan">
            <span>● 100% real database count</span>
          </div>
        </div>

        <div className="metric-card emerald-glow">
          <div className="metric-header">
            <span className="metric-label">SAFE SITES</span>
            <div className="metric-icon emerald">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
              </svg>
            </div>
          </div>
          <div className="metric-value text-emerald">{loading ? '...' : safe}</div>
          <div className="metric-footer text-emerald">
            <span>{total ? Math.round((safe / total) * 100) : 0}% of scanned traffic</span>
          </div>
        </div>

        <div className="metric-card amber-glow">
          <div className="metric-header">
            <span className="metric-label">SUSPICIOUS URLS</span>
            <div className="metric-icon amber">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                <line x1="12" y1="9" x2="12" y2="13"></line>
                <line x1="12" y1="17" x2="12.01" y2="17"></line>
              </svg>
            </div>
          </div>
          <div className="metric-value text-amber">{loading ? '...' : suspicious}</div>
          <div className="metric-footer text-amber">
            <span>Elevated risk profile</span>
          </div>
        </div>

        <div className="metric-card rose-glow">
          <div className="metric-header">
            <span className="metric-label">PHISHING DETECTIONS</span>
            <div className="metric-icon rose">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
              </svg>
            </div>
          </div>
          <div className="metric-value text-rose">{loading ? '...' : phishing}</div>
          <div className="metric-footer text-rose">
            <span>Confirmed malicious threats</span>
          </div>
        </div>
      </div>

      {/* Quick Scan Input Box */}
      <div className="quick-scan-card glass-panel">
        <div className="quick-scan-info">
          <h3 className="section-title">
            <span className="icon-pulse">⚡</span> Quick Heuristic Intercept
          </h3>
          <p className="section-subtitle">
            Instantly evaluate suspicious links against 10 deep heuristic detection rules.
          </p>
        </div>
        <form onSubmit={handleQuickScan} className="quick-scan-form">
          <div className="input-with-icon">
            <svg className="url-input-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <input
              type="text"
              className="quick-input"
              placeholder="Paste target URL (e.g. https://secure-paypaI-update.top/login)..."
              value={quickUrl}
              onChange={(e) => setQuickUrl(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-scan" disabled={quickLoading}>
            {quickLoading ? 'Analyzing...' : 'Analyze Now'}
          </button>
        </form>
        {quickError && <div className="quick-error">{quickError}</div>}
      </div>

      {/* Visual Telemetry Charts & Recent Activity */}
      <div className="two-column-grid">
        {/* Threat Distribution Card */}
        <div className="glass-panel">
          <div className="panel-header">
            <h3 className="panel-title">Threat Distribution Analysis</h3>
            <span className="badge-pill">Verdicts</span>
          </div>
          <div className="distribution-bars">
            <div className="dist-item">
              <div className="dist-labels">
                <span className="text-emerald">Safe URLs</span>
                <span>{safe} ({total ? Math.round((safe / total) * 100) : 0}%)</span>
              </div>
              <div className="progress-track">
                <div
                  className="progress-fill bg-emerald"
                  style={{ width: `${total ? (safe / total) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-labels">
                <span className="text-amber">Suspicious URLs</span>
                <span>{suspicious} ({total ? Math.round((suspicious / total) * 100) : 0}%)</span>
              </div>
              <div className="progress-track">
                <div
                  className="progress-fill bg-amber"
                  style={{ width: `${total ? (suspicious / total) * 100 : 0}%` }}
                />
              </div>
            </div>

            <div className="dist-item">
              <div className="dist-labels">
                <span className="text-rose">Phishing URLs</span>
                <span>{phishing} ({total ? Math.round((phishing / total) * 100) : 0}%)</span>
              </div>
              <div className="progress-track">
                <div
                  className="progress-fill bg-rose"
                  style={{ width: `${total ? (phishing / total) * 100 : 0}%` }}
                />
              </div>
            </div>
          </div>

          <div className="chart-legend">
            <div className="legend-item"><span className="dot bg-emerald"></span> Safe</div>
            <div className="legend-item"><span className="dot bg-amber"></span> Suspicious</div>
            <div className="legend-item"><span className="dot bg-rose"></span> Phishing</div>
          </div>
        </div>

        {/* Daily Scanning Activity Graph */}
        <div className="glass-panel">
          <div className="panel-header">
            <h3 className="panel-title">Daily Scanning Telemetry</h3>
            <span className="badge-pill">Last 7 Days (IST)</span>
          </div>
          <div className="activity-chart">
            {stats?.daily_activity?.map((item, idx) => {
              const maxVal = Math.max(...(stats.daily_activity.map(d => d.count)), 5);
              const heightPct = Math.max(12, Math.round((item.count / maxVal) * 100));
              return (
                <div key={idx} className="activity-bar-col">
                  <div className="bar-wrapper">
                    <span className="bar-tooltip">{item.count} scans</span>
                    <div
                      className="activity-bar"
                      style={{ height: `${heightPct}%` }}
                    />
                  </div>
                  <span className="bar-label">{item.date}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent Threats Table */}
      <div className="glass-panel mt-6">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">Recent Flagged Threats</h3>
            <p className="panel-sub">Real-time alert stream of detected anomalous and phishing links</p>
          </div>
          <button className="btn-text" onClick={() => setActiveTab('history')}>
            View All History &rarr;
          </button>
        </div>

        <div className="table-container">
          <table className="threats-table">
            <thead>
              <tr>
                <th>Target URL</th>
                <th>Time (IST)</th>
                <th>Verdict</th>
                <th>Risk Score</th>
                <th>Rules Triggered</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {stats?.recent_threats?.length ? (
                stats.recent_threats.map((threat, idx) => (
                  <tr key={idx}>
                    <td className="url-cell" title={threat.url}>
                      <span className="url-text">{threat.url}</span>
                    </td>
                    <td className="timestamp-cell">
                      {threat.timestamp_ist || threat.timestamp_display || (threat.timestamp_utc ? new Date(threat.timestamp_utc).toLocaleTimeString('en-IN') : 'Recent')}
                    </td>
                    <td>
                      <span className={`verdict-badge ${threat.verdict?.toLowerCase()}`}>
                        {threat.verdict}
                      </span>
                    </td>
                    <td>
                      <div className="score-cell">
                        <span className={`score-pill score-${threat.verdict?.toLowerCase()}`}>
                          {threat.score} / 10
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className="rules-count">
                        {threat.triggered_rules?.length || 0} indicator(s)
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn-inspect"
                        onClick={() => {
                          setQuickUrl(threat.url);
                          handleQuickScan({ preventDefault: () => {} });
                        }}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="empty-state">
                    No active threats currently logged. Clean posture!
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
