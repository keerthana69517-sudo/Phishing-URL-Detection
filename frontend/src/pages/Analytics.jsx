import React, { useState, useEffect } from 'react';
import { getStats, getHistory } from '../api';

export default function Analytics() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [sData, hData] = await Promise.all([
          getStats(),
          getHistory({ limit: 100 })
        ]);
        setStats(sData);
        setHistory(hData.history || []);
      } catch (err) {
        console.error('Analytics load error', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const total = stats?.total_scans || 0;
  const safe = stats?.safe_count || 0;
  const suspicious = stats?.suspicious_count || 0;
  const phishing = stats?.phishing_count || 0;

  // Calculate rule trigger frequency
  const ruleCounts = {};
  history.forEach(item => {
    (item.triggered_rules || []).forEach(r => {
      ruleCounts[r.name] = (ruleCounts[r.name] || 0) + 1;
    });
  });

  const sortedRules = Object.entries(ruleCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  const maxRuleCount = sortedRules.length ? Math.max(...sortedRules.map(r => r[1])) : 1;

  return (
    <div className="analytics-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat Telemetry & Risk Analytics</h1>
          <p className="page-subtitle">Security intelligence metrics, rule frequency vectors, and temporal trends</p>
        </div>
      </div>

      {/* Analytics KPI Ribbon */}
      <div className="metrics-grid">
        <div className="metric-card cyan-glow">
          <span className="metric-label">AGGREGATE VOLUME</span>
          <div className="metric-value">{total}</div>
          <span className="text-cyan text-xs">Evaluated URLs</span>
        </div>
        <div className="metric-card rose-glow">
          <span className="metric-label">ATTACK INTERCEPTION RATE</span>
          <div className="metric-value text-rose">
            {total ? Math.round(((phishing + suspicious) / total) * 100) : 0}%
          </div>
          <span className="text-rose text-xs">Elevated / High Threat</span>
        </div>
        <div className="metric-card emerald-glow">
          <span className="metric-label">AVERAGE EVALUATION TIME</span>
          <div className="metric-value text-emerald">&lt; 15 ms</div>
          <span className="text-emerald text-xs">Sub-second heuristic latency</span>
        </div>
        <div className="metric-card amber-glow">
          <span className="metric-label">ACTIVE HEURISTIC VECTORS</span>
          <div className="metric-value text-amber">10 Rules</div>
          <span className="text-amber text-xs">Lexical & structural weights</span>
        </div>
      </div>

      <div className="two-column-grid mt-6">
        {/* Most Frequently Triggered Rules */}
        <div className="glass-panel">
          <div className="panel-header">
            <h3 className="panel-title">Top Triggered Threat Heuristics</h3>
            <span className="badge-pill">Attack Vectors</span>
          </div>
          <p className="panel-sub mb-4">Breakdown of which indicators trigger most frequently across recent scans</p>

          <div className="frequency-bars">
            {sortedRules.length ? (
              sortedRules.map(([ruleName, count], idx) => {
                const pct = Math.round((count / maxRuleCount) * 100);
                return (
                  <div key={idx} className="freq-item">
                    <div className="freq-labels">
                      <span className="freq-name">{ruleName}</span>
                      <span className="freq-val">{count} hit(s)</span>
                    </div>
                    <div className="progress-track">
                      <div
                        className="progress-fill bg-cyan"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="empty-state">No rule trigger data accumulated yet.</div>
            )}
          </div>
        </div>

        {/* Temporal Daily Volume */}
        <div className="glass-panel">
          <div className="panel-header">
            <h3 className="panel-title">Inspection Frequency Timeline</h3>
            <span className="badge-pill">Temporal</span>
          </div>
          <p className="panel-sub mb-4">Daily scan velocity across the 7-day trailing window</p>

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

      {/* Detection Ratio & Breakdown Summary */}
      <div className="glass-panel mt-6">
        <h3 className="section-title">Telemetry Proportional Analysis</h3>
        <div className="proportional-bar-wrapper mt-4">
          <div
            className="prop-slice bg-emerald"
            style={{ width: `${total ? (safe / total) * 100 : 33}%` }}
            title={`Safe: ${safe}`}
          />
          <div
            className="prop-slice bg-amber"
            style={{ width: `${total ? (suspicious / total) * 100 : 33}%` }}
            title={`Suspicious: ${suspicious}`}
          />
          <div
            className="prop-slice bg-rose"
            style={{ width: `${total ? (phishing / total) * 100 : 34}%` }}
            title={`Phishing: ${phishing}`}
          />
        </div>

        <div className="prop-legend mt-3">
          <div className="prop-legend-item">
            <span className="dot bg-emerald"></span>
            <span>Safe: {safe} ({total ? Math.round((safe / total) * 100) : 0}%)</span>
          </div>
          <div className="prop-legend-item">
            <span className="dot bg-amber"></span>
            <span>Suspicious: {suspicious} ({total ? Math.round((suspicious / total) * 100) : 0}%)</span>
          </div>
          <div className="prop-legend-item">
            <span className="dot bg-rose"></span>
            <span>Phishing: {phishing} ({total ? Math.round((phishing / total) * 100) : 0}%)</span>
          </div>
        </div>
      </div>
    </div>
  );
}
