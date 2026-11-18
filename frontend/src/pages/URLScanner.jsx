import React, { useState } from 'react';
import { analyze, qrScan } from '../api';

export default function URLScanner({ initialResult }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(initialResult || null);
  const [error, setError] = useState('');
  const [qrLoading, setQrLoading] = useState(false);
  const [qrMessage, setQrMessage] = useState('');

  const testCases = [
    { label: 'Safe URL', url: 'https://github.com/torvalds/linux' },
    { label: 'Suspicious URL', url: 'https://secure-login.portal-update.xyz/account' },
    { label: 'Phishing URL', url: 'http://192.168.1.50/paypaI-security-verify.top/login@victim.com' }
  ];

  const handleScan = async (targetUrl = url) => {
    const scanTarget = (typeof targetUrl === 'string' ? targetUrl : url).trim();
    if (!scanTarget) {
      setError('Please provide a URL to analyze.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const data = await analyze(scanTarget);
      setResult(data);
    } catch (err) {
      setError(err.message || 'Heuristic evaluation failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleQrUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setQrMessage('');
    setError('');
    setQrLoading(true);
    try {
      const resp = await qrScan(file);
      if (resp.type === 'url' && resp.analysis) {
        setResult(resp.analysis);
        setUrl(resp.qr_content);
        setQrMessage(`QR code decoded: "${resp.qr_content}". Extracted URL analyzed safely.`);
      } else {
        setQrMessage(`QR Decoded text: "${resp.qr_content}". Not an HTTP/HTTPS URL.`);
      }
    } catch (err) {
      setError(err.message || 'Failed to decode QR image.');
    } finally {
      setQrLoading(false);
      e.target.value = '';
    }
  };

  const handleDownloadPdf = () => {
    if (!result?.report_html) return;
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>PhishGuard Threat Intelligence Report - ${result.url}</title>
          <style>
            body { background: #0b1120; margin: 0; padding: 24px; font-family: system-ui, sans-serif; }
            @media print {
              body { background: #fff !important; color: #000 !important; }
              .phishguard-report { box-shadow: none !important; border: 1px solid #ccc !important; }
            }
          </style>
        </head>
        <body>
          ${result.report_html}
        </body>
      </html>
    `);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 300);
  };

  // Calculate Gauge Degree & Percentage (0 to 100)
  const score = result?.score || 0;
  const scorePct = Math.min(100, Math.round((score / 10) * 100));
  const verdict = result?.verdict || 'Safe';

  return (
    <div className="scanner-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Explainable URL Threat Scanner</h1>
          <p className="page-subtitle">Multi-rule heuristic vector weighting &bull; Zero execution sandbox safety</p>
        </div>
        {result && (
          <button className="btn-secondary" onClick={handleDownloadPdf}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            Export PDF Report
          </button>
        )}
      </div>

      {/* Input Controls Card */}
      <div className="glass-panel">
        <div className="scanner-input-group">
          <div className="input-wrapper">
            <span className="input-prefix">TARGET</span>
            <input
              type="text"
              className="scanner-input"
              placeholder="Enter complete target URL (e.g. https://domain.xyz/login)..."
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
            />
            {url && (
              <button className="input-clear-btn" onClick={() => setUrl('')}>✕</button>
            )}
          </div>

          <button
            className="btn-primary scan-action-btn"
            disabled={loading}
            onClick={() => handleScan()}
          >
            {loading ? (
              <span className="loading-spinner">Analyzing...</span>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                </svg>
                Scan URL
              </>
            )}
          </button>

          {/* QR Code Upload Button */}
          <label className="btn-secondary qr-upload-btn" title="Upload QR Code Image">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="7" height="7"></rect>
              <rect x="14" y="3" width="7" height="7"></rect>
              <rect x="14" y="14" width="7" height="7"></rect>
              <rect x="3" y="14" width="7" height="7"></rect>
            </svg>
            <span>{qrLoading ? 'Decoding QR...' : 'Scan QR Code'}</span>
            <input
              type="file"
              accept="image/*"
              style={{ display: 'none' }}
              onChange={handleQrUpload}
              disabled={qrLoading}
            />
          </label>
        </div>

        {/* Preset Sample URLs for Viva Demo */}
        <div className="test-presets">
          <span className="presets-label">Viva Quick Test Samples:</span>
          {testCases.map((tc, idx) => (
            <button
              key={idx}
              className="preset-pill"
              onClick={() => {
                setUrl(tc.url);
                handleScan(tc.url);
              }}
            >
              {tc.label}
            </button>
          ))}
        </div>

        {error && <div className="scanner-alert alert-error">{error}</div>}
        {qrMessage && <div className="scanner-alert alert-info">{qrMessage}</div>}
      </div>

      {/* Analysis Results View */}
      {result && (
        <div className="analysis-results-section mt-6">
          {/* Top Verdict & Score Gauge Bar */}
          <div className="verdict-banner glass-panel">
            <div className="verdict-info-col">
              <div className="verdict-header-row">
                <span className={`verdict-tag tag-${verdict.toLowerCase()}`}>
                  {verdict.toUpperCase()} VERDICT
                </span>
                <span className="analysis-type-tag">Heuristic Multi-Vector</span>
              </div>
              <h2 className="scanned-url-display">{result.url}</h2>
              <p className="verdict-summary-desc">
                {verdict === 'Phishing'
                  ? 'Severe threat indicators detected. The URL exhibits manipulative structural spoofing characteristic of credential theft operations.'
                  : verdict === 'Suspicious'
                  ? 'Elevated risk detected. Several deceptive indicators present that warrant user caution.'
                  : 'No known phishing signatures or anomalous heuristic patterns detected by the engine.'}
              </p>
            </div>

            {/* Circular Risk Score Gauge */}
            <div className="gauge-container">
              <div className={`circular-gauge gauge-${verdict.toLowerCase()}`}>
                <div className="gauge-inner">
                  <span className="gauge-score">{scorePct}</span>
                  <span className="gauge-max">/ 100</span>
                  <span className="gauge-label">Risk Index</span>
                </div>
              </div>
            </div>
          </div>

          {/* Explainable Insights: Rules Breakdown & Recommendations */}
          <div className="two-column-grid mt-6">
            {/* Triggered Rules & Weights */}
            <div className="glass-panel">
              <div className="panel-header">
                <h3 className="panel-title">
                  <span className="text-cyan">◆</span> Triggered Rule Weights ({result.triggered_rules?.length || 0})
                </h3>
                <span className="badge-pill">Explainability</span>
              </div>

              {result.triggered_rules?.length ? (
                <div className="rules-list">
                  {result.triggered_rules.map((rule, idx) => (
                    <div key={idx} className="rule-item-card">
                      <div className="rule-item-header">
                        <span className="rule-name">{rule.name}</span>
                        <span className="rule-weight-badge">+{rule.weight} Weight</span>
                      </div>
                      <div className="rule-meta">
                        <span className="rule-id">ID: {rule.id}</span>
                        <span className="rule-contrib">
                          Contribution: {Math.round((rule.weight / (score || 1)) * 100)}% of total risk
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="clean-rules-card">
                  <div className="clean-icon">✓</div>
                  <h4>No Risk Rules Triggered</h4>
                  <p>The URL passed all 10 heuristic pattern evaluations cleanly.</p>
                </div>
              )}
            </div>

            {/* Recommendations & Defensive Actions */}
            <div className="glass-panel">
              <div className="panel-header">
                <h3 className="panel-title">
                  <span className="text-emerald">🛡</span> Security Recommendations
                </h3>
                <span className="badge-pill">Action Plan</span>
              </div>

              <div className="recommendations-box">
                {verdict === 'Phishing' ? (
                  <ul className="rec-list">
                    <li><strong className="text-rose">Do not browse:</strong> Never visit or input credentials on this domain.</li>
                    <li><strong className="text-rose">Firewall block:</strong> Add the domain and host IP to the egress blackhole.</li>
                    <li><strong className="text-rose">Credential audit:</strong> Invalidate sessions if accessed from your corporate perimeter.</li>
                    <li><strong className="text-rose">Report threat:</strong> Forward URL telemetry to anti-phishing authorities.</li>
                  </ul>
                ) : verdict === 'Suspicious' ? (
                  <ul className="rec-list">
                    <li><strong className="text-amber">Verify domain:</strong> Check WHOIS registration age and owner identity.</li>
                    <li><strong className="text-amber">Isolated sandbox:</strong> If required, evaluate strictly inside an isolated container.</li>
                    <li><strong className="text-amber">Avoid input:</strong> Do not submit MFA codes, passwords, or personal details.</li>
                  </ul>
                ) : (
                  <ul className="rec-list">
                    <li><strong className="text-emerald">Standard posture:</strong> Maintain standard browsing hygiene.</li>
                    <li><strong className="text-emerald">SSL check:</strong> Ensure the browser displays a valid, trusted TLS certificate.</li>
                    <li><strong className="text-emerald">Continuous watch:</strong> Monitor for unexpected domain redirection changes.</li>
                  </ul>
                )}
              </div>

              {/* Threat Intelligence Layer */}
              <div className="intel-layer-card mt-4">
                <div className="intel-layer-header">
                  <span>External Threat Intelligence</span>
                  <span className="badge-status">
                    {result.google_safe_browsing?.matches?.length ? 'THREAT DETECTED' : 'CLEAN / HEURISTIC INDEPENDENT'}
                  </span>
                </div>
                <p className="intel-layer-text">
                  PhishGuard heuristic engine operates 100% autonomously without external dependency, augmented by Google Safe Browsing telemetry when connected.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
