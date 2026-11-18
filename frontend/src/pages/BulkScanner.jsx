import React, { useState } from 'react';
import { analyze, uploadBulkCSV } from '../api';

export default function BulkScanner() {
  const [textInput, setTextInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [batchReportHtml, setBatchReportHtml] = useState('');
  const [error, setError] = useState('');
  const [statusMsg, setStatusMsg] = useState('');

  const sampleBatch = [
    'https://google.com',
    'https://secure-update.account-support.top/signin',
    'http://192.168.0.1/auth-login',
    'https://github.com',
    'https://verify-paypaI.xyz/update'
  ].join('\n');

  const handleScanText = async () => {
    const urls = textInput
      .split(/\n|,/)
      .map(u => u.trim())
      .filter(Boolean);

    if (!urls.length) {
      setError('Please provide at least one URL to scan.');
      return;
    }
    setError('');
    setStatusMsg(`Scanning ${urls.length} URLs simultaneously...`);
    setLoading(true);

    try {
      const resp = await analyze(urls);
      const resList = resp.results || (resp.url ? [resp] : []);
      setResults(resList);
      setBatchReportHtml(resp.report_html || '');
      setStatusMsg(`Successfully analyzed ${resList.length} URLs.`);
    } catch (err) {
      setError(err.message || 'Bulk scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setError('');
    setStatusMsg(`Parsing and analyzing CSV file "${file.name}"...`);
    setLoading(true);

    try {
      const resp = await uploadBulkCSV(file);
      const resList = resp.results || [];
      setResults(resList);
      setBatchReportHtml(resp.report_html || '');
      setStatusMsg(`Successfully processed CSV: ${resList.length} URLs analyzed.`);
    } catch (err) {
      setError(err.message || 'Failed to process CSV file.');
    } finally {
      setLoading(false);
      e.target.value = '';
    }
  };

  const downloadCSVResults = () => {
    if (!results.length) return;
    const headers = ['URL', 'Verdict', 'Risk Score', 'Triggered Rules Count', 'Triggered Rule Names'];
    const rows = results.map(r => [
      `"${r.url.replace(/"/g, '""')}"`,
      r.verdict,
      r.score,
      r.triggered_rules?.length || 0,
      `"${(r.triggered_rules || []).map(x => x.name).join('; ').replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard_scan_results_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const downloadBatchReport = () => {
    if (!batchReportHtml) return;
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>PhishGuard Bulk Inspection Report</title>
          <style>
            body { background: #0b1120; margin: 0; padding: 24px; font-family: system-ui, sans-serif; }
            @media print {
              body { background: #fff !important; color: #000 !important; }
            }
          </style>
        </head>
        <body>
          ${batchReportHtml}
        </body>
      </html>
    `);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 300);
  };

  return (
    <div className="bulk-scanner-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Bulk URL Intelligence Scanner</h1>
          <p className="page-subtitle">Batch inspection for enterprise feeds, proxy logs, and CSV threat feeds</p>
        </div>
        {results.length > 0 && (
          <div className="header-actions">
            <button className="btn-secondary" onClick={downloadCSVResults}>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="7 10 12 15 17 10"></polyline>
                <line x1="12" y1="15" x2="12" y2="3"></line>
              </svg>
              Export CSV
            </button>
            <button className="btn-primary" onClick={downloadBatchReport}>
              Print Batch PDF
            </button>
          </div>
        )}
      </div>

      {/* Input Options Grid */}
      <div className="two-column-grid">
        {/* Paste URLs */}
        <div className="glass-panel">
          <div className="panel-header">
            <h3 className="panel-title">Option 1: Paste Multiple URLs</h3>
            <button
              className="btn-text"
              onClick={() => setTextInput(sampleBatch)}
            >
              Fill Sample Batch
            </button>
          </div>
          <textarea
            className="bulk-textarea"
            rows="6"
            placeholder="Paste URLs (one per line or separated by commas)..."
            value={textInput}
            onChange={(e) => setTextInput(e.target.value)}
          />
          <div className="panel-footer mt-4">
            <button
              className="btn-primary"
              disabled={loading}
              onClick={handleScanText}
            >
              {loading ? 'Evaluating...' : 'Start Batch Analysis'}
            </button>
          </div>
        </div>

        {/* Upload CSV */}
        <div className="glass-panel">
          <div className="panel-header">
            <h3 className="panel-title">Option 2: Upload CSV File</h3>
            <span className="badge-pill">Enterprise</span>
          </div>
          <div className="csv-upload-dropzone">
            <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="#00f0ff" strokeWidth="1.5">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="17 8 12 3 7 8"></polyline>
              <line x1="12" y1="3" x2="12" y2="15"></line>
            </svg>
            <h4>Upload URL Telemetry CSV</h4>
            <p className="dropzone-sub">
              Upload standard CSV files containing a URL column.
            </p>
            <label className="btn-secondary mt-3">
              Browse CSV File
              <input
                type="file"
                accept=".csv,text/csv"
                style={{ display: 'none' }}
                onChange={handleFileUpload}
                disabled={loading}
              />
            </label>
          </div>
        </div>
      </div>

      {statusMsg && <div className="scanner-alert alert-info mt-4">{statusMsg}</div>}
      {error && <div className="scanner-alert alert-error mt-4">{error}</div>}

      {/* Results Table */}
      {results.length > 0 && (
        <div className="glass-panel mt-6">
          <div className="panel-header">
            <div>
              <h3 className="panel-title">Batch Evaluation Results ({results.length})</h3>
              <p className="panel-sub">Heuristic verdict distribution and risk telemetry</p>
            </div>
            <div className="results-summary-pills">
              <span className="summary-pill pill-safe">
                Safe: {results.filter(r => r.verdict === 'Safe').length}
              </span>
              <span className="summary-pill pill-suspicious">
                Suspicious: {results.filter(r => r.verdict === 'Suspicious').length}
              </span>
              <span className="summary-pill pill-phishing">
                Phishing: {results.filter(r => r.verdict === 'Phishing').length}
              </span>
            </div>
          </div>

          <div className="table-container">
            <table className="threats-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Target URL</th>
                  <th>Verdict</th>
                  <th>Risk Score</th>
                  <th>Triggered Rules</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, idx) => (
                  <tr key={idx}>
                    <td>{idx + 1}</td>
                    <td className="url-cell" title={r.url}>
                      <span className="url-text">{r.url}</span>
                    </td>
                    <td>
                      <span className={`verdict-badge ${r.verdict?.toLowerCase()}`}>
                        {r.verdict}
                      </span>
                    </td>
                    <td>
                      <span className={`score-pill score-${r.verdict?.toLowerCase()}`}>
                        {r.score} / 10
                      </span>
                    </td>
                    <td>
                      {r.triggered_rules?.length ? (
                        <div className="triggered-tags">
                          {r.triggered_rules.map((rule, rIdx) => (
                            <span key={rIdx} className="rule-tag" title={rule.name}>
                              {rule.name}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-emerald">None (Clean)</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
