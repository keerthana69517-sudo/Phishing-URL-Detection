import React, { useState } from 'react';
import { analyze } from '../api';

export default function Reports() {
  const [reportUrl, setReportUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [error, setError] = useState('');

  const generateReport = async (e) => {
    e.preventDefault();
    if (!reportUrl.trim()) {
      setError('Please provide a URL to generate an executive report.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const data = await analyze(reportUrl.trim());
      setReportData(data);
    } catch (err) {
      setError(err.message || 'Report generation failed.');
    } finally {
      setLoading(false);
    }
  };

  const handlePrint = () => {
    if (!reportData?.report_html) return;
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>PhishGuard Executive Security Report - ${reportData.url}</title>
          <style>
            body { background: #0b1120; margin: 0; padding: 24px; font-family: system-ui, sans-serif; }
            @media print {
              body { background: #fff !important; color: #000 !important; }
            }
          </style>
        </head>
        <body>
          ${reportData.report_html}
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
    <div className="reports-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Executive Risk Assessment Reports</h1>
          <p className="page-subtitle">Publish audit-ready technical reports with risk metrics, heuristic evidence, and mitigation guidance</p>
        </div>
        {reportData && (
          <button className="btn-primary" onClick={handlePrint}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            Print / Save PDF Report
          </button>
        )}
      </div>

      {/* Generator Form */}
      <div className="glass-panel">
        <h3 className="section-title">Generate On-Demand Security Dossier</h3>
        <form onSubmit={generateReport} className="quick-scan-form mt-3">
          <div className="input-with-icon">
            <svg className="url-input-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <input
              type="text"
              className="quick-input"
              placeholder="Enter target URL for report compilation..."
              value={reportUrl}
              onChange={(e) => setReportUrl(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-scan" disabled={loading}>
            {loading ? 'Compiling Dossier...' : 'Generate Report'}
          </button>
        </form>
        {error && <div className="scanner-alert alert-error mt-3">{error}</div>}
      </div>

      {/* Report Preview */}
      {reportData ? (
        <div className="report-preview-container glass-panel mt-6">
          <div className="panel-header border-b pb-3 mb-4">
            <h3 className="panel-title">Report Live Preview</h3>
            <span className="badge-pill">Ready to Export</span>
          </div>

          <div
            className="embedded-report-html"
            dangerouslySetInnerHTML={{ __html: reportData.report_html }}
          />
        </div>
      ) : (
        <div className="glass-panel mt-6 text-center py-12">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#64748b" strokeWidth="1.5" className="mx-auto mb-3">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
            <polyline points="10 9 9 9 8 9"></polyline>
          </svg>
          <h4 className="text-slate font-medium">No Report Compiled Yet</h4>
          <p className="text-muted text-sm mt-1">Enter a URL above to compile and view the full technical analysis dossier.</p>
        </div>
      )}
    </div>
  );
}
