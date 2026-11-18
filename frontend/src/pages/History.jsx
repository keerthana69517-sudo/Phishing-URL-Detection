import React, { useState, useEffect } from 'react';
import { getHistory, clearHistory } from '../api';

export default function History() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchUrl, setSearchUrl] = useState('');
  const [selectedVerdict, setSelectedVerdict] = useState('All');
  const [sortBy, setSortBy] = useState('timestamp');

  useEffect(() => {
    fetchHistory();
  }, [selectedVerdict, sortBy]);

  const fetchHistory = async () => {
    try {
      setLoading(true);
      const params = {};
      if (searchUrl.trim()) params.url = searchUrl.trim();
      if (selectedVerdict !== 'All') params.verdict = selectedVerdict;
      params.sort = sortBy;
      params.limit = 100;

      const data = await getHistory(params);
      setHistory(data.history || []);
    } catch (err) {
      console.error('Failed to fetch history', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchHistory();
  };

  const handleClearHistory = async () => {
    if (!window.confirm("Are you sure you want to clear all previous scan records from MongoDB? This will reset all historical tests to zero.")) {
      return;
    }
    try {
      setLoading(true);
      await clearHistory();
      setHistory([]);
    } catch (err) {
      alert("Failed to clear history: " + (err.message || 'Error'));
    } finally {
      setLoading(false);
    }
  };

  const exportHistoryCSV = () => {
    if (!history.length) return;
    const headers = ['URL', 'Verdict', 'Risk Score', 'Timestamp IST', 'Triggered Rules'];
    const rows = history.map(h => [
      `"${(h.url || '').replace(/"/g, '""')}"`,
      h.verdict,
      h.score,
      `"${h.timestamp_ist || h.timestamp_display || h.timestamp_utc || ''}"`,
      `"${(h.triggered_rules || []).map(r => r.name).join('; ').replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const link = document.createElement('a');
    link.href = encodeURI(csvContent);
    link.download = `phishguard_history_${Date.now()}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const openReportModal = (item) => {
    const printWindow = window.open('', '_blank');
    const htmlContent = item.report_html || `
      <div style="font-family: sans-serif; padding: 24px; color: #fff; background: #0b1120;">
        <h2>PhishGuard Scan Log</h2>
        <p><strong>Target URL:</strong> ${item.url}</p>
        <p><strong>Verdict:</strong> ${item.verdict}</p>
        <p><strong>Score:</strong> ${item.score}/10</p>
        <p><strong>Scanned At:</strong> ${item.timestamp_ist || item.timestamp_display || item.timestamp_utc}</p>
      </div>
    `;
    printWindow.document.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>PhishGuard Saved Report - ${item.url}</title>
          <style>body { background: #0b1120; margin: 0; padding: 20px; }</style>
        </head>
        <body>${htmlContent}</body>
      </html>
    `);
    printWindow.document.close();
  };

  const formatItemTime = (item) => {
    if (item.timestamp_ist) return item.timestamp_ist;
    if (item.timestamp_display) return item.timestamp_display;
    if (item.timestamp_utc) {
      try {
        const d = new Date(item.timestamp_utc);
        return d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: true });
      } catch (e) {
        return String(item.timestamp_utc);
      }
    }
    return 'Recent';
  };

  return (
    <div className="history-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Persistent Scan Telemetry & History</h1>
          <p className="page-subtitle">Indexed audit trails stored in MongoDB &bull; Indian Standard Time (IST)</p>
        </div>
        <div className="header-actions">
          <button className="btn-secondary text-rose" onClick={handleClearHistory} disabled={!history.length}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="3 6 5 6 21 6"></polyline>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            </svg>
            Clear All History
          </button>
          <button className="btn-secondary" onClick={exportHistoryCSV} disabled={!history.length}>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            Export Audit CSV
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-panel filter-panel">
        <form onSubmit={handleSearchSubmit} className="history-filter-form">
          <div className="search-input-box">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <input
              type="text"
              placeholder="Search by URL substring..."
              value={searchUrl}
              onChange={(e) => setSearchUrl(e.target.value)}
            />
          </div>

          <div className="filter-select-group">
            <label>Verdict:</label>
            <select
              value={selectedVerdict}
              onChange={(e) => setSelectedVerdict(e.target.value)}
            >
              <option value="All">All Verdicts</option>
              <option value="Safe">Safe Only</option>
              <option value="Suspicious">Suspicious Only</option>
              <option value="Phishing">Phishing Only</option>
            </select>
          </div>

          <div className="filter-select-group">
            <label>Sort By:</label>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
            >
              <option value="timestamp">Latest First</option>
              <option value="score">Highest Risk Score</option>
            </select>
          </div>

          <button type="submit" className="btn-primary">Filter</button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              setSearchUrl('');
              setSelectedVerdict('All');
              setSortBy('timestamp');
            }}
          >
            Reset
          </button>
        </form>
      </div>

      {/* History Table */}
      <div className="glass-panel mt-6">
        <div className="panel-header">
          <h3 className="panel-title">Indexed Records ({history.length})</h3>
          <span className="badge-pill">MongoDB Stream</span>
        </div>

        <div className="table-container">
          <table className="threats-table">
            <thead>
              <tr>
                <th>Timestamp (IST)</th>
                <th>Target URL</th>
                <th>Verdict</th>
                <th>Risk Score</th>
                <th>Indicators Triggered</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="6" className="empty-state">Loading scan history...</td>
                </tr>
              ) : history.length ? (
                history.map((item, idx) => (
                  <tr key={idx}>
                    <td className="timestamp-cell">
                      {formatItemTime(item)}
                    </td>
                    <td className="url-cell" title={item.url}>
                      <span className="url-text">{item.url}</span>
                    </td>
                    <td>
                      <span className={`verdict-badge ${item.verdict?.toLowerCase()}`}>
                        {item.verdict}
                      </span>
                    </td>
                    <td>
                      <span className={`score-pill score-${item.verdict?.toLowerCase()}`}>
                        {item.score} / 10
                      </span>
                    </td>
                    <td>
                      <span className="rules-count">
                        {item.triggered_rules?.length || 0} rule(s)
                      </span>
                    </td>
                    <td>
                      <button
                        className="btn-inspect"
                        onClick={() => openReportModal(item)}
                      >
                        View Report
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="empty-state">
                    No scan records found. Start scanning URLs to build history!
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
