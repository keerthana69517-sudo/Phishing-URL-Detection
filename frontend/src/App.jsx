import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import URLScanner from './pages/URLScanner';
import BulkScanner from './pages/BulkScanner';
import ThreatIntel from './pages/ThreatIntel';
import History from './pages/History';
import Analytics from './pages/Analytics';
import Awareness from './pages/Awareness';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import './App.css';

export default function App() {
  const getInitialTab = () => {
    const hash = window.location.hash.replace('#', '');
    const validTabs = ['dashboard', 'scanner', 'bulk', 'threat-intel', 'history', 'analytics', 'awareness', 'reports', 'settings'];
    return validTabs.includes(hash) ? hash : 'dashboard';
  };

  const [activeTab, setActiveTabState] = useState(getInitialTab);
  const [collapsed, setCollapsed] = useState(false);
  const [passedScanResult, setPassedScanResult] = useState(null);

  const setActiveTab = (tabId) => {
    setActiveTabState(tabId);
    window.location.hash = tabId;
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#', '');
      const validTabs = ['dashboard', 'scanner', 'bulk', 'threat-intel', 'history', 'analytics', 'awareness', 'reports', 'settings'];
      if (validTabs.includes(hash)) {
        setActiveTabState(hash);
      }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const handleScanFromDashboard = (result) => {
    setPassedScanResult(result);
  };

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''}`}>
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        collapsed={collapsed}
        setCollapsed={setCollapsed}
      />

      {/* Main Content Viewport */}
      <main className="main-viewport">
        {activeTab === 'dashboard' && (
          <Dashboard
            setActiveTab={setActiveTab}
            onScanResult={handleScanFromDashboard}
          />
        )}
        {activeTab === 'scanner' && (
          <URLScanner initialResult={passedScanResult} />
        )}
        {activeTab === 'bulk' && <BulkScanner />}
        {activeTab === 'threat-intel' && <ThreatIntel />}
        {activeTab === 'history' && <History />}
        {activeTab === 'analytics' && <Analytics />}
        {activeTab === 'awareness' && <Awareness />}
        {activeTab === 'reports' && <Reports />}
        {activeTab === 'settings' && <Settings />}
      </main>
    </div>
  );
}
