const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:5000";

async function handle(res) {
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || data.message || `Request failed with status ${res.status}`);
  }
  return data;
}

export async function analyze(urls) {
  const payload = Array.isArray(urls) ? { urls } : { url: urls };
  const res = await fetch(`${API_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return handle(res);
}

export async function getStats() {
  const res = await fetch(`${API_URL}/stats`);
  return handle(res);
}

export async function getHistory(params = {}) {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch(`${API_URL}/history?${qs}`);
  return handle(res);
}

export async function clearHistory() {
  const res = await fetch(`${API_URL}/clear-history`, {
    method: "POST"
  });
  return handle(res);
}

export async function uploadBulkCSV(file) {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_URL}/bulk-upload`, {
    method: "POST",
    body: formData
  });
  return handle(res);
}

export async function qrScan(file) {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_URL}/qr-scan`, {
    method: "POST",
    body: formData
  });
  return handle(res);
}

export async function checkDbHealth() {
  const res = await fetch(`${API_URL}/db-health`);
  return handle(res);
}

export async function getThreatIntelStatus() {
  const res = await fetch(`${API_URL}/threat-intel/status`);
  return handle(res);
}
