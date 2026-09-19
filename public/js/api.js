/**
 * AethelTech SOC - Unified Client API Service
 * Supports local port 3000, VS Code Live Server, and file:// protocol execution.
 */

const BASE_URL = (typeof window !== 'undefined' && window.location.origin && window.location.protocol.startsWith('http') && window.location.port === '3000')
  ? ''
  : 'http://localhost:3000';

const API = {
  async analyze(text, type = 'text', source = 'Direct Input', companyDomain = 'aetheltech.io') {
    const res = await fetch(`${BASE_URL}/api/scan-and-save`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, type, source, companyDomain })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Analysis failed');
    }
    return res.json();
  },

  async getScenarios() {
    const res = await fetch(`${BASE_URL}/api/scenarios`);
    return res.json();
  },

  async runScenario(id) {
    const res = await fetch(`${BASE_URL}/api/scenarios/run/${id}`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to run scenario');
    }
    return res.json();
  },

  async getIncidents(params = {}) {
    const query = new URLSearchParams(params).toString();
    const res = await fetch(`${BASE_URL}/api/incidents?${query}`);
    return res.json();
  },

  async getIncidentById(id) {
    const res = await fetch(`${BASE_URL}/api/incidents/${id}`);
    if (!res.ok) throw new Error('Incident not found');
    return res.json();
  },

  async updateIncidentStatus(id, status) {
    const res = await fetch(`${BASE_URL}/api/incidents/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    return res.json();
  },

  async getStats() {
    const res = await fetch(`${BASE_URL}/api/dashboard/stats`);
    return res.json();
  },

  async seedDatabase() {
    const res = await fetch(`${BASE_URL}/api/seed`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to seed database');
    return res.json();
  },

  async uploadCsv(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${BASE_URL}/api/upload/csv`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'CSV upload failed');
    }
    return res.json();
  },

  async uploadJson(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${BASE_URL}/api/upload/json`, {
      method: 'POST',
      body: formData
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'JSON upload failed');
    }
    return res.json();
  }
};
