import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../data');
const DB_FILE = path.join(DATA_DIR, 'incidents.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

class Database {
  constructor() {
    this.records = [];
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        this.records = JSON.parse(raw);
      } else {
        this.records = [];
        this.save();
      }
    } catch (err) {
      console.error('[DB] Error loading database, initializing empty:', err.message);
      this.records = [];
    }
  }

  save() {
    try {
      const tempPath = `${DB_FILE}.tmp`;
      fs.writeFileSync(tempPath, JSON.stringify(this.records, null, 2), 'utf8');
      fs.renameSync(tempPath, DB_FILE);
    } catch (err) {
      console.error('[DB] Error persisting database:', err.message);
    }
  }

  insert(record) {
    const item = {
      id: record.id || `inc_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
      createdAt: record.createdAt || new Date().toISOString(),
      status: record.status || 'Open',
      ...record
    };
    this.records.unshift(item); // latest first
    this.save();
    return item;
  }

  insertMany(items) {
    const created = items.map((r, idx) => ({
      id: r.id || `inc_${Date.now()}_${idx}_${Math.random().toString(36).substring(2, 7)}`,
      createdAt: r.createdAt || new Date(Date.now() - (items.length - idx) * 3600000).toISOString(),
      status: r.status || 'Open',
      ...r
    }));
    this.records.unshift(...created);
    this.save();
    return created;
  }

  getAll(filters = {}) {
    let result = [...this.records];

    if (filters.search) {
      const q = filters.search.toLowerCase().trim();
      result = result.filter(r => 
        (r.inputText && r.inputText.toLowerCase().includes(q)) ||
        (r.customerIntelligence?.summary && r.customerIntelligence.summary.toLowerCase().includes(q)) ||
        (r.customerIntelligence?.category && r.customerIntelligence.category.toLowerCase().includes(q)) ||
        (r.securityAnalysis?.threatType && r.securityAnalysis.threatType.toLowerCase().includes(q)) ||
        (r.id && r.id.toLowerCase().includes(q)) ||
        (r.source && r.source.toLowerCase().includes(q))
      );
    }

    if (filters.category && filters.category !== 'all') {
      result = result.filter(r => r.customerIntelligence?.category === filters.category);
    }

    if (filters.sentiment && filters.sentiment !== 'all') {
      result = result.filter(r => r.customerIntelligence?.sentiment === filters.sentiment);
    }

    if (filters.risk && filters.risk !== 'all') {
      result = result.filter(r => r.riskAssessment?.riskLevel === filters.risk);
    }

    if (filters.threatOnly === 'true' || filters.threatOnly === true) {
      result = result.filter(r => r.securityAnalysis?.hasThreat);
    }

    if (filters.status && filters.status !== 'all') {
      result = result.filter(r => r.status === filters.status);
    }

    const total = result.length;
    const limit = parseInt(filters.limit) || 25;
    const page = parseInt(filters.page) || 1;
    const startIndex = (page - 1) * limit;
    const paginated = result.slice(startIndex, startIndex + limit);

    return {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
      items: paginated
    };
  }

  getById(id) {
    return this.records.find(r => r.id === id) || null;
  }

  updateStatus(id, newStatus) {
    const record = this.records.find(r => r.id === id);
    if (!record) return null;
    record.status = newStatus;
    record.updatedAt = new Date().toISOString();
    this.save();
    return record;
  }

  clear() {
    this.records = [];
    this.save();
  }

  getStats() {
    const total = this.records.length;
    if (total === 0) {
      return {
        total: 0,
        riskBreakdown: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
        categoryBreakdown: {},
        sentimentBreakdown: { Positive: 0, Neutral: 0, Negative: 0, Frustrated: 0 },
        threatCount: 0,
        threatRate: 0,
        avgRiskScore: 0,
        recentThreats: []
      };
    }

    const riskBreakdown = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    const categoryBreakdown = {};
    const sentimentBreakdown = { Positive: 0, Neutral: 0, Negative: 0, Frustrated: 0 };
    let threatCount = 0;
    let totalRiskScore = 0;

    for (const r of this.records) {
      const risk = r.riskAssessment?.riskLevel || 'LOW';
      riskBreakdown[risk] = (riskBreakdown[risk] || 0) + 1;

      const cat = r.customerIntelligence?.category || 'General Inquiry';
      categoryBreakdown[cat] = (categoryBreakdown[cat] || 0) + 1;

      const sent = r.customerIntelligence?.sentiment || 'Neutral';
      sentimentBreakdown[sent] = (sentimentBreakdown[sent] || 0) + 1;

      if (r.securityAnalysis?.hasThreat) {
        threatCount++;
      }

      totalRiskScore += (r.riskAssessment?.riskScore || 0);
    }

    return {
      total,
      riskBreakdown,
      categoryBreakdown,
      sentimentBreakdown,
      threatCount,
      threatRate: Math.round((threatCount / total) * 100),
      avgRiskScore: Math.round(totalRiskScore / total),
      recentThreats: this.records.filter(r => r.securityAnalysis?.hasThreat).slice(0, 5)
    };
  }
}

export const db = new Database();
