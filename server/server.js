import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { CONFIG } from './config.js';
import apiRouter from './routes/api.js';
import { db } from './db.js';
import { generateFullDataset } from './data/demoDataset.js';
import { processPipeline } from './engines/aiHybrid.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Static frontend assets
app.use(express.static(path.join(__dirname, '../public')));

// Mount API routes
app.use('/api', apiRouter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    version: '1.0.0',
    mode: CONFIG.AI_API_KEY ? 'Hybrid (AI + Deterministic)' : 'Deterministic High-Performance',
    company: CONFIG.COMPANY_NAME,
    domain: CONFIG.COMPANY_DOMAIN,
    recordsInDb: db.records.length,
    uptime: process.uptime()
  });
});

// Single Page App fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Auto-seed if database is empty on start
async function autoSeedIfEmpty() {
  if (db.records.length === 0) {
    console.log('[Bootstrap] Initializing database with 100 realistic heterogeneous conversations...');
    const rawItems = generateFullDataset();
    const processed = [];
    for (const raw of rawItems) {
      const analysis = await processPipeline(raw.inputText, {
        source: raw.source,
        companyDomain: CONFIG.COMPANY_DOMAIN
      });
      processed.push({
        ...analysis,
        createdAt: raw.createdAt
      });
    }
    db.insertMany(processed);
    console.log(`[Bootstrap] Successfully seeded ${processed.length} incidents across 10 categories & security profiles.`);
  } else {
    console.log(`[Bootstrap] Loaded ${db.records.length} persistent incidents from database.`);
  }
}

app.listen(CONFIG.PORT, async () => {
  console.log(`=======================================================`);
  console.log(`🚀 Customer Intelligence & Security Risk Platform`);
  console.log(`📡 Server running on http://localhost:${CONFIG.PORT}`);
  console.log(`🛡️  Company Domain Target: ${CONFIG.COMPANY_DOMAIN}`);
  console.log(`🤖 AI Enhancement: ${CONFIG.AI_API_KEY ? 'ENABLED' : 'OFFLINE DETERMINISTIC (100% Reliable)'}`);
  console.log(`=======================================================`);
  await autoSeedIfEmpty();
});
