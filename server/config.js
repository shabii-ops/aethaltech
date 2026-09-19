import dotenv from 'dotenv';
dotenv.config();

export const CONFIG = {
  PORT: process.env.PORT || 3000,
  COMPANY_NAME: process.env.COMPANY_NAME || 'Aethel Technologies',
  COMPANY_DOMAIN: process.env.COMPANY_DOMAIN || 'aetheltech.io',
  COMPANY_KEYWORDS: ['aethel', 'aetheltech', 'aethel-tech', 'novapay'],
  AI_API_KEY: process.env.AI_API_KEY || process.env.GEMINI_API_KEY || process.env.ANTIGRAVITY_API_KEY || '',
  AI_MODEL: process.env.AI_MODEL || 'gemini-1.5-flash',
  DATA_DIR: './data'
};
