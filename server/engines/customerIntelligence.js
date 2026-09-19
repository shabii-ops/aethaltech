/**
 * Customer Intelligence Engine
 * Handles Complaint Classification, Sentiment Analysis, Keyword/Issue Extraction, and Summarization.
 */

// Categorization Lexicon & Pattern Weights
const CATEGORY_RULES = [
  {
    category: 'Account Security',
    patterns: [
      /\b(compromised|hacked|breach|unauthorized access|unrecognized login|stolen|phishing|suspicious activity|password reset|2fa|otp)\b/i,
      /\b(security alert|account locked|fraud alert)\b/i
    ],
    weight: 25
  },
  {
    category: 'Payment Failure',
    patterns: [
      /\b(payment failed|card declined|double charged|charged twice|transaction failed|billing error|payment not going through|money deducted|deducted but not received)\b/i,
      /\b(credit card|debit card|checkout failed|stripe|paypal failure)\b/i
    ],
    weight: 20
  },
  {
    category: 'Refund Request',
    patterns: [
      /\b(refund|money back|reimbursement|return money|return policy|chargeback|cancel subscription and refund)\b/i
    ],
    weight: 20
  },
  {
    category: 'Delivery Issue',
    patterns: [
      /\b(delivery|shipping|tracking|package|courier|delayed shipment|not delivered|missing item|damaged package|dispatch)\b/i
    ],
    weight: 18
  },
  {
    category: 'Account Access',
    patterns: [
      /\b(cannot login|forgot password|locked out|reset link not working|login error|blocked account|reactivate account)\b/i
    ],
    weight: 18
  },
  {
    category: 'Technical Support',
    patterns: [
      /\b(bug|error code|crash|app keeps crashing|server error|500 internal|glitch|api error|feature not working|slow loading|connection timeout)\b/i
    ],
    weight: 16
  }
];

// Sentiment Lexicon
const POSITIVE_WORDS = new Set([
  'great', 'excellent', 'fast', 'helpful', 'resolved', 'thanks', 'thank', 'appreciate',
  'amazing', 'good', 'wonderful', 'perfect', 'awesome', 'fixed', 'pleased', 'satisfied'
]);

const NEGATIVE_WORDS = new Set([
  'bad', 'poor', 'terrible', 'horrible', 'worst', 'failed', 'broken', 'disappointed',
  'unacceptable', 'disaster', 'useless', 'unhelpful', 'scam', 'ridiculous', 'waste', 'annoying'
]);

const FRUSTRATED_WORDS = new Set([
  'furious', 'livid', 'lawyer', 'sue', 'unacceptable', 'disgusted', 'sick and tired',
  'demanding', 'immediately', 'outrageous', 'steal', 'robbery', 'incompetent', 'cheated'
]);

const STOP_WORDS = new Set([
  'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', 'aren\'t',
  'as', 'at', 'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by',
  'can', 'can\'t', 'cannot', 'could', 'couldn\'t', 'did', 'didn\'t', 'do', 'does', 'doesn\'t', 'doing',
  'don\'t', 'down', 'during', 'each', 'few', 'for', 'from', 'further', 'had', 'hadn\'t', 'has', 'hasn\'t',
  'have', 'haven\'t', 'having', 'he', 'he\'d', 'he\'ll', 'he\'s', 'her', 'here', 'here\'s', 'hers',
  'herself', 'him', 'himself', 'his', 'how', 'how\'s', 'i', 'i\'d', 'i\'ll', 'i\'m', 'i\'ve', 'if',
  'in', 'into', 'is', 'isn\'t', 'it', 'it\'s', 'its', 'itself', 'let\'s', 'me', 'more', 'most', 'mustn\'t',
  'my', 'myself', 'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'ought', 'our',
  'ours', 'ourselves', 'out', 'over', 'own', 'same', 'shan\'t', 'she', 'she\'d', 'she\'ll', 'she\'s',
  'should', 'shouldn\'t', 'so', 'some', 'such', 'than', 'that', 'that\'s', 'the', 'their', 'theirs',
  'them', 'themselves', 'then', 'there', 'there\'s', 'these', 'they', 'they\'d', 'they\'ll', 'they\'re',
  'they\'ve', 'this', 'those', 'through', 'to', 'too', 'under', 'until', 'up', 'very', 'was', 'wasn\'t',
  'we', 'we\'d', 'we\'ll', 'we\'re', 'we\'ve', 'were', 'weren\'t', 'what', 'what\'s', 'when', 'when\'s',
  'where', 'where\'s', 'which', 'while', 'who', 'who\'s', 'whom', 'why', 'why\'s', 'with', 'won\'t',
  'would', 'wouldn\'t', 'you', 'you\'d', 'you\'ll', 'you\'re', 'you\'ve', 'your', 'yours', 'yourself'
]);

export function analyzeCustomerIntelligence(preprocessed, securityContext = {}) {
  const { cleanText, tokens, sentences } = preprocessed;
  const lowerText = cleanText.toLowerCase();

  // 1. Complaint Classification
  let bestCategory = 'General Inquiry';
  let highestScore = 0;

  // If critical security signals are present, bump Account Security
  const securityOverride = securityContext.hasThreat && (
    lowerText.includes('account') || 
    lowerText.includes('password') || 
    lowerText.includes('login') || 
    lowerText.includes('compromised') ||
    lowerText.includes('otp')
  );

  if (securityOverride) {
    bestCategory = 'Account Security';
    highestScore = 50;
  } else {
    for (const rule of CATEGORY_RULES) {
      let score = 0;
      for (const pattern of rule.patterns) {
        const matches = cleanText.match(pattern);
        if (matches) {
          score += rule.weight * matches.length;
        }
      }
      if (score > highestScore) {
        highestScore = score;
        bestCategory = rule.category;
      }
    }
  }

  // 2. Sentiment Analysis & Frustration Detection
  let posCount = 0;
  let negCount = 0;
  let frustCount = 0;

  for (const token of tokens) {
    if (POSITIVE_WORDS.has(token)) posCount++;
    if (NEGATIVE_WORDS.has(token)) negCount++;
    if (FRUSTRATED_WORDS.has(token)) frustCount++;
  }

  // Punctuation and casing signals
  const shoutyMatches = cleanText.match(/[A-Z]{3,}/g) || [];
  const exclamationMatches = cleanText.match(/!{2,}|\?{2,}|!\?/g) || [];
  const shoutyBonus = shoutyMatches.length * 0.2;
  const punctuationBonus = exclamationMatches.length * 0.3;

  // Compute sentiment polarity (-1.0 to 1.0)
  const totalSentimentTokens = posCount + negCount + frustCount;
  let sentimentScore = 0;
  if (totalSentimentTokens > 0) {
    sentimentScore = (posCount - (negCount + frustCount * 1.5)) / totalSentimentTokens;
  }
  sentimentScore = Math.max(-1.0, Math.min(1.0, sentimentScore - (shoutyBonus + punctuationBonus) * 0.2));

  // Determine sentiment label
  let sentiment = 'Neutral';
  if (frustCount >= 2 || (frustCount >= 1 && (shoutyMatches.length > 0 || exclamationMatches.length > 0)) || sentimentScore <= -0.6) {
    sentiment = 'Frustrated';
  } else if (sentimentScore <= -0.15 || negCount > posCount) {
    sentiment = 'Negative';
  } else if (sentimentScore >= 0.2 && posCount > negCount) {
    sentiment = 'Positive';
  }

  // 3. Issue & Keyword Extraction
  const wordFreq = {};
  for (const token of tokens) {
    if (token.length > 3 && !STOP_WORDS.has(token)) {
      wordFreq[token] = (wordFreq[token] || 0) + 1;
    }
  }
  const extractedKeywords = Object.entries(wordFreq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([word]) => word);

  // Extract core issues (phrases or notable terms)
  const issueCandidates = [];
  if (lowerText.includes('payment') || lowerText.includes('charge')) issueCandidates.push('Billing Discrepancy');
  if (lowerText.includes('refund')) issueCandidates.push('Refund Pending');
  if (lowerText.includes('compromised') || lowerText.includes('hacked')) issueCandidates.push('Compromised Account Alert');
  if (lowerText.includes('otp') || lowerText.includes('password')) issueCandidates.push('Authentication Credential Disclosure');
  if (lowerText.includes('delivery') || lowerText.includes('package')) issueCandidates.push('Order Logistics Delay');
  if (lowerText.includes('error') || lowerText.includes('crash')) issueCandidates.push('Software Service Degradation');
  if (issueCandidates.length === 0) {
    issueCandidates.push(bestCategory);
  }

  // 4. Extractive Summarization
  const summary = generateSummary(sentences, cleanText);

  // 5. Customer Priority Determination
  let priority = 'LOW';
  if (bestCategory === 'Account Security' || securityContext.hasThreat) {
    priority = (sentiment === 'Frustrated' || lowerText.includes('urgent') || securityContext.threatScore >= 50) ? 'URGENT' : 'HIGH';
  } else if (sentiment === 'Frustrated' || lowerText.includes('urgent') || highestScore >= 40) {
    priority = 'HIGH';
  } else if (sentiment === 'Negative' || highestScore >= 20) {
    priority = 'MEDIUM';
  }

  return {
    category: bestCategory,
    categoryConfidence: Math.min(0.98, Math.max(0.65, 0.5 + highestScore * 0.02)),
    sentiment,
    sentimentScore: Math.round(sentimentScore * 100) / 100,
    priority,
    summary,
    extractedKeywords,
    keyIssues: issueCandidates
  };
}

function generateSummary(sentences, rawText) {
  if (!sentences || sentences.length === 0) {
    return rawText.substring(0, 150) + (rawText.length > 150 ? '...' : '');
  }
  if (sentences.length <= 2) {
    return sentences.join(' ');
  }

  // Rank sentences by key action words and informative density
  const scoredSentences = sentences.map((s, idx) => {
    let score = 0;
    const lower = s.toLowerCase();
    if (idx === 0) score += 4; // first sentence often contains prime intent
    if (idx === sentences.length - 1) score += 2; // last sentence often contains request
    if (/\b(urgent|need|help|problem|issue|failed|refund|compromised|stolen|cancel|error)\b/i.test(lower)) score += 3;
    if (s.length > 25 && s.length < 180) score += 2;
    return { sentence: s, score };
  });

  scoredSentences.sort((a, b) => b.score - a.score);
  const selected = scoredSentences.slice(0, 2).map(item => item.sentence);
  
  // Maintain original order of appearance
  return sentences.filter(s => selected.includes(s)).join(' ');
}
