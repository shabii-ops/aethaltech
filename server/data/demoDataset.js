/**
 * Realistic Demo Dataset Generator
 * Contains 100+ diverse, realistic conversations across 10 distinct categories/security profiles.
 */

export const DEMO_SCENARIOS = [
  {
    id: 'payment_failure',
    title: 'Payment Failure',
    category: 'Payment Failure',
    badge: 'Billing Issue',
    input: "Hi support, my payment for the annual subscription was declined twice today with error code ERR_502, but my credit card statement shows two pending charges of $120. Please reverse the duplicate charge and activate my plan."
  },
  {
    id: 'unresolved_refund',
    title: 'Unresolved Refund',
    category: 'Refund Request',
    badge: 'Customer Dispute',
    input: "I requested a full refund 14 days ago for order #NV-88291. Your agent Sarah promised it would hit my account in 3 business days. It has still not arrived and nobody is answering my emails. I need my $349 back immediately."
  },
  {
    id: 'angry_customer',
    title: 'Angry Customer',
    category: 'Technical Support',
    badge: 'High Frustration',
    input: "THIS IS COMPLETELY UNACCEPTABLE!! Your platform crashed in the middle of our client presentation for the THIRD TIME THIS WEEK! We lost a $50k contract because of your broken software! Fix this bug immediately or I am suing your company!"
  },
  {
    id: 'account_problem',
    title: 'Account Problem',
    category: 'Account Access',
    badge: 'Access Recovery',
    input: "Hello, I am locked out of my corporate admin profile after switching phones. The SMS recovery code is not arriving on my number +1-555-0199. Can an administrator assist me in verifying my identity and unlocking my workspace?"
  },
  {
    id: 'suspicious_url',
    title: 'Suspicious URL',
    category: 'Security & Fraud',
    badge: 'Hostile Host',
    input: "We noticed unexpected outbound traffic to http://194.26.29.112:8080/novapay/login.php from one of our internal workstations. Could your security team verify if this IP belongs to your cloud infrastructure?"
  },
  {
    id: 'phishing_domain',
    title: 'Phishing',
    category: 'Account Security',
    badge: 'Brand Impersonation',
    input: "ALERT: Your NovaPay billing profile is expiring today. To prevent termination, please verify your account details immediately at https://novapay-security-verify.com/login?session=92842 and confirm your card number."
  },
  {
    id: 'otp_social_engineering',
    title: 'OTP Social Engineering',
    category: 'Account Security',
    badge: 'Token Theft',
    input: "Hello, this is Kevin from IT Support Department. We detected an unauthorized login attempt on your account from Russia. I just sent a 6-digit verification code to your mobile phone. Please reply with the OTP immediately to block the hacker."
  },
  {
    id: 'authority_impersonation',
    title: 'Impersonation',
    category: 'Account Security',
    badge: 'Executive Spoof',
    input: "URGENT from Chief Financial Officer: I am currently in a closed board meeting with poor connectivity. We need an urgent wire transfer of $24,500 completed before 3 PM for project acquisition. Send confirmation receipt to ceo-office@novapay-corp.xyz."
  },
  {
    id: 'financial_fraud',
    title: 'Financial Fraud',
    category: 'Payment Failure',
    badge: 'Extortion Pressure',
    input: "ATTENTION: An unauthorized wire transfer of $4,850 was initiated from your checking account. To reverse this transaction, purchase a $500 Apple gift card or send BTC to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 1 hour."
  },
  {
    id: 'combined_threat',
    title: 'Combined Threat (E2E Mandate)',
    category: 'Account Security',
    badge: 'Critical Attack',
    input: "URGENT! Your account has been compromised. Click this link immediately https://novapay-support.online/secure-login and enter your username, password and OTP."
  }
];

export function generateFullDataset() {
  const dataset = [];

  // Group 1: 10 Normal Conversations
  const normalTemplates = [
    "Could you please let me know what integrations are currently supported for Shopify and WooCommerce in the Pro tier?",
    "Hi team, just wanted to say thank you for the swift resolution on ticket #4410 yesterday. Everything works smoothly now!",
    "Hello, is there any scheduled maintenance planned for the reporting dashboard this coming weekend?",
    "Where can I find the official API documentation for webhooks v2? The previous link in the portal returned a 404.",
    "Can we add two additional team members as viewers to our existing organization workspace under the standard plan?",
    "Good morning, I was wondering if your platform supports export to Apache Parquet format in addition to CSV?",
    "Hi, we are evaluating your service for a pilot project of 50 users. Do you offer an extended 30-day trial period?",
    "Please send over the updated SOC2 Type II compliance report for our annual vendor risk review.",
    "Is it possible to customize the notification frequency for daily billing digests?",
    "Thank you for the product demonstration this afternoon. The automated reporting feature looks very promising."
  ];
  normalTemplates.forEach((text, i) => {
    dataset.push({
      inputText: text,
      source: 'Customer Portal',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  // Group 2: 10 Payment Issues
  const paymentTemplates = [
    "My corporate Mastercard was charged $890 twice this morning for the single renewal invoice #INV-2024-991.",
    "Payment failed with code ERR_INSUFFICIENT_FUNDS even though our business bank balance has over $15,000 available.",
    "Why is our credit card being declined during checkout? The bank confirmed no fraud blocks are placed on our end.",
    "We need to update our billing tax ID (VAT) before the upcoming automatic invoice generates next Tuesday.",
    "The currency was billed in EUR instead of USD as configured in our billing preferences, causing FX conversion fees.",
    "Our accounting department needs a formal receipt showing the breakdown of sales tax for invoice #9012.",
    "Subscription got paused due to a failed automated retry. We just updated our corporate card; please re-run payment.",
    "Can we switch our billing payment method from credit card to ACH direct bank transfer for annual invoices?",
    "We received an automated email saying card expiring soon, but the link inside the portal leads to a blank modal.",
    "Why was our account charged an overage fee of $120 when our dashboard showed 18,000 API requests out of 20,000 quota?"
  ];
  paymentTemplates.forEach(text => {
    dataset.push({
      inputText: text,
      source: 'Billing Desk',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  // Group 3: 10 Account Issues
  const accountTemplates = [
    "I am locked out of my account after entering my password incorrectly three times. Please send an unlock link.",
    "Our previous IT admin left the company and we need to transfer primary account ownership to security-lead@novapay.io.",
    "The 2FA authenticator app code is returning 'invalid token' even though the device time is synchronized.",
    "I haven't received the password reset email on user.admin@enterprise.org after multiple requests today.",
    "Can you remove SSO enforcement for one break-glass emergency account so we can troubleshoot Okta SCIM sync?",
    "My user profile shows role as 'Viewer' when my manager granted me 'Billing Administrator' privileges.",
    "How can I delete an inactive secondary workspace without losing data in our primary organization?",
    "We need to re-enable two-factor authentication for a contractor who lost their registered YubiKey hardware key.",
    "User session keeps getting logged out every 5 minutes while working in the analytics builder.",
    "Can you verify why our employee directory sync via Google Workspace stopped updating new hires?"
  ];
  accountTemplates.forEach(text => {
    dataset.push({
      inputText: text,
      source: 'Identity Helpdesk',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  // Group 4: 10 Delivery Issues
  const deliveryTemplates = [
    "Tracking number NV-TRK-9901 shows package stuck in transit at Memphis distribution center for over 6 days.",
    "The hardware POS terminal delivered yesterday was missing the power adapter and USB-C connection cable.",
    "Courier marked order as 'Delivered to front porch' at 2 PM, but our security cameras confirm no delivery took place.",
    "Can we redirect the shipment of replacement smart card readers to our secondary branch office in Austin?",
    "Package arrived severely crushed and the internal display unit is cracked. Photos attached for damage claim.",
    "Delivery was delayed because the shipping carrier recorded 'Incorrect suite number'. We need this expedited.",
    "Where is the second box for our batch hardware order #8841? Only one of two parcels was handed over.",
    "The estimated delivery date has shifted three times this week. Our retail store opening is delayed as a result.",
    "Customs clearance documents were rejected due to missing commercial invoice details on international shipping.",
    "Please cancel the pending courier dispatch for order #6712 as our client requested a different terminal model."
  ];
  deliveryTemplates.forEach(text => {
    dataset.push({
      inputText: text,
      source: 'Logistics Queue',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  // Group 5: 10 Refund Issues
  const refundTemplates = [
    "I cancelled my subscription within the 30-day money-back guarantee window. Please confirm when the $499 refund will post.",
    "Your support agent promised a credit adjustment of $75 for system downtime on March 12th, but it's not on our invoice.",
    "We returned the defective biometric scanner 10 days ago (tracking #940011). When will the refund be issued?",
    "I was charged for an annual renewal that I had disabled auto-renew for. I request an immediate refund.",
    "Our bank processed a chargeback dispute by mistake. We withdrew it; can you please restore account balance?",
    "Where is the refund transaction receipt for accounting reconciliation? We need an official credit note PDF.",
    "We downgrade our plan mid-cycle. Please prorate the remaining 8 months and refund the credit to our card.",
    "Item returned in original packaging was received at warehouse, but refund status still shows 'Pending Inspection'.",
    "Duplicate subscription was activated under wrong email address. Please cancel and refund the duplicate $199 fee.",
    "Our event was cancelled due to severe weather. Can we receive a full refund on the unused event ticketing license?"
  ];
  refundTemplates.forEach(text => {
    dataset.push({
      inputText: text,
      source: 'Refunds Center',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  // Group 6: 10 Technical Issues
  const technicalTemplates = [
    "GraphQL endpoint /api/v2/transactions is returning 500 Internal Server Error when querying pagination cursor.",
    "WebSocket connection drops intermittently every 45 seconds with error code 1006 under moderate load.",
    "CSV bulk import parser is throwing unhandled exception when field contains escaped double quotes and commas.",
    "Mobile iOS application build 2.4.1 crashes immediately upon opening the barcode scanner camera view.",
    "Database replica lag is exceeding 400 seconds, causing stale reads on customer payment verification checks.",
    "CORS preflight request fails with Missing Access-Control-Allow-Origin header on custom domain endpoints.",
    "Memory leak observed in background worker process after processing batch files larger than 50MB.",
    "PDF generation tool fails with timeout error when rendering invoices containing high-resolution company logos.",
    "Redis cache cluster CPU utilization spiked to 98% following the 11:00 AM deployment, causing request throttling.",
    "Search index has stopped indexing newly inserted records since midnight; search queries return outdated data."
  ];
  technicalTemplates.forEach(text => {
    dataset.push({
      inputText: text,
      source: 'Developer Support',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  // Group 7: 10 Negative / Frustrated Conversations
  const frustratedTemplates = [
    "I AM LIVID!! This is the fourth time your software lost our end-of-day reconciliation data! Incompetent service!",
    "Your customer service is completely useless! I have been on hold for 2 hours and transferred 5 times! DISASTER!",
    "Fix this immediately or I am filing a formal complaint with the Consumer Financial Protection Bureau and our attorney!",
    "Worst experience ever! You took our money and our service has been offline for 48 hours with ZERO communication!",
    "Absolute scam! You keep charging our credit card after three separate cancellation requests! Refund us NOW!!",
    "I am sick and tired of your repeated excuses. Your engineering team has no idea what they are doing. Horrible!",
    "UNACCEPTABLE! Our production servers went down during Black Friday sale because of your unannounced database update!",
    "You guys are thieves! Refusing to refund $1,200 for a broken product that never worked from day one!",
    "I demand to speak with a VP or senior director right now! Your frontline agents are completely unhelpful and rude!",
    "Cancel our entire enterprise contract immediately! We are switching to your competitor today after this fiasco!"
  ];
  frustratedTemplates.forEach(text => {
    dataset.push({
      inputText: text,
      source: 'Escalations Desk',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  // Group 8: 10 Phishing Cases
  const phishingTemplates = [
    "SECURITY WARNING: Unauthorized sign-in attempt from IP 185.220.101.5. Confirm your credentials at https://novapay-security-verify.com/login immediately to prevent lock.",
    "URGENT: Your NovaPay merchant profile requires mandatory KYC re-verification. Access http://novapay-kyc-portal.ru/auth to submit your password and identity proof.",
    "Dear customer, your pending payout of $3,420 is on hold. Log in to http://194.87.112.45/verify?token=99281 to confirm your banking password.",
    "Action Required: We detected unusual transaction activity. Visit https://novapay-compliance.live/secure-update and enter your login details.",
    "Your password will expire in 2 hours. To maintain continuous access, click http://bit.ly/novapay-pass-reset and input current username and password.",
    "Notice from Security Team: Your billing account has been suspended. Please confirm your credentials at http://novapay.io.security-alert-center.top/login.",
    "CRITICAL: Immediate action required. An unauthorized device joined your account. Review activity at http://54.211.90.12/auth/login.html now.",
    "Your tax invoice is ready for download. Please access https://secure-novapay-invoice.xyz/auth.php and verify your username to decrypt file.",
    "System Alert: Security settings have been modified. If this was not you, verify account immediately at http://novapay-portal.online/reset.",
    "Urgent security patch required for your desktop client. Download update and enter root administrator password at http://tinyurl.com/novapay-patch."
  ];
  phishingTemplates.forEach(text => {
    dataset.push({
      inputText: text,
      source: 'Security Inbound',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  // Group 9: 10 Social Engineering Cases
  const socialEngTemplates = [
    "Hello, this is James from Corporate IT Helpdesk. We are performing an emergency server migration. Please reply with your 6-digit OTP code to verify your mailbox.",
    "URGENT from Executive Office: CEO Mark needs you to purchase 10x $100 Apple gift cards for the client appreciation dinner. Send card codes to ceo-desk@novapay-corp.xyz.",
    "Hi, I am calling on behalf of Bank Fraud Division. A fraudulent transaction of $1,800 is processing. To cancel it, read back the one-time verification code just sent to your phone.",
    "Immediate action: Compliance audit detected unverified administrative permissions. Enter your current password and 2FA code here to prevent immediate termination.",
    "Internal Security Drill: Please confirm your employee identity by submitting your corporate username and password to hr-security@novapay-hr.online.",
    "Hey quick favor, this is David from DevOps. I am locked out of production bastion host. Can you share your MFA token so I can approve the emergency hotfix?",
    "Attention: Legal department subpoena requires immediate verification. Failure to submit requested credentials within 4 hours will result in statutory penalties.",
    "Your account was accessed from an unrecognized browser in Nigeria. Send your one-time password immediately to verify you are the legitimate account owner.",
    "Hello team, this is the building management network engineer. We are re-registering WiFi MAC addresses. Please provide your network login credentials.",
    "URGENT: Payroll direct deposit failed due to invalid routing information. Provide your social security number and online banking login to avoid salary delay."
  ];
  socialEngTemplates.forEach(text => {
    dataset.push({
      inputText: text,
      source: 'SOC Threat Feed',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  // Group 10: 10 Mixed Customer / Security Cases
  const mixedTemplates = [
    "Hi support, my payment failed this morning, and then I received an email from http://novapay-billing-resolve.xyz telling me to enter my password and card pin to unblock it. Is this legitimate?",
    "I was trying to get a refund for order #4491 when someone claiming to be your agent emailed me from support@novapay-refunds.com asking for my SMS verification code.",
    "Our company card was double charged, and 10 minutes later we received a call claiming our account was compromised and demanding our OTP code to reverse it.",
    "We cannot log into our admin portal, and clicking 'forgot password' directed us to a strange Russian domain http://novapay.ru/login. Could our DNS be hijacked?",
    "A customer called our hotline complaining that an email from billing-alert@novapay-finance.online instructed them to wire funds to a private Bitcoin address.",
    "My delivery was delayed, and when I clicked the SMS tracking link http://bit.ly/novapay-pkg-track, it asked me to enter my Apple ID username and password.",
    "Our technical API integration threw 401 Unauthorized, and someone on Slack claiming to be IT Support asked for our private production API secret keys.",
    "I am extremely frustrated with unresolved refund #9901, and now a suspicious email from refund-help@novapay.buzz is asking for my full credit card CVV code!",
    "Account access was locked out after payment error, and now we received an urgent message saying pay $250 in crypto to restore service immediately.",
    "URGENT! Your account has been compromised. Click this link immediately https://novapay-support.online/secure-login and enter your username, password and OTP."
  ];
  mixedTemplates.forEach(text => {
    dataset.push({
      inputText: text,
      source: 'Mixed Incident Channel',
      createdAt: new Date(Date.now() - (100 - dataset.length) * 3600000).toISOString()
    });
  });

  return dataset;
}
