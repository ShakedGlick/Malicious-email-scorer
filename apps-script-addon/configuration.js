var SECURITY_CONFIG = {
  THRESHOLDS: { MALICIOUS: 70, SUSPICIOUS: 30 },
  WEIGHTS: {
    CRITICAL_ATTACHMENT: 60,
    IDENTITY_SPOOFING: 70,
    LINK_OBFUSCATION: 65,
    URGENCY_KEYWORDS: 30,
     SECURITY_SIGNATURE_FAIL: 60,
    NEW_SENDER_PENALTY: 15
  },
  WATCHED_BRANDS: ["google", "apple", "paypal", "microsoft", "amazon", "bank"],
  GLOBAL_BLOCKLIST: ["spamsender.com", "phish-site.net", "verify-bank.io"]
};
