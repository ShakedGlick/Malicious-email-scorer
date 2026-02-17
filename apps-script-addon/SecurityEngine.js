function calculateRiskScore(context, message) {
  var score = 0;
  var reasons = [];
  var weights = SECURITY_CONFIG.WEIGHTS;

  // 1. BLACKLIST CHECK
  if (DataStore.isBlacklisted(context.sender)) {
    return { score: 100, reasons: ["🛑 **User Blacklist**: You have manually blocked this sender."] };
  }

  // 2. GLOBAL THREAT INTELLIGENCE (Blocklist by domain)
  //currently hardcoded- next step is checking with known global
  if (SECURITY_CONFIG.GLOBAL_BLOCKLIST.some(function(blocked) {
    return context.domain === blocked || context.domain.endsWith("." + blocked);
  })) {
    score += 90;
    reasons.push("🛑 **Known Threat**: Domain flagged in global malicious database.");
  }

  // 3. IDENTITY SPOOFING (Watched Brands)
  //checks that the name matches the email 
  SECURITY_CONFIG.WATCHED_BRANDS.forEach(function(brand) {
    if (context.displayName.toLowerCase().indexOf(brand) !== -1 && context.sender.indexOf(brand) === -1) {
      score += weights.IDENTITY_SPOOFING;
      reasons.push("🛑 **Identity Spoofing**: Display name claims to be " + brand + " but the email domain is unverified.");
    }
  });

  // 4. SMART WHITELIST (Trust but Verify)
  //checks if it manully whitelisted and than reduced the risk score 
  if (DataStore.getWhitelist().toLowerCase().indexOf(context.domain) !== -1) {
    score -= 30;
    reasons.push("✅ **Policy Trust**: This domain is on your organization's whitelist.");
  }

  // 5. BEHAVIORAL REPUTATION
  //checks for history 
  var history = DataStore.getReputation(context.sender);
  if (history.avgScore > 80) {
    score += 100;
    reasons.push("🛑 **User Trained Risk**: You previously flagged this sender as a threat.");
  } else if (history.count >= 5 && history.avgScore < 15) {
    score -= 10;
    reasons.push("✅ **Trusted Contact**: Consistent safe history with this sender.");
  } else if (history.count === 0) {
    score += weights.NEW_SENDER_PENALTY;
    reasons.push("🔍 **First Encounter**: You have never received mail from this address before.");
  }

  // 6. STATIC HEURISTICS (Attachments & Language) 
  // checks if contains exe files 
  // added pdf just for demo 
  if (context.attachments.some(f => f.getName().toLowerCase().match(/\.(exe|js|vbs|pdf)$/))) {
    score += weights.CRITICAL_ATTACHMENT;
    reasons.push("🛑 **Dangerous File**: Attachment contains a potentially malicious script or executable.");
  }
//checks for commen words that use pressure for phishing 
  var urgencyWords = ["urgent", "action", "verify", "suspended", "password"];
  if (urgencyWords.some(word => context.subject.toLowerCase().indexOf(word) !== -1)) {
    score += weights.URGENCY_KEYWORDS;
    reasons.push("⚠️ **Urgency**: Subject line uses pressure language typical of phishing.");
  }

  return {
    score: Math.max(0, Math.min(score, 100)),
    reasons: reasons.length ? reasons : ["✅ No immediate red flags detected."]
  };
}

  
