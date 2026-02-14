/**
 * ==========================================
 * GLOBAL CONFIGURATION (The Policy)
 * ==========================================
 */
//saved as global so can be easily modified and modular
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

/**
 * Main function called by Gmail when an email is opened.
 */
function buildAddOn(e) {
  var accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  
  var messageId = e.gmail.messageId;
  var message = GmailApp.getMessageById(messageId);
  var sender = extractEmailAddress(message.getFrom()); // sender = user@domain.com


  var subject = message.getSubject();
  var userProperties = PropertiesService.getUserProperties();

  var analysis = calculateRiskScore(sender, subject, [], message);//caling the scoring mec. links not implemnted yet 
  var totalScore = analysis.score;
  var reasons = analysis.reasons;

  recordSenderHistory(sender, totalScore);

  var threshold = parseInt(userProperties.getProperty("MIN_MALICIOUS_SCORE") || "70");
  var verdict = (totalScore >= threshold)
  ? "MALICIOUS"
  : (totalScore >= SECURITY_CONFIG.THRESHOLDS.SUSPICIOUS ? "SUSPICIOUS" : "SAFE");


  var card = CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("Verdict: " + verdict).setSubtitle("Risk Score: " + totalScore + "/100"));

  card.addSection(CardService.newCardSection().setHeader("Security Analysis")
      .addWidget(CardService.newTextParagraph().setText("<b>Reasoning:</b>\n\n" + reasons.join("\n\n"))));

  var actionSection = CardService.newCardSection().setHeader("User Actions");
  actionSection.addWidget(CardService.newButtonSet()
      .addButton(CardService.newTextButton().setText("👍 Correct").setOnClickAction(CardService.newAction().setFunctionName("handleFeedback").setParameters({status: "correct", sender: sender})))
      .addButton(CardService.newTextButton().setText("👎 Wrong").setOnClickAction(CardService.newAction().setFunctionName("handleFeedback").setParameters({status: "wrong", sender: sender})))
  );
  actionSection.addWidget(CardService.newTextButton().setText("🔍 Run Deep Check").setTextButtonStyle(CardService.TextButtonStyle.FILLED).setOnClickAction(CardService.newAction().setFunctionName("executeDeepCheck").setParameters({sender: sender})));

  card.addSection(actionSection);

  var manageSection = CardService.newCardSection().setHeader("Manage Blacklist");
  var isBlacklisted = userProperties.getProperty("BL_" + sender) === "true";
  manageSection.addWidget(CardService.newTextButton().setText(isBlacklisted ? "✅ Remove Blacklist" : "🚫 Blacklist Sender").setOnClickAction(CardService.newAction().setFunctionName(isBlacklisted ? "removeFromBlacklist" : "blacklistSender").setParameters({ "senderEmail": sender })));
  manageSection.addWidget(CardService.newTextButton().setText("🗑️ Clear Blacklist").setOnClickAction(CardService.newAction().setFunctionName("clearAllBlacklist")));
  //need to modifiy here just to clear black list 
  //make sure the black list is saving the sender not the show name 

  return card.addSection(manageSection).build();
}

function extractEmailAddress(fromField) {
  // Handles: 'Name <user@domain.com>' OR 'user@domain.com'
  var match = fromField.match(/<([^>]+)>/);
  var email = match ? match[1] : fromField;
  return String(email).trim().toLowerCase();
}

function extractDomain(email) {
  var parts = String(email).split('@');
  return (parts.length === 2) ? parts[1].toLowerCase() : "";
}


/**
 * SCORING ENGINE: Now with Smart Whitelist & Global Intel
 */
function calculateRiskScore(sender, subject, links, message) {
  var score = 0;
  var reasons = [];
  var weights = SECURITY_CONFIG.WEIGHTS;
  var userProperties = PropertiesService.getUserProperties();

  // 1. Check Personal Blacklist (Instant 100)
  if (userProperties.getProperty("BL_" + sender) === "true")
  return { score: 100, reasons: ["🛑 **User Blacklist**: Blocked sender."] };


  // 2. Check Global Threat Intelligence
  var senderDomain = extractDomain(sender);

  if (SECURITY_CONFIG.GLOBAL_BLOCKLIST.some(blocked => senderDomain === blocked || senderDomain.endsWith("." +  blocked))) {
  score += 90;
  reasons.push("🛑 **Known Threat**: Domain flagged in global malicious database.");
}


  // 3. Smart Whitelist Discount (Trust but Verify)
  var senderDomain = extractDomain(sender);
  var whitelist = userProperties.getProperty("DOMAIN_WHITELIST") || "";
  if (whitelist.toLowerCase().indexOf(senderDomain) !== -1) {
    score -= 30; 
    reasons.push("✅ **Policy Trust**: Domain is whitelisted. Sensitivity reduced.");
  }

  // 4. Reputation History
  var historyStr = userProperties.getProperty("REP_" + sender);
  if (historyStr) {
    var history = JSON.parse(historyStr);
    if (history.count >= 5 && history.avgScore < 15) { score -= 10; reasons.push("✅ **Trusted Contact**: Safe history."); }
  } else {
    score += weights.NEW_SENDER_PENALTY;
    reasons.push("🔍 **First Encounter**: New sender.");
  }

  // 5. Traditional Scans (Spoofing, Files, Urgency)
  var fromHeader = message.getFrom();
  var displayName = fromHeader.split('<')[0].replace(/"/g, '').trim();
  SECURITY_CONFIG.WATCHED_BRANDS.forEach(brand => {
    if (displayName.toLowerCase().indexOf(brand) !== -1 && sender.indexOf(brand) === -1) {
      score += weights.IDENTITY_SPOOFING;
      reasons.push("🛑 **Identity Spoofing**: Name claims to be " + brand);
    }
  });

  if (message.getAttachments().some(f => f.getName().toLowerCase().match(/\.(exe|js|vbs)$/))) { score += weights.CRITICAL_ATTACHMENT; reasons.push("🛑 **Dangerous File**: Executable found."); }
  if (["urgent", "action", "verify", "suspended"].some(w => subject.toLowerCase().includes(w))) { score += weights.URGENCY_KEYWORDS; reasons.push("⚠️ **Urgency**: Pressure language."); }

  return { score: Math.max(0, Math.min(score, 100)), reasons: reasons.length ? reasons : ["✅ No red flags."] };
}

/**
 * REFINED HOMEPAGE: Management Console
 */
function buildHomepage(e) {
  var userProperties = PropertiesService.getUserProperties();
  var currentThreshold = userProperties.getProperty("MIN_MALICIOUS_SCORE") || "70";
  var currentWhitelist = userProperties.getProperty("DOMAIN_WHITELIST") || "No domains whitelisted";
  
  var card = CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle("🛡️ Settings").setSubtitle("System Policy"));

  var settingsSection = CardService.newCardSection()
      .setHeader("Sensitivity")
      .addWidget(CardService.newTextParagraph().setText("Threshold: <b>" + currentThreshold + "</b>"))
      .addWidget(CardService.newDecoratedText().setText("Strict Mode (60)").setSwitchControl(CardService.newSwitch().setFieldName("strict_mode").setValue("enabled").setSelected(currentThreshold === "60").setOnChangeAction(CardService.newAction().setFunctionName("updateThreshold"))));

  var whitelistSection = CardService.newCardSection()
      .setHeader("Policy: Whitelist")
      .addWidget(CardService.newTextParagraph().setText("Trusted: <i>" + currentWhitelist + "</i>"))
      .addWidget(CardService.newTextInput().setFieldName("new_domain").setTitle("Add Domain").setHint("e.g., bgu.ac.il"))
      .addWidget(CardService.newTextButton().setText("💾 Save Whitelist").setOnClickAction(CardService.newAction().setFunctionName("saveWhitelist")));

  return card.addSection(settingsSection).addSection(whitelistSection).build();
}

/**
 * ACTION HANDLERS
 */
function saveWhitelist(e) {
  PropertiesService.getUserProperties().setProperty("DOMAIN_WHITELIST", e.formInput.new_domain);
  return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText("Policy Updated.")).setNavigation(CardService.newNavigation().updateCard(buildHomepage(e))).build();
}

function updateThreshold(e) {
  PropertiesService.getUserProperties().setProperty("MIN_MALICIOUS_SCORE", (e.formInput.strict_mode === "enabled") ? "60" : "70");
  return CardService.newNavigation().updateCard(buildHomepage(e));
}

function handleFeedback(e) {
  var status = e.parameters.status;
  var sender = e.parameters.sender;
  var userProperties = PropertiesService.getUserProperties();
  var history = JSON.parse(userProperties.getProperty("REP_" + sender) || '{"count":1, "avgScore":50}');
  var msg = "Verdict confirmed.";
  if (status === "wrong") {
    var newAvg = (history.avgScore < 50) ? 90 : 0; 
    userProperties.setProperty("REP_" + sender, JSON.stringify({count: 10, avgScore: newAvg, lastSeen: new Date().toISOString()}));
    msg = (newAvg === 0) ? "Sender whitelisted." : "Sender flagged as risk.";
  }
  return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText("System trained: " + msg)).build();
}

function executeDeepCheck(e) {
  var domain = extractDomain(e.parameters.sender);
  try {
    var response = UrlFetchApp.fetch("https://rdap.org/domain/" + domain, {muteHttpExceptions: true});
    var resultText = (response.getResponseCode() === 200) ? "✅ Registered domain." : "⚠️ Unverified/Burner domain.";
    return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText(resultText)).build();
  } catch (err) {
    return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText("Deep Scan: Service timeout.")).build();
  }
}

function recordSenderHistory(sender, score) {
  var props = PropertiesService.getUserProperties();
  var data = JSON.parse(props.getProperty("REP_" + sender) || '{"count":0,"avgScore":0}');
  data.avgScore = ((data.avgScore * data.count) + score) / (data.count + 1);
  data.count++;
  props.setProperty("REP_" + sender, JSON.stringify(data));
}

function blacklistSender(e) {
  PropertiesService.getUserProperties().setProperty("BL_" + e.parameters.senderEmail, "true");
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Blacklisted."))
    .build();
}

function removeFromBlacklist(e) {
  PropertiesService.getUserProperties().deleteProperty("BL_" + e.parameters.senderEmail);
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Removed."))
    .build();
}

function clearAllBlacklist() {
  var props = PropertiesService.getUserProperties();
  var all = props.getProperties();
  Object.keys(all).forEach(function(key) {
    if (key.indexOf("BL_") === 0) props.deleteProperty(key);
  });

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Blacklist cleared."))
    .build();
}
