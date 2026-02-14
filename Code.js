/**
 * ==========================================
 * GLOBAL CONFIGURATION (The Policy)
 * ==========================================
 */
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
  var sender = extractEmailAddress(message.getFrom());

  var subject = message.getSubject();
  var userProperties = PropertiesService.getUserProperties();

  var analysis = calculateRiskScore(sender, subject, [], message);
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
      .addButton(CardService.newTextButton().setText("👍 Correct").setOnClickAction(CardService.newAction().setFunctionName("handleFeedback").setParameters({
        status: "correct", 
        sender: sender,
        currentScore: totalScore.toString()
      })))
      .addButton(CardService.newTextButton().setText("👎 Wrong").setOnClickAction(CardService.newAction().setFunctionName("handleFeedback").setParameters({
        status: "wrong", 
        sender: sender,
        currentScore: totalScore.toString()
      })))
  );

  actionSection.addWidget(CardService.newTextButton().setText("🔍 Run Deep Check").setTextButtonStyle(CardService.TextButtonStyle.FILLED).setOnClickAction(CardService.newAction().setFunctionName("executeDeepCheck").setParameters({sender: sender})));

  card.addSection(actionSection);

  var manageSection = CardService.newCardSection().setHeader("Manage Blacklist");
  var isBlacklisted = userProperties.getProperty("BL_" + sender) === "true";
  manageSection.addWidget(CardService.newTextButton().setText(isBlacklisted ? "✅ Remove from Blacklist" : "🚫 Blacklist Sender").setOnClickAction(CardService.newAction().setFunctionName(isBlacklisted ? "removeFromBlacklist" : "blacklistSender").setParameters({ "senderEmail": sender })));
  manageSection.addWidget(CardService.newTextButton().setText("🗑️ Clear Blacklist").setOnClickAction(CardService.newAction().setFunctionName("clearAllBlacklist")));

  return card.addSection(manageSection).build();
}

/**
 * IDENTITY EXTRACTION HELPERS
 */
function extractEmailAddress(fromField) {
  var match = fromField.match(/<([^>]+)>/);
  var email = match ? match[1] : fromField;
  return String(email).trim().toLowerCase();
}

function extractDomain(email) {
  var parts = String(email).split('@');
  return (parts.length === 2) ? parts[1].toLowerCase() : "";
}

/**
 * SCORING ENGINE
 */
function calculateRiskScore(sender, subject, links, message) {
  var score = 0;
  var reasons = [];
  var weights = SECURITY_CONFIG.WEIGHTS;
  var userProperties = PropertiesService.getUserProperties();

  // 1. Personal Blacklist
  if (userProperties.getProperty("BL_" + sender) === "true")
    return { score: 100, reasons: ["🛑 **User Blacklist**: Blocked sender."] };

  // 2. Global Threat Intelligence
  var senderDomain = extractDomain(sender);
  if (SECURITY_CONFIG.GLOBAL_BLOCKLIST.some(blocked => senderDomain === blocked || senderDomain.endsWith("." + blocked))) {
    score += 90;
    reasons.push("🛑 **Known Threat**: Domain flagged in global malicious database.");
  }

  // 3.  Whitelist
  var whitelist = userProperties.getProperty("DOMAIN_WHITELIST") || "";
  if (whitelist.toLowerCase().indexOf(senderDomain) !== -1) {
    score -= 30; 
    reasons.push("✅ **Policy Trust**: Domain is whitelisted. Sensitivity reduced.");
  }

  // 4. Reputation History
  var historyStr = userProperties.getProperty("REP_" + sender);
  if (historyStr) {
    var history = JSON.parse(historyStr);
    if (history.count >= 5 && history.avgScore < 15) { 
      score -= 10; 
      reasons.push("✅ **Trusted Contact**: Safe history confirmed."); 
    }
    if (history.avgScore > 80) {
      score += 100;
      reasons.push("🛑 **User Trained Risk**: You previously flagged this sender as malicious.");
    }
  } else {
    score += weights.NEW_SENDER_PENALTY;
    reasons.push("🔍 **First Encounter**: New sender.");
  }

  // 5. Static Heuristics
  if (message.getAttachments().some(f => f.getName().toLowerCase().match(/\.(exe|js|vbs)$/))) { score += weights.CRITICAL_ATTACHMENT; reasons.push("🛑 **Dangerous File**: Executable found."); }
  if (["urgent", "action", "verify", "suspended","password"].some(w => subject.toLowerCase().includes(w))) { score += weights.URGENCY_KEYWORDS; reasons.push("⚠️ **Urgency**: Pressure language."); }

  return { score: Math.max(0, Math.min(score, 100)), reasons: reasons.length ? reasons : ["✅ No red flags."] };
}

/**
 * MANAGEMENT CONSOLE
 */
function buildHomepage(e) {
  var userProperties = PropertiesService.getUserProperties();
  var currentThreshold = userProperties.getProperty("MIN_MALICIOUS_SCORE") || "70";
  var currentWhitelist = userProperties.getProperty("DOMAIN_WHITELIST") || "No domains whitelisted";
  
  var card = CardService.newCardBuilder().setHeader(CardService.newCardHeader().setTitle("🛡️ Settings").setSubtitle("System Policy"));
  var settingsSection = CardService.newCardSection().setHeader("Sensitivity")
      .addWidget(CardService.newTextParagraph().setText("Threshold: <b>" + currentThreshold + "</b>"))
      .addWidget(CardService.newDecoratedText().setText("Strict Mode (60)").setSwitchControl(CardService.newSwitch().setFieldName("strict_mode").setValue("enabled").setSelected(currentThreshold === "60").setOnChangeAction(CardService.newAction().setFunctionName("updateThreshold"))));

  var whitelistSection = CardService.newCardSection().setHeader("Policy: Whitelist")
      .addWidget(CardService.newTextParagraph().setText("Trusted: <i>" + currentWhitelist + "</i>"))
      .addWidget(CardService.newTextInput().setFieldName("new_domain").setTitle("Add Domain").setHint("e.g., bgu.ac.il"))
      .addWidget(CardService.newTextButton().setText("💾 Save Whitelist").setOnClickAction(CardService.newAction().setFunctionName("saveWhitelist")));

  return card.addSection(settingsSection).addSection(whitelistSection).build();
}

/**
 * ACTION HANDLERS
 */
function handleFeedback(e) {
  var status = e.parameters.status;
  var sender = e.parameters.sender;
  var currentScore = parseInt(e.parameters.currentScore || "0");
  var userProperties = PropertiesService.getUserProperties();
  
  if (status === "wrong") {
    var wasMarkedSafe = currentScore < 30; 
    var message = "";

    if (wasMarkedSafe) {
      userProperties.setProperty("BL_" + sender, "true");
      userProperties.setProperty("REP_" + sender, JSON.stringify({count: 10, avgScore: 90}));
      message = "Sender blacklisted and flagged as high-risk.";
    } else {
      userProperties.deleteProperty("REP_" + sender);
      userProperties.deleteProperty("BL_" + sender);
      message = "Sender whitelisted and removed from blacklist.";
    }
    
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText("System trained: " + message))
        .setNavigation(CardService.newNavigation().updateCard(buildAddOn(e)))
        .build();
  }
  return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText("Verdict confirmed.")).build();
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

function saveWhitelist(e) { PropertiesService.getUserProperties().setProperty("DOMAIN_WHITELIST", e.formInput.new_domain); return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText("Policy Updated.")).setNavigation(CardService.newNavigation().updateCard(buildHomepage(e))).build(); }
function updateThreshold(e) { PropertiesService.getUserProperties().setProperty("MIN_MALICIOUS_SCORE", (e.formInput.strict_mode === "enabled") ? "60" : "70"); return CardService.newNavigation().updateCard(buildHomepage(e)); }
function blacklistSender(e) { PropertiesService.getUserProperties().setProperty("BL_" + e.parameters.senderEmail, "true"); return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText("Blacklisted.")).setNavigation(CardService.newNavigation().updateCard(buildAddOn(e))).build(); }
function removeFromBlacklist(e) { PropertiesService.getUserProperties().deleteProperty("BL_" + e.parameters.senderEmail); return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText("Removed.")).setNavigation(CardService.newNavigation().updateCard(buildAddOn(e))).build(); }
function clearAllBlacklist() { var props = PropertiesService.getUserProperties(); var all = props.getProperties(); Object.keys(all).forEach(function(key) { if (key.indexOf("BL_") === 0) props.deleteProperty(key); }); return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText("Blacklist cleared.")).build(); }