/**
 * ==========================================
 * ACTION HANDLERS (Buttons + Settings)
 * ==========================================
 * - Feedback buttons
 * - Deep check 
 * - Whitelist / Threshold settings
 * - Blacklist management
 */

/**
 * User feedback: Correct / Wrong
 */
function handleFeedback(e) {
  var status = e.parameters.status;
  var sender = e.parameters.sender;
  var currentScore = parseInt(e.parameters.currentScore || "0", 10);

  // If user says "wrong", we adjust our state
  if (status === "wrong") {
    var wasMarkedSafe = currentScore < SECURITY_CONFIG.THRESHOLDS.SUSPICIOUS;
    var msg = "";

    if (wasMarkedSafe) {
      // False negative: user says it's risky although we marked SAFE
      DataStore.setBlacklist(sender, true);
      DataStore.saveReputation(sender, 90, 10); // Force high-risk
      msg = "Sender blacklisted and flagged as high-risk.";
    } else {
      // False positive: user says it's safe although we flagged it
      DataStore.setBlacklist(sender, false);
      DataStore.deleteReputation(sender);
      msg = "Sender removed from blacklist and reputation cleared.";
    }

    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("System trained: " + msg))
      .build();
  }

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Verdict confirmed."))
    .build();
}

/**
 * Deep check: 
 */
function executeDeepCheck(e) {
  var sender = e.parameters.sender || "";

  var domain = (sender.indexOf("@") !== -1) ? sender.split("@")[1] : sender;

  if (!domain) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Error: Could not extract domain."))
      .build();
  }

  // --- VIRUSTOTAL INTEGRATION ---
  var apiKey = PropertiesService.getScriptProperties().getProperty("VT_API_KEY");
if (!apiKey) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("VirusTotal API key is missing (VT_API_KEY)."))
    .build();
}

  var url = "https://www.virustotal.com/api/v3/domains/" + domain;

  try {
    var response = UrlFetchApp.fetch(url, {
      "method": "get",
      "headers": { "x-apikey": apiKey },
      "muteHttpExceptions": true
    });

    var code = response.getResponseCode();
    if (code !== 200) {
      //
      return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText("VT Scan: Domain not found in database."))
        .build();
    }

    var json = JSON.parse(response.getContentText());
    var stats = json.data.attributes.last_analysis_stats;
    
    // 
    var maliciousCount = stats.malicious;
    var suspiciousCount = stats.suspicious;
    
    var resultText = "";
    if (maliciousCount > 0) {
      resultText = "🛑 DANGER: Flagged by " + maliciousCount + " security vendors!";
    } else if (suspiciousCount > 0) {
      resultText = "⚠️ WARNING: Flagged as suspicious by " + suspiciousCount + " vendors.";
    } else {
      resultText = "✅ CLEAN: Verified by " + (stats.harmless + stats.undetected) + " security vendors.";
    }

    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText(resultText))
      .build();

  } catch (err) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Scan Failed: Check API Quota."))
      .build();
  }
}

/**
 * Save whitelist from homepage settings
 */
function saveWhitelist(e) {
  var input = (e.formInput && e.formInput.new_domain) ? String(e.formInput.new_domain).trim() : "";

  if (!input) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Please enter a domain."))
      .build();
  }

  // Optional validation (you already have isValidDomain in Helpers.js)
  if (!isValidDomain(input)) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Invalid domain format. Example: bgu.ac.il"))
      .build();
  }

  DataStore.setWhitelist(input);

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Whitelist updated."))
    .setNavigation(CardService.newNavigation().updateCard(buildHomepage(e)))
    .build();
}

/**
 * Toggle strict mode threshold (60) vs default (70)
 */
function updateThreshold(e) {
  var strictEnabled = (e.formInput && e.formInput.strict_mode === "enabled");
  var newValue = strictEnabled ? 60 : 70;

  DataStore.setThreshold(newValue);

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Threshold set to " + newValue + "."))
    .setNavigation(CardService.newNavigation().updateCard(buildHomepage(e)))
    .build();
}

/**
 * Add sender to blacklist (from email card)
 */
function blacklistSender(e) {
  var senderEmail = e.parameters.senderEmail;
  DataStore.setBlacklist(senderEmail, true);

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Blacklisted."))
    .build();
}

/**
 * Remove sender from blacklist (from email card)
 */
function removeFromBlacklist(e) {
  var senderEmail = e.parameters.senderEmail;
  DataStore.setBlacklist(senderEmail, false);

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Removed from blacklist."))
    .build();
}

/**
 * Clear only the blacklist entries (BL_* keys)
 */
function clearAllBlacklist() {
  DataStore.clearBlacklist();

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Blacklist cleared."))
    .build();
}
