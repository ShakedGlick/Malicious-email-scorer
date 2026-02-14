/**
 * ==========================================
 * UI BUILDER: Gmail Contextual Card
 * ==========================================
 */

function buildAddOn(e) {
  // Important for Gmail Add-on context access
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);

  var message = GmailApp.getMessageById(e.gmail.messageId);
  var context = getEmailContext(message);

  var analysis = calculateRiskScore(context, message);
  recordSenderHistory(context.sender, analysis.score);

  return createMainCard(context, analysis).build();
}

function createMainCard(context, analysis) {
  var threshold = DataStore.getThreshold();

  // 3-state verdict (like the original)
  var verdict =
    analysis.score >= threshold ? "MALICIOUS" :
    analysis.score >= SECURITY_CONFIG.THRESHOLDS.SUSPICIOUS ? "SUSPICIOUS" :
    "SAFE";

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Verdict: " + verdict)
        .setSubtitle("Risk Score: " + analysis.score + "/100")
    );

  // --- Security Analysis section ---
  card.addSection(
    CardService.newCardSection()
      .setHeader("Security Analysis")
      .addWidget(
        CardService.newTextParagraph().setText("<b>Reasoning:</b>\n\n" + analysis.reasons.join("\n\n"))
      )
  );

  // --- User Actions section (feedback + deep check) ---
  var actionSection = CardService.newCardSection().setHeader("User Actions");

  actionSection.addWidget(
    CardService.newButtonSet()
      .addButton(
        CardService.newTextButton()
          .setText("👍 Correct")
          .setOnClickAction(
            CardService.newAction()
              .setFunctionName("handleFeedback")
              .setParameters({
                status: "correct",
                sender: context.sender,
                currentScore: String(analysis.score)
              })
          )
      )
      .addButton(
        CardService.newTextButton()
          .setText("👎 Wrong")
          .setOnClickAction(
            CardService.newAction()
              .setFunctionName("handleFeedback")
              .setParameters({
                status: "wrong",
                sender: context.sender,
                currentScore: String(analysis.score)
              })
          )
      )
  );

  actionSection.addWidget(
    CardService.newTextButton()
      .setText("🔍 Run Deep Check")
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("executeDeepCheck")
          .setParameters({ sender: context.sender })
      )
  );

  card.addSection(actionSection);

  // --- Manage Blacklist section ---
  var manageSection = CardService.newCardSection().setHeader("Manage Blacklist");
  var isBlacklisted = DataStore.isBlacklisted(context.sender);

  manageSection.addWidget(
    CardService.newTextButton()
      .setText(isBlacklisted ? "✅ Remove from Blacklist" : "🚫 Blacklist Sender")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName(isBlacklisted ? "removeFromBlacklist" : "blacklistSender")
          .setParameters({ senderEmail: context.sender })
      )
  );

  manageSection.addWidget(
    CardService.newTextButton()
      .setText("🗑️ Clear Blacklist")
      .setOnClickAction(
        CardService.newAction().setFunctionName("clearAllBlacklist")
      )
  );

  card.addSection(manageSection);

  return card;
}
/**
 * ==========================================
 * HOMEPAGE (Settings Console)
 * ==========================================
 * Lets the user:
 * - Toggle strict mode (threshold 60 vs 70)
 * - Add whitelist domain
 */

function buildHomepage(e) {
  var currentThreshold = String(DataStore.getThreshold());
  var currentWhitelist = DataStore.getWhitelist() || "No domains whitelisted";

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("🛡️ Settings")
        .setSubtitle("System Policy")
    );

  // --- Sensitivity section ---
  var settingsSection = CardService.newCardSection()
    .setHeader("Sensitivity")
    .addWidget(
      CardService.newTextParagraph()
        .setText("Threshold: <b>" + currentThreshold + "</b>")
    )
    .addWidget(
      CardService.newDecoratedText()
        .setText("Strict Mode (60)")
        .setSwitchControl(
          CardService.newSwitch()
            .setFieldName("strict_mode")
            .setValue("enabled")
            .setSelected(currentThreshold === "60")
            .setOnChangeAction(
              CardService.newAction().setFunctionName("updateThreshold")
            )
        )
    );

  // --- Whitelist section ---
  var whitelistSection = CardService.newCardSection()
    .setHeader("Policy: Whitelist")
    .addWidget(
      CardService.newTextParagraph()
        .setText("Trusted: <i>" + currentWhitelist + "</i>")
    )
    .addWidget(
      CardService.newTextInput()
        .setFieldName("new_domain")
        .setTitle("Add Domain")
        .setHint("e.g., bgu.ac.il")
    )
    .addWidget(
      CardService.newTextButton()
        .setText("💾 Save Whitelist")
        .setOnClickAction(
          CardService.newAction().setFunctionName("saveWhitelist")
        )
    );

  return card.addSection(settingsSection).addSection(whitelistSection).build();
}


