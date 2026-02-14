/**
 * ==========================================
 * HELPERS: Utility & Data Processing
 * ==========================================
 */

/**
 * Extracts a clean email address from a "From" header.
 * Handles formats like: "Name <user@domain.com>" or just "user@domain.com".
 */

function getEmailContext(message) {
  var rawFrom = message.getFrom();
  var senderEmail = extractEmailAddress(rawFrom); // Call from Helpers.gs
  
  return {
    sender: senderEmail,
    domain: extractDomain(senderEmail), // Call from Helpers.gs
    subject: message.getSubject(),
    attachments: message.getAttachments(),
    displayName: rawFrom.split('<')[0].replace(/"/g, '').trim() // For spoofing check
  };
}

function extractEmailAddress(fromField) {
  if (!fromField) return "";
  var match = fromField.match(/<([^>]+)>/);
  var email = match ? match[1] : fromField;
  return String(email).trim().toLowerCase();
}

/**
 * Extracts the domain part of an email address.
 */
function extractDomain(email) {
  if (!email) return "";
  var parts = String(email).split('@');
  return (parts.length === 2) ? parts[1].toLowerCase() : "";
}

/**
 * Updates the sender's reputation in the background.
 * Uses a rolling average formula to ensure historical state is preserved.
 */
function recordSenderHistory(sender, currentScore) {
  // Retrieve the existing reputation object from the DataStore
   currentScore = Number(currentScore) || 0;
  var history = DataStore.getReputation(sender);
  
  // Rolling average formula: ((OldAvg * OldCount) + NewScore) / NewCount
  var newCount = history.count + 1;
  var newAvg = ((history.avgScore * history.count) + currentScore) / newCount;
  
  // Persist the updated state back to the Hash Map
  DataStore.saveReputation(sender, newAvg, newCount);
}

/**
 * Validates if a string is a valid domain format. 
 * Useful for the Whitelist input in the Management Console.
 */
function isValidDomain(domain) {
  var re = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
  return re.test(domain);
}