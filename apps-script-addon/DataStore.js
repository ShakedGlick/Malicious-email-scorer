/**
 * ==========================================
 * DATA STORE: Persistent State (User Properties)
 * ==========================================
 * Stores user-specific settings and learning state:
 * - Threshold
 * - Whitelist
 * - Blacklist
 * - Sender reputation (count + avgScore)
 */

var DataStore = {
  // Settings
  getThreshold: function() {
    return parseInt(
      PropertiesService.getUserProperties().getProperty("MIN_MALICIOUS_SCORE") || "70",
      10
    );
  },

  setThreshold: function(value) {
    PropertiesService.getUserProperties().setProperty("MIN_MALICIOUS_SCORE", String(value));
  },

  getWhitelist: function() {
    return PropertiesService.getUserProperties().getProperty("DOMAIN_WHITELIST") || "";
  },

  setWhitelist: function(value) {
    PropertiesService.getUserProperties().setProperty("DOMAIN_WHITELIST", String(value || ""));
  },

  // Blacklist
  isBlacklisted: function(email) {
    return PropertiesService.getUserProperties().getProperty("BL_" + email) === "true";
  },

  setBlacklist: function(email, status) {
    if (status) {
      PropertiesService.getUserProperties().setProperty("BL_" + email, "true");
    } else {
      PropertiesService.getUserProperties().deleteProperty("BL_" + email);
    }
  },

  clearBlacklist: function() {
    var props = PropertiesService.getUserProperties();
    var all = props.getProperties();
    Object.keys(all).forEach(function(key) {
      if (key.indexOf("BL_") === 0) props.deleteProperty(key);
    });
  },

  // Reputation
  getReputation: function(email) {
    var data = PropertiesService.getUserProperties().getProperty("REP_" + email);
    return data ? JSON.parse(data) : { count: 0, avgScore: 0 };
  },

  saveReputation: function(email, avgScore, count) {
    PropertiesService.getUserProperties()
      .setProperty("REP_" + email, JSON.stringify({ count: count, avgScore: avgScore }));
  },

  deleteReputation: function(email) {
    PropertiesService.getUserProperties().deleteProperty("REP_" + email);
  }
};
