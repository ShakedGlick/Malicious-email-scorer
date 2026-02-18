
This project implements a Gmail Add-on that analyzes opened emails and evaluates the likelihood that they are malicious or phishing attempts.
The system uses a rule-based security engine combined with behavioral state tracking. The next step would be to integrate machine learning to it. 
The goal was to simulate how a security product reasons about risk: combining static indicators (attachments, spoofing, urgency language) with dynamic signals (user feedback and sender history).
It focuses on explainable security decisions - showing the user why an email is suspicious and allowing them to train the system over time.
Architecture:
This project follows a Modular Monolith architecture designed for the Google Apps Script environment, emphasizing Separation of Concerns (SoC).
UI Layer (UIBuilder.js)
Responsible for rendering the Gmail sidebar and homepage cards using CardService.(enables building card-based user interfaces for Google Workspace add-ons).
Intelligence Layer (SecurityEngine.js)
Contains the heuristic analysis and risk scoring engine.
Data Access Layer (DataStore.js)
Persistent storage wrapper over PropertiesService (allows scripts to store simple data in key-value pairs with different scopes.) managing user settings, blacklist, whitelist, and sender reputation.
Logic Controllers (ActionHandlers.js)
Handles user feedback ("human-in-the-loop") and external checks.
Utility Layer (Helpers.gs)
Performs email normalization, parsing, and background reputation updates.
Runtime Flow
1.	Gmail opens an email → UI Layer triggers analysis
2.	UI calls Security Engine → risk score calculated
3.	Security Engine queries DataStore → behavioral state
4.	User feedback updates DataStore → future decisions adapt

APIs Used:
Gmail Add-on Runtime (GmailApp & CardService)
The system integrates directly with Gmail through the Google Apps Script Add-on environment.
Used for:
•	Accessing message metadata (sender, subject, attachments)
•	Triggering analysis when an email is opened
•	Rendering the security verdict inside the Gmail sidebar
________________________________________
VirusTotal (Domain Reputation)
The add-on performs an optional Deep Check against VirusTotal to assess the sender’s reputation during the Deep Check action:
 https://www.virustotal.com/api/v3/domains/{domain}
Purpose:
Validate whether the domain is known for malicious activity using aggregated security vendor analysis.
________________________________________
UrlFetchApp
Used to securely perform external HTTP requests from the Apps Script.

Implemented Features: 
1.  Risk Scoring (Heuristic Intelligence)
The engine evaluates emails to calculate a risk score from 0–100:
•	Identity & Brand Spoofing Protection: Detects "Brand-Jacking" by cross-referencing the email's Display Name (e.g., "Microsoft Support") against the actual authenticated sender domain.
•	Behavioral Reputation Engine: Implements a Stateful Backend using a rolling average formula. This allows the system to differentiate between "First Encounter" anomalies and long-term trusted contacts.
•	Linguistic Pressure Analysis: Scans subjects for "Social Engineering" triggers such as urgency, suspension threats, or password-related pressure keywords.
•	Payload Inspection: Automatically identifies and flags high-risk file attachments, specifically targeting scriptable or executable extensions like .exe, .js, and .vbs.
•	Global Blocklist Integration: Immediately flags domains found in a global repository of known malicious actors.
2. "Human-in-the-Loop" (HITL) Learning
The project treats the user as a real-time sensor to refine the model's accuracy:
•	Directional Feedback: When a user clicks "Wrong," the system performs a context-aware correction. If a "Safe" email was missed, the system doesn't just whitelist it; it pivots the sender's reputation to "Malicious" in the database.
•	Automated Enforcement: Marking a safe email as "Wrong" automatically triggers a blacklist entry for that sender, immediately updating the security policy for all future emails from that source.
3. Management Console:
•	Dynamic Policy Thresholds: Toggle between Standard and Strict detection thresholds.
•	Manual Blacklist Management: users can add, remove, or clear blocked senders.
•	Organizational Whitelisting: Trusted domains receive reduced sensitivity while still undergoing attachment inspection.
•	Deep Domain Verification: On-demand RDAP query verifies domain registration legitimacy.

Limitations:
•	 Heuristic vs. Probabilistic Analysis: The engine currently utilizes a weighted heuristic model based on known attack patterns. While highly effective for common threats, it lacks the deep semantic understanding provided by a trained Large Language Model (LLM) or Machine Learning classifier.
•	Static URL Analysis: The current iteration scans email metadata, headers, and attachments, but it does not perform sandboxing of URLs within the message body to detect redirected malicious payloads.
•	Local Storage Scope: Data persistence is currently managed via PropertiesService, which scopes sender reputation and blacklists to the individual user. It does not yet feature a centralized "Global Threat Intelligence" sync across different users within the same organization.

The next step:
•  Predictive AI & Machine Learning: I would transition from a heuristic model to a probabilistic one by training a classifier on the collected reputation data. The system could perform semantic analysis to detect "Zero-Day" social engineering attempts that do not contain known malicious keywords.
•  Proactive Pre-Inbox Filtering: Currently, the engine runs when an email is opened. The next step is to implement a background service that scans incoming assigning risk scores and blocking malicious content before a user even interacts with the message.
•  Automated Incident Response:
•	CISO Alerting: Implement an automated trigger to notify the Security Operations Center (SOC) or CISO when a high-confidence "Malicious" verdict is reached.
•	Cluster Remediation: If a threat is confirmed in one mailbox, the system would search for and delete identical malicious signatures from all other employee mailboxes across the organization.
•  Public Security API: I would wrap the scoring logic into a standalone API. This would allow other internal tools or third-party developers to query my reputation database and scoring engine for their own security workflows.
•  Expanded Checks:
•	URL Sandboxing: Integrating with a service to "detonate" links in a safe environment before the user clicks.
•	Header Forensic Analysis: Adding checks for DKIM/SPF/DMARC alignment to detect more sophisticated domain spoofing.


