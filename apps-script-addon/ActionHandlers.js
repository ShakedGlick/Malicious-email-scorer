// /**
//  * ==========================================
//  * AI SERVICE (Gemini) - Display Only
//  * ==========================================
//  * Returns { score: number, reason: string }
//  * Does NOT affect heuristic score.
//  */
// var apiKey = PropertiesService.getScriptProperties().getProperty("GEMINI_API_KEY");


// var AIService = {
//   analyze: function(sender, subject) {
    
//     return getGeminiAnalysis_(sender, subject);
//   }
// };

// function getGeminiAnalysis_(sender, subject) {
//   var apiKey = PropertiesService.getScriptProperties().getProperty("GEMINI_API_KEY");
//   if (!apiKey) return { score: null, reason: "AI key not configured." };

//   var apiUrl =
//   "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key=" +
//   apiKey;


//   var prompt =
//     "You are a cybersecurity analyst. Given ONLY sender and subject, estimate phishing risk.\n" +
//     "Return a SINGLE LINE of JSON ONLY (no markdown, no extra text), like:\n" +
//     "{\"score\": 42, \"reason\": \"short reason\"}\n\n" +
//     "Sender: " + sender + "\n" +
//     "Subject: " + subject;

//   var payload = { contents: [{ parts: [{ text: prompt }] }] };

//   try {
//     var response = UrlFetchApp.fetch(apiUrl, {
//       method: "post",
//       contentType: "application/json",
//       payload: JSON.stringify(payload),
//       muteHttpExceptions: true
//     });
//     Logger.log(response.getContentText());


//     var code = response.getResponseCode();
//     var body = response.getContentText();

//     if (code < 200 || code >= 300) {
//       return { score: null, reason: "AI HTTP error " + code };
//     }

//     var json = JSON.parse(body);
//     if (!json.candidates || !json.candidates.length) {
//       return { score: null, reason: "AI returned no candidates." };
//     }

//     var rawText = (json.candidates[0].content.parts || [])
//       .map(function(p) { return p.text || ""; })
//       .join("")
//       .trim();

//     var clean = rawText.replace(/```json|```/g, "").trim();

//   try {
//       var parsed = JSON.parse(clean);
//       return {
//         score: (parsed.score === 0 || parsed.score) ? Number(parsed.score) : null,
//         reason: String(parsed.reason || "").slice(0, 250)
//       };
//     } catch (e) {
//       return { score: null, reason: "AI returned non-JSON: " + rawText.slice(0, 80) + "..." };
//     }

//   } catch (e) {
    
//     Logger.log("FETCH EXCEPTION: " + e);
//     return { score: null, reason: "AI fetch failed: " + e };
//   }
// }
// function testAI() {
//   var res = AIService.analyze("support@microsoft-secure-login.com", "URGENT verify your password now");
//   Logger.log(res);
// }



