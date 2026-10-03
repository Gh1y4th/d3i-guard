const fetch = require("node-fetch");

async function checkSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return {
      enabled: false,
      findings: ["Google Safe Browsing check skipped — no GOOGLE_SAFE_BROWSING_API_KEY configured."],
      score: 0,
    };
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const body = {
    client: { clientId: "qr-url-guard", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      timeout: 8000,
    });
    if (!res.ok) {
      return { enabled: true, findings: [`Safe Browsing API returned HTTP ${res.status}.`], score: 0 };
    }
    const data = await res.json();
    if (data.matches && data.matches.length > 0) {
      const types = [...new Set(data.matches.map((m) => m.threatType))].join(", ");
      return {
        enabled: true,
        flagged: true,
        threatTypes: types,
        findings: [`Google Safe Browsing FLAGGED this URL for: ${types}.`],
        score: 60,
      };
    }
    return {
      enabled: true,
      flagged: false,
      findings: ["Not flagged by Google Safe Browsing."],
      score: 0,
    };
  } catch (err) {
    return { enabled: true, findings: [`Safe Browsing check failed: ${err.message}`], score: 0 };
  }
}

module.exports = { checkSafeBrowsing };
