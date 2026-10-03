const fetch = require("node-fetch");

function toUrlId(url) {
  // VirusTotal v3 identifies URLs by base64url of the URL, no padding.
  return Buffer.from(url).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return {
      enabled: false,
      findings: ["VirusTotal check skipped — no VIRUSTOTAL_API_KEY configured."],
      score: 0,
    };
  }

  const headers = { "x-apikey": apiKey };

  try {
    // Submit the URL for analysis (VT dedupes if already known).
    const submit = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`,
      timeout: 8000,
    });

    if (!submit.ok) {
      return { enabled: true, findings: [`VirusTotal submit returned HTTP ${submit.status}.`], score: 0 };
    }

    // Fetch cached report by URL id (works even before the fresh submission finishes analyzing).
    const urlId = toUrlId(url.replace(/\/+$/, ""));
    const report = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers,
      timeout: 8000,
    });

    if (!report.ok) {
      return {
        enabled: true,
        findings: ["Submitted to VirusTotal — no cached report yet (results populate over the next minute)."],
        score: 0,
      };
    }

    const data = await report.json();
    const stats = data?.data?.attributes?.last_analysis_stats;
    if (!stats) {
      return { enabled: true, findings: ["VirusTotal report had no analysis stats yet."], score: 0 };
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    const findings = [
      `VirusTotal: ${malicious} malicious / ${suspicious} suspicious out of ${total} vendor engines.`,
    ];

    let score = 0;
    if (malicious >= 3) score = 60;
    else if (malicious >= 1) score = 35;
    else if (suspicious >= 2) score = 20;

    return { enabled: true, malicious, suspicious, total, findings, score };
  } catch (err) {
    return { enabled: true, findings: [`VirusTotal check failed: ${err.message}`], score: 0 };
  }
}

module.exports = { checkVirusTotal };
