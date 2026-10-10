const express = require("express");
const router = express.Router();

const { analyzeUrlStructure } = require("../checks/urlHeuristics");
const { checkTyposquat } = require("../checks/typosquat");
const { checkSsl } = require("../checks/sslCheck");
const { traceRedirects } = require("../checks/redirectTrace");
const { checkDomainInfo } = require("../checks/domainInfo");
const { checkSafeBrowsing } = require("../checks/safeBrowsing");
const { checkVirusTotal } = require("../checks/virusTotal");
const { captureAndInspect } = require("../checks/screenshot");
const { combine } = require("../riskScore");
const { saveScan } = require("../db");

router.post("/scan", async (req, res) => {
  const { url, deep = true } = req.body || {};
  const sessionId = req.get("x-session-id") || null;

  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Body must include a `url` string." });
  }

  const heuristics = analyzeUrlStructure(url);
  if (!heuristics.valid) {
    return res.status(400).json({ error: "Invalid URL.", findings: heuristics.findings });
  }

  const hostname = heuristics.hostname;

  try {
    const [typosquat, ssl, redirects, domain, safeBrowsing, virusTotal] = await Promise.all([
      Promise.resolve(checkTyposquat(hostname)),
      checkSsl(hostname).catch((e) => ({ findings: [`SSL check error: ${e.message}`], score: 0 })),
      traceRedirects(url).catch((e) => ({ findings: [`Redirect trace error: ${e.message}`], score: 0 })),
      checkDomainInfo(hostname).catch((e) => ({ findings: [`Domain info error: ${e.message}`], score: 0 })),
      checkSafeBrowsing(url).catch((e) => ({ findings: [`Safe Browsing error: ${e.message}`], score: 0 })),
      checkVirusTotal(url).catch((e) => ({ findings: [`VirusTotal error: ${e.message}`], score: 0 })),
    ]);

    let screenshot = { enabled: false, findings: ["Deep page analysis not requested."], score: 0 };
    if (deep) {
      screenshot = await captureAndInspect(redirects.finalUrl || url).catch((e) => ({
        findings: [`Screenshot analysis error: ${e.message}`],
        score: 0,
      }));
    }

    const results = { heuristics, typosquat, ssl, redirects, domain, safeBrowsing, virusTotal, screenshot };
    const { totalScore, verdict, findings } = combine(results);

    const responsePayload = {
      url,
      hostname,
      verdict,
      score: totalScore,
      findings,
      details: results,
      scannedAt: new Date().toISOString(),
    };

    const saved = await saveScan({
      url,
      hostname,
      verdict,
      score: totalScore,
      result: responsePayload,
    }).catch((e) => {
      console.error("[scan] Failed to persist scan:", e.message);
      return null;
    });

    if (saved) {
      responsePayload.id = saved.id;
    }

    res.json(responsePayload);
  } catch (err) {
    console.error("[scan] Unexpected failure:", err);
    res.status(500).json({ error: "Scan failed unexpectedly.", message: err.message });
  }
});

module.exports = router;
