function computeVerdict(totalScore) {
  if (totalScore >= 60) return "DANGEROUS";
  if (totalScore >= 25) return "CAUTION";
  return "SAFE";
}

// Weighted combination — reputation-list hits (Safe Browsing / VirusTotal) dominate,
// since a confirmed blocklist match is far more reliable than a heuristic.
function combine(results) {
  const {
    heuristics, typosquat, ssl, redirects, domain, safeBrowsing, virusTotal, screenshot,
  } = results;

  const weighted =
    (heuristics?.score || 0) * 1.0 +
    (typosquat?.score || 0) * 1.0 +
    (ssl?.score || 0) * 0.8 +
    (redirects?.score || 0) * 0.8 +
    (domain?.score || 0) * 0.9 +
    (safeBrowsing?.score || 0) * 1.4 +
    (virusTotal?.score || 0) * 1.3 +
    (screenshot?.score || 0) * 1.1;

  const totalScore = Math.max(0, Math.min(100, Math.round(weighted)));
  const verdict = computeVerdict(totalScore);

  const allFindings = [
    ...(heuristics?.findings || []).map((f) => ({ category: "URL structure", finding: f })),
    ...(typosquat?.findings || []).map((f) => ({ category: "Brand impersonation", finding: f })),
    ...(ssl?.findings || []).map((f) => ({ category: "TLS/SSL", finding: f })),
    ...(redirects?.findings || []).map((f) => ({ category: "Redirects", finding: f })),
    ...(domain?.findings || []).map((f) => ({ category: "Domain age", finding: f })),
    ...(safeBrowsing?.findings || []).map((f) => ({ category: "Google Safe Browsing", finding: f })),
...(virusTotal?.findings || []).map((f) => ({ category: "Deep in the unseen", finding: f })),  ];

  return { totalScore, verdict, findings: allFindings };
}

module.exports = { combine, computeVerdict };
