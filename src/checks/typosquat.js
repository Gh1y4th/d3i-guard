// Popular brands most commonly impersonated in phishing/QR-code scams.
// Extend this list freely — it's just plain strings.
const WATCHED_BRANDS = [
  "google.com", "paypal.com", "apple.com", "microsoft.com", "amazon.com",
  "facebook.com", "instagram.com", "whatsapp.com", "netflix.com", "bankofamerica.com",
  "chase.com", "wellsfargo.com", "dhl.com", "fedex.com", "ups.com",
  "binance.com", "coinbase.com", "steamcommunity.com", "outlook.com", "office.com",
  "linkedin.com", "twitter.com", "x.com", "telegram.org", "yellowsparkle.co",
];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function checkTyposquat(hostname) {
  const findings = [];
  let score = 0;
  const host = hostname.toLowerCase().replace(/^www\./, "");

  for (const brand of WATCHED_BRANDS) {
    if (host === brand) continue; // it IS the real domain
    const distance = levenshtein(host, brand);
    // Close edit distance relative to length = likely lookalike (e.g. paypa1.com, gooogle.com)
    const threshold = brand.length <= 8 ? 1 : 2;
    if (distance > 0 && distance <= threshold) {
      findings.push(`Hostname "${host}" is suspiciously close to "${brand}" (edit distance ${distance}) — possible typosquat.`);
      score += 30;
    } else if (host.includes(brand.split(".")[0]) && host !== brand) {
      // brand name embedded as substring in an unrelated domain, e.g. paypal-secure-login.com
      findings.push(`Hostname "${host}" embeds the brand name "${brand.split(".")[0]}" without being that domain — common phishing pattern.`);
      score += 20;
    }
  }

  if (findings.length === 0) {
    findings.push("No brand-impersonation or typosquat patterns detected against the watchlist.");
  }

  return { findings, score: Math.min(score, 40) };
}

module.exports = { checkTyposquat, WATCHED_BRANDS };
