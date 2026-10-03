const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "xyz", "top", "gq", "cf", "tk", "ml", "ga", "work",
  "click", "link", "country", "stream", "loan", "men", "date", "review"
]);

const SHORTENER_HOSTS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id"
]);

function isIpLiteral(hostname) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^\[?[0-9a-fA-F:]+\]?$/;
  return ipv4.test(hostname) || (hostname.includes(":") && ipv6.test(hostname));
}

function analyzeUrlStructure(rawUrl) {
  const findings = [];
  let score = 0; // added to risk score (0-100 scale contribution)
  let parsed;

  try {
    parsed = new URL(rawUrl);
  } catch (e) {
    return {
      valid: false,
      findings: ["URL could not be parsed — malformed or not a valid absolute URL."],
      score: 40,
    };
  }

  if (parsed.protocol !== "https:") {
    findings.push(`Not using HTTPS (protocol: ${parsed.protocol})`);
    score += 15;
  }

  if (parsed.username || parsed.password) {
    findings.push("URL embeds credentials (user:pass@host) — classic obfuscation trick.");
    score += 20;
  }

  const hostname = parsed.hostname;

  if (isIpLiteral(hostname)) {
    findings.push(`Host is a raw IP address (${hostname}) instead of a domain name.`);
    score += 25;
  }

  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    findings.push("Hostname uses punycode (internationalized domain) — check for homograph spoofing.");
    score += 15;
  }

  const labels = hostname.split(".");
  if (labels.length >= 5) {
    findings.push(`Unusually deep subdomain nesting (${labels.length} labels): ${hostname}`);
    score += 10;
  }

  const tld = labels[labels.length - 1]?.toLowerCase();
  if (SUSPICIOUS_TLDS.has(tld)) {
    findings.push(`TLD ".${tld}" is disproportionately favored by spam/phishing campaigns.`);
    score += 10;
  }

  if (parsed.port && !["80", "443", ""].includes(parsed.port)) {
    findings.push(`Non-standard port specified: ${parsed.port}`);
    score += 8;
  }

  if (rawUrl.length > 120) {
    findings.push(`Very long URL (${rawUrl.length} chars) — can hide the real destination.`);
    score += 5;
  }

  const isShortener = SHORTENER_HOSTS.has(hostname.replace(/^www\./, ""));
  if (isShortener) {
    findings.push(`Host (${hostname}) is a known URL shortener — real destination is hidden until resolved.`);
    score += 8;
  }

  if (findings.length === 0) {
    findings.push("No structural red flags in the URL itself.");
  }

  return {
    valid: true,
    hostname,
    protocol: parsed.protocol,
    isShortener,
    findings,
    score: Math.min(score, 60),
  };
}

module.exports = { analyzeUrlStructure, SHORTENER_HOSTS };
