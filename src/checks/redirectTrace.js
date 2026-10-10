const fetch = require("node-fetch");
const psl = require("psl");

function registrableDomain(hostname) {
  const parsed = psl.parse(hostname);
  return parsed.domain || hostname;
}

async function traceRedirects(startUrl, maxHops = 8, timeoutMs = 8000) {
  const chain = [];
  let current = startUrl;
  const findings = [];
  let score = 0;

  for (let i = 0; i < maxHops; i++) {
    let res;
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), timeoutMs);
      res = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": "QR-URL-Guard/1.0 (+link-safety-scanner)" },
      });
      clearTimeout(t);
    } catch (err) {
      findings.push(`Request to ${current} failed: ${err.message}`);
      score += 15;
      break;
    }

    chain.push({ url: current, status: res.status });

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.get("location");
      if (!location) {
        findings.push(`Redirect status ${res.status} with no Location header.`);
        score += 10;
        break;
      }
      current = new URL(location, current).toString();
      continue;
    }
    break;
  }

  if (chain.length >= maxHops) {
    findings.push(`Hit the redirect hop limit (${maxHops}) — possible redirect loop or deliberate cloaking chain.`);
    score += 20;
  }

  if (chain.length > 1) {
    const startHost = new URL(chain[0].url).hostname;
    const finalHost = new URL(chain[chain.length - 1].url).hostname;
    if (startHost !== finalHost) {
      findings.push(`URL redirects across domains: ${startHost} → ${finalHost}.`);
      score += 10;
    }
    findings.push(`Followed ${chain.length - 1} redirect hop(s) before reaching final destination.`);
  } else {
    findings.push("No redirects — URL resolves directly.");
  }

  return {
    chain,
    finalUrl: chain.length ? chain[chain.length - 1].url : startUrl,
    findings,
    score: Math.min(score, 40),
  };
}

module.exports = { traceRedirects };
