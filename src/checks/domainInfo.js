const psl = require("psl");

// whois-json ships as an ESM-only module in recent versions, so it can't be
// loaded with a plain require() from this CommonJS project. A dynamic
// import() works from CommonJS and gives us the same function.
let whoisPromise = null;
function loadWhois() {
  if (!whoisPromise) {
    whoisPromise = import("whois-json").then((mod) => mod.default || mod);
  }
  return whoisPromise;
}

async function checkDomainInfo(hostname, timeoutMs = 8000) {
  const findings = [];
  let score = 0;

  const parsedDomain = psl.parse(hostname);
  const registrableDomain = parsedDomain.domain || hostname;

  try {
    const whois = await loadWhois();
    const data = await Promise.race([
      whois(registrableDomain),
      new Promise((_, reject) => setTimeout(() => reject(new Error("WHOIS timeout")), timeoutMs)),
    ]);

    const createdRaw = data.creationDate || data.createdDate || data.created || data["Creation Date"];
    let ageDays = null;

    if (createdRaw) {
      const created = new Date(createdRaw);
      if (!isNaN(created.getTime())) {
        ageDays = Math.round((Date.now() - created.getTime()) / 86400000);
        if (ageDays < 30) {
          findings.push(`Domain was registered only ${ageDays} day(s) ago — very new domains are heavily overrepresented in phishing.`);
          score += 30;
        } else if (ageDays < 180) {
          findings.push(`Domain is ${ageDays} days old — relatively new.`);
          score += 12;
        } else {
          findings.push(`Domain age: ~${Math.round(ageDays / 365)} year(s) — established.`);
        }
      }
    } else {
      findings.push("Registration date not available from WHOIS (privacy-protected or unsupported TLD).");
      score += 5;
    }

    const registrar = data.registrar || data.registrarName || null;

    return {
      registrableDomain,
      registrar,
      createdRaw: createdRaw || null,
      ageDays,
      findings,
      score: Math.min(score, 40),
    };
  } catch (err) {
    findings.push(`WHOIS lookup unavailable for this domain: ${err.message}`);
    return { registrableDomain, registrar: null, createdRaw: null, ageDays: null, findings, score: 5 };
  }
}

module.exports = { checkDomainInfo };
