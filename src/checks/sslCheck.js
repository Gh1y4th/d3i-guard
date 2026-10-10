const tls = require("tls");

function checkSsl(hostname, port = 443, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const findings = [];
    let score = 0;
    let settled = false;

    const done = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    let socket;
    try {
      socket = tls.connect(
        { host: hostname, port, servername: hostname, timeout: timeoutMs, rejectUnauthorized: false },
        () => {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;

          if (!cert || Object.keys(cert).length === 0) {
            findings.push("No certificate returned by the server.");
            score += 20;
            socket.end();
            return done({ hasSsl: false, findings, score });
          }

           if (!authorized) {
            findings.push(`Certificate is not trusted by standard CAs (${socket.authorizationError || "unknown reason"}).`);
            score += 15;
          }

          const now = new Date();
          const validTo = new Date(cert.valid_to);
          const validFrom = new Date(cert.valid_from);
          if (validTo < now) {
            findings.push(`Certificate expired on ${cert.valid_to}.`);
            score += 25;
          }
          if (validFrom > now) {
            findings.push(`Certificate is not yet valid (starts ${cert.valid_from}).`);
            score += 15;
          }

          const daysToExpiry = Math.round((validTo - now) / 86400000);
          if (daysToExpiry >= 0 && daysToExpiry < 7) {
            findings.push(`Certificate expires very soon (${daysToExpiry} day(s)).`);
            score += 10;
          }

          if (cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN) {
            findings.push("Certificate appears self-signed (issuer equals subject).");
            score += 25;
          }

          if (findings.length === 0) {
            findings.push("Certificate is valid and trusted.");
          }

          socket.end();
          done({
            hasSsl: true,
            authorized,
            issuer: cert.issuer && cert.issuer.O,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysToExpiry,
            findings,
            score: Math.min(score, 50),
          });
        }
      );

      socket.on("error", (err) => {
        findings.push(`Could not establish a TLS connection: ${err.message}`);
        done({ hasSsl: false, findings, score: 30 });
      });

      socket.on("timeout", () => {
        findings.push("TLS connection timed out.");
        socket.destroy();
        done({ hasSsl: false, findings, score: 15 });
      });
    } catch (err) {
      findings.push(`TLS check failed to run: ${err.message}`);
      done({ hasSsl: false, findings, score: 10 });
    }
  });
}

module.exports = { checkSsl };
