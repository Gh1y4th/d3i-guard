let puppeteer;
try {
  puppeteer = require("puppeteer");
} catch (e) {
  puppeteer = null;
}
const psl = require("psl");

// Compare registrable domains (e.g. "furniture.com"), not full hostnames, so a
// login/cart/account subdomain of the SAME site (cart.furniture.com vs
// www.furniture.com) isn't mistaken for a redirect to a different company.
function registrableDomain(hostname) {
  const parsed = psl.parse(hostname);
  return parsed.domain || hostname;
}

async function captureAndInspect(url, timeoutMs = 15000) {
  if (!puppeteer) {
    return {
      enabled: false,
      findings: ["Screenshot/page analysis skipped — puppeteer not installed in this environment."],
      score: 0,
    };
  }

  const findings = [];
  let score = 0;
  let browser;

  try {
    browser = await puppeteer.launch({
      headless: "new",
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
    });
    const page = await browser.newPage();
    await page.setUserAgent("Mozilla/5.0 (compatible; QR-URL-Guard/1.0; +link-safety-scanner)");
    await page.setViewport({ width: 1280, height: 800 });

    let finalUrl = url;
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame()) finalUrl = frame.url();
    });

    await page.goto(url, { waitUntil: "networkidle2", timeout: timeoutMs });

    const pageTitle = await page.title();

    const hasPasswordField = await page.evaluate(
      () => document.querySelectorAll('input[type="password"]').length > 0
    );
    const hasLoginKeywords = await page.evaluate(() => {
      const text = document.body ? document.body.innerText.toLowerCase() : "";
      return ["login", "sign in", "verify your account", "confirm your identity", "update your payment"].some((k) =>
        text.includes(k)
      );
    });

    const finalHost = registrableDomain(new URL(finalUrl).hostname);
    const startHost = registrableDomain(new URL(url).hostname);

    if (hasPasswordField && startHost !== finalHost) {
      findings.push(`Page collects a password after redirecting to a different domain (${startHost} → ${finalHost}) — classic credential-harvesting pattern.`);
      score += 30;
    } else if (hasPasswordField) {
      findings.push("Page contains a password input field — verify this destination is where you expect to log in.");
      score += 5;
    }

    if (hasLoginKeywords && hasPasswordField) {
      findings.push("Page combines login/verification language with a password field.");
      score += 5;
    }

    const screenshotBuffer = await page.screenshot({ type: "jpeg", quality: 60 });
    const screenshotBase64 = `data:image/jpeg;base64,${screenshotBuffer.toString("base64")}`;

    if (findings.length === 0) {
      findings.push("No credential-harvesting patterns detected on the landing page.");
    }

    return {
      enabled: true,
      pageTitle,
      finalUrl,
      hasPasswordField,
      screenshotBase64,
      findings,
      score: Math.min(score, 40),
    };
  } catch (err) {
    return { enabled: true, findings: [`Page analysis failed: ${err.message}`], score: 0 };
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

module.exports = { captureAndInspect };
