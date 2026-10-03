# QR URL Guard

Checks a URL (typically one extracted from a scanned QR code) for signs it's malicious or a phishing/credential-harvesting site — **before** the person visits it. Returns a 0–100 risk score, a Safe / Caution / Dangerous verdict, and a category-by-category breakdown. Comes with a small dashboard showing scan history.

## What it checks

| Category | What it does |
|---|---|
| **Google Safe Browsing** | Cross-references Google's live phishing/malware/unwanted-software blocklists |
| **VirusTotal** | Aggregates verdicts from 70+ security vendors |
| **URL structure** | IP-literal hosts, embedded credentials, punycode/IDN, suspicious TLDs, non-standard ports, excessive subdomains |
| **Brand impersonation** | Edit-distance + substring matching against a watchlist of commonly spoofed brands (typosquatting detection) |
| **TLS/SSL** | Certificate validity, trust chain, expiry, self-signed detection |
| **Redirects** | Follows the full redirect chain, flags cross-domain hops and shorteners, resolves the real final destination |
| **Domain age (WHOIS)** | Freshly registered domains are a strong phishing signal |
| **Page analysis (deep scan)** | Headlessly renders the final page, screenshots it, and flags password fields combined with cross-domain redirects or login-language — the actual credential-harvesting pattern |

**What this tool deliberately does *not* do:** it does not send SQL-injection payloads or any other attack traffic to the target site. Actively probing a server you don't own/operate for exploitable vulnerabilities is out of scope — for legal reasons, and because it wouldn't even help your actual goal (a phishing clone can have zero vulnerabilities and still steal your users' info; reputation + behavior signals are what catch that).

## Local setup

```bash
npm install
cp .env.example .env
# fill in DATABASE_URL and (optional but recommended) the two API keys
npm start
```

Visit `http://localhost:3000`.

> Note: `puppeteer` (used for the deep page-analysis/screenshot check) downloads a Chromium binary on install (~200MB). If you want a lighter deploy, remove it from `package.json` and the app will simply skip that one check gracefully — everything else still works.

## Getting the free API keys

- **Google Safe Browsing** (free, generous quota): [console.cloud.google.com](https://console.cloud.google.com/) → enable "Safe Browsing API" → create an API key.
- **VirusTotal** (free tier: 4 requests/min): [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) after creating a free account.

The app runs fine with neither key set — it just skips those two checks and relies on the heuristic/structural/TLS/domain-age/page-analysis checks.

## Deploying split (Render API + Netlify frontend)

If you want the dashboard on Netlify and only the API on Render:

1. Deploy this whole project (minus `public/`, which isn't needed server-side) to Render as described below — it's an API-only service once the frontend lives elsewhere.
2. Use the separate `qr-url-guard-frontend/` folder (same `public/` files, packaged standalone) for Netlify. Open its `index.html` and set:
   ```html
   window.QR_GUARD_API_BASE = "https://your-service-name.onrender.com";
   ```
3. Deploy that folder to Netlify (drag-and-drop or Git-connected, publish directory `.`).
4. CORS is already open on the API (`cors()` in `server.js`), so Netlify → Render requests work with no extra config.

Express still serves `public/` directly as a fallback, so the Render URL alone continues to work as a combined deployment too if you ever want to collapse back to one service.

## Deploying to Render

This repo includes a `render.yaml` Blueprint that provisions both the web service and a free Postgres database in one step:

1. Push this project to a GitHub repo.
2. In the Render dashboard: **New → Blueprint**, point it at your repo.
3. Render reads `render.yaml` and creates the web service + database automatically.
4. After the first deploy, go to the service's **Environment** tab and fill in `GOOGLE_SAFE_BROWSING_API_KEY` and `VIRUSTOTAL_API_KEY` (left blank by the blueprint since they're secrets).
5. Redeploy — done.

`DATABASE_URL` is wired automatically from the provisioned Postgres instance; you don't need to set it by hand.

## API

**`POST /api/scan`**
```json
{ "url": "https://example.com/path", "deep": true }
```
Returns the full risk report (see `src/riskScore.js` for the scoring model). `deep: false` skips the puppeteer screenshot/page-analysis step for a faster response — use this if your friend's QR app calls this synchronously and needs low latency; run deep scans async/in the background if you want both speed and thoroughness.

**`GET /api/history?limit=50`** — recent scans (id, url, verdict, score, timestamp).

**`GET /api/history/:id`** — full stored report for one past scan.

## Extending it

- Add more brands to `WATCHED_BRANDS` in `src/checks/typosquat.js`.
- Adjust category weights in `src/riskScore.js` if you want Safe Browsing/VirusTotal to dominate the verdict even more (or less).
- Swap WHOIS for a paid domain-intel API (WhoisXML, SecurityTrails) if you outgrow the free `whois-json` lookups, which can be flaky on some TLDs.
