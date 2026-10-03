// Base URL of your Render API service, e.g. "https://qr-url-guard.onrender.com"
// Leave as "" if the dashboard is served from the same origin as the API.
const API_BASE = window.QR_GUARD_API_BASE || "";

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const deepToggle = document.getElementById("deep-toggle");
const scanBtn = document.getElementById("scan-btn");
const scanStatus = document.getElementById("scan-status");
const resultPanel = document.getElementById("result-panel");
const historyBody = document.getElementById("history-body");

function verdictBadge(verdict) {
  return `<span class="verdict-badge verdict-${verdict}">${verdict}</span>`;
}

function renderCategory(title, items) {
  if (!items || items.length === 0) return "";
  const lis = items
    .filter((f) => f.category === title)
    .map((f) => `<li>${escapeHtml(f.finding)}</li>`)
    .join("");
  if (!lis) return "";
  return `<div class="category-block"><div class="category-title">${title}</div><ul>${lis}</ul></div>`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function renderResult(data) {
  const categories = [
    "Google Safe Browsing", "VirusTotal", "Page analysis", "Brand impersonation",
    "URL structure", "TLS/SSL", "Redirects", "Domain age",
  ];

  const screenshot = data.details?.screenshot;
  const shot = screenshot?.screenshotBase64
    ? `<img class="screenshot-preview" src="${screenshot.screenshotBase64}" alt="Landing page screenshot" />`
    : "";

  resultPanel.innerHTML = `
    <div class="result-head">
      <div>
        ${verdictBadge(data.verdict)}
        <div class="result-url">${escapeHtml(data.url)}</div>
      </div>
      <div class="score-num">${data.score}/100</div>
    </div>
    ${categories.map((c) => renderCategory(c, data.findings)).join("")}
    ${shot}
  `;
  resultPanel.classList.remove("hidden");
}

async function runScan(url, deep) {
  scanBtn.disabled = true;
  scanStatus.textContent = deep
    ? "Scanning — checking reputation, TLS, domain age, redirects, and rendering the page…"
    : "Scanning…";
  resultPanel.classList.add("hidden");

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, deep }),
    });
    const data = await res.json();
    if (!res.ok) {
      scanStatus.textContent = data.error || "Scan failed.";
      return;
    }
    scanStatus.textContent = "";
    renderResult(data);
    loadHistory();
  } catch (err) {
    scanStatus.textContent = `Request failed: ${err.message}`;
  } finally {
    scanBtn.disabled = false;
  }
}

async function loadHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    const rows = await res.json();
    historyBody.innerHTML = rows
      .map(
        (r) => `
      <tr class="history-row" data-id="${r.id}">
        <td>${new Date(r.created_at).toLocaleString()}</td>
        <td class="url-cell">${escapeHtml(r.url)}</td>
        <td>${verdictBadge(r.verdict)}</td>
        <td>${r.score}</td>
      </tr>`
      )
      .join("");

    document.querySelectorAll(".history-row").forEach((row) => {
      row.addEventListener("click", async () => {
        const id = row.getAttribute("data-id");
        const res = await fetch(`${API_BASE}/api/history/${id}`);
        const data = await res.json();
        renderResult(data);
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    });
  } catch (err) {
    console.error("Failed to load history", err);
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;
  runScan(url, deepToggle.checked);
});

loadHistory();
