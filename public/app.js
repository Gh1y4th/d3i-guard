const API_BASE = window.QR_GUARD_API_BASE || "";

function getSessionId() {
  let id = localStorage.getItem("qrguard_session_id");
  if (!id) {
    id = (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(36).slice(2)}`);
    localStorage.setItem("qrguard_session_id", id);
  }
  return id;
}
const SESSION_ID = getSessionId();

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const deepToggle = document.getElementById("deep-toggle");
const scanBtn = document.getElementById("scan-btn");
const scanStatus = document.getElementById("scan-status");
const resultPanel = document.getElementById("result-panel");
const historyBody = document.getElementById("history-body");
const historyEmpty = document.getElementById("history-empty");

const video = document.getElementById("qr-video");
const canvas = document.getElementById("qr-canvas");
const ctx = canvas.getContext("2d", { willReadFrequently: true });
const cameraToggleBtn = document.getElementById("camera-toggle");
const cameraState = document.getElementById("camera-state");
const cameraPlaceholder = document.getElementById("camera-placeholder");
const scanFrame = document.querySelector(".scan-frame");

let stream = null;
let rafId = null;
let lastDecodedUrl = null;
let lastDecodedAt = 0;

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

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

function renderResult(data) {
  const categories = [
    "Google Safe Browsing", "Deep in the unseen", "Page analysis", "Brand impersonation",
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
    <a href="${escapeHtml(data.url)}" target="_blank" rel="noopener noreferrer" class="tb-btn primary full open-site-btn">
      <i class="fa-solid fa-arrow-up-right-from-square"></i> Open Website
    </a>
  `;
  resultPanel.classList.remove("hidden");
  resultPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
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
      headers: { "Content-Type": "application/json", "X-Session-Id": SESSION_ID },
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
    if (!rows || rows.length === 0) {
      historyBody.innerHTML = "";
      historyEmpty.classList.remove("hidden");
      return;
    }
    historyEmpty.classList.add("hidden");
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

function setCameraState(text, live) {
  cameraState.textContent = text;
  cameraState.classList.toggle("live", live);
}

async function startCamera() {
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: "environment" },
    });
  } catch (err) {
    scanStatus.textContent = `Camera access failed: ${err.message}`;
    return;
  }

  video.srcObject = stream;
  await video.play();
  video.classList.add("active");
  cameraPlaceholder.classList.add("hidden");
  scanFrame.classList.add("active");
  setCameraState("Scanning…", true);
  cameraToggleBtn.innerHTML = '<i class="fa-solid fa-video-slash"></i> Stop Camera';
  cameraToggleBtn.classList.add("stopping");

  tick();
}

function stopCamera() {
  if (rafId) cancelAnimationFrame(rafId);
  rafId = null;
  if (stream) {
    stream.getTracks().forEach((t) => t.stop());
    stream = null;
  }
  video.classList.remove("active");
  cameraPlaceholder.classList.remove("hidden");
  scanFrame.classList.remove("active", "hit");
  setCameraState("Camera off", false);
  cameraToggleBtn.innerHTML = '<i class="fa-solid fa-video"></i> Start Camera';
  cameraToggleBtn.classList.remove("stopping");
}

function tick() {
  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: "dontInvert",
    });

    if (code && code.data) {
      handleDecoded(code.data);
      return;
    }
  }
  rafId = requestAnimationFrame(tick);
}

function handleDecoded(data) {
  lastDecodedUrl = data;
  lastDecodedAt = Date.now();

  scanFrame.classList.add("hit");
  urlInput.value = data;
  setCameraState("Code found", true);

  stopCamera();

  runScan(data, deepToggle.checked);
}

cameraToggleBtn.addEventListener("click", () => {
  if (stream) {
    stopCamera();
  } else {
    startCamera();
  }
});

loadHistory();
