const form = document.getElementById("scan-form");
const statusText = document.getElementById("status-text");
const progressBar = document.getElementById("progress-bar");
const pagesScanned = document.getElementById("pages-scanned");
const findingsCount = document.getElementById("findings-count");
const findingsContainer = document.getElementById("findings");
const aiSummary = document.getElementById("ai-summary");
const scanErrors = document.getElementById("scan-errors");
const historyContainer = document.getElementById("history");
const refreshHistoryButton = document.getElementById("refresh-history");

let activeScanId = null;
let pollTimer = null;

refreshHistoryButton.addEventListener("click", () => {
  refreshHistory();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (pollTimer) {
    clearInterval(pollTimer);
  }

  const data = new FormData(form);
  const payload = {
    target_url: data.get("target"),
    options: {
      max_pages: Number(data.get("maxPages")) || 15,
      timeout_seconds: 10,
      include_ai: data.get("includeAi") === "on",
      allowlist: parseAllowlist(data.get("allowlist")),
    },
  };

  setStatus("Submitting scan...");
  findingsContainer.innerHTML = "";
  aiSummary.textContent = data.get("includeAi") === "on"
    ? "Waiting for AI summary..."
    : "Enable AI recommendations to see a summary.";
  scanErrors.textContent = "No errors reported.";

  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    setStatus("Failed to start scan.");
    return;
  }

  const body = await response.json();
  activeScanId = body.scan_id;
  setStatus("Scan queued...");

  pollTimer = setInterval(pollScan, 1500);
  refreshHistory();
});

async function pollScan() {
  if (!activeScanId) return;
  const response = await fetch(`/api/scan/${activeScanId}`);
  if (!response.ok) {
    setStatus("Scan status unavailable.");
    clearInterval(pollTimer);
    return;
  }

  const data = await response.json();
  updateProgress(data);

  if (data.status === "completed" || data.status === "failed") {
    clearInterval(pollTimer);
    refreshHistory();
  }
}

function updateProgress(data) {
  pagesScanned.textContent = data.pages_scanned;
  findingsCount.textContent = data.findings.length;
  progressBar.style.width = `${data.progress}%`;
  setStatus(`Scan ${data.status}.`);
  renderFindings(data.findings);

  if (data.ai_summary) {
    aiSummary.textContent = data.ai_summary;
  }

  if (data.errors && data.errors.length) {
    scanErrors.textContent = data.errors.join("\n");
  }
}

function renderFindings(findings) {
  if (!findings.length) {
    findingsContainer.innerHTML = "<p class=\"note\">No findings yet.</p>";
    return;
  }

  findingsContainer.innerHTML = findings
    .map((finding) => {
      return `
        <div class="finding">
          <span class="badge ${finding.severity}">${finding.severity}</span>
          <span class="badge">${finding.category}</span>
          <h3>${finding.title}</h3>
          <p>${finding.description}</p>
          ${finding.recommendation ? `<p><strong>Recommendation:</strong> ${finding.recommendation}</p>` : ""}
        </div>
      `;
    })
    .join("");
}

function setStatus(message) {
  statusText.textContent = message;
}

function parseAllowlist(rawValue) {
  if (!rawValue) return [];
  return rawValue
    .split(/[,\\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

async function refreshHistory() {
  const response = await fetch("/api/scans");
  if (!response.ok) {
    historyContainer.innerHTML = "<p class=\"note\">History unavailable.</p>";
    return;
  }

  const scans = await response.json();
  if (!scans.length) {
    historyContainer.innerHTML = "<p class=\"note\">No scans yet.</p>";
    return;
  }

  historyContainer.innerHTML = scans
    .map((scan) => {
      const started = new Date(scan.started_at).toLocaleString();
      const status = scan.status;
      return `
        <div class="history-item">
          <div>
            <div><strong>${scan.target_url}</strong></div>
            <div class="history-meta">${started}</div>
          </div>
          <div>
            <div class="history-meta">Status</div>
            <div>${status}</div>
          </div>
          <div>
            <div class="history-meta">Findings</div>
            <div>${scan.findings_count}</div>
          </div>
          <div class="history-actions">
            <a href="/api/scan/${scan.scan_id}/export?format=csv">Export CSV</a>
            <a href="/api/scan/${scan.scan_id}/export?format=json">Export JSON</a>
          </div>
        </div>
      `;
    })
    .join("");
}

refreshHistory();
