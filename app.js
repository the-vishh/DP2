const API_BASE = "http://localhost:8080/api";

function getLocalApiTokenFromBackground() {
  return new Promise((resolve, reject) => {
    if (!chrome?.runtime?.sendMessage) {
      reject(new Error("Runtime messaging unavailable"));
      return;
    }

    chrome.runtime.sendMessage({ action: "getLocalApiToken" }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      if (response?.token) {
        resolve(response.token);
        return;
      }

      reject(new Error(response?.error || "Token unavailable"));
    });
  });
}

function refreshLocalApiTokenFromBackground() {
  return new Promise((resolve, reject) => {
    if (!chrome?.runtime?.sendMessage) {
      reject(new Error("Runtime messaging unavailable"));
      return;
    }

    chrome.runtime.sendMessage(
      { action: "refreshLocalApiToken" },
      (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        if (response?.token) {
          resolve(response.token);
          return;
        }

        reject(new Error(response?.error || "Token refresh failed"));
      },
    );
  });
}

const pageMeta = {
  dashboard: {
    title: "Security Dashboard",
    subtitle: "Real-time threat monitoring and protection",
  },
  history: {
    title: "Detection History",
    subtitle: "Recent detections and actions taken",
  },
  analytics: {
    title: "Analytics",
    subtitle: "Threat trends, volume, and protection effectiveness",
  },
  settings: {
    title: "Settings",
    subtitle: "Tune protection behavior for your browsing",
  },
  help: {
    title: "Help",
    subtitle: "Quick answers and troubleshooting guidance",
  },
};

let analyticsThreatChart = null;
let analyticsVolumeChart = null;
let dashboardThreatChart = null;
let dashboardTypesChart = null;
let dashboardSourcesChart = null;
let autoRefresh = true;
let lastDashboardSnapshot = null;
let historyActivities = [];

const TIME_RANGES = {
  "24h": {
    label: "Last 24 Hours",
    unit: "hour",
    points: 24,
    analyticsLimit: 200,
  },
  "7d": {
    label: "Last 7 Days",
    unit: "day",
    points: 7,
    analyticsLimit: 300,
  },
  "30d": {
    label: "Last 30 Days",
    unit: "day",
    points: 30,
    analyticsLimit: 500,
  },
};

function switchPage(page) {
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.page === page);
  });

  document.querySelectorAll(".page-section").forEach((section) => {
    section.classList.remove("active");
  });

  const target = document.getElementById(`page-${page}`);
  if (target) {
    target.classList.add("active");
  }

  const meta = pageMeta[page] || pageMeta.dashboard;
  document.getElementById("pageTitle").textContent = meta.title;
  document.getElementById("pageSubtitle").textContent = meta.subtitle;

  if (page === "history") {
    loadHistory();
  }

  if (page === "analytics") {
    loadAnalytics();
  }
}

async function fetchJson(url) {
  let token = await getLocalApiTokenFromBackground();
  let response = await fetch(url, {
    headers: {
      "X-PhishGuard-Token": token,
    },
  });

  if (response.status === 401) {
    token = await refreshLocalApiTokenFromBackground();
    response = await fetch(url, {
      headers: {
        "X-PhishGuard-Token": token,
      },
    });
  }

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function fetchPublicJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

function getTimeRange() {
  const selected = document.getElementById("timeRange")?.value || "24h";
  return TIME_RANGES[selected] ? selected : "24h";
}

function getRangeConfig(rangeKey) {
  return TIME_RANGES[rangeKey] || TIME_RANGES["24h"];
}

function parseTimestamp(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatRelativeTime(value) {
  const date = parseTimestamp(value);
  if (!date) {
    return "Unknown";
  }

  const deltaSeconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (deltaSeconds < 60) {
    return "just now";
  }
  if (deltaSeconds < 3600) {
    return `${Math.floor(deltaSeconds / 60)}m ago`;
  }
  if (deltaSeconds < 86400) {
    return `${Math.floor(deltaSeconds / 3600)}h ago`;
  }
  return `${Math.floor(deltaSeconds / 86400)}d ago`;
}

function formatLatencyMs(ms) {
  if (typeof ms !== "number" || Number.isNaN(ms)) {
    return "--";
  }
  if (ms >= 1000) {
    return `${(ms / 1000).toFixed(2)}s`;
  }
  return `${ms.toFixed(0)}ms`;
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = value;
  }
}

function formatPercent(value) {
  return `${Math.max(0, Math.min(100, value)).toFixed(1)}%`;
}

function setServiceStatus(healthData, hasStats, authFailed) {
  const statusText = document.getElementById("systemStatusText");
  const statusLight = document.getElementById("systemStatusLight");
  const badge = document.getElementById("systemHealthBadge");
  const dbStatus = document.getElementById("dbStatus");
  const dbStatusLight = document.getElementById("dbStatusLight");
  const dataMode = document.getElementById("dataMode");
  const lastSync = document.getElementById("lastSync");

  if (lastSync) {
    lastSync.textContent = `Last sync: ${new Date().toLocaleTimeString()}`;
  }
  if (dataMode) {
    dataMode.textContent = "Live backend telemetry";
  }

  const healthy =
    healthData?.status === "healthy" || healthData?.ml_service === "healthy";
  const degraded =
    !!healthData &&
    healthData.status !== "healthy" &&
    healthData.ml_service !== "healthy";

  if (statusLight) {
    statusLight.classList.toggle("active", healthy);
  }
  if (dbStatusLight) {
    dbStatusLight.classList.toggle("active", hasStats);
  }

  if (statusText) {
    statusText.textContent = healthy
      ? "System Active"
      : authFailed
        ? "API Reachable - Auth Required"
        : degraded
          ? "System Degraded"
          : "Backend Unreachable";
  }

  if (badge) {
    badge.textContent = healthy ? "Healthy" : degraded ? "Degraded" : "Offline";
    badge.className = `status-badge ${healthy ? "healthy" : degraded ? "warning" : "critical"}`;
  }

  if (dbStatus) {
    dbStatus.textContent = hasStats
      ? "Online"
      : authFailed
        ? "Auth Needed"
        : "Offline";
  }

  const apiPill = document.getElementById("serviceApiStatus");
  if (apiPill) {
    apiPill.textContent = healthy
      ? "Healthy"
      : authFailed
        ? "Reachable / Auth"
        : degraded
          ? "Degraded"
          : "Offline";
    apiPill.className = `service-pill ${healthy ? "healthy" : authFailed ? "warning" : degraded ? "warning" : "critical"}`;
  }

  const mlPill = document.getElementById("serviceMlStatus");
  if (mlPill) {
    const mlHealthy =
      healthData?.ml_service === "healthy" ||
      healthData?.services?.ml_service === "connected";
    mlPill.textContent = mlHealthy ? "Connected" : "Unavailable";
    mlPill.className = `service-pill ${mlHealthy ? "healthy" : "critical"}`;
  }
}

function normalizeThreatType(value) {
  const raw = String(value || "").toLowerCase();
  if (raw.includes("phish")) return "phishing";
  if (raw.includes("mal")) return "malware";
  if (raw.includes("scam")) return "scam";
  if (raw.includes("safe")) return "safe";
  return raw || "suspicious";
}

function getHistoryRows() {
  const search = (document.getElementById("historySearch")?.value || "")
    .trim()
    .toLowerCase();
  const threatFilter =
    document.getElementById("historyThreatFilter")?.value || "all";
  const statusFilter =
    document.getElementById("historyStatusFilter")?.value || "all";
  const sortBy = document.getElementById("historySortBy")?.value || "newest";

  const filtered = historyActivities.filter((item) => {
    const domain = String(item?.domain || "unknown").toLowerCase();
    const threatType = normalizeThreatType(item?.threat_type);
    const status = item?.is_phishing ? "blocked" : "allowed";

    if (search && !domain.includes(search)) {
      return false;
    }
    if (threatFilter !== "all" && threatType !== threatFilter) {
      return false;
    }
    if (statusFilter !== "all" && status !== statusFilter) {
      return false;
    }
    return true;
  });

  if (sortBy === "oldest") {
    filtered.sort(
      (a, b) =>
        new Date(a?.timestamp || 0).getTime() -
        new Date(b?.timestamp || 0).getTime(),
    );
  } else if (sortBy === "confidence") {
    filtered.sort((a, b) => (b?.confidence || 0) - (a?.confidence || 0));
  } else {
    filtered.sort(
      (a, b) =>
        new Date(b?.timestamp || 0).getTime() -
        new Date(a?.timestamp || 0).getTime(),
    );
  }

  return filtered;
}

function updateHistoryKPIs(rows) {
  const blocked = rows.filter((item) => item?.is_phishing).length;
  const highConfidence = rows.filter(
    (item) => (item?.confidence || 0) >= 0.85,
  ).length;
  const domainCounts = rows.reduce((acc, item) => {
    const key = String(item?.domain || "unknown");
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const topDomain =
    Object.entries(domainCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || "--";

  setText("historyTotalEvents", rows.length.toLocaleString());
  setText("historyBlockedEvents", blocked.toLocaleString());
  setText("historyHighConfidence", highConfidence.toLocaleString());
  setText("historyTopDomain", topDomain);
}

function renderHistoryTable() {
  const body = document.getElementById("historyTableBody");
  const hint = document.getElementById("historyEmptyHint");
  if (!body) {
    return;
  }

  const rows = getHistoryRows();
  updateHistoryKPIs(rows);

  if (!rows.length) {
    body.innerHTML =
      '<tr><td colspan="5">No detections match current filters.</td></tr>';
    if (hint) {
      hint.textContent = "Try clearing filters or expanding the time range.";
    }
    return;
  }

  if (hint) {
    hint.textContent = `${rows.length} events shown`;
  }

  body.innerHTML = rows
    .slice(0, 200)
    .map((item) => {
      const confidence = Math.round((item.confidence || 0) * 100);
      const status = item.is_phishing ? "Blocked" : "Allowed";
      const time = new Date(item.timestamp).toLocaleString();
      const tone = item.is_phishing ? "high" : "low";
      return `
          <tr>
            <td>${time}</td>
            <td>${item.domain || "unknown"}</td>
            <td><span class="threat-tag ${normalizeThreatType(item.threat_type)}">${normalizeThreatType(item.threat_type)}</span></td>
            <td>${confidence}%</td>
            <td><span class="status-tag ${tone}">${status}</span></td>
          </tr>
        `;
    })
    .join("");
}

function exportHistoryCsv() {
  const rows = getHistoryRows();
  if (!rows.length) {
    return;
  }

  const csv = [
    ["timestamp", "domain", "threat_type", "confidence", "status"],
    ...rows.map((row) => [
      row.timestamp || "",
      row.domain || "unknown",
      normalizeThreatType(row.threat_type),
      `${Math.round((row.confidence || 0) * 100)}%`,
      row.is_phishing ? "blocked" : "allowed",
    ]),
  ]
    .map((cols) =>
      cols.map((v) => `"${String(v).replaceAll('"', '""')}"`).join(","),
    )
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `phishguard-history-${Date.now()}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function setActiveSensitivityPill(mode) {
  document.querySelectorAll(".pill-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === mode);
  });
}

function setActivePreset(preset) {
  document.querySelectorAll(".preset-chip").forEach((chip) => {
    chip.classList.toggle("active", chip.dataset.preset === preset);
  });
}

function updatePosturePreview() {
  const sensitivity =
    document.getElementById("settingSensitivity")?.value || "balanced";
  const protection = !!document.getElementById("settingProtection")?.checked;
  const autoBlock = !!document.getElementById("settingAutoBlock")?.checked;
  const liveAlerts = !!document.getElementById("settingLiveAlerts")?.checked;

  const fill = document.getElementById("postureFill");
  const label = document.getElementById("postureLabel");
  const hint = document.getElementById("postureHint");

  if (!fill || !label || !hint) {
    return;
  }

  if (!protection) {
    fill.style.width = "18%";
    fill.style.background = "linear-gradient(90deg, #c0152f 0%, #ff5459 100%)";
    label.textContent = "Low Protection";
    hint.textContent =
      "Engine is disabled. Turn protection on for real-time defense.";
    return;
  }

  let score = 50;
  if (sensitivity === "conservative") score = 42;
  if (sensitivity === "balanced") score = 64;
  if (sensitivity === "aggressive") score = 86;
  if (autoBlock) score += 7;
  if (liveAlerts) score += 5;
  score = Math.max(0, Math.min(100, score));

  fill.style.width = `${score}%`;

  if (score < 45) {
    fill.style.background = "linear-gradient(90deg, #e68161 0%, #f59e0b 100%)";
    label.textContent = "Comfort Mode";
    hint.textContent =
      "Lower strictness with fewer disruptions, but reduced threat catch rate.";
  } else if (score < 75) {
    fill.style.background = "linear-gradient(90deg, #10b981 0%, #32b8c6 100%)";
    label.textContent = "Balanced";
    hint.textContent = "Recommended blend of safety and browsing comfort.";
  } else {
    fill.style.background = "linear-gradient(90deg, #32b8c6 0%, #7be7f0 100%)";
    label.textContent = "Fortress";
    hint.textContent =
      "Maximum defense profile tuned to aggressively catch suspicious threats.";
  }
}

function applyPreset(preset) {
  const sensitivityEl = document.getElementById("settingSensitivity");
  const protectionEl = document.getElementById("settingProtection");
  const refreshEl = document.getElementById("settingAutoRefresh");
  const alertsEl = document.getElementById("settingLiveAlerts");
  const autoBlockEl = document.getElementById("settingAutoBlock");
  const soundEl = document.getElementById("settingSound");

  if (
    !sensitivityEl ||
    !protectionEl ||
    !refreshEl ||
    !alertsEl ||
    !autoBlockEl ||
    !soundEl
  ) {
    return;
  }

  if (preset === "work") {
    protectionEl.checked = true;
    refreshEl.checked = true;
    alertsEl.checked = true;
    autoBlockEl.checked = true;
    soundEl.checked = false;
    sensitivityEl.value = "balanced";
  }

  if (preset === "personal") {
    protectionEl.checked = true;
    refreshEl.checked = true;
    alertsEl.checked = false;
    autoBlockEl.checked = false;
    soundEl.checked = false;
    sensitivityEl.value = "conservative";
  }

  if (preset === "fortress") {
    protectionEl.checked = true;
    refreshEl.checked = true;
    alertsEl.checked = true;
    autoBlockEl.checked = true;
    soundEl.checked = true;
    sensitivityEl.value = "aggressive";
  }

  setActivePreset(preset);
  setActiveSensitivityPill(sensitivityEl.value);
  updatePosturePreview();
}

function updateDashboardStats(globalStats, healthData) {
  if (!globalStats) {
    setText("attacksPrevented", "--");
    setText("sitesScanned", "--");
    setText("activeUsers", "--");
    setText("detectionRate", "--");
    setText("aiAccuracy", "--");
    setText("queueLength", "--");
    setText("processingSpeed", "--");
    setText("lastUpdate", "Unknown");
    setText("blockedTrend", "Live data unavailable");
    setText("scanTrend", "Live data unavailable");
    setText("confidenceTrend", "Live data unavailable");
    setText("usersTrend", "Live data unavailable");
    const bar = document.getElementById("aiAccuracyBar");
    if (bar) {
      bar.style.width = "0%";
    }
    return;
  }

  const scans = globalStats.total_scans || 0;
  const blocked = globalStats.threats_blocked || 0;
  const users = globalStats.total_users || 0;
  const confidence = (globalStats.avg_confidence || 0) * 100;

  setText("attacksPrevented", blocked.toLocaleString());
  setText("sitesScanned", scans.toLocaleString());
  setText("activeUsers", users.toLocaleString());
  setText("detectionRate", formatPercent(confidence));
  setText("aiAccuracy", formatPercent(confidence));
  setText("queueLength", Math.max(0, scans - blocked).toLocaleString());
  setText("processingSpeed", formatLatencyMs(globalStats.avg_latency_ms));
  setText(
    "lastUpdate",
    healthData?.timestamp
      ? formatRelativeTime(healthData.timestamp)
      : "Unknown",
  );
  setText(
    "blockedTrend",
    `${(globalStats.threats_last_24h || 0).toLocaleString()} threats in 24h`,
  );
  setText(
    "scanTrend",
    `${(globalStats.scans_last_hour || 0).toLocaleString()} scans in the last hour`,
  );
  setText(
    "confidenceTrend",
    `Confidence from ${scans.toLocaleString()} total scans`,
  );
  setText(
    "usersTrend",
    `${(globalStats.active_users || 0).toLocaleString()} users active in 24h`,
  );

  const bar = document.getElementById("aiAccuracyBar");
  if (bar) {
    bar.style.width = `${Math.max(0, Math.min(100, confidence))}%`;
  }
}

function buildActivityRows(activities) {
  const feed = document.getElementById("activityList");
  if (!feed) {
    return;
  }

  if (!activities.length) {
    feed.innerHTML = `
      <div class="activity-item">
        <div class="activity-icon low">i</div>
        <div class="activity-details">
          <h4>No live activity yet</h4>
          <p>New detections will appear here automatically.</p>
        </div>
        <div class="activity-time">--</div>
      </div>
    `;
    return;
  }

  feed.innerHTML = activities
    .slice(0, 10)
    .map((item) => {
      const levelRaw = String(item?.threat_type || "").toLowerCase();
      const level = item?.is_phishing
        ? "high"
        : levelRaw.includes("mal")
          ? "medium"
          : "low";
      const status = item?.is_phishing ? "Blocked" : "Allowed";
      const domain = item?.domain || "unknown";
      const confidence = Math.round((item?.confidence || 0) * 100);
      return `
        <div class="activity-item">
          <div class="activity-icon ${level}">${level === "high" ? "!" : level === "medium" ? "~" : "i"}</div>
          <div class="activity-details">
            <h4>${domain}</h4>
            <p>${status} - ${confidence}% confidence</p>
          </div>
          <div class="activity-time">${formatRelativeTime(item?.timestamp)}</div>
        </div>
      `;
    })
    .join("");
}

function buildTimelineSeries(activities, rangeKey, threatOnly) {
  const range = getRangeConfig(rangeKey);
  const now = new Date();
  const labels = [];
  const values = [];

  for (let idx = range.points - 1; idx >= 0; idx -= 1) {
    const bucketStart = new Date(now);
    if (range.unit === "hour") {
      bucketStart.setMinutes(0, 0, 0);
      bucketStart.setHours(now.getHours() - idx);
      labels.push(`${bucketStart.getHours().toString().padStart(2, "0")}:00`);
    } else {
      bucketStart.setHours(0, 0, 0, 0);
      bucketStart.setDate(now.getDate() - idx);
      labels.push(`${bucketStart.getMonth() + 1}/${bucketStart.getDate()}`);
    }

    const bucketEnd = new Date(bucketStart);
    if (range.unit === "hour") {
      bucketEnd.setHours(bucketStart.getHours() + 1);
    } else {
      bucketEnd.setDate(bucketStart.getDate() + 1);
    }

    const count = activities.filter((item) => {
      const ts = parseTimestamp(item?.timestamp);
      if (!ts) {
        return false;
      }
      if (threatOnly && !item?.is_phishing) {
        return false;
      }
      return ts >= bucketStart && ts < bucketEnd;
    }).length;

    values.push(count);
  }

  return { labels, values };
}

function initMainCharts(globalStats, activities, rangeKey) {
  const breakdown = globalStats?.threat_breakdown || {};
  const threatSeries = [
    breakdown.critical || 0,
    breakdown.high || 0,
    breakdown.medium || 0,
    breakdown.low || 0,
    breakdown.safe || 0,
  ];

  const timeline = buildTimelineSeries(activities, rangeKey, true);
  const topDomains = (globalStats?.top_phishing_domains || []).slice(0, 5);

  const lineCtx = document.getElementById("threatsChart")?.getContext("2d");
  const pieCtx = document.getElementById("threatTypesChart")?.getContext("2d");
  const barCtx = document
    .getElementById("threatSourcesChart")
    ?.getContext("2d");

  if (lineCtx) {
    if (dashboardThreatChart) {
      dashboardThreatChart.destroy();
    }
    dashboardThreatChart = new Chart(lineCtx, {
      type: "line",
      data: {
        labels: timeline.labels,
        datasets: [
          {
            data: timeline.values,
            borderColor: "#1FB896",
            backgroundColor: "rgba(31, 184, 150, 0.2)",
            borderWidth: 2,
            fill: true,
            tension: 0.3,
          },
        ],
      },
      options: {
        plugins: { legend: { display: false } },
        scales: { x: { ticks: { maxTicksLimit: 8 } } },
      },
    });
  }

  if (pieCtx) {
    if (dashboardTypesChart) {
      dashboardTypesChart.destroy();
    }
    dashboardTypesChart = new Chart(pieCtx, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "Safe"],
        datasets: [
          {
            data: threatSeries,
            backgroundColor: [
              "#E56E6E",
              "#D9A05B",
              "#9CA3A1",
              "#1FB896",
              "#1AA181",
            ],
          },
        ],
      },
      options: { plugins: { legend: { position: "bottom" } } },
    });
  }

  if (barCtx) {
    if (dashboardSourcesChart) {
      dashboardSourcesChart.destroy();
    }
    dashboardSourcesChart = new Chart(barCtx, {
      type: "bar",
      data: {
        labels: topDomains.map((item) => item.domain || "unknown"),
        datasets: [
          {
            data: topDomains.map((item) => item.count || 0),
            backgroundColor: "#1FB896",
          },
        ],
      },
      options: { plugins: { legend: { display: false } } },
    });
  }
}

function getStoredUserId() {
  return new Promise((resolve, reject) => {
    if (!chrome?.storage?.local) {
      reject(new Error("Chrome storage unavailable"));
      return;
    }

    chrome.storage.local.get(["userId"], (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      if (result.userId) {
        resolve(result.userId);
        return;
      }

      const newUserId = crypto.randomUUID();
      chrome.storage.local.set({ userId: newUserId }, () => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(newUserId);
      });
    });
  });
}

async function loadHistory() {
  const body = document.getElementById("historyTableBody");
  if (!body) {
    return;
  }

  try {
    const userId = await getStoredUserId();
    const data = await fetchJson(
      `${API_BASE}/user/${userId}/analytics?limit=100`,
    );
    const activities = data.recent_activities || [];

    historyActivities = activities;
    renderHistoryTable();
  } catch (_error) {
    body.innerHTML =
      '<tr><td colspan="5">History unavailable. Start backend services to load live data.</td></tr>';
  }
}

function buildAnalyticsCharts(data) {
  const breakdown = data.threat_breakdown || {};
  const threatData = [
    breakdown.phishing_count || 0,
    breakdown.malware_count || 0,
    breakdown.cryptojacking_count || 0,
    (breakdown.total_count || 0) -
      (breakdown.phishing_count || 0) -
      (breakdown.malware_count || 0) -
      (breakdown.cryptojacking_count || 0), // Other
  ];

  const volumeTimeline = buildTimelineSeries(
    data.activities || [],
    "7d",
    false,
  );

  if (analyticsThreatChart) {
    analyticsThreatChart.destroy();
  }
  if (analyticsVolumeChart) {
    analyticsVolumeChart.destroy();
  }

  const threatCtx = document
    .getElementById("analyticsThreatChart")
    ?.getContext("2d");
  const volumeCtx = document
    .getElementById("analyticsVolumeChart")
    ?.getContext("2d");

  if (threatCtx) {
    analyticsThreatChart = new Chart(threatCtx, {
      type: "bar",
      data: {
        labels: ["Phishing", "Malware", "Crypto", "Other"],
        datasets: [
          {
            data: threatData,
            backgroundColor: ["#1AA181", "#1FB896", "#9CA3A1", "#6B7270"],
          },
        ],
      },
      options: { plugins: { legend: { display: false } } },
    });
  }

  if (volumeCtx) {
    analyticsVolumeChart = new Chart(volumeCtx, {
      type: "line",
      data: {
        labels: volumeTimeline.labels,
        datasets: [
          {
            data: volumeTimeline.values,
            borderColor: "#1FB896",
            tension: 0.3,
            fill: false,
          },
        ],
      },
      options: { plugins: { legend: { display: false } } },
    });
  }
}

async function loadAnalytics() {
  const rangeKey = getTimeRange();
  const snapshot = await loadDashboardSnapshot(rangeKey);
  const blocked = snapshot.globalStats?.threats_blocked || 0;
  const scans = snapshot.globalStats?.total_scans || 0;
  const ratio = scans ? (blocked / scans) * 100 : 0;
  const activities = snapshot.activities || [];
  const allowed = Math.max(0, scans - blocked);
  const highRisk = activities.filter((item) => {
    const t = normalizeThreatType(item?.threat_type);
    return t === "phishing" || t === "malware";
  }).length;
  const topDomain =
    Object.entries(
      activities.reduce((acc, item) => {
        const key = String(item?.domain || "unknown");
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {}),
    ).sort((a, b) => b[1] - a[1])[0]?.[0] || "--";

  const avgConfidence =
    activities.length > 0
      ? (activities.reduce((sum, item) => sum + (item?.confidence || 0), 0) /
          activities.length) *
        100
      : 0;

  const byHour = activities.reduce((acc, item) => {
    const ts = parseTimestamp(item?.timestamp);
    if (!ts) return acc;
    const key = `${ts.getHours().toString().padStart(2, "0")}:00`;
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const peakWindow =
    Object.entries(byHour).sort((a, b) => b[1] - a[1])[0]?.[0] || "--";

  const threatCounts = activities.reduce((acc, item) => {
    const type = normalizeThreatType(item?.threat_type);
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {});
  const topThreat =
    Object.entries(threatCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || "--";

  setText("analyticsBlocked", blocked.toLocaleString());
  setText("analyticsScans", scans.toLocaleString());
  setText("analyticsRatio", formatPercent(ratio));
  setText("analyticsHighRisk", highRisk.toLocaleString());
  setText("analyticsAllowed", allowed.toLocaleString());
  setText("analyticsTopDomain", topDomain);

  setText("insightPeakWindow", peakWindow);
  setText("insightTopThreat", topThreat);
  setText("insightAvgConfidence", formatPercent(avgConfidence));
  setText(
    "insightPosture",
    blocked > 0 ? "Threat Blocking Active" : "Monitoring",
  );

  buildAnalyticsCharts({
    ...(snapshot.globalStats || {}),
    activities: snapshot.activities,
  });
}

async function loadDashboardSnapshot(rangeKey) {
  const userId = await getStoredUserId();
  const range = getRangeConfig(rangeKey);

  const [globalResult, healthResult, userResult] = await Promise.allSettled([
    fetchJson(`${API_BASE}/stats/global`),
    fetchPublicJson("http://localhost:8080/health"),
    fetchJson(
      `${API_BASE}/user/${userId}/analytics?limit=${range.analyticsLimit}`,
    ),
  ]);

  const snapshot = {
    globalStats:
      globalResult.status === "fulfilled" ? globalResult.value : null,
    health: healthResult.status === "fulfilled" ? healthResult.value : null,
    userAnalytics: userResult.status === "fulfilled" ? userResult.value : null,
    activities:
      userResult.status === "fulfilled"
        ? userResult.value.recent_activities || []
        : [],
    errors: {
      global:
        globalResult.status === "rejected" ? String(globalResult.reason) : "",
      health:
        healthResult.status === "rejected" ? String(healthResult.reason) : "",
      user: userResult.status === "rejected" ? String(userResult.reason) : "",
    },
  };

  lastDashboardSnapshot = snapshot;
  return snapshot;
}

async function loadDashboard() {
  const rangeKey = getTimeRange();
  let snapshot = null;

  try {
    snapshot = await loadDashboardSnapshot(rangeKey);
  } catch (_error) {
    snapshot = lastDashboardSnapshot;
  }

  if (!snapshot) {
    setServiceStatus(null, false);
    updateDashboardStats(null, null);
    buildActivityRows([]);
    initMainCharts(null, [], rangeKey);
    return;
  }

  const authFailed = /401|token|auth/i.test(
    `${snapshot.errors?.global || ""} ${snapshot.errors?.user || ""}`,
  );
  setServiceStatus(snapshot.health, !!snapshot.globalStats, authFailed);
  updateDashboardStats(snapshot.globalStats, snapshot.health);
  buildActivityRows(snapshot.activities);
  initMainCharts(snapshot.globalStats, snapshot.activities, rangeKey);
}

async function refreshServiceChecks() {
  const statusEl = document.getElementById("serviceCheckStatus");
  if (statusEl) {
    statusEl.textContent = "Checking services...";
  }

  try {
    const health = await fetchPublicJson("http://localhost:8080/health");
    const authFailed = !lastDashboardSnapshot?.globalStats;
    setServiceStatus(health, !!lastDashboardSnapshot?.globalStats, authFailed);
    if (statusEl) {
      statusEl.textContent = "Service check completed";
      setTimeout(() => {
        statusEl.textContent = "";
      }, 2500);
    }
  } catch (_error) {
    setServiceStatus(null, false, false);
    if (statusEl) {
      statusEl.textContent = "Unable to reach backend health endpoint";
    }
  }
}

function wireHelpExperience() {
  document.querySelectorAll(".help-question").forEach((btn) => {
    btn.addEventListener("click", () => {
      const item = btn.closest(".help-item");
      if (!item) return;
      item.classList.toggle("open");
    });
  });

  const helpSearch = document.getElementById("helpSearch");
  const emptyHint = document.getElementById("helpEmptyHint");
  if (helpSearch) {
    helpSearch.addEventListener("input", () => {
      const q = helpSearch.value.trim().toLowerCase();
      let visible = 0;
      document.querySelectorAll("#helpAccordion .help-item").forEach((item) => {
        const content = item.textContent?.toLowerCase() || "";
        const tags = item.getAttribute("data-tags") || "";
        const show = !q || content.includes(q) || tags.includes(q);
        item.style.display = show ? "block" : "none";
        if (show) visible += 1;
      });
      if (emptyHint) {
        emptyHint.textContent = visible
          ? ""
          : "No help results matched your query.";
      }
    });
  }

  document.querySelectorAll(".help-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const target = chip.getAttribute("data-help-target");
      const answer = target
        ? document.querySelector(`[data-help-id="${target}"]`)
        : null;
      if (!answer) return;

      const item = answer.closest(".help-item");
      if (!item) return;

      document.querySelectorAll("#helpAccordion .help-item").forEach((row) => {
        row.classList.remove("open");
      });
      item.classList.add("open");
      item.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  });
}

function loadSettings() {
  if (!chrome?.storage?.local) {
    return;
  }

  chrome.storage.local.get(
    [
      "protectionEnabled",
      "sensitivityMode",
      "dashboardAutoRefresh",
      "liveThreatAlerts",
      "autoBlockHighRisk",
      "notificationSound",
    ],
    (result) => {
      const protection = result.protectionEnabled !== false;
      const sensitivity = result.sensitivityMode || "balanced";
      autoRefresh = result.dashboardAutoRefresh !== false;
      const liveAlerts = result.liveThreatAlerts !== false;
      const autoBlock = result.autoBlockHighRisk !== false;
      const notificationSound = result.notificationSound === true;

      const protectionEl = document.getElementById("settingProtection");
      const sensitivityEl = document.getElementById("settingSensitivity");
      const autoRefreshEl = document.getElementById("settingAutoRefresh");
      const liveAlertsEl = document.getElementById("settingLiveAlerts");
      const autoBlockEl = document.getElementById("settingAutoBlock");
      const soundEl = document.getElementById("settingSound");

      if (protectionEl) protectionEl.checked = protection;
      if (sensitivityEl) sensitivityEl.value = sensitivity;
      if (autoRefreshEl) autoRefreshEl.checked = autoRefresh;
      if (liveAlertsEl) liveAlertsEl.checked = liveAlerts;
      if (autoBlockEl) autoBlockEl.checked = autoBlock;
      if (soundEl) soundEl.checked = notificationSound;

      setActiveSensitivityPill(sensitivity);
      updatePosturePreview();
    },
  );
}

function saveSettings() {
  const protectionEl = document.getElementById("settingProtection");
  const sensitivityEl = document.getElementById("settingSensitivity");
  const autoRefreshEl = document.getElementById("settingAutoRefresh");
  const liveAlertsEl = document.getElementById("settingLiveAlerts");
  const autoBlockEl = document.getElementById("settingAutoBlock");
  const soundEl = document.getElementById("settingSound");
  const statusEl = document.getElementById("settingsStatus");

  const settings = {
    protectionEnabled: !!protectionEl?.checked,
    sensitivityMode: sensitivityEl?.value || "balanced",
    dashboardAutoRefresh: !!autoRefreshEl?.checked,
    liveThreatAlerts: !!liveAlertsEl?.checked,
    autoBlockHighRisk: !!autoBlockEl?.checked,
    notificationSound: !!soundEl?.checked,
  };

  autoRefresh = settings.dashboardAutoRefresh;

  if (!chrome?.storage?.local) {
    if (statusEl) {
      statusEl.textContent = "Saved for current session";
    }
    return;
  }

  chrome.storage.local.set(settings, () => {
    if (statusEl) {
      statusEl.textContent = "Settings saved";
      setTimeout(() => {
        statusEl.textContent = "";
      }, 3000);
    }
  });
}

function wireEvents() {
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.addEventListener("click", (event) => {
      event.preventDefault();
      switchPage(item.dataset.page || "dashboard");
    });
  });

  document
    .getElementById("refreshHistoryBtn")
    ?.addEventListener("click", loadHistory);
  document
    .getElementById("saveSettingsBtn")
    ?.addEventListener("click", saveSettings);
  document
    .getElementById("recheckServicesBtn")
    ?.addEventListener("click", refreshServiceChecks);
  document
    .getElementById("historyExportBtn")
    ?.addEventListener("click", exportHistoryCsv);

  document.getElementById("timeRange")?.addEventListener("change", async () => {
    const active = document.querySelector(".page-section.active")?.id;
    if (active === "page-analytics") {
      await loadAnalytics();
      return;
    }
    await loadDashboard();
  });

  document.querySelectorAll(".pill-button").forEach((button) => {
    button.addEventListener("click", () => {
      const mode = button.dataset.mode || "balanced";
      const sensitivityEl = document.getElementById("settingSensitivity");
      if (sensitivityEl) {
        sensitivityEl.value = mode;
      }
      setActiveSensitivityPill(mode);
      setActivePreset("");
      updatePosturePreview();
    });
  });

  document.querySelectorAll(".preset-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      applyPreset(chip.dataset.preset || "work");
    });
  });

  [
    "settingProtection",
    "settingAutoRefresh",
    "settingLiveAlerts",
    "settingAutoBlock",
    "settingSound",
    "settingSensitivity",
  ].forEach((id) => {
    document.getElementById(id)?.addEventListener("change", () => {
      setActivePreset("");
      updatePosturePreview();
    });
  });

  [
    "historySearch",
    "historyThreatFilter",
    "historyStatusFilter",
    "historySortBy",
  ].forEach((id) => {
    document.getElementById(id)?.addEventListener("input", renderHistoryTable);
    document.getElementById(id)?.addEventListener("change", renderHistoryTable);
  });

  wireHelpExperience();
}

document.addEventListener("DOMContentLoaded", async () => {
  if (window.Chart) {
    Chart.defaults.color = "#9CA3A1";
    Chart.defaults.borderColor = "#313534";
    Chart.defaults.font.family = '"Inter", -apple-system, sans-serif';
  }

  wireEvents();
  loadSettings();
  await loadDashboard();

  setInterval(async () => {
    if (!autoRefresh) {
      return;
    }
    const active = document.querySelector(".page-section.active")?.id;
    if (active === "page-dashboard") {
      await loadDashboard();
    }
    if (active === "page-history") {
      await loadHistory();
    }
    if (active === "page-analytics") {
      await loadAnalytics();
    }
  }, 2000);
});
