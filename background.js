/**
 * 🛡️ PHISHGUARD AI - BACKGROUND SERVICE WORKER
 * ============================================
 *
 * Central hub for extension logic and network monitoring
 *
 * Features:
 * - Network request interception (webRequest API)
 * - C&C server blacklist management
 * - Data exfiltration tracking
 * - Threat intelligence integration
 * - Real-time blocking capabilities
 * - Statistics tracking

 *
 * @author PhishGuard AI Team
 * @version 2.0.0
 * @date October 10, 2025
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  // ML API endpoint - REAL RUST API GATEWAY
  ML_API_URL: "http://localhost:8080/api/check-url",

  // 📊 USER ANALYTICS API - NEW
  ANALYTICS_API_URL: "http://localhost:8080/api/user",

  // Runtime control-plane endpoints
  CONTROL_PLANE_BOOTSTRAP_URL:
    "http://localhost:8080/api/control-plane/bootstrap",
  CONTROL_PLANE_ROTATE_URL: "http://localhost:8080/api/control-plane/rotate",

  // Data exfiltration thresholds
  LARGE_POST_THRESHOLD: 100 * 1024, // 100 KB
  CRITICAL_POST_THRESHOLD: 1024 * 1024, // 1 MB

  // C&C server patterns
  CC_SERVER_PATTERNS: [
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/, // IP:PORT
    /\.onion($|\/)/, // Tor
    /\.i2p($|\/)/, // I2P
    /[a-z0-9]{20,}\.com/, // DGA domains
    /pastebin\.com\/raw/,
    /discord\.com\/api\/webhooks/,
    /bit\.ly|tinyurl\.com|goo\.gl/,
  ],

  // Suspicious ports
  SUSPICIOUS_PORTS: [
    4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 6667, 6668, 6669,
  ],

  // Whitelisted domains
  WHITELIST: [
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "microsoft.com",
    "amazon.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
  ],

  // Auto-blocking
  AUTO_BLOCK_CC_SERVERS: true,
  AUTO_BLOCK_LARGE_EXFILTRATION: true,

  DEBUG: true,
};

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

const state = {
  // Protection status
  protectionEnabled: true,

  // Statistics
  totalRequests: 0,
  blockedRequests: 0,
  phishingSitesBlocked: 0,

  // Blacklists
  ccServerBlacklist: new Set(),
  domainBlacklist: new Set(),

  // Network monitoring
  suspiciousActivity: [],
  dataExfiltrationEvents: [],

  // Fingerprinting
  fingerprintingDetections: [],

  // Behavioral
  behavioralAlerts: [],

  // Last scan
  lastScanTime: null,
  lastThreatDetected: null,
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function debug(message, data = null) {
  if (CONFIG.DEBUG) {
    console.log(`[PhishGuard BG] ${message}`, data || "");
  }
}

async function getOrCreateInstallId() {
  const result = await chrome.storage.local.get(["controlPlaneInstallId"]);
  if (result.controlPlaneInstallId) {
    return result.controlPlaneInstallId;
  }

  const installId = crypto.randomUUID();
  await chrome.storage.local.set({ controlPlaneInstallId: installId });
  return installId;
}

async function bootstrapControlPlaneToken(forceRotate = false) {
  const installId = await getOrCreateInstallId();
  const extensionId = chrome.runtime.id;
  const { localApiToken } = await chrome.storage.local.get(["localApiToken"]);

  const shouldRotate = forceRotate && !!localApiToken;
  const url = shouldRotate
    ? CONFIG.CONTROL_PLANE_ROTATE_URL
    : CONFIG.CONTROL_PLANE_BOOTSTRAP_URL;

  const headers = {
    "Content-Type": "application/json",
  };

  if (shouldRotate) {
    headers["X-PhishGuard-Token"] = localApiToken;
  }

  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({
      install_id: installId,
      extension_id: extensionId,
    }),
  });

  if (!response.ok) {
    throw new Error(`Control-plane request failed: ${response.status}`);
  }

  const payload = await response.json();
  await chrome.storage.local.set({ localApiToken: payload.token });
  return payload.token;
}

async function getLocalApiToken() {
  const { localApiToken } = await chrome.storage.local.get(["localApiToken"]);
  if (localApiToken) {
    return localApiToken;
  }

  return bootstrapControlPlaneToken(false);
}

async function refreshLocalApiToken() {
  try {
    return await bootstrapControlPlaneToken(true);
  } catch (_error) {
    return bootstrapControlPlaneToken(false);
  }
}

async function fetchWithControlPlaneAuth(
  url,
  options = {},
  retryOnAuth = true,
) {
  const token = await getLocalApiToken();
  let response = await fetch(url, {
    ...options,
    headers: {
      ...(options.headers || {}),
      "X-PhishGuard-Token": token,
    },
  });

  if (response.status === 401 && retryOnAuth) {
    const refreshedToken = await refreshLocalApiToken();
    response = await fetch(url, {
      ...options,
      headers: {
        ...(options.headers || {}),
        "X-PhishGuard-Token": refreshedToken,
      },
    });
  }

  return response;
}

function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (e) {
    return null;
  }
}

function extractPort(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.port || (urlObj.protocol === "https:" ? 443 : 80);
  } catch (e) {
    return null;
  }
}

function isWhitelisted(domain) {
  return CONFIG.WHITELIST.some((whitelisted) => domain.includes(whitelisted));
}

function isBlacklisted(domain) {
  return (
    state.domainBlacklist.has(domain) || state.ccServerBlacklist.has(domain)
  );
}

function addToBlacklist(domain, reason = "Suspicious activity") {
  state.domainBlacklist.add(domain);
  debug(`🚫 Blacklisted: ${domain} (${reason})`);

  // Persist to storage
  chrome.storage.local.set({
    domainBlacklist: Array.from(state.domainBlacklist),
  });
}

// ============================================================================
// 🔐 ENCRYPTION & USER ANALYTICS (NEW)
// ============================================================================

/**
 * Get or generate user ID
 */
async function getUserId() {
  const result = await chrome.storage.local.get("userId");
  if (result.userId) {
    return result.userId;
  }

  // Generate new UUID for user
  const userId = crypto.randomUUID();
  await chrome.storage.local.set({ userId });
  debug(`🆔 Generated new user ID: ${userId}`);
  return userId;
}

/**
 * Derive encryption key from user ID using SHA-256
 */
async function deriveEncryptionKey(userId) {
  const encoder = new TextEncoder();
  const data = encoder.encode(userId);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);

  // Import as AES-GCM key
  const key = await crypto.subtle.importKey(
    "raw",
    hashBuffer,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );

  return key;
}

/**
 * Encrypt URL with AES-256-GCM
 */
async function encryptURL(url, key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(url);

  // Generate random 96-bit nonce
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    data,
  );

  // Convert to base64
  const ciphertextBase64 = btoa(
    String.fromCharCode(...new Uint8Array(ciphertext)),
  );
  const nonceBase64 = btoa(String.fromCharCode(...nonce));

  return {
    ciphertext: ciphertextBase64,
    nonce: nonceBase64,
  };
}

/**
 * Create SHA-256 hash for URL indexing
 */
async function hashForIndexing(data) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function generateRequestNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Log activity to user analytics API
 */
async function logUserActivity(url, scanResult) {
  try {
    const userId = await getUserId();
    const key = await deriveEncryptionKey(userId);
    const encrypted = await encryptURL(url, key);
    const urlHash = await hashForIndexing(url);

    const domain = extractDomain(url);

    // Local-first privacy default: do not perform external IP lookups.
    // IP data can be introduced later only through explicit opt-in flows.
    const clientIp = null;

    const activity = {
      encrypted_url: encrypted.ciphertext,
      encrypted_url_hash: urlHash,
      domain: domain || "unknown",
      is_phishing: scanResult.is_phishing || false,
      threat_type: scanResult.threat_type || null,
      threat_level: scanResult.threat_level || null,
      confidence: scanResult.confidence || 0.0,
      action_taken: scanResult.blocked
        ? "blocked"
        : scanResult.warning
          ? "warned"
          : "allowed",
      client_ip: clientIp,
      request_nonce: generateRequestNonce(),
      client_timestamp: Math.floor(Date.now() / 1000),
    };

    // Send to API
    const response = await fetchWithControlPlaneAuth(
      `${CONFIG.ANALYTICS_API_URL}/${userId}/activity`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(activity),
      },
    );

    if (response.ok) {
      debug(`📊 Activity logged for user ${userId}`);
    } else {
      debug(`⚠️ Failed to log activity: ${response.status}`);
    }
  } catch (error) {
    debug(`❌ Error logging activity: ${error.message}`);
  }
}

// ============================================================================
// NETWORK REQUEST MONITORING
// ============================================================================

/**
 * Monitor all outgoing requests for suspicious activity
 */
chrome.webRequest.onBeforeRequest.addListener(
  function (details) {
    if (!state.protectionEnabled) return {};

    state.totalRequests++;

    const url = details.url;
    const domain = extractDomain(url);

    if (!domain) return {};

    debug(`Request: ${details.method} ${url}`);

    // Check whitelist
    if (isWhitelisted(domain)) {
      return {};
    }

    // Check blacklist
    if (isBlacklisted(domain)) {
      state.blockedRequests++;
      debug(`🚫 BLOCKED (blacklisted): ${url}`);
      return { cancel: true };
    }

    // Check for C&C server patterns
    const ccDetection = detectCCServer(url, domain);
    if (ccDetection.isCC) {
      state.blockedRequests++;
      state.ccServerBlacklist.add(domain);

      showNotification(
        "C&C Server Blocked",
        `Blocked connection to suspicious server: ${domain}\nReason: ${ccDetection.reason}`,
      );

      if (CONFIG.AUTO_BLOCK_CC_SERVERS) {
        return { cancel: true };
      }
    }

    // Check for data exfiltration (POST/PUT with large body)
    if (
      (details.method === "POST" || details.method === "PUT") &&
      details.requestBody
    ) {
      const bodySize = estimateRequestBodySize(details.requestBody);

      if (bodySize > CONFIG.LARGE_POST_THRESHOLD) {
        state.dataExfiltrationEvents.push({
          url: url,
          domain: domain,
          size: bodySize,
          timestamp: Date.now(),
        });

        debug(
          `📤 Large POST detected: ${domain} - ${(bodySize / 1024).toFixed(
            2,
          )} KB`,
        );

        if (
          bodySize > CONFIG.CRITICAL_POST_THRESHOLD &&
          CONFIG.AUTO_BLOCK_LARGE_EXFILTRATION
        ) {
          state.blockedRequests++;
          showNotification(
            "Data Exfiltration Blocked",
            `Blocked large data upload to: ${domain}\nSize: ${(
              bodySize /
              1024 /
              1024
            ).toFixed(2)} MB`,
          );
          return { cancel: true };
        }
      }
    }

    return {};
  },
  { urls: ["<all_urls>"] },
  ["requestBody"], // Removed "blocking" - not supported in Manifest V3 without enterprise policy
);

/**
 * Monitor request headers for suspicious patterns
 */
chrome.webRequest.onBeforeSendHeaders.addListener(
  function (details) {
    if (!state.protectionEnabled) return {};

    const headers = details.requestHeaders || [];

    // Check for suspicious headers
    const suspiciousHeaders = [
      "x-forwarded-for",
      "x-originating-ip",
      "x-real-ip",
    ];

    for (const header of headers) {
      if (suspiciousHeaders.includes(header.name.toLowerCase())) {
        debug(`⚠️ Suspicious header: ${header.name} = ${header.value}`);
      }
    }

    return {};
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"], // Removed "blocking" - not supported in Manifest V3 without enterprise policy
);

// ============================================================================
// C&C SERVER DETECTION
// ============================================================================

function detectCCServer(url, domain) {
  // Check URL patterns
  for (const pattern of CONFIG.CC_SERVER_PATTERNS) {
    if (pattern.test(url)) {
      return {
        isCC: true,
        reason: `URL matches known C&C pattern: ${pattern.toString()}`,
      };
    }
  }

  // Check suspicious ports
  const port = extractPort(url);
  if (port && CONFIG.SUSPICIOUS_PORTS.includes(parseInt(port))) {
    return {
      isCC: true,
      reason: `Connection to suspicious port: ${port}`,
    };
  }

  // Check for direct IP connections
  const ipPattern = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  if (ipPattern.test(url)) {
    return {
      isCC: true,
      reason: "Direct IP connection (no domain name)",
    };
  }

  return { isCC: false };
}

// ============================================================================
// DATA EXFILTRATION HELPERS
// ============================================================================

function estimateRequestBodySize(requestBody) {
  let size = 0;

  if (requestBody.raw) {
    requestBody.raw.forEach((part) => {
      if (part.bytes) {
        size += part.bytes.byteLength;
      }
    });
  } else if (requestBody.formData) {
    Object.values(requestBody.formData).forEach((values) => {
      values.forEach((value) => {
        size += (value.length || 0) * 2; // UTF-16
      });
    });
  }

  return size;
}

// ============================================================================
// NOTIFICATION SYSTEM
// ============================================================================

function showNotification(title, message) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icon128.svg",
    title: title,
    message: message,
    priority: 2,
  });
}

// ============================================================================
// MESSAGE HANDLERS (from content scripts)
// ============================================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  debug(`Message received: ${request.action}`);

  if (request.action === "closeCurrentTab" && sender.tab) {
    chrome.tabs.remove(sender.tab.id);
    return true;
  }

  switch (request.action) {
    case "networkThreatDetected":
      handleNetworkThreat(request.report, sender);
      sendResponse({ success: true });
      break;

    case "fingerprintingDetected":
      handleFingerprintingDetection(request.data, sender);
      sendResponse({ success: true });
      break;

    case "behavioralThreatDetected":
      handleBehavioralThreat(request.data, sender);
      sendResponse({ success: true });
      break;

    case "blockConnection":
      blockConnection(request.data);
      sendResponse({ success: true });
      break;

    case "getStatistics":
      sendResponse({ statistics: state });
      break;

    case "toggleProtection":
      state.protectionEnabled = request.enabled;
      debug(`Protection ${state.protectionEnabled ? "ENABLED" : "DISABLED"}`);
      sendResponse({ success: true });
      break;

    case "checkURL":
      checkURLWithML(request.url).then((result) => {
        sendResponse({ result: result });
      });
      return true; // Keep channel open for async response

    case "getLocalApiToken":
      getLocalApiToken()
        .then((token) => sendResponse({ token }))
        .catch((error) =>
          sendResponse({ success: false, error: error.message }),
        );
      return true;

    case "refreshLocalApiToken":
      refreshLocalApiToken()
        .then((token) => sendResponse({ token }))
        .catch((error) =>
          sendResponse({ success: false, error: error.message }),
        );
      return true;

    default:
      debug(`Unknown action: ${request.action}`);
      sendResponse({ success: false, error: "Unknown action" });
  }

  return true;
});

// ============================================================================
// THREAT HANDLERS
// ============================================================================

function handleNetworkThreat(report, sender) {
  debug(`🚨 Network Threat: ${report.type}`, report);

  state.suspiciousActivity.push({
    type: report.type,
    data: report.data,
    severity: report.severity,
    url: sender.url,
    timestamp: Date.now(),
  });

  state.lastThreatDetected = Date.now();

  // Auto-block if critical
  if (report.severity === "CRITICAL") {
    const domain = extractDomain(report.data.url || sender.url);
    if (domain) {
      addToBlacklist(domain, report.type);
    }
  }
}

function handleFingerprintingDetection(data, sender) {
  debug(`🔬 Fingerprinting: ${data.type}`, data);

  state.fingerprintingDetections.push({
    type: data.type,
    data: data.data,
    severity: data.severity,
    url: sender.url,
    timestamp: Date.now(),
  });
}

function handleBehavioralThreat(data, sender) {
  debug(`🎯 Behavioral Threat: ${data.threat}`, data);

  state.behavioralAlerts.push({
    threat: data.threat,
    details: data.details,
    riskLevel: data.riskLevel,
    url: sender.url,
    timestamp: Date.now(),
  });

  // Block site if HIGH or CRITICAL risk
  if (data.riskLevel === "HIGH" || data.riskLevel === "CRITICAL") {
    const domain = extractDomain(sender.url);
    if (domain) {
      addToBlacklist(domain, `Behavioral threat: ${data.threat}`);

      showNotification(
        "Phishing Site Blocked",
        `Blocked phishing attempt: ${domain}\nThreat: ${data.threat}`,
      );

      state.phishingSitesBlocked++;
    }
  }
}

function blockConnection(data) {
  const domain = extractDomain(data.url);
  if (domain) {
    addToBlacklist(domain, "User blocked connection");
    debug(`🚫 User blocked: ${domain}`);
  }
}

// ============================================================================
// ML INTEGRATION
// ============================================================================

async function checkURLWithML(url) {
  try {
    debug(`🔍 Checking URL with ML API: ${url}`);

    // Get user's sensitivity mode from settings
    const settings = await chrome.storage.local.get(["sensitivityMode"]);
    const sensitivityMode = settings.sensitivityMode || "balanced";

    debug(`   Using sensitivity mode: ${sensitivityMode}`);

    const response = await fetchWithControlPlaneAuth(CONFIG.ML_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: url,
        sensitivity_mode: sensitivityMode,
      }),
      signal: AbortSignal.timeout(30000), // 30s timeout
    });

    if (!response.ok) {
      throw new Error(
        `ML API returned status ${response.status}: ${response.statusText}`,
      );
    }

    const result = await response.json();

    debug(`✅ ML Prediction received:`, result);

    // 📊 Log activity to user analytics (NEW)
    logUserActivity(url, {
      is_phishing: result.is_phishing,
      threat_type: result.threat_type || "unknown",
      threat_level: result.threat_level || "low",
      confidence: result.confidence,
      blocked: result.is_phishing,
      warning: false,
    }).catch((err) => debug(`⚠️ Failed to log activity: ${err.message}`));

    // Update state based on result
    if (result.is_phishing) {
      state.phishingSitesBlocked++;
      const domain = extractDomain(url);
      if (domain) {
        addToBlacklist(domain, "ML detected phishing");

        showNotification(
          "🚨 Phishing Site Detected!",
          `Blocked: ${domain}\nConfidence: ${(result.confidence * 100).toFixed(
            1,
          )}%\nThreat: ${result.threat_level}`,
        );
      }
    }

    // Update last scan time
    state.lastScanTime = Date.now();

    return result;
  } catch (error) {
    console.error("❌ ML API error:", error);
    return {
      error: error.message,
      is_phishing: false,
      confidence: 0,
      details: {
        error: true,
        message: `Failed to connect to ML API: ${error.message}`,
      },
    };
  }
}

// ============================================================================
// STORAGE SYNC
// ============================================================================

// Load state from storage on startup
chrome.storage.local.get(
  [
    "domainBlacklist",
    "ccServerBlacklist",
    "protectionEnabled",
    "statistics",
    "suspiciousActivity",
    "dataExfiltrationEvents",
    "fingerprintingDetections",
    "behavioralAlerts",
  ],
  (result) => {
    if (result.domainBlacklist) {
      state.domainBlacklist = new Set(result.domainBlacklist);
      debug(`Loaded ${state.domainBlacklist.size} blacklisted domains`);
    }

    if (result.ccServerBlacklist) {
      state.ccServerBlacklist = new Set(result.ccServerBlacklist);
      debug(`Loaded ${state.ccServerBlacklist.size} C&C servers`);
    }

    if (result.protectionEnabled !== undefined) {
      state.protectionEnabled = result.protectionEnabled;
    }

    if (result.statistics) {
      state.totalRequests = result.statistics.totalRequests || 0;
      state.blockedRequests = result.statistics.blockedRequests || 0;
      state.phishingSitesBlocked = result.statistics.phishingSitesBlocked || 0;
      state.lastScanTime = result.statistics.lastScanTime;
      state.lastThreatDetected = result.statistics.lastThreatDetected;
      debug(`Loaded statistics:`, result.statistics);
    }

    if (result.suspiciousActivity) {
      state.suspiciousActivity = result.suspiciousActivity;
    }

    if (result.dataExfiltrationEvents) {
      state.dataExfiltrationEvents = result.dataExfiltrationEvents;
    }

    if (result.fingerprintingDetections) {
      state.fingerprintingDetections = result.fingerprintingDetections;
    }

    if (result.behavioralAlerts) {
      state.behavioralAlerts = result.behavioralAlerts;
    }

    debug("✅ Complete state loaded from storage");
  },
);

// Periodic save to storage and broadcast updates
setInterval(() => {
  const statistics = {
    totalRequests: state.totalRequests,
    blockedRequests: state.blockedRequests,
    phishingSitesBlocked: state.phishingSitesBlocked,
    suspiciousActivityCount: state.suspiciousActivity.length,
    dataExfiltrationCount: state.dataExfiltrationEvents.length,
    fingerprintingCount: state.fingerprintingDetections.length,
    behavioralAlertsCount: state.behavioralAlerts.length,
    lastScanTime: state.lastScanTime,
    lastThreatDetected: state.lastThreatDetected,
  };

  chrome.storage.local.set({
    domainBlacklist: Array.from(state.domainBlacklist),
    ccServerBlacklist: Array.from(state.ccServerBlacklist),
    protectionEnabled: state.protectionEnabled,
    statistics: statistics,
    suspiciousActivity: state.suspiciousActivity.slice(-100), // Keep last 100
    dataExfiltrationEvents: state.dataExfiltrationEvents.slice(-100),
    fingerprintingDetections: state.fingerprintingDetections.slice(-50),
    behavioralAlerts: state.behavioralAlerts.slice(-50),
  });

  debug("📊 Statistics saved to storage:", statistics);
}, 10000); // Every 10 seconds for real-time updates

// ============================================================================
// INSTALLATION & INITIALIZATION
// ============================================================================

// Initialize user ID on installation
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    const userId = await getUserId();
    debug(`🎉 Extension installed! User ID: ${userId}`);

    // Initialize default settings
    await chrome.storage.local.set({
      protectionEnabled: true,
      sensitivityMode: "balanced",
      autoBlockEnabled: true,
    });

    try {
      await bootstrapControlPlaneToken(false);
      debug("🔐 Control-plane token bootstrapped on install");
    } catch (error) {
      debug(`⚠️ Control-plane bootstrap failed on install: ${error.message}`);
    }
  } else if (details.reason === "update") {
    debug(
      `🔄 Extension updated to version ${chrome.runtime.getManifest().version}`,
    );
    // Ensure user ID exists for existing users
    await getUserId();

    try {
      await bootstrapControlPlaneToken(true);
      debug("🔐 Control-plane token rotated on update");
    } catch (error) {
      debug(`⚠️ Control-plane rotation failed on update: ${error.message}`);
    }
  }
});

refreshLocalApiToken().catch((error) => {
  debug(`⚠️ Control-plane bootstrap failed at startup: ${error.message}`);
});

debug("🛡️ PhishGuard Background Service Worker initialized");
debug("Protection:", state.protectionEnabled ? "ENABLED ✅" : "DISABLED ❌");
debug("Config:", CONFIG);

// Export for debugging
globalThis.PhishGuardBackground = {
  state: state,
  config: CONFIG,
  addToBlacklist: addToBlacklist,
  checkURLWithML: checkURLWithML,
};
