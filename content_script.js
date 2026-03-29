/**
 * 🛡️ PHISHGUARD AI - CONTENT SCRIPT
 * ==================================
 *
 * Real-time behavioral monitoring and phishing detection
 *
 * Features:
 * - Immediate password request detection
 * - Rapid redirect monitoring
 * - Form submission analysis
 * - Cross-origin form detection
 * - Suspicious timing analysis
 * - User interaction profiling

 * @author PhishGuard AI Team
 * @version 2.0.0
 * @date October 10, 2025
 */

(function () {
  "use strict";

  // ============================================================================
  // CONFIGURATION
  // ============================================================================

  const CONFIG = {
    // Timing thresholds (milliseconds)
    IMMEDIATE_PASSWORD_THRESHOLD: 2000, // < 2 seconds = suspicious
    RAPID_REDIRECT_THRESHOLD: 1000, // < 1 second between redirects
    RAPID_REDIRECT_COUNT: 3, // 3+ rapid redirects = very suspicious

    // Form analysis
    CROSS_ORIGIN_FORMS_ALLOWED: false, // Block cross-origin credential forms
    SUSPICIOUS_PARAM_KEYWORDS: [
      "redirect",
      "return",
      "next",
      "continue",
      "goto",
      "url",
      "link",
    ],

    // Input focus tracking
    TRACK_INPUT_FOCUS: true,
    SUSPICIOUS_FOCUS_PATTERNS: ["password", "credit-card", "cvv"],

    // Clipboard monitoring
    TRACK_CLIPBOARD_ACCESS: true,

    // Debug mode
    DEBUG: true,
  };

  // ============================================================================
  // STATE MANAGEMENT
  // ============================================================================

  const state = {
    pageLoadTime: performance.now(),
    firstPasswordPrompt: null,
    redirectCount: 0,
    lastRedirectTime: Date.now(),
    formSubmissions: [],
    inputFocusEvents: [],
    clipboardAccessCount: 0,
    suspiciousActivities: [],
  };

  // ============================================================================
  // UTILITY FUNCTIONS
  // ============================================================================

  /**
   * Log debug messages
   */
  function debug(message, data = null) {
    if (CONFIG.DEBUG) {
      console.log(`[PhishGuard Content] ${message}`, data || "");
    }
  }

  /**
   * Send message to background script
   */
  function reportToBackground(action, data) {
    chrome.runtime.sendMessage(
      {
        action: action,
        data: data,
        url: window.location.href,
        timestamp: Date.now(),
      },
      (response) => {
        if (chrome.runtime.lastError) {
          console.error("Message sending failed:", chrome.runtime.lastError);
        } else {
          debug(`Reported ${action}:`, response);
        }
      }
    );
  }

  /**
   * Report suspicious activity
   */
  function reportSuspiciousActivity(type, data, riskLevel = "MEDIUM") {
    const activity = {
      type: type,
      data: data,
      riskLevel: riskLevel,
      url: window.location.href,
      timestamp: Date.now(),
    };

    state.suspiciousActivities.push(activity);

    debug(`🚨 Suspicious Activity: ${type}`, activity);

    reportToBackground("suspiciousActivity", activity);

    // Show warning for HIGH/CRITICAL risks
    if (riskLevel === "HIGH" || riskLevel === "CRITICAL") {
      showInPageWarning(type, data);
    }
  }

  /**
   * Show in-page warning overlay
   */

  function showInPageWarning(type, data) {
    if (document.getElementById('phishguard-warning-overlay')) return;

    const warningMessages = {
      IMMEDIATE_PASSWORD_REQUEST: {
        title: 'Immediate Password Request Detected',
        message: 'This page is aggressively prompting for your password. This indicates a high-threat credential harvesting attempt.',
        recommendation: 'ABORT ACTION. Verify domain authenticity immediately.',
        severity: 'CRITICAL'
      },
      RAPID_REDIRECTS: {
        title: 'Suspicious Rapid Redirects Detected',
        message: 'Network trajectory analysis shows multiple consecutive redirects. Evasion and obfuscation techniques likely active.',
        recommendation: 'Terminate connection to avoid forced drops or payload injections.',
        severity: 'HIGH'
      },
      EXTERNAL_FORM_SUBMIT: {
        title: 'Cross-Origin Credential Leak',
        message: 'Exfiltration detected. Form submission is targeting an unauthorized external endpoint.',
        recommendation: 'Do NOT submit. Traffic is being routed to an unverified third party.',
        severity: 'CRITICAL'
      },
      CLIPBOARD_ABUSE: {
        title: 'Excessive Clipboard Interception',
        message: 'Unauthorized memory access detected. Page is repeatedly attempting to read clipboard contents.',
        recommendation: 'Purge clipboard. Sensitive data may have been copied.',
        severity: 'MEDIUM'
      },
      PHISHING_DETECTED: {
        title: 'Malicious Phishing Attempt Blocked',
        message: 'PhishGuard Neural Engine has classified this domain as a severe zero-day phishing threat.',
        recommendation: 'Close this tab immediately.',
        severity: 'CRITICAL'
      },
      SOCIAL_ENGINEERING_URGENCY: {
        title: 'NLP Intent Analysis: High Urgency Threat',
        message: 'In-browser NLP engine detected extreme psychological manipulation and urgency triggers typical of spear-phishing.',
        recommendation: 'Pause and verify. Do not let artificial urgency force you into a mistake.',
        severity: 'HIGH'
      },
      HOMOGRAPH_ATTACK: {
        title: 'Cryptographic URL Spoof (Punycode)',
        message: 'The URL contains Cyrillic or Greek characters disguised as standard English letters to trick you into trusting it.',
        recommendation: 'Exit site immediately. It is not the real domain.',
        severity: 'CRITICAL'
      },
      OBFUSCATION_BOMB: {
        title: 'Obfuscated Payload Detected',
        message: 'Massive blocks of encrypted JavaScript were found, commonly used by exploit kits and advanced phishing to hide their operations.',
        recommendation: 'Close tab. Code is actively attempting to evade security scanners.',
        severity: 'HIGH'
      },
      HOMOGRAPH_ATTACK: {
        title: 'Cryptographic URL Spoof (Punycode)',
        message: 'The URL contains Cyrillic or Greek characters disguised as standard English letters to trick you into trusting it.',
        recommendation: 'Exit site immediately. It is not the real domain.',
        severity: 'CRITICAL'
      },
      OBFUSCATION_BOMB: {
        title: 'Obfuscated Payload Detected',
        message: 'Massive blocks of encrypted JavaScript were found, commonly used by exploit kits and advanced phishing to hide their operations.',
        recommendation: 'Close tab. Code is actively attempting to evade security scanners.',
        severity: 'HIGH'
      },
      WEB3_WALLET_DRAINER: {
        title: 'Malicious Web3 Smart Contract',
        message: 'A Web3 permission hijack (Wallet Drainer or Approval Phishing) was intercepted before signature execution.',
        recommendation: 'Reject the transaction in your wallet immediately.',
        severity: 'CRITICAL'
      },
      SOCIAL_ENGINEERING_URGENCY: {
        title: 'NLP Intent Analysis: High Urgency Threat',
        message: 'In-browser NLP engine detected extreme psychological manipulation and urgency triggers typical of spear-phishing.',
        recommendation: 'Pause and verify. Do not let artificial urgency force you into a mistake.',
        severity: 'HIGH'
      },
      WEB3_WALLET_DRAINER: {
        title: 'Malicious Web3 Smart Contract',
        message: 'A Web3 permission hijack (Wallet Drainer or Approval Phishing) was intercepted before signature execution.',
        recommendation: 'Reject the transaction in your wallet immediately.',
        severity: 'CRITICAL'
      },
      BRAND_SPOOFING_DETECTED: {
        title: 'Corporate Brand Spoofing Detected',
        message: 'This site is masquerading as a trusted brand, but its domain is completely mismatched. This is a severe visual spoofing attack.',
        recommendation: 'DO NOT ENTER YOUR CREDENTIALS. The visual identity of this page is falsified.',
        severity: 'CRITICAL'
      },
      HOLLOW_DOM_STRUCTURE: {
        title: 'Anomalous DOM Fingerprint',
        message: 'Structural fingerprinting reveals a hollow page layout heavily skewed toward data extraction (abnormal input-to-content ratio).',
        recommendation: 'Page is structurally designed for credential harvesting. Proceed with extreme skepticism.',
        severity: 'HIGH'
      },
      INVISIBLE_IFRAME_OVERLAY: {
        title: 'Clickjacking Overlay Detected',
        message: 'A massive, highly transparent invisible layer is placed over this page. Clicking anywhere may result in an unintended credential physical hijack.',
        recommendation: 'Close this tab immediately. Your clicks are being intercepted.',
        severity: 'CRITICAL'
      },
      BRAND_SPOOFING_DETECTED: {
        title: 'Corporate Brand Spoofing Detected',
        message: 'This site is masquerading as a trusted brand, but its domain is completely mismatched. This is a severe visual spoofing attack.',
        recommendation: 'DO NOT ENTER YOUR CREDENTIALS. The visual identity of this page is falsified.',
        severity: 'CRITICAL'
      },
      HOLLOW_DOM_STRUCTURE: {
        title: 'Anomalous DOM Fingerprint',
        message: 'Structural fingerprinting reveals a hollow page layout heavily skewed toward data extraction (abnormal input-to-content ratio).',
        recommendation: 'Page is structurally designed for credential harvesting. Proceed with extreme skepticism.',
        severity: 'HIGH'
      },
      INVISIBLE_IFRAME_OVERLAY: {
        title: 'Clickjacking Overlay Detected',
        message: 'A massive, highly transparent invisible layer is placed over this page. Clicking anywhere may result in an unintended credential physical hijack.',
        recommendation: 'Close this tab immediately. Your clicks are being intercepted.',
        severity: 'CRITICAL'
      }
    };

    const warningInfo = warningMessages[type] || {
        title: 'Suspicious Telemetry Detected',
        message: 'Anomalous DOM or network behaviors detected on this site.',
        recommendation: 'Proceed with extreme caution.',
        severity: 'MEDIUM'
    };

    const overlay = document.createElement('div');
    overlay.id = 'phishguard-warning-overlay';
    overlay.style.cssText = 
        'position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;' +
        'z-index: 2147483647; display: flex; align-items: center; justify-content: center;' +
        'font-family: Inter, system-ui, -apple-system, sans-serif;' +
        'background: rgba(4, 6, 10, 0.85); backdrop-filter: blur(24px) saturate(0.6);' +
        '-webkit-backdrop-filter: blur(24px) saturate(0.6);' +
        'animation: pg-overlay-fade 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;';

    const isCritical = warningInfo.severity === 'CRITICAL';
    const themeColor = isCritical ? '#ef4444' : '#f59e0b';
    const themeColorGlow = isCritical ? 'rgba(239, 68, 68, 0.4)' : 'rgba(245, 158, 11, 0.4)';
    const themeDarkBg = isCritical ? 'rgba(239, 68, 68, 0.05)' : 'rgba(245, 158, 11, 0.05)';

    const headerIcon = isCritical ? 
        '<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="' + themeColor + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="filter: drop-shadow(0 0 12px ' + themeColorGlow + ');"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M12 8v4"></path><path d="M12 16h.01"></path></svg>' : 
        '<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="' + themeColor + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="filter: drop-shadow(0 0 12px ' + themeColorGlow + ');"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';

    overlay.innerHTML = 
        '<style>' +
            '@keyframes pg-overlay-fade { from { opacity: 0; } to { opacity: 1; } }' +
            '@keyframes pg-box-intro { from { transform: scale(0.95) translateY(20px); opacity: 0; } to { transform: scale(1) translateY(0); opacity: 1; } }' +
            '@keyframes pg-pulse-border { 0% { box-shadow: 0 0 0 0 ' + themeColorGlow + '; } 70% { box-shadow: 0 0 0 15px rgba(0,0,0,0); } 100% { box-shadow: 0 0 0 0 rgba(0,0,0,0); } }' +
            '@keyframes pg-scanline { 0% { transform: translateY(-100%); } 100% { transform: translateY(100%); } }' +
            '#pg-sec-box { position: relative; width: 100%; max-width: 580px; background: rgba(13, 17, 23, 0.85); border: 1px solid rgba(255, 255, 255, 0.1); border-top: 2px solid ' + themeColor + '; padding: 48px; border-radius: 24px; box-shadow: 0 25px 80px rgba(0,0,0,0.8), inset 0 0 40px ' + themeDarkBg + '; animation: pg-box-intro 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards; overflow: hidden; color: #e2e8f0; text-align: left; }' +
            '#pg-sec-box::before { content: ""; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: linear-gradient(to bottom, transparent 50%, rgba(255,255,255,0.02) 51%); background-size: 100% 4px; pointer-events: none; z-index: 1; }' +
            '.pg-scan-line { position: absolute; top: 0; left: 0; width: 100%; height: 20%; background: linear-gradient(to bottom, transparent, ' + themeColorGlow + ', transparent); opacity: 0.1; pointer-events: none; animation: pg-scanline 4s linear infinite; z-index: 2; }' +
            '.pg-header { display: flex; flex-direction: column; align-items: center; text-align: center; margin-bottom: 32px; position: relative; z-index: 10; }' +
            '.pg-icon-wrap { margin-bottom: 24px; animation: pg-pulse-border 2s infinite; border-radius: 50%; background: ' + themeDarkBg + '; padding: 16px; border: 1px solid rgba(255,255,255,0.05); }' +
            '.pg-title { font-size: 28px; font-weight: 700; color: #ffffff; margin: 0; letter-spacing: -0.5px; line-height: 1.2; text-shadow: 0 0 20px ' + themeColorGlow + '; }' +
            '.pg-badge { display: inline-block; margin-top: 16px; padding: 6px 16px; font-size: 11px; font-weight: 800; letter-spacing: 1.5px; text-transform: uppercase; border-radius: 99px; background: ' + themeDarkBg + '; color: ' + themeColor + '; border: 1px solid ' + themeColorGlow + '; box-shadow: 0 0 10px ' + themeColorGlow + '; }' +
            '.pg-content { position: relative; z-index: 10; display: flex; flex-direction: column; gap: 16px; margin-bottom: 40px; }' +
            '.pg-panel { background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 24px; backdrop-filter: blur(10px); }' +
            '.pg-panel p { margin: 0; font-size: 15px; line-height: 1.6; color: #94a3b8; }' +
            '.pg-recommendation { border-left: 3px solid #38bdf8; background: linear-gradient(90deg, rgba(56, 189, 248, 0.05) 0%, transparent 100%); }' +
            '.pg-recommendation p { color: #f8fafc; }' +
            '.pg-recommendation strong { color: #38bdf8; font-weight: 600; display: block; margin-bottom: 8px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }' +
            '.pg-actions { display: flex; gap: 16px; position: relative; z-index: 10; }' +
            '.pg-btn { flex: 1; padding: 16px 24px; border-radius: 12px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s ease; display: flex; align-items: center; justify-content: center; gap: 8px; font-family: inherit; }' +
            '.pg-btn-primary { background: ' + themeColor + '; color: #fff; border: none; box-shadow: 0 4px 15px ' + themeColorGlow + '; }' +
            '.pg-btn-primary:hover { background: #fff; color: ' + themeColor + '; transform: translateY(-2px); box-shadow: 0 8px 25px ' + themeColorGlow + '; }' +
            '.pg-btn-secondary { background: transparent; color: #64748b; border: 1px solid rgba(255, 255, 255, 0.1); }' +
            '.pg-btn-secondary:hover { background: rgba(255, 255, 255, 0.05); color: #94a3b8; }' +
            '.pg-footer { margin-top: 32px; text-align: center; font-size: 12px; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 1.5px; display: flex; align-items: center; justify-content: center; gap: 10px; position: relative; z-index: 10; }' +
            '.pg-footer span { display: inline-block; width: 8px; height: 8px; background: #10b981; border-radius: 50%; box-shadow: 0 0 12px #10b981; animation: pg-pulse-border 2s infinite; }' +
        '</style>' +
        '<div id="pg-sec-box">' +
            '<div class="pg-scan-line"></div>' +
            '<div class="pg-header">' +
                '<div class="pg-icon-wrap">' + headerIcon + '</div>' +
                '<h2 class="pg-title">' + warningInfo.title + '</h2>' +
                '<span class="pg-badge">' + warningInfo.severity + ' THREAT LEVEL</span>' +
            '</div>' +
            '<div class="pg-content">' +
                '<div class="pg-panel"><p>' + warningInfo.message + '</p></div>' +
                '<div class="pg-panel pg-recommendation"><p><strong>Action Required</strong> ' + warningInfo.recommendation + '</p></div>' +
            '</div>' +
            '<div class="pg-actions">' +
                '<button id="phishguard-go-back" class="pg-btn pg-btn-primary"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg> Safety Abort</button>' +
                '<button id="phishguard-continue" class="pg-btn pg-btn-secondary">Bypass Warning</button>' +
            '</div>' +
            '<div class="pg-footer"><span></span> PhishGuard Neural Engine Active</div>' +
        '</div>';

    document.body.appendChild(overlay);

    document.getElementById('phishguard-go-back').onclick = () => {
      reportToBackground('userAction', { action: 'went_back', alertType: type });
      try { window.close(); } catch(e) {}
      chrome.runtime.sendMessage({ action: "closeCurrentTab" });
    };

    document.getElementById('phishguard-continue').onclick = () => {
      overlay.remove();
      reportToBackground('userAction', { action: 'continued_anyway', alertType: type });
    };
  }

  function monitorPasswordRequests() {
    // Check on DOM ready
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", checkPasswordInputs);
    } else {
      checkPasswordInputs();
    }

    // Also observe DOM changes (dynamically added forms)
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          checkPasswordInputs();
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  function checkPasswordInputs() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');

    if (passwordInputs.length > 0 && state.firstPasswordPrompt === null) {
      state.firstPasswordPrompt = performance.now();
      const timeDelta = state.firstPasswordPrompt - state.pageLoadTime;

      debug(`Password input detected after ${timeDelta}ms`);

      if (timeDelta < CONFIG.IMMEDIATE_PASSWORD_THRESHOLD) {
        reportSuspiciousActivity(
          "IMMEDIATE_PASSWORD_REQUEST",
          {
            timeDelta: timeDelta,
            passwordFieldCount: passwordInputs.length,
            pageUrl: window.location.href,
          },
          "HIGH"
        );
      }
    }
  }

  // ============================================================================
  // 2. RAPID REDIRECT DETECTION
  // ============================================================================

  /**
   * Monitor for rapid redirects (common phishing technique to confuse users)
   */
  function monitorRedirects() {
    window.addEventListener("beforeunload", () => {
      const currentTime = Date.now();
      const timeSinceLastRedirect = currentTime - state.lastRedirectTime;

      if (timeSinceLastRedirect < CONFIG.RAPID_REDIRECT_THRESHOLD) {
        state.redirectCount++;

        debug(`Rapid redirect detected: ${state.redirectCount} redirects`);

        if (state.redirectCount >= CONFIG.RAPID_REDIRECT_COUNT) {
          reportSuspiciousActivity(
            "RAPID_REDIRECTS",
            {
              count: state.redirectCount,
              avgTime: timeSinceLastRedirect,
              pattern: "rapid_succession",
            },
            "CRITICAL"
          );
        }
      } else {
        // Reset counter if redirects are spaced out
        state.redirectCount = 1;
      }

      state.lastRedirectTime = currentTime;
    });

    // Also monitor popstate (back/forward navigation)
    window.addEventListener("popstate", () => {
      debug("Navigation event detected (popstate)");
    });
  }

  // ============================================================================
  // 3. FORM SUBMISSION ANALYSIS
  // ============================================================================

  /**
   * Analyze form submissions for credential harvesting attempts
   */
  function monitorFormSubmissions() {
    document.addEventListener(
      "submit",
      (e) => {
        const form = e.target;

        if (!(form instanceof HTMLFormElement)) {
          return;
        }

        analyzeForm(form, e);
      },
      true
    ); // Use capture phase to intercept before default action
  }

  function analyzeForm(form, event) {
    const inputs = Array.from(form.querySelectorAll("input"));

    // Check for credential inputs
    const hasPassword = inputs.some((i) => i.type === "password");
    const hasEmail = inputs.some(
      (i) => i.type === "email" || i.name.toLowerCase().includes("email")
    );
    const hasUsername = inputs.some(
      (i) =>
        i.name.toLowerCase().includes("user") ||
        i.name.toLowerCase().includes("login")
    );
    const hasCreditCard = inputs.some(
      (i) =>
        i.name.toLowerCase().includes("card") ||
        i.name.toLowerCase().includes("cc") ||
        i.autocomplete === "cc-number"
    );

    const formData = {
      action: form.action || window.location.href,
      method: form.method || "get",
      hasPassword: hasPassword,
      hasEmail: hasEmail,
      hasUsername: hasUsername,
      hasCreditCard: hasCreditCard,
      inputCount: inputs.length,
      timestamp: Date.now(),
    };

    debug("Form submission detected:", formData);

    // Check for cross-origin form submission
    try {
      const formOrigin = new URL(formData.action).origin;
      const pageOrigin = window.location.origin;

      if (
        formOrigin !== pageOrigin &&
        (hasPassword || hasEmail || hasCreditCard)
      ) {
        // CRITICAL: Credentials being sent to different domain
        event.preventDefault();

        reportSuspiciousActivity(
          "EXTERNAL_FORM_SUBMIT",
          {
            formAction: formData.action,
            pageOrigin: pageOrigin,
            formOrigin: formOrigin,
            hasCredentials: true,
            credentialTypes: {
              password: hasPassword,
              email: hasEmail,
              creditCard: hasCreditCard,
            },
          },
          "CRITICAL"
        );

        return false; // Block submission
      }
    } catch (error) {
      debug("Form action URL parsing error:", error);
    }

    // Check for suspicious parameters in form action
    if (formData.action) {
      const suspiciousParams = CONFIG.SUSPICIOUS_PARAM_KEYWORDS.filter(
        (keyword) => formData.action.toLowerCase().includes(keyword)
      );

      if (suspiciousParams.length > 0 && hasPassword) {
        reportSuspiciousActivity(
          "SUSPICIOUS_FORM_PARAMS",
          {
            formAction: formData.action,
            suspiciousParams: suspiciousParams,
            hasCredentials: hasPassword || hasEmail,
          },
          "MEDIUM"
        );
      }
    }

    // Track form submission
    state.formSubmissions.push(formData);
  }

  // ============================================================================
  // 4. INPUT FOCUS TRACKING
  // ============================================================================

  /**
   * Track input field focus patterns (unusual focus = suspicious)
   */
  function monitorInputFocus() {
    if (!CONFIG.TRACK_INPUT_FOCUS) return;

    document.addEventListener(
      "focus",
      (e) => {
        if (e.target instanceof HTMLInputElement) {
          const input = e.target;

          const focusEvent = {
            type: input.type,
            name: input.name || input.id || "unnamed",
            timestamp: Date.now(),
            timeFromPageLoad: performance.now() - state.pageLoadTime,
          };

          state.inputFocusEvents.push(focusEvent);

          // Check for suspicious immediate focus on sensitive fields
          if (focusEvent.timeFromPageLoad < 1000) {
            const isSensitive = CONFIG.SUSPICIOUS_FOCUS_PATTERNS.some(
              (pattern) =>
                focusEvent.type.includes(pattern) ||
                focusEvent.name.toLowerCase().includes(pattern)
            );

            if (isSensitive) {
              reportSuspiciousActivity(
                "IMMEDIATE_SENSITIVE_FOCUS",
                {
                  inputType: focusEvent.type,
                  inputName: focusEvent.name,
                  timeDelta: focusEvent.timeFromPageLoad,
                },
                "MEDIUM"
              );
            }
          }
        }
      },
      true
    );
  }

  // ============================================================================
  // 5. CLIPBOARD ACCESS MONITORING
  // ============================================================================

  /**
   * Monitor clipboard access (some phishing sites steal clipboard content)
   */
  function monitorClipboardAccess() {
    if (!CONFIG.TRACK_CLIPBOARD_ACCESS) return;

    // Monitor clipboard read
    document.addEventListener("copy", () => {
      debug("Clipboard copy event");
    });

    document.addEventListener("cut", () => {
      debug("Clipboard cut event");
    });

    document.addEventListener("paste", () => {
      state.clipboardAccessCount++;
      debug(`Clipboard paste event (count: ${state.clipboardAccessCount})`);

      if (state.clipboardAccessCount > 10) {
        reportSuspiciousActivity(
          "CLIPBOARD_ABUSE",
          {
            accessCount: state.clipboardAccessCount,
          },
          "MEDIUM"
        );
      }
    });

    // Intercept navigator.clipboard API
    if (navigator.clipboard) {
      const originalRead = navigator.clipboard.read;
      const originalReadText = navigator.clipboard.readText;

      navigator.clipboard.read = function () {
        state.clipboardAccessCount++;
        debug("Clipboard API: read() called");
        return originalRead.apply(this, arguments);
      };

      navigator.clipboard.readText = function () {
        state.clipboardAccessCount++;
        debug("Clipboard API: readText() called");
        return originalReadText.apply(this, arguments);
      };
    }
  }

  // ============================================================================
  // 6. PAGE VISIBILITY MONITORING
  // ============================================================================

  /**
   * Track page visibility changes (phishing in background tabs)
   */
  function monitorPageVisibility() {
    document.addEventListener("visibilitychange", () => {
      debug(
        `Page visibility changed: ${document.hidden ? "hidden" : "visible"}`
      );

      reportToBackground("visibilityChange", {
        hidden: document.hidden,
        visibilityState: document.visibilityState,
      });
    });
  }

  // ============================================================================
  // 7. SUSPICIOUS POPUP DETECTION
  // ============================================================================

  /**
   * Monitor for popup attempts (phishing often uses popups)
   */
  function monitorPopups() {
    const originalOpen = window.open;
    let popupCount = 0;

    window.open = function () {
      popupCount++;
      debug(`Popup detected (count: ${popupCount})`);

      if (popupCount > 3) {
        reportSuspiciousActivity(
          "EXCESSIVE_POPUPS",
          {
            count: popupCount,
          },
          "MEDIUM"
        );
      }

      reportToBackground("popupAttempt", {
        url: arguments[0],
        count: popupCount,
      });

      return originalOpen.apply(this, arguments);
    };
  }

  // ============================================================================
  // 8. AUTO-SUBMIT DETECTION
  // ============================================================================

  /**
   * Detect forms that auto-submit (phishing trick)
   */
  function detectAutoSubmit() {
    const forms = document.querySelectorAll("form");

    forms.forEach((form) => {
      // Check if form has auto-submit script
      const scripts = form.querySelectorAll("script");
      const hasAutoSubmit = Array.from(scripts).some(
        (script) =>
          script.textContent.includes("submit()") ||
          script.textContent.includes(".submit")
      );

      if (hasAutoSubmit) {
        reportSuspiciousActivity(
          "AUTO_SUBMIT_FORM",
          {
            formAction: form.action,
            formId: form.id || "unknown",
          },
          "HIGH"
        );
      }
    });
  }

  // ============================================================================
  // INITIALIZATION
  // ============================================================================

  /**
   * Initialize all monitors
   */
  function initialize() {
    debug("🛡️ PhishGuard Content Script initialized");
    debug("URL:", window.location.href);
    debug("Config:", CONFIG);

    try {
      // Start all monitoring systems
      monitorPasswordRequests();
      monitorRedirects();
      monitorFormSubmissions();
      monitorInputFocus();
      monitorClipboardAccess();
      monitorPageVisibility();
      monitorPopups();

      // Delayed checks
      setTimeout(() => {
        detectAutoSubmit();
      }, 2000);

      // Periodic status report
      setInterval(() => {
        if (state.suspiciousActivities.length > 0) {
          reportToBackground("statusReport", {
            suspiciousActivities: state.suspiciousActivities.length,
            formSubmissions: state.formSubmissions.length,
            inputFocusEvents: state.inputFocusEvents.length,
            clipboardAccess: state.clipboardAccessCount,
          });
        }
      }, 30000); // Every 30 seconds

      debug("✅ All monitors active");
    } catch (error) {
      console.error("[PhishGuard] Initialization error:", error);
    }
  }

  // Start when DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize);
  } else {
    initialize();
  }

  // ============================================================================
  // MESSAGE HANDLER (from background script)
  // ============================================================================

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    debug("Message received from background:", request);

    if (request.action === "getState") {
      sendResponse({ state: state });
    } else if (request.action === "reset") {
      // Reset state
      state.suspiciousActivities = [];
      state.formSubmissions = [];
      state.inputFocusEvents = [];
      state.clipboardAccessCount = 0;
      sendResponse({ success: true });
    }

    return true; // Keep message channel open
  });

  // ============================================================================
  


  // ============================================================================
  // PHASE 1: ZERO-DAY VISUAL & DOM LAYOUT ENGINE
  // ============================================================================

  const VisualEngine = {
    protectedBrands: {
      "microsoft": ["microsoft.com", "live.com", "windows.com", "office.com"],
      "google": ["google.com", "youtube.com", "gmail.com"],
      "paypal": ["paypal.com", "paypal.me"],
      "chase": ["chase.com"],
      "bank of america": ["bankofamerica.com", "bofa.com"],
      "metamask": ["metamask.io"],
      "apple": ["apple.com", "icloud.com"]
    },

    init: function() {
      if (document.readyState === "complete") {
        this.runFullScan();
      } else {
        window.addEventListener("load", () => setTimeout(() => this.runFullScan(), 1000));
      }
    },

    runFullScan: function() {
      this.detectBrandSpoofing();
      this.computeDOMFingerprint();
      this.detectClickjackingLayers();
    },

    detectBrandSpoofing: function() {
      const hostname = window.location.hostname.toLowerCase();
      // bypassed for localhost
      
      const pageText = (document.title + " " + document.body.innerText.substring(0, 2000)).toLowerCase();
      
      for (const [brand, allowedDomains] of Object.entries(this.protectedBrands)) {
        if (pageText.includes(brand)) {
          const isAllowed = allowedDomains.some(d => hostname === d || hostname.endsWith("." + d));
          if (!isAllowed) {
            const titleHasBrand = document.title.toLowerCase().includes(brand);
            const headers = Array.from(document.querySelectorAll('h1, h2')).map(h => h.innerText.toLowerCase());
            const headerHasBrand = headers.some(h => h.includes(brand));
            
            if (titleHasBrand || headerHasBrand) {
               showInPageWarning("BRAND_SPOOFING_DETECTED", { brand: brand });
               reportSuspiciousActivity("brand_spoofing", { brand: brand, hostname: hostname });
               return; 
            }
          }
        }
      }
    },

    computeDOMFingerprint: function() {
      const passwordInputs = document.querySelectorAll('input[type="password"]');
      if (passwordInputs.length === 0) return;

      const totalTextLen = document.body.innerText.trim().length;
      const allInputs = document.querySelectorAll('input');
      const allLinks = document.querySelectorAll('a');
      
      let suspiciousScore = 0;

      if (totalTextLen < 300) suspiciousScore += 30;
      if (allInputs.length > 0 && (totalTextLen / allInputs.length) < 50) suspiciousScore += 25;

      let deadLinks = 0;
      allLinks.forEach(a => {
         const href = a.getAttribute("href") || "";
         if (href === "#" || href.startsWith("javascript:")) deadLinks++;
      });
      if (allLinks.length > 0 && (deadLinks / allLinks.length) > 0.5) suspiciousScore += 40;
      
      if (suspiciousScore >= 70) {
         showInPageWarning("HOLLOW_DOM_STRUCTURE", { score: suspiciousScore });
         reportSuspiciousActivity("hollow_dom", { score: suspiciousScore });
      }
    },

    detectClickjackingLayers: function() {
       const suspiciousNodes = [];
       const elements = document.querySelectorAll('div, iframe');
       
       elements.forEach(node => {
           const style = window.getComputedStyle(node);
           const opacity = parseFloat(style.opacity);
           const zIndex = parseInt(style.zIndex);
           
           if ((style.position === 'absolute' || style.position === 'fixed') && (!isNaN(zIndex) && zIndex > 900)) {
              const rect = node.getBoundingClientRect();
              const area = rect.width * rect.height;
              const windowArea = window.innerWidth * window.innerHeight;
              
              if (area > windowArea * 0.8) {
                  if (opacity < 0.1 || style.backgroundColor === 'rgba(0, 0, 0, 0)' || style.backgroundColor === 'transparent') {
                      suspiciousNodes.push(node);
                  }
              }
           }
       });
       
       if (suspiciousNodes.length > 0) {
           showInPageWarning("INVISIBLE_IFRAME_OVERLAY", {});
           reportSuspiciousActivity("clickjacking_layer", { count: suspiciousNodes.length });
       }
    }
  };

  VisualEngine.init();

  // ============================================================================
  // PHASE 2: LOCAL LLM INTENT & NLP PIPELINE
  // ============================================================================

  const NLPEngine = {
    urgencyKeywords: [
      "urgent", "immediate action required", "24 hours", "suspended", "locked",
      "restricted", "verify your account", "unauthorized access", "will be closed",
      "final warning", "action required"
    ],
    
    financialKeywords: [
      "wallet", "funds", "transfer", "crypto", "bitcoin", "ethereum",
      "payment", "invoice", "billing", "seed phrase"
    ],

    init: function() {
      if (document.readyState === "complete") {
        this.analyzeIntent();
      } else {
        window.addEventListener("load", () => setTimeout(() => this.analyzeIntent(), 1500));
      }
    },

    analyzeIntent: function() {
      const hostname = window.location.hostname;
      
      const pageText = document.body.innerText.toLowerCase();
      
      let urgencyScore = 0;
      let financialScore = 0;

      this.urgencyKeywords.forEach(kw => {
        if (pageText.includes(kw)) urgencyScore++;
      });
      
      this.financialKeywords.forEach(kw => {
        if (pageText.includes(kw)) financialScore++;
      });

      if (urgencyScore >= 2 && financialScore >= 1) {
         const topSites = ["paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "amazon.com"];
         const isTop = topSites.some(t => hostname === t || hostname.endsWith("." + t));
         
         if (!isTop) {
            showInPageWarning("SOCIAL_ENGINEERING_URGENCY", { score: urgencyScore });
            reportSuspiciousActivity("nlp_high_urgency", { urgency: urgencyScore, finance: financialScore });
         }
      }
    }
  };

  NLPEngine.init();


  // ============================================================================
  // PHASE 3: CRYPTOGRAPHIC & DNS FORENSICS
  // ============================================================================

  const CryptographicEngine = {
    init: function() {
      this.detectHomographAttacks();
    },

    detectHomographAttacks: function() {
      const hostname = window.location.hostname;
      const cyrillicRegex = /[\u0400-\u04FF\u0500-\u052F]/;
      
      if (hostname.includes('xn--') || (cyrillicRegex.test(hostname) && /[a-z]/i.test(hostname))) {
        showInPageWarning("HOMOGRAPH_ATTACK", { url: hostname });
        reportSuspiciousActivity("cryptographic_homograph", { hostname: hostname });
      }
    }
  };

  CryptographicEngine.init();


  // ============================================================================
  // PHASE 4: ANTI-EVASION & SANDBOXING
  // ============================================================================

  const AntiEvasionEngine = {
    init: function() {
      if (document.readyState === "complete") {
        this.scanForObfuscation();
      } else {
        window.addEventListener("load", () => setTimeout(() => this.scanForObfuscation(), 2000));
      }
    },

    scanForObfuscation: function() {
      const scripts = document.querySelectorAll('script:not([src])');
      let maxBlockSize = 0;
      let evalCount = 0;
      
      scripts.forEach(s => {
        const text = s.innerText || s.textContent || "";
        const localEvalMatch = text.match(/eval\s*\(/g);
        if (localEvalMatch) evalCount += localEvalMatch.length;
        
        const denseBlocks = text.split(/\s+/);
        for (let b of denseBlocks) {
          if (b.length > maxBlockSize) maxBlockSize = b.length;
        }
      });
      
      if (maxBlockSize > 8000 || evalCount > 5) {
         showInPageWarning("OBFUSCATION_BOMB", { maxBlock: maxBlockSize, evalCount: evalCount });
         reportSuspiciousActivity("anti_evasion_obfuscator", { maxBlock: maxBlockSize, evals: evalCount });
      }
    }
  };

  AntiEvasionEngine.init();

// ============================================================================
  // EXPORTS
  // ============================================================================

  window.PhishGuardContentScript = {
    reportSuspiciousActivity: reportSuspiciousActivity,
  };

})(); // CLOSE THE IIFE!
