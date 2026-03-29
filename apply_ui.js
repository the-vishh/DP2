const fs = require("fs");
const code = `
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
      overlay.remove();
      reportToBackground('userAction', { action: 'went_back', alertType: type });
      window.history.back();
    };

    document.getElementById('phishguard-continue').onclick = () => {
      overlay.remove();
      reportToBackground('userAction', { action: 'continued_anyway', alertType: type });
    };
  }
`;
const c = fs.readFileSync(
  "c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js",
  "utf8",
);
const p1 = c.indexOf("  function showInPageWarning(type, data) {");
const p2 = c.indexOf("  function monitorPasswordRequests() {");
if (p1 > -1 && p2 > -1) {
  fs.writeFileSync(
    "c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js",
    c.substring(0, p1) + code + "\n" + c.substring(p2),
  );
  console.log("Successfully injected crazy UI!");
} else {
  console.log("Failed to find indices", p1, p2);
}
