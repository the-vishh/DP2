  /**
   * Show in-page warning overlay
   */
  function showInPageWarning(type, data) {
    // Prevent multiple overlays
    if (document.getElementById("phishguard-warning-overlay")) {
      return;
    }

    const warningMessages = {
      IMMEDIATE_PASSWORD_REQUEST: {
        title: "⚠️ Immediate Password Request Detected",
        message:
          "This page is asking for your password unusually quickly. This is a common phishing technique.",
        recommendation:
          "Verify the website URL carefully before entering any credentials.",
      },
      RAPID_REDIRECTS: {
        title: "🔄 Rapid Redirects Detected",
        message: `This page has redirected ${data.count} times in rapid succession. This is suspicious behavior.`,
        recommendation:
          "Close this tab and avoid entering any personal information.",
      },
      EXTERNAL_FORM_SUBMIT: {
        title: "🚫 Cross-Origin Form Submission",
        message: `This form is submitting your data to a different website: ${data.formOrigin}`,
        recommendation:
          "This is highly suspicious. Do not submit credentials to external sites.",
      },
      CLIPBOARD_ABUSE: {
        title: "📋 Excessive Clipboard Access",
        message: "This page is trying to access your clipboard repeatedly.",
        recommendation:
          "Your clipboard may contain sensitive information. Be cautious.",
      },
    };

    const warningInfo = warningMessages[type] || {
      title: "⚠️ Suspicious Activity Detected",
      message: "This page is exhibiting suspicious behavior.",
      recommendation: "Proceed with caution.",
    };

    const overlay = document.createElement("div");
    overlay.id = "phishguard-warning-overlay";
    overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            animation: fadeIn 0.3s ease-in;
        `;

    overlay.innerHTML = `
            <style>
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                @keyframes slideIn {
                    from { transform: translateY(-20px); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }
                #phishguard-warning-box {
                    animation: slideIn 0.4s ease-out;
                }
            </style>
            <div id="phishguard-warning-box" style="
                background: white;
                padding: 40px;
                border-radius: 16px;
                max-width: 600px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            ">
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="font-size: 64px; margin-bottom: 10px;">${
                      warningInfo.title.split(" ")[0]
                    }</div>
                    <h2 style="margin: 0; color: #dc2626; font-size: 24px;">${warningInfo.title.substring(
                      2
                    )}</h2>
                </div>

                <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 16px; margin-bottom: 20px; border-radius: 4px;">
                    <p style="margin: 0; color: #991b1b; font-size: 16px; line-height: 1.5;">
                        ${warningInfo.message}
                    </p>
                </div>

                <div style="background: #f0fdf4; border-left: 4px solid #16a34a; padding: 16px; margin-bottom: 30px; border-radius: 4px;">
                    <p style="margin: 0; color: #166534; font-size: 14px; line-height: 1.5;">
                        <strong>💡 Recommendation:</strong> ${
                          warningInfo.recommendation
                        }
                    </p>
                </div>

                <div style="display: flex; gap: 12px; justify-content: center;">
                    <button id="phishguard-go-back" style="
                        padding: 12px 24px;
                        background: #dc2626;
                        color: white;
                        border: none;
                        border-radius: 8px;
                        font-size: 16px;
                        font-weight: 600;
                        cursor: pointer;
                        transition: background 0.2s;
                    " onmouseover="this.style.background='#b91c1c'" onmouseout="this.style.background='#dc2626'">
                        🛡️ Go Back (Recommended)
                    </button>
                    <button id="phishguard-continue" style="
                        padding: 12px 24px;
                        background: #6b7280;
                        color: white;
                        border: none;
                        border-radius: 8px;
                        font-size: 16px;
                        font-weight: 600;
                        cursor: pointer;
                        transition: background 0.2s;
                    " onmouseover="this.style.background='#4b5563'" onmouseout="this.style.background='#6b7280'">
                        Continue Anyway
                    </button>
                </div>

                <div style="margin-top: 20px; text-align: center; font-size: 12px; color: #6b7280;">
                    Protected by PhishGuard AI
                </div>
            </div>
        `;

    document.body.appendChild(overlay);

    // Button handlers
    document.getElementById("phishguard-go-back").onclick = () => {
      overlay.remove();
      reportToBackground("userAction", {
        action: "went_back",
        alertType: type,
      });
      window.history.back();
    };

    document.getElementById("phishguard-continue").onclick = () => {
      overlay.remove();
      reportToBackground("userAction", {
        action: "continued_anyway",
        alertType: type,
      });
