const fs = require('fs');
const filePath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let c = fs.readFileSync(filePath, 'utf8');

const targetStr = `      PHISHING_DETECTED: {
        title: 'Malicious Phishing Attempt Blocked',
        message: 'PhishGuard Neural Engine has classified this domain as a severe zero-day phishing threat.',
        recommendation: 'Close this tab immediately.',
        severity: 'CRITICAL'
      }`;

const insertionStr = `      PHISHING_DETECTED: {
        title: 'Malicious Phishing Attempt Blocked',
        message: 'PhishGuard Neural Engine has classified this domain as a severe zero-day phishing threat.',
        recommendation: 'Close this tab immediately.',
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
      }`;

if (c.includes(targetStr)) {
    c = c.replace(targetStr, insertionStr);
    fs.writeFileSync(filePath, c);
    console.log('Successfully added new warnings!');
} else {
    console.log('Failed to find target string in content_script.js');
}
