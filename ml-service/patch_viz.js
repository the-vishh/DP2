const fs = require('fs');
const filePath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let c = fs.readFileSync(filePath, 'utf8');

const anchor = '  // ============================================================================';
const exportAnchor = '  window.PhishGuardContentScript = {';

const insertIdx = c.lastIndexOf(exportAnchor);
if (insertIdx > -1) {
    const visualEngineCode = `
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
      if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "") return;

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
               reportSuspiciousActivity("brand_spoofing", {
                   brand: brand,
                   hostname: hostname
               });
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

`;
    const finalContent = c.substring(0, insertIdx) + visualEngineCode + c.substring(insertIdx);
    fs.writeFileSync(filePath, finalContent);
    console.log("Successfully injected Phase 1 Visual Engine!");
} else {
    console.log("Failed to find anchor.");
}
