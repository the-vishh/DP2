const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let code = fs.readFileSync(filepath, 'utf8');

// Replace the Web3Interceptor phase entirely
const web3old = /const Web3Interceptor = {[\s\S]*?Web3Interceptor\.init\(\);/m;
const web3new = `const Web3Interceptor = {
    init: function() {
      const injectCode = \`
        (function() {
           function hookWeb3(ethObj) {
               if (ethObj && ethObj.request && !ethObj._phishGuardHooked) {
                   const originalRequest = ethObj.request;
                   ethObj.request = async function(args) {
                       if (args && args.method) {
                           const method = args.method;
                           if (method === 'eth_signTypedData_v4' || method === 'eth_sendTransaction' || method === 'personal_sign') {
                               window.postMessage({
                                 type: 'PHISHGUARD_WEB3_ALERT',
                                 method: method,
                                 payload: args.params
                               }, '*');
                               throw new Error("PhishGuard Intercept: Transaction blocked by Web3 Defense Grid.");
                           }
                       }
                       return originalRequest.apply(this, arguments);
                   };
                   ethObj._phishGuardHooked = true;
               }
           }

           // Try to hook immediately
           if (window.ethereum) hookWeb3(window.ethereum);

           // Watch for window.ethereum getting defined dynamically via Object.defineProperty
           let _ethereum = window.ethereum;
           Object.defineProperty(window, 'ethereum', {
               get: function() { return _ethereum; },
               set: function(val) {
                   _ethereum = val;
                   hookWeb3(_ethereum);
               },
               configurable: true,
               enumerable: true
           });
           
           // Also interval poll just in case
           setInterval(() => {
               if (window.ethereum) hookWeb3(window.ethereum);
           }, 200);
        })();
      \`;

      const script = document.createElement('script');
      script.textContent = injectCode;
      (document.head || document.documentElement).appendChild(script);
      script.remove();

      window.addEventListener('message', (event) => {
        if (event.source !== window || !event.data || event.data.type !== 'PHISHGUARD_WEB3_ALERT') {
          return;
        }
        showInPageWarning("WEB3_WALLET_DRAINER", { method: event.data.method });
        reportSuspiciousActivity("web3_wallet_drainer", { method: event.data.method });
      });
    }
  };
  
  Web3Interceptor.init();`;

if (code.match(web3old)) {
   fs.writeFileSync(filepath, code.replace(web3old, web3new));
   console.log("Web3 patched!");
} else {
   console.log("Could not find Web3 interception logic");
}
