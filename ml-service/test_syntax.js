const dom = {};
const window = {};

let _ethereum;
Object.defineProperty(window, 'ethereum', {
    get: function() { return _ethereum; },
    set: function(val) {
        console.log("Setter called with", val);
        _ethereum = val;
    },
    configurable: true,
    enumerable: true
});

window.ethereum = { request: () => "hi" };
console.log(window.ethereum.request());
