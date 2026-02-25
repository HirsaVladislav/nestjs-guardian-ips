"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setIpsRuntime = setIpsRuntime;
exports.getIpsRuntime = getIpsRuntime;
exports.clearIpsRuntime = clearIpsRuntime;
let runtime = null;
/** Stores module-created runtime for access from middleware/filter instances created outside DI. */
function setIpsRuntime(next) {
    runtime = next;
}
/** Returns shared runtime instance registered by `IpsModule`, if available. */
function getIpsRuntime() {
    return runtime;
}
/** Clears shared runtime reference during module shutdown. */
function clearIpsRuntime() {
    runtime = null;
}
