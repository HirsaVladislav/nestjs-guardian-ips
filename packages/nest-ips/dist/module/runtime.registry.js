"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setIpsRuntime = setIpsRuntime;
exports.getIpsRuntime = getIpsRuntime;
exports.clearIpsRuntime = clearIpsRuntime;
let runtime = null;
function setIpsRuntime(next) {
    runtime = next;
}
function getIpsRuntime() {
    return runtime;
}
function clearIpsRuntime() {
    runtime = null;
}
