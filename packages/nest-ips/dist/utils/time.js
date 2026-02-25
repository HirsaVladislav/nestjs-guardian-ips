"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nowMs = nowMs;
exports.nowSec = nowSec;
/** Returns current timestamp in milliseconds. */
function nowMs() {
    return Date.now();
}
/** Returns current UNIX timestamp in seconds. */
function nowSec() {
    return Math.floor(Date.now() / 1000);
}
