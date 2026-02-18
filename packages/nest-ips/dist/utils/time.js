"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.nowMs = nowMs;
exports.nowSec = nowSec;
function nowMs() {
    return Date.now();
}
function nowSec() {
    return Math.floor(Date.now() / 1000);
}
