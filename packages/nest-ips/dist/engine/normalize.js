"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.applyNormalization = applyNormalization;
function applyNormalization(input, steps = []) {
    let value = input;
    for (const step of steps) {
        if (step === 'lowercase') {
            value = value.toLowerCase();
            continue;
        }
        if (step === 'urlDecode') {
            try {
                value = decodeURIComponent(value);
            }
            catch {
                // Keep original value when URI sequence is invalid.
            }
            continue;
        }
        if (step === 'normalizePath') {
            value = normalizePathValue(value);
        }
    }
    return value;
}
function normalizePathValue(path) {
    const noQuery = path.split('?')[0] ?? path;
    const compact = noQuery.replace(/\/{2,}/g, '/');
    const clean = compact.replace(/\/.\//g, '/');
    return clean || '/';
}
