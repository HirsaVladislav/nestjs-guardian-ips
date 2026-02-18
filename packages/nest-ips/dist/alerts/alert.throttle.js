"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AlertThrottle = void 0;
class AlertThrottle {
    constructor(store) {
        this.store = store;
    }
    async shouldSend(ruleId, ip, throttleSec) {
        const key = `alert:${ruleId}:${ip}`;
        const hit = await this.store.get(key);
        if (hit) {
            return false;
        }
        await this.store.set(key, '1', throttleSec);
        return true;
    }
}
exports.AlertThrottle = AlertThrottle;
