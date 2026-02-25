"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AlertThrottle = void 0;
/** Per-rule/IP alert throttle backed by the configured store. */
class AlertThrottle {
    constructor(store) {
        this.store = store;
    }
    /** Returns `true` when alert should be sent and stores throttle marker. */
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
