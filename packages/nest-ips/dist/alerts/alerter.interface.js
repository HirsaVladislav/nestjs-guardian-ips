"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MultiAlerter = void 0;
/** Fan-out alerter that dispatches one event to multiple channels. */
class MultiAlerter {
    constructor(alerters) {
        this.alerters = alerters;
    }
    async send(event) {
        const results = await Promise.allSettled(this.alerters.map((alerter) => alerter.send(event)));
        const succeeded = results.some((result) => result.status === 'fulfilled');
        if (succeeded) {
            return;
        }
        const reasons = results
            .filter((result) => result.status === 'rejected')
            .map((result) => result.reason);
        throw new AggregateError(reasons, '[nest-ips] All alert channels failed');
    }
}
exports.MultiAlerter = MultiAlerter;
