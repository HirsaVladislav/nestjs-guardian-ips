"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MultiAlerter = void 0;
class MultiAlerter {
    constructor(alerters) {
        this.alerters = alerters;
    }
    async send(event) {
        await Promise.allSettled(this.alerters.map((alerter) => alerter.send(event)));
    }
}
exports.MultiAlerter = MultiAlerter;
