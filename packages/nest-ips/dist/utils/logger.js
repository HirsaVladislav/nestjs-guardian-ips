"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IpsLogger = void 0;
class IpsLogger {
    constructor(scope = 'nest-ips') {
        this.scope = scope;
    }
    debug(message, meta) {
        this.print('DEBUG', message, meta);
    }
    info(message, meta) {
        this.print('INFO', message, meta);
    }
    warn(message, meta) {
        this.print('WARN', message, meta);
    }
    error(message, meta) {
        this.print('ERROR', message, meta);
    }
    print(level, message, meta) {
        if (meta && Object.keys(meta).length > 0) {
            // eslint-disable-next-line no-console
            console.log(`[${this.scope}] [${level}] ${message}`, meta);
            return;
        }
        // eslint-disable-next-line no-console
        console.log(`[${this.scope}] [${level}] ${message}`);
    }
}
exports.IpsLogger = IpsLogger;
