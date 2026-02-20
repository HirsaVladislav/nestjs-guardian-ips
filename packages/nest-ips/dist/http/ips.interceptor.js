"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.IpsInterceptor = void 0;
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const rxjs_1 = require("rxjs");
const operators_1 = require("rxjs/operators");
const decorators_1 = require("../module/decorators");
const runtime_1 = require("../module/runtime");
const runtime_registry_1 = require("../module/runtime.registry");
let IpsInterceptor = class IpsInterceptor {
    constructor(runtime, reflector) {
        this.runtime = runtime;
        this.reflector = reflector;
    }
    async intercept(context, next) {
        if (context.getType() !== 'http') {
            return next.handle();
        }
        const bypass = this.reflector?.getAllAndOverride(decorators_1.IPS_BYPASS_KEY, [context.getHandler(), context.getClass()]) ?? false;
        if (bypass) {
            return next.handle();
        }
        const req = context.switchToHttp().getRequest();
        const runtime = this.runtime ?? (0, runtime_registry_1.getIpsRuntime)();
        if (runtime) {
            await runtime.onBeforeHandler(req);
        }
        return next.handle().pipe((0, operators_1.catchError)((error) => {
            if (runtime) {
                const status = extractStatus(error);
                void runtime.onError(req, status);
            }
            return (0, rxjs_1.throwError)(() => error);
        }));
    }
};
exports.IpsInterceptor = IpsInterceptor;
exports.IpsInterceptor = IpsInterceptor = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Optional)()),
    __param(1, (0, common_1.Optional)()),
    __metadata("design:paramtypes", [runtime_1.IpsRuntime,
        core_1.Reflector])
], IpsInterceptor);
function extractStatus(error) {
    if (!error || typeof error !== 'object') {
        return 500;
    }
    const status = error.status;
    if (typeof status === 'number') {
        return status;
    }
    const statusCode = error.statusCode;
    if (typeof statusCode === 'number') {
        return statusCode;
    }
    const getStatus = error.getStatus;
    if (typeof getStatus === 'function') {
        return getStatus();
    }
    return 500;
}
