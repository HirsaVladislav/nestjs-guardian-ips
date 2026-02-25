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
exports.IpsGuard = void 0;
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const decorators_1 = require("../module/decorators");
const runtime_1 = require("../module/runtime");
const runtime_registry_1 = require("../module/runtime.registry");
const headers_1 = require("./headers");
let IpsGuard = class IpsGuard {
    constructor(reflector, runtime) {
        this.reflector = reflector;
        this.runtime = runtime;
    }
    /** Runs guard-level IPS checks for HTTP requests and throws Nest HTTP exceptions on block decisions. */
    async canActivate(context) {
        if (context.getType() !== 'http') {
            return true;
        }
        const req = context.switchToHttp().getRequest();
        const res = context.switchToHttp().getResponse();
        const runtime = this.runtime ?? (0, runtime_registry_1.getIpsRuntime)();
        if (!runtime) {
            return true;
        }
        const bypass = this.reflector.getAllAndOverride(decorators_1.IPS_BYPASS_KEY, [context.getHandler(), context.getClass()]) ?? false;
        const profile = this.reflector.getAllAndOverride(decorators_1.IPS_PROFILE_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        const tags = this.reflector.getAllAndOverride(decorators_1.IPS_TAGS_KEY, [context.getHandler(), context.getClass()]) ??
            [];
        const decision = await runtime.guardCheck(req, profile, bypass, tags);
        const baselineHeaders = runtime.getRateLimitHeaders(req);
        if (baselineHeaders) {
            (0, headers_1.applyHeaders)(res, baselineHeaders);
        }
        if (decision?.headers) {
            (0, headers_1.applyHeaders)(res, decision.headers);
        }
        if (!decision?.blocked) {
            return true;
        }
        if (decision.status === 429) {
            throw new common_1.HttpException(decision.message, 429);
        }
        throw new common_1.ForbiddenException(decision.message);
    }
};
exports.IpsGuard = IpsGuard;
exports.IpsGuard = IpsGuard = __decorate([
    (0, common_1.Injectable)()
    /** Global/class/route guard that executes profile checks, CIDR policy, rules and profile rate limits. */
    ,
    __param(1, (0, common_1.Optional)()),
    __metadata("design:paramtypes", [core_1.Reflector,
        runtime_1.IpsRuntime])
], IpsGuard);
