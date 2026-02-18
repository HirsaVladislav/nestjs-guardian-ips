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
exports.IpsNotFoundFilter = void 0;
const common_1 = require("@nestjs/common");
const runtime_1 = require("../module/runtime");
const runtime_registry_1 = require("../module/runtime.registry");
const headers_1 = require("./headers");
let IpsNotFoundFilter = class IpsNotFoundFilter {
    constructor(runtime) {
        this.runtime = runtime;
    }
    catch(exception, host) {
        if (host.getType() !== 'http') {
            throw exception;
        }
        const http = host.switchToHttp();
        const req = http.getRequest();
        const res = http.getResponse();
        const runtime = this.runtime ?? (0, runtime_registry_1.getIpsRuntime)();
        const route = req.route;
        if (!route && runtime) {
            void runtime.onRouteNotFound(req);
        }
        const payload = exception.getResponse();
        const body = typeof payload === 'string'
            ? {
                statusCode: 404,
                message: payload,
            }
            : payload;
        const headers = runtime?.getRateLimitHeaders(req);
        if (headers) {
            (0, headers_1.applyHeaders)(res, headers);
        }
        if (typeof res.status === 'function') {
            const chain = res.status(404);
            if (chain && typeof chain.json === 'function') {
                chain.json(body);
                return;
            }
        }
        if (typeof res.writeHead === 'function') {
            res.writeHead(404, {
                'content-type': 'application/json',
            });
        }
        if (typeof res.end === 'function') {
            res.end(JSON.stringify(body));
        }
    }
};
exports.IpsNotFoundFilter = IpsNotFoundFilter;
exports.IpsNotFoundFilter = IpsNotFoundFilter = __decorate([
    (0, common_1.Catch)(common_1.NotFoundException),
    __param(0, (0, common_1.Optional)()),
    __metadata("design:paramtypes", [runtime_1.IpsRuntime])
], IpsNotFoundFilter);
