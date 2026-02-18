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
var IpsModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.IpsModule = void 0;
const common_1 = require("@nestjs/common");
const ips_tokens_1 = require("./ips.tokens");
const runtime_registry_1 = require("./runtime.registry");
const runtime_1 = require("./runtime");
let IpsModule = IpsModule_1 = class IpsModule {
    constructor(runtime) {
        this.runtime = runtime;
    }
    static forRoot(options = {}) {
        return {
            module: IpsModule_1,
            providers: [
                {
                    provide: ips_tokens_1.IPS_OPTIONS,
                    useValue: options,
                },
                {
                    provide: runtime_1.IpsRuntime,
                    useFactory: (input) => new runtime_1.IpsRuntime(input),
                    inject: [ips_tokens_1.IPS_OPTIONS],
                },
            ],
            exports: [runtime_1.IpsRuntime],
            global: true,
        };
    }
    async onModuleInit() {
        await this.runtime.startup();
        (0, runtime_registry_1.setIpsRuntime)(this.runtime);
    }
    async onModuleDestroy() {
        await this.runtime.shutdown();
        (0, runtime_registry_1.clearIpsRuntime)();
    }
};
exports.IpsModule = IpsModule;
exports.IpsModule = IpsModule = IpsModule_1 = __decorate([
    (0, common_1.Global)(),
    (0, common_1.Module)({}),
    __metadata("design:paramtypes", [runtime_1.IpsRuntime])
], IpsModule);
