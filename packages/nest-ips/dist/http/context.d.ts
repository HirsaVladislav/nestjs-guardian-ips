import { IpsProfileName } from '../module/options';
export interface IpsRateLimitSnapshot {
    limit: number;
    remaining: number;
    windowSec: number;
    resetAtSec: number;
    resetAfterSec: number;
}
export interface IpsHttpContext {
    ip: string;
    ua: string;
    method: string;
    path: string;
    requestId: string;
    profile: IpsProfileName;
    userId?: string;
    email?: string;
    username?: string;
    tags?: string[];
    rateLimit?: IpsRateLimitSnapshot;
}
export declare function setIpsContext(req: Record<string, unknown>, ctx: IpsHttpContext): void;
export declare function getIpsContext(req: Record<string, unknown>): IpsHttpContext | undefined;
export declare function ensureIpsContext(req: Record<string, unknown>): IpsHttpContext;
