import { IpsProfileName } from '../module/options';
/** Snapshot used to render rate-limit headers for the current request. */
export interface IpsRateLimitSnapshot {
    limit: number;
    remaining: number;
    windowSec: number;
    resetAtSec: number;
    resetAfterSec: number;
}
/** Per-request IPS context stored on the raw HTTP request object. */
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
/** Stores IPS context on request object. */
export declare function setIpsContext(req: Record<string, unknown>, ctx: IpsHttpContext): void;
/** Reads IPS context from request object if already initialized. */
export declare function getIpsContext(req: Record<string, unknown>): IpsHttpContext | undefined;
/** Returns existing IPS context or initializes a safe fallback context. */
export declare function ensureIpsContext(req: Record<string, unknown>): IpsHttpContext;
