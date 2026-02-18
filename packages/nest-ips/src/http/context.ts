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

const IPS_HTTP_CONTEXT_KEY = Symbol.for('nest-ips:http-context');

export function setIpsContext(req: Record<string, unknown>, ctx: IpsHttpContext): void {
  (req as Record<symbol, unknown>)[IPS_HTTP_CONTEXT_KEY] = ctx;
}

export function getIpsContext(req: Record<string, unknown>): IpsHttpContext | undefined {
  return (req as Record<symbol, unknown>)[IPS_HTTP_CONTEXT_KEY] as IpsHttpContext | undefined;
}

export function ensureIpsContext(req: Record<string, unknown>): IpsHttpContext {
  const existing = getIpsContext(req);
  if (existing) {
    return existing;
  }

  const fallback: IpsHttpContext = {
    ip: '0.0.0.0',
    ua: 'unknown',
    method: 'GET',
    path: '/',
    requestId: 'n/a',
    profile: 'default',
  };
  setIpsContext(req, fallback);
  return fallback;
}
