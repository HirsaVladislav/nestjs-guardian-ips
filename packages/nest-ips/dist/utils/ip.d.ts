import { IpsResolvedOptions } from '../module/options';
interface RequestLike {
    headers?: Record<string, string | string[] | undefined>;
    ip?: string;
    ips?: string[];
    socket?: {
        remoteAddress?: string;
    };
    connection?: {
        remoteAddress?: string;
    };
    method?: string;
    path?: string;
    originalUrl?: string;
    url?: string;
}
/** Reads a request header by name using case-insensitive lookup. */
export declare function getHeader(req: RequestLike, name: string): string | undefined;
/** Resolves client IP according to configured trust model (`strict` or `hops`). */
export declare function extractClientIp(req: RequestLike, options: IpsResolvedOptions): string;
/** Extracts request path without query string. */
export declare function extractPath(req: RequestLike): string;
/** Extracts uppercase HTTP method with `GET` fallback. */
export declare function extractMethod(req: RequestLike): string;
/** Converts IPv4-mapped IPv6 format (`::ffff:x.x.x.x`) to plain IPv4 string. */
export declare function stripIpv6Prefix(ip: string): string;
/** Checks whether an IP belongs to CIDR (or equals a plain IP string). */
export declare function isIpInCidr(ip: string, cidr: string): boolean;
export {};
