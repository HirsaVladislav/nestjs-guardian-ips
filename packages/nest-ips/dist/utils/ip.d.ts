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
export declare function getHeader(req: RequestLike, name: string): string | undefined;
export declare function extractClientIp(req: RequestLike, options: IpsResolvedOptions): string;
export declare function extractPath(req: RequestLike): string;
export declare function extractMethod(req: RequestLike): string;
export declare function stripIpv6Prefix(ip: string): string;
export declare function isIpInCidr(ip: string, cidr: string): boolean;
export {};
