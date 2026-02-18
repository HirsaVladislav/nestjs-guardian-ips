import { Rule } from '../module/options';
export interface MatchContext {
    ip: string;
    path: string;
    ua: string;
    method: string;
    profile: string;
    headers: Record<string, unknown>;
    query: Record<string, unknown>;
    body?: unknown;
}
export declare function matchesWhen(rule: Rule, ctx: MatchContext): boolean;
export declare function matchesAll(rule: Rule, ctx: MatchContext): boolean;
