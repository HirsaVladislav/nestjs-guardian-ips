import { Rule } from '../module/options';
/** Rule matching context built from normalized request data. */
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
/** Evaluates `rule.when` preconditions (method/profile/path gates). */
export declare function matchesWhen(rule: Rule, ctx: MatchContext): boolean;
/** Evaluates all `rule.match` clauses against the request context. */
export declare function matchesAll(rule: Rule, ctx: MatchContext): boolean;
