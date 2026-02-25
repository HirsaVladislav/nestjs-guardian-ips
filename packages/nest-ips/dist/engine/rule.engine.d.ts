import { IpsResolvedOptions, Rule } from '../module/options';
import { LoggerPort } from '../utils/logger.interface';
import { MatchContext } from './matchers';
/** Loads and matches IPS rules from file and/or inline config. */
export declare class RuleEngine {
    private readonly options;
    private readonly logger;
    private rules;
    constructor(options: IpsResolvedOptions, logger: LoggerPort);
    /** Returns currently loaded rule set. */
    getRules(): Rule[];
    /** Returns all enabled rules matching the provided context. */
    match(ctx: MatchContext): Rule[];
    private loadRules;
    private loadRulesFromFile;
}
