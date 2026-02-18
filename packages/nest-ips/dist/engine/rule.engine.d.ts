import { IpsResolvedOptions, Rule } from '../module/options';
import { LoggerPort } from '../utils/logger.interface';
import { MatchContext } from './matchers';
export declare class RuleEngine {
    private readonly options;
    private readonly logger;
    private rules;
    constructor(options: IpsResolvedOptions, logger: LoggerPort);
    getRules(): Rule[];
    match(ctx: MatchContext): Rule[];
    private loadRules;
    private loadRulesFromFile;
}
