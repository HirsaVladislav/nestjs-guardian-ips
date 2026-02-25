import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { IpsResolvedOptions, Rule } from '../module/options';
import { LoggerPort } from '../utils/logger.interface';
import { MatchContext, matchesAll, matchesWhen } from './matchers';

/** Loads and matches IPS rules from file and/or inline config. */
export class RuleEngine {
  private rules: Rule[] = [];

  constructor(
    private readonly options: IpsResolvedOptions,
    private readonly logger: LoggerPort,
  ) {
    this.rules = this.loadRules();
  }

  /** Returns currently loaded rule set. */
  getRules(): Rule[] {
    return this.rules;
  }

  /** Returns all enabled rules matching the provided context. */
  match(ctx: MatchContext): Rule[] {
    const out: Rule[] = [];

    for (const rule of this.rules) {
      if (rule.enabled === false) {
        continue;
      }
      if (!matchesWhen(rule, ctx)) {
        continue;
      }
      if (!matchesAll(rule, ctx)) {
        continue;
      }
      out.push(rule);
    }

    return out;
  }

  private loadRules(): Rule[] {
    const source = this.options.rules;
    if (!source) {
      return [];
    }

    if (Array.isArray(source)) {
      return source;
    }

    const byFile = source.loadFrom ? this.loadRulesFromFile(source.loadFrom) : [];
    const inline = source.items ?? [];
    return [...byFile, ...inline];
  }

  private loadRulesFromFile(pathLike: string): Rule[] {
    try {
      const resolved = resolve(process.cwd(), pathLike);
      const content = readFileSync(resolved, 'utf-8');
      const parsed = JSON.parse(content);
      if (!Array.isArray(parsed)) {
        this.logger.warn('Rules file does not contain an array', { path: resolved });
        return [];
      }
      return parsed as Rule[];
    } catch (error) {
      this.logger.error('Failed to load rules file', {
        path: pathLike,
        error: (error as Error).message,
      });
      return [];
    }
  }
}
