"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RuleEngine = void 0;
const node_fs_1 = require("node:fs");
const node_path_1 = require("node:path");
const matchers_1 = require("./matchers");
/** Loads and matches IPS rules from file and/or inline config. */
class RuleEngine {
    constructor(options, logger) {
        this.options = options;
        this.logger = logger;
        this.rules = [];
        this.rules = this.loadRules();
    }
    /** Returns currently loaded rule set. */
    getRules() {
        return this.rules;
    }
    /** Returns all enabled rules matching the provided context. */
    match(ctx) {
        const out = [];
        for (const rule of this.rules) {
            if (rule.enabled === false) {
                continue;
            }
            if (!(0, matchers_1.matchesWhen)(rule, ctx)) {
                continue;
            }
            if (!(0, matchers_1.matchesAll)(rule, ctx)) {
                continue;
            }
            out.push(rule);
        }
        return out;
    }
    loadRules() {
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
    loadRulesFromFile(pathLike) {
        try {
            const resolved = (0, node_path_1.resolve)(process.cwd(), pathLike);
            const content = (0, node_fs_1.readFileSync)(resolved, 'utf-8');
            const parsed = JSON.parse(content);
            if (!Array.isArray(parsed)) {
                this.logger.warn('Rules file does not contain an array', { path: resolved });
                return [];
            }
            return parsed;
        }
        catch (error) {
            this.logger.error('Failed to load rules file', {
                path: pathLike,
                error: error.message,
            });
            return [];
        }
    }
}
exports.RuleEngine = RuleEngine;
