"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.renderAlertTemplate = renderAlertTemplate;
exports.renderAlertTemplateValue = renderAlertTemplateValue;
exports.renderAlertFields = renderAlertFields;
const PLACEHOLDER_PATTERN = /{{\s*([a-zA-Z0-9_]+)\s*}}/g;
const FIELD_LABELS = {
    ts: 'ts',
    tsIso: 'timestamp',
    mode: 'mode',
    action: 'action',
    actionUpper: 'action',
    ip: 'ip',
    method: 'method',
    path: 'path',
    ua: 'ua',
    profile: 'profile',
    ruleId: 'ruleId',
    severity: 'severity',
    counts: 'counts',
    countsJson: 'counts',
    message: 'message',
};
function renderAlertTemplate(template, event) {
    if (!template) {
        return '';
    }
    return template.replace(PLACEHOLDER_PATTERN, (_, token) => {
        const value = resolveAlertToken(event, token);
        return value ?? '';
    });
}
function renderAlertTemplateValue(value, event) {
    if (typeof value === 'string') {
        return renderAlertTemplate(value, event);
    }
    if (Array.isArray(value)) {
        return value.map((item) => renderAlertTemplateValue(item, event));
    }
    if (!value || typeof value !== 'object') {
        return value;
    }
    const output = {};
    for (const [k, v] of Object.entries(value)) {
        output[k] = renderAlertTemplateValue(v, event);
    }
    return output;
}
function renderAlertFields(event, fields, separator = '\n') {
    return fields
        .map((field) => {
        const value = resolveAlertToken(event, field);
        if (!value) {
            return null;
        }
        return `${FIELD_LABELS[field]}: ${value}`;
    })
        .filter((line) => Boolean(line))
        .join(separator);
}
function resolveAlertToken(event, token) {
    if (token === 'tsIso') {
        return new Date(event.ts).toISOString();
    }
    if (token === 'actionUpper') {
        return event.action.toUpperCase();
    }
    if (token === 'countsJson') {
        return event.counts ? JSON.stringify(event.counts) : undefined;
    }
    if (token === 'counts') {
        return formatCounts(event.counts);
    }
    const key = token;
    const value = event[key];
    if (value === undefined || value === null) {
        return undefined;
    }
    if (typeof value === 'string') {
        return value.trim() || undefined;
    }
    if (typeof value === 'number') {
        return String(value);
    }
    return JSON.stringify(value);
}
function formatCounts(counts) {
    if (!counts) {
        return undefined;
    }
    const entries = Object.entries(counts);
    if (entries.length === 0) {
        return undefined;
    }
    return entries.map(([k, v]) => `${k}=${v}`).join(', ');
}
