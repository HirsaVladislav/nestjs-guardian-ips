"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SlackWebhookAlerter = void 0;
const node_https_1 = require("node:https");
const template_renderer_1 = require("./template.renderer");
const DEFAULT_SLACK_TIMEOUT_MS = 5000;
const DEFAULT_SLACK_FIELDS = [
    'actionUpper',
    'mode',
    'ip',
    'method',
    'path',
    'ruleId',
    'severity',
    'message',
];
/** Slack webhook alerter with text or payload-template rendering support. */
class SlackWebhookAlerter {
    constructor(config) {
        if (typeof config === 'string') {
            this.webhookUrl = config;
            this.fields = DEFAULT_SLACK_FIELDS;
            this.payloadIncludeText = true;
            return;
        }
        this.webhookUrl = config.webhookUrl;
        this.template = config.template;
        this.fields = config.fields ?? DEFAULT_SLACK_FIELDS;
        this.payloadTemplate = config.payloadTemplate;
        this.payloadIncludeText = config.payloadIncludeText ?? true;
    }
    /** Sends alert event to Slack Incoming Webhook endpoint. */
    async send(event) {
        if (!this.webhookUrl) {
            return;
        }
        const text = this.renderText(event);
        const payload = this.renderPayload(event, text);
        const body = JSON.stringify(payload);
        await new Promise((resolve, reject) => {
            const url = new URL(this.webhookUrl);
            const req = (0, node_https_1.request)({
                method: 'POST',
                hostname: url.hostname,
                path: `${url.pathname}${url.search}`,
                port: url.port || 443,
                headers: {
                    'content-type': 'application/json',
                    'content-length': Buffer.byteLength(body),
                },
            }, (res) => {
                res.resume();
                const status = res.statusCode ?? 500;
                if (status >= 200 && status < 300) {
                    resolve();
                    return;
                }
                reject(new Error(`Slack webhook failed with status ${status}`));
            });
            req.on('error', reject);
            req.setTimeout(DEFAULT_SLACK_TIMEOUT_MS, () => {
                req.destroy(new Error(`Slack webhook timed out after ${DEFAULT_SLACK_TIMEOUT_MS}ms`));
            });
            req.write(body);
            req.end();
        });
    }
    renderPayload(event, text) {
        if (!this.payloadTemplate) {
            return { text };
        }
        const rendered = (0, template_renderer_1.renderAlertTemplateValue)(this.payloadTemplate, event);
        const payload = this.isRecord(rendered) ? { ...rendered } : {};
        if (this.payloadIncludeText && !payload.text) {
            payload.text = text;
        }
        return payload;
    }
    renderText(event) {
        const text = this.template
            ? (0, template_renderer_1.renderAlertTemplate)(this.template, event)
            : (0, template_renderer_1.renderAlertFields)(event, this.fields, '\n');
        return text.trim() || `*${event.action.toUpperCase()}* (${event.mode})\nIP: ${event.ip}\nMessage: ${event.message}`;
    }
    isRecord(value) {
        return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
    }
}
exports.SlackWebhookAlerter = SlackWebhookAlerter;
