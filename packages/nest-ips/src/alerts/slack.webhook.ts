import { request } from 'node:https';
import { AlertEvent, Alerter, AlertTemplateField } from './alerter.interface';
import { renderAlertFields, renderAlertTemplate, renderAlertTemplateValue } from './template.renderer';

const DEFAULT_SLACK_TIMEOUT_MS = 5000;
const DEFAULT_SLACK_FIELDS: AlertTemplateField[] = [
  'actionUpper',
  'mode',
  'ip',
  'method',
  'path',
  'ruleId',
  'severity',
  'message',
];

interface SlackWebhookConfig {
  webhookUrl: string;
  template?: string;
  fields?: AlertTemplateField[];
  payloadTemplate?: Record<string, unknown>;
  payloadIncludeText?: boolean;
}

/** Slack webhook alerter with text or payload-template rendering support. */
export class SlackWebhookAlerter implements Alerter {
  private readonly webhookUrl: string;
  private readonly template?: string;
  private readonly fields: AlertTemplateField[];
  private readonly payloadTemplate?: Record<string, unknown>;
  private readonly payloadIncludeText: boolean;

  constructor(config: string | SlackWebhookConfig) {
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
  async send(event: AlertEvent): Promise<void> {
    if (!this.webhookUrl) {
      return;
    }

    const text = this.renderText(event);
    const payload = this.renderPayload(event, text);
    const body = JSON.stringify(payload);

    await new Promise<void>((resolve, reject) => {
      const url = new URL(this.webhookUrl);
      const req = request(
        {
          method: 'POST',
          hostname: url.hostname,
          path: `${url.pathname}${url.search}`,
          port: url.port || 443,
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(body),
          },
        },
        (res) => {
          res.resume();
          const status = res.statusCode ?? 500;
          if (status >= 200 && status < 300) {
            resolve();
            return;
          }
          reject(new Error(`Slack webhook failed with status ${status}`));
        },
      );

      req.on('error', reject);
      req.setTimeout(DEFAULT_SLACK_TIMEOUT_MS, () => {
        req.destroy(new Error(`Slack webhook timed out after ${DEFAULT_SLACK_TIMEOUT_MS}ms`));
      });
      req.write(body);
      req.end();
    });
  }

  private renderPayload(event: AlertEvent, text: string): Record<string, unknown> {
    if (!this.payloadTemplate) {
      return { text };
    }

    const rendered = renderAlertTemplateValue(this.payloadTemplate, event);
    const payload = this.isRecord(rendered) ? { ...rendered } : {};
    if (this.payloadIncludeText && !payload.text) {
      payload.text = text;
    }

    return payload;
  }

  private renderText(event: AlertEvent): string {
    const text = this.template
      ? renderAlertTemplate(this.template, event)
      : renderAlertFields(event, this.fields, '\n');

    return text.trim() || `*${event.action.toUpperCase()}* (${event.mode})\nIP: ${event.ip}\nMessage: ${event.message}`;
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }
}
