import { AlertEvent, Alerter, AlertTemplateField } from './alerter.interface';
interface SlackWebhookConfig {
    webhookUrl: string;
    template?: string;
    fields?: AlertTemplateField[];
    payloadTemplate?: Record<string, unknown>;
    payloadIncludeText?: boolean;
}
/** Slack webhook alerter with text or payload-template rendering support. */
export declare class SlackWebhookAlerter implements Alerter {
    private readonly webhookUrl;
    private readonly template?;
    private readonly fields;
    private readonly payloadTemplate?;
    private readonly payloadIncludeText;
    constructor(config: string | SlackWebhookConfig);
    /** Sends alert event to Slack Incoming Webhook endpoint. */
    send(event: AlertEvent): Promise<void>;
    private renderPayload;
    private renderText;
    private isRecord;
}
export {};
