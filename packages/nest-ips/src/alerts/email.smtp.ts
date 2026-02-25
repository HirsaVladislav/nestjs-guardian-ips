import nodemailer from 'nodemailer';
import { AlertEvent, Alerter, AlertTemplateField } from './alerter.interface';
import { renderAlertFields, renderAlertTemplate } from './template.renderer';

const DEFAULT_SMTP_CONNECTION_TIMEOUT_MS = 5000;
const DEFAULT_SMTP_GREETING_TIMEOUT_MS = 5000;
const DEFAULT_SMTP_SOCKET_TIMEOUT_MS = 10000;

interface SmtpConfig {
  host: string;
  port: number;
  user: string;
  pass: string;
  from: string;
  to: string[];
  secure?: boolean;
  subjectTemplate?: string;
  textTemplate?: string;
  fields?: AlertTemplateField[];
}

/** SMTP email alerter implemented via `nodemailer`. */
export class EmailSmtpAlerter implements Alerter {
  private transporter: {
    sendMail(input: {
      from: string;
      to: string;
      subject: string;
      text: string;
    }): Promise<void>;
  } | null = null;
  private readonly subjectTemplate: string;
  private readonly textTemplate?: string;
  private readonly fields: AlertTemplateField[];

  constructor(private readonly config: SmtpConfig) {
    this.subjectTemplate = config.subjectTemplate ?? '[IPS] {{actionUpper}} {{ip}}';
    this.textTemplate = config.textTemplate;
    this.fields = config.fields ?? [
      'mode',
      'action',
      'ip',
      'method',
      'path',
      'profile',
      'ruleId',
      'severity',
      'ua',
      'counts',
      'message',
      'tsIso',
    ];
    this.transporter = this.createTransporter();
  }

  /** Sends one alert email to configured recipients. */
  async send(event: AlertEvent): Promise<void> {
    if (!this.transporter) {
      return;
    }

    const subject = renderAlertTemplate(this.subjectTemplate, event).trim() || '[IPS] ALERT';
    const text = this.textTemplate
      ? renderAlertTemplate(this.textTemplate, event)
      : renderAlertFields(event, this.fields, '\n');

    await this.transporter.sendMail({
      from: this.config.from,
      to: this.config.to.join(','),
      subject,
      text,
    });
  }

  private createTransporter(): {
    sendMail(input: { from: string; to: string; subject: string; text: string }): Promise<void>;
  } | null {
    try {
      return nodemailer.createTransport({
        host: this.config.host,
        port: this.config.port,
        secure: this.config.secure ?? this.config.port === 465,
        connectionTimeout: DEFAULT_SMTP_CONNECTION_TIMEOUT_MS,
        greetingTimeout: DEFAULT_SMTP_GREETING_TIMEOUT_MS,
        socketTimeout: DEFAULT_SMTP_SOCKET_TIMEOUT_MS,
        auth: {
          user: this.config.user,
          pass: this.config.pass,
        },
      });
    } catch {
      return null;
    }
  }
}
