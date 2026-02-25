import { AlertEvent, Alerter, AlertTemplateField } from './alerter.interface';
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
export declare class EmailSmtpAlerter implements Alerter {
    private readonly config;
    private transporter;
    private readonly subjectTemplate;
    private readonly textTemplate?;
    private readonly fields;
    constructor(config: SmtpConfig);
    /** Sends one alert email to configured recipients. */
    send(event: AlertEvent): Promise<void>;
    private createTransporter;
}
export {};
