"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.EmailSmtpAlerter = void 0;
const nodemailer_1 = __importDefault(require("nodemailer"));
const template_renderer_1 = require("./template.renderer");
class EmailSmtpAlerter {
    constructor(config) {
        this.config = config;
        this.transporter = null;
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
    async send(event) {
        if (!this.transporter) {
            return;
        }
        const subject = (0, template_renderer_1.renderAlertTemplate)(this.subjectTemplate, event).trim() || '[IPS] ALERT';
        const text = this.textTemplate
            ? (0, template_renderer_1.renderAlertTemplate)(this.textTemplate, event)
            : (0, template_renderer_1.renderAlertFields)(event, this.fields, '\n');
        await this.transporter.sendMail({
            from: this.config.from,
            to: this.config.to.join(','),
            subject,
            text,
        });
    }
    createTransporter() {
        try {
            return nodemailer_1.default.createTransport({
                host: this.config.host,
                port: this.config.port,
                secure: this.config.secure ?? this.config.port === 465,
                auth: {
                    user: this.config.user,
                    pass: this.config.pass,
                },
            });
        }
        catch {
            return null;
        }
    }
}
exports.EmailSmtpAlerter = EmailSmtpAlerter;
