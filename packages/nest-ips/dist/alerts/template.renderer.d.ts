import { AlertEvent, AlertTemplateField } from './alerter.interface';
export declare function renderAlertTemplate(template: string, event: AlertEvent): string;
export declare function renderAlertTemplateValue<T>(value: T, event: AlertEvent): T;
export declare function renderAlertFields(event: AlertEvent, fields: AlertTemplateField[], separator?: string): string;
