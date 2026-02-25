import { AlertEvent, AlertTemplateField } from './alerter.interface';
/** Renders a string template by replacing `{{token}}` placeholders from `AlertEvent`. */
export declare function renderAlertTemplate(template: string, event: AlertEvent): string;
/** Recursively renders template placeholders inside strings/arrays/objects. */
export declare function renderAlertTemplateValue<T>(value: T, event: AlertEvent): T;
/** Renders selected alert fields as human-readable lines. */
export declare function renderAlertFields(event: AlertEvent, fields: AlertTemplateField[], separator?: string): string;
