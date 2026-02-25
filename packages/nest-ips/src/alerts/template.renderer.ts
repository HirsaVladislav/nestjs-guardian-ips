import { AlertEvent, AlertTemplateField } from './alerter.interface';

const PLACEHOLDER_PATTERN = /{{\s*([a-zA-Z0-9_]+)\s*}}/g;

const FIELD_LABELS: Record<AlertTemplateField, string> = {
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

/** Renders a string template by replacing `{{token}}` placeholders from `AlertEvent`. */
export function renderAlertTemplate(template: string, event: AlertEvent): string {
  if (!template) {
    return '';
  }

  return template.replace(PLACEHOLDER_PATTERN, (_, token: string) => {
    const value = resolveAlertToken(event, token);
    return value ?? '';
  });
}

/** Recursively renders template placeholders inside strings/arrays/objects. */
export function renderAlertTemplateValue<T>(value: T, event: AlertEvent): T {
  if (typeof value === 'string') {
    return renderAlertTemplate(value, event) as T;
  }

  if (Array.isArray(value)) {
    return value.map((item) => renderAlertTemplateValue(item, event)) as T;
  }

  if (!value || typeof value !== 'object') {
    return value;
  }

  const output: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    output[k] = renderAlertTemplateValue(v, event);
  }
  return output as T;
}

/** Renders selected alert fields as human-readable lines. */
export function renderAlertFields(event: AlertEvent, fields: AlertTemplateField[], separator = '\n'): string {
  return fields
    .map((field) => {
      const value = resolveAlertToken(event, field);
      if (!value) {
        return null;
      }
      return `${FIELD_LABELS[field]}: ${value}`;
    })
    .filter((line): line is string => Boolean(line))
    .join(separator);
}

function resolveAlertToken(event: AlertEvent, token: string): string | undefined {
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

  const key = token as keyof AlertEvent;
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

function formatCounts(counts: AlertEvent['counts']): string | undefined {
  if (!counts) {
    return undefined;
  }

  const entries = Object.entries(counts);
  if (entries.length === 0) {
    return undefined;
  }

  return entries.map(([k, v]) => `${k}=${v}`).join(', ');
}
