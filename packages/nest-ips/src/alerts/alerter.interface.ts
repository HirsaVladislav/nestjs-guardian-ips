export interface AlertEvent {
  ts: number;
  mode: 'IDS' | 'IPS';
  action: 'alert' | 'block' | 'rateLimit' | 'ban';
  ip: string;
  method?: string;
  path?: string;
  ua?: string;
  profile?: string;
  ruleId?: string;
  severity?: string;
  counts?: Record<string, number>;
  message: string;
}

export type AlertIncludeField = 'ip' | 'path' | 'method' | 'ua' | 'profile' | 'ruleId' | 'severity' | 'counts';

export type AlertTemplateField =
  | keyof AlertEvent
  | 'tsIso'
  | 'actionUpper'
  | 'countsJson';

export interface Alerter {
  send(event: AlertEvent): Promise<void>;
}

export class MultiAlerter implements Alerter {
  constructor(private readonly alerters: Alerter[]) {}

  async send(event: AlertEvent): Promise<void> {
    await Promise.allSettled(this.alerters.map((alerter) => alerter.send(event)));
  }
}
