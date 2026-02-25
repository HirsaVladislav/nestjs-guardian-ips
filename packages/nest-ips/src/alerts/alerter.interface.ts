/** Canonical alert payload emitted by IPS/IDS detections. */
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

/** Selectable alert fields for privacy filtering and rule-specific include lists. */
export type AlertIncludeField = 'ip' | 'path' | 'method' | 'ua' | 'profile' | 'ruleId' | 'severity' | 'counts';

/** Template placeholders supported by alert renderers. */
export type AlertTemplateField =
  | keyof AlertEvent
  | 'tsIso'
  | 'actionUpper'
  | 'countsJson';

/** Alert transport contract (Slack, email, custom implementations). */
export interface Alerter {
  send(event: AlertEvent): Promise<void>;
}

/** Fan-out alerter that dispatches one event to multiple channels. */
export class MultiAlerter implements Alerter {
  constructor(private readonly alerters: Alerter[]) {}

  async send(event: AlertEvent): Promise<void> {
    const results = await Promise.allSettled(this.alerters.map((alerter) => alerter.send(event)));
    const succeeded = results.some((result) => result.status === 'fulfilled');
    if (succeeded) {
      return;
    }

    const reasons = results
      .filter((result): result is PromiseRejectedResult => result.status === 'rejected')
      .map((result) => result.reason);
    throw new AggregateError(reasons, '[nest-ips] All alert channels failed');
  }
}
