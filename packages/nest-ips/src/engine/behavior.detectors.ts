import { BehaviorPolicy, ProfilePolicy } from '../module/options';
import { Store } from '../store/store.interface';

export interface BehaviorSignal {
  id: 'spike.404' | 'spike.401' | 'spike.429' | 'stuffing' | 'burst' | 'route-not-found';
  message: string;
  counts: Record<string, number>;
  severity: 'medium' | 'high' | 'critical';
}

export class BehaviorDetectors {
  constructor(private readonly store: Store) {}

  async recordRequest(ip: string, profile: ProfilePolicy): Promise<BehaviorSignal[]> {
    const behavior = this.normalizeBehavior(profile.behavior);
    const burst = await this.store.incr(`behavior:burst:${ip}`, behavior.windowSec);

    if (burst > behavior.maxReq) {
      return [
        {
          id: 'burst',
          message: `Burst threshold exceeded (${burst}/${behavior.maxReq})`,
          counts: { burst },
          severity: 'high',
        },
      ];
    }

    return [];
  }

  async recordStatus(ip: string, status: number, profile: ProfilePolicy): Promise<BehaviorSignal[]> {
    const behavior = this.normalizeBehavior(profile.behavior);
    const signals: BehaviorSignal[] = [];

    if (status === 401 || status === 403) {
      const auth = await this.store.incr(`behavior:401:${ip}`, behavior.windowSec);
      if (auth > behavior.max401) {
        signals.push({
          id: 'spike.401',
          message: `Auth failures exceeded (${auth}/${behavior.max401})`,
          counts: { auth401: auth },
          severity: 'high',
        });
      }
    }

    if (status === 404) {
      const notFound = await this.store.incr(`behavior:404:${ip}`, behavior.windowSec);
      if (notFound > behavior.max404) {
        signals.push({
          id: 'spike.404',
          message: `404 spike detected (${notFound}/${behavior.max404})`,
          counts: { notFound404: notFound },
          severity: 'high',
        });
      }
    }

    if (status === 429) {
      const tooMany = await this.store.incr(`behavior:429:${ip}`, behavior.windowSec);
      if (tooMany > behavior.max429) {
        signals.push({
          id: 'spike.429',
          message: `429 spike detected (${tooMany}/${behavior.max429})`,
          counts: { tooMany429: tooMany },
          severity: 'critical',
        });
      }
    }

    return signals;
  }

  async recordStuffing(ip: string, username: string | undefined, profile: ProfilePolicy): Promise<BehaviorSignal[]> {
    if (!username) {
      return [];
    }

    const behavior = this.normalizeBehavior(profile.behavior);
    const uniqueUsers = await this.store.sadd(`behavior:stuff:${ip}`, username, behavior.windowSec);

    if (uniqueUsers > behavior.maxUniqueUsernames) {
      return [
        {
          id: 'stuffing',
          message: `Credential stuffing pattern (${uniqueUsers}/${behavior.maxUniqueUsernames})`,
          counts: { uniqueUsers },
          severity: 'critical',
        },
      ];
    }

    return [];
  }

  async recordRouteNotFound(ip: string, windowSec: number, max: number): Promise<BehaviorSignal[]> {
    const count = await this.store.incr(`behavior:route404:${ip}`, windowSec);

    if (count > max) {
      return [
        {
          id: 'route-not-found',
          message: `Route-not-found spike (${count}/${max})`,
          counts: { routeNotFound: count },
          severity: 'critical',
        },
      ];
    }

    return [];
  }

  private normalizeBehavior(behavior?: BehaviorPolicy): Required<BehaviorPolicy> {
    return {
      windowSec: behavior?.windowSec ?? 60,
      max404: behavior?.max404 ?? 30,
      max401: behavior?.max401 ?? 20,
      max429: behavior?.max429 ?? 20,
      maxReq: behavior?.maxReq ?? 300,
      maxUniqueUsernames: behavior?.maxUniqueUsernames ?? 20,
    };
  }
}
