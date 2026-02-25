import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  HttpException,
  Injectable,
  Optional,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IPS_BYPASS_KEY, IPS_PROFILE_KEY, IPS_TAGS_KEY } from '../module/decorators';
import { IpsProfileName } from '../module/options';
import { IpsRuntime } from '../module/runtime';
import { getIpsRuntime } from '../module/runtime.registry';
import { applyHeaders } from './headers';

@Injectable()
/** Global/class/route guard that executes profile checks, CIDR policy, rules and profile rate limits. */
export class IpsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Optional() private readonly runtime?: IpsRuntime,
  ) {}

  /** Runs guard-level IPS checks for HTTP requests and throws Nest HTTP exceptions on block decisions. */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== 'http') {
      return true;
    }

    const req = context.switchToHttp().getRequest<Record<string, unknown>>();
    const res = context.switchToHttp().getResponse<Record<string, unknown>>();
    const runtime = this.runtime ?? getIpsRuntime();
    if (!runtime) {
      return true;
    }

    const bypass =
      this.reflector.getAllAndOverride<boolean>(IPS_BYPASS_KEY, [context.getHandler(), context.getClass()]) ?? false;
    const profile = this.reflector.getAllAndOverride<IpsProfileName | undefined>(IPS_PROFILE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    const tags =
      this.reflector.getAllAndOverride<string[] | undefined>(IPS_TAGS_KEY, [context.getHandler(), context.getClass()]) ??
      [];

    const decision = await runtime.guardCheck(req, profile, bypass, tags);

    const baselineHeaders = runtime.getRateLimitHeaders(req);
    if (baselineHeaders) {
      applyHeaders(res, baselineHeaders);
    }
    if (decision?.headers) {
      applyHeaders(res, decision.headers);
    }

    if (!decision?.blocked) {
      return true;
    }

    if (decision.status === 429) {
      throw new HttpException(decision.message, 429);
    }

    throw new ForbiddenException(decision.message);
  }
}
