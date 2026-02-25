import { SetMetadata } from '@nestjs/common';
import { IpsProfileName } from './options';

/** Metadata key used by `@IpsProfile()`. */
export const IPS_PROFILE_KEY = 'ips:profile';
/** Metadata key used by `@IpsBypass()`. */
export const IPS_BYPASS_KEY = 'ips:bypass';
/** Metadata key used by `@IpsTags()`. */
export const IPS_TAGS_KEY = 'ips:tags';

/** Assigns a route/controller to a specific IPS profile (`default`, `login`, etc.). */
export function IpsProfile(profile: IpsProfileName): MethodDecorator & ClassDecorator {
  return SetMetadata(IPS_PROFILE_KEY, profile);
}

/** Skips IPS guard checks (and interceptor tracking in current implementation) for a route/controller. */
export function IpsBypass(): MethodDecorator & ClassDecorator {
  return SetMetadata(IPS_BYPASS_KEY, true);
}

/** Adds custom tags to request context for rule matching and logging. */
export function IpsTags(...tags: string[]): MethodDecorator & ClassDecorator {
  return SetMetadata(IPS_TAGS_KEY, tags);
}
