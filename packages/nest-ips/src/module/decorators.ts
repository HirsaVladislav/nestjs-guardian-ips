import { SetMetadata } from '@nestjs/common';
import { IpsProfileName } from './options';

export const IPS_PROFILE_KEY = 'ips:profile';
export const IPS_BYPASS_KEY = 'ips:bypass';
export const IPS_TAGS_KEY = 'ips:tags';

export function IpsProfile(profile: IpsProfileName): MethodDecorator & ClassDecorator {
  return SetMetadata(IPS_PROFILE_KEY, profile);
}

export function IpsBypass(): MethodDecorator & ClassDecorator {
  return SetMetadata(IPS_BYPASS_KEY, true);
}

export function IpsTags(...tags: string[]): MethodDecorator & ClassDecorator {
  return SetMetadata(IPS_TAGS_KEY, tags);
}
