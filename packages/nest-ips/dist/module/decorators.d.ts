import { IpsProfileName } from './options';
export declare const IPS_PROFILE_KEY = "ips:profile";
export declare const IPS_BYPASS_KEY = "ips:bypass";
export declare const IPS_TAGS_KEY = "ips:tags";
export declare function IpsProfile(profile: IpsProfileName): MethodDecorator & ClassDecorator;
export declare function IpsBypass(): MethodDecorator & ClassDecorator;
export declare function IpsTags(...tags: string[]): MethodDecorator & ClassDecorator;
