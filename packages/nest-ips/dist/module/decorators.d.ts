import { IpsProfileName } from './options';
/** Metadata key used by `@IpsProfile()`. */
export declare const IPS_PROFILE_KEY = "ips:profile";
/** Metadata key used by `@IpsBypass()`. */
export declare const IPS_BYPASS_KEY = "ips:bypass";
/** Metadata key used by `@IpsTags()`. */
export declare const IPS_TAGS_KEY = "ips:tags";
/** Assigns a route/controller to a specific IPS profile (`default`, `login`, etc.). */
export declare function IpsProfile(profile: IpsProfileName): MethodDecorator & ClassDecorator;
/** Skips IPS guard checks (and interceptor tracking in current implementation) for a route/controller. */
export declare function IpsBypass(): MethodDecorator & ClassDecorator;
/** Adds custom tags to request context for rule matching and logging. */
export declare function IpsTags(...tags: string[]): MethodDecorator & ClassDecorator;
