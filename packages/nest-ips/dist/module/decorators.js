"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IPS_TAGS_KEY = exports.IPS_BYPASS_KEY = exports.IPS_PROFILE_KEY = void 0;
exports.IpsProfile = IpsProfile;
exports.IpsBypass = IpsBypass;
exports.IpsTags = IpsTags;
const common_1 = require("@nestjs/common");
/** Metadata key used by `@IpsProfile()`. */
exports.IPS_PROFILE_KEY = 'ips:profile';
/** Metadata key used by `@IpsBypass()`. */
exports.IPS_BYPASS_KEY = 'ips:bypass';
/** Metadata key used by `@IpsTags()`. */
exports.IPS_TAGS_KEY = 'ips:tags';
/** Assigns a route/controller to a specific IPS profile (`default`, `login`, etc.). */
function IpsProfile(profile) {
    return (0, common_1.SetMetadata)(exports.IPS_PROFILE_KEY, profile);
}
/** Skips IPS guard checks (and interceptor tracking in current implementation) for a route/controller. */
function IpsBypass() {
    return (0, common_1.SetMetadata)(exports.IPS_BYPASS_KEY, true);
}
/** Adds custom tags to request context for rule matching and logging. */
function IpsTags(...tags) {
    return (0, common_1.SetMetadata)(exports.IPS_TAGS_KEY, tags);
}
