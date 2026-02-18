"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IPS_TAGS_KEY = exports.IPS_BYPASS_KEY = exports.IPS_PROFILE_KEY = void 0;
exports.IpsProfile = IpsProfile;
exports.IpsBypass = IpsBypass;
exports.IpsTags = IpsTags;
const common_1 = require("@nestjs/common");
exports.IPS_PROFILE_KEY = 'ips:profile';
exports.IPS_BYPASS_KEY = 'ips:bypass';
exports.IPS_TAGS_KEY = 'ips:tags';
function IpsProfile(profile) {
    return (0, common_1.SetMetadata)(exports.IPS_PROFILE_KEY, profile);
}
function IpsBypass() {
    return (0, common_1.SetMetadata)(exports.IPS_BYPASS_KEY, true);
}
function IpsTags(...tags) {
    return (0, common_1.SetMetadata)(exports.IPS_TAGS_KEY, tags);
}
