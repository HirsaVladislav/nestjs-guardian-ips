"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createNodeRedisClient = createNodeRedisClient;
function createNodeRedisClient(url, connectTimeoutMs) {
    const redisLib = require('redis');
    return redisLib.createClient({
        url,
        disableOfflineQueue: true,
        socket: {
            connectTimeout: connectTimeoutMs,
            reconnectStrategy: false,
        },
    });
}
