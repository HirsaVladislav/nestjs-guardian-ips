# @nestjs-guardian/nest-ips

Application-level IDS/IPS for NestJS APIs.

## What It Does

- Protects NestJS APIs with an IDS/IPS rule engine, not only a limiter.
- Detects attack patterns (401/404/429 spikes, scans, abusive routes, suspicious UA).
- Applies actions: `alert`, `rate-limit`, `ban`, `block`.
- Supports multi-worker/shared state via Redis and local mode via memory store.
- Sends security alerts to Slack and email with customizable templates.
- Can aggregate repeated `rateLimit` alerts into periodic summary reports (`alerts.rateLimitReport`) to reduce alert spam.

## Install

```bash
npm i @nestjs-guardian/nest-ips
```

## Quick Start (Express/Nest)

```ts
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import {
  IpsModule,
  IpsGuard,
  IpsInterceptor,
  IpsNotFoundFilter,
  createIpsMiddleware,
} from '@nestjs-guardian/nest-ips';

@Module({
  imports: [IpsModule.forRoot({})],
  providers: [
    { provide: APP_GUARD, useClass: IpsGuard },
    { provide: APP_INTERCEPTOR, useClass: IpsInterceptor },
    { provide: APP_FILTER, useClass: IpsNotFoundFilter },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(createIpsMiddleware()).forRoutes('*');
  }
}
```

## How Client IP Is Determined (Trust Proxy Model)

- `clientIp.mode: 'strict'`: trust forwarded headers only from trusted proxies.
- `clientIp.mode: 'hops'`: resolve client IP by fixed proxy hop count.
- `headersPriority` controls header parsing order.
- `denyPrivateIpsFromHeaders` can reject private/local forwarded IPs.
- See `Client IP Trust Model` below for detailed behavior and examples.

## Rules Examples (401/404/429 + Path Rules)

```ts
IpsModule.forRoot({
  profiles: {
    default: {
      behavior: { windowSec: 60, max401: 20, max404: 30, max429: 20 },
    },
  },
  notFound: { windowSec: 60, max: 30 },
});
```

```json
[
  {
    "id": "block.admin.path",
    "severity": "high",
    "when": { "path": { "prefix": "/admin" } },
    "match": [{ "field": "path", "contains": "/admin" }],
    "action": "block",
    "block": { "status": 403, "message": "Forbidden" }
  }
]
```

## Storage (Memory vs Redis)

- `store.type: 'memory'` (default): fastest local mode, state is per-process/per-worker.
- `store.type: 'redis'`: shared counters/bans across workers and instances.
- `store.type: 'auto'`: try Redis first, fallback to memory on connection failure.

```ts
store: {
  type: 'auto',
  redis: { url: process.env.REDIS_URL },
}
```

## Alerts (Slack/Email)

- Slack: requires `alerts.slack.webhookUrl`.
- Email: requires full `alerts.email.smtp` config.
- Optional: `alerts.rateLimitReport` aggregates repeated `rateLimit` events into periodic summary alerts.
- If channel is configured but destination is missing, module throws startup error.
- Supports templates and field-based rendering.

## Rate-Limit Summary Reports (`alerts.rateLimitReport`)

Use this feature to reduce alert spam from repeated `429` / `rateLimit` decisions.

What it does:

- Collects `rateLimit` events in memory.
- Groups identical events by `ruleId + ip + method + path + profile`.
- Sends one periodic summary alert (Slack/Email) instead of many repeated alerts.
- Can optionally suppress immediate `rateLimit` alerts.

What it does not change:

- `ban`, `block`, and behavior spike alerts (`spike.401`, `spike.404`, `spike.429`, `burst`, etc.) are still sent normally.

Notes:

- If `alerts.rateLimitReport` is omitted, this feature is disabled (default behavior remains unchanged).
- Summary sending requires at least one configured alert channel (`alerts.slack` and/or `alerts.email`).
- Aggregation is per-process (each app instance/worker sends its own summary).

### Mode selection via `suppressImmediate`

Use one config and switch behavior with `suppressImmediate`:

```ts
IpsModule.forRoot({
  alerts: {
    slack: {
      webhookUrl: process.env.SLACK_WEBHOOK_URL!,
    },
    rateLimitReport: {
      collect: true,
      period: '30m',
      suppressImmediate: true, // set false for hybrid mode
      maxItems: 50,
      maxGroups: 2000,
    },
  },
});
```

How `suppressImmediate` works:

- `suppressImmediate: true` -> summary-only mode (recommended for noisy production APIs)
  - `rateLimit` alerts are collected and sent only in periodic reports (`period`)
  - immediate `rateLimit` alerts are suppressed
- `suppressImmediate: false` -> hybrid mode (immediate alerts + periodic summary)
  - immediate `rateLimit` alerts are still sent
  - the same events are also aggregated into periodic reports

Important:

- This flag affects only `rateLimit` alerts.
- `ban`, `block`, `spike.*`, `burst`, and other non-`rateLimit` alerts are still sent immediately.

### `period` format

- Supports seconds as number or numeric string: `30`, `'30'`
- Supports duration strings:
  - `30m` (30 minutes)
  - `1h` / `10h` (hours)
  - `1d` (day)
- Invalid values fallback to `30m`

### Memory control (`maxGroups`)

- `maxGroups` limits how many unique grouped rows are stored in memory during one report window.
- When limit is reached, oldest groups are evicted first (FIFO) and new groups are accepted.
- Summary message includes eviction counters when this happens.
- Report rows are cleared after each summary flush (`period`) and on shutdown flush, so data does not accumulate across windows.
- Memory usage for this feature is bounded by `maxGroups` (group count), not by total request volume.
- Repeated events for the same group only increment `count` (they do not create new rows).

Example behavior:

- `maxGroups: 2000`
- first 2000 unique groups are stored in the current window
- group #2001 arrives -> oldest stored group is removed, new group is added
- at next summary flush, all current rows are sent/cleared and a new window starts

## Security Notes (Direct Access, Spoofing)

- If direct internet access to app is possible, do not trust forwarded headers from unknown sources.
- In strict mode, configure trusted proxy CIDRs or trust function correctly.
- Wrong proxy trust setup can lead to wrong client attribution and weaker bans.
- In multi-worker production, prefer Redis store for consistent behavior.

## Configuration Reference

- Minimal/default config: `IpsModule.forRoot({})`
- Full options and defaults: see sections below (`npm Usage Guide`, `Top-level options reference`, `Client IP Trust Model`, `Spikes And Actions`, `Alert Templates`).

## Funding

Support development:
- BuyMeACoffee: https://buymeacoffee.com/vladyslavkhyrsa
- GitHub Sponsors: https://github.com/sponsors/HirsaVladislav

## npm Usage Guide

### Risks and mandatory parameters (read first)

Security risks if misconfigured:
- If proxy trust is wrong, attacker IP attribution can be wrong.
- If app is accessible directly and headers are trusted incorrectly, IP spoofing risk increases.
- If Redis is not used in multi-worker deployment, each worker keeps separate memory state.
- If alert channel is configured without destination (`webhookUrl` or SMTP), module throws at startup.

Mandatory parameters by scenario:
- Basic IPS: no mandatory fields in `forRoot`, but required pipeline registration (module + providers + middleware).
- Trusted proxy headers (`strict`): configure trusted source (`trustedProxyCidrs` or `isTrustedProxy`).
- Fixed hops mode: set `clientIp.hops`.
- Redis strict mode: set `store.redis.url` (or `REDIS_URL`).
- Slack alerts: set `alerts.slack.webhookUrl`.
- Email alerts: set full `alerts.email.smtp` object.

### Required integration steps (must-have)

1. Add `IpsModule.forRoot(...)` in `imports`.
2. Register global providers:
   - `APP_GUARD -> IpsGuard`
   - `APP_INTERCEPTOR -> IpsInterceptor`
   - `APP_FILTER -> IpsNotFoundFilter`
3. Apply middleware: `createIpsMiddleware()` for routes.

Without these 3 steps, full IPS pipeline will not work.

### Example 1: Minimal setup (safe defaults)

Required fields:
- none in `forRoot` (all values have defaults).

Optional fields:
- everything in `IpsModuleOptions`.

Defaults used:
- `mode: 'IPS'`
- `logging: true`
- `clientIp.mode: 'strict'`
- `clientIp.headersPriority: ['cf-connecting-ip', 'true-client-ip', 'fastly-client-ip', 'x-forwarded-for', 'forwarded', 'x-real-ip']`
- `clientIp.hops: 1`
- `clientIp.denyPrivateIpsFromHeaders: true`
- `store.type: 'memory'`
- `store.maxBytes: 500MB`
- `scoreThreshold: 100`
- `cheapSignatures.enabled: true`
- `notFound.windowSec: 60`
- `notFound.max: 30`

```ts
IpsModule.forRoot({});
```

### Example 2: Strict proxy trust (recommended for internet-facing apps)

Required fields for trusted headers:
- `clientIp.mode: 'strict'`
- at least one of:
  - `clientIp.trustedProxyCidrs`
  - `clientIp.isTrustedProxy`

Optional fields:
- `clientIp.headersPriority`
- `clientIp.denyPrivateIpsFromHeaders`

Defaults:
- `headersPriority` default list (see above)
- `denyPrivateIpsFromHeaders: true`

```ts
IpsModule.forRoot({
  clientIp: {
    mode: 'strict',
    trustedProxyCidrs: ['10.0.0.0/8'],
  },
});
```

### Example 3: Hops mode (fixed proxy chain)

Required fields:
- `clientIp.mode: 'hops'`
- `clientIp.hops`

Optional fields:
- `clientIp.headersPriority`
- `clientIp.denyPrivateIpsFromHeaders`

Defaults:
- `hops: 1` (if omitted)
- `denyPrivateIpsFromHeaders: true`

```ts
IpsModule.forRoot({
  clientIp: {
    mode: 'hops',
    hops: 2,
    headersPriority: ['x-forwarded-for', 'forwarded'],
  },
});
```

### Example 4: Redis store (shared state between workers)

Required fields:
- for `store.type: 'redis'`:
  - `store.redis.url` or `REDIS_URL` env var.

Optional fields:
- `store.redis.keyPrefix`
- `store.redis.connectTimeoutMs`
- `store.redis.connectionRetries`
- `store.redis.retryDelayMs`

Defaults:
- `store.type: 'memory'`
- `connectTimeoutMs: 5000`
- `connectionRetries: 10`
- `retryDelayMs: 300`
- in `auto` mode, fallback to memory on Redis connection failure.

```ts
IpsModule.forRoot({
  store: {
    type: 'auto',
    redis: {
      url: process.env.REDIS_URL,
    },
  },
});
```

### Example 5: Alerts (Slack / Email)

Required fields:
- Slack channel:
  - `alerts.slack.webhookUrl`
- Email channel:
  - `alerts.email.smtp.host`
  - `alerts.email.smtp.port`
  - `alerts.email.smtp.user`
  - `alerts.email.smtp.pass`
  - `alerts.email.smtp.from`
  - `alerts.email.smtp.to[]`

Optional fields:
- templates/fields/throttle settings.

Defaults:
- Slack `throttleSec: 120`
- Email `throttleSec: 300`
- Email `secure: port === 465` (inside transporter setup)

```ts
IpsModule.forRoot({
  alerts: {
    slack: {
      webhookUrl: process.env.SLACK_WEBHOOK_URL!,
    },
    email: {
      smtp: {
        host: process.env.SMTP_HOST!,
        port: 587,
        user: process.env.SMTP_USER!,
        pass: process.env.SMTP_PASS!,
        from: 'ips@yourapp.com',
        to: ['security@yourapp.com'],
      },
    },
  },
});
```

### Example 6: Periodic rate-limit summary reports

Required fields:
- none (feature is disabled unless `alerts.rateLimitReport` is configured with `collect: true` or `enabled: true`).

Optional fields:
- `alerts.rateLimitReport.collect`
- `alerts.rateLimitReport.enabled` (alias of `collect`)
- `alerts.rateLimitReport.period`
- `alerts.rateLimitReport.suppressImmediate`
- `alerts.rateLimitReport.maxItems`
- `alerts.rateLimitReport.maxGroups`

Defaults (when enabled):
- `period: 1800` seconds (`30m`)
- `suppressImmediate: true`
- `maxItems: 50`
- `maxGroups: 2000`

```ts
IpsModule.forRoot({
  alerts: {
    slack: {
      webhookUrl: process.env.SLACK_WEBHOOK_URL!,
    },
    rateLimitReport: {
      collect: true,
      period: '30m',
      suppressImmediate: true,
      maxItems: 50,
      maxGroups: 2000,
    },
  },
});
```

### Example 7: Spikes and profile behavior

Required fields:
- none (behavior has defaults per profile).

Optional fields:
- `profiles.<name>.behavior.{windowSec,max401,max404,max429,maxReq,maxUniqueUsernames}`

Defaults (profile-dependent):
- `default.behavior`: `windowSec=60,max401=20,max404=30,max429=20,maxReq=300,maxUniqueUsernames=20`
- `public.behavior`: `60,30,40,30,400,40`
- `login.behavior`: `120,10,20,10,120,10`
- `admin.behavior`: `60,8,10,8,80,5`

```ts
IpsModule.forRoot({
  profiles: {
    login: {
      behavior: { windowSec: 120, max401: 8, max429: 8 },
    },
  },
});
```

### Top-level options reference

| Field | Required | Default |
|---|---|---|
| `mode` | no | `'IPS'` |
| `clientIp` | no | strict defaults |
| `logging` | no | `true` |
| `logger` | no | internal logger |
| `store` | no | memory store |
| `memoryCapBytes` | no | `500 * 1024 * 1024` |
| `rules` | no | `undefined` |
| `profiles` | no | built-in defaults |
| `alerts` | no | disabled unless configured |
| `privacy` | no | standard include list |
| `scoreThreshold` | no | `100` |
| `cheapSignatures` | no | enabled + built-in patterns |
| `notFound` | no | `{ windowSec: 60, max: 30 }` |

## Nest Integration

```ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { APP_FILTER, APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import {
  IpsModule,
  IpsGuard,
  IpsInterceptor,
  IpsNotFoundFilter,
  createIpsMiddleware,
} from '@nestjs-guardian/nest-ips';

@Module({
  imports: [
    IpsModule.forRoot({
      mode: 'IPS',
      logging: true,
      // logger: yourCustomLogger, // optional, should implement LoggerPort
      clientIp: {
        mode: 'strict',
        trustedProxyCidrs: ['10.0.0.0/8'],
        headersPriority: [
          'cf-connecting-ip',
          'true-client-ip',
          'fastly-client-ip',
          'x-forwarded-for',
          'forwarded',
        ],
        denyPrivateIpsFromHeaders: true,
      },
      store: {
        type: 'memory',
        maxBytes: 500 * 1024 * 1024,
      },
      profiles: {
        default: {
          rateLimit: { key: 'ip', windowSec: 60, max: 120 },
          banTtlSec: 600,
        },
        login: {
          rateLimit: { key: 'ip+id', windowSec: 120, max: 8 },
          banTtlSec: 900,
          behavior: { max401: 10, max429: 10, windowSec: 120 },
        },
        admin: {
          rateLimit: { key: 'ip', windowSec: 60, max: 30 },
          allowCidrs: ['10.0.0.0/8'],
          banTtlSec: 1800,
        },
        public: {
          rateLimit: { key: 'ip', windowSec: 60, max: 300 },
          banTtlSec: 300,
        },
      },
      rules: {
        loadFrom: 'node_modules/@nestjs-guardian/nest-ips/rules/baseline.json',
      },
      alerts: {
        slack: {
          webhookUrl: process.env.SLACK_WEBHOOK_URL!,
          throttleSec: 120,
          template: '*{{actionUpper}}* ({{mode}})\nIP: {{ip}}\nPath: {{path}}\nMessage: {{message}}',
          // payloadTemplate: { env: 'prod', service: 'your-service', title: '{{ruleId}}', error: '{{message}}' },
          // payloadIncludeText: false,
        },
        email: {
          smtp: {
            host: process.env.SMTP_HOST!,
            port: Number(process.env.SMTP_PORT || 587),
            user: process.env.SMTP_USER!,
            pass: process.env.SMTP_PASS!,
            from: 'ips@yourapp.com',
            to: ['security@yourapp.com'],
          },
          throttleSec: 300,
          subjectTemplate: '[IPS][{{mode}}] {{actionUpper}} {{ip}}',
          textTemplate:
            'action={{action}} mode={{mode}}\nip={{ip}} method={{method}} path={{path}}\nrule={{ruleId}} severity={{severity}}\nmessage={{message}}\ncounts={{countsJson}}\nts={{tsIso}}',
        },
        // Optional periodic summary for repeated rate-limit alerts (429 spam reduction)
        // rateLimitReport: {
        //   collect: true,
        //   period: '30m',
        //   suppressImmediate: true,
        //   maxItems: 50,
        //   maxGroups: 2000,
        // },
      },
    }),
  ],
  providers: [
    { provide: APP_GUARD, useClass: IpsGuard },
    { provide: APP_INTERCEPTOR, useClass: IpsInterceptor },
    { provide: APP_FILTER, useClass: IpsNotFoundFilter },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(createIpsMiddleware()).forRoutes('*');
  }
}
```

## Decorators

```ts
import { Controller, Get, Post } from '@nestjs/common';
import { IpsBypass, IpsProfile } from '@nestjs-guardian/nest-ips';

@Controller()
export class AppController {
  @Get('/health')
  @IpsBypass()
  health() {
    return 'ok';
  }

  @Post('/auth/login')
  @IpsProfile('login')
  login() {}

  @Get('/admin/panel')
  @IpsProfile('admin')
  panel() {}
}
```

### `@IpsBypass()`

What problem it solves:

- Excludes a route/class from IPS guard/interceptor observation (for example `/health`, probes, internal callbacks).

Example:

```ts
@IpsBypass()
@Get('/health')
health() {
  return { ok: true };
}
```

What it is for:

- Skips guard-level IPS checks and interceptor tracking for the route.
- For full route exclusion (including middleware), see `Excluding Routes From IPS Observation` below.

### `@IpsProfile('default' | 'public' | 'login' | 'admin')`

What problem it solves:

- Assigns a route/class to a specific IPS profile with its own limits and behavior thresholds.

Example:

```ts
@IpsProfile('login')
@Post('/auth/login')
login() {}
```

What it is for:

- Use stricter anti-bruteforce/stuffing settings for auth routes.
- Use stronger controls for sensitive routes (for example `admin`).

### `@IpsTags(...tags)`

What problem it solves:

- Adds route/class tags into IPS request context for custom logic and future rule extensions.

Example:

```ts
@IpsTags('payments', 'public-api')
@Get('/payments/status')
status() {}
```

What it is for:

- Group detections by feature/domain.
- Mark routes with domain-specific metadata (for custom integrations or future tag-based rules).

Current built-in behavior:

- Tags are attached to IPS request context by `IpsGuard`.
- Built-in rules/alerts/logs do not yet use tags directly.

## Excluding Routes From IPS Observation (Example: `/health`)

For health-check routes (ALB/ELB, uptime probes), use both:

1. middleware `exclude(...)` to skip `createIpsMiddleware()`
2. `@IpsBypass()` to skip IPS guard/interceptor checks

Why both are required:

- `exclude(...)` disables only middleware checks (global rate-limit, cheap signatures, early block).
- `@IpsBypass()` disables IPS checks on handler/class level (guard/interceptor path).
- Using only one of them can still leave the route counted or blocked at another IPS stage.

### 1) Exclude from IPS middleware

```ts
import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { createIpsMiddleware } from '@nestjs-guardian/nest-ips';

export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(createIpsMiddleware())
      .exclude({ path: 'health', method: RequestMethod.GET })
      .forRoutes('*');
  }
}
```

### 2) Add `@IpsBypass()` to the route

```ts
import { Controller, Get } from '@nestjs/common';
import { IpsBypass } from '@nestjs-guardian/nest-ips';

@Controller()
export class AppController {
  @IpsBypass()
  @Get('/health')
  health() {
    return { ok: true };
  }
}
```

### Notes

- Check the exact path in `exclude(...)` (including global prefix, e.g. `/api/health`).
- Keep `/health` lightweight (no heavy DB/external calls).
- Protect public `/health` at ALB/WAF/security-group level rather than app-level IPS limits.

## Client IP Trust Model

Client IP extraction is configured via `clientIp`.

`strict` mode:

- Reads client IP from headers only when request comes from trusted proxy.
- Trust can be defined by:
  - `trustedProxyCidrs`
  - `isTrustedProxy(remoteIp)`
- If request is not from trusted proxy, headers are ignored.

```ts
clientIp: {
  mode: 'strict',
  trustedProxyCidrs: ['10.0.0.0/8', '192.168.0.0/16'],
  headersPriority: ['cf-connecting-ip', 'x-forwarded-for', 'forwarded'],
  denyPrivateIpsFromHeaders: true,
}
```

## Spikes And Actions

This package is a rule engine + behavior engine (not only a simple limiter).

Action semantics:

- `rate-limit`: soft control, returns `429 Too Many Requests`.
- `ban`: hard control, blocks IP for TTL (`403` in IPS mode).
- `spike`: anomaly detector in a time window, can escalate to `ban/alert`.
- `slowdown`: not implemented yet (planned), would delay response instead of blocking.

Where spikes are configured:

- `profiles.<name>.behavior`
  - `windowSec`
  - `max401`
  - `max404`
  - `max429`
  - `maxReq`
  - `maxUniqueUsernames`
- `notFound` (`route-not-found` spike detector).

```ts
profiles: {
  default: {
    rateLimit: { key: 'ip', windowSec: 60, max: 120 },
    behavior: {
      windowSec: 60,
      max401: 20,
      max404: 30,
      max429: 20,
      maxReq: 300,
      maxUniqueUsernames: 20,
    },
    banTtlSec: 600,
  },
},
notFound: {
  windowSec: 60,
  max: 30,
}
```

Canonical spike scenarios:

- `spike.401(ip, windowSec, max)` -> configured by `behavior.max401`.
- `spike.404(ip, windowSec, max)` -> configured by `behavior.max404`.
- `spike.429(ip, windowSec, max)` -> configured by `behavior.max429`.
- `spike.path("/admin", ...)` -> use rule `match.path` + `action`.
- `spike.ua(pattern, ...)` -> use rule `match.ua.regex`.
- `spike.method("TRACE", ...)` -> use rule `when.methods`.

Rules examples:

```json
[
  {
    "id": "spike.path.admin",
    "severity": "high",
    "when": { "path": { "prefix": "/admin" } },
    "match": [{ "field": "path", "contains": "/admin" }],
    "action": "alert"
  },
  {
    "id": "spike.ua.scanner",
    "severity": "medium",
    "match": [{ "field": "ua", "regex": "(sqlmap|nikto|nmap|gobuster)" }],
    "action": "alert"
  },
  {
    "id": "spike.method.trace",
    "severity": "high",
    "when": { "methods": ["TRACE"] },
    "match": [{ "field": "path", "regex": ".*" }],
    "action": "block",
    "block": { "status": 403, "message": "Forbidden" }
  }
]
```

`hops` mode:

- Uses proxy hop count (`hops`) to select client IP from forwarding chain.
- Useful when app is always behind fixed number of proxies.

```ts
clientIp: {
  mode: 'hops',
  hops: 2,
  headersPriority: ['x-forwarded-for', 'forwarded'],
  denyPrivateIpsFromHeaders: true,
}
```

## Public API

Exports:

- `IpsModule`
- `IpsGuard`, `IpsInterceptor`, `IpsNotFoundFilter`, `createIpsMiddleware()`
- `@IpsProfile()`, `@IpsBypass()`, `@IpsTags()`
- Types: `IpsModuleOptions`, `IpsClientIpOptions`, `IpsResolvedClientIpOptions`, `Rule`, `AlertEvent`, `AlertTemplateField`, `AlertIncludeField`, `Store`, `Alerter`, `LoggerPort`

## Alert Templates

You can customize Slack and email content via templates:

- `alerts.slack.template`
- `alerts.slack.fields`
- `alerts.slack.payloadTemplate`
- `alerts.slack.payloadIncludeText`
- `alerts.email.subjectTemplate`
- `alerts.email.textTemplate`
- `alerts.email.fields`

Enable behavior:

- If `enabled` is explicitly set, that value is used.
- If `enabled` is omitted and channel config exists, channel is treated as enabled.
- If `alerts.slack` is enabled/configured without `webhookUrl`, module throws at startup.
- If `alerts.email` is enabled/configured without full `smtp` config, module throws at startup.

Template placeholders:

- `{{ts}}`, `{{tsIso}}`
- `{{mode}}`, `{{action}}`, `{{actionUpper}}`
- `{{ip}}`, `{{method}}`, `{{path}}`, `{{ua}}`
- `{{profile}}`, `{{ruleId}}`, `{{severity}}`
- `{{counts}}`, `{{countsJson}}`
- `{{message}}`

If template is not provided, channel uses `fields` list (empty fields are skipped).

### Slack formats

`1) Plain text template`

```ts
alerts: {
  slack: {
    webhookUrl: process.env.SLACK_WEBHOOK_URL!,
    template: '*{{actionUpper}}* ({{mode}})\nIP: {{ip}}\nPath: {{path}}\nMessage: {{message}}',
  },
}
```

`2) Auto text from selected fields`

```ts
alerts: {
  slack: {
    webhookUrl: process.env.SLACK_WEBHOOK_URL!,
    fields: ['actionUpper', 'mode', 'ip', 'path', 'ruleId', 'severity', 'message'],
  },
}
```

`3) JSON payload template (for Slack Workflow fields like env/service/title/error)`

```ts
alerts: {
  slack: {
    webhookUrl: process.env.SLACK_WEBHOOK_URL!,
    payloadTemplate: {
      env: 'prod',
      service: 'your-service',
      title: '[{{mode}}] {{actionUpper}} {{ruleId}}',
      error: '{{message}}',
      ip: '{{ip}}',
      path: '{{path}}',
    },
    payloadIncludeText: false, // true by default
  },
}
```

## Memory Cap

`MemoryStore` enforces a hard cap (`maxBytes`) using:

- TTL eviction
- LRU eviction
- pressure mode (TTL shortening + set trimming)
- high-priority ban keys (evicted last)

This cap is for IPS stored data only. Total Node.js process memory can be higher.

## Redis Store

Use built-in Redis store (based on `node-redis`) to share counters/bans across workers:

```ts
IpsModule.forRoot({
  store: {
    type: 'auto', // 'redis' to require Redis, 'auto' to fallback to memory
    redis: {
      url: process.env.REDIS_URL,
      keyPrefix: 'ips:',
      connectTimeoutMs: 5000,
      connectionRetries: 10, // default: 10
      retryDelayMs: 300, // default: 300ms
    },
  },
});
```

`store.type = 'redis'` requires `redis.url` (or `REDIS_URL`) and fails startup if unavailable.

## Planned Tasks

Next tasks:

- [ ] Prometheus metrics for limits, bans, and rule hits.
- [ ] Canary mode for new rules (log-only before enforce).
- [ ] Slowdown action (response delay without blocking).
- [ ] Security event stream output (structured JSON + optional webhook).
- [ ] Cluster/worker stress tests for shared Redis state.
- [ ] Redis outage tests for `auto` fallback and strict `redis` mode.
