import { BlockList, isIP } from 'node:net';
import { IpsResolvedClientIpOptions, IpsResolvedOptions } from '../module/options';

interface RequestLike {
  headers?: Record<string, string | string[] | undefined>;
  ip?: string;
  ips?: string[];
  socket?: { remoteAddress?: string };
  connection?: { remoteAddress?: string };
  method?: string;
  path?: string;
  originalUrl?: string;
  url?: string;
}

export function getHeader(req: RequestLike, name: string): string | undefined {
  const headers = req.headers ?? {};
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  if (!key) {
    return undefined;
  }
  const value = headers[key];
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

export function extractClientIp(req: RequestLike, options: IpsResolvedOptions): string {
  const remoteIp = extractRemoteIp(req);
  const config = options.clientIp;

  if (config.mode === 'hops') {
    const byHops = extractClientIpByHops(req, remoteIp, config);
    if (byHops) {
      return byHops;
    }
  } else if (remoteIp && isTrustedProxyRemote(remoteIp, config)) {
    const byTrustedHeaders = extractFromHeadersPriority(req, config);
    if (byTrustedHeaders) {
      return byTrustedHeaders;
    }
  }

  if (remoteIp) {
    return remoteIp;
  }

  return '0.0.0.0';
}

export function extractPath(req: RequestLike): string {
  const candidate = req.originalUrl ?? req.url ?? req.path ?? '/';
  const noQuery = candidate.split('?')[0] ?? '/';
  return noQuery || '/';
}

export function extractMethod(req: RequestLike): string {
  return (req.method ?? 'GET').toUpperCase();
}

export function stripIpv6Prefix(ip: string): string {
  if (ip.startsWith('::ffff:')) {
    return ip.slice(7);
  }
  return ip;
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  const normalizedIp = normalizeIpCandidate(ip);
  if (!normalizedIp) {
    return false;
  }

  const normalizedCidr = cidr.trim();
  if (!normalizedCidr.includes('/')) {
    const target = normalizeIpCandidate(normalizedCidr);
    return Boolean(target && target === normalizedIp);
  }

  const [baseIp, maskPart] = normalizedCidr.split('/');
  const normalizedBase = normalizeIpCandidate(baseIp);
  const maskBits = Number(maskPart);
  if (!normalizedBase || !Number.isInteger(maskBits)) {
    return false;
  }

  const family = isIP(normalizedBase);
  if (!family || isIP(normalizedIp) !== family) {
    return false;
  }

  try {
    const blockList = new BlockList();
    blockList.addSubnet(normalizedBase, maskBits, family === 6 ? 'ipv6' : 'ipv4');
    return blockList.check(normalizedIp, family === 6 ? 'ipv6' : 'ipv4');
  } catch {
    return false;
  }
}

function extractRemoteIp(req: RequestLike): string | undefined {
  const candidates = [req.socket?.remoteAddress, req.connection?.remoteAddress, req.ip, ...(req.ips ?? [])];
  for (const candidate of candidates) {
    const normalized = normalizeIpCandidate(candidate);
    if (normalized) {
      return normalized;
    }
  }
  return undefined;
}

function extractClientIpByHops(
  req: RequestLike,
  remoteIp: string | undefined,
  config: IpsResolvedClientIpOptions,
): string | undefined {
  const chain = extractForwardChain(req, config.headersPriority);
  if (chain.length > 0) {
    const fullChain = remoteIp ? [...chain, remoteIp] : [...chain];
    let index = fullChain.length - 1 - config.hops;
    if (index < 0) {
      index = 0;
    }

    for (let i = index; i >= 0; i -= 1) {
      const candidate = fullChain[i];
      const fromHeaders = i < chain.length;
      if (fromHeaders && config.denyPrivateIpsFromHeaders && isPrivateOrLocalIp(candidate)) {
        continue;
      }
      return candidate;
    }
  }

  return extractFromHeadersPriority(req, config);
}

function extractForwardChain(req: RequestLike, headersPriority: string[]): string[] {
  for (const header of headersPriority) {
    if (header === 'x-forwarded-for') {
      const value = getHeader(req, header);
      if (!value) {
        continue;
      }
      const parsed = parseXForwardedFor(value);
      if (parsed.length > 0) {
        return parsed;
      }
      continue;
    }

    if (header === 'forwarded') {
      const value = getHeader(req, header);
      if (!value) {
        continue;
      }
      const parsed = parseForwardedFor(value);
      if (parsed.length > 0) {
        return parsed;
      }
    }
  }

  return [];
}

function extractFromHeadersPriority(req: RequestLike, config: IpsResolvedClientIpOptions): string | undefined {
  for (const header of config.headersPriority) {
    const candidates = extractHeaderCandidates(req, header);
    for (const candidate of candidates) {
      if (config.denyPrivateIpsFromHeaders && isPrivateOrLocalIp(candidate)) {
        continue;
      }
      return candidate;
    }
  }
  return undefined;
}

function extractHeaderCandidates(req: RequestLike, header: string): string[] {
  const value = getHeader(req, header);
  if (!value) {
    return [];
  }

  if (header === 'x-forwarded-for') {
    return parseXForwardedFor(value);
  }

  if (header === 'forwarded') {
    return parseForwardedFor(value);
  }

  return value
    .split(',')
    .map((candidate) => normalizeIpCandidate(candidate))
    .filter((candidate): candidate is string => Boolean(candidate));
}

function parseXForwardedFor(value: string): string[] {
  return value
    .split(',')
    .map((part) => normalizeIpCandidate(part))
    .filter((candidate): candidate is string => Boolean(candidate));
}

function parseForwardedFor(value: string): string[] {
  const out: string[] = [];
  const entries = value.split(',');
  for (const entry of entries) {
    const params = entry.split(';');
    for (const param of params) {
      const [rawKey, ...rawValueParts] = param.split('=');
      if (!rawKey || rawKey.trim().toLowerCase() !== 'for') {
        continue;
      }

      const rawValue = rawValueParts.join('=').trim();
      const candidate = normalizeIpCandidate(rawValue);
      if (candidate) {
        out.push(candidate);
      }
      break;
    }
  }

  return out;
}

function normalizeIpCandidate(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }

  let candidate = value.trim();
  if (!candidate) {
    return undefined;
  }

  if (candidate.startsWith('"') && candidate.endsWith('"')) {
    candidate = candidate.slice(1, -1).trim();
  }

  if (!candidate || candidate.toLowerCase() === 'unknown' || candidate === '_hidden') {
    return undefined;
  }

  if (candidate.startsWith('[')) {
    const bracketEnd = candidate.indexOf(']');
    if (bracketEnd > 1) {
      candidate = candidate.slice(1, bracketEnd);
    }
  } else if (candidate.includes(':') && isIP(candidate) !== 6) {
    const maybePort = candidate.match(/^(.+):(\d+)$/);
    if (maybePort && isIP(maybePort[1]) === 4) {
      candidate = maybePort[1];
    }
  }

  candidate = stripIpv6Prefix(candidate);
  if (isIP(candidate) === 0) {
    return undefined;
  }

  return candidate;
}

function isTrustedProxyRemote(remoteIp: string, config: IpsResolvedClientIpOptions): boolean {
  if (typeof config.isTrustedProxy === 'function') {
    try {
      if (config.isTrustedProxy(remoteIp)) {
        return true;
      }
    } catch {
      // ignore user callback errors
    }
  }

  return config.trustedProxyCidrs.some((cidr) => isIpInCidr(remoteIp, cidr));
}

function isPrivateOrLocalIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) {
    return (
      isIpInCidr(ip, '10.0.0.0/8') ||
      isIpInCidr(ip, '172.16.0.0/12') ||
      isIpInCidr(ip, '192.168.0.0/16') ||
      isIpInCidr(ip, '127.0.0.0/8') ||
      isIpInCidr(ip, '169.254.0.0/16') ||
      isIpInCidr(ip, '100.64.0.0/10') ||
      isIpInCidr(ip, '0.0.0.0/8')
    );
  }

  if (family === 6) {
    const normalized = ip.toLowerCase();
    return (
      normalized === '::1' ||
      normalized === '::' ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('fe8') ||
      normalized.startsWith('fe9') ||
      normalized.startsWith('fea') ||
      normalized.startsWith('feb')
    );
  }

  return false;
}
