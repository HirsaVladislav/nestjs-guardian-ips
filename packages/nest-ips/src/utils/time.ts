/** Returns current timestamp in milliseconds. */
export function nowMs(): number {
  return Date.now();
}

/** Returns current UNIX timestamp in seconds. */
export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}
