/** Applies response headers across common response adapters (`setHeader`, `header`, `set`). */
export function applyHeaders(res: Record<string, unknown>, headers: Record<string, string>): void {
  for (const [key, value] of Object.entries(headers)) {
    if (typeof (res as { setHeader?: (name: string, value: string) => void }).setHeader === 'function') {
      (res as { setHeader: (name: string, value: string) => void }).setHeader(key, value);
      continue;
    }

    if (typeof (res as { header?: (name: string, value: string) => void }).header === 'function') {
      (res as { header: (name: string, value: string) => void }).header(key, value);
      continue;
    }

    if (typeof (res as { set?: (name: string, value: string) => void }).set === 'function') {
      (res as { set: (name: string, value: string) => void }).set(key, value);
    }
  }
}
