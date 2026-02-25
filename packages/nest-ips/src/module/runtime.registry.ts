import { IpsRuntime } from './runtime';

let runtime: IpsRuntime | null = null;

/** Stores module-created runtime for access from middleware/filter instances created outside DI. */
export function setIpsRuntime(next: IpsRuntime): void {
  runtime = next;
}

/** Returns shared runtime instance registered by `IpsModule`, if available. */
export function getIpsRuntime(): IpsRuntime | null {
  return runtime;
}

/** Clears shared runtime reference during module shutdown. */
export function clearIpsRuntime(): void {
  runtime = null;
}
