import { IpsRuntime } from './runtime';

let runtime: IpsRuntime | null = null;

export function setIpsRuntime(next: IpsRuntime): void {
  runtime = next;
}

export function getIpsRuntime(): IpsRuntime | null {
  return runtime;
}

export function clearIpsRuntime(): void {
  runtime = null;
}
