import { IpsRuntime } from './runtime';
/** Stores module-created runtime for access from middleware/filter instances created outside DI. */
export declare function setIpsRuntime(next: IpsRuntime): void;
/** Returns shared runtime instance registered by `IpsModule`, if available. */
export declare function getIpsRuntime(): IpsRuntime | null;
/** Clears shared runtime reference during module shutdown. */
export declare function clearIpsRuntime(): void;
