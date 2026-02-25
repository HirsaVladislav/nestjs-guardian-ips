/** Supported normalization pipeline steps for rule matching. */
export type NormalizeStep = 'lowercase' | 'urlDecode' | 'normalizePath';
/** Applies normalization steps in order to a string used in rule matching. */
export declare function applyNormalization(input: string, steps?: NormalizeStep[]): string;
