export type NormalizeStep = 'lowercase' | 'urlDecode' | 'normalizePath';
export declare function applyNormalization(input: string, steps?: NormalizeStep[]): string;
