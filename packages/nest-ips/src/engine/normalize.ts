export type NormalizeStep = 'lowercase' | 'urlDecode' | 'normalizePath';

export function applyNormalization(input: string, steps: NormalizeStep[] = []): string {
  let value = input;

  for (const step of steps) {
    if (step === 'lowercase') {
      value = value.toLowerCase();
      continue;
    }

    if (step === 'urlDecode') {
      try {
        value = decodeURIComponent(value);
      } catch {
        // Keep original value when URI sequence is invalid.
      }
      continue;
    }

    if (step === 'normalizePath') {
      value = normalizePathValue(value);
    }
  }

  return value;
}

function normalizePathValue(path: string): string {
  const noQuery = path.split('?')[0] ?? path;
  const compact = noQuery.replace(/\/{2,}/g, '/');
  const clean = compact.replace(/\/.\//g, '/');
  return clean || '/';
}
