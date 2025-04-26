
export function ensureBase64Padding(input: string): string {
  const padding = input.length % 4;
  return padding === 0 ? input : input + "=".repeat(4 - padding);
}

export function isLikelyBase64(str: string): boolean {
  return /^[A-Za-z0-9+/=]+$/.test(str) && str.length % 4 === 0;
}

export function isPrintable(str: string): boolean {
  const printable = str.replace(/[^\x20-\x7E]/g, "").length;
  return printable / str.length >= 0.7;
}

export function safeDecode<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback;
  }
}
