import { invoke } from "@tauri-apps/api/core";

interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

/** Invoke a Tauri command, unwrapping the `ApiResponse<T>` envelope. */
export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const res = await invoke<ApiResponse<T>>(cmd, args);
  if (!res.success) throw new Error(res.error || "command failed");
  return res.data as T;
}

/** 1 ZCRYPT = 1,000,000 atomic base units (6 decimals) — the protocol's atomic unit.
 *  Multi-limb values let a single coin hold up to 2^52-1 base units, so per-coin
 *  caps are no longer a concern. Shielded assets carry their own decimals (zBTC = 8). */
export const BASE = 1_000_000;
export const ZCRYPT_DECIMALS = 6;

/** Format `base` units of an asset with `decimals` decimal places (default ZCRYPT). */
export const fmtAsset = (base: number, decimals = ZCRYPT_DECIMALS): string =>
  (base / Math.pow(10, decimals)).toLocaleString(undefined, { maximumFractionDigits: decimals });

/**
 * Parse a decimal amount string into integer base units without IEEE float.
 * Accepts "1", "1.5", ".5", "0.00000001". Rejects scientific notation and empty.
 */
export function toBaseAsset(amount: string, decimals = ZCRYPT_DECIMALS): number {
  const s = amount.trim();
  if (!s || !/^\d*\.?\d+$/.test(s)) {
    throw new Error(`invalid amount: ${amount}`);
  }
  const neg = s.startsWith("-");
  if (neg) throw new Error("amount must be non-negative");
  const [wholePart, fracPart = ""] = s.split(".");
  if (fracPart.length > decimals) {
    throw new Error(`too many decimal places (max ${decimals})`);
  }
  const whole = wholePart === "" ? "0" : wholePart;
  const frac = fracPart.padEnd(decimals, "0");
  // BigInt for intermediate so we don't lose precision near 2^53.
  const base = BigInt(whole) * 10n ** BigInt(decimals) + BigInt(frac || "0");
  if (base > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("amount too large for safe integer transport");
  }
  return Number(base);
}

// ZCRYPT-specific convenience wrappers (unchanged call sites keep working).
export const fmt = (base: number): string => fmtAsset(base, ZCRYPT_DECIMALS);
export const toBase = (zcrypt: string): number => toBaseAsset(zcrypt, ZCRYPT_DECIMALS);

/** A shielded asset the wallet holds (from `held_assets`). `asset_id` is a STRING — it's
 *  a hash-derived u64 that exceeds JS's 2^53 safe-integer range, so it must never be a
 *  JS number (that silently corrupts the low digits and breaks sends). */
export interface HeldAsset {
  asset_id: string;
  ticker: string;
  decimals: number;
  balance: number;
}

export const trunc = (a: string, head = 18, tail = 8): string =>
  a.length > head + tail + 1 ? `${a.slice(0, head)}…${a.slice(-tail)}` : a;

export async function copy(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}

/** Save `content` to a real file (Downloads) via the backend; returns its path. */
export async function saveFile(filename: string, content: string): Promise<string> {
  return call<string>("save_export", { filename, content });
}

/** Open a URL / file path with the OS default handler (share links, reveal file). */
export async function openExternal(target: string): Promise<void> {
  await call<boolean>("open_external", { target });
}

/** Share links for a text payload (a bearer coin or stealth note). */
export function shareLinks(text: string, subject = "A ZCrypt payment for you") {
  const t = encodeURIComponent(text);
  const s = encodeURIComponent(subject);
  return {
    whatsapp: `https://wa.me/?text=${t}`,
    telegram: `https://t.me/share/url?url=${t}&text=${s}`,
    email: `mailto:?subject=${s}&body=${t}`,
  };
}
