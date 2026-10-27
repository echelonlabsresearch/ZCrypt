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
 * Bring a typed amount into the plain `digits.digits` form the parser expects. The iOS
 * decimal keypad inserts the REGION's separator, so a phone set to a European region
 * types "0,5" (and an Arabic-region one "0٫5"); some keyboards also pad with a no-break
 * space. A lone comma with no dot is the decimal separator; when both appear, the last
 * one is the decimal separator and the other is thousands grouping.
 */
export function normalizeAmount(amount: string): string {
  let s = amount.replace(/[\s\u00a0\u202f'_]/g, "").replace(/[\u066b\u2396]/g, ".");
  const dot = s.lastIndexOf(".");
  const comma = s.lastIndexOf(",");
  const grouped = (sep: string) => new RegExp(`^\\d{1,3}(\\${sep}\\d{3})+$`);
  if (comma >= 0 && dot < 0) {
    if (grouped(",").test(s)) s = s.replace(/,/g, "");
    else if (s.split(",").length === 2) s = s.replace(",", ".");
  } else if (comma >= 0 && dot >= 0) {
    const [whole, frac, sep] = comma > dot ? [s.slice(0, comma), s.slice(comma + 1), "."] : [s.slice(0, dot), s.slice(dot + 1), ","];
    if (grouped(sep).test(whole)) s = `${whole.replace(/[.,]/g, "")}.${frac}`;
  }
  return s;
}

/**
 * Parse a decimal amount string into integer base units without IEEE float.
 * Accepts "1", "1.5", ".5", "0.00000001". Rejects scientific notation and empty.
 */
export function toBaseAsset(amount: string, decimals = ZCRYPT_DECIMALS): number {
  const s = normalizeAmount(amount);
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
/** What each whitelisted ticker is pegged to, for the portfolio rows. Unknown tickers fall back to the ticker itself. */
export const WHITELIST_NAMES: Record<string, string> = {
  ZBTC: "Bitcoin",
  ZETH: "Ether",
  ZSOL: "Solana",
  ZBNB: "BNB",
  ZTON: "Toncoin",
  ZDAI: "Dai",
  ZUSDT: "Tether",
  ZGOLD: "Gold",
};
export const whitelistName = (ticker: string) => WHITELIST_NAMES[ticker.toUpperCase()] ?? ticker;
/** Case-insensitive, like tickers on the chain. */
export const isWhitelisted = (ticker: string, list: string[]) => list.some((t) => t.toUpperCase() === ticker.toUpperCase());

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

/**
 * Copy a SECRET (recovery phrase, bearer coin, stealth note). The clipboard is cleared
 * after `clearMs` if it still holds the text; if the clipboard cannot be read back it is
 * cleared unconditionally (security over convenience).
 */
let lastSecret: string | null = null;

export async function copySensitive(text: string, clearMs = 60_000): Promise<void> {
  await navigator.clipboard.writeText(text);
  lastSecret = text;
  setTimeout(async () => {
    await clearIfStillHolds(text);
  }, clearMs);
}

async function clearIfStillHolds(text: string): Promise<void> {
  try {
    const cur = await navigator.clipboard.readText();
    if (cur === text) await navigator.clipboard.writeText("");
  } catch {
    try {
      await navigator.clipboard.writeText("");
    } catch {
      /* clipboard unavailable */
    }
  }
  if (lastSecret === text) lastSecret = null;
}

/**
 * Clear the clipboard NOW if it still holds the last secret copied. Called when the wallet
 * locks or the window closes, so a lock inside the 60 s window does not leave a recovery
 * phrase or bearer coin behind.
 */
export async function clearSensitiveClipboard(): Promise<void> {
  if (lastSecret === null) return;
  await clearIfStillHolds(lastSecret);
}

/** Save `content` to a real file (Downloads) via the backend; returns its path. */
export async function saveFile(filename: string, content: string): Promise<string> {
  return call<string>("save_export", { filename, content });
}

/** Open a URL / file path with the OS default handler (reveal an exported file). */
export async function openExternal(target: string): Promise<void> {
  await call<boolean>("open_external", { target });
}
