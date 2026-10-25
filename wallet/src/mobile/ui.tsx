import { ReactNode, useEffect, useState } from "react";
import { call } from "../lib/api";

// ---------- icons (24x24, 1.8px strokes) ----------
export type IconName =
  | "home"
  | "send"
  | "receive"
  | "history"
  | "gear"
  | "faceid"
  | "copy"
  | "share"
  | "check"
  | "close"
  | "chevron"
  | "back"
  | "backspace"
  | "refresh"
  | "lock"
  | "file"
  | "paste"
  | "shield"
  | "warn";

const PATHS: Record<IconName, ReactNode> = {
  home: (
    <>
      <rect x="3.5" y="3.5" width="7" height="7" rx="2" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="2" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="2" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="2" />
    </>
  ),
  send: (
    <>
      <path d="M7 17 17 7" />
      <path d="M9 7h8v8" />
    </>
  ),
  receive: (
    <>
      <path d="M12 4v13" />
      <path d="m6 11 6 6 6-6" />
      <path d="M5 20h14" />
    </>
  ),
  history: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </>
  ),
  gear: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </>
  ),
  faceid: (
    <>
      <path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2" />
      <path d="M9 9.5v1.5M15 9.5v1.5M12 9.5V13h-1" />
      <path d="M9 15.5c.8.7 1.8 1 3 1s2.2-.3 3-1" />
    </>
  ),
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2.5" />
      <path d="M5 15H4.5A1.5 1.5 0 0 1 3 13.5v-9A1.5 1.5 0 0 1 4.5 3h9A1.5 1.5 0 0 1 15 4.5V5" />
    </>
  ),
  share: (
    <>
      <path d="M12 3v12" />
      <path d="m8 7 4-4 4 4" />
      <path d="M6 11v8a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-8" />
    </>
  ),
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  close: <path d="M6 6l12 12M18 6 6 18" />,
  chevron: <path d="m9 6 6 6-6 6" />,
  back: <path d="m15 6-6 6 6 6" />,
  backspace: (
    <>
      <path d="M8.5 5h11A1.5 1.5 0 0 1 21 6.5v11a1.5 1.5 0 0 1-1.5 1.5h-11L3 12z" />
      <path d="m11 9.5 5 5M16 9.5l-5 5" />
    </>
  ),
  refresh: (
    <>
      <path d="M20 12a8 8 0 1 1-2.3-5.7" />
      <path d="M20 4v5h-5" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10.5" width="14" height="10" rx="2.5" />
      <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
    </>
  ),
  file: (
    <>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <path d="M14 3v5h5" />
    </>
  ),
  paste: (
    <>
      <rect x="6" y="5" width="12" height="16" rx="2" />
      <path d="M9 5V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1" />
    </>
  ),
  shield: (
    <>
      <path d="M12 3 5 6v5c0 4.5 3 8.3 7 9.5 4-1.2 7-5 7-9.5V6z" />
      <path d="m9.5 12 1.8 1.8L15 10" />
    </>
  ),
  warn: (
    <>
      <path d="M12 4 2.5 20h19z" />
      <path d="M12 10v4M12 17.5v.1" />
    </>
  ),
};

export function Icon({ name, size = 22, stroke = 1.8 }: { name: IconName; size?: number; stroke?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {PATHS[name]}
    </svg>
  );
}

/** The app mark: a Z cut through a rounded square. */
export function Logo({ small = false }: { small?: boolean }) {
  const s = small ? 20 : 40;
  return (
    <div className={`m-logo ${small ? "small" : ""}`}>
      <svg width={s} height={s} viewBox="0 0 40 40" fill="none" aria-hidden>
        <path d="M9 10h22L9 30h22" stroke="#04111a" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}

// ---------- primitives ----------
export function Btn({
  kind = "primary",
  full = false,
  small = false,
  children,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { kind?: "primary" | "secondary" | "ghost" | "danger"; full?: boolean; small?: boolean }) {
  return (
    <button className={`m-btn ${kind} ${full ? "full" : ""} ${small ? "small" : ""}`} {...rest}>
      {children}
    </button>
  );
}

export function Segmented<T extends string>({ options, value, onChange }: { options: { value: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="m-seg">
      {options.map((o) => (
        <button key={o.value} className={o.value === value ? "active" : ""} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="m-field">
      <label>{label}</label>
      {children}
      {hint && <div className="m-hint">{hint}</div>}
    </div>
  );
}

export function Banner({ tone = "info", children }: { tone?: "ok" | "warn" | "bad" | "info"; children: ReactNode }) {
  const icon: IconName = tone === "ok" ? "check" : tone === "warn" || tone === "bad" ? "warn" : "shield";
  return (
    <div className={`m-banner ${tone === "info" ? "" : tone}`}>
      <span style={{ flex: "none", marginTop: 1 }}>
        <Icon name={icon} size={18} />
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>{children}</div>
    </div>
  );
}

/** Put the on-screen keyboard away: iOS scrolls the page under it and pushes a sheet's bottom off screen. */
export function dismissKeyboard() {
  const el = document.activeElement as HTMLElement | null;
  if (el && typeof el.blur === "function") el.blur();
  window.scrollTo(0, 0);
}

export function Sheet({ open, onClose, title, children }: { open: boolean; onClose: () => void; title?: string; children: ReactNode }) {
  useEffect(() => {
    if (open) dismissKeyboard();
  }, [open]);
  if (!open) return null;
  return (
    <div className="m-sheet-backdrop" onClick={onClose}>
      <div className="m-sheet" onClick={(e) => e.stopPropagation()}>
        <div className="m-sheet-handle" />
        {title && <h3 className="m-sheet-title">{title}</h3>}
        {children}
      </div>
    </div>
  );
}

export function Switch({ on, onChange, disabled }: { on: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return <button className={`m-switch ${on ? "on" : ""}`} disabled={disabled} onClick={() => onChange(!on)} aria-pressed={on} />;
}

export function Spinner() {
  return <div className="m-spinner" />;
}

/**
 * The 6-digit keypad. No system keyboard, so nothing on screen moves. `error` shakes the
 * dots and clears them; `resetKey` clears them silently (step changes).
 */
export function PinPad({
  onComplete,
  error,
  resetKey,
  message,
  extra,
  disabled,
}: {
  onComplete: (pin: string) => void;
  error?: string;
  resetKey?: unknown;
  message?: string;
  /** Bottom-left key: e.g. a Face ID button. */
  extra?: ReactNode;
  disabled?: boolean;
}) {
  const [pin, setPin] = useState("");
  const [shake, setShake] = useState(false);

  useEffect(() => {
    setPin("");
  }, [resetKey]);
  useEffect(() => {
    if (!error) return;
    setShake(true);
    const t = setTimeout(() => {
      setShake(false);
      setPin("");
    }, 420);
    return () => clearTimeout(t);
  }, [error]);

  function press(d: string) {
    if (disabled || shake || pin.length >= 6) return;
    const next = pin + d;
    setPin(next);
    if (next.length === 6) setTimeout(() => onComplete(next), 60);
  }

  return (
    <div style={{ width: "100%" }}>
      <div className={`m-pin-dots ${shake ? "shake" : ""}`}>
        {Array.from({ length: 6 }, (_, i) => (
          <div key={i} className={`m-pin-dot ${i < pin.length ? "on" : ""}`} />
        ))}
      </div>
      <div className={`m-pin-msg ${error ? "bad" : ""}`}>{error || message || ""}</div>
      <div className="m-keypad">
        {["1", "2", "3", "4", "5", "6", "7", "8", "9"].map((d) => (
          <button key={d} className="m-key" disabled={disabled} onClick={() => press(d)}>
            {d}
          </button>
        ))}
        <div style={{ display: "flex" }}>{extra}</div>
        <button className="m-key" disabled={disabled} onClick={() => press("0")}>
          0
        </button>
        <button className="m-key ghost" disabled={disabled || !pin} onClick={() => setPin((p) => p.slice(0, -1))} aria-label="Delete">
          <Icon name="backspace" size={26} />
        </button>
      </div>
    </div>
  );
}

/** Machine-readable errors from the mobile auth commands. */
export function authError(e: unknown): { kind: "wrong" | "locked" | "biometric" | "other"; n: number; msg: string } {
  const s = String(e instanceof Error ? e.message : e);
  const m = /^(wrong|locked|biometric):(.*)$/.exec(s);
  if (!m) return { kind: "other", n: 0, msg: s };
  if (m[1] === "biometric") return { kind: "biometric", n: 0, msg: m[2] };
  return { kind: m[1] as "wrong" | "locked", n: Number(m[2]) || 0, msg: s };
}

export function lockMessage(secs: number): string {
  if (secs >= 3600) return `Too many attempts. Try again in ${Math.ceil(secs / 3600)} h.`;
  if (secs >= 60) return `Too many attempts. Try again in ${Math.ceil(secs / 60)} min.`;
  return `Too many attempts. Try again in ${secs} s.`;
}

/** Hand a payment text to the system share sheet as a .zcrypt file; falls back to saving it. */
export async function shareFile(text: string, filename: string, save: (f: string, t: string) => Promise<string>): Promise<string> {
  // iOS: the native sheet, presented by the app itself, with a real .zcrypt document.
  if (/iPhone|iPad|iPod/.test(navigator.userAgent)) {
    try {
      await call<boolean>("share_file", { filename, content: text });
      return "shared";
    } catch (e) {
      return `Could not open the share sheet: ${String(e)}`;
    }
  }
  try {
    const file = new File([text], filename, { type: "application/x-zcrypt" });
    const nav = navigator as Navigator & { canShare?: (d: ShareData) => boolean };
    if (nav.canShare && nav.canShare({ files: [file] })) {
      await navigator.share({ files: [file], title: filename });
      return "shared";
    }
  } catch (e) {
    if ((e as Error)?.name === "AbortError") return "cancelled";
  }
  return save(filename, text);
}

export const short = (a: string, head = 10, tail = 6): string => (a.length > head + tail + 1 ? `${a.slice(0, head)}…${a.slice(-tail)}` : a);
