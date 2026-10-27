import React, { useCallback, useEffect, useState, DragEvent } from "react";
import QRCode from "qrcode";
import { call, fmtAsset } from "../lib/api";
import { CopyButton } from "./Share";

export interface ReceivedInfo {
  amount: number;
  ticker: string;
  decimals: number;
}

interface Stealth {
  index: number;
  address: string;
}

/** Plain-language guide to every address / key type. */
const TYPES = [
  {
    icon: "🏷️",
    name: "Normal address",
    color: "--color-cyan",
    tag: "zc1… · recoverable from your phrase",
    body: "Your everyday address. Share it to get paid: payments land on-chain and auto-credit when you Refresh. Your 24-word phrase restores it, and your view key can see what arrives here.",
  },
  {
    icon: "🕶️",
    name: "Stealth address",
    color: "--color-purple",
    tag: "zc1… (stealth) · NOT in your phrase",
    body: "Maximum privacy. A payment arrives as an encrypted FILE (nothing readable is left on-chain) and is invisible even to your own view key. Each stealth address has its own key that your phrase will NOT restore, so back up the key.",
  },
  {
    icon: "💵",
    name: "Bearer coin",
    color: "--color-yellow",
    tag: "file · coin + gas",
    body: "Not an address: a file from the Send tab. Send it over any chat. Opening it in a wallet credits the full amount, and the file includes 0.01 ZCRYPT gas so a brand-new wallet can claim it. Until that claim is in a block, anyone with the file can take it.",
  },
  {
    icon: "🔎",
    name: "View key",
    color: "--color-green",
    tag: "read-only · for auditors",
    body: "A key you can GIVE someone so they can see the amounts of payments to your NORMAL address, and nothing else. It can never spend, and cannot see stealth or bearer coins. Find it under Settings.",
  },
  {
    icon: "₿",
    name: "Bitcoin deposit address",
    color: "--color-cyan",
    tag: "bc1… · derived from the same phrase",
    body: "Real Bitcoin, on the Bitcoin chain. Deposit here, then shield it into private zBTC under Bridge, or send it out again under Send.",
  },
];

const QR_COLOR = { dark: "#0b0f19", light: "#ffffff" };

/**
 * QR-friendly form of an address. A `zc1…` address is 2,008 characters (it carries a
 * 1,184-byte ML-KEM key), and bech32 is case-insensitive, so it is encoded in upper case:
 * the QR alphanumeric mode then spends 5.5 bits per character instead of 8, and the code
 * drops from version 40 to about version 30. The scanner lowercases it again.
 */
function qrText(text: string): string {
  return /^[a-z0-9]+$/.test(text) ? text.toUpperCase() : text;
}

/** Pixels per module that fit `n` modules (quiet zone included) into `px` pixels. */
function fitScale(text: string, px: number): number {
  const n = QRCode.create(qrText(text), { errorCorrectionLevel: "L" }).modules.size + 8;
  return Math.max(1, Math.floor(px / n));
}

/**
 * The text as a QR image (data URL), or "" while it renders or when there is no text.
 * Rendered at an integer number of pixels per module and shown at its natural size, so
 * every module is a crisp square on screen (a fixed CSS width resamples the grid, and a
 * phone camera then fails to lock on). `scale` is CSS pixels per module.
 */
function useQr(text: string, scale: number): string {
  const [qr, setQr] = useState("");
  useEffect(() => {
    if (!text) return setQr("");
    QRCode.toDataURL(qrText(text), { margin: 4, scale, errorCorrectionLevel: "L", color: QR_COLOR })
      .then(setQr)
      .catch(() => setQr(""));
  }, [text, scale]);
  return qr;
}

/**
 * Full-window QR for scanning. An address code has about 150 modules a side, so the
 * tile preview is far too small for a phone camera; this renders it at the largest
 * integer scale that fits the window, on white, and closes on any click or Escape.
 */
function QrOverlay({ text, title, onClose }: { text: string; title: string; onClose: () => void }) {
  const [src, setSrc] = useState("");
  useEffect(() => {
    const px = Math.min(window.innerWidth, window.innerHeight - 120) * 0.92;
    QRCode.toDataURL(qrText(text), { margin: 4, scale: fitScale(text, px), errorCorrectionLevel: "L", color: QR_COLOR })
      .then(setSrc)
      .catch(() => setSrc(""));
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [text, onClose]);
  return (
    <div className="qr-overlay" onClick={onClose} role="dialog" aria-label={title}>
      <div className="qr-overlay-title">{title}</div>
      {src ? <img src={src} alt={`QR code: ${title}`} /> : null}
      <div className="qr-overlay-hint">Scan it with the mobile wallet. Click anywhere, or press Escape, to close.</div>
    </div>
  );
}

/** One address with its QR code, the address text and a copy button. */
function AddressTile({
  icon, title, tag, color, address, qr, note, empty, extra, onShowQr,
}: {
  icon: string;
  title: string;
  tag: string;
  color: string;
  address: string;
  qr: string;
  note: string;
  /** Shown in place of the QR and address when there is no address yet. */
  empty?: React.ReactNode;
  /** Controls specific to this address, rendered under the address line. */
  extra?: React.ReactNode;
  onShowQr: (text: string, title: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const short = address.length > 24 ? `${address.slice(0, 12)}…${address.slice(-8)}` : address;
  return (
    <div className="card addr-tile">
      <div className="addr-tile-title" style={{ color }}>
        {icon} {title}
      </div>
      <div className="addr-tile-tag">{tag}</div>
      {address ? (
        <>
          <button className="qr-tile qr-tile-btn" onClick={() => onShowQr(address, title)} title="Show a large QR code for scanning">
            {qr ? <img src={qr} alt={`QR code: ${title}`} /> : null}
          </button>
          <button className="btn-link" onClick={() => onShowQr(address, title)}>⛶ Show large QR to scan</button>
          <div className="addr-line">
            <code title={address} style={{ color }} className={expanded ? "full" : ""}>
              {expanded ? address : short}
            </code>
            <span className="addr-actions">
              <button className="copy-btn" onClick={() => setExpanded((e) => !e)}>
                {expanded ? "Collapse" : "Expand"}
              </button>
              <CopyButton text={address} label="⧉ Copy" />
            </span>
          </div>
          {extra}
        </>
      ) : (
        <div className="addr-tile-empty">{empty ?? <span style={{ opacity: 0.5 }}>…</span>}</div>
      )}
      <div className="addr-tile-note">{note}</div>
    </div>
  );
}

/**
 * Receive: everything about getting paid in one place. Your addresses (normal, stealth,
 * Bitcoin), the drop zone that claims a coin file or an encrypted note, and the view key.
 */
export default function Receive({
  onReceived,
  incoming = "",
  onConsumed,
}: {
  onReceived: (r: ReceivedInfo) => void;
  /** Text of a `.zcrypt` file the OS opened with the app; credited as soon as it arrives. */
  incoming?: string;
  onConsumed?: () => void;
}) {
  // Addresses & keys
  const [normal, setNormal] = useState("");
  const [btcAddr, setBtcAddr] = useState("");
  const [stealth, setStealth] = useState<Stealth[]>([]);
  // Backup seeds are spend secrets: they are never bulk-fetched. Each is revealed one at a
  // time, behind a fresh password check (reveal_stealth_backup), and held only in local state.
  const [revealed, setRevealed] = useState<Record<number, string>>({});
  const [pwFor, setPwFor] = useState<number | null>(null);
  const [pw, setPw] = useState("");
  const [revealErr, setRevealErr] = useState("");
  const [stealthBusy, setStealthBusy] = useState(false);
  const [err, setErr] = useState("");
  // The shielded tile shows one stealth address at a time: the newest, or the one picked.
  const [stealthIdx, setStealthIdx] = useState<number | null>(null);
  const shown = stealth.find((x) => x.index === stealthIdx) ?? stealth[stealth.length - 1];
  const latestStealth = shown?.address ?? "";
  const [bigQr, setBigQr] = useState<{ text: string; title: string } | null>(null);
  const showQr = useCallback((text: string, title: string) => setBigQr({ text, title }), []);
  const hideQr = useCallback(() => setBigQr(null), []);
  // Tile previews: a 2,008-character address needs about 150 modules a side, so the
  // preview is 1 px per module and only the overlay (QrOverlay) is meant to be scanned.
  const normalQr = useQr(normal, 1);
  const stealthQr = useQr(latestStealth, 1);
  const btcQr = useQr(btcAddr, 4);

  // Drop zone
  const [blob, setBlob] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [state, setState] = useState<"idle" | "ok" | "err" | "warn">("idle");
  const [msg, setMsg] = useState("");

  const load = useCallback(() => {
    call<string>("get_address").then(setNormal).catch(() => {});
    call<Stealth[]>("list_stealth_addresses").then(setStealth).catch(() => {});
    // Derived locally from the phrase: no network call, nothing revealed to anyone.
    call<string>("btc_deposit_address").then(setBtcAddr).catch(() => setBtcAddr(""));
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  // A file handed over by the OS behaves like a drop: show it, then credit it.
  useEffect(() => {
    if (!incoming || busy) return;
    setBlob(incoming);
    receive(incoming).finally(() => onConsumed?.());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incoming]);

  async function newStealth() {
    setErr("");
    setStealthBusy(true);
    try {
      await call("new_stealth_address");
      load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setStealthBusy(false);
    }
  }

  async function revealBackup(index: number) {
    setRevealErr("");
    try {
      const seed = await call<string>("reveal_stealth_backup", { index, password: pw });
      setRevealed((r) => ({ ...r, [index]: seed }));
      setPwFor(null);
      setPw("");
    } catch {
      setRevealErr("Wrong password.");
    }
  }

  function cancelReveal() {
    setPwFor(null);
    setPw("");
    setRevealErr("");
  }

  async function receive(text: string) {
    const s = text.trim();
    if (!s) return;
    setBusy(true);
    setState("idle");
    try {
      if (s.startsWith("zcrypt-receipt/1")) {
        const r = await call<{ on_chain: boolean; names_recipient: boolean; summary: string }>("verify_receipt", { text: s });
        setState(r.on_chain && r.names_recipient ? "ok" : r.on_chain ? "warn" : "err");
        setMsg(r.summary);
        return;
      }
      if (s.startsWith("zcb1")) {
        throw new Error("a bearer coin is a zcrypt-bearer/1 file with a coin line and a gas line");
      }
      const isBearer = s.startsWith("zcrypt-bearer/1");
      const cmd = isBearer ? "claim_bearer" : "receive_coin";
      const args = isBearer ? { token: s } : { note: s };
      const r = await call<{ amount: number; coin_id: string; ticker: string; decimals: number }>(cmd, args);
      setState("ok");
      setMsg(`Received ${fmtAsset(r.amount, r.decimals)} ${r.ticker}`);
      setBlob("");
      onReceived({ amount: r.amount, ticker: r.ticker, decimals: r.decimals });
    } catch (e) {
      setState("err");
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  }

  function onDragOver(e: DragEvent) {
    e.preventDefault();
    if (!dragging) setDragging(true);
  }
  function onDragLeave(e: DragEvent) {
    // only clear when leaving the dropzone itself, not a child
    if (e.currentTarget === e.target) setDragging(false);
  }
  async function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      const text = await file.text();
      setBlob(text.trim());
      receive(text);
      return;
    }
    const text = e.dataTransfer.getData("text");
    if (text) {
      setBlob(text.trim());
      receive(text);
    }
  }

  const cls = dragging ? "dragging" : state === "ok" ? "success" : state === "err" ? "error" : "";

  return (
    <div>
      <h2 className="view-title">📥 Receive</h2>

      {/* Your addresses: one tile per address, each with its QR code and the address text.
          Whitelisted assets with a native chain get a tile here as they are added. */}
      <div className="addr-tiles">
        <AddressTile
          icon="🏷️"
          title="Your ZCRYPT recoverable address"
          tag="zc1… · restored by your recovery phrase"
          color="var(--color-cyan)"
          address={normal}
          qr={normalQr}
          onShowQr={showQr}
          note="Share this to get paid in ZCRYPT or any shielded asset. Your view key can see what arrives here; nobody else can."
        />
        <AddressTile
          icon="🕶️"
          title="Your ZCRYPT shielded address"
          tag="zc1… (stealth) · NOT recoverable from your phrase"
          color="var(--color-purple)"
          address={latestStealth}
          qr={stealthQr}
          onShowQr={showQr}
          note="Maximum privacy: paid with an encrypted file, invisible even to your own view key. Your recovery phrase will NOT restore it: back up its private key."
          empty={
            <button className="btn-secondary" disabled={stealthBusy} onClick={newStealth}>
              {stealthBusy ? "Creating…" : "Create a shielded address"}
            </button>
          }
          extra={shown && (
            <div className="stealth-tools">
              {stealth.length > 1 && (
                <select value={shown.index} onChange={(e) => setStealthIdx(Number(e.target.value))}>
                  {stealth.map((x) => (
                    <option key={x.index} value={x.index}>
                      Shielded #{x.index} · {x.address.slice(0, 10)}…{x.address.slice(-6)}
                    </option>
                  ))}
                </select>
              )}
              {revealed[shown.index] ? (
                <>
                  <div className="mono-box" style={{ color: "var(--color-yellow)", wordBreak: "break-all", fontSize: "0.74rem", textAlign: "left" }}>
                    {revealed[shown.index]}
                  </div>
                  <CopyButton text={revealed[shown.index]} label="⧉ Copy private key" />
                </>
              ) : pwFor === shown.index ? (
                <div className="stealth-reveal">
                  <input
                    type="password"
                    placeholder="Password to reveal"
                    value={pw}
                    autoFocus
                    onChange={(e) => setPw(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && revealBackup(shown.index)}
                  />
                  <span className="addr-actions">
                    <button className="copy-btn" onClick={() => revealBackup(shown.index)}>Reveal</button>
                    <button className="btn-link" onClick={cancelReveal}>Cancel</button>
                  </span>
                  {revealErr && <span style={{ color: "var(--color-red, #e66)", fontSize: "0.78rem" }}>{revealErr}</span>}
                </div>
              ) : (
                <span className="addr-actions">
                  <button className="btn-link" onClick={() => { setPwFor(shown.index); setPw(""); setRevealErr(""); }}>
                    🔑 Reveal private key
                  </button>
                  <button className="btn-link" disabled={stealthBusy} onClick={newStealth}>
                    {stealthBusy ? "…" : "+ New shielded address"}
                  </button>
                </span>
              )}
            </div>
          )}
        />
        <AddressTile
          icon="₿"
          title="Your Bitcoin address"
          tag="bc1… · restored by your recovery phrase"
          color="var(--color-yellow)"
          address={btcAddr}
          qr={btcQr}
          onShowQr={showQr}
          note="Real BTC on the Bitcoin chain. Deposit here, then shield it into zBTC under Bridge."
        />
      </div>

      {/* The drop zone: a coin file, an encrypted note, or a receipt to check. */}
      <div className={`dropzone compact ${cls}`} style={{ marginTop: "1.2rem" }} onDragOver={onDragOver} onDragEnter={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}>
        <div className="drop-icon">{dragging ? "⬇️" : state === "ok" ? "✓" : state === "err" ? "✗" : "💎"}</div>
        <div style={{ fontWeight: "bold", color: dragging ? "var(--color-cyan)" : undefined }}>
          {dragging ? "Drop the coin to receive it" : "Got a coin file or a note? Drop it here"}
        </div>
        <div style={{ width: "100%", padding: "0 1.2rem", boxSizing: "border-box" }}>
          <textarea
            className="mnemonic-input"
            value={blob}
            onChange={(e) => setBlob(e.target.value)}
            placeholder="or paste a bearer coin file, an encrypted stealth note, or a payment receipt"
            style={{ minHeight: 90 }}
          />
          <button className="btn-primary btn-block" style={{ marginTop: "0.6rem" }} disabled={busy} onClick={() => receive(blob)}>
            {busy ? "Verifying…" : "Receive"}
          </button>
          {state !== "idle" && !dragging && (
            <div className={`msg ${state === "ok" ? "ok" : state === "warn" ? "warn" : "err"}`}>{msg}</div>
          )}
          <div style={{ fontSize: "0.74rem", opacity: 0.6, marginTop: "0.5rem" }}>
            A receipt pasted here is checked against the chain; it moves nothing. Never drop a coin into anything but your own wallet.
          </div>
        </div>
      </div>

      {/* Plain-language guide, folded away */}
      <details className="card guide" style={{ marginTop: "1.2rem" }}>
        <summary>Which one should I use?</summary>
        {TYPES.map((t) => (
          <div className="card-row" key={t.name} style={{ alignItems: "flex-start" }}>
            <div style={{ flex: 1 }}>
              <div style={{ color: `var(${t.color})`, fontWeight: "bold" }}>
                {t.icon} {t.name}
              </div>
              <div style={{ fontSize: "0.72rem", opacity: 0.55, margin: "0.15rem 0 0.35rem" }}>{t.tag}</div>
              <div style={{ fontSize: "0.85rem", opacity: 0.85, lineHeight: 1.5 }}>{t.body}</div>
            </div>
          </div>
        ))}
      </details>

      {err && <div className="msg err">{err}</div>}
      {bigQr && <QrOverlay text={bigQr.text} title={bigQr.title} onClose={hideQr} />}
    </div>
  );
}
