import { useCallback, useEffect, useState, type DragEvent } from "react";
import QRCode from "qrcode";
import { call, copySensitive, fmtAsset } from "../lib/api";
import { CopyButton } from "./Share";
import Success from "../mobile/Success";

export interface ReceivedInfo {
  amount: number;
  ticker: string;
  decimals: number;
}

interface Stealth {
  index: number;
  address: string;
}

const QR_COLOR = { dark: "#0b0f19", light: "#ffffff" };

type TileId = "zcrypt" | "shield" | "btc";

function shortAddr(address: string): string {
  if (!address) return "…";
  if (address.length <= 16) return address;
  return `${address.slice(0, 4)}…${address.slice(-4)}`;
}

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

/** Copy a spend secret, then clear the clipboard. */
function KeyCopy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="copy-btn"
      type="button"
      onClick={async () => {
        await copySensitive(text);
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
    >
      {done ? "Copied (clears in 60 s)" : "Copy private key"}
    </button>
  );
}

/**
 * Receive: the whole screen accepts a coin file. The three receive addresses sit in a
 * dock on the right. A shielded address is not in the recovery phrase; its key is shown
 * only after the wallet password.
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
  const [open, setOpen] = useState<TileId | null>(null);

  // Drop zone
  const [blob, setBlob] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [phase, setPhase] = useState<
    | { kind: "form" }
    | { kind: "busy"; what: "coin" | "receipt" }
    | { kind: "credited"; pretty: string }
    | { kind: "failed"; msg: string }
    | { kind: "receipt"; ok: boolean; msg: string }
  >({ kind: "form" });

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
      const info = await call<Stealth>("new_stealth_address");
      setStealth((list) => (list.some((x) => x.index === info.index) ? list : [...list, info]));
      setStealthIdx(info.index);
      setOpen("shield");
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

  function hideKey(index: number) {
    setRevealed((r) => {
      const next = { ...r };
      delete next[index];
      return next;
    });
    cancelReveal();
  }

  async function receive(text: string) {
    const s = text.trim();
    if (!s) return;
    setBusy(true);
    setDragging(false);
    const receipt = s.startsWith("zcrypt-receipt/1");
    setPhase({ kind: "busy", what: receipt ? "receipt" : "coin" });
    try {
      if (receipt) {
        const r = await call<{ on_chain: boolean; names_recipient: boolean; summary: string }>("verify_receipt", { text: s });
        setPhase({ kind: "receipt", ok: r.on_chain && r.names_recipient, msg: r.summary });
        return;
      }
      if (s.startsWith("zcb1")) {
        throw new Error("a bearer coin is a zcrypt-bearer/1 file with a coin line and a gas line");
      }
      const isBearer = s.startsWith("zcrypt-bearer/1");
      const cmd = isBearer ? "claim_bearer" : "receive_coin";
      const args = isBearer ? { token: s } : { note: s };
      const r = await call<{ amount: number; coin_id: string; ticker: string; decimals: number }>(cmd, args);
      setBlob("");
      setPhase({ kind: "credited", pretty: `${fmtAsset(r.amount, r.decimals)} ${r.ticker}` });
      onReceived({ amount: r.amount, ticker: r.ticker, decimals: r.decimals });
    } catch (e) {
      const msg = String(e instanceof Error ? e.message : e);
      if (receipt) setPhase({ kind: "receipt", ok: false, msg });
      else setPhase({ kind: "failed", msg });
    } finally {
      setBusy(false);
    }
  }

  function onDragOver(e: DragEvent) {
    e.preventDefault();
    if (!dragging) setDragging(true);
  }
  function onDragLeave(e: DragEvent) {
    if (e.currentTarget.contains(e.relatedTarget as Node)) return;
    setDragging(false);
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

  function toggle(id: TileId) {
    setOpen((cur) => (cur === id ? null : id));
  }

  const key = shown ? revealed[shown.index] : undefined;

  if (phase.kind === "busy") {
    return (
      <Success
        tone="busy"
        title={phase.what === "receipt" ? "Checking receipt" : "Receiving payment"}
        subtitle={
          phase.what === "receipt"
            ? "Looking the payment up on the chain."
            : "Checking the chain and building the claim proof on this computer. This takes a few seconds."
        }
        onDone={() => {}}
      />
    );
  }
  if (phase.kind === "credited") {
    return (
      <Success
        title={`${phase.pretty} received!`}
        subtitle="The coin is yours now and already counts in your portfolio."
        onDone={() => setPhase({ kind: "form" })}
      />
    );
  }
  if (phase.kind === "failed") {
    const claimed = /already|spent|claimed|nullifier/i.test(phase.msg);
    return (
      <Success
        tone="bad"
        title={claimed ? "Already claimed" : "Could not receive"}
        subtitle={
          claimed
            ? "This coin was claimed before, by this wallet or by someone else who had the file. It cannot be received twice."
            : "The payment could not be credited. Nothing was taken from the sender."
        }
        onDone={() => { setPhase({ kind: "form" }); setBlob(""); }}
      >
        {!claimed && <div className="m-done-detail">{phase.msg}</div>}
      </Success>
    );
  }
  if (phase.kind === "receipt") {
    return (
      <Success
        tone={phase.ok ? "ok" : "bad"}
        title={phase.ok ? "Receipt checked" : "Receipt not confirmed"}
        subtitle={phase.msg}
        onDone={() => setPhase({ kind: "form" })}
      />
    );
  }

  return (
    <div className="rx">
      <div
        className={`rx-stage${dragging ? " dragging" : ""}${open ? " has-sheet" : ""}`}
        onDragOver={onDragOver}
        onDragEnter={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
      >
        <div className="rx-copy">
          <div className="rx-kicker">Receive</div>
          <div className="rx-mark" aria-hidden="true">
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
              <path d="M8 6.5h10.2L24 12.2V25.5H8V6.5z" stroke="#35e0ff" strokeWidth="1.6" strokeLinejoin="round" />
              <path d="M18 6.8V12h5" stroke="#35e0ff" strokeWidth="1.6" strokeLinejoin="round" />
              <path d="M16 22.2V15.2M16 22.2l-2.6-2.6M16 22.2l2.6-2.6" stroke="#35e0ff" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <h2>{dragging ? "Drop the coin to receive it" : "Drop a coin file anywhere"}</h2>
          <p className="rx-lead">
            {dragging
              ? "Release to claim it into this wallet."
              : "The whole screen takes the file. Bearer coins, shielded notes, and payment receipts all land here."}
          </p>
          <div className="rx-paste">
            <textarea
              value={blob}
              onChange={(e) => setBlob(e.target.value)}
              placeholder="or paste a coin file, a shielded note, or a receipt"
            />
            <button className="btn-primary btn-block" style={{ marginTop: 10 }} disabled={busy} onClick={() => receive(blob)}>
              {busy ? "Verifying…" : "Receive"}
            </button>
            <div className="rx-fine">A receipt is only checked. It does not move funds.</div>
          </div>
        </div>

        <aside className="rx-dock" aria-label="Addresses to receive into">
          <button className={`rx-tile${open === "zcrypt" ? " open" : ""}`} type="button" aria-pressed={open === "zcrypt"} onClick={() => toggle("zcrypt")}>
            <span className="rx-glyph z">Z</span>
            <span className="rx-tile-name">ZCRYPT</span>
            <span className="rx-tile-sub">{shortAddr(normal)}</span>
          </button>
          <button className={`rx-tile${open === "shield" ? " open" : ""}`} type="button" aria-pressed={open === "shield"} onClick={() => toggle("shield")}>
            <span className="rx-glyph s" aria-hidden="true">
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                <path d="M10 2.2l6 2.2v5.1c0 3.6-2.4 6.2-6 7.5-3.6-1.3-6-3.9-6-7.5V4.4l6-2.2z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
              </svg>
            </span>
            <span className="rx-tile-name">Shielded</span>
            <span className="rx-tile-sub">{latestStealth ? shortAddr(latestStealth) : "Create"}</span>
          </button>
          <button className={`rx-tile${open === "btc" ? " open" : ""}`} type="button" aria-pressed={open === "btc"} onClick={() => toggle("btc")}>
            <span className="rx-glyph b" aria-hidden="true">
              <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                <path d="M9 1.4v2.1M9 14.5v2.1M6.2 4.2h4.1a2.35 2.35 0 0 1 0 4.7H6.2h4.5a2.55 2.55 0 0 1 0 5.1H6.2M6.2 4.2v9.8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </span>
            <span className="rx-tile-name">Bitcoin</span>
            <span className="rx-tile-sub">{shortAddr(btcAddr)}</span>
          </button>
        </aside>

        {open === "zcrypt" && (
          <div className="rx-sheet">
            <div className="eyebrow">Recoverable · zc1</div>
            <h3>ZCRYPT address</h3>
            <p>Share this to get paid in ZCRYPT or any shielded asset. Your recovery phrase restores it.</p>
            <div className="rx-addr" title={normal}>{normal || "Loading…"}</div>
            <div className="rx-row">
              {normal && <CopyButton text={normal} label="Copy address" />}
              <button className="ghost" type="button" disabled={!normal} onClick={() => showQr(normal, "ZCRYPT address")}>Large QR</button>
            </div>
            {normal && <div className="rx-fine">{normal.length.toLocaleString()} characters</div>}
          </div>
        )}

        {open === "shield" && (
          <div className="rx-sheet">
            <div className="eyebrow">Not in your phrase · zc1</div>
            <h3>Shielded address</h3>
            <p>A payment arrives as an encrypted file. Nothing readable is left on-chain.</p>
            {shown ? (
              <>
                {stealth.length > 1 && (
                  <select value={shown.index} onChange={(e) => { setStealthIdx(Number(e.target.value)); cancelReveal(); }}>
                    {stealth.map((x) => (
                      <option key={x.index} value={x.index}>
                        Shielded #{x.index} · {shortAddr(x.address)}
                      </option>
                    ))}
                  </select>
                )}
                <div className="rx-addr" title={shown.address}>{shown.address}</div>
                <div className="rx-row">
                  <CopyButton text={shown.address} label="Copy address" />
                  <button className="ghost" type="button" onClick={() => showQr(shown.address, "Shielded address")}>Large QR</button>
                </div>
                <div className="rx-fine">Share the address. Keep the key.</div>
                <div className="rx-rule" />
                <div className="rx-key-label">Private key</div>
                {key ? (
                  <>
                    <div className="rx-key">{key}</div>
                    <div className="rx-row">
                      <KeyCopy text={key} />
                      <button className="ghost" type="button" onClick={() => hideKey(shown.index)}>Hide</button>
                    </div>
                    <div className="rx-fine">Write this down. Your 24-word phrase will not restore it. Losing the key and this wallet loses anything sent here.</div>
                  </>
                ) : pwFor === shown.index ? (
                  <>
                    <p>Enter your wallet password. The key for this address is shown once you confirm it.</p>
                    <input
                      type="password"
                      placeholder="Wallet password"
                      value={pw}
                      autoFocus
                      onChange={(e) => setPw(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && revealBackup(shown.index)}
                    />
                    {revealErr && <div className="msg err">{revealErr}</div>}
                    <div className="rx-row">
                      <button className="rx-recover" type="button" style={{ width: "auto" }} onClick={() => revealBackup(shown.index)}>Recover</button>
                      <button className="ghost" type="button" onClick={cancelReveal}>Cancel</button>
                    </div>
                  </>
                ) : (
                  <>
                    <p>Your recovery phrase does not restore this address. Recover its private key with your wallet password, then store the key yourself.</p>
                    <button className="rx-recover" type="button" onClick={() => { setPwFor(shown.index); setPw(""); setRevealErr(""); }}>
                      Recover private key
                    </button>
                  </>
                )}
                <div className="rx-row">
                  <button className="btn-link" type="button" disabled={stealthBusy} onClick={newStealth}>
                    {stealthBusy ? "Creating…" : "+ New shielded address"}
                  </button>
                </div>
              </>
            ) : (
              <>
                <p>You do not have a shielded address yet. Creating one makes a key your recovery phrase cannot restore.</p>
                <button className="rx-recover" type="button" disabled={stealthBusy} onClick={newStealth}>
                  {stealthBusy ? "Creating…" : "Create a shielded address"}
                </button>
              </>
            )}
            {err && <div className="msg err">{err}</div>}
          </div>
        )}

        {open === "btc" && (
          <div className="rx-sheet">
            <div className="eyebrow">Bitcoin chain · bc1</div>
            <h3>Bitcoin address</h3>
            <p>Real bitcoin. Deposit here, then shield it into zBTC under Bridge, or send it out under Send.</p>
            <div className="rx-addr" title={btcAddr}>{btcAddr || "Loading…"}</div>
            <div className="rx-row">
              {btcAddr && <CopyButton text={btcAddr} label="Copy address" />}
              <button className="ghost" type="button" disabled={!btcAddr} onClick={() => showQr(btcAddr, "Bitcoin address")}>Large QR</button>
            </div>
            <div className="rx-fine">Restored by the same phrase.</div>
          </div>
        )}
      </div>
      {bigQr && <QrOverlay text={bigQr.text} title={bigQr.title} onClose={hideQr} />}
    </div>
  );
}
