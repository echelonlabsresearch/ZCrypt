import { useCallback, useEffect, useState, DragEvent } from "react";
import { call, fmtAsset, saveFile } from "../lib/api";
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
    body: "A key you can GIVE someone so they can see the amounts of payments to your NORMAL address, and nothing else. It can never spend, and cannot see stealth or bearer coins.",
  },
  {
    icon: "₿",
    name: "Bitcoin deposit address",
    color: "--color-cyan",
    tag: "bc1… · derived from the same phrase",
    body: "Real Bitcoin, on the Bitcoin chain. Deposit here, then shield it into private zBTC under Bridge, or send it out again under Send.",
  },
];

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
  const [viewKey, setViewKey] = useState("");
  const [showVk, setShowVk] = useState(false);
  // Backup seeds are spend secrets: they are never bulk-fetched. Each is revealed one at a
  // time, behind a fresh password check (reveal_stealth_backup), and held only in local state.
  const [revealed, setRevealed] = useState<Record<number, string>>({});
  const [pwFor, setPwFor] = useState<number | null>(null);
  const [pw, setPw] = useState("");
  const [revealErr, setRevealErr] = useState("");
  const [saved, setSaved] = useState("");
  const [stealthBusy, setStealthBusy] = useState(false);
  const [err, setErr] = useState("");

  // Drop zone
  const [blob, setBlob] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [state, setState] = useState<"idle" | "ok" | "err" | "warn">("idle");
  const [msg, setMsg] = useState("");

  const load = useCallback(() => {
    call<string>("get_address").then(setNormal).catch(() => {});
    call<Stealth[]>("list_stealth_addresses").then(setStealth).catch(() => {});
    call<string>("get_view_key").then(setViewKey).catch(() => {});
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

      <div className="receive-grid">
        {/* Your addresses: the thing every wallet shows first under Receive. */}
        <div className="card">
          <h2>🏷️ Your address</h2>
          <div style={{ fontSize: "0.8rem", opacity: 0.7, marginBottom: "0.5rem" }}>
            Share this to get paid in ZCRYPT or any shielded asset. Payments arrive on-chain and
            credit on Refresh. Your view key can see them; nobody else can.
          </div>
          <div className="addr-box">
            <code title={normal}>{normal || "…"}</code>
          </div>
          <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.5rem", flexWrap: "wrap" }}>
            <CopyButton text={normal} label="⧉ Copy address" />
          </div>

          <div className="card-row" style={{ marginTop: "0.9rem", alignItems: "flex-start" }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: "var(--color-text-dim)", fontWeight: "bold" }}>₿ Bitcoin deposit address</div>
              <div style={{ fontSize: "0.76rem", opacity: 0.65, margin: "0.2rem 0 0.4rem" }}>
                Real BTC, derived from the same phrase. Deposit here, then shield it into zBTC under <b>Bridge</b>.
              </div>
              <code style={{ color: "var(--color-cyan)", wordBreak: "break-all" }}>{btcAddr || "—"}</code>
            </div>
            {btcAddr && <CopyButton text={btcAddr} />}
          </div>
        </div>

        {/* The drop zone: a coin file, an encrypted note, or a receipt to check. */}
        <div className={`dropzone compact ${cls}`} onDragOver={onDragOver} onDragEnter={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}>
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
      </div>

      {/* Stealth addresses: persisted list */}
      <div className="card" style={{ marginTop: "1.2rem" }}>
        <div className="card-row" style={{ borderTop: "none", paddingTop: 0 }}>
          <h2 style={{ margin: 0 }}>🕶️ Stealth addresses</h2>
          <button className="copy-btn" disabled={stealthBusy} onClick={newStealth}>
            {stealthBusy ? "…" : "+ New stealth address"}
          </button>
        </div>
        {stealth.length === 0 && (
          <div style={{ opacity: 0.6, fontSize: "0.85rem" }}>
            None yet. A stealth address is paid with an encrypted file and is invisible even to your own view key.
          </div>
        )}
        {stealth.map((s) => (
          <div key={s.index} className="card-row" style={{ alignItems: "flex-start" }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: "0.72rem", opacity: 0.5 }}>Stealth #{s.index}</div>
              <code style={{ color: "var(--color-purple)", wordBreak: "break-all" }}>{s.address}</code>
              <div style={{ marginTop: "0.4rem" }}>
                {revealed[s.index] ? (
                  <div className="mono-box" style={{ color: "var(--color-yellow)", wordBreak: "break-all" }}>
                    {revealed[s.index]}
                  </div>
                ) : pwFor === s.index ? (
                  <div style={{ display: "flex", gap: "0.4rem", alignItems: "center", flexWrap: "wrap" }}>
                    <input
                      type="password"
                      placeholder="Password to reveal"
                      value={pw}
                      autoFocus
                      onChange={(e) => setPw(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && revealBackup(s.index)}
                    />
                    <button className="copy-btn" onClick={() => revealBackup(s.index)}>
                      Reveal
                    </button>
                    <button className="btn-link" onClick={cancelReveal}>
                      Cancel
                    </button>
                    {revealErr && <span style={{ color: "var(--color-red, #e66)", fontSize: "0.78rem" }}>{revealErr}</span>}
                  </div>
                ) : (
                  <button className="btn-link" onClick={() => { setPwFor(s.index); setPw(""); setRevealErr(""); }}>
                    🔑 Reveal private key
                  </button>
                )}
              </div>
              <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.5rem", flexWrap: "wrap" }}>
                <CopyButton text={s.address} label="⧉ Copy address" />
                {revealed[s.index] && <CopyButton text={revealed[s.index]} label="⧉ Copy private key" />}
              </div>
            </div>
          </div>
        ))}
        <div className="warn" style={{ marginTop: "0.8rem" }}>
          ⚠️ Your recovery phrase will <b>not</b> restore stealth addresses. Back up each private key
          separately. Every stealth address you generate is saved here.
        </div>
      </div>

      {/* View key */}
      <div className="card" style={{ marginTop: "1.2rem" }}>
        <h2>🔎 View key</h2>
        <div style={{ fontSize: "0.85rem", opacity: 0.85, lineHeight: 1.5, marginBottom: "0.6rem" }}>
          Give this to an auditor to let them <b>see the amounts</b> of payments to your normal address,
          and nothing more. It can never spend, and it cannot see stealth or bearer coins.
        </div>
        {showVk ? (
          <>
            <div className="mono-box" style={{ color: "var(--color-green)", wordBreak: "break-all" }}>
              {viewKey}
            </div>
            <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.5rem", flexWrap: "wrap" }}>
              <CopyButton text={viewKey} label="⧉ Copy view key" />
              <button
                className="copy-btn"
                onClick={async () => {
                  try {
                    setSaved(await saveFile("zcrypt-view-key.txt", viewKey));
                  } catch (e) {
                    setSaved(`error: ${e}`);
                  }
                }}
              >
                💾 Save file
              </button>
              <button className="btn-link" onClick={() => setShowVk(false)}>
                Hide
              </button>
            </div>
            {saved && (
              <div style={{ fontSize: "0.78rem", opacity: 0.7, marginTop: "0.4rem" }}>
                {saved.startsWith("error") ? (
                  <span style={{ color: "var(--color-red, #e66)" }}>{saved}</span>
                ) : (
                  <>
                    ✓ Saved to <code>{saved}</code>
                  </>
                )}
              </div>
            )}
          </>
        ) : (
          <button className="btn-secondary" onClick={() => setShowVk(true)}>
            👁 Reveal my view key
          </button>
        )}
        <div className="warn" style={{ marginTop: "0.8rem" }}>
          A view key is a disclosure, and it cannot be un-shared.
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
    </div>
  );
}
