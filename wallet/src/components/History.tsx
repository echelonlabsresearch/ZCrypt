import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  call,
  coinFileName,
  copySensitive,
  fmtAsset,
  HeldAsset,
  openCoinShare,
  saveFile,
  SHARE_CHANNELS,
  ShareChannel,
} from "../lib/api";

interface Tx {
  tx_id: string;
  kind: string;
  amount: number; // base units
  counterparty: string;
  timestamp: number;
  status: string;
  asset_id: string; // "0" = ZCRYPT
  decimals: number; // ZCRYPT = 6, shielded assets = 8
  /** The saved receipt this row produced, or "" (older rows: matched by amount below). */
  receipt_id: string;
}

interface Verdict {
  on_chain: boolean;
  names_recipient: boolean;
  pays_this_wallet: boolean;
  kind: string;
  amount: number;
  asset_id: string;
  decimals: number;
  ticker: string;
  recipient: string;
  summary: string;
}

interface Receipt {
  id: string;
  kind: string;
  amount: number;
  asset_id: string;
  decimals: number;
  recipient: string;
  timestamp: number;
  text: string;
}

const RECEIPT_KIND: Record<string, string> = {
  normal: "Normal payment",
  stealth: "Stealth payment",
  bearer: "Bearer coin",
};

const RECEIPT_NOTE: Record<string, string> = {
  normal:
    "Show this to prove the coin was created for that address. The recipient's view key reads the same coin. The leaf stays on the chain after they spend it.",
  stealth:
    "Show this to prove the coin was created for that stealth address. The note line is the file they need. Their main view key cannot see this payment.",
  bearer:
    "This records the coin in the file. The nullifier line is how a sweep of that file is recognized. The receipt does not contain the spend secret.",
};

interface PendingSecret {
  id: number;
  kind: string;
  label: string;
  secret: string;
  created: number;
}

/** The wallet stores "N base units of asset 0". Asset 0 is always ZCRYPT, 6 decimals. */
function secretMeta(label: string): string {
  const m = label.match(/(\d+) base units of asset (\d+)/);
  if (m && m[2] === "0") return `${fmtAsset(Number(m[1]), 6)} ZCRYPT · still on this computer`;
  return `${label} · still on this computer`;
}

/**
 * A coin or note still in the wallet because it was never saved. Copy and share leave it
 * here. Save writes one file, then the row goes away.
 */
function UnsentCoin({ sx, onSaved }: { sx: PendingSecret; onSaved: (id: number) => void }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState("");
  const fileKind = sx.kind === "stealth_note" ? "note" : "bearer";
  const title = fileKind === "note" ? "Stealth note" : "Bearer coin";
  const subject = fileKind === "note" ? "ZCrypt note" : "ZCrypt coin";
  const [filename] = useState(() => coinFileName(fileKind));
  const lock = useRef(false);
  const wrote = useRef(false);

  async function copyCoin() {
    try {
      await copySensitive(sx.secret);
      setNote("Copied. The clipboard clears in 60 seconds. Paste it to send the coin again.");
    } catch (e) {
      setNote(String(e instanceof Error ? e.message : e));
    }
  }

  async function save() {
    if (lock.current) return;
    lock.current = true;
    setBusy("save");
    setNote("");
    try {
      if (!wrote.current) {
        try {
          await saveFile(filename, sx.secret);
        } catch (e) {
          // The first click already wrote this name. Do not mint another one.
          if (!/already exists/i.test(String(e))) throw e;
        }
        wrote.current = true;
      }
      await call("dismiss_pending_secret", { id: sx.id });
      window.dispatchEvent(new Event("zc-secrets"));
      onSaved(sx.id);
    } catch (e) {
      setNote(String(e instanceof Error ? e.message : e));
      lock.current = false;
      setBusy("");
    }
  }

  async function share(channel: ShareChannel) {
    setBusy(channel);
    setNote("");
    try {
      await openCoinShare(channel, sx.secret, coinFileName(fileKind), subject);
      const label = SHARE_CHANNELS.find((c) => c.id === channel)?.label ?? channel;
      setNote(`Opened ${label}. The coin is still here if it did not go through.`);
    } catch (e) {
      setNote(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="tx-card secret">
      <div className="secret-top">
        <span className="tx-icon">{fileKind === "note" ? "🕶️" : "💠"}</span>
        <div className="tx-body">
          <div className="tx-type">{title}</div>
          <div className="tx-meta">{secretMeta(sx.label)}</div>
        </div>
      </div>
      <div className="secret-actions">
        <button className="copy-btn" disabled={!!busy} onClick={copyCoin}>
          ⧉ Copy
        </button>
        <button className="copy-btn" disabled={!!busy} onClick={save}>
          {busy === "save" ? "Saving…" : "💾 Save"}
        </button>
        {SHARE_CHANNELS.map((c) => (
          <button key={c.id} className="copy-btn" disabled={!!busy} onClick={() => share(c.id)}>
            {busy === c.id ? "Opening…" : c.label}
          </button>
        ))}
      </div>
      {note && <div className="secret-note">{note}</div>}
    </div>
  );
}

const ICON: Record<string, string> = {
  receive: "📥",
  send: "📤",
  mint: "💎",
  bearer: "💠",
  fund: "🪙",
  reward: "🏆",
  shield: "₿",
  redeem: "₿",
  fee: "🧾",
  swap: "🔁",
  escrow: "🔓",
};

/**
 * One list. Every row is the event; a row that produced a payment receipt opens to show it,
 * with copy, save and an on-chain check. To check a receipt someone else sent you, paste it
 * under Receive.
 */
export default function History({ active }: { active: boolean }) {
  const [items, setItems] = useState<Tx[]>([]);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [tickers, setTickers] = useState<Record<string, string>>({});
  const [open, setOpen] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [saved, setSaved] = useState<Record<string, string>>({});
  const [checking, setChecking] = useState<string | null>(null);
  const [checked, setChecked] = useState<Record<string, Verdict>>({});
  const [secrets, setSecrets] = useState<PendingSecret[]>([]);
  const savedIds = useRef(new Set<number>());

  const load = useCallback(() => {
    call<Tx[]>("get_history").then(setItems).catch(() => {});
    call<Receipt[]>("list_receipts").then(setReceipts).catch(() => {});
    call<PendingSecret[]>("list_pending_secrets")
      .then((list) => setSecrets(list.filter((s) => !savedIds.current.has(s.id))))
      .catch(() => {});
    call<HeldAsset[]>("held_assets")
      .then((assets) => {
        const m: Record<string, string> = {};
        for (const a of assets) m[a.asset_id] = a.ticker;
        setTickers(m);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!active) return;
    load();
    const t = setInterval(load, 12000);
    return () => clearInterval(t);
  }, [active, load]);

  // Ticker for a row: ZCRYPT for asset 0, else look it up (falls back to blank).
  const unitOf = (assetId: string) => (assetId === "0" ? "ZCRYPT" : tickers[assetId] ?? "");

  // Receipt for each row. New rows carry `receipt_id`; rows written before that field
  // existed are matched to the nearest unclaimed receipt of the same kind, asset and amount.
  const receiptFor = useMemo(() => {
    const byId = new Map(receipts.map((r) => [r.id, r]));
    const out = new Map<string, Receipt>();
    const taken = new Set<string>();
    for (const t of items) {
      if (t.receipt_id && byId.has(t.receipt_id)) {
        out.set(t.tx_id, byId.get(t.receipt_id)!);
        taken.add(t.receipt_id);
      }
    }
    for (const t of items) {
      if (out.has(t.tx_id) || (t.kind !== "send" && t.kind !== "bearer")) continue;
      const kinds = t.kind === "bearer" ? ["bearer"] : ["normal", "stealth"];
      let best: Receipt | null = null;
      for (const r of receipts) {
        if (taken.has(r.id) || !kinds.includes(r.kind) || r.asset_id !== t.asset_id || r.amount !== Math.abs(t.amount)) continue;
        if (r.timestamp < t.timestamp || r.timestamp > t.timestamp + 3) continue;
        if (!best || Math.abs(r.timestamp - t.timestamp) < Math.abs(best.timestamp - t.timestamp)) best = r;
      }
      if (best) {
        out.set(t.tx_id, best);
        taken.add(best.id);
      }
    }
    return out;
  }, [items, receipts]);

  async function check(id: string) {
    setChecking(id);
    try {
      const r = await call<Verdict>("check_receipt", { id });
      setChecked((m) => ({ ...m, [id]: r }));
    } catch (e) {
      setChecked((m) => ({
        ...m,
        [id]: {
          on_chain: false,
          names_recipient: false,
          pays_this_wallet: false,
          kind: "",
          amount: 0,
          asset_id: "0",
          decimals: 6,
          ticker: "",
          recipient: "",
          summary: String(e),
        },
      }));
    } finally {
      setChecking(null);
    }
  }

  function verdictClass(v: Verdict) {
    if (v.on_chain && v.names_recipient) return "ok";
    if (v.on_chain) return "warn";
    return "err";
  }

  const unsent = [...secrets].reverse();

  return (
    <div>
      <h2 className="view-title">📋 History</h2>
      {unsent.length > 0 && (
        <div className="unsent">
          <h3>Still on this computer</h3>
          <p>These files are the payment. Copy one to send it again, or save it. Saving once removes it from this list.</p>
          {unsent.map((sx) => (
            <UnsentCoin
              key={sx.id}
              sx={sx}
              onSaved={(id) => {
                savedIds.current.add(id);
                setSecrets((list) => list.filter((s) => s.id !== id));
              }}
            />
          ))}
        </div>
      )}
      {items.length === 0 ? (
        <div className="empty">{unsent.length ? "No other transactions yet" : "📭 No transactions yet"}</div>
      ) : (
        items.map((t) => {
          const r = receiptFor.get(t.tx_id);
          const isOpen = open === t.tx_id;
          return (
            <div className={`tx-card ${t.kind} ${r ? "expandable" : ""} ${isOpen ? "open" : ""}`} key={t.tx_id}>
              <div className="tx-row" onClick={() => r && setOpen(isOpen ? null : t.tx_id)}>
                <span className="tx-icon">{ICON[t.kind] || "•"}</span>
                <div className="tx-body">
                  <div className="tx-type">{t.kind}</div>
                  <div className="tx-meta">{t.counterparty} · #{t.timestamp}</div>
                </div>
                <div className={`tx-amount ${t.amount >= 0 ? "pos" : "neg"}`}>
                  {t.amount >= 0 ? "+" : "−"}
                  {fmtAsset(Math.abs(t.amount), t.decimals)}
                  <span style={{ fontSize: "0.7em", opacity: 0.7, marginLeft: "0.3em" }}>{unitOf(t.asset_id)}</span>
                </div>
                <span className="pill">✓ {t.status}</span>
                {r && <span className="tx-chevron">{isOpen ? "▾" : "▸"}</span>}
              </div>
              {r && isOpen && (
                <div className="tx-detail">
                  <div style={{ fontSize: "0.8rem", color: "var(--color-text-dim)", fontWeight: "bold" }}>
                    🧾 {RECEIPT_KIND[r.kind] || r.kind} receipt
                  </div>
                  <div style={{ fontSize: "0.8rem", opacity: 0.75, margin: "0.3rem 0 0.6rem" }}>{RECEIPT_NOTE[r.kind]}</div>
                  <div className="mono-box">{r.text}</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginTop: "0.6rem" }}>
                    <button
                      className="copy-btn"
                      onClick={async () => {
                        await copySensitive(r.text);
                        setCopied(r.id);
                        setTimeout(() => setCopied((c) => (c === r.id ? null : c)), 1500);
                      }}
                    >
                      {copied === r.id ? "✓ Copied (clears in 60 s)" : "⧉ Copy receipt"}
                    </button>
                    <button
                      className="copy-btn"
                      onClick={async () => {
                        try {
                          const path = await saveFile(`zcrypt-${r.id}.txt`, r.text);
                          setSaved((m) => ({ ...m, [r.id]: path }));
                        } catch (e) {
                          setSaved((m) => ({ ...m, [r.id]: String(e) }));
                        }
                      }}
                    >
                      💾 Save file
                    </button>
                    <button className="copy-btn" disabled={checking === r.id} onClick={() => check(r.id)}>
                      {checking === r.id ? "Checking…" : "Check on chain"}
                    </button>
                  </div>
                  {saved[r.id] && (
                    <div style={{ fontSize: "0.78rem", opacity: 0.75, marginTop: "0.4rem" }}>{saved[r.id]}</div>
                  )}
                  {checked[r.id] && (
                    <div className={`msg ${verdictClass(checked[r.id])}`} style={{ marginTop: "0.6rem" }}>
                      {checked[r.id].summary}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })
      )}

      <div style={{ opacity: 0.5, fontSize: "0.8rem", marginTop: "1.5rem", textAlign: "center" }}>
        Amounts are hidden on-chain; finality is sub-second BFT. A row with ▸ holds the payment's receipt.
        To check a receipt someone sent <i>you</i>, paste it under <b>Receive</b>.
      </div>
    </div>
  );
}
