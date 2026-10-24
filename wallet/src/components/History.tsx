import { useCallback, useEffect, useMemo, useState } from "react";
import { call, copySensitive, fmtAsset, HeldAsset, saveFile } from "../lib/api";

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

  const load = useCallback(() => {
    call<Tx[]>("get_history").then(setItems).catch(() => {});
    call<Receipt[]>("list_receipts").then(setReceipts).catch(() => {});
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

  return (
    <div>
      <h2 className="view-title">📋 History</h2>
      {items.length === 0 ? (
        <div className="empty">📭 No transactions yet</div>
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
