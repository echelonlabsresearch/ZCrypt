import { useCallback, useEffect, useState } from "react";
import { call, copySensitive, fmtAsset, HeldAsset, saveFile, trunc } from "../lib/api";

interface Tx {
  tx_id: string;
  kind: string;
  amount: number; // base units
  counterparty: string;
  timestamp: number;
  status: string;
  asset_id: string; // "0" = ZCRYPT
  decimals: number; // ZCRYPT = 6, shielded assets = 8
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

export default function History({ active }: { active: boolean }) {
  const [items, setItems] = useState<Tx[]>([]);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [tickers, setTickers] = useState<Record<string, string>>({});
  const [open, setOpen] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [saved, setSaved] = useState<Record<string, string>>({});
  const [checking, setChecking] = useState<string | null>(null);
  const [checked, setChecked] = useState<Record<string, Verdict>>({});
  const [foreign, setForeign] = useState("");
  const [foreignBusy, setForeignBusy] = useState(false);
  const [foreignVerdict, setForeignVerdict] = useState<Verdict | null>(null);
  const [foreignErr, setForeignErr] = useState("");

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

  async function checkText(text: string) {
    const s = text.trim();
    if (!s) return;
    setForeignBusy(true);
    setForeignErr("");
    setForeignVerdict(null);
    try {
      setForeignVerdict(await call<Verdict>("verify_receipt", { text: s }));
    } catch (e) {
      setForeignErr(String(e));
    } finally {
      setForeignBusy(false);
    }
  }

  function verdictClass(v: Verdict) {
    if (v.on_chain && v.names_recipient) return "ok";
    if (v.on_chain) return "warn";
    return "err";
  }

  return (
    <div>
      <h2 className="view-title">📋 Transaction History</h2>
      {items.length === 0 ? (
        <div className="empty">📭 No transactions yet</div>
      ) : (
        items.map((t) => (
          <div className={`tx-card ${t.kind}`} key={t.tx_id}>
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
          </div>
        ))
      )}
      <h2 className="view-title" style={{ marginTop: "2rem" }}>🧾 Payment receipts</h2>
      <div style={{ opacity: 0.7, fontSize: "0.85rem", margin: "-0.4rem 0 1rem" }}>
        Paste any receipt to check it. A confirmed receipt created a coin for the address it names, and that coin is on this chain. Your own receipts are saved below, encrypted in this wallet.
      </div>
      <div
        className="card"
        style={{ marginBottom: "1rem" }}
        onDragOver={(e) => e.preventDefault()}
        onDrop={async (e) => {
          e.preventDefault();
          const file = e.dataTransfer.files?.[0];
          const text = file ? await file.text() : e.dataTransfer.getData("text");
          if (text) {
            setForeign(text.trim());
            checkText(text);
          }
        }}
      >
        <textarea
          className="mnemonic-input"
          value={foreign}
          onChange={(e) => setForeign(e.target.value)}
          placeholder="paste a zcrypt-receipt/1 file"
          style={{ minHeight: 100 }}
        />
        <button className="btn-primary btn-block" style={{ marginTop: "0.8rem" }} disabled={foreignBusy} onClick={() => checkText(foreign)}>
          {foreignBusy ? "Checking…" : "Check receipt"}
        </button>
        {foreignVerdict && <div className={`msg ${verdictClass(foreignVerdict)}`} style={{ marginTop: "0.8rem" }}>{foreignVerdict.summary}</div>}
        {foreignErr && <div className="msg err" style={{ marginTop: "0.8rem" }}>{foreignErr}</div>}
      </div>
      {receipts.length === 0 ? (
        <div className="empty">📭 No payment receipts yet</div>
      ) : (
        receipts.map((r) => (
          <div className="tx-card send" key={r.id} style={{ display: "block" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
              <span className="tx-icon">{r.kind === "bearer" ? "💠" : r.kind === "stealth" ? "🕶️" : "📤"}</span>
              <div className="tx-body">
                <div className="tx-type">{RECEIPT_KIND[r.kind] || r.kind}</div>
                <div className="tx-meta">
                  {r.recipient ? trunc(r.recipient) : "bearer file"} · #{r.timestamp}
                </div>
              </div>
              <div className="tx-amount neg">
                −{fmtAsset(r.amount, r.decimals)}
                <span style={{ fontSize: "0.7em", opacity: 0.7, marginLeft: "0.3em" }}>{unitOf(r.asset_id)}</span>
              </div>
              <button className="copy-btn" onClick={() => setOpen(open === r.id ? null : r.id)}>
                {open === r.id ? "Hide" : "Show receipt"}
              </button>
            </div>
            {open === r.id && (
              <div style={{ marginTop: "0.9rem" }}>
                <div style={{ fontSize: "0.82rem", opacity: 0.8, marginBottom: "0.6rem" }}>{RECEIPT_NOTE[r.kind]}</div>
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
        ))
      )}

      <div style={{ opacity: 0.5, fontSize: "0.8rem", marginTop: "1.5rem", textAlign: "center" }}>
        Amounts are hidden on-chain (ZK); finality is sub-second BFT. A receipt is what reopens one of your own payments.
      </div>
    </div>
  );
}
