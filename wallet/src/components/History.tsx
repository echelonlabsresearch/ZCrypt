import { useCallback, useEffect, useState } from "react";
import { call, fmtAsset, HeldAsset } from "../lib/api";

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

const ICON: Record<string, string> = {
  receive: "📥",
  send: "📤",
  mint: "💎",
  bearer: "💠",
  fund: "🪙",
  reward: "🏆",
  shield: "₿",
  redeem: "₿",
};

export default function History({ active }: { active: boolean }) {
  const [items, setItems] = useState<Tx[]>([]);
  const [tickers, setTickers] = useState<Record<string, string>>({});

  const load = useCallback(() => {
    call<Tx[]>("get_history").then(setItems).catch(() => {});
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
      <div style={{ opacity: 0.5, fontSize: "0.8rem", marginTop: "1.5rem", textAlign: "center" }}>
        Amounts are hidden on-chain (ZK); finality is sub-second BFT.
      </div>
    </div>
  );
}
