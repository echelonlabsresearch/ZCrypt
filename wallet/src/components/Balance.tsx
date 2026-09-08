import { useCallback, useEffect, useState } from "react";
import { call, fmt, fmtAsset, trunc, HeldAsset } from "../lib/api";
import { CopyButton } from "./Share";

interface BtcWallet {
  connected: boolean;
  balance: number;
  deposit_address: string;
}

export default function Balance({ balance, onRefresh }: { balance: number; onRefresh: () => void }) {
  const [normal, setNormal] = useState("");
  const [count, setCount] = useState(0);
  const [spinning, setSpinning] = useState(false);
  const [assets, setAssets] = useState<HeldAsset[]>([]);
  const [btc, setBtc] = useState<BtcWallet | null>(null);
  const [btcBusy, setBtcBusy] = useState(false);

  // Everything here is local to this machine. The Bitcoin balance is NOT fetched
  // automatically: it asks the configured Esplora server about your deposit address,
  // which tells that server which address is yours. It runs only when you click.
  const load = useCallback(() => {
    call<string>("get_address").then(setNormal).catch(() => {});
    call<{ coin_count: number }>("get_balance").then((b) => setCount(b.coin_count)).catch(() => {});
    call<HeldAsset[]>("held_assets").then(setAssets).catch(() => {});
  }, []);

  async function checkBtc() {
    setBtcBusy(true);
    try {
      setBtc(await call<BtcWallet>("btc_wallet_info"));
    } catch {
      setBtc({ connected: false, balance: 0, deposit_address: "" });
    } finally {
      setBtcBusy(false);
    }
  }

  useEffect(() => {
    load();
  }, [balance, load]);

  async function refresh() {
    setSpinning(true);
    await onRefresh();
    load();
    setTimeout(() => setSpinning(false), 400);
  }

  // Non-native shielded assets (zBTC, …) with a positive balance.
  const shielded = assets.filter((a) => a.asset_id !== "0" && a.balance > 0);

  return (
    <div>
      <h2 className="view-title">💰 Balance</h2>

      <div className="card hero">
        <div className="card-row" style={{ borderTop: "none", paddingTop: 0 }}>
          <h2 style={{ margin: 0 }}>Total Balance</h2>
          <button className="btn-secondary" onClick={refresh}>{spinning ? "⟳ …" : "🔄 Refresh"}</button>
        </div>
        <div className="balance-big">
          <span className="amount">{fmt(balance)}</span> <span className="unit">ZCRYPT</span>
        </div>
        <div className="card-row">
          <span>💸 Spendable</span>
          <span style={{ color: "var(--color-green)", fontWeight: "bold" }}>{fmt(balance)} ZCRYPT</span>
        </div>
        <div className="card-row">
          <span>🪙 Coins</span>
          <span>{count}</span>
        </div>
      </div>

      {shielded.length > 0 && (
        <div className="card" style={{ marginTop: "1.2rem" }}>
          <h2>🪙 Shielded assets</h2>
          {shielded.map((a) => (
            <div className="card-row" key={a.asset_id}>
              <span style={{ fontWeight: "bold", color: "var(--color-yellow)" }}>{a.ticker}</span>
              <span>{fmtAsset(a.balance, a.decimals)} {a.ticker}</span>
            </div>
          ))}
          <div style={{ fontSize: "0.78rem", opacity: 0.6, marginTop: "0.5rem" }}>
            Shielded assets are private coins, anonymous among the whole pool. Send them from the Send tab or hand them off as bearer coins.
          </div>
        </div>
      )}

      <div className="card" style={{ marginTop: "1.2rem" }}>
        <div className="card-row" style={{ borderTop: "none", paddingTop: 0 }}>
          <h2 style={{ margin: 0 }}>₿ Bitcoin (L1)</h2>
          <button className="btn-secondary" onClick={checkBtc} disabled={btcBusy}>
            {btcBusy ? "Checking…" : btc ? "🔄 Re-check" : "Check Bitcoin balance"}
          </button>
        </div>
        {btc === null ? (
          <div style={{ opacity: 0.7, fontSize: "0.85rem" }}>
            Not checked. Checking asks your configured Esplora server (Settings) about your
            deposit address, which reveals that address to it; it is never done automatically.
          </div>
        ) : btc.connected ? (
          <>
            <div className="balance-big" style={{ fontSize: "1.6rem" }}>
              <span className="amount">{btc.balance.toLocaleString(undefined, { maximumFractionDigits: 8 })}</span>{" "}
              <span className="unit">BTC</span>
            </div>
            <div className="card-row">
              <div style={{ flex: 1 }}>
                <div style={{ color: "var(--color-text-dim)", fontWeight: "bold" }}>Deposit address — send BTC here</div>
                <div style={{ fontSize: "0.78rem", opacity: 0.65, margin: "0.2rem 0 0.4rem" }}>
                  Deposit BTC, then use the <b>Bridge</b> tab to shield it into private zBTC.
                </div>
                <code style={{ color: "var(--color-cyan)", wordBreak: "break-all" }}>
                  {btc.deposit_address || "—"}
                </code>
              </div>
              <CopyButton text={btc.deposit_address} />
            </div>
            <div style={{ fontSize: "0.78rem", opacity: 0.6, marginTop: "0.5rem" }}>
              To send BTC out (or shield it to zBTC), use the <b>Send</b> tab — it handles ZCRYPT, shielded assets, and Bitcoin in one place.
            </div>
          </>
        ) : (
          <div style={{ opacity: 0.7, fontSize: "0.9rem" }}>
            No bitcoind connected. Configure your Bitcoin RPC in <b>Settings</b> to deposit, shield, and withdraw BTC.
          </div>
        )}
      </div>

      <div className="card" style={{ marginTop: "1.2rem" }}>
        <h2>📇 Your address</h2>
        <div className="card-row" style={{ borderTop: "none", paddingTop: 0 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ color: "var(--color-text-dim)", fontWeight: "bold" }}>Normal — recoverable from your phrase</div>
            <div style={{ fontSize: "0.78rem", opacity: 0.65, margin: "0.2rem 0 0.4rem" }}>
              Share this to get paid. Payments arrive on-chain and auto-credit on Refresh.
            </div>
            <code style={{ color: "var(--color-cyan)", wordBreak: "break-all" }} title={normal}>
              {trunc(normal, 30, 10)}
            </code>
          </div>
          <CopyButton text={normal} />
        </div>
        <div style={{ fontSize: "0.78rem", opacity: 0.65, marginTop: "0.6rem" }}>
          Manage <b>stealth addresses</b> (and their keys) and your <b>view key</b> in the{" "}
          <b>Addresses</b> tab — every stealth address you create is saved there.
        </div>
      </div>
    </div>
  );
}
