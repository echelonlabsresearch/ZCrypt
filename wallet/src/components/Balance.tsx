import { useCallback, useEffect, useState } from "react";
import type React from "react";
import { call, fmt, fmtAsset, HeldAsset, isWhitelisted, whitelistName } from "../lib/api";

interface BtcWallet {
  connected: boolean;
  balance: number;
  deposit_address: string;
}

const btcFmt = (n: number) => n.toLocaleString(undefined, { minimumFractionDigits: 8, maximumFractionDigits: 8 });

/**
 * The front page: what this wallet holds, one tile per asset, nothing else. Addresses live
 * in Receive, actions in Send. The Bitcoin tile asks the Esplora server about the deposit
 * address, which tells that server the address is yours, so it only runs on a click.
 */
export default function Balance({ balance, onRefresh }: { balance: number; onRefresh: () => Promise<void> }) {
  const [count, setCount] = useState(0);
  const [spinning, setSpinning] = useState(false);
  const [assets, setAssets] = useState<HeldAsset[]>([]);
  const [btc, setBtc] = useState<BtcWallet | null>(null);
  const [whitelist, setWhitelist] = useState<string[]>([]);

  const load = useCallback(async () => {
    await Promise.all([
      call<{ coin_count: number }>("get_balance").then((b) => setCount(b.coin_count)).catch(() => {}),
      call<HeldAsset[]>("held_assets").then(setAssets).catch(() => {}),
      call<string[]>("whitelisted_assets").then(setWhitelist).catch(() => {}),
    ]);
  }, []);

  async function checkBtc() {
    try {
      setBtc(await call<BtcWallet>("btc_wallet_info"));
    } catch {
      setBtc({ connected: false, balance: 0, deposit_address: "" });
    }
  }

  useEffect(() => {
    void load();
  }, [balance, load]);

  /**
   * The one refresh: every tile spins until its own number is back. The chain scan
   * (ZCRYPT and shielded assets) and the Bitcoin lookup (every address of the wallet, via
   * the Esplora server) run side by side.
   */
  async function refresh() {
    if (spinning) return;
    setSpinning(true);
    try {
      await Promise.all([Promise.resolve(onRefresh()).then(load), checkBtc()]);
    } finally {
      setSpinning(false);
    }
  }
  const amount = (node: React.ReactNode) => (spinning ? <div className="asset-amount"><span className="spinner small" /></div> : node);

  // Non-native shielded assets (zBTC, …) with a positive balance.
  const shielded = assets.filter((a) => a.asset_id !== "0" && a.balance > 0);
  // Whitelisted tickers this wallet holds none of: the names consensus reserves for the
  // project's own pegged assets, shown so people know which ones are real.
  const upcoming = whitelist.filter((t) => !shielded.some((a) => a.ticker.toUpperCase() === t.toUpperCase()));

  return (
    <div>
      <div className="dash-head">
        <h2 className="view-title" style={{ margin: 0 }}>💰 Portfolio</h2>
        <button className="btn-secondary" onClick={refresh} disabled={spinning}>{spinning ? "⟳ Refreshing…" : "🔄 Refresh"}</button>
      </div>

      <div className="asset-grid">
        <div className="asset-tile primary">
          <div className="asset-tile-head">
            <span className="asset-ticker" style={{ color: "var(--color-green)" }}>ZCRYPT</span>
            <span className="asset-kind">native · gas</span>
          </div>
          {amount(<div className="asset-amount" style={{ color: "var(--color-green)", textShadow: "var(--glow-green)" }}>{fmt(balance)}</div>)}
          <div className="asset-sub">
            {count} coin{count === 1 ? "" : "s"} · all spendable
          </div>
        </div>

        {shielded.map((a) => (
          <div className="asset-tile" key={a.asset_id}>
            <div className="asset-tile-head">
              <span className="asset-ticker" style={{ color: "var(--color-yellow)" }}>{a.ticker}</span>
              <span className="asset-kind">
                {isWhitelisted(a.ticker, whitelist) && <span className="whitelisted">whitelisted</span>} shielded
              </span>
            </div>
            {amount(<div className="asset-amount">{fmtAsset(a.balance, a.decimals)}</div>)}
            <div className="asset-sub">private · anonymous among the whole pool</div>
          </div>
        ))}

        <div className="asset-tile">
          <div className="asset-tile-head">
            <span className="asset-ticker" style={{ color: "var(--color-cyan)" }}>₿ BTC</span>
            <span className="asset-kind">bitcoin L1</span>
          </div>
          {spinning ? (
            <>
              {amount(null)}
              <div className="asset-sub">asking your Esplora server…</div>
            </>
          ) : btc === null ? (
            <>
              <div className="asset-amount dim">—</div>
              <div className="asset-sub" title="Refresh asks your Esplora server about your addresses, which reveals them to it. It never runs on its own.">
                press Refresh to check · reveals your addresses to the Esplora server
              </div>
            </>
          ) : btc.connected ? (
            <>
              <div className="asset-amount">{btcFmt(btc.balance)}</div>
              <div className="asset-sub">across all your addresses</div>
            </>
          ) : (
            <>
              <div className="asset-amount dim">—</div>
              <div className="asset-sub">Esplora server not reachable. Set it under Settings → Bitcoin.</div>
            </>
          )}
        </div>

        {upcoming.map((t) => (
          <div className="asset-tile upcoming" key={t}>
            <div className="asset-tile-head">
              <span className="asset-ticker">{t}</span>
              <span className="asset-kind"><span className="whitelisted">whitelisted</span> {whitelistName(t)}</span>
            </div>
            <div className="asset-amount dim">—</div>
            <div className="asset-sub">{t.toUpperCase() === "ZBTC" ? "Shield BTC into zBTC under Bridge." : "Name reserved by the network. Coming with its own bridge."}</div>
          </div>
        ))}
      </div>

      <div className="dash-foot">
        Your addresses are under <b>Receive</b>. <b>Send</b> moves any of these, including Bitcoin. Shield BTC into zBTC under <b>Bridge</b>.
      </div>
    </div>
  );
}
