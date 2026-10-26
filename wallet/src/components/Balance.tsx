import { useCallback, useEffect, useState } from "react";
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
export default function Balance({ balance, onRefresh }: { balance: number; onRefresh: () => void }) {
  const [count, setCount] = useState(0);
  const [spinning, setSpinning] = useState(false);
  const [assets, setAssets] = useState<HeldAsset[]>([]);
  const [btc, setBtc] = useState<BtcWallet | null>(null);
  const [btcBusy, setBtcBusy] = useState(false);
  const [whitelist, setWhitelist] = useState<string[]>([]);

  const load = useCallback(() => {
    call<{ coin_count: number }>("get_balance").then((b) => setCount(b.coin_count)).catch(() => {});
    call<HeldAsset[]>("held_assets").then(setAssets).catch(() => {});
    call<string[]>("whitelisted_assets").then(setWhitelist).catch(() => {});
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
    if (btc?.connected) checkBtc();
    setTimeout(() => setSpinning(false), 400);
  }

  // Non-native shielded assets (zBTC, …) with a positive balance.
  const shielded = assets.filter((a) => a.asset_id !== "0" && a.balance > 0);
  // Whitelisted tickers this wallet holds none of: the names consensus reserves for the
  // project's own pegged assets, shown so people know which ones are real.
  const upcoming = whitelist.filter((t) => !shielded.some((a) => a.ticker.toUpperCase() === t.toUpperCase()));

  return (
    <div>
      <div className="dash-head">
        <h2 className="view-title" style={{ margin: 0 }}>💰 Portfolio</h2>
        <button className="btn-secondary" onClick={refresh}>{spinning ? "⟳ …" : "🔄 Refresh"}</button>
      </div>

      <div className="asset-grid">
        <div className="asset-tile primary">
          <div className="asset-tile-head">
            <span className="asset-ticker" style={{ color: "var(--color-green)" }}>ZCRYPT</span>
            <span className="asset-kind">native · gas</span>
          </div>
          <div className="asset-amount" style={{ color: "var(--color-green)", textShadow: "var(--glow-green)" }}>{fmt(balance)}</div>
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
            <div className="asset-amount">{fmtAsset(a.balance, a.decimals)}</div>
            <div className="asset-sub">private · anonymous among the whole pool</div>
          </div>
        ))}

        <div className="asset-tile">
          <div className="asset-tile-head">
            <span className="asset-ticker" style={{ color: "var(--color-cyan)" }}>₿ BTC</span>
            <span className="asset-kind">bitcoin L1</span>
          </div>
          {btc === null ? (
            <>
              <div className="asset-amount dim">—</div>
              <div className="asset-sub">
                <button className="btn-link" style={{ padding: 0 }} disabled={btcBusy} onClick={checkBtc}>
                  {btcBusy ? "Checking…" : "Check balance"}
                </button>
                <span title="Checking asks your Esplora server about your deposit address, which reveals that address to it. It never runs on its own."> · reveals your address to the Esplora server</span>
              </div>
            </>
          ) : btc.connected ? (
            <>
              <div className="asset-amount">{btcFmt(btc.balance)}</div>
              <div className="asset-sub">
                on the deposit address ·{" "}
                <button className="btn-link" style={{ padding: 0 }} disabled={btcBusy} onClick={checkBtc}>
                  {btcBusy ? "…" : "re-check"}
                </button>
              </div>
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
