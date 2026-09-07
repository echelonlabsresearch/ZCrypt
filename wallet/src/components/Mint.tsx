import { useCallback, useEffect, useState } from "react";
import { call, toBase, toBaseAsset, fmtAsset } from "../lib/api";

/** Every shielded asset uses 8 decimals — one standard for all of them (like BTC/zBTC),
 *  so users never have to pick and amounts always mean the same thing. */
const ASSET_DECIMALS = 8;

interface MinterAsset {
  asset_id: string; // hash-derived u64 — a string, never a JS number (2^53 precision)
  ticker: string;
  decimals: number;
  minted: number;
  balance: number;
}

export default function Mint({ onMinted }: { onMinted: (amount: number) => void }) {
  // ZCRYPT devnet faucet
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  // Shielded-asset mint
  const [ticker, setTicker] = useState("");
  const [aAmount, setAAmount] = useState("");
  const [maxSupply, setMaxSupply] = useState("");
  const [existingTicker, setExistingTicker] = useState(false);
  const [aBusy, setABusy] = useState(false);
  const [aErr, setAErr] = useState("");
  const [aOk, setAOk] = useState("");

  // Assets this wallet is the minter of
  const [mine, setMine] = useState<MinterAsset[]>([]);
  const loadMine = useCallback(() => {
    call<MinterAsset[]>("my_assets").then(setMine).catch(() => {});
  }, []);
  useEffect(() => {
    loadMine();
  }, [loadMine]);

  async function fund() {
    setErr("");
    const base = toBase(amount);
    if (!base || base <= 0) return setErr("Enter a valid amount.");
    setBusy(true);
    try {
      await call<number>("fund_onchain", { amount: base });
      setAmount("");
      onMinted(base);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function mintAsset() {
    setAErr("");
    setAOk("");
    const t = ticker.trim();
    // Every shielded asset uses 8 decimals — one standard for everyone, no choice to get wrong.
    const dec = ASSET_DECIMALS;
    if (!/^[A-Za-z][A-Za-z0-9]{1,9}$/.test(t)) return setAErr("Ticker: 2–10 letters/digits, starting with a letter.");
    const base = toBaseAsset(aAmount, dec);
    if (!base || base <= 0) return setAErr("Enter a valid amount.");
    // On first registration the asset must declare a hard supply cap. When minting
    // more of a ticker you already own, the cap is fixed and this field is ignored.
    let cap = base;
    if (!existingTicker) {
      cap = toBaseAsset(maxSupply, dec);
      if (!cap || cap < base) return setAErr("Max supply must be a number ≥ the amount you're minting.");
    }
    setABusy(true);
    try {
      await call<string>("mint_asset", { ticker: t, amount: base, decimals: dec, maxSupply: cap });
      setAOk(`✓ Minted ${aAmount} ${t}. It's now in Send, and in "Assets you mint" below.`);
      setAAmount("");
      onMinted(0);
      loadMine();
    } catch (e) {
      setAErr(String(e));
    } finally {
      setABusy(false);
    }
  }

  function mintMore(a: MinterAsset) {
    setTicker(a.ticker);
    setAAmount("");
    setMaxSupply("");
    setExistingTicker(true);
    setAErr("");
    setAOk("");
    document.getElementById("mint-asset-form")?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  return (
    <div>
      <h2 className="view-title">💎 Mint (devnet)</h2>

      {mine.length > 0 && (
        <div className="card" style={{ maxWidth: 560, margin: "0 auto 1.2rem" }}>
          <h2>🏷️ Assets you mint</h2>
          <div style={{ fontSize: "0.82rem", opacity: 0.7, marginBottom: "0.6rem" }}>
            Tickers you registered — your wallet holds the mint capability (derived from your seed), so you can
            mint more of these anytime.
          </div>
          {mine.map((a) => (
            <div className="card-row" key={a.asset_id}>
              <div>
                <span style={{ fontWeight: "bold", color: "var(--color-yellow)" }}>{a.ticker}</span>
                <span style={{ opacity: 0.6, fontSize: "0.8rem", marginLeft: "0.6rem" }}>
                  you hold {fmtAsset(a.balance, a.decimals)} · supply {fmtAsset(a.minted, a.decimals)}
                </span>
              </div>
              <button className="copy-btn" onClick={() => mintMore(a)}>+ Mint more</button>
            </div>
          ))}
        </div>
      )}

      <div id="mint-asset-form" className="card" style={{ maxWidth: 560, margin: "0 auto" }}>
        <h2>🪙 Mint a new ZRC20 asset</h2>
        <div style={{ fontSize: "0.82rem", opacity: 0.7, marginBottom: "0.6rem" }}>
          Register a ticker and issue it to yourself. Tickers are <b>first-mint-wins</b> and{" "}
          <b>case-insensitive</b> (<code>zBTC</code> = <code>ZBTC</code> = <code>zbtc</code>). When you're the
          first minter, your <b>mint capability</b> is held in this wallet (derived from your seed) — so you can
          come back and <b>mint more</b> anytime (see "Assets you mint" above). Someone else's ticker (e.g.{" "}
          <b>zBTC</b>, owned by the bridge) can't be minted by you.
        </div>
        <div className="field">
          <label>Ticker</label>
          <input
            value={ticker}
            onChange={(e) => {
              setTicker(e.target.value);
              setExistingTicker(false);
            }}
            placeholder="e.g. GOLD"
            maxLength={10}
          />
        </div>
        {!existingTicker && (
          <div className="field">
            <label>Max supply ({ticker || "asset"})</label>
            <input value={maxSupply} onChange={(e) => setMaxSupply(e.target.value)} placeholder="e.g. 1000000" inputMode="decimal" />
            <div style={{ fontSize: "0.76rem", opacity: 0.6, marginTop: "0.3rem" }}>
              A permanent, on-chain ceiling on this asset's total supply. Set once at registration — it can never be
              raised, so no one (not even you) can mint past it.
            </div>
          </div>
        )}
        <div className="field">
          <label>Amount ({ticker || "asset"})</label>
          <input value={aAmount} onChange={(e) => setAAmount(e.target.value)} placeholder="0.0" inputMode="decimal" />
        </div>
        {aErr && <div className="msg err">{aErr}</div>}
        {aOk && <div className="msg ok">{aOk}</div>}
        <button className="btn-primary btn-block" disabled={aBusy} onClick={mintAsset}>
          {aBusy ? "Registering + minting…" : "🪙 Mint asset"}
        </button>
      </div>

      <div className="card" style={{ maxWidth: 560, margin: "1.2rem auto 0" }}>
        <h2>🚰 Devnet faucet (test ZCRYPT)</h2>
        <div className="warn" style={{ marginBottom: "0.8rem" }}>
          <b>This is not how ZCRYPT is issued.</b> Real ZCRYPT enters supply only via <b>block rewards</b> —
          bond stake and claim them in the <b>Rewards</b> tab — plus the one-time foundation allocation. This
          faucet just seeds <i>test</i> ZCRYPT so you can exercise the wallet on devnet; it has no place on
          mainnet.
        </div>
        <div className="field">
          <label>Amount (test ZCRYPT)</label>
          <input value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0.0" inputMode="decimal" />
        </div>
        {err && <div className="msg err">{err}</div>}
        <button className="btn-secondary btn-block" disabled={busy} onClick={fund}>
          {busy ? "Seeding…" : "🚰 Get test ZCRYPT"}
        </button>
      </div>
    </div>
  );
}
