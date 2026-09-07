import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { call, toBaseAsset } from "../lib/api";
import { CopyButton } from "./Share";

interface Status {
  btc_connected: boolean;
  btc_balance: number;
  zbtc_asset: number;
  /** Spendable zBTC (matured — in the on-chain tree). */
  zbtc_balance: number;
  /** Freshly-shielded zBTC still MATURING (held out of the spendable pool by the
   *  deep-reorg defense until its BTC deposit is buried past reorg risk). */
  zbtc_maturing: number;
  btc_network: string;
  deposit_address: string;
  lp_address: string;
}

interface Progress {
  percent: number;
  phase: string;
}

/** 1 zBTC = 100,000,000 base units (8 decimals, like BTC). */
const ZBTC_BASE = 100_000_000;
const zfmt = (base: number) => (base / ZBTC_BASE).toLocaleString(undefined, { maximumFractionDigits: 8 });

type Tab = "shield" | "redeem";

export default function Bridge({
  active,
  onSwapped,
}: {
  active: boolean;
  onSwapped: (msg: string) => void;
}) {
  const [status, setStatus] = useState<Status | null>(null);
  const [tab, setTab] = useState<Tab>("shield");
  const [shieldAmt, setShieldAmt] = useState("0.05");
  const [redeemAmt, setRedeemAmt] = useState("0.05");
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const [progress, setProgress] = useState<Progress | null>(null);
  const [fixMsg, setFixMsg] = useState("");

  const load = useCallback(async () => {
    try {
      setStatus(await call<Status>("bridge_status"));
    } catch {
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, load]);

  // While any zBTC is maturing, relay fresh Bitcoin headers to the chain and refresh,
  // so the deposit's confirmations climb toward maturity and the coin becomes spendable.
  useEffect(() => {
    if (!active || !status || (status.zbtc_maturing ?? 0) <= 0) return;
    const t = setInterval(async () => {
      try {
        await call<string>("bridge_mature");
      } catch {
        /* best-effort */
      }
      await load();
    }, 15_000);
    return () => clearInterval(t);
  }, [active, status, load]);

  // Live swap progress: the backend emits "swap-progress" as each atomic-swap step settles.
  useEffect(() => {
    const un = listen<Progress>("swap-progress", (e) => setProgress(e.payload));
    return () => {
      un.then((f) => f());
    };
  }, []);

  function switchTab(t: Tab) {
    setTab(t);
    setErr("");
    setFixMsg("");
  }

  async function recover() {
    setErr("");
    setFixMsg("");
    setBusy("recover");
    try {
      const r = await call<{ message: string }>("bridge_recover");
      setFixMsg(r.message);
      await load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy("");
    }
  }

  async function init() {
    setErr("");
    setBusy("init");
    try {
      await call<number>("bridge_init");
      await load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy("");
    }
  }

  async function shield() {
    setErr("");
    setFixMsg("");
    let sats: number;
    try {
      sats = toBaseAsset(shieldAmt, 8);
    } catch {
      return setErr("Enter a valid BTC amount to shield.");
    }
    if (sats <= 0) return setErr("Enter a BTC amount to shield.");
    setBusy("shield");
    setProgress({ percent: 0, phase: "Starting the atomic swap…" });
    try {
      // 1:1 peg — consensus-enforced (SPV: minted base units ≤ locked sats)
      await call<number>("swap_shield_btc", { zbtcAmount: sats, btc: shieldAmt.trim() });
      onSwapped(`Shielded ${shieldAmt.trim()} BTC → ${shieldAmt.trim()} zBTC`);
      await load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy("");
      setTimeout(() => setProgress(null), 1200);
    }
  }

  async function redeem() {
    setErr("");
    setFixMsg("");
    let sats: number;
    try {
      sats = toBaseAsset(redeemAmt, 8);
    } catch {
      return setErr("Enter a valid zBTC amount to redeem.");
    }
    if (sats <= 0) return setErr("Enter a zBTC amount to redeem.");
    setBusy("redeem");
    setProgress({ percent: 0, phase: "Starting the atomic swap…" });
    try {
      // The backend redeems in rounds when the balance is fragmented, each round
      // burning a small zBTC fee, so the amount actually redeemed can be a hair under
      // the request. Report what really went out (returned in base units).
      const redeemedBase = await call<number>("swap_redeem_btc", { btc: redeemAmt.trim() });
      const got = redeemedBase / ZBTC_BASE;
      const note = redeemedBase < sats ? " (per-round zBTC fees deducted)" : "";
      onSwapped(`Redeemed ${zfmt(redeemedBase)} zBTC → ${got.toFixed(8)} BTC${note}`);
      await load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy("");
      setTimeout(() => setProgress(null), 1200);
    }
  }

  function redeemMax() {
    if (!status) return;
    // Request the full balance: the backend drains it in as many rounds as needed and
    // returns the achievable amount (each round burns one fee), so we don't pre-subtract.
    const max = Math.max(0, status.zbtc_balance / ZBTC_BASE);
    setRedeemAmt(max.toFixed(8).replace(/\.?0+$/, ""));
  }

  const zbtcBal = status ? status.zbtc_balance / ZBTC_BASE : 0;

  return (
    <div>
      <h2 className="view-title">₿ ⇄ zBTC Bridge</h2>
      <div className="card" style={{ maxWidth: 620, margin: "0 auto" }}>
        <div className="bridge-stats">
          <div className="bridge-stat">
            <span className="util">Bitcoin ({status?.btc_network ?? "…"})</span>
            <div className="reward-amount" style={{ fontSize: "1.5rem", color: "var(--color-cyan)" }}>
              {status?.btc_connected ? `${status.btc_balance.toFixed(4)} BTC` : "— not connected"}
            </div>
          </div>
          <div className="bridge-stat">
            <span className="util">Shielded zBTC (spendable)</span>
            <div className="reward-amount" style={{ fontSize: "1.5rem" }}>
              {status ? `${zfmt(status.zbtc_balance)} zBTC` : "…"}
            </div>
          </div>
          <div
            className="bridge-stat"
            style={
              status && (status.zbtc_maturing ?? 0) > 0
                ? { borderColor: "var(--color-amber, #d99a00)", background: "rgba(217,154,0,0.06)" }
                : undefined
            }
          >
            <span className="util">Shielded zBTC (maturing)</span>
            <div
              className="reward-amount"
              style={{
                fontSize: "1.5rem",
                color:
                  status && (status.zbtc_maturing ?? 0) > 0
                    ? "var(--color-amber, #d99a00)"
                    : "var(--color-text-dim)",
              }}
            >
              {status ? `${(status.zbtc_maturing ?? 0) > 0 ? "⏳ " : ""}${zfmt(status.zbtc_maturing ?? 0)} zBTC` : "…"}
            </div>
          </div>
        </div>

        {status && (status.zbtc_maturing ?? 0) > 0 && (
          <div
            className="card"
            style={{ marginTop: "0.75rem", background: "var(--bg-grid)", borderLeft: "3px solid var(--color-amber, #d99a00)" }}
          >
            <div style={{ fontWeight: "bold" }}>
              ⏳ {zfmt(status.zbtc_maturing)} zBTC maturing
            </div>
            <div style={{ fontSize: "0.72rem", color: "var(--color-text-dim)", marginTop: 4 }}>
              Freshly-shielded zBTC is held out of the spendable pool until its Bitcoin
              deposit is buried past reorg risk (the deep-reorg defense) — so a chain
              reorg can still void it before it can be spent. It becomes spendable/redeemable
              automatically once the deposit matures (near-instant on regtest, up to ~a few
              hours on mainnet). This tab keeps relaying Bitcoin headers to advance it.
            </div>
          </div>
        )}

        {status && (status.deposit_address || status.lp_address) && (
          <div className="card" style={{ marginTop: "1rem", background: "var(--bg-grid)" }}>
            <div style={{ fontWeight: "bold", color: "var(--color-text-dim)", marginBottom: 6 }}>
              Fund these seed-derived addresses to test (self-custody, no node)
            </div>
            <div style={{ fontSize: "0.72rem", color: "var(--color-text-dim)", marginBottom: 8 }}>
              Fund <b>your</b> address to SHIELD; fund the <b>LP</b> address too to test REDEEM
              (the LP needs BTC to pay out). Both derive from your mnemonic.
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span style={{ minWidth: 40 }}>You</span>
              <code style={{ fontSize: "0.72rem", wordBreak: "break-all", flex: 1 }}>{status.deposit_address || "—"}</code>
              <CopyButton text={status.deposit_address} />
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ minWidth: 40 }}>LP</span>
              <code style={{ fontSize: "0.72rem", wordBreak: "break-all", flex: 1 }}>{status.lp_address || "—"}</code>
              <CopyButton text={status.lp_address} />
            </div>
          </div>
        )}

        {status && status.zbtc_asset === 0 && (
          <div className="warn" style={{ marginTop: "1rem" }}>
            zBTC isn't registered on this chain yet.{" "}
            <button className="btn-link" disabled={busy !== ""} onClick={init}>
              {busy === "init" ? "Registering…" : "Register zBTC + seed pool"}
            </button>
          </div>
        )}

        {/* Direction tabs */}
        <div className="seg" style={{ marginTop: "1.3rem" }}>
          <button
            className={`seg-btn ${tab === "shield" ? "active" : ""}`}
            onClick={() => switchTab("shield")}
            disabled={busy !== ""}
          >
            ₿ → zBTC <span className="seg-sub">Shield</span>
          </button>
          <button
            className={`seg-btn ${tab === "redeem" ? "active" : ""}`}
            onClick={() => switchTab("redeem")}
            disabled={busy !== ""}
          >
            zBTC → ₿ <span className="seg-sub">Redeem</span>
          </button>
        </div>

        {tab === "shield" ? (
          <>
            <div className="field" style={{ marginTop: "1.2rem" }}>
              <label>Amount to shield (BTC)</label>
              <input
                value={shieldAmt}
                onChange={(e) => setShieldAmt(e.target.value)}
                inputMode="decimal"
                placeholder="0.05"
              />
              <div style={{ fontSize: "0.74rem", opacity: 0.6, marginTop: "0.3rem" }}>
                Locks this much BTC in an on-chain HTLC and mints the same amount of hidden zBTC (1:1).
              </div>
            </div>
            {err && <div className="msg err">{err}</div>}
            {renderProgress(progress)}
            <button className="btn-primary btn-block" disabled={busy !== ""} onClick={shield}>
              {busy === "shield" ? "Swapping BTC → zBTC…" : "Shield BTC → zBTC"}
            </button>
          </>
        ) : (
          <>
            <div className="field" style={{ marginTop: "1.2rem" }}>
              <label>
                Amount to redeem (zBTC)
                <button
                  className="btn-link"
                  style={{ float: "right", fontSize: "0.72rem" }}
                  disabled={busy !== "" || !status}
                  onClick={redeemMax}
                >
                  Max {status ? `(${zfmt(status.zbtc_balance)})` : ""}
                </button>
              </label>
              <input
                value={redeemAmt}
                onChange={(e) => setRedeemAmt(e.target.value)}
                inputMode="decimal"
                placeholder="0.05"
              />
              <div style={{ fontSize: "0.74rem", opacity: 0.6, marginTop: "0.3rem" }}>
                Burns this much zBTC and releases the same amount of BTC (1:1). Any remaining zBTC stays
                in your wallet as change. You have <b>{zfmt(status?.zbtc_balance ?? 0)} zBTC</b> spendable.
              </div>
            </div>
            {err && <div className="msg err">{err}</div>}
            {renderProgress(progress)}
            <button
              className="btn-primary btn-block"
              disabled={busy !== "" || zbtcBal <= 0}
              onClick={redeem}
            >
              {busy === "redeem" ? "Swapping zBTC → BTC…" : "Redeem zBTC → BTC"}
            </button>
          </>
        )}

        <div style={{ display: "flex", gap: "1rem", marginTop: "0.8rem", flexWrap: "wrap" }}>
          <button className="btn-link" disabled={busy !== ""} onClick={load}>
            ↻ Refresh
          </button>
          <button
            className="btn-link"
            disabled={busy !== ""}
            onClick={recover}
            title="Reconcile zBTC with the chain and clear anything stuck"
          >
            {busy === "recover" ? "Checking…" : "🔧 Diagnose & fix a stuck swap"}
          </button>
        </div>
        {fixMsg && (
          <div className="msg ok" style={{ marginTop: "0.8rem", fontSize: "0.84rem" }}>
            {fixMsg}
          </div>
        )}

        <div className="warn" style={{ marginTop: "1rem" }}>
          Trustless cross-chain <b>atomic swap</b>: one SHA-256 hashlock settles a Bitcoin HTLC and a
          ZCrypt shield-HTLC escrow together — reveal the preimage to claim one leg and it unlocks the
          other, so neither side can take without giving. <b>Shield</b> locks BTC and mints hidden zBTC;
          <b> Redeem</b> burns a chosen amount of zBTC and releases the matching BTC, keeping the rest as
          change. Each step updates the progress bar as it settles on-chain. Requires bitcoind (regtest)
          + a node (Settings).
        </div>
      </div>
    </div>
  );
}

function renderProgress(progress: Progress | null) {
  if (!progress) return null;
  return (
    <div style={{ margin: "1rem 0" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: "0.82rem",
          marginBottom: "0.35rem",
        }}
      >
        <span style={{ opacity: 0.85 }}>{progress.phase}</span>
        <span style={{ color: "var(--color-cyan)", fontVariantNumeric: "tabular-nums" }}>
          {progress.percent}%
        </span>
      </div>
      <div style={{ height: 8, borderRadius: 5, background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
        <div
          style={{
            height: "100%",
            width: `${progress.percent}%`,
            borderRadius: 5,
            background: "linear-gradient(90deg, var(--color-purple), var(--color-cyan))",
            transition: "width 0.4s ease",
          }}
        />
      </div>
    </div>
  );
}
