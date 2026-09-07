import { useCallback, useEffect, useState } from "react";
import { call, fmt } from "../lib/api";

/** Claim accrued staking block rewards into spendable shield coins. */
export default function Rewards({
  active,
  onClaimed,
}: {
  active: boolean;
  onClaimed: (amount: number) => void;
}) {
  const [claimable, setClaimable] = useState(0);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  // Bridge-fee yield (asset-denominated, e.g. zBTC) — earned by validators AND delegators.
  type FeeYield = { asset_id: string; ticker: string; decimals: number; amount: string };
  const [fees, setFees] = useState<FeeYield[]>([]);
  const [feeBusy, setFeeBusy] = useState("");
  // Pending unbonding (validator unbond or undelegate): persists until the 10-day timer ends.
  type Unbonding = { stake: string; release_time: string };
  const [unbonding, setUnbonding] = useState<Unbonding[]>([]);
  // Become a validator: bond a node's consensus key with a stake from this wallet.
  const [seed, setSeed] = useState("");
  const [stake, setStake] = useState("10000");
  const [commissionPct, setCommissionPct] = useState("10");
  const [bonding, setBonding] = useState(false);
  const [bondMsg, setBondMsg] = useState("");
  const [bondErr, setBondErr] = useState("");
  // Delegate: stake to an existing validator without running a node.
  type ValInfo = { pubkey: string; stake: string; commission_pct: number };
  const [vals, setVals] = useState<ValInfo[]>([]);
  const [selVal, setSelVal] = useState("");
  const [delAmt, setDelAmt] = useState("1000");
  const [delBusy, setDelBusy] = useState(false);
  const [delMsg, setDelMsg] = useState("");
  const [delErr, setDelErr] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setClaimable(await call<number>("get_claimable"));
    } catch {
      setClaimable(0);
    }
    try {
      const vs = await call<ValInfo[]>("list_validators");
      setVals(vs);
      setSelVal((prev) => prev || vs[0]?.pubkey || "");
    } catch {
      setVals([]);
    }
    try {
      setFees(await call<FeeYield[]>("claimable_fees"));
    } catch {
      setFees([]);
    }
    try {
      setUnbonding(await call<Unbonding[]>("my_unbonding"));
    } catch {
      setUnbonding([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, load]);

  async function claim() {
    setErr("");
    setBusy(true);
    try {
      const r = await call<{ claimed: number; coins: number }>("claim_rewards");
      onClaimed(r.claimed);
      await load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function claimFee(assetId: string) {
    setErr("");
    setFeeBusy(assetId);
    try {
      await call<number>("claim_fees", { assetId });
      await load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setFeeBusy("");
    }
  }

  async function bond() {
    setBondErr("");
    setBondMsg("");
    setBonding(true);
    try {
      const msg = await call<string>("bond_validator", {
        consensusSeedHex: seed.trim(),
        stakeZcrypt: stake.trim(),
        commissionPct: commissionPct.trim(),
      });
      setBondMsg(msg);
      setSeed("");
      await load();
    } catch (e) {
      setBondErr(String(e));
    } finally {
      setBonding(false);
    }
  }

  async function delegate() {
    setDelErr("");
    setDelMsg("");
    setDelBusy(true);
    try {
      const msg = await call<string>("delegate_validator", {
        validatorPubkeyHex: selVal,
        stakeZcrypt: delAmt,
      });
      setDelMsg(msg);
      await load();
    } catch (e) {
      setDelErr(String(e));
    } finally {
      setDelBusy(false);
    }
  }

  async function undelegate() {
    setDelErr("");
    setDelMsg("");
    setDelBusy(true);
    try {
      const msg = await call<string>("undelegate_validator", { validatorPubkeyHex: selVal });
      setDelMsg(msg);
      await load();
    } catch (e) {
      setDelErr(String(e));
    } finally {
      setDelBusy(false);
    }
  }

  return (
    <div>
      <h2 className="view-title">🏆 Staking Rewards</h2>
      <div className="card" style={{ maxWidth: 560, margin: "0 auto" }}>
        <div className="field">
          <label>Claimable</label>
          <div className="reward-amount">
            {loading ? "…" : `${fmt(claimable)} ZCRYPT`}
          </div>
        </div>
        {err && <div className="msg err">{err}</div>}
        <button
          className="btn-primary btn-block"
          disabled={busy || loading || claimable === 0}
          onClick={claim}
        >
          {busy
            ? "Claiming on-chain…"
            : claimable === 0
              ? "Nothing to claim"
              : `Claim ${fmt(claimable)} ZCRYPT`}
        </button>
        <button
          className="btn-secondary btn-block"
          style={{ marginTop: "0.6rem" }}
          disabled={loading || busy}
          onClick={load}
        >
          ↻ Refresh
        </button>
        <div className="warn" style={{ marginTop: "1rem" }}>
          Block rewards accrue to this wallet's address when a validator bonded to it
          signs blocks — every epoch, the reward is split by <b>stake × participation</b>.
          Claiming mints coinbase coins <b>bound to your key</b> into the note tree; only
          you can spend them. The amount is fixed by the emission schedule, so a validator
          can never mint itself extra. Requires a node connection (Settings).
        </div>
      </div>

      <div className="card" style={{ maxWidth: 560, margin: "1.25rem auto 0" }}>
        <h3 style={{ marginTop: 0 }}>🌉 Bridge-fee yield</h3>
        <div style={{ fontSize: "0.82rem", opacity: 0.75, marginBottom: "0.7rem" }}>
          Real asset-denominated yield (e.g. zBTC) from bridge volume, earned by validators{" "}
          <b>and delegators</b> by stake × participation, net of commission. Separate from
          ZCRYPT block rewards above.
        </div>
        {fees.length === 0 ? (
          <div className="warn">No bridge-fee yield to claim yet.</div>
        ) : (
          fees.map((f) => (
            <div
              key={f.asset_id}
              style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.6rem", marginBottom: "0.5rem" }}
            >
              <div className="reward-amount" style={{ fontSize: "1.1rem" }}>
                {(Number(f.amount) / 10 ** f.decimals).toFixed(Math.min(f.decimals, 8))} {f.ticker}
              </div>
              <button
                className="btn-primary"
                disabled={feeBusy === f.asset_id}
                onClick={() => claimFee(f.asset_id)}
              >
                {feeBusy === f.asset_id ? "Claiming…" : `Claim ${f.ticker}`}
              </button>
            </div>
          ))
        )}
      </div>

      <div className="card" style={{ maxWidth: 560, margin: "1.25rem auto 0" }}>
        <h3 style={{ marginTop: 0 }}>🛡️ Become a validator</h3>
        <div style={{ fontSize: "0.82rem", opacity: 0.75, marginBottom: "0.7rem" }}>
          Bond a running validator node using a stake from <b>this wallet's balance</b>.
          Rewards from the validator accrue here. The stake is pledged (burned) and returns
          after a 10-day unbond.
        </div>
        <div className="field">
          <label>Validator consensus key (hex)</label>
          <input
            value={seed}
            onChange={(e) => setSeed(e.target.value)}
            placeholder="first 32 bytes of the node's priv_validator_key.json"
            spellCheck={false}
          />
          <div style={{ fontSize: "0.72rem", opacity: 0.6, marginTop: 4 }}>
            Get it with:{" "}
            <code>
              docker exec zcrypt-validator-cometbft cat /cometbft/config/priv_validator_key.json
            </code>{" "}
            (base64-decode <code>priv_key.value</code>, first 32 bytes, hex).
          </div>
        </div>
        <div className="field">
          <label>Stake (ZCRYPT, min 10,000)</label>
          <input
            value={stake}
            onChange={(e) => setStake(e.target.value)}
            inputMode="numeric"
          />
        </div>
        <div className="field">
          <label>Commission % (your cut of delegators' rewards)</label>
          <input
            value={commissionPct}
            onChange={(e) => setCommissionPct(e.target.value)}
            inputMode="decimal"
          />
          <div style={{ fontSize: "0.72rem", opacity: 0.6, marginTop: 4 }}>
            Lower commission attracts more delegators; you keep this % of what your
            delegators earn. 0-100%.
          </div>
        </div>
        {bondErr && <div className="msg err">{bondErr}</div>}
        {bondMsg && <div className="msg ok">{bondMsg}</div>}
        <button
          className="btn-primary btn-block"
          disabled={bonding || !seed.trim()}
          onClick={bond}
        >
          {bonding ? "Bonding on-chain…" : `Bond ${stake || "?"} ZCRYPT`}
        </button>
      </div>

      <div className="card" style={{ maxWidth: 560, margin: "1.25rem auto 0" }}>
        <h3 style={{ marginTop: 0 }}>🤝 Delegate to a validator</h3>
        <div style={{ fontSize: "0.82rem", opacity: 0.75, marginBottom: "0.7rem" }}>
          Stake to an existing validator without running a node. You earn a share of its
          rewards (minus its commission); your stake returns after a 10-day undelegate.
        </div>
        {vals.length === 0 ? (
          <div className="warn">No bonded validators to delegate to yet.</div>
        ) : (
          <>
            <div className="field">
              <label>Validator</label>
              <select value={selVal} onChange={(e) => setSelVal(e.target.value)}>
                {vals.map((v) => (
                  <option key={v.pubkey} value={v.pubkey}>
                    {v.pubkey.slice(0, 16)}… · {fmt(Number(v.stake))} staked · {v.commission_pct}% commission
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>Amount (ZCRYPT)</label>
              <input value={delAmt} onChange={(e) => setDelAmt(e.target.value)} inputMode="numeric" />
            </div>
            {delErr && <div className="msg err">{delErr}</div>}
            {delMsg && <div className="msg ok">{delMsg}</div>}
            <button
              className="btn-primary btn-block"
              disabled={delBusy || !selVal}
              onClick={delegate}
            >
              {delBusy ? "Working on-chain…" : `Delegate ${delAmt || "?"} ZCRYPT`}
            </button>
            <button
              className="btn-secondary btn-block"
              style={{ marginTop: "0.6rem" }}
              disabled={delBusy || !selVal}
              onClick={undelegate}
            >
              Undelegate from this validator
            </button>
          </>
        )}
      </div>

      {unbonding.length > 0 && (
        <div className="card" style={{ maxWidth: 560, margin: "1.25rem auto 0" }}>
          <h3 style={{ marginTop: 0 }}>⏳ Unbonding</h3>
          <div style={{ fontSize: "0.82rem", opacity: 0.75, marginBottom: "0.7rem" }}>
            Stake you unbonded or undelegated, locked for the 10-day unbonding period. It
            returns to this wallet as claimable balance when the timer ends.
          </div>
          {unbonding.map((u, i) => {
            const releaseMs = Number(u.release_time) * 1000;
            const days = Math.max(0, Math.ceil((releaseMs - Date.now()) / 86_400_000));
            return (
              <div
                key={i}
                style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.6rem", marginBottom: "0.5rem" }}
              >
                <div className="reward-amount" style={{ fontSize: "1.1rem" }}>
                  {fmt(Number(u.stake))} ZCRYPT
                </div>
                <div style={{ fontSize: "0.8rem", opacity: 0.8, textAlign: "right" }}>
                  {days > 0 ? `free in ~${days} day${days === 1 ? "" : "s"}` : "releasing…"}
                  <br />
                  <span style={{ opacity: 0.6 }}>{new Date(releaseMs).toLocaleDateString()}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
