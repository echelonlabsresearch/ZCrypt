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
  // Become a validator: the consensus PRIVATE key never enters the wallet. Step 1 prepares
  // the bond parameters (a fresh reward key), the validator host signs them, step 2 submits
  // the signature together with a stake pledge from this wallet.
  type BondRequest = {
    reward_index: number;
    reward_address_hex: string;
    chain_id: string;
    stake_base: string;
    commission_bps: number;
    message_layout: string;
  };
  const [stake, setStake] = useState("10000");
  const [commissionPct, setCommissionPct] = useState("10");
  const [bondReq, setBondReq] = useState<BondRequest | null>(null);
  const [vpk, setVpk] = useState("");
  const [nonce, setNonce] = useState("0");
  const [sig, setSig] = useState("");
  const [bonding, setBonding] = useState(false);
  const [bondMsg, setBondMsg] = useState("");
  const [bondErr, setBondErr] = useState("");
  // Reward balances are fetched only on an explicit click (see the note in the UI).
  const [checked, setChecked] = useState(false);
  // Delegate: stake to an existing validator without running a node.
  type ValInfo = { pubkey: string; stake: string; commission_pct: number };
  const [vals, setVals] = useState<ValInfo[]>([]);
  const [selVal, setSelVal] = useState("");
  const [delAmt, setDelAmt] = useState("1000");
  const [delBusy, setDelBusy] = useState(false);
  const [delMsg, setDelMsg] = useState("");
  const [delErr, setDelErr] = useState("");

  // Validators list sends nothing about this wallet to the node: safe to auto-load.
  const loadValidators = useCallback(async () => {
    try {
      const vs = await call<ValInfo[]>("list_validators");
      setVals(vs);
      setSelVal((prev) => prev || vs[0]?.pubkey || "");
    } catch {
      setVals([]);
    }
  }, []);

  // Balance lookups send this wallet's REWARD keys to the node (fresh keys created per bond
  // and delegation, never the payment address). They run only when the user asks.
  const load = useCallback(async () => {
    setLoading(true);
    setChecked(true);
    try {
      setClaimable(await call<number>("get_claimable"));
    } catch {
      setClaimable(0);
    }
    await loadValidators();
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
  }, [loadValidators]);

  useEffect(() => {
    if (active) loadValidators();
  }, [active, loadValidators]);

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

  async function prepareBond() {
    setBondErr("");
    setBondMsg("");
    setBonding(true);
    try {
      const r = await call<BondRequest>("bond_request", {
        stakeZcrypt: stake.trim(),
        commissionPct: commissionPct.trim(),
      });
      setBondReq(r);
    } catch (e) {
      setBondErr(String(e));
    } finally {
      setBonding(false);
    }
  }

  async function submitBond() {
    if (!bondReq) return;
    setBondErr("");
    setBondMsg("");
    setBonding(true);
    try {
      const msg = await call<string>("bond_validator_signed", {
        rewardIndex: bondReq.reward_index,
        consensusPubkeyHex: vpk.trim(),
        nonce: nonce.trim(),
        signatureHex: sig.trim(),
        stakeZcrypt: stake.trim(),
        commissionPct: commissionPct.trim(),
      });
      setBondMsg(msg);
      setBondReq(null);
      setVpk("");
      setSig("");
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
            {!checked ? "not checked" : loading ? "…" : `${fmt(claimable)} ZCRYPT`}
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
          {checked ? "↻ Check again" : "🔎 Check rewards"}
        </button>
        <div className="warn" style={{ marginTop: "1rem" }}>
          Checking asks the node for the balances of this wallet's <b>reward keys</b>: a fresh key is created
          for every bond and delegation, so your payment address is never sent. The node still learns that this
          session owns those keys, which is why the check only runs when you click. Claiming mints coinbase
          coins <b>bound to your key</b>; only you can spend them. The amount is fixed by the emission schedule,
          so a validator can never mint itself extra.
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
          Bond a running validator node using a stake from <b>this wallet's balance</b>. The validator's
          consensus <b>private key stays on the validator host</b>: the wallet prepares the bond, the host
          signs it, and the wallet submits the signature with the stake pledge. Rewards accrue to a fresh
          reward key of this wallet. The stake is pledged (burned) and returns after a 10-day unbond.
        </div>
        <div className="field">
          <label>Stake (ZCRYPT, min 10,000)</label>
          <input
            value={stake}
            onChange={(e) => setStake(e.target.value)}
            inputMode="numeric"
            disabled={!!bondReq}
          />
        </div>
        <div className="field">
          <label>Commission % (your cut of delegators' rewards)</label>
          <input
            value={commissionPct}
            onChange={(e) => setCommissionPct(e.target.value)}
            inputMode="decimal"
            disabled={!!bondReq}
          />
          <div style={{ fontSize: "0.72rem", opacity: 0.6, marginTop: 4 }}>
            Lower commission attracts more delegators; you keep this % of what your
            delegators earn. 0-100%.
          </div>
        </div>
        {!bondReq ? (
          <button className="btn-primary btn-block" disabled={bonding} onClick={prepareBond}>
            {bonding ? "Preparing…" : "1. Prepare bond (creates the reward key)"}
          </button>
        ) : (
          <>
            <div className="mono-box" style={{ fontSize: "0.74rem", whiteSpace: "pre-wrap" }}>
{`reward_address = ${bondReq.reward_address_hex}
chain_id       = ${bondReq.chain_id}
stake_base     = ${bondReq.stake_base}
commission_bps = ${bondReq.commission_bps}`}
            </div>
            <div style={{ fontSize: "0.74rem", opacity: 0.7, margin: "0.4rem 0 0.6rem" }}>
              2. On the validator host, sign with the consensus key (ed25519) the bytes{" "}
              <code>{bondReq.message_layout}</code>, where <code>nonce</code> is the node's{" "}
              <code>/staking/auth_nonce/&lt;consensus_pubkey_hex&gt;</code>. Then paste the pubkey, the nonce
              you used and the signature below. Nothing secret is entered here.
            </div>
            <div className="field">
              <label>Validator consensus PUBLIC key (hex, 64 chars)</label>
              <input value={vpk} onChange={(e) => setVpk(e.target.value)} spellCheck={false} />
            </div>
            <div className="field">
              <label>Nonce used in the signature</label>
              <input value={nonce} onChange={(e) => setNonce(e.target.value)} inputMode="numeric" />
            </div>
            <div className="field">
              <label>Signature (hex, 128 chars)</label>
              <input value={sig} onChange={(e) => setSig(e.target.value)} spellCheck={false} />
            </div>
            <button
              className="btn-primary btn-block"
              disabled={bonding || vpk.trim().length !== 64 || sig.trim().length !== 128}
              onClick={submitBond}
            >
              {bonding ? "Bonding on-chain…" : `3. Bond ${stake || "?"} ZCRYPT`}
            </button>
            <button className="btn-link" style={{ marginTop: "0.5rem" }} onClick={() => setBondReq(null)}>
              Cancel
            </button>
          </>
        )}
        {bondErr && <div className="msg err">{bondErr}</div>}
        {bondMsg && <div className="msg ok">{bondMsg}</div>}
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
