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

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setClaimable(await call<number>("get_claimable"));
    } catch {
      setClaimable(0);
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
    </div>
  );
}
