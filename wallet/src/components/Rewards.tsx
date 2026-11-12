import { useCallback, useEffect, useState } from "react";
import { call, copySensitive, fmt } from "../lib/api";

/**
 * Staking home.
 *
 * Not validating and not delegating: two equal cards (run a validator, delegate).
 * Validating: one dashboard. An existing delegation stays reachable so its stake
 * can be unbonded, but the delegate setup is not shown.
 * Delegating and not validating: one dashboard. Several live delegations are all listed.
 * After unbond or undelegate the setup returns, and each returning stake keeps its line
 * until it is withdrawn into the wallet. Matured stake is credited as claimable and
 * comes back through the same claim the reward button uses.
 */

type FeeYield = { asset_id: string; ticker: string; decimals: number; amount: string };
type Unbonding = { stake: string; release_time: string };
type ValidatorIdentity = {
  pubkey_hex: string;
  env_line: string;
  bonded: boolean;
  stake: number;
  commission_pct: number;
  ever_bonded: boolean;
  signed_this_epoch: number;
  epoch_progress: number;
  epoch_blocks: number;
  /** Base units, as a string (u64). */
  delegated: string;
  delegation_count: number;
};
type ValInfo = { pubkey: string; stake: string; commission_pct: number };
type MyDelegation = {
  validator_pubkey: string;
  index: number;
  legacy: boolean;
  stake: string;
  commission_pct: number;
};
type Claimable = { ready: number; accruing: number; accruing_keys: number };

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function releaseLabel(unix: string): string {
  const d = new Date(Number(unix) * 1000);
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
}

function noticeId(u: Unbonding): string {
  return `${u.stake}:${u.release_time}`;
}

function noticeStore(pubkey: string): string {
  return `zcrypt.unbonding.${pubkey}`;
}

function saneNotice(u: unknown): u is Unbonding {
  if (!u || typeof u !== "object") return false;
  const x = u as Unbonding;
  return /^\d+$/.test(x.stake) && /^\d+$/.test(x.release_time);
}

function readNotices(pubkey: string): Unbonding[] {
  try {
    const raw = localStorage.getItem(noticeStore(pubkey));
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter(saneNotice) : [];
  } catch {
    return [];
  }
}

function writeNotices(pubkey: string, items: Unbonding[]) {
  localStorage.setItem(noticeStore(pubkey), JSON.stringify(items));
}

function mergeNotices(local: Unbonding[], chain: Unbonding[]): Unbonding[] {
  const map = new Map<string, Unbonding>();
  for (const u of local) map.set(noticeId(u), u);
  for (const u of chain) map.set(noticeId(u), u);
  return [...map.values()].sort((a, b) => Number(a.release_time) - Number(b.release_time));
}

function shortPk(pk: string): string {
  const s = pk.trim();
  return s.length <= 8 ? s : `${s.slice(0, 8)}…`;
}

function zcrypt(base: number | string): string {
  return `${fmt(Number(base))} ZCRYPT`;
}

function delegatedLine(count: number, delegated: string): string {
  const amount = Number(delegated);
  if (!count && !amount) return "None";
  if (!count) return zcrypt(delegated);
  const wallets = count === 1 ? "1 wallet" : `${count} wallets`;
  return `${wallets} · ${zcrypt(delegated)}`;
}

export default function Rewards({
  active,
  onClaimed,
}: {
  active: boolean;
  onClaimed: (amount: number) => void;
}) {
  const [ready, setReady] = useState(0);
  const [accruing, setAccruing] = useState(0);
  const [accruingKeys, setAccruingKeys] = useState(0);
  const [balancesOk, setBalancesOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [fees, setFees] = useState<FeeYield[]>([]);
  const [feeBusy, setFeeBusy] = useState("");
  const [feeMsg, setFeeMsg] = useState("");
  const [unbonding, setUnbonding] = useState<Unbonding[]>([]);
  const [unbondLoaded, setUnbondLoaded] = useState(false);
  const [unbondErr, setUnbondErr] = useState("");
  const [notices, setNotices] = useState<Unbonding[]>([]);
  const [ident, setIdent] = useState<ValidatorIdentity | null>(null);
  const [identErr, setIdentErr] = useState("");
  const [identLoaded, setIdentLoaded] = useState(false);
  const [nodeReady, setNodeReady] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  const [stake, setStake] = useState("10000");
  const [commissionPct, setCommissionPct] = useState("10");
  const [bonding, setBonding] = useState(false);
  const [bondErr, setBondErr] = useState("");
  const [vals, setVals] = useState<ValInfo[]>([]);
  const [selVal, setSelVal] = useState("");
  const [delAmt, setDelAmt] = useState("1000");
  const [delBusy, setDelBusy] = useState(false);
  const [delErr, setDelErr] = useState("");
  const [dels, setDels] = useState<MyDelegation[]>([]);
  const [delLoadErr, setDelLoadErr] = useState("");
  const [delsLoaded, setDelsLoaded] = useState(false);

  const loadValidators = useCallback(async () => {
    try {
      const vs = await call<ValInfo[]>("list_validators");
      setVals(vs);
      setSelVal((prev) => prev || vs[0]?.pubkey || "");
    } catch {
      setVals([]);
    }
  }, []);

  const loadBalances = useCallback(async () => {
    try {
      const c = await call<Claimable>("get_claimable");
      setReady(c.ready);
      setAccruing(c.accruing);
      setAccruingKeys(c.accruing_keys);
      setBalancesOk(true);
    } catch (e) {
      setBalancesOk(false);
      setErr(String(e));
    }
  }, []);

  const refreshPositions = useCallback(async () => {
    await loadValidators();
    const [idRes, delRes, unRes] = await Promise.allSettled([
      call<ValidatorIdentity>("validator_identity"),
      call<MyDelegation[]>("my_delegations"),
      call<Unbonding[]>("my_unbonding"),
    ]);
    if (idRes.status === "fulfilled") {
      setIdent(idRes.value);
      setIdentErr("");
    } else {
      setIdentErr(String(idRes.reason));
    }
    setIdentLoaded(true);
    if (delRes.status === "fulfilled") {
      setDels(delRes.value);
      setDelLoadErr("");
    } else {
      setDelLoadErr(String(delRes.reason));
    }
    setDelsLoaded(true);
    if (unRes.status === "fulfilled") {
      setUnbonding(unRes.value.filter(saneNotice));
      setUnbondErr("");
      setUnbondLoaded(true);
    } else {
      setUnbondErr(String(unRes.reason));
      setUnbondLoaded(false);
    }
    // Bridge-fee yield is claimed on this tab. An empty result draws nothing, so the
    // idle cards stay the only thing in the middle.
    call<FeeYield[]>("claimable_fees").then(setFees).catch(() => {});
  }, [loadValidators]);

  useEffect(() => {
    if (!active) return;
    void refreshPositions();
    const t = setInterval(() => void refreshPositions(), 60_000);
    return () => clearInterval(t);
  }, [active, refreshPositions]);

  // Remember every unbonding the chain reports. Once the queue drops the entry, the
  // line has to survive until a claim actually moves the stake — the chain no longer
  // lists it. Do not drop a line before that fetch has succeeded, or a slow answer
  // looks like the stake was already released.
  useEffect(() => {
    const pk = ident?.pubkey_hex;
    if (!pk) return;
    const now = Date.now() / 1000;
    const queued = new Set(unbonding.map(noticeId));
    let merged = mergeNotices(readNotices(pk), unbonding);
    if (unbondLoaded && balancesOk && ready === 0) {
      merged = merged.filter((u) => !(Number(u.release_time) <= now && !queued.has(noticeId(u))));
    }
    writeNotices(pk, merged);
    setNotices(merged);
  }, [ident?.pubkey_hex, unbonding, unbondLoaded, balancesOk, ready]);

  const dueNotice = notices.some((u) => Number(u.release_time) <= Date.now() / 1000);
  const needsBalances = Boolean(ident?.bonded) || dels.length > 0 || dueNotice;

  useEffect(() => {
    if (!active || !needsBalances) return;
    void loadBalances();
  }, [active, needsBalances, loadBalances, ident?.bonded, dels.length, unbonding]);

  async function claim() {
    setErr("");
    setBusy(true);
    try {
      const r = await call<{ claimed: number; coins: number }>("claim_rewards");
      onClaimed(r.claimed);
      await loadBalances();
      await refreshPositions();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function claimFee(assetId: string) {
    setErr("");
    setFeeMsg("");
    setFeeBusy(assetId);
    const f = fees.find((x) => x.asset_id === assetId);
    try {
      const claimed = await call<number>("claim_fees", { assetId });
      const dec = f?.decimals ?? 0;
      const amount = (Number(claimed) / 10 ** dec).toFixed(Math.min(dec, 8));
      setFeeMsg(`Claimed ${amount} ${f?.ticker ?? ""}: the coins are in your wallet and spendable. New yield accrues with bridge volume.`);
      await refreshPositions();
    } catch (e) {
      setErr(String(e));
    } finally {
      setFeeBusy("");
    }
  }

  async function copyNodeKey() {
    if (!ident) return;
    try {
      await copySensitive(ident.env_line);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2500);
    } catch {
      setBondErr("Could not reach the clipboard. Select the line and copy it by hand.");
    }
  }

  async function bond() {
    setBondErr("");
    setBonding(true);
    try {
      await call<string>("bond_validator", {
        stakeZcrypt: stake.trim(),
        commissionPct: commissionPct.trim(),
      });
      setNodeReady(false);
      await refreshPositions();
      await loadBalances();
    } catch (e) {
      setBondErr(String(e));
    } finally {
      setBonding(false);
    }
  }

  async function unbond() {
    setBondErr("");
    setBonding(true);
    try {
      await call<string>("unbond_validator");
      setNodeReady(false);
      await refreshPositions();
    } catch (e) {
      setBondErr(String(e));
    } finally {
      setBonding(false);
    }
  }

  async function delegate() {
    setDelErr("");
    setDelBusy(true);
    try {
      await call<string>("delegate_validator", {
        validatorPubkeyHex: selVal,
        stakeZcrypt: delAmt.trim(),
      });
      await refreshPositions();
      await loadBalances();
    } catch (e) {
      setDelErr(String(e));
    } finally {
      setDelBusy(false);
    }
  }

  async function undelegate(d: MyDelegation) {
    setDelErr("");
    setDelBusy(true);
    try {
      await call<string>("undelegate_validator", {
        validatorPubkeyHex: d.validator_pubkey,
        index: d.index,
        legacy: d.legacy,
      });
      await refreshPositions();
    } catch (e) {
      setDelErr(String(e));
    } finally {
      setDelBusy(false);
    }
  }

  const queued = new Set(unbonding.map(noticeId));
  const nowSec = Date.now() / 1000;

  function stakeIsReady(u: Unbonding): boolean {
    if (!unbondLoaded || !balancesOk || ready <= 0) return false;
    if (Number(u.release_time) > nowSec) return false;
    return !queued.has(noticeId(u));
  }

  function pendingPanel() {
    if (notices.length === 0 && !unbondErr) return null;
    return (
      <section className="rewards-pending">
        {unbondErr && <div className="msg err">Could not refresh unbonding: {unbondErr}</div>}
        {notices.map((u) => {
          const due = Number(u.release_time) <= nowSec;
          const stillQueued = queued.has(noticeId(u));
          const open = stakeIsReady(u);
          const msg = !due || stillQueued
            ? `${zcrypt(u.stake)} is returning to this wallet on ${releaseLabel(u.release_time)}.${due && stillQueued ? " The chain credits it on the next block." : ""}`
            : `${zcrypt(u.stake)} is ready to withdraw into this wallet.`;
          return (
            <div className="rewards-prow" key={noticeId(u)}>
              <p className="rewards-back">{msg}</p>
              <button
                className={open ? "btn-primary" : "btn-primary btn-later"}
                disabled={!open || busy}
                onClick={claim}
              >
                {busy ? "Withdrawing…" : "Withdraw to wallet"}
              </button>
            </div>
          );
        })}
      </section>
    );
  }

  function claimRows() {
    const avail = balancesOk ? zcrypt(ready) : "…";
    const held = balancesOk ? zcrypt(accruing) : "…";
    return (
      <>
        <div className="rewards-stat">
          <span className="lab">Available to withdraw</span>
          <span className={`val${balancesOk && ready > 0 ? " ok" : ""}`}>{avail}</span>
        </div>
        <div className="rewards-stat">
          <span className="lab">Not available to withdraw</span>
          <span className={`val${balancesOk && accruing > 0 ? " warn" : ""}`}>{held}</span>
        </div>
      </>
    );
  }

  function withdrawButton() {
    const label = !balancesOk
      ? "Checking…"
      : ready > 0
        ? `Withdraw ${zcrypt(ready)}`
        : "Nothing to withdraw";
    return (
      <button className="btn-primary btn-block" disabled={busy || !balancesOk || ready <= 0} onClick={claim}>
        {busy ? "Withdrawing…" : label}
      </button>
    );
  }

  function validatorDash(id: ValidatorIdentity) {
    const silent = id.epoch_progress >= 5 && id.signed_this_epoch === 0;
    const lead = silent
      ? `Your node is not signing. The chain has seen 0 signatures in the ${id.epoch_progress} blocks of this epoch, so no rewards accrue. The node has to be running with the key from this wallet.`
      : id.signed_this_epoch > 0
        ? `Your node is signing ${id.signed_this_epoch} of ${id.epoch_progress} blocks this epoch.`
        : "The epoch just started. The signing check needs a few more blocks.";
    const floor = balancesOk && accruing > 0
      ? ` ${zcrypt(accruing)} stays on the ledger until that reward key reaches 1 ZCRYPT${accruingKeys > 1 ? ` (${accruingKeys} keys)` : ""}.`
      : "";
    return (
      <>
        <section className="rewards-dash">
          <h2>Your validator</h2>
          <p className={silent ? "msg err" : "rewards-lead"}>{lead}</p>
          {claimRows()}
          <div className="rewards-stat">
            <span className="lab">Delegated to you</span>
            <span className="val">{delegatedLine(id.delegation_count, id.delegated || "0")}</span>
          </div>
          <p className="rewards-foot">
            Commission you keep from people who delegate to you is already inside Available to withdraw.
            The chain adds it to rewards on your own stake, so it is not a second balance.{floor}
          </p>
          {bondErr && <div className="msg err">{bondErr}</div>}
          <div className="rewards-actions">
            {withdrawButton()}
            <button className="btn-secondary btn-block" disabled={bonding} onClick={unbond}>
              {bonding ? "Stopping…" : "Stop validating"}
            </button>
          </div>
        </section>
        {dels.length > 0 && (
          <section className="rewards-dash">
            <h2>Also delegated</h2>
            <p className="rewards-lead">This stake is with another validator. Unbonding it takes 10 days and does not stop your own validator.</p>
            {dels.map((d) => (
              <div className="rewards-stat" key={`${d.validator_pubkey}:${d.index}:${d.legacy}`}>
                <span className="lab">{shortPk(d.validator_pubkey)} · {d.commission_pct}%</span>
                <span className="val">{zcrypt(d.stake)}</span>
              </div>
            ))}
            {delErr && <div className="msg err">{delErr}</div>}
            <div className="rewards-actions">
              {dels.map((d) => (
                <button
                  key={`${d.validator_pubkey}:${d.index}:unbond`}
                  className="btn-secondary btn-block"
                  disabled={delBusy}
                  onClick={() => undelegate(d)}
                >
                  {delBusy ? "Working on-chain…" : `Unbond from ${shortPk(d.validator_pubkey)}`}
                </button>
              ))}
            </div>
          </section>
        )}
      </>
    );
  }

  function delegateDash() {
    const one = dels.length === 1 ? dels[0] : null;
    const floor = balancesOk && accruing > 0
      ? ` ${zcrypt(accruing)} stays on the ledger until that reward key reaches 1 ZCRYPT.`
      : "";
    return (
      <section className="rewards-dash">
        <h2>{one ? "Your delegation" : "Your delegations"}</h2>
        <p className="rewards-lead">
          {one
            ? `Staked with ${shortPk(one.validator_pubkey)}. You earn a share of that validator's rewards, minus its ${one.commission_pct}% commission.`
            : "You have stake with more than one validator. Each unbond takes 10 days."}
        </p>
        {claimRows()}
        <div className="rewards-stat">
          <span className="lab">Earned from delegating</span>
          <span className="val">{balancesOk ? zcrypt(ready + accruing) : "…"}</span>
        </div>
        {one ? (
          <div className="rewards-stat">
            <span className="lab">Delegated</span>
            <span className="val">{zcrypt(one.stake)}</span>
          </div>
        ) : (
          dels.map((d) => (
            <div className="rewards-stat" key={`${d.validator_pubkey}:${d.index}:${d.legacy}`}>
              <span className="lab">{shortPk(d.validator_pubkey)} · {d.commission_pct}%</span>
              <span className="val">{zcrypt(d.stake)}</span>
            </div>
          ))
        )}
        <p className="rewards-foot">
          Earned from delegating is what is still on the ledger: the amount available now, plus what is still under the 1 ZCRYPT minimum.
          Unbonding returns the stake after 10 days.{floor}
        </p>
        {delErr && <div className="msg err">{delErr}</div>}
        <div className="rewards-actions">
          {withdrawButton()}
          {dels.map((d) => (
            <button
              key={`${d.validator_pubkey}:${d.index}:unbond`}
              className="btn-secondary btn-block"
              disabled={delBusy}
              onClick={() => undelegate(d)}
            >
              {delBusy ? "Working on-chain…" : one ? "Unbond" : `Unbond from ${shortPk(d.validator_pubkey)}`}
            </button>
          ))}
        </div>
      </section>
    );
  }

  function setupBoard() {
    const keyPreview = ident ? `${ident.env_line.slice(0, 28)}…` : "";
    return (
      <div className="rewards-setup">
        <div className="bg l" />
        <div className="bg r" />

        <h2 className="c l r1 pad-top">Run a validator</h2>
        <h2 className="c r r1 pad-top">Delegate</h2>

        <div className="c l r2"><div className="rewards-k">Step 1</div></div>
        <div className="c r r2"><div className="rewards-k">Validator</div></div>

        <div className="c l r3"><p className="rewards-t">Start the node</p></div>
        <div className="c r r3"><p className="rewards-t">Choose who to stake with</p></div>

        <div className="c l r4">
          <p className="rewards-d">
            Clone the repo, <code>cd chain/validator</code>, copy <code>.env.example</code> to <code>.env</code>, paste the line, then <code>docker compose up -d</code>. The line has to be in place before the first start.
          </p>
        </div>
        <div className="c r r4">
          <p className="rewards-d">Stake, commission, and signing record are public. You earn a share of that validator's rewards, minus its commission.</p>
        </div>

        <div className="c l r5">
          <div className="rewards-keyline">
            <span>{keyPreview}</span>
            <button className="copy-btn" type="button" onClick={copyNodeKey}>{copiedKey ? "Copied" : "Copy"}</button>
          </div>
        </div>
        <div className="c r r5">
          {vals.length === 0 ? (
            <div className="warn">No bonded validators to delegate to yet.</div>
          ) : (
            <select value={selVal} onChange={(e) => setSelVal(e.target.value)} aria-label="Validator">
              {vals.map((v) => (
                <option key={v.pubkey} value={v.pubkey}>
                  {shortPk(v.pubkey)} · {fmt(Number(v.stake))} staked · {v.commission_pct}%
                </option>
              ))}
            </select>
          )}
        </div>

        <div className="c l r6" />
        <div className="c r r6" />

        <div className="c l r7"><div className="rewards-k">Step 2</div></div>
        <div className="c r r7"><div className="rewards-k">Amount</div></div>

        <div className="c l r8"><p className="rewards-t">Sync to the tip</p></div>
        <div className="c r r8"><p className="rewards-t">ZCRYPT to delegate</p></div>

        <div className="c l r9">
          <p className="rewards-d">Wait until the node is caught up. Bonding earlier means it misses blocks from the moment it joins.</p>
        </div>
        <div className="c r r9">
          <p className="rewards-d">This leaves your spendable balance and stays delegated until you undelegate. Undelegate takes 10 days to return.</p>
        </div>

        <div className="c l r10">
          <label className="rewards-check">
            <input type="checkbox" checked={nodeReady} onChange={(e) => setNodeReady(e.target.checked)} />
            Node is synced
          </label>
        </div>
        <div className="c r r10">
          <input value={delAmt} onChange={(e) => setDelAmt(e.target.value)} inputMode="numeric" aria-label="Amount to delegate" />
        </div>

        <div className="c l r11" />
        <div className="c r r11" />

        <div className="c l r12"><div className="rewards-k">Step 3</div></div>
        <div className="c r r12" />

        <div className="c l r13"><p className="rewards-t">Bond the stake</p></div>
        <div className="c r r13" />

        <div className="c l r14">
          <div className="rewards-pair">
            <div className="field">
              <span className="rewards-k">Stake</span>
              <input value={stake} onChange={(e) => setStake(e.target.value)} inputMode="numeric" aria-label="Stake, minimum 10,000 ZCRYPT" />
            </div>
            <div className="field">
              <span className="rewards-k">Commission</span>
              <input value={commissionPct} onChange={(e) => setCommissionPct(e.target.value)} inputMode="decimal" aria-label="Commission percent" />
            </div>
          </div>
        </div>
        <div className="c r r14" />

        <div className="c l r15">
          <p className="rewards-d">Commission is the share you keep of rewards earned by people who delegate to you. A lower percent draws more of their stake. 0–100%. Minimum stake is 10,000 ZCRYPT.</p>
        </div>
        <div className="c r r15" />

        <div className="c l r16">
          <button className="btn-primary btn-block" disabled={bonding || !nodeReady} onClick={bond}>
            {bonding ? "Bonding…" : "Bond"}
          </button>
        </div>
        <div className="c r r16">
          <button className="btn-primary btn-block" disabled={delBusy || !selVal || vals.length === 0} onClick={delegate}>
            {delBusy ? "Delegating…" : "Delegate"}
          </button>
        </div>

        <div className="c l r17 pad-bot">
          {bondErr && <div className="msg err">{bondErr}</div>}
        </div>
        <div className="c r r17 pad-bot">
          {delErr && <div className="msg err">{delErr}</div>}
        </div>
      </div>
    );
  }

  function feeCard() {
    if (fees.length === 0 && !feeMsg) return null;
    return (
      <div className="card rewards-fees">
        <h3 style={{ marginTop: 0 }}>Bridge-fee yield</h3>
        <p className="rewards-d">Asset-denominated yield from bridge volume, earned by validators and delegators. Separate from ZCRYPT block rewards.</p>
        {feeMsg && <div className="msg ok">{feeMsg}</div>}
        {fees.map((f) => (
          <div className="rewards-stat" key={f.asset_id}>
            <span className="val">
              {(Number(f.amount) / 10 ** f.decimals).toFixed(Math.min(f.decimals, 8))} {f.ticker}
            </span>
            <button className="btn-primary" disabled={feeBusy === f.asset_id} onClick={() => claimFee(f.asset_id)}>
              {feeBusy === f.asset_id ? "Claiming…" : `Claim ${f.ticker}`}
            </button>
          </div>
        ))}
      </div>
    );
  }

  const blocked = identLoaded && delsLoaded && (!ident || (!ident.bonded && dels.length === 0 && !!delLoadErr));
  const mode = ident?.bonded ? "run" : dels.length > 0 ? "del" : "setup";

  return (
    <div>
      <h2 className="view-title">🏆 Staking Rewards</h2>
      {!identLoaded || !delsLoaded ? (
        <div className="rewards-stage single">
          <section className="rewards-dash">
            <p className="rewards-lead" style={{ margin: 0 }}>Loading staking…</p>
          </section>
        </div>
      ) : blocked ? (
        <div className="rewards-stage single">
          <section className="rewards-dash">
            <div className="msg err">{identErr || delLoadErr || "Could not read this wallet's staking position."}</div>
            <button className="btn-secondary" onClick={() => void refreshPositions()}>Try again</button>
          </section>
        </div>
      ) : (
        <div className={mode === "setup" ? "rewards-stage wide" : "rewards-stage single"}>
          {err && <div className="msg err">{err}</div>}
          {identErr && <div className="msg err">{identErr}</div>}
          {delLoadErr && mode === "run" && <div className="msg err">{delLoadErr}</div>}
          {pendingPanel()}
          {mode === "run" && ident ? validatorDash(ident) : mode === "del" ? delegateDash() : setupBoard()}
          {feeCard()}
        </div>
      )}
    </div>
  );
}
