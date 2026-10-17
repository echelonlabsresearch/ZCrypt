import { useCallback, useEffect, useState } from "react";
import { call, fmtAsset, toBaseAsset, HeldAsset } from "../lib/api";
import { CopyButton } from "./Share";

interface Listed {
  asset_id: string;
  ticker: string;
  decimals: number;
}

interface Offer {
  ticket: string;
  give_ticker: string;
  take_ticker: string;
  my_timeout: number;
}

interface Preview {
  receive_ticker: string;
  receive_amount: string;
  receive_decimals: number;
  pay_ticker: string;
  pay_amount: string;
  pay_decimals: number;
  their_timeout: number;
  blocks_left: number;
  my_timeout: number;
  pay_balance: string;
}

interface Pending {
  role: string;
  give_ticker: string;
  take_ticker: string;
  give_amount: string;
  take_amount: string;
  give_decimals: number;
  take_decimals: number;
  phase: string;
  ticket: string;
  my_escrow_hex: string;
  my_timeout: number;
  can_refund: boolean;
}

type Side = "start" | "accept";

/** Swap one shielded asset for another with a person who already holds it. */
export default function AssetSwap({ active }: { active: boolean }) {
  const [side, setSide] = useState<Side>("start");
  const [held, setHeld] = useState<HeldAsset[]>([]);
  const [listed, setListed] = useState<Listed[]>([]);
  const [address, setAddress] = useState("");
  const [giveId, setGiveId] = useState("0");
  const [giveAmt, setGiveAmt] = useState("");
  const [takeId, setTakeId] = useState("");
  const [takeAmt, setTakeAmt] = useState("");
  const [maker, setMaker] = useState("");
  const [offerText, setOfferText] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewOf, setPreviewOf] = useState("");
  const [ticket, setTicket] = useState("");
  const [pending, setPending] = useState<Pending[]>([]);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    const [h, listedAssets, open] = await Promise.all([
      call<HeldAsset[]>("held_assets"),
      call<Listed[]>("registered_assets"),
      call<Pending[]>("list_pending_swaps"),
    ]);
    setHeld(h);
    setListed(listedAssets);
    setPending(open);
    setGiveId((cur) => (h.some((a) => a.asset_id === cur) ? cur : h[0]?.asset_id ?? "0"));
    setTakeId((cur) => (listedAssets.some((a) => a.asset_id === cur) ? cur : listedAssets.find((a) => a.asset_id !== (h[0]?.asset_id ?? "0"))?.asset_id ?? listedAssets[0]?.asset_id ?? ""));
  }, []);

  useEffect(() => {
    if (!active) return;
    load().catch((e) => setErr(String(e)));
  }, [active, load]);

  // A fresh per-swap key for the other side to address its offer to (never the reusable
  // payment address). One per visit to this tab; "New" rotates it again.
  async function newSwapAddress() {
    try {
      setAddress(await call<string>("swap_receive_address"));
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => {
    if (!active || address) return;
    newSwapAddress();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  // Finish a swap whose other side has locked, without asking the user to do it.
  useEffect(() => {
    if (!active) return;
    const t = setInterval(async () => {
      try {
        const notes = await call<string[]>("swap_asset_settle");
        if (notes.length) {
          setNote(notes[notes.length - 1]);
          setPending(await call<Pending[]>("list_pending_swaps"));
        }
      } catch {
        /* the next pass retries */
      }
    }, 8_000);
    return () => clearInterval(t);
  }, [active]);

  const give = held.find((a) => a.asset_id === giveId);
  const take = listed.find((a) => a.asset_id === takeId);
  const receiveChoices = listed.filter((a) => a.asset_id !== giveId);

  async function start() {
    setErr("");
    setNote("");
    setTicket("");
    if (!give || !take) return setErr("Choose what you pay and what you receive.");
    let giveBase: number;
    let takeBase: number;
    try {
      giveBase = toBaseAsset(giveAmt, give.decimals);
      takeBase = toBaseAsset(takeAmt, take.decimals);
    } catch (e) {
      return setErr(String(e));
    }
    if (giveBase <= 0 || takeBase <= 0) return setErr("Enter both amounts.");
    if (giveBase > give.balance) return setErr(`That is more ${give.ticker} than this wallet can spend.`);
    setBusy("start");
    try {
      const offer = await call<Offer>("swap_asset_start", {
        giveAsset: give.asset_id,
        giveAmount: giveBase,
        takeAsset: take.asset_id,
        takeAmount: takeBase,
        makerAddress: maker.trim(),
      });
      setTicket(offer.ticket);
      setNote(`Locked. Send the offer to them. It refunds at block ${offer.my_timeout} if they never accept.`);
      await load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy("");
    }
  }

  // Step 1: decode and show the terms. Nothing is locked until the user confirms them.
  async function review() {
    setErr("");
    setNote("");
    setPreview(null);
    if (!offerText.trim()) return setErr("Paste the offer they sent you.");
    setBusy("preview");
    try {
      const p = await call<Preview>("swap_asset_preview", { ticket: offerText.trim() });
      setPreview(p);
      setPreviewOf(offerText.trim());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy("");
    }
  }

  // Step 2: lock exactly the reviewed offer.
  async function accept() {
    setErr("");
    setNote("");
    if (!preview || previewOf !== offerText.trim()) return setErr("Review the offer first.");
    setBusy("accept");
    try {
      const msg = await call<string>("swap_asset_accept", { ticket: previewOf });
      setNote(msg);
      setOfferText("");
      setPreview(null);
      setPreviewOf("");
      await load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy("");
    }
  }

  async function refund(escrow: string) {
    setErr("");
    setBusy("refund");
    try {
      setNote(await call<string>("swap_asset_refund", { escrowHex: escrow }));
      await load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy("");
    }
  }

  return (
    <div>
      <p style={{ fontSize: "0.84rem", opacity: 0.75, marginTop: 0 }}>
        Swap a shielded asset with someone who already holds the other one. You lock yours, they lock
        theirs, and both sides finish or both get a refund. The fee is 0.01 ZCRYPT, taken from this wallet.
      </p>
      <div className="field">
        <label>Your swap address — they put this in their offer (a fresh one-time key, not your payment address)</label>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <code style={{ fontSize: "0.72rem", wordBreak: "break-all", flex: 1 }}>{address || "…"}</code>
          <CopyButton text={address} />
          <button className="btn-link" disabled={busy !== ""} onClick={newSwapAddress}>New</button>
        </div>
      </div>

      <div className="seg" style={{ marginTop: "0.6rem" }}>
        <button className={`seg-btn ${side === "start" ? "active" : ""}`} disabled={busy !== ""} onClick={() => { setSide("start"); setErr(""); }}>
          Start <span className="seg-sub">you lock first</span>
        </button>
        <button className={`seg-btn ${side === "accept" ? "active" : ""}`} disabled={busy !== ""} onClick={() => { setSide("accept"); setErr(""); }}>
          Accept <span className="seg-sub">they locked first</span>
        </button>
      </div>

      {side === "start" ? (
        <>
          <div className="field" style={{ marginTop: "1rem" }}>
            <label>You pay {give ? `— available ${fmtAsset(give.balance, give.decimals)} ${give.ticker}` : ""}</label>
            <select value={giveId} onChange={(e) => setGiveId(e.target.value)}>
              {held.map((a) => (
                <option key={a.asset_id} value={a.asset_id}>
                  {a.ticker}
                </option>
              ))}
            </select>
            <input style={{ marginTop: "0.45rem" }} value={giveAmt} onChange={(e) => setGiveAmt(e.target.value)} placeholder="0.0" inputMode="decimal" />
          </div>
          <div className="field">
            <label>You receive</label>
            <select value={takeId} onChange={(e) => setTakeId(e.target.value)}>
              {receiveChoices.map((a) => (
                <option key={a.asset_id} value={a.asset_id}>
                  {a.ticker}
                </option>
              ))}
            </select>
            <input style={{ marginTop: "0.45rem" }} value={takeAmt} onChange={(e) => setTakeAmt(e.target.value)} placeholder="0.0" inputMode="decimal" />
          </div>
          <div className="field">
            <label>Their wallet address</label>
            <input value={maker} onChange={(e) => setMaker(e.target.value)} placeholder="zc1…" />
          </div>
          <button className="btn-primary btn-block" disabled={busy !== ""} onClick={start}>
            {busy === "start" ? "Locking your asset…" : "Lock and create the offer"}
          </button>
          {ticket && (
            <div className="field" style={{ marginTop: "0.9rem" }}>
              <label>Offer — send this to them</label>
              <textarea readOnly value={ticket} rows={4} style={{ width: "100%", fontFamily: "monospace", fontSize: "0.72rem" }} />
              <CopyButton text={ticket} label="Copy offer" />
            </div>
          )}
        </>
      ) : (
        <>
          <div className="field" style={{ marginTop: "1rem" }}>
            <label>Their offer</label>
            <textarea
              value={offerText}
              onChange={(e) => { setOfferText(e.target.value); setPreview(null); }}
              rows={4}
              placeholder="zcswap1.…"
              style={{ width: "100%", fontFamily: "monospace", fontSize: "0.72rem" }}
            />
          </div>
          {!preview || previewOf !== offerText.trim() ? (
            <button className="btn-primary btn-block" disabled={busy !== ""} onClick={review}>
              {busy === "preview" ? "Reading the offer…" : "Review the offer"}
            </button>
          ) : (
            <>
              <div className="card" style={{ padding: "0.8rem 0.9rem", marginBottom: "0.7rem", borderLeft: "3px solid var(--color-amber, #d99a00)" }}>
                <div style={{ fontWeight: 700, marginBottom: 6 }}>Check these terms before locking</div>
                <div style={{ fontSize: "0.9rem" }}>
                  You pay <b>{fmtAsset(Number(preview.pay_amount), preview.pay_decimals)} {preview.pay_ticker}</b>
                </div>
                <div style={{ fontSize: "0.9rem" }}>
                  You receive <b>{fmtAsset(Number(preview.receive_amount), preview.receive_decimals)} {preview.receive_ticker}</b>
                </div>
                <div style={{ fontSize: "0.76rem", opacity: 0.7, marginTop: 6 }}>
                  Spendable {preview.pay_ticker}: {fmtAsset(Number(preview.pay_balance), preview.pay_decimals)}. Their lock expires at block{" "}
                  {preview.their_timeout} ({preview.blocks_left} blocks from now); yours would expire at block {preview.my_timeout}.
                  Once they claim, this wallet collects on its own while it is unlocked.
                </div>
                {Number(preview.pay_amount) > Number(preview.pay_balance) && (
                  <div className="msg err" style={{ marginTop: 6 }}>This is more {preview.pay_ticker} than this wallet can spend.</div>
                )}
              </div>
              <button className="btn-primary btn-block" disabled={busy !== ""} onClick={accept}>
                {busy === "accept"
                  ? "Locking your side…"
                  : `Confirm: lock ${fmtAsset(Number(preview.pay_amount), preview.pay_decimals)} ${preview.pay_ticker}`}
              </button>
            </>
          )}
        </>
      )}

      {err && <div className="msg err" style={{ marginTop: "0.8rem" }}>{err}</div>}
      {note && <div className="msg ok" style={{ marginTop: "0.8rem", fontSize: "0.84rem" }}>{note}</div>}

      {pending.length > 0 && (
        <div style={{ marginTop: "1.1rem" }}>
          <div style={{ fontWeight: 700, marginBottom: "0.4rem" }}>In progress</div>
          {pending.map((p) => (
            <div key={p.my_escrow_hex} className="card" style={{ padding: "0.7rem 0.8rem", marginBottom: "0.5rem" }}>
              <div style={{ fontSize: "0.86rem" }}>
                {p.role === "taker"
                  ? `You pay ${fmtAsset(Number(p.give_amount), p.give_decimals)} ${p.give_ticker} for ${fmtAsset(Number(p.take_amount), p.take_decimals)} ${p.take_ticker}`
                  : `You pay ${fmtAsset(Number(p.take_amount), p.take_decimals)} ${p.take_ticker} for ${fmtAsset(Number(p.give_amount), p.give_decimals)} ${p.give_ticker}`}
              </div>
              <div style={{ fontSize: "0.76rem", opacity: 0.7, marginTop: 4 }}>{p.phase}</div>
              <div style={{ display: "flex", gap: "0.8rem", marginTop: 6, flexWrap: "wrap" }}>
                {p.ticket && <CopyButton text={p.ticket} label="Copy offer" />}
                <button className="btn-link" disabled={busy !== "" || !p.can_refund} onClick={() => refund(p.my_escrow_hex)}>
                  {p.can_refund ? "Refund" : `Refunds at block ${p.my_timeout}`}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
