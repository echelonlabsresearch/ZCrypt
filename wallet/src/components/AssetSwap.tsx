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
  const [ticket, setTicket] = useState("");
  const [pending, setPending] = useState<Pending[]>([]);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    const [h, listedAssets, addr, open] = await Promise.all([
      call<HeldAsset[]>("held_assets"),
      call<Listed[]>("registered_assets"),
      call<string>("get_address"),
      call<Pending[]>("list_pending_swaps"),
    ]);
    setHeld(h);
    setListed(listedAssets);
    setAddress(addr);
    setPending(open);
    setGiveId((cur) => (h.some((a) => a.asset_id === cur) ? cur : h[0]?.asset_id ?? "0"));
    setTakeId((cur) => (listedAssets.some((a) => a.asset_id === cur) ? cur : listedAssets.find((a) => a.asset_id !== (h[0]?.asset_id ?? "0"))?.asset_id ?? listedAssets[0]?.asset_id ?? ""));
  }, []);

  useEffect(() => {
    if (!active) return;
    load().catch((e) => setErr(String(e)));
  }, [active, load]);

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

  async function accept() {
    setErr("");
    setNote("");
    if (!offerText.trim()) return setErr("Paste the offer they sent you.");
    setBusy("accept");
    try {
      const msg = await call<string>("swap_asset_accept", { ticket: offerText.trim() });
      setNote(msg);
      setOfferText("");
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
        <label>Your address — they put this in their offer</label>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <code style={{ fontSize: "0.72rem", wordBreak: "break-all", flex: 1 }}>{address || "…"}</code>
          <CopyButton text={address} />
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
            <textarea value={offerText} onChange={(e) => setOfferText(e.target.value)} rows={4} placeholder="zcswap1.…" style={{ width: "100%", fontFamily: "monospace", fontSize: "0.72rem" }} />
          </div>
          <button className="btn-primary btn-block" disabled={busy !== ""} onClick={accept}>
            {busy === "accept" ? "Locking your side…" : "Lock my side"}
          </button>
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
