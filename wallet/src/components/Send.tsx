import { useCallback, useEffect, useRef, useState } from "react";
import {
  call,
  coinFileName,
  dismissSavedSecret,
  fmtAsset,
  HeldAsset,
  openCoinShare,
  saveCoinFile,
  SHARE_CHANNELS,
  ShareChannel,
  toBaseAsset,
} from "../lib/api";
import Success from "../mobile/Success";
import { Btn } from "../mobile/ui";

type Deliver = "normal" | "stealth" | "bearer";

const BLURB: Record<Deliver, string> = {
  normal:
    "On-chain payment to a zc1… address. The recipient's wallet scans and auto-credits it — no file to send. Visible to that address's view key.",
  stealth:
    "Off-chain: produces an encrypted file to hand the recipient. Nothing decryptable is left on-chain, and it's invisible to any view key. The recipient needs their stealth key + this file.",
  bearer:
    "A bearer coin file you can send over any chat. The first person who opens it in a wallet is credited the full amount. The file includes 0.01 ZCRYPT gas, so they need no balance and no wallet beforehand. Until that claim is in a block, anyone with the file can take it.",
};

const FALLBACK: HeldAsset = { asset_id: "0", ticker: "ZCRYPT", decimals: 6, balance: 0 };

interface BtcWallet {
  connected: boolean;
  balance: number;
  deposit_address: string;
}

const btcFmt = (n: number) => n.toLocaleString(undefined, { maximumFractionDigits: 8 });

/** Exact BTC string for a satoshi count (no float formatting). */
const satsToBtc = (sats: number) => {
  const whole = Math.floor(sats / 1e8);
  const frac = String(sats % 1e8).padStart(8, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : String(whole);
};

type Speed = "fast" | "normal" | "slow";
const SPEED_LABEL: Record<Speed, string> = {
  fast: "Fast — next couple of blocks",
  normal: "Normal — about an hour",
  slow: "Slow — about a day, cheapest",
};

interface BtcQuote {
  amount_sats: number;
  fee_sats: number;
  fee_rate_sat_vb: number;
  inputs: number;
}

type SendWhat = "bearer" | "note" | "payment" | "btc";

type Phase =
  | { kind: "form" }
  | { kind: "busy"; what: SendWhat }
  | { kind: "handoff"; what: "bearer" | "note"; pretty: string; file: string; filename: string }
  | { kind: "sent"; what: "payment" | "btc"; pretty: string; detail?: string }
  | { kind: "failed"; msg: string };

const BUSY_COPY: Record<SendWhat, { title: string; subtitle: string }> = {
  bearer: {
    title: "Creating the coin",
    subtitle: "Building the coin file on this computer. This takes a few seconds.",
  },
  note: {
    title: "Creating the note",
    subtitle: "Encrypting the payment on this computer. This takes a few seconds.",
  },
  payment: {
    title: "Sending payment",
    subtitle: "Checking the chain and building the proof on this computer. This takes a few seconds.",
  },
  btc: {
    title: "Sending bitcoin",
    subtitle: "Signing the transaction and broadcasting it.",
  },
};

export default function Send({
  active,
  onSent,
}: {
  active: boolean;
  onSent: () => void;
  /** Kept so a result screen is not paired with a second toast. */
  toast: (t: string, b: string) => void;
}) {
  const [assets, setAssets] = useState<HeldAsset[]>([]);
  const [btc, setBtc] = useState<BtcWallet | null>(null);
  const [sel, setSel] = useState("0"); // an asset_id (string) for shielded assets, or "btc" for Bitcoin L1
  const [deliver, setDeliver] = useState<Deliver>("normal");
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [checking, setChecking] = useState(false);
  const [err, setErr] = useState("");
  const [phase, setPhase] = useState<Phase>({ kind: "form" });
  const [acting, setActing] = useState<"" | "save" | ShareChannel>("");
  const [handErr, setHandErr] = useState("");
  const handLock = useRef(false);
  const wroteFile = useRef(false);
  // Bitcoin: fee speed, a live quote from the same builder that signs, and "Max".
  const [speed, setSpeed] = useState<Speed>("normal");
  const [quote, setQuote] = useState<BtcQuote | null>(null);
  const [quoteErr, setQuoteErr] = useState("");
  const [quoting, setQuoting] = useState(false);
  const [maxBusy, setMaxBusy] = useState(false);

  const loadAssets = useCallback(() => {
    call<HeldAsset[]>("held_assets").then(setAssets).catch(() => {});
    call<BtcWallet>("btc_wallet_info").then(setBtc).catch(() => setBtc(null));
  }, []);

  // Re-fetch whenever the Send tab becomes active — tabs stay mounted (display:none),
  // so a coin shielded on another tab (e.g. zBTC via the Bridge) only shows up here
  // if we refresh on entry.
  useEffect(() => {
    if (active) loadAssets();
  }, [active, loadAssets]);

  const isBtc = sel === "btc";
  const asset = assets.find((a) => String(a.asset_id) === sel) ?? FALLBACK;

  // Quote the Bitcoin fee whenever the address, amount or speed changes (debounced). The
  // quote runs the real coin selection, so what it says is what the send will pay.
  useEffect(() => {
    if (!isBtc) return;
    setQuote(null);
    setQuoteErr("");
    const addr = recipient.trim();
    const amt = amount.trim();
    if (!addr || !amt) return;
    let sats: number;
    try {
      sats = toBaseAsset(amt, 8);
    } catch {
      return;
    }
    if (sats <= 0) return;
    const t = setTimeout(async () => {
      setQuoting(true);
      try {
        setQuote(await call<BtcQuote>("estimate_btc_send", { address: addr, btc: amt, speed }));
        setQuoteErr("");
      } catch (e) {
        setQuote(null);
        setQuoteErr(String(e));
      } finally {
        setQuoting(false);
      }
    }, 500);
    return () => clearTimeout(t);
  }, [isBtc, recipient, amount, speed]);

  async function useMax() {
    setMaxBusy(true);
    setErr("");
    try {
      const q = await call<BtcQuote>("btc_max_send", { speed });
      setAmount(satsToBtc(q.amount_sats));
      setQuote(q);
      setQuoteErr("");
    } catch (e) {
      setQuoteErr(String(e));
    } finally {
      setMaxBusy(false);
    }
  }

  function errText(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function submit() {
    setErr("");
    // A typo stays on the form. The spinner starts only once the payment itself is in flight,
    // so a bad address does not flash the full-screen result.
    let started = false;
    try {
      if (isBtc) {
        const sats = toBaseAsset(amount, 8);
        if (!sats || sats <= 0) throw new Error("Enter a valid BTC amount.");
        if (!recipient.trim()) throw new Error("Enter a Bitcoin address.");
        const pretty = `${satsToBtc(sats)} BTC`;
        started = true;
        setPhase({ kind: "busy", what: "btc" });
        const txid = await call<string>("withdraw_btc", { address: recipient.trim(), btc: amount.trim(), speed });
        const feeNote = quote ? `Fee ${quote.fee_sats.toLocaleString()} sat. ` : "";
        setAmount("");
        setRecipient("");
        setQuote(null);
        onSent();
        loadAssets();
        setPhase({ kind: "sent", what: "btc", pretty, detail: `${feeNote}Transaction ${txid}` });
        return;
      }

      const base = toBaseAsset(amount, asset.decimals);
      if (!base || base <= 0) throw new Error("Enter a valid amount.");
      if (base > asset.balance) throw new Error(`Amount exceeds your ${asset.ticker} balance.`);
      const pretty = `${fmtAsset(base, asset.decimals)} ${asset.ticker}`;

      if (deliver !== "bearer") {
        if (!recipient.startsWith("zc1")) throw new Error("Recipient must be a zc1… address.");
        setChecking(true);
        const kind = await call<string>("address_kind", { address: recipient.trim() });
        setChecking(false);
        if (kind === "invalid") throw new Error("That doesn't look like a valid zc1… address.");
        if (deliver === "stealth" && kind !== "stealth")
          throw new Error("Stealth send requires a STEALTH address — you entered a normal address.");
        if (deliver === "normal" && kind !== "normal")
          throw new Error("That's a stealth address — switch delivery to Stealth to send to it.");
      }

      if (deliver === "bearer") {
        started = true;
        setPhase({ kind: "busy", what: "bearer" });
        const token = await call<string>("create_bearer", { amount: base, assetId: asset.asset_id });
        setAmount("");
        onSent();
        loadAssets();
        setPhase({ kind: "handoff", what: "bearer", pretty, file: token, filename: coinFileName("bearer") });
      } else if (deliver === "stealth") {
        started = true;
        setPhase({ kind: "busy", what: "note" });
        const r = await call<{ file: string }>("send_stealth", {
          recipient: recipient.trim(),
          amount: base,
          assetId: asset.asset_id,
        });
        setAmount("");
        setRecipient("");
        onSent();
        loadAssets();
        setPhase({ kind: "handoff", what: "note", pretty, file: r.file, filename: coinFileName("note") });
      } else {
        started = true;
        setPhase({ kind: "busy", what: "payment" });
        await call("send_onchain", { recipient: recipient.trim(), amount: base, assetId: asset.asset_id });
        setAmount("");
        setRecipient("");
        onSent();
        loadAssets();
        setPhase({ kind: "sent", what: "payment", pretty });
      }
    } catch (e) {
      setChecking(false);
      if (started) setPhase({ kind: "failed", msg: errText(e) });
      else setErr(errText(e));
    }
  }

  function leaveHandoff() {
    setActing("");
    setHandErr("");
    handLock.current = false;
    wroteFile.current = false;
    setPhase({ kind: "form" });
  }

  async function saveCoin(file: string, filename: string) {
    if (handLock.current) return;
    handLock.current = true;
    setActing("save");
    setHandErr("");
    try {
      // A second click must not mint another filename. The first write is the file.
      if (!wroteFile.current) {
        await saveCoinFile(filename, file);
        wroteFile.current = true;
      }
      await dismissSavedSecret(file);
      window.dispatchEvent(new Event("zc-secrets"));
      leaveHandoff();
    } catch (e) {
      setHandErr(errText(e));
      handLock.current = false;
      setActing("");
    }
  }

  async function shareCoin(channel: ShareChannel, file: string, filename: string, subject: string) {
    if (handLock.current) return;
    handLock.current = true;
    setActing(channel);
    setHandErr("");
    try {
      await openCoinShare(channel, file, filename, subject);
      leaveHandoff();
    } catch (e) {
      setHandErr(errText(e));
      handLock.current = false;
      setActing("");
    }
  }

  const availLabel = isBtc
    ? `Amount (BTC) — ${btcFmt(btc?.balance ?? 0)} on your deposit address`
    : `Amount (${asset.ticker}) — available ${fmtAsset(asset.balance, asset.decimals)}`;

  if (phase.kind === "busy") {
    const copy = BUSY_COPY[phase.what];
    return <Success tone="busy" title={copy.title} subtitle={copy.subtitle} onDone={() => {}} />;
  }
  if (phase.kind === "failed") {
    return (
      <Success
        tone="bad"
        title="Could not send"
        subtitle="The payment did not go out."
        doneLabel="Back to send"
        onDone={() => setPhase({ kind: "form" })}
      >
        <div className="m-done-detail">{phase.msg}</div>
      </Success>
    );
  }
  if (phase.kind === "sent") {
    return (
      <Success
        title={`${phase.pretty} sent!`}
        subtitle={
          phase.what === "btc"
            ? "Broadcast on the Bitcoin network."
            : "Settled on the chain. The recipient's wallet credits it on the next refresh."
        }
        onDone={() => setPhase({ kind: "form" })}
      >
        {phase.detail && <div className="m-done-detail">{phase.detail}</div>}
      </Success>
    );
  }
  if (phase.kind === "handoff") {
    const subject = phase.what === "note" ? `${phase.pretty} ZCrypt note` : `${phase.pretty} ZCrypt coin`;
    const noun = phase.what === "note" ? "note" : "coin";
    return (
      <Success
        title={`${phase.pretty} ready`}
        subtitle={
          phase.what === "note"
            ? "Save the note, or send it on WhatsApp, Telegram, or email. Only their stealth key can open it."
            : "Save the coin, or send it on WhatsApp, Telegram, or email. Whoever opens the file first gets the full amount."
        }
        doneKind="secondary"
        doneLabel="Back to send"
        onDone={() => {
          if (!acting) leaveHandoff();
        }}
      >
        <div className="send-hand">
          <div className="send-hand-name">{phase.filename}</div>
          <Btn kind="primary" full disabled={!!acting} onClick={() => saveCoin(phase.file, phase.filename)}>
            {acting === "save" ? "Saving…" : phase.what === "note" ? "Save note file" : "Save coin file"}
          </Btn>
          <div className="send-share">
            {SHARE_CHANNELS.map((c) => (
              <Btn key={c.id} kind="secondary" disabled={!!acting} onClick={() => shareCoin(c.id, phase.file, phase.filename, subject)}>
                {acting === c.id ? "Opening…" : c.label}
              </Btn>
            ))}
          </div>
          {handErr && <div className="m-done-detail">{handErr}</div>}
          <p className="send-hand-note">
            Until it is claimed, anyone with the file can take it. Leave without saving and this {noun} stays under History, ready to copy.
          </p>
        </div>
      </Success>
    );
  }

  return (
    <div>
      <h2 className="view-title">📤 Send</h2>
      <div className="card" style={{ maxWidth: 640, margin: "0 auto" }}>
        <div className="field">
          <label>Asset</label>
          <select
            value={sel}
            onChange={(e) => {
              setSel(e.target.value);
              setRecipient("");
              setErr("");
            }}
          >
            {(assets.length ? assets : [FALLBACK]).map((a) => (
              <option key={a.asset_id} value={String(a.asset_id)}>
                {a.ticker} — available {fmtAsset(a.balance, a.decimals)}
              </option>
            ))}
            {btc?.connected && <option value="btc">Bitcoin (L1) — {btcFmt(btc.balance)} BTC</option>}
          </select>
          {isBtc && (
            <div style={{ fontSize: "0.8rem", opacity: 0.7, marginTop: "0.5rem" }}>
              Real on-chain Bitcoin to any external address, signed here with keys from your phrase. To move BTC{" "}
              <b>privately</b>, shield it to zBTC in the Bridge tab, then send zBTC here.
            </div>
          )}
        </div>

        {isBtc && (
          <div className="field">
            <label>Fee</label>
            <select value={speed} onChange={(e) => setSpeed(e.target.value as Speed)}>
              {(Object.keys(SPEED_LABEL) as Speed[]).map((k) => (
                <option key={k} value={k}>{SPEED_LABEL[k]}</option>
              ))}
            </select>
          </div>
        )}

        {!isBtc && (
          <div className="field">
            <label>Deliver</label>
            <select value={deliver} onChange={(e) => setDeliver(e.target.value as Deliver)}>
              <option value="normal">To a normal address — on-chain, auto-credited</option>
              <option value="stealth">To a stealth address — encrypted file, max privacy</option>
              <option value="bearer">As a bearer coin — a file anyone can open and be credited</option>
            </select>
            <div style={{ fontSize: "0.8rem", opacity: 0.7, marginTop: "0.5rem" }}>{BLURB[deliver]}</div>
          </div>
        )}

        {(isBtc || deliver !== "bearer") && (
          <div className="field">
            <label>{isBtc ? "Bitcoin address" : deliver === "stealth" ? "Recipient stealth address" : "Recipient address"}</label>
            <input
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              placeholder={isBtc ? "bc1… / tb1… / bcrt1…" : "zc1…"}
            />
          </div>
        )}

        <div className="field">
          <label>{availLabel}</label>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <input value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0.0" inputMode="decimal" style={{ flex: 1 }} />
            {isBtc && (
              <button className="copy-btn" disabled={maxBusy} onClick={useMax} title="Everything in the wallet after the fee, in one transaction, nothing left behind">
                {maxBusy ? "…" : "Max"}
              </button>
            )}
          </div>
          {isBtc && (
            <div style={{ fontSize: "0.76rem", opacity: 0.72, marginTop: "0.4rem", minHeight: "1.1em" }}>
              {quoting ? (
                "Pricing the transaction…"
              ) : quote ? (
                <>
                  Fee <b>{quote.fee_sats.toLocaleString()} sat</b> at {quote.fee_rate_sat_vb.toFixed(1)} sat/vB · {quote.inputs} input{quote.inputs === 1 ? "" : "s"} ·
                  recipient gets <b>{satsToBtc(quote.amount_sats)} BTC</b>. Priced by the same builder that signs: the fee is never more than a quarter of the amount, and change below dust goes to the miner, not to a coin you cannot spend.
                </>
              ) : quoteErr ? (
                <span style={{ color: "var(--color-yellow)" }}>{quoteErr}</span>
              ) : (
                "Enter an address and an amount to see the fee before you send. Max sends everything spendable in one transaction."
              )}
            </div>
          )}
        </div>

        {!isBtc && deliver !== "bearer" && (
          <div style={{ fontSize: "0.76rem", opacity: 0.62, margin: "-0.3rem 0 0.7rem" }}>
            ⛽ A <b>0.01 ZCRYPT</b> gas fee is added automatically. ZCRYPT is the gas for everything —
            so keep a little on hand even to move zBTC or other assets. (Staking is free.)
          </div>
        )}
        {!isBtc && deliver === "bearer" && (
          <div style={{ fontSize: "0.76rem", opacity: 0.62, margin: "-0.3rem 0 0.7rem" }}>
            ⛽ The file includes <b>0.01 ZCRYPT</b> gas so the recipient can claim it with an empty
            wallet. Creating the file also spends <b>0.02 ZCRYPT</b> in gas.
          </div>
        )}

        {err && <div className="msg err">{err}</div>}

        <button className="btn-primary btn-block" disabled={checking} onClick={submit}>
          {checking
            ? "Checking…"
            : isBtc
            ? "₿ Send BTC"
            : deliver === "bearer"
            ? "💠 Create Bearer Coin"
            : "📤 Send"}
        </button>
      </div>
    </div>
  );
}
