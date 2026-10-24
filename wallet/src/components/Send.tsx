import { useCallback, useEffect, useState } from "react";
import { call, fmtAsset, toBaseAsset, HeldAsset } from "../lib/api";
import { ShareBar } from "./Share";

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

export default function Send({
  active,
  onSent,
  toast,
}: {
  active: boolean;
  onSent: () => void;
  toast: (t: string, b: string) => void;
}) {
  const [assets, setAssets] = useState<HeldAsset[]>([]);
  const [btc, setBtc] = useState<BtcWallet | null>(null);
  const [sel, setSel] = useState("0"); // an asset_id (string) for shielded assets, or "btc" for Bitcoin L1
  const [deliver, setDeliver] = useState<Deliver>("normal");
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [okMsg, setOkMsg] = useState("");
  const [onchainOk, setOnchainOk] = useState(false);
  const [file, setFile] = useState("");
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

  function resetOutputs() {
    setErr("");
    setOkMsg("");
    setOnchainOk(false);
    setFile("");
  }

  async function submit() {
    resetOutputs();
    setBusy(true);
    try {
      // --- Bitcoin (L1): a real on-chain BTC withdrawal ---
      if (isBtc) {
        const sats = toBaseAsset(amount, 8);
        if (!sats || sats <= 0) throw new Error("Enter a valid BTC amount.");
        const btcAmt = sats / 1e8;
        if (!recipient.trim()) throw new Error("Enter a Bitcoin address.");
        const txid = await call<string>("withdraw_btc", { address: recipient.trim(), btc: amount.trim(), speed });
        const feeNote = quote ? ` (fee ${quote.fee_sats.toLocaleString()} sat)` : "";
        setOkMsg(`✓ Sent ${btcFmt(btcAmt)} BTC${feeNote} — txid ${txid}`);
        toast("BTC sent", `${btcFmt(btcAmt)} BTC broadcast on the Bitcoin network`);
        setAmount("");
        setRecipient("");
        setQuote(null);
        onSent();
        loadAssets();
        return;
      }

      // --- Shielded asset (ZCRYPT / zBTC / …) ---
      const base = toBaseAsset(amount, asset.decimals);
      if (!base || base <= 0) throw new Error("Enter a valid amount.");
      if (base > asset.balance) throw new Error(`Amount exceeds your ${asset.ticker} balance.`);
      const pretty = `${fmtAsset(base, asset.decimals)} ${asset.ticker}`;
      if (deliver === "bearer") {
        const token = await call<string>("create_bearer", { amount: base, assetId: asset.asset_id });
        setFile(token);
        toast("Bearer coin created", `${pretty} — send the file. The receipt is in History`);
      } else {
        // Validate the recipient address kind against the delivery mode BEFORE
        // proving (avoids wasting a proof; the backend enforces this too).
        if (!recipient.startsWith("zc1")) throw new Error("Recipient must be a zc1… address.");
        const kind = await call<string>("address_kind", { address: recipient.trim() });
        if (kind === "invalid") throw new Error("That doesn't look like a valid zc1… address.");
        if (deliver === "stealth" && kind !== "stealth")
          throw new Error("Stealth send requires a STEALTH address — you entered a normal address.");
        if (deliver === "normal" && kind !== "normal")
          throw new Error("That's a stealth address — switch delivery to Stealth to send to it.");

        if (deliver === "stealth") {
          const r = await call<{ file: string }>("send_stealth", { recipient: recipient.trim(), amount: base, assetId: asset.asset_id });
          setFile(r.file);
          toast("Stealth send", `${pretty} — share the note. The receipt is in History`);
        } else {
          await call("send_onchain", { recipient: recipient.trim(), amount: base, assetId: asset.asset_id });
          setOnchainOk(true);
          toast("Sent on-chain", `${pretty} — receipt saved in History`);
        }
      }
      setAmount("");
      onSent();
      loadAssets();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const availLabel = isBtc
    ? `Amount (BTC) — ${btcFmt(btc?.balance ?? 0)} on your deposit address`
    : `Amount (${asset.ticker}) — available ${fmtAsset(asset.balance, asset.decimals)}`;

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
              resetOutputs();
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

        <button className="btn-primary btn-block" disabled={busy} onClick={submit}>
          {busy
            ? isBtc
              ? "Signing & broadcasting…"
              : "Proving…"
            : isBtc
            ? "₿ Send BTC"
            : deliver === "bearer"
            ? "💠 Create Bearer Coin"
            : "📤 Send"}
        </button>

        {okMsg && <div className="msg ok" style={{ marginTop: "1.2rem" }}>{okMsg}</div>}

        {onchainOk && (
          <div className="msg ok" style={{ marginTop: "1.2rem" }}>
            ✓ Settled on-chain — hidden amount, anonymous among the whole shielded pool. The receipt is in <b>History</b>. <b>No file for an address payment</b> — the
            recipient's wallet finds it on its next <b>Refresh</b> (paid yourself? Refresh and it returns as change).
          </div>
        )}

        {file && (
          <div style={{ marginTop: "1.2rem" }}>
            <div className="msg ok">
              {deliver === "stealth"
                ? "Stealth note — share it with the recipient (any channel). Only their stealth key can open it, and nothing on-chain reveals the payment. The receipt is in History."
                : "Bearer coin — send the .zcrypt file like a photo. Opening it in the ZCrypt app credits their wallet the full amount. Until that claim is in a block, anyone who has the file can claim it first. The receipt is in History."}
            </div>
            <div className="mono-box">{file}</div>
            <ShareBar
              text={file}
              filename={deliver === "stealth" ? "zcrypt-stealth-note.zcrypt" : "zcrypt-bearer.zcrypt"}
            />
          </div>
        )}
      </div>
    </div>
  );
}
