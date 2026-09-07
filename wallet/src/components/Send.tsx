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
    "A coin file anyone holding it can claim — like cash. It's a real on-chain-backed coin (spendable, first-to-spend wins). No recipient, invisible to view keys. Protect the token like cash.",
};

const FALLBACK: HeldAsset = { asset_id: "0", ticker: "ZCRYPT", decimals: 6, balance: 0 };

interface BtcWallet {
  connected: boolean;
  balance: number;
  deposit_address: string;
}

const btcFmt = (n: number) => n.toLocaleString(undefined, { maximumFractionDigits: 8 });

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
        if (btc && btcAmt > btc.balance) throw new Error("Amount exceeds your BTC balance.");
        if (!recipient.trim()) throw new Error("Enter a Bitcoin address.");
        const txid = await call<string>("withdraw_btc", { address: recipient.trim(), btc: amount.trim() });
        setOkMsg(`✓ Withdrew ${btcFmt(btcAmt)} BTC — txid ${txid.slice(0, 16)}…`);
        toast("BTC withdrawn", `${btcFmt(btcAmt)} BTC sent on-chain`);
        setAmount("");
        setRecipient("");
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
        toast("Bearer coin created", `${pretty} — on-chain, anyone with the token can claim it`);
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
          toast("Stealth send", `${pretty} — share the coin with the recipient`);
        } else {
          await call("send_onchain", { recipient: recipient.trim(), amount: base, assetId: asset.asset_id });
          setOnchainOk(true);
          toast("Sent on-chain", `${pretty} — hidden amount, anonymous among the whole pool`);
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
    ? `Amount (BTC) — available ${btcFmt(btc?.balance ?? 0)}`
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
              Withdraw real on-chain Bitcoin to any external address. To move BTC <b>privately</b>, shield it to
              zBTC in the Bridge tab, then send zBTC here.
            </div>
          )}
        </div>

        {!isBtc && (
          <div className="field">
            <label>Deliver</label>
            <select value={deliver} onChange={(e) => setDeliver(e.target.value as Deliver)}>
              <option value="normal">To a normal address — on-chain, auto-credited</option>
              <option value="stealth">To a stealth address — encrypted file, max privacy</option>
              <option value="bearer">As a bearer coin — a file anyone can claim</option>
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
          <input value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0.0" inputMode="decimal" />
        </div>

        {!isBtc && (
          <div style={{ fontSize: "0.76rem", opacity: 0.62, margin: "-0.3rem 0 0.7rem" }}>
            ⛽ A <b>0.01 ZCRYPT</b> gas fee is added automatically. ZCRYPT is the gas for everything —
            so keep a little on hand even to move zBTC or other assets. (Staking is free.)
          </div>
        )}

        {err && <div className="msg err">{err}</div>}

        <button className="btn-primary btn-block" disabled={busy} onClick={submit}>
          {busy
            ? isBtc
              ? "Sending…"
              : "Proving…"
            : isBtc
            ? "₿ Withdraw BTC"
            : deliver === "bearer"
            ? "💠 Create Bearer Coin"
            : "📤 Send"}
        </button>

        {okMsg && <div className="msg ok" style={{ marginTop: "1.2rem" }}>{okMsg}</div>}

        {onchainOk && (
          <div className="msg ok" style={{ marginTop: "1.2rem" }}>
            ✓ Settled on-chain — hidden amount, anonymous among the whole shielded pool. <b>No file for an address payment</b> — the
            recipient's wallet finds it on its next <b>Refresh</b> (paid yourself? Refresh and it returns as change).
          </div>
        )}

        {file && (
          <div style={{ marginTop: "1.2rem" }}>
            <div className="msg ok">
              {deliver === "stealth"
                ? "Stealth note — share it with the recipient (any channel). Only their stealth key can open it, and nothing on-chain reveals the payment."
                : "Bearer coin — the money itself, backed on-chain. Anyone holding this token can claim it, so treat it like cash."}
            </div>
            <div className="mono-box">{file}</div>
            <ShareBar
              text={file}
              filename={deliver === "stealth" ? "zcrypt-stealth-note.txt" : "zcrypt-bearer-coin.txt"}
            />
          </div>
        )}
      </div>
    </div>
  );
}
