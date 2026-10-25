import { useCallback, useEffect, useState } from "react";
import { call, copySensitive, fmtAsset, HeldAsset, saveFile, toBaseAsset } from "../lib/api";
import { Btn, dismissKeyboard, Field, Icon, Segmented, Sheet, shareFile, short, Spinner } from "./ui";
import Success from "./Success";
import { useAuth } from "./MobileApp";

type Mode = "address" | "bearer";
const FEE = 10_000; // 0.01 ZCRYPT in base units
const initials = (t: string) => t.replace(/^z/i, "").slice(0, 3).toUpperCase();

interface Result {
  kind: "onchain" | "stealth" | "bearer";
  pretty: string;
  file?: string;
}

/**
 * Send: pick an asset, an amount and either a zc1… address (a stealth address is detected
 * and paid with an encrypted note) or a bearer file. The review sheet asks for Face ID or
 * the PIN, then the proof is built on the phone.
 */
export default function SendScreen({ active, onSent }: { active: boolean; onSent: () => void }) {
  const { confirm, toast } = useAuth();
  const [assets, setAssets] = useState<HeldAsset[]>([]);
  const [sel, setSel] = useState("0");
  const [mode, setMode] = useState<Mode>("address");
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [err, setErr] = useState("");
  const [review, setReview] = useState(false);
  const [busy, setBusy] = useState<"" | "checking" | "proving">("");
  const [result, setResult] = useState<Result | null>(null);
  const [shared, setShared] = useState("");
  const [copied, setCopied] = useState(false);

  const load = useCallback(() => {
    call<HeldAsset[]>("held_assets").then(setAssets).catch(() => {});
  }, []);
  useEffect(() => {
    if (active) load();
  }, [active, load]);

  const asset = assets.find((a) => a.asset_id === sel) ?? { asset_id: "0", ticker: "ZCRYPT", decimals: 6, balance: 0 };
  const isNative = asset.asset_id === "0";
  const native = assets.find((a) => a.asset_id === "0");
  const gasShort = (native?.balance ?? 0) < (mode === "bearer" ? 3 * FEE : FEE);

  function max() {
    const spendable = isNative ? Math.max(0, asset.balance - (mode === "bearer" ? 3 * FEE : FEE)) : asset.balance;
    setAmount(fmtAsset(spendable, asset.decimals).replace(/,/g, ""));
  }

  async function paste() {
    try {
      setTo((await navigator.clipboard.readText()).trim());
    } catch {
      toast("Clipboard is empty");
    }
  }

  function validate(): number | null {
    setErr("");
    let base: number;
    try {
      base = toBaseAsset(amount || "0", asset.decimals);
    } catch (e) {
      setErr(String((e as Error).message));
      return null;
    }
    if (base <= 0) return setErr("Enter an amount."), null;
    if (base > asset.balance) return setErr(`That is more than your ${asset.ticker} balance.`), null;
    if (mode === "address" && !to.trim().startsWith("zc1")) return setErr("The recipient must be a zc1… address."), null;
    if (gasShort) return setErr("You need a little ZCRYPT for the network fee."), null;
    return base;
  }

  async function send() {
    const base = validate();
    if (base === null) return;
    const pretty = `${fmtAsset(base, asset.decimals)} ${asset.ticker}`;
    try {
      setBusy("checking");
      let kind: "normal" | "stealth" = "normal";
      if (mode === "address") {
        const k = await call<string>("address_kind", { address: to.trim() });
        if (k === "invalid") throw new Error("That is not a valid zc1… address.");
        kind = k === "stealth" ? "stealth" : "normal";
      }
      const ok = await confirm(`Send ${pretty}`);
      if (!ok) return;
      setBusy("proving");
      if (mode === "bearer") {
        const file = await call<string>("create_bearer", { amount: base, assetId: asset.asset_id });
        setResult({ kind: "bearer", pretty, file });
      } else if (kind === "stealth") {
        const r = await call<{ file: string }>("send_stealth", { recipient: to.trim(), amount: base, assetId: asset.asset_id });
        setResult({ kind: "stealth", pretty, file: r.file });
      } else {
        await call("send_onchain", { recipient: to.trim(), amount: base, assetId: asset.asset_id });
        setResult({ kind: "onchain", pretty });
      }
      setReview(false);
      setAmount("");
      setTo("");
      onSent();
      load();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
      setReview(false);
    } finally {
      setBusy("");
    }
  }

  function reset() {
    setResult(null);
    setShared("");
  }

  // ---------- result ----------
  if (result) {
    const filename = result.kind === "bearer" ? "zcrypt-bearer.zcrypt" : "zcrypt-stealth-note.zcrypt";
    return (
      <Success
        title={result.kind === "onchain" ? `${result.pretty} sent!` : `${result.pretty} ready to send!`}
        subtitle={
          result.kind === "onchain"
            ? "Settled on the chain. The recipient's wallet credits it on its next refresh."
            : result.kind === "stealth"
              ? "The payment is this encrypted note. Only the recipient's stealth key can open it."
              : "The payment is this file. Whoever opens it in a ZCrypt wallet receives the full amount."
        }
        onDone={reset}
      >
        {result.file && (
          <div className="m-card">
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span className="m-avatar soft"><Icon name="file" size={20} /></span>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 600 }}>{filename}</div>
                <div style={{ fontSize: 13, color: "var(--text-2)" }}>{short(result.file.replace(/\s+/g, " "), 26, 8)}</div>
              </div>
            </div>
            <div className="m-btnrow" style={{ marginTop: 4 }}>
              <Btn onClick={async () => setShared(await shareFile(result.file!, filename, saveFile))}>
                <Icon name="share" size={18} /> Share
              </Btn>
              <Btn kind="secondary" onClick={() => { copySensitive(result.file!); setCopied(true); setTimeout(() => setCopied(false), 1800); setShared("Copied. The clipboard clears in 60 s."); }}>
                <Icon name={copied ? "check" : "copy"} size={18} /> {copied ? "Copied" : "Copy"}
              </Btn>
            </div>
            {shared && shared !== "cancelled" && (
              <p className="m-hint">{shared === "shared" ? "Shared." : shared.startsWith("/") ? `Saved to ${shared.split("/").pop()} in Files.` : shared}</p>
            )}
            <p className="m-hint" style={{ color: "var(--warn)" }}>
              Hand this over through an end-to-end encrypted channel or in person. Until it is claimed, anyone holding the file can take it.
            </p>
          </div>
        )}
      </Success>
    );
  }

  // ---------- form ----------
  return (
    <>
      <div className="m-head">
        <h1 className="m-title">Send</h1>
      </div>

      <div className="m-chips">
        {(assets.length ? assets : [asset]).map((a) => (
          <button key={a.asset_id} className={`m-chip ${a.asset_id === sel ? "active" : ""}`} onClick={() => { setSel(a.asset_id); setErr(""); }}>
            <span className={`m-avatar ${a.asset_id === "0" ? "native" : "soft"}`}>{a.asset_id === "0" ? "Z" : initials(a.ticker)}</span>
            {a.ticker}
          </button>
        ))}
      </div>

      <Field label="Amount">
        <div className="m-input-wrap" style={{ paddingLeft: 16 }}>
          <input className="m-input big" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0" inputMode="decimal" autoCorrect="off" />
          <span style={{ color: "var(--text-2)", fontWeight: 600 }}>{asset.ticker}</span>
          <button className="m-tag" onClick={max}>Max</button>
        </div>
        <div className="m-hint m-num">Available {fmtAsset(asset.balance, asset.decimals)} {asset.ticker}</div>
      </Field>

      <Field label="Deliver">
        <Segmented<Mode>
          value={mode}
          onChange={(m) => { setMode(m); setErr(""); }}
          options={[
            { value: "address", label: "To an address" },
            { value: "bearer", label: "As a file" },
          ]}
        />
      </Field>

      {mode === "address" ? (
        <Field label="Recipient" hint="A stealth address is recognised automatically and paid with an encrypted note instead of an on-chain transfer.">
          <div className="m-input-wrap">
            <input className="m-input" value={to} onChange={(e) => setTo(e.target.value)} placeholder="zc1…" autoCapitalize="none" autoCorrect="off" spellCheck={false} />
            <button className="m-iconbtn" style={{ width: 36, height: 36, border: 0 }} onClick={paste} aria-label="Paste">
              <Icon name="paste" size={18} />
            </button>
          </div>
        </Field>
      ) : (
        <p className="m-hint" style={{ marginTop: 10 }}>
          A bearer file is the coin itself. Send it like a photo over a secure channel; the first wallet to open it is credited the full amount. It carries its own 0.01 ZCRYPT fee, so the recipient needs nothing beforehand.
        </p>
      )}

      <p className="m-hint m-num" style={{ marginTop: 14 }}>
        Network fee {mode === "bearer" ? "0.03" : "0.01"} ZCRYPT
      </p>

      {err && <div className="m-banner bad">{err}</div>}

      <Btn full style={{ marginTop: 18 }} disabled={!amount || (mode === "address" && !to)} onClick={() => { dismissKeyboard(); setErr(""); if (validate() !== null) setReview(true); }}>
        Review
      </Btn>

      <Sheet open={review} onClose={() => !busy && setReview(false)} title={busy === "proving" ? "Sending" : "Review"}>
        {busy === "proving" ? (
          <div className="m-center" style={{ padding: "22px 0 10px" }}>
            <div style={{ display: "inline-flex" }}><Spinner /></div>
            <p className="m-sub" style={{ marginTop: 16 }}>Building the zero-knowledge proof on this phone. A few seconds.</p>
          </div>
        ) : (
          <>
            <div className="m-kv"><span>Amount</span><span className="m-num">{amount} {asset.ticker}</span></div>
            <div className="m-kv"><span>{mode === "bearer" ? "Delivery" : "To"}</span><span>{mode === "bearer" ? "Bearer file" : short(to.trim(), 12, 8)}</span></div>
            <div className="m-kv"><span>Network fee</span><span className="m-num">{mode === "bearer" ? "0.03" : "0.01"} ZCRYPT</span></div>
            <Btn full style={{ marginTop: 16 }} disabled={busy !== ""} onClick={send}>
              {busy === "checking" ? "Checking…" : <><Icon name="faceid" size={20} /> Confirm</>}
            </Btn>
          </>
        )}
      </Sheet>
    </>
  );
}
