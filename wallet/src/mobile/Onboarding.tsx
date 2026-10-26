import { useRef, useState } from "react";
import { call, copySensitive, saveFile } from "../lib/api";
import { authError, Btn, Icon, Logo, PinPad, shareFile, Spinner } from "./ui";
import { bioName, useAuth } from "./MobileApp";

type Step = "welcome" | "restore" | "password" | "pin" | "pin2" | "bio" | "working" | "seed";

/**
 * First run. New wallet or restore, then a 6-digit PIN, then Face ID, then (for a new
 * wallet) the recovery phrase. `adopt` is the path for a wallet that was created with a
 * password by an earlier build: the password is asked once and replaced by the PIN.
 */
export default function Onboarding({ adopt, onDone }: { adopt: boolean; onDone: () => void }) {
  const { status, toast } = useAuth();
  const [step, setStep] = useState<Step>(adopt ? "password" : "welcome");
  const [restoring, setRestoring] = useState(false);
  const [mnemonic, setMnemonic] = useState("");
  const [password, setPassword] = useState("");
  const [pin1, setPin1] = useState("");
  const [pinErr, setPinErr] = useState("");
  const [err, setErr] = useState("");
  const [seed, setSeed] = useState("");
  const [ack, setAck] = useState(false);
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState("");
  const key = useRef(0);
  const bio = bioName(status);

  function back(to: Step) {
    setErr("");
    setPinErr("");
    key.current += 1;
    setStep(to);
  }

  function firstPin(p: string) {
    setPin1(p);
    key.current += 1;
    setStep("pin2");
  }
  function secondPin(p: string) {
    if (p !== pin1) {
      key.current += 1;
      setPinErr("The PINs do not match. Start again.");
      setTimeout(() => {
        setPinErr("");
        setPin1("");
        setStep("pin");
      }, 900);
      return;
    }
    if (status.biometry_available) setStep("bio");
    else finish(false);
  }

  async function finish(biometric: boolean) {
    setStep("working");
    setErr("");
    try {
      if (adopt) {
        await call("mobile_adopt", { password, pin: pin1, biometric });
        onDone();
        return;
      }
      const r = await call<{ address: string; seed_phrase: string }>("mobile_create", {
        pin: pin1,
        mnemonic: restoring ? mnemonic.trim() : null,
        biometric,
      });
      if (restoring) {
        const found = await call<number>("scan_onchain").catch(() => -1);
        toast("Wallet restored", found > 0 ? `${found} coin${found === 1 ? "" : "s"} recovered from the chain.` : "Your coins appear once the chain has been scanned.");
        onDone();
      } else {
        setSeed(r.seed_phrase);
        setStep("seed");
      }
    } catch (e) {
      const a = authError(e);
      setErr(a.msg);
      setPin1("");
      key.current += 1;
      setStep(adopt ? "password" : restoring ? "restore" : "welcome");
    }
  }

  // ---------- screens ----------
  if (step === "welcome") {
    return (
      <div className="m-gate">
        <div className="fill" />
        <Logo />
        <h1 className="m-title">ZCrypt</h1>
        <p className="m-sub">Private payments with post-quantum keys. Amounts and parties stay hidden on the chain.</p>
        <div className="fill" />
        {err && <p className="m-sub" style={{ color: "var(--bad)" }}>{err}</p>}
        <div className="wide">
          <Btn full onClick={() => { setRestoring(false); setStep("pin"); }}>Create a new wallet</Btn>
          <div style={{ height: 10 }} />
          <Btn full kind="secondary" onClick={() => { setRestoring(true); setStep("restore"); }}>I have a recovery phrase</Btn>
        </div>
      </div>
    );
  }

  if (step === "restore") {
    const words = mnemonic.trim().split(/\s+/).filter(Boolean).length;
    return (
      <div className="m-gate top">
        <button className="m-back" onClick={() => back("welcome")}><Icon name="back" size={20} /> Back</button>
        <h1 className="m-title small" style={{ alignSelf: "flex-start", marginTop: 0 }}>Recovery phrase</h1>
        <p className="m-sub" style={{ alignSelf: "flex-start", textAlign: "left", margin: "4px 0 16px" }}>Type or paste the 24 words, in order.</p>
        <div className="wide">
          <textarea className="m-textarea" style={{ minHeight: 150 }} value={mnemonic} onChange={(e) => setMnemonic(e.target.value)} placeholder="word word word …" autoCapitalize="none" autoCorrect="off" spellCheck={false} />
          <div className="m-hint">{words} / 24 words</div>
          {err && <p className="m-hint" style={{ color: "var(--bad)" }}>{err}</p>}
          <div style={{ height: 18 }} />
          <Btn full disabled={words !== 24} onClick={() => setStep("pin")}>Continue</Btn>
        </div>
      </div>
    );
  }

  if (step === "password") {
    return (
      <div className="m-gate top">
        <Logo small />
        <h1 className="m-title small">Set up a PIN</h1>
        <p className="m-sub">This wallet was created with a password. Enter it once; from now on a PIN{status.biometry_available ? ` and ${bio}` : ""} will open it.</p>
        <div className="wide" style={{ marginTop: 22 }}>
          <div className="m-input-wrap">
            <input className="m-input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Current password" autoFocus />
          </div>
          {err && <p className="m-hint" style={{ color: "var(--bad)" }}>{err}</p>}
          <div style={{ height: 18 }} />
          <Btn full disabled={password.length < 8} onClick={() => setStep("pin")}>Continue</Btn>
        </div>
      </div>
    );
  }

  if (step === "pin" || step === "pin2") {
    return (
      <div className="m-gate">
        {!adopt && <button className="m-back" onClick={() => back(restoring ? "restore" : "welcome")}><Icon name="back" size={20} /> Back</button>}
        <Logo small />
        <h1 className="m-title small">{step === "pin" ? "Choose a PIN" : "Confirm your PIN"}</h1>
        <p className="m-sub">{step === "pin" ? "6 digits. It opens the wallet and confirms every payment." : "Enter the same 6 digits again."}</p>
        <div className="fill" />
        <PinPad onComplete={step === "pin" ? firstPin : secondPin} error={pinErr} resetKey={key.current} />
      </div>
    );
  }

  if (step === "bio") {
    return (
      <div className="m-gate">
        <div className="fill" />
        <div className="m-logo" style={{ background: "var(--surface-2)", boxShadow: "none", color: "var(--accent)" }}>
          <Icon name="faceid" size={40} />
        </div>
        <h1 className="m-title small">Use {bio}?</h1>
        <p className="m-sub">Open the wallet and confirm payments with a glance. Your PIN keeps working as the fallback.</p>
        <div className="fill" />
        <div className="wide">
          <Btn full onClick={() => finish(true)}>Turn on {bio}</Btn>
          <div style={{ height: 10 }} />
          <Btn full kind="ghost" onClick={() => finish(false)}>Not now</Btn>
        </div>
      </div>
    );
  }

  if (step === "working") {
    return (
      <div className="m-gate">
        <div className="fill" />
        <Spinner />
        <p className="m-sub" style={{ marginTop: 18 }}>{adopt ? "Securing your wallet…" : restoring ? "Restoring your wallet…" : "Generating your keys…"}</p>
        <div className="fill" />
      </div>
    );
  }

  // seed
  const words = seed.split(/\s+/).filter(Boolean);
  return (
    <div className="m-gate top seed">
      <h1 className="m-title small" style={{ marginTop: 0 }}>Your recovery phrase</h1>
      <p className="m-sub">Write these 24 words down and keep them offline. They are the only way to recover this wallet.</p>
      <div className="m-seed">
        {words.map((w, i) => (
          <div key={i}><span>{i + 1}</span>{w}</div>
        ))}
      </div>
      <div className="wide m-seed-actions">
        <Btn full kind="secondary" small onClick={() => { copySensitive(seed); setCopied(true); setTimeout(() => setCopied(false), 1800); }}>
          <Icon name="copy" size={18} /> {copied ? "Copied · clears in 60 s" : "Copy phrase"}
        </Btn>
        <Btn full kind="secondary" small onClick={async () => setSaved(await shareFile(seed + "\n", "zcrypt-recovery-phrase.txt", saveFile))}>
          <Icon name="share" size={18} /> {saved === "shared" ? "Saved" : "Save to Files"}
        </Btn>
      </div>
      {saved && saved !== "shared" && saved !== "cancelled" && (
        <p className="m-hint wide" style={{ marginTop: 6 }}>{saved.startsWith("Could not") ? saved : `Saved to ${saved}`}</p>
      )}
      <div className="wide m-seed-footer">
        <label className="m-check">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          I have written the phrase down. Anyone who has it controls my funds, and ZCrypt cannot recover it for me.
        </label>
        <Btn full disabled={!ack} onClick={onDone}>Open my wallet</Btn>
      </div>
    </div>
  );
}
