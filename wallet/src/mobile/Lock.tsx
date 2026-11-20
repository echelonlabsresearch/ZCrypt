import { useEffect, useRef, useState } from "react";
import { call } from "../lib/api";
import { authError, Btn, Icon, lockMessage, Logo, PinPad } from "./ui";
import { bioName, useAuth } from "./MobileApp";

/** The lock screen: Face ID straight away when it is on, the keypad underneath. */
export default function Lock({ onUnlocked, onForgotten }: { onUnlocked: () => void; onForgotten: () => void }) {
  const { status, refreshStatus } = useAuth();
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [lockedFor, setLockedFor] = useState(status.locked_for_s);
  const key = useRef(0);
  const prompted = useRef(false);

  // Lockout countdown.
  useEffect(() => {
    setLockedFor(status.locked_for_s);
  }, [status.locked_for_s]);
  useEffect(() => {
    if (lockedFor <= 0) return;
    const t = setInterval(() => setLockedFor((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(t);
  }, [lockedFor > 0]);

  async function face() {
    if (busy) return;
    setBusy(true);
    setErr("");
    try {
      await call("mobile_unlock", { pin: null });
      onUnlocked();
    } catch (e) {
      const a = authError(e);
      if (a.kind !== "biometric") setErr(a.msg);
      // A declined or failed Face ID just leaves the keypad.
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (status.biometric && !prompted.current && lockedFor <= 0) {
      prompted.current = true;
      // Give the view a moment to settle so the system sheet appears over the lock screen.
      setTimeout(face, 350);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status.biometric]);

  async function pin(p: string) {
    setBusy(true);
    setErr("");
    try {
      await call("mobile_unlock", { pin: p });
      onUnlocked();
    } catch (e) {
      const a = authError(e);
      key.current += 1;
      if (a.kind === "wrong") setErr(`Wrong PIN. ${a.n} attempt${a.n === 1 ? "" : "s"} left.`);
      else if (a.kind === "locked") {
        setErr(lockMessage(a.n));
        setLockedFor(a.n);
        refreshStatus().catch(() => {});
      } else setErr(a.msg);
    } finally {
      setBusy(false);
    }
  }

  // A backup restored onto another phone: the key that guards the PIN stayed on the old
  // one, so the PIN cannot open these files. The recovery phrase restores the wallet.
  if (status.copied) {
    return (
      <div className="m-gate">
        <div className="fill" />
        <Logo />
        <h1 className="m-title small">Restore this wallet</h1>
        <p className="m-sub">This wallet was copied from another phone, for example by a backup. For your safety the PIN only works on the phone it was set on. Enter your 24-word recovery phrase to use the wallet here.</p>
        {err && <p className="m-sub" style={{ color: "var(--bad)" }}>{err}</p>}
        <div className="fill" />
        <div className="wide">
          <Btn
            full
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setErr("");
              try {
                await call("mobile_forget_copied");
                onForgotten();
              } catch (e) {
                setErr(String(e instanceof Error ? e.message : e));
              } finally {
                setBusy(false);
              }
            }}
          >
            I have my recovery phrase
          </Btn>
        </div>
      </div>
    );
  }

  const locked = lockedFor > 0;
  return (
    <div className="m-gate">
      <Logo />
      <h1 className="m-title">ZCrypt</h1>
      <p className="m-sub">{locked ? lockMessage(lockedFor) : "Enter your PIN"}</p>
      <div className="fill" />
      <PinPad
        onComplete={pin}
        error={err}
        resetKey={key.current}
        disabled={busy || locked}
        message={busy ? "Unlocking…" : ""}
        extra={
          status.biometric ? (
            <button className="m-key ghost" style={{ flex: 1 }} disabled={busy || locked} onClick={face} aria-label={bioName(status)}>
              <Icon name="faceid" size={30} />
            </button>
          ) : null
        }
      />
    </div>
  );
}
