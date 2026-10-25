import { useEffect, useRef, useState } from "react";
import { call } from "../lib/api";
import { authError, Icon, lockMessage, Logo, PinPad } from "./ui";
import { bioName, useAuth } from "./MobileApp";

/** The lock screen: Face ID straight away when it is on, the keypad underneath. */
export default function Lock({ onUnlocked }: { onUnlocked: () => void }) {
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
