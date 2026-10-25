import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { call, clearSensitiveClipboard } from "../lib/api";
import { authError, Icon, IconName, lockMessage, PinPad, Sheet } from "./ui";
import Onboarding from "./Onboarding";
import Lock from "./Lock";
import Home from "./Home";
import SendScreen from "./SendScreen";
import ReceiveScreen from "./ReceiveScreen";
import HistoryScreen from "./HistoryScreen";

export interface AuthStatus {
  wallet: boolean;
  pin: boolean;
  biometric: boolean;
  biometry_available: boolean;
  biometry_type: "faceid" | "touchid" | "none";
  locked_for_s: number;
}

export const bioName = (s: AuthStatus | null) => (s?.biometry_type === "touchid" ? "Touch ID" : "Face ID");

interface AuthApi {
  status: AuthStatus;
  refreshStatus: () => Promise<AuthStatus>;
  /** Owner check before money leaves: biometrics first, the PIN sheet as fallback. */
  confirm: (title?: string) => Promise<boolean>;
  /** Ask for the PIN only (needed to switch biometrics on or change the PIN). */
  askPin: (title: string, verify: (pin: string) => Promise<void>) => Promise<boolean>;
  lock: () => Promise<void>;
  toast: (title: string, body?: string) => void;
}

const EMPTY: AuthStatus = { wallet: false, pin: false, biometric: false, biometry_available: false, biometry_type: "none", locked_for_s: 0 };
const AuthContext = createContext<AuthApi>({
  status: EMPTY,
  refreshStatus: async () => EMPTY,
  confirm: async () => false,
  askPin: async () => false,
  lock: async () => {},
  toast: () => {},
});
export const useAuth = () => useContext(AuthContext);

type Phase = "loading" | "onboard" | "adopt" | "lock" | "ready";
type Tab = "home" | "send" | "receive" | "history";
const TABS: { id: Tab; label: string; icon: IconName }[] = [
  { id: "home", label: "Portfolio", icon: "home" },
  { id: "send", label: "Send", icon: "send" },
  { id: "receive", label: "Receive", icon: "receive" },
  { id: "history", label: "History", icon: "history" },
];

interface PinRequest {
  title: string;
  verify: (pin: string) => Promise<void>;
  resolve: (ok: boolean) => void;
}

export default function MobileApp() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [status, setStatus] = useState<AuthStatus>(EMPTY);
  const [tab, setTab] = useState<Tab>("home");
  const [toasts, setToasts] = useState<{ id: number; title: string; body?: string }[]>([]);
  const [incoming, setIncoming] = useState<string[]>([]);
  const [refreshTick, setRefreshTick] = useState(0);
  // The PIN sheet: one request at a time, resolved by the pad or by dismissing it.
  const [pinReq, setPinReq] = useState<PinRequest | null>(null);
  const [pinErr, setPinErr] = useState("");
  const [pinBusy, setPinBusy] = useState(false);
  const pinKey = useRef(0);

  const toast = useCallback((title: string, body?: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, title, body }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4500);
  }, []);

  const refreshStatus = useCallback(async () => {
    const s = await call<AuthStatus>("mobile_auth_status");
    setStatus(s);
    return s;
  }, []);

  // Boot: which gate applies?
  useEffect(() => {
    refreshStatus()
      .then((s) => setPhase(!s.wallet ? "onboard" : !s.pin ? "adopt" : "lock"))
      .catch((e) => {
        toast("Could not start", String(e));
        setPhase("onboard");
      });
  }, [refreshStatus, toast]);

  // Files opened with the app (AirDrop, Files, Mail): credited under Receive once unlocked.
  useEffect(() => {
    call<string[]>("take_opened_files")
      .then((f) => f.length && setIncoming((q) => [...q, ...f]))
      .catch(() => {});
    let un: (() => void) | null = null;
    listen<string>("zcrypt-open", (e) => setIncoming((q) => [...q, e.payload]))
      .then((u) => (un = u))
      .catch(() => {});
    return () => {
      if (un) un();
    };
  }, []);
  useEffect(() => {
    if (phase === "ready" && incoming.length) setTab("receive");
  }, [phase, incoming.length]);

  const askPin = useCallback((title: string, verify: (pin: string) => Promise<void>) => {
    return new Promise<boolean>((resolve) => {
      pinKey.current += 1;
      setPinErr("");
      setPinReq({ title, verify, resolve });
    });
  }, []);

  async function pinEntered(pin: string) {
    if (!pinReq) return;
    setPinBusy(true);
    try {
      await pinReq.verify(pin);
      pinReq.resolve(true);
      setPinReq(null);
    } catch (e) {
      const a = authError(e);
      pinKey.current += 1;
      setPinErr(a.kind === "wrong" ? `Wrong PIN. ${a.n} attempt${a.n === 1 ? "" : "s"} left.` : a.kind === "locked" ? lockMessage(a.n) : a.msg);
    } finally {
      setPinBusy(false);
    }
  }
  function pinCancel() {
    pinReq?.resolve(false);
    setPinReq(null);
  }

  const confirm = useCallback(
    async (title = "Confirm this payment") => {
      if (status.biometric) {
        try {
          await call("mobile_confirm", { pin: null });
          return true;
        } catch (e) {
          if (authError(e).kind !== "biometric") {
            toast("Could not confirm", String(e));
            return false;
          }
          // Face ID declined or unavailable: fall through to the PIN.
        }
      }
      return askPin(title, (pin) => call("mobile_confirm", { pin }).then(() => undefined));
    },
    [status.biometric, askPin, toast]
  );

  const lock = useCallback(async () => {
    await clearSensitiveClipboard();
    await call("lock_wallet").catch(() => {});
    setTab("home");
    setPhase("lock");
  }, []);

  const api: AuthApi = { status, refreshStatus, confirm, askPin, lock, toast };

  function unlocked() {
    refreshStatus().catch(() => {});
    setRefreshTick((t) => t + 1);
    setPhase("ready");
  }

  return (
    <AuthContext.Provider value={api}>
      <div className="m-app">
        {phase === "loading" && <div className="m-gate" />}
        {(phase === "onboard" || phase === "adopt") && <Onboarding adopt={phase === "adopt"} onDone={unlocked} />}
        {phase === "lock" && <Lock onUnlocked={unlocked} />}

        {phase === "ready" && (
          <>
            <div className="m-screen" style={{ display: tab === "home" ? "block" : "none" }}>
              <Home refreshTick={refreshTick} onSend={() => setTab("send")} onReceive={() => setTab("receive")} />
            </div>
            <div className="m-screen" style={{ display: tab === "send" ? "block" : "none" }}>
              <SendScreen active={tab === "send"} onSent={() => setRefreshTick((t) => t + 1)} />
            </div>
            <div className="m-screen" style={{ display: tab === "receive" ? "block" : "none" }}>
              <ReceiveScreen
                active={tab === "receive"}
                incoming={incoming[0] ?? ""}
                onConsumed={() => setIncoming((q) => q.slice(1))}
                onReceived={() => setRefreshTick((t) => t + 1)}
              />
            </div>
            <div className="m-screen" style={{ display: tab === "history" ? "block" : "none" }}>
              <HistoryScreen active={tab === "history"} refreshTick={refreshTick} />
            </div>

            <nav className="m-tabs">
              {TABS.map((t) => (
                <button key={t.id} className={`m-tab ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
                  <Icon name={t.icon} size={24} stroke={tab === t.id ? 2.1 : 1.8} />
                  {t.label}
                </button>
              ))}
            </nav>
          </>
        )}

        <Sheet open={pinReq !== null} onClose={pinCancel} title={pinReq?.title}>
          <PinPad onComplete={pinEntered} error={pinErr} resetKey={pinKey.current} disabled={pinBusy} message={pinBusy ? "Checking…" : "Enter your 6-digit PIN"} />
          <button className="m-btn ghost full" style={{ marginTop: 10 }} onClick={pinCancel}>
            Cancel
          </button>
        </Sheet>

        <div className="m-toasts">
          {toasts.map((t) => (
            <div className="m-toast" key={t.id}>
              <b>{t.title}</b>
              {t.body && <span>{t.body}</span>}
            </div>
          ))}
        </div>
      </div>
    </AuthContext.Provider>
  );
}
