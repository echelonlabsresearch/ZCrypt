import { useEffect, useRef, useState } from "react";
import { call } from "../lib/api";
import { authError, Btn, Icon, PinPad, Sheet, Switch } from "./ui";
import { bioName, useAuth } from "./MobileApp";

interface NodeStatus {
  connected: boolean;
  height: number;
  version: string;
}
interface Settings {
  node_url: string;
}

const VERSION = "0.1.1-alpha";

/** Security and connection, nothing else. Reached from the gear on the portfolio. */
export default function SettingsSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { status, refreshStatus, askPin, lock, toast } = useAuth();
  const [node, setNode] = useState<NodeStatus | null>(null);
  const [url, setUrl] = useState("");
  const [chain, setChain] = useState("");
  const [bioBusy, setBioBusy] = useState(false);
  // Change PIN: a three-step pad inside this sheet.
  const [changing, setChanging] = useState<"" | "old" | "new" | "again">("");
  const [oldPin, setOldPin] = useState("");
  const [newPin, setNewPin] = useState("");
  const [pinErr, setPinErr] = useState("");
  const key = useRef(0);
  const bio = bioName(status);

  useEffect(() => {
    if (!open) return;
    call<NodeStatus>("node_status").then(setNode).catch(() => setNode(null));
    call<Settings>("get_settings").then((s) => setUrl(s.node_url)).catch(() => {});
    call<string>("chain_pin").then(setChain).catch(() => {});
    refreshStatus().catch(() => {});
  }, [open, refreshStatus]);

  async function toggleBio(on: boolean) {
    setBioBusy(true);
    try {
      if (on) {
        const ok = await askPin(`Enter your PIN to turn on ${bio}`, (pin) => call("mobile_set_biometric", { enabled: true, pin }).then(() => undefined));
        if (ok) toast(`${bio} is on`);
      } else {
        await call("mobile_set_biometric", { enabled: false, pin: null });
        toast(`${bio} is off`, "Your PIN opens the wallet.");
      }
      await refreshStatus();
    } catch (e) {
      toast("Could not change", String(e));
    } finally {
      setBioBusy(false);
    }
  }

  function startChange() {
    setOldPin("");
    setNewPin("");
    setPinErr("");
    key.current += 1;
    setChanging("old");
  }
  async function pinStep(p: string) {
    key.current += 1;
    if (changing === "old") {
      setOldPin(p);
      setChanging("new");
    } else if (changing === "new") {
      setNewPin(p);
      setChanging("again");
    } else {
      if (p !== newPin) {
        setPinErr("The PINs do not match.");
        setTimeout(() => { setPinErr(""); setChanging("new"); }, 900);
        return;
      }
      try {
        await call("mobile_change_pin", { old: oldPin, new: newPin });
        toast("PIN changed");
        setChanging("");
      } catch (e) {
        const a = authError(e);
        setPinErr(a.kind === "wrong" ? "The current PIN was wrong." : a.msg);
        setTimeout(() => { setPinErr(""); setChanging("old"); }, 1200);
      }
    }
  }

  if (changing) {
    const title = changing === "old" ? "Current PIN" : changing === "new" ? "New PIN" : "Confirm new PIN";
    return (
      <Sheet open={open} onClose={() => setChanging("")} title={title}>
        <PinPad onComplete={pinStep} error={pinErr} resetKey={key.current} />
        <Btn full kind="ghost" style={{ marginTop: 10 }} onClick={() => setChanging("")}>Cancel</Btn>
      </Sheet>
    );
  }

  return (
    <Sheet open={open} onClose={onClose} title="Settings">
      <div className="m-section" style={{ marginTop: 4 }}>Security</div>
      <div className="m-list">
        <div className="m-row">
          <span className="m-avatar soft"><Icon name="faceid" size={20} /></span>
          <div className="grow">
            <div className="primary">{bio}</div>
            <div className="secondary">{status.biometry_available ? "Unlock and confirm payments" : "Not available on this device"}</div>
          </div>
          <Switch on={status.biometric} disabled={bioBusy || !status.biometry_available} onChange={toggleBio} />
        </div>
        <button className="m-row" onClick={startChange}>
          <span className="m-avatar soft"><Icon name="lock" size={20} /></span>
          <div className="grow">
            <div className="primary">Change PIN</div>
            <div className="secondary">6 digits</div>
          </div>
          <Icon name="chevron" size={20} />
        </button>
        <button className="m-row" onClick={() => { onClose(); lock(); }}>
          <span className="m-avatar soft"><Icon name="close" size={20} /></span>
          <div className="grow">
            <div className="primary">Lock now</div>
          </div>
        </button>
      </div>

      <div className="m-section">Network</div>
      <div className="m-list">
        <div className="m-row">
          <span className={`m-avatar ${node?.connected ? "ok" : "bad"}`}><Icon name="shield" size={20} /></span>
          <div className="grow">
            <div className="primary">{node?.connected ? "Connected" : "Not connected"}</div>
            <div className="secondary">{url || "…"}{chain ? ` · ${chain}` : ""}</div>
          </div>
          <div className="end m-num secondary">{node?.connected ? `#${node.height.toLocaleString()}` : ""}</div>
        </div>
      </div>

      <p className="m-hint m-center" style={{ marginTop: 20 }}>
        ZCrypt Wallet {VERSION} · keys never leave this phone
      </p>
    </Sheet>
  );
}
