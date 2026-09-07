import { useEffect, useState, useCallback } from "react";
import { call, fmt, fmtAsset, trunc, copy, copySensitive } from "./lib/api";
import Balance from "./components/Balance";
import Send from "./components/Send";
import Receive from "./components/Receive";
import Addresses from "./components/Addresses";
import History from "./components/History";
import Mint from "./components/Mint";
import Rewards from "./components/Rewards";
import Bridge from "./components/Bridge";
import Settings from "./components/Settings";

type Tab = "balance" | "receive" | "send" | "addresses" | "history" | "mint" | "rewards" | "bridge" | "settings";
type Mode = "loading" | "choose" | "create" | "restore" | "seed" | "unlock" | "ready";

interface Toast {
  id: number;
  title: string;
  body: string;
}

const VERSION = "0.1.0";

export default function App() {
  const [mode, setMode] = useState<Mode>("loading");
  const [tab, setTab] = useState<Tab>("balance");
  const [address, setAddress] = useState("");
  const [balance, setBalance] = useState(0);
  const [toasts, setToasts] = useState<Toast[]>([]);

  // create/restore form
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [mnemonicIn, setMnemonicIn] = useState("");
  const [seedPhrase, setSeedPhrase] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [copiedSeed, setCopiedSeed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [err, setErr] = useState("");

  const toast = useCallback((title: string, body: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, title, body }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6000);
  }, []);

  const refresh = useCallback(async () => {
    try {
      // Show locally-known address + balance IMMEDIATELY (no network on this path).
      const a = await call<string>("get_address");
      setAddress(a);
      const b = await call<{ total: number }>("get_balance");
      setBalance(b.total);
      // Scan the chain for incoming coins in the BACKGROUND (no-op if no node), then
      // refresh the balance. Never blocks showing the wallet — the scan holds no lock
      // across its network I/O, so the UI stays responsive while it runs.
      call("scan_onchain")
        .then(async () => {
          const b2 = await call<{ total: number }>("get_balance");
          setBalance(b2.total);
        })
        .catch(() => {});
    } catch {
      /* locked */
    }
  }, []);

  useEffect(() => {
    (async () => {
      const exists = await call<boolean>("wallet_exists").catch(() => false);
      setMode(exists ? "unlock" : "choose");
    })();
  }, []);

  useEffect(() => {
    if (mode === "ready") refresh();
  }, [mode, refresh]);

  async function doCreate() {
    setErr("");
    if (pw.length < 8) return setErr("Password must be at least 8 characters.");
    if (pw !== pw2) return setErr("Passwords do not match.");
    setBusy(true);
    try {
      const r = await call<{ address: string; seed_phrase: string }>("create_wallet", { password: pw });
      setAddress(r.address);
      setSeedPhrase(r.seed_phrase);
      setMode("seed");
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function doRestore() {
    setErr("");
    if (pw.length < 8) return setErr("Password must be at least 8 characters.");
    if (pw !== pw2) return setErr("Passwords do not match.");
    setBusy(true);
    try {
      // 1) Rebuild the account from the recovery phrase.
      await call("restore_wallet", { password: pw, mnemonic: mnemonicIn.trim() });
      // 2) Recover the coins: scan the chain for notes addressed to this account.
      //    (-1 = couldn't reach a node; 0 = none found yet; N = recovered N coins.)
      setRecovering(true);
      const found = await call<number>("scan_onchain").catch(() => -1);
      setMode("ready");
      if (found > 0) {
        toast("Wallet Restored", `Recovered ${found} coin${found === 1 ? "" : "s"} from the chain.`);
      } else if (found === 0) {
        toast("Wallet Restored", "Account ready — no coins found yet. If you expect a balance, set your node in Settings and tap 🔄 Refresh.");
      } else {
        toast("Wallet Restored", "Account ready. Couldn't reach a node to scan for coins — set it in Settings, then tap 🔄 Refresh.");
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
      setRecovering(false);
    }
  }

  async function doUnlock() {
    setErr("");
    setBusy(true);
    try {
      await call("unlock_wallet", { password: pw });
      setMode("ready");
    } catch (e) {
      setErr("Wrong password.");
    } finally {
      setBusy(false);
    }
  }

  async function lock() {
    await call("lock_wallet").catch(() => {});
    setPw("");
    setMode("unlock");
  }

  // ---------- onboarding ----------
  if (mode === "loading") {
    return (
      <div className="app">
        <div className="gate">
          <div className="spinner" />
          <div>Loading ZCrypt Wallet…</div>
        </div>
      </div>
    );
  }

  if (mode !== "ready") {
    return (
      <div className="app">
        <div className="main">
          <div className="gate">
            <div className="logo-big">⚡</div>
            <h1>ZCrypt Wallet</h1>
            <div className="tagline">Post-Quantum • Private • Zero-Knowledge</div>

            {mode === "choose" && (
              <div className="password-form">
                <button className="btn-primary btn-block" onClick={() => { setErr(""); setMode("create"); }}>
                  Create New Wallet
                </button>
                <div style={{ height: "0.8rem" }} />
                <button className="btn-secondary btn-block" onClick={() => { setErr(""); setMode("restore"); }}>
                  Restore from Seed Phrase
                </button>
                <div className="feature-chips">
                  <span className="chip">🔐 Post-Quantum Keys</span>
                  <span className="chip">⚡ Plonky3 ZK Proofs</span>
                  <span className="chip">🌐 BFT Consensus</span>
                </div>
              </div>
            )}

            {mode === "create" && (
              <div className="password-form">
                <div className="field">
                  <label>Password</label>
                  <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="min 8 characters" />
                </div>
                <div className="field">
                  <label>Confirm Password</label>
                  <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
                </div>
                {err && <div className="msg err">{err}</div>}
                <button className="btn-primary btn-block" disabled={busy} onClick={doCreate}>
                  {busy ? "Generating…" : "Generate Wallet"}
                </button>
                <div style={{ marginTop: "0.8rem" }}>
                  <button className="btn-link" onClick={() => setMode("choose")}>← Back</button>
                </div>
              </div>
            )}

            {mode === "restore" && (
              <div className="password-form">
                <div className="field">
                  <label>Recovery Phrase (24 words)</label>
                  <textarea className="mnemonic-input" value={mnemonicIn} onChange={(e) => setMnemonicIn(e.target.value)} placeholder="word1 word2 word3 …" />
                </div>
                <div className="field">
                  <label>New Password</label>
                  <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} />
                </div>
                <div className="field">
                  <label>Confirm Password</label>
                  <input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} />
                </div>
                <div style={{ fontSize: "0.8rem", opacity: 0.7, marginBottom: "0.2rem" }}>
                  After restoring, your coins are recovered by scanning the chain — make sure your node is set in Settings first.
                </div>
                {err && <div className="msg err">{err}</div>}
                <button className="btn-primary btn-block" disabled={busy} onClick={doRestore}>
                  {recovering ? "Recovering your coins…" : busy ? "Restoring…" : "Restore Wallet"}
                </button>
                <div style={{ marginTop: "0.8rem" }}>
                  <button className="btn-link" onClick={() => setMode("choose")}>← Back</button>
                </div>
              </div>
            )}

            {mode === "seed" && (
              <div className="password-form" style={{ maxWidth: 640 }}>
                <h2 style={{ color: "var(--color-cyan)" }}>🔑 Your Recovery Phrase</h2>
                <p className="warn">Write these 24 words down and store them offline. They are the ONLY way to recover this wallet.</p>
                <div className="seed-grid">
                  {seedPhrase.split(/\s+/).map((w, i) => (
                    <div className="seed-word" key={i}>
                      <span className="num">{i + 1}</span>
                      <span className="word">{w}</span>
                    </div>
                  ))}
                </div>
                <button
                  className="copy-btn"
                  style={copiedSeed ? { background: "var(--color-green)", color: "var(--color-bg)", borderColor: "var(--color-green)" } : undefined}
                  onClick={() => { copySensitive(seedPhrase); setCopiedSeed(true); setTimeout(() => setCopiedSeed(false), 1800); }}
                >
                  {copiedSeed ? "✓ Copied (clipboard clears in 60 s)" : "📋 Copy phrase"}
                </button>
                <ul className="danger-list">
                  <li>Never share your phrase with anyone.</li>
                  <li>ZCrypt cannot recover it for you.</li>
                  <li>Anyone with these words controls your funds.</li>
                </ul>
                <label style={{ display: "flex", gap: "0.5rem", alignItems: "center", fontWeight: "normal" }}>
                  <input type="checkbox" style={{ width: "auto" }} checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
                  I have saved my recovery phrase securely.
                </label>
                <button className="btn-primary btn-block" disabled={!confirmed} onClick={() => setMode("ready")}>
                  Continue to Wallet
                </button>
              </div>
            )}

            {mode === "unlock" && (
              <div className="password-form">
                <div className="field">
                  <label>Password</label>
                  <input
                    type="password"
                    value={pw}
                    onChange={(e) => setPw(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && doUnlock()}
                    autoFocus
                  />
                </div>
                {err && <div className="msg err">{err}</div>}
                <button className="btn-primary btn-block" disabled={busy} onClick={doUnlock}>
                  {busy ? "Unlocking…" : "Unlock Wallet"}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // ---------- main app ----------
  const tabs: Tab[] = ["balance", "receive", "send", "addresses", "history", "mint", "rewards", "bridge", "settings"];
  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <span className="logo-symbol">⚡</span>
          <h1>ZCrypt</h1>
          <span className="version">v{VERSION}</span>
        </div>
        <div className="header-right">
          <span className="balance-pill">Balance: {fmt(balance)} ZCRYPT</span>
        </div>
      </header>

      <nav className="nav">
        <div className="nav-tabs">
          {tabs.map((t) => (
            <button key={t} className={`nav-tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>
              {t}
            </button>
          ))}
        </div>
        <button className="btn-lock" onClick={lock}>🔒 Lock</button>
      </nav>

      <main className="main">
        <div style={{ display: tab === "balance" ? "block" : "none" }}>
          <Balance balance={balance} onRefresh={refresh} />
        </div>
        <div style={{ display: tab === "receive" ? "block" : "none" }}>
          <Receive onReceived={(r) => { refresh(); toast("Coin Received!", `+${fmtAsset(r.amount, r.decimals)} ${r.ticker}`); }} />
        </div>
        <div style={{ display: tab === "send" ? "block" : "none" }}>
          <Send active={tab === "send"} onSent={refresh} toast={toast} />
        </div>
        <div style={{ display: tab === "addresses" ? "block" : "none" }}>
          <Addresses />
        </div>
        <div style={{ display: tab === "history" ? "block" : "none" }}>
          <History active={tab === "history"} />
        </div>
        <div style={{ display: tab === "mint" ? "block" : "none" }}>
          <Mint onMinted={(a) => { refresh(); toast("Minted", `+${fmt(a)} ZCRYPT`); }} />
        </div>
        <div style={{ display: tab === "rewards" ? "block" : "none" }}>
          <Rewards active={tab === "rewards"} onClaimed={(a) => { refresh(); toast("Rewards Claimed", `+${fmt(a)} ZCRYPT now spendable`); }} />
        </div>
        <div style={{ display: tab === "bridge" ? "block" : "none" }}>
          <Bridge active={tab === "bridge"} onSwapped={(m) => { refresh(); toast("Swap Complete", m); }} />
        </div>
        <div style={{ display: tab === "settings" ? "block" : "none" }}>
          <Settings />
        </div>
      </main>

      <footer className="footer">
        <span className="util">Your Address:</span>
        <code onClick={() => { copy(address); toast("Copied", "Address copied to clipboard."); }} title={address}>
          {trunc(address, 22, 8)}
        </code>
        <span className="spacer" />
        <span className="util">post-quantum · amounts hidden · whole-pool anonymity</span>
      </footer>

      <div className="toast-stack">
        {toasts.map((t) => (
          <div className="toast" key={t.id}>
            <div className="t-title">💰 {t.title}</div>
            <div>{t.body}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
