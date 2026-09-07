import { useEffect, useState } from "react";
import { call, copy } from "../lib/api";

interface NodeStatus {
  connected: boolean;
  height: number;
  app: string;
  version: string;
}

// Full settings object — kept intact so saving one field never resets the others.
interface WalletSettings {
  node_url: string;
  btc_url: string;
  btc_user: string;
  btc_pass: string;
  btc_wallet: string;
  btc_network: string;
  btc_selfcustody: boolean;
  esplora_url: string;
  tor_enabled: boolean;
  tor_proxy: string;
}

export default function Settings() {
  const [pw, setPw] = useState("");
  const [phrase, setPhrase] = useState("");
  const [err, setErr] = useState("");

  // H6 defense-in-depth: keep the recovery phrase in the DOM/JS heap only briefly.
  // A revealed seed auto-hides after 60s, and is always cleared when leaving Settings,
  // shrinking the window in which any injected script could read it.
  useEffect(() => {
    if (!phrase) return;
    const t = setTimeout(() => setPhrase(""), 60_000);
    return () => clearTimeout(t);
  }, [phrase]);
  useEffect(() => () => setPhrase(""), []);

  const [nodeUrl, setNodeUrl] = useState("");
  const [torEnabled, setTorEnabled] = useState(false);
  const [torProxy, setTorProxy] = useState("127.0.0.1:9050");
  const [full, setFull] = useState<WalletSettings | null>(null);
  const [status, setStatus] = useState<NodeStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const [saved, setSaved] = useState(false);
  type TorStatus = {
    enabled: boolean;
    reachable: boolean;
    node_routed: boolean;
    bridge_routed: boolean;
    proxy: string;
    detail: string;
  };
  const [tor, setTor] = useState<TorStatus | null>(null);

  useEffect(() => {
    call<WalletSettings>("get_settings")
      .then((s) => {
        setFull(s);
        setNodeUrl(s.node_url);
        setTorEnabled(!!s.tor_enabled);
        setTorProxy(s.tor_proxy || "127.0.0.1:9050");
      })
      .catch(() => {});
    checkNode();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Save the FULL settings object (preserving BTC + any other fields) with the
  // current node/Tor values applied.
  async function saveSettings(next: Partial<WalletSettings>) {
    const merged: WalletSettings = {
      node_url: nodeUrl.trim(),
      btc_url: full?.btc_url ?? "http://localhost:18443",
      btc_user: full?.btc_user ?? "zcrypt",
      btc_pass: full?.btc_pass ?? "zcrypt",
      btc_wallet: full?.btc_wallet ?? "demo",
      btc_network: full?.btc_network ?? "bitcoin",
      btc_selfcustody: full?.btc_selfcustody ?? true,
      esplora_url: full?.esplora_url ?? "https://blockstream.info/api",
      tor_enabled: torEnabled,
      tor_proxy: torProxy.trim() || "127.0.0.1:9050",
      ...next,
    };
    await call("save_settings", { settings: merged });
    setFull(merged);
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
    checkNode();
  }

  async function saveNode() {
    await saveSettings({ node_url: nodeUrl.trim() });
  }

  async function checkNode() {
    setChecking(true);
    try {
      const s = await call<NodeStatus>("node_status");
      setStatus(s);
    } catch {
      setStatus({ connected: false, height: 0, app: "", version: "" });
    } finally {
      setChecking(false);
    }
    try {
      setTor(await call<TorStatus>("tor_status"));
    } catch {
      setTor(null);
    }
  }

  async function reveal() {
    setErr("");
    setPhrase("");
    try {
      const p = await call<string>("get_seed_phrase", { password: pw });
      setPhrase(p);
      setPw("");
    } catch (e) {
      setErr("Wrong password.");
    }
  }

  return (
    <div>
      <h2 className="view-title">⚙️ Settings</h2>

      <div className="card">
        <h2>🌐 Consensus Node</h2>
        <div className="field" style={{ marginTop: "0.8rem" }}>
          <label>CometBFT RPC URL</label>
          <input value={nodeUrl} onChange={(e) => setNodeUrl(e.target.value)} placeholder="http://localhost:36657" />
        </div>
        <div style={{ display: "flex", gap: "0.6rem", alignItems: "center", flexWrap: "wrap" }}>
          <button className="btn-primary" onClick={saveNode}>{saved ? "✓ Saved" : "Save"}</button>
          <button className="btn-secondary" onClick={checkNode}>{checking ? "Checking…" : "🔄 Test Connection"}</button>
          <div style={{ marginLeft: "auto" }}>
            {status ? (
              status.connected ? (
                <span style={{ color: "var(--color-green)" }}>
                  ● Connected · {status.app} v{status.version} · height {status.height}
                </span>
              ) : (
                <span style={{ color: "var(--color-red)" }}>● Not reachable — is your node running?</span>
              )
            ) : (
              <span style={{ opacity: 0.5 }}>…</span>
            )}
          </div>
        </div>
        <div className="warn" style={{ marginTop: "0.9rem" }}>
          Local devnet default is <code style={{ color: "var(--color-cyan)" }}>http://localhost:36657</code> (the
          Docker compose chain). The height only advances when a transaction is
          submitted — empty blocks are disabled, so a stable height while idle is
          normal, not a stall. Fund or Send and you'll see it move.
        </div>
      </div>

      <div className="card" style={{ marginTop: "1.2rem" }}>
        <h2>🧅 Tor Privacy</h2>
        <div style={{ fontSize: "0.82rem", opacity: 0.75, marginBottom: "0.7rem" }}>
          When enabled, the wallet reaches the node <b>only through a local Tor proxy</b>, so the node operator and
          anyone on the network path can't tie your IP to the coins and nullifiers you look up. <b>Off by default.</b>{" "}
          Requires a Tor daemon running locally (hostnames, including <code>.onion</code>, resolve inside Tor — no DNS
          leaks).
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: "0.6rem", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={torEnabled}
            onChange={(e) => {
              setTorEnabled(e.target.checked);
              saveSettings({ tor_enabled: e.target.checked });
            }}
            style={{ width: "auto" }}
          />
          <span>Route node + bridge traffic through Tor</span>
          {torEnabled && tor && (
            <span
              style={{
                fontSize: "0.8rem",
                color: !tor.reachable
                  ? "var(--color-red, #e5484d)"
                  : tor.node_routed
                    ? "var(--color-green)"
                    : "var(--color-amber, #d99a00)",
              }}
            >
              {!tor.reachable
                ? "● proxy unreachable"
                : tor.node_routed
                  ? "● routed via Tor"
                  : "● active (node is local → direct)"}
            </span>
          )}
        </label>
        <div className="field" style={{ marginTop: "0.8rem" }}>
          <label>Tor SOCKS proxy</label>
          <input
            value={torProxy}
            onChange={(e) => setTorProxy(e.target.value)}
            placeholder="127.0.0.1:9050"
          />
          <div style={{ fontSize: "0.76rem", opacity: 0.6, marginTop: "0.3rem" }}>
            Tor daemon default is <code>127.0.0.1:9050</code>; Tor Browser uses <code>127.0.0.1:9150</code>.
          </div>
        </div>
        <button className="btn-primary" onClick={() => saveSettings({ tor_proxy: torProxy.trim() })}>
          {saved ? "✓ Saved" : "Save Tor settings"}
        </button>
        {torEnabled && tor && (
          <div className={tor.reachable ? "warn" : "msg err"} style={{ marginTop: "0.9rem" }}>
            {tor.detail} The wallet <b>fails closed</b> — it never falls back to a direct
            connection that would reveal your IP.
          </div>
        )}
      </div>

      <div className="card" style={{ marginTop: "1.2rem" }}>
        <h2>🔑 Recovery Seed Phrase</h2>
        <p className="warn">Revealing your phrase exposes full control of your funds. Make sure no one is watching.</p>
        {!phrase ? (
          <div style={{ display: "flex", gap: "0.6rem", alignItems: "flex-end" }}>
            <div style={{ flex: 1 }}>
              <label>Password</label>
              <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} onKeyDown={(e) => e.key === "Enter" && reveal()} />
            </div>
            <button className="btn-secondary" onClick={reveal}>Reveal</button>
          </div>
        ) : (
          <>
            <div className="mono-box" style={{ color: "var(--color-green)" }}>{phrase}</div>
            <button className="copy-btn" style={{ marginTop: "0.6rem" }} onClick={() => copy(phrase)}>📋 Copy</button>
            <button className="btn-link" style={{ marginLeft: "0.8rem" }} onClick={() => setPhrase("")}>Hide</button>
          </>
        )}
        {err && <div className="msg err">{err}</div>}
      </div>

      <div className="card" style={{ marginTop: "1.2rem" }}>
        <h2>ℹ️ About</h2>
        <div className="card-row" style={{ borderTop: "none", paddingTop: 0 }}>
          <span>Value proof</span>
          <span style={{ color: "var(--color-cyan)" }}>Plonky3 STARK · 128-bit · no trusted setup</span>
        </div>
        <div className="card-row">
          <span>Signatures & notes</span>
          <span style={{ color: "var(--color-cyan)" }}>ML-KEM-768 · post-quantum</span>
        </div>
        <div className="card-row">
          <span>Anonymity set</span>
          <span style={{ color: "var(--color-cyan)" }}>whole pool — every coin in history</span>
        </div>
        <div className="card-row">
          <span>Recovery</span>
          <span style={{ color: "var(--color-cyan)" }}>BIP-39 · one phrase covers normal + stealth</span>
        </div>
      </div>
    </div>
  );
}
