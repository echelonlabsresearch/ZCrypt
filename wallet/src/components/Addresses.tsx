import { useCallback, useEffect, useState } from "react";
import { call, saveFile } from "../lib/api";
import { CopyButton } from "./Share";

interface Stealth {
  index: number;
  address: string;
}

/** Plain-language guide to every address / key type. */
const TYPES = [
  {
    icon: "🏷️",
    name: "Normal address",
    color: "--color-cyan",
    tag: "zc1… · recoverable from your phrase",
    body: "Your everyday address — share it to get paid. Payments land on-chain and auto-credit when you Refresh. Your 24-word phrase restores it, and your view key (below) can see what arrives here.",
  },
  {
    icon: "🕶️",
    name: "Stealth address",
    color: "--color-purple",
    tag: "zc1… (stealth) · NOT in your phrase",
    body: "Maximum privacy. A payment arrives as an encrypted FILE (nothing readable is left on-chain) and is invisible even to your own view key. Each stealth address has its own key that your phrase will NOT restore — so back up the key. Make as many as you like.",
  },
  {
    icon: "💵",
    name: "Bearer coin",
    color: "--color-yellow",
    tag: "file · coin + gas",
    body: "Not an address — a file from the Send tab. Send it over any chat. Opening it in the wallet credits the full amount, and the file includes 0.01 ZCRYPT gas so a new wallet can claim it. Until that claim is in a block, anyone with the file can take it.",
  },
  {
    icon: "🔎",
    name: "View key",
    color: "--color-green",
    tag: "read-only · for auditors",
    body: "A key you can GIVE someone so they can see the amounts of payments to your NORMAL address — and nothing else. It can never spend, and can't see stealth or bearer coins. This is how you make a selective, compliance-friendly disclosure.",
  },
];

export default function Addresses() {
  const [normal, setNormal] = useState("");
  const [stealth, setStealth] = useState<Stealth[]>([]);
  const [viewKey, setViewKey] = useState("");
  const [showVk, setShowVk] = useState(false);
  // Backup seeds are spend secrets: they are never bulk-fetched. Each is revealed one at a
  // time, behind a fresh password check (reveal_stealth_backup), and held only in local state.
  const [revealed, setRevealed] = useState<Record<number, string>>({});
  const [pwFor, setPwFor] = useState<number | null>(null);
  const [pw, setPw] = useState("");
  const [revealErr, setRevealErr] = useState("");
  const [saved, setSaved] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(() => {
    call<string>("get_address").then(setNormal).catch(() => {});
    call<Stealth[]>("list_stealth_addresses").then(setStealth).catch(() => {});
    call<string>("get_view_key").then(setViewKey).catch(() => {});
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  async function newStealth() {
    setErr("");
    setBusy(true);
    try {
      await call("new_stealth_address");
      load();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function revealBackup(index: number) {
    setRevealErr("");
    try {
      const seed = await call<string>("reveal_stealth_backup", { index, password: pw });
      setRevealed((r) => ({ ...r, [index]: seed }));
      setPwFor(null);
      setPw("");
    } catch {
      setRevealErr("Wrong password.");
    }
  }

  function cancelReveal() {
    setPwFor(null);
    setPw("");
    setRevealErr("");
  }

  return (
    <div>
      <h2 className="view-title">📇 Addresses & Keys</h2>

      {/* Plain-language guide */}
      <div className="card">
        <h2>Which one should I use?</h2>
        {TYPES.map((t) => (
          <div className="card-row" key={t.name} style={{ alignItems: "flex-start" }}>
            <div style={{ flex: 1 }}>
              <div style={{ color: `var(${t.color})`, fontWeight: "bold" }}>
                {t.icon} {t.name}
              </div>
              <div style={{ fontSize: "0.72rem", opacity: 0.55, margin: "0.15rem 0 0.35rem" }}>{t.tag}</div>
              <div style={{ fontSize: "0.85rem", opacity: 0.85, lineHeight: 1.5 }}>{t.body}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Normal address */}
      <div className="card" style={{ marginTop: "1.2rem" }}>
        <h2>🏷️ Your normal address</h2>
        <div className="card-row" style={{ borderTop: "none", paddingTop: 0 }}>
          <code style={{ color: "var(--color-cyan)", wordBreak: "break-all", flex: 1 }} title={normal}>
            {normal || "…"}
          </code>
          <CopyButton text={normal} />
        </div>
      </div>

      {/* Stealth addresses — persisted list */}
      <div className="card" style={{ marginTop: "1.2rem" }}>
        <div className="card-row" style={{ borderTop: "none", paddingTop: 0 }}>
          <h2 style={{ margin: 0 }}>🕶️ Stealth addresses</h2>
          <button className="copy-btn" disabled={busy} onClick={newStealth}>
            {busy ? "…" : "+ New stealth"}
          </button>
        </div>
        {stealth.length === 0 && (
          <div style={{ opacity: 0.6, fontSize: "0.85rem" }}>
            None yet. Generate one for maximum-privacy, file-delivered payments.
          </div>
        )}
        {stealth.map((s) => (
          <div key={s.index} className="card-row" style={{ alignItems: "flex-start" }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: "0.72rem", opacity: 0.5 }}>Stealth #{s.index}</div>
              <code style={{ color: "var(--color-purple)", wordBreak: "break-all" }}>{s.address}</code>
              <div style={{ marginTop: "0.4rem" }}>
                {revealed[s.index] ? (
                  <div className="mono-box" style={{ color: "var(--color-yellow)", wordBreak: "break-all" }}>
                    {revealed[s.index]}
                  </div>
                ) : pwFor === s.index ? (
                  <div style={{ display: "flex", gap: "0.4rem", alignItems: "center", flexWrap: "wrap" }}>
                    <input
                      type="password"
                      placeholder="Password to reveal"
                      value={pw}
                      autoFocus
                      onChange={(e) => setPw(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && revealBackup(s.index)}
                    />
                    <button className="copy-btn" onClick={() => revealBackup(s.index)}>
                      Reveal
                    </button>
                    <button className="btn-link" onClick={cancelReveal}>
                      Cancel
                    </button>
                    {revealErr && <span style={{ color: "var(--color-red, #e66)", fontSize: "0.78rem" }}>{revealErr}</span>}
                  </div>
                ) : (
                  <button className="btn-link" onClick={() => { setPwFor(s.index); setPw(""); setRevealErr(""); }}>
                    🔑 Reveal private key
                  </button>
                )}
              </div>
              <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.5rem", flexWrap: "wrap" }}>
                <CopyButton text={s.address} label="⧉ Copy address" />
                {revealed[s.index] && <CopyButton text={revealed[s.index]} label="⧉ Copy private key" />}
              </div>
            </div>
          </div>
        ))}
        <div className="warn" style={{ marginTop: "0.8rem" }}>
          ⚠️ Your recovery phrase will <b>not</b> restore stealth addresses — back up each private key
          separately (copy it somewhere safe). Every stealth address you generate is saved here.
        </div>
      </div>

      {/* View key */}
      <div className="card" style={{ marginTop: "1.2rem" }}>
        <h2>🔎 View key — share for compliance</h2>
        <div style={{ fontSize: "0.85rem", opacity: 0.85, lineHeight: 1.5, marginBottom: "0.6rem" }}>
          Give this to an auditor to let them <b>see the amounts</b> of payments to your normal address —
          and nothing more. It can never spend, and it can't see stealth or bearer coins.
        </div>
        {showVk ? (
          <>
            <div className="mono-box" style={{ color: "var(--color-green)", wordBreak: "break-all" }}>
              {viewKey}
            </div>
            <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.5rem", flexWrap: "wrap" }}>
              <CopyButton text={viewKey} label="⧉ Copy view key" />
              <button
                className="copy-btn"
                onClick={async () => {
                  try {
                    setSaved(await saveFile("zcrypt-view-key.txt", viewKey));
                  } catch (e) {
                    setSaved(`error: ${e}`);
                  }
                }}
              >
                💾 Save file
              </button>
              <button className="btn-link" onClick={() => setShowVk(false)}>
                Hide
              </button>
            </div>
            {saved && (
              <div style={{ fontSize: "0.78rem", opacity: 0.7, marginTop: "0.4rem" }}>
                {saved.startsWith("error") ? (
                  <span style={{ color: "var(--color-red, #e66)" }}>{saved}</span>
                ) : (
                  <>
                    ✓ Saved to <code>{saved}</code>
                  </>
                )}
              </div>
            )}
          </>
        ) : (
          <button className="btn-secondary" onClick={() => setShowVk(true)}>
            👁 Reveal my view key
          </button>
        )}
        <div className="warn" style={{ marginTop: "0.8rem" }}>
          Only share your view key with people you want to grant read-access to your normal-address
          receipts. It is a disclosure, and it cannot be un-shared.
        </div>
      </div>

      {err && <div className="msg err">{err}</div>}
    </div>
  );
}
