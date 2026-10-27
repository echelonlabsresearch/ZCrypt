import { useCallback, useEffect, useRef, useState } from "react";
import { call, copySensitive, fmtAsset, HeldAsset, isWhitelisted, whitelistName } from "../lib/api";
import { Icon, Sheet, Btn, shareFile, short } from "./ui";
import { saveFile } from "../lib/api";
import SettingsSheet from "./SettingsSheet";

interface NodeStatus {
  connected: boolean;
  height: number;
  error: string;
}
interface PendingSecret {
  id: number;
  kind: string;
  label: string;
  secret: string;
}

const initials = (t: string) => t.replace(/^z/i, "").slice(0, 3).toUpperCase();

/** The portfolio: what this wallet holds, with Send and Receive one tap away. */
export default function Home({ refreshTick, onSend, onReceive, onBuy }: { refreshTick: number; onSend: () => void; onReceive: () => void; onBuy: () => void }) {
  const [assets, setAssets] = useState<HeldAsset[]>([]);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [coins, setCoins] = useState(0);
  const [node, setNode] = useState<NodeStatus | null>(null);
  const [secrets, setSecrets] = useState<PendingSecret[]>([]);
  const [spinning, setSpinning] = useState(false);
  const [settings, setSettings] = useState(false);
  const [openSecret, setOpenSecret] = useState<PendingSecret | null>(null);
  // Pull to refresh: how far the finger has dragged down from the top of the screen.
  const [pull, setPull] = useState(0);
  const pullRef = useRef<{ y0: number; on: boolean }>({ y0: 0, on: false });
  const wrap = useRef<HTMLDivElement>(null);

  const loadLocal = useCallback(async () => {
    const [a, b, s] = await Promise.all([
      call<HeldAsset[]>("held_assets").catch(() => [] as HeldAsset[]),
      call<{ coin_count: number }>("get_balance").catch(() => ({ coin_count: 0 })),
      call<PendingSecret[]>("list_pending_secrets").catch(() => [] as PendingSecret[]),
    ]);
    setAssets(a);
    setCoins(b.coin_count);
    setSecrets(s);
  }, []);

  useEffect(() => {
    call<string[]>("whitelisted_assets").then(setWhitelist).catch(() => {});
  }, []);

  const refresh = useCallback(async () => {
    setSpinning(true);
    await loadLocal();
    call<NodeStatus>("node_status").then(setNode).catch(() => setNode({ connected: false, height: 0, error: "" }));
    // Scan the chain for new coins in the background, then show them.
    call("scan_onchain")
      .then(loadLocal)
      .catch(() => {})
      .finally(() => setSpinning(false));
  }, [loadLocal]);

  useEffect(() => {
    refresh();
  }, [refresh, refreshTick]);
  useEffect(() => {
    const t = setInterval(() => {
      loadLocal();
      call<NodeStatus>("node_status").then(setNode).catch(() => {});
    }, 20000);
    return () => clearInterval(t);
  }, [loadLocal]);

  const native = assets.find((a) => a.asset_id === "0") ?? { asset_id: "0", ticker: "ZCRYPT", decimals: 6, balance: 0 };
  const others = assets.filter((a) => a.asset_id !== "0");
  // Whitelisted tickers not held yet: the names the network reserves for its own pegged assets.
  const upcoming = whitelist.filter((t) => !others.some((a) => a.ticker.toUpperCase() === t.toUpperCase()));
  const [whole, frac] = fmtAsset(native.balance, native.decimals).split(".");

  const PULL_ARM = 72;
  function pullStart(e: React.TouchEvent) {
    const scroller = wrap.current?.parentElement;
    pullRef.current = { y0: e.touches[0].clientY, on: !!scroller && scroller.scrollTop <= 0 && !spinning };
  }
  function pullMove(e: React.TouchEvent) {
    if (!pullRef.current.on) return;
    const dy = e.touches[0].clientY - pullRef.current.y0;
    setPull(dy > 0 ? Math.min(dy * 0.55, 110) : 0);
  }
  function pullEnd() {
    if (!pullRef.current.on) return;
    pullRef.current.on = false;
    if (pull >= PULL_ARM) refresh();
    setPull(0);
  }

  async function dismiss(id: number) {
    await call("dismiss_pending_secret", { id }).catch(() => {});
    setOpenSecret(null);
    loadLocal();
  }

  return (
    <div ref={wrap} onTouchStart={pullStart} onTouchMove={pullMove} onTouchEnd={pullEnd} onTouchCancel={pullEnd}>
      <div className={`m-pull ${spinning ? "busy" : ""}`} style={{ height: spinning ? 44 : pull }} aria-hidden={!spinning && pull === 0}>
        <span
          style={{
            display: "inline-flex",
            opacity: spinning ? 1 : Math.min(pull / PULL_ARM, 1),
            transform: spinning ? "none" : `rotate(${Math.min(pull / PULL_ARM, 1) * 360}deg)`,
            animation: spinning ? "m-spin 0.8s linear infinite" : "none",
          }}
        >
          <Icon name="refresh" size={20} />
        </span>
      </div>
      <div className="m-head">
        <h1 className="m-title">Portfolio</h1>
        <button className="m-iconbtn" onClick={() => setSettings(true)} aria-label="Settings">
          <Icon name="gear" size={20} />
        </button>
      </div>

      <div className="m-hero">
        <div className="m-hero-label">ZCRYPT balance</div>
        <div className="m-hero-amount">
          {whole}
          {frac && <span style={{ color: "var(--text-2)" }}>.{frac}</span>}
        </div>
        <div className="m-hero-foot">
          <span className={`m-dot ${node?.connected ? "" : "off"}`} />
          {node === null ? "Connecting…" : node.connected ? `Synced · block ${node.height.toLocaleString()}` : "Node unreachable"}
          <span style={{ marginLeft: "auto" }}>{coins} coin{coins === 1 ? "" : "s"}</span>
        </div>
      </div>

      <div className="m-actions">
        <button className="m-action primary" onClick={onSend}>
          <Icon name="send" size={20} stroke={2.2} /> Send
        </button>
        <button className="m-action" onClick={onReceive}>
          <Icon name="receive" size={20} stroke={2.2} /> Receive
        </button>
      </div>
      <button className="m-action buy" onClick={onBuy}>
        <span className="m-buy-mark">₿</span> Buy ZCRYPT with Bitcoin
      </button>

      {secrets.length > 0 && (
        <div className="m-banner warn" style={{ alignItems: "center" }}>
          <Icon name="file" size={20} />
          <div style={{ flex: 1 }}>
            <b>{secrets.length} payment file{secrets.length === 1 ? "" : "s"} not handed over yet</b>
            <div style={{ fontSize: 13, opacity: 0.85 }}>A bearer coin or stealth note is the money itself. Share it, then dismiss it.</div>
          </div>
          <button className="m-tag" onClick={() => setOpenSecret(secrets[0])}>Open</button>
        </div>
      )}

      <div className="m-section">Assets</div>
      <div className="m-list">
        <div className="m-row">
          <span className="m-avatar native">Z</span>
          <div className="grow">
            <div className="primary">ZCRYPT</div>
            <div className="secondary">Native · pays network fees</div>
          </div>
          <div className="end m-num">
            <div className="primary">{fmtAsset(native.balance, native.decimals)}</div>
          </div>
        </div>
        {others.map((a) => (
          <div className="m-row" key={a.asset_id}>
            <span className="m-avatar soft">{initials(a.ticker)}</span>
            <div className="grow">
              <div className="primary">
                {a.ticker}
                {isWhitelisted(a.ticker, whitelist) && <span className="m-whitelisted">Whitelisted</span>}
              </div>
              <div className="secondary">Shielded asset</div>
            </div>
            <div className="end m-num">
              <div className="primary">{fmtAsset(a.balance, a.decimals)}</div>
            </div>
          </div>
        ))}
        {upcoming.map((t) => (
          <div className="m-row upcoming" key={t}>
            <span className="m-avatar soft">{initials(t)}</span>
            <div className="grow">
              <div className="primary">
                {t}
                <span className="m-whitelisted">Whitelisted</span>
              </div>
              <div className="secondary">{whitelistName(t)} · {t.toUpperCase() === "ZBTC" ? "shield BTC from the desktop wallet" : "coming with its own bridge"}</div>
            </div>
            <div className="end m-num">
              <div className="primary dim">—</div>
            </div>
          </div>
        ))}
      </div>
      <p className="m-hint m-center" style={{ marginTop: 16 }}>
        Balances are private. Nothing on the chain shows what this wallet holds.
      </p>

      <SettingsSheet open={settings} onClose={() => setSettings(false)} />

      <Sheet open={openSecret !== null} onClose={() => setOpenSecret(null)} title={openSecret?.kind === "bearer" ? "Bearer coin to hand over" : "Stealth note to hand over"}>
        {openSecret && (
          <>
            <p className="m-hint" style={{ margin: "0 0 12px" }}>{openSecret.label}. Until it is opened in a wallet, this file is the only copy of that money.</p>
            <div className="m-mono">{short(openSecret.secret, 60, 20)}</div>
            <div className="m-btnrow">
              <Btn kind="secondary" onClick={() => shareFile(openSecret.secret, openSecret.kind === "bearer" ? "zcrypt-bearer.zcrypt" : "zcrypt-stealth-note.zcrypt", saveFile)}>
                <Icon name="share" size={18} /> Share file
              </Btn>
              <Btn kind="secondary" onClick={() => copySensitive(openSecret.secret)}>
                <Icon name="copy" size={18} /> Copy
              </Btn>
            </div>
            <Btn full kind="ghost" style={{ marginTop: 6 }} onClick={() => dismiss(openSecret.id)}>
              Handed over, dismiss
            </Btn>
          </>
        )}
      </Sheet>
    </div>
  );
}
