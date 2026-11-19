import { useCallback, useEffect, useRef, useState } from "react";
import { call, copySensitive, fmtAsset, HeldAsset, isWhitelisted, unbackedNote, whitelistName } from "../lib/api";
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
export default function Home({ refreshTick, onSend, onReceive }: { refreshTick: number; onSend: () => void; onReceive: () => void }) {
  const [assets, setAssets] = useState<HeldAsset[]>([]);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [coins, setCoins] = useState(0);
  // The block this wallet has read up to. "Synced" is said about this, not the node's tip.
  const [cursor, setCursor] = useState(0);
  // While a scan is reading the chain: the block it has reached.
  const [readingAt, setReadingAt] = useState(0);
  const scanning = useRef(false);
  const [node, setNode] = useState<NodeStatus | null>(null);
  const [secrets, setSecrets] = useState<PendingSecret[]>([]);
  const [spinning, setSpinning] = useState(false);
  // The last scan did not reach the tip: the balance below may be out of date.
  const [syncErr, setSyncErr] = useState("");
  const [settings, setSettings] = useState(false);
  const [openSecret, setOpenSecret] = useState<PendingSecret | null>(null);
  // Pull to refresh: how far the finger has dragged down from the top of the screen.
  const [pull, setPull] = useState(0);
  const pullRef = useRef<{ y0: number; on: boolean }>({ y0: 0, on: false });
  const wrap = useRef<HTMLDivElement>(null);

  const loadLocal = useCallback(async () => {
    const [a, b, s] = await Promise.all([
      call<HeldAsset[]>("held_assets").catch(() => [] as HeldAsset[]),
      call<{ coin_count: number; scan_height?: number }>("get_balance").catch(() => ({ coin_count: 0, scan_height: undefined })),
      call<PendingSecret[]>("list_pending_secrets").catch(() => [] as PendingSecret[]),
    ]);
    setAssets(a);
    setCoins(b.coin_count);
    if (b.scan_height !== undefined) setCursor(b.scan_height);
    setSecrets(s);
  }, []);

  useEffect(() => {
    call<string[]>("whitelisted_assets").then(setWhitelist).catch(() => {});
  }, []);

  // One scan at a time from this screen. A second request while one is reading the chain
  // is dropped: the running scan decides when the screen may say "synced".
  const scan = useCallback(
    (quiet: boolean) => {
      if (scanning.current) return;
      scanning.current = true;
      if (!quiet) setSpinning(true);
      // A scan that stops early keeps what it found and says so; hiding that would show
      // an out-of-date balance as if it were current.
      call("scan_onchain")
        .then(() => {
          setSyncErr("");
          return loadLocal();
        })
        .catch((e) => {
          setSyncErr(String(e instanceof Error ? e.message : e));
          return loadLocal();
        })
        .finally(() => {
          scanning.current = false;
          setSpinning(false);
        });
    },
    [loadLocal]
  );

  const refresh = useCallback(async () => {
    setSpinning(true);
    await loadLocal();
    call<NodeStatus>("node_status").then(setNode).catch(() => setNode({ connected: false, height: 0, error: "" }));
    scan(false);
  }, [loadLocal, scan]);

  useEffect(() => {
    refresh();
  }, [refresh, refreshTick]);
  useEffect(() => {
    // Keep reading the chain while the app is open, so a payment shows up without a pull.
    const t = setInterval(() => {
      if (document.visibilityState !== "visible") return;
      loadLocal();
      call<NodeStatus>("node_status").then(setNode).catch(() => {});
      scan(true);
    }, 20000);
    return () => clearInterval(t);
  }, [loadLocal, scan]);

  // While a scan runs, follow how far it has read.
  useEffect(() => {
    if (!spinning) {
      setReadingAt(0);
      return;
    }
    const t = setInterval(() => {
      call<{ scanning_at?: number }>("get_balance").then((b) => setReadingAt(b.scanning_at ?? 0)).catch(() => {});
    }, 1500);
    return () => clearInterval(t);
  }, [spinning]);

  const native = assets.find((a) => a.asset_id === "0") ?? { asset_id: "0", ticker: "ZCRYPT", decimals: 6, balance: 0 };
  const others = assets.filter((a) => a.asset_id !== "0");
  // Whitelisted tickers not held yet: the names the network reserves for its own pegged assets.
  const upcoming = whitelist.filter((t) => !others.some((a) => a.ticker.toUpperCase() === t.toUpperCase()));
  const [whole, frac] = fmtAsset(native.balance, native.decimals).split(".");

  const behind = !!node?.connected && syncErr !== "" && !/locked/i.test(syncErr);

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
          <span className={`m-dot ${!node?.connected ? "off" : behind ? "warn" : ""}`} />
          {node === null ? "Connecting…" : !node.connected ? "Offline · last synced balance" : behind ? "Sync incomplete · balance may be out of date" : spinning ? (Math.max(readingAt, cursor) > 0 && node.height > 0 ? `Syncing · block ${Math.min(Math.max(readingAt, cursor), node.height).toLocaleString()} of ${node.height.toLocaleString()}` : "Syncing…") : cursor > 0 && node.height > 0 ? `Synced · block ${Math.min(cursor, node.height).toLocaleString()} of ${node.height.toLocaleString()}` : `Synced · block ${node.height.toLocaleString()}`}
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

      {behind && (
        <div className="m-banner warn" style={{ alignItems: "center" }}>
          <Icon name="warn" size={20} />
          <div style={{ flex: 1 }}>
            <b>Sync incomplete</b>
            <div style={{ fontSize: 13, opacity: 0.85 }}>The wallet could not read the chain to the end, so this balance may be out of date. Nothing is lost.</div>
          </div>
          <button className="m-tag" disabled={spinning} onClick={refresh}>{spinning ? "Syncing…" : "Retry"}</button>
        </div>
      )}

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
            {!!native.unbacked && <div className="m-unbacked">{unbackedNote(native, true)}</div>}
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
              {!!a.unbacked && <div className="m-unbacked">{unbackedNote(a, native.balance >= 10_000)}</div>}
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
