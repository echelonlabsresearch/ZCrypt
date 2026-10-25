import { useCallback, useEffect, useMemo, useState } from "react";
import { call, copySensitive, fmtAsset, HeldAsset } from "../lib/api";
import { Banner, Btn, Icon, IconName, Sheet } from "./ui";

interface Tx {
  tx_id: string;
  kind: string;
  amount: number;
  counterparty: string;
  timestamp: number;
  at: number;
  status: string;
  asset_id: string;
  decimals: number;
  receipt_id: string;
}
interface Receipt {
  id: string;
  kind: string;
  amount: number;
  asset_id: string;
  timestamp: number;
  text: string;
}
interface Verdict {
  on_chain: boolean;
  names_recipient: boolean;
  summary: string;
}

const LABEL: Record<string, string> = {
  receive: "Received",
  send: "Sent",
  bearer: "Bearer file created",
  mint: "Minted",
  fund: "Funded",
  reward: "Staking reward",
  shield: "Shielded",
  redeem: "Redeemed",
  fee: "Fee",
  swap: "Swap",
  escrow: "Escrow",
};
const ICON: Record<string, IconName> = { receive: "receive", send: "send", bearer: "file", reward: "shield", swap: "refresh" };

const PAGE = 10;

/** "Today 14:02", "Yesterday 09:15", "12 Mar 18:40", or "—" for rows older than the clock. */
function when(at: number): string {
  if (!at) return "—";
  const d = new Date(at * 1000);
  const now = new Date();
  const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  const sameDay = (a: Date, b: Date) => a.toDateString() === b.toDateString();
  const yday = new Date(now);
  yday.setDate(now.getDate() - 1);
  if (sameDay(d, now)) return `Today ${time}`;
  if (sameDay(d, yday)) return `Yesterday ${time}`;
  const day = d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: d.getFullYear() === now.getFullYear() ? undefined : "numeric" });
  return `${day} ${time}`;
}
function whenFull(at: number): string {
  if (!at) return "Before this wallet kept times";
  return new Date(at * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** Every movement, newest first, ten to a page. A row with a receipt opens to show and check it. */
export default function HistoryScreen({ active, refreshTick }: { active: boolean; refreshTick: number }) {
  const [items, setItems] = useState<Tx[]>([]);
  const [page, setPage] = useState(0);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [tickers, setTickers] = useState<Record<string, string>>({});
  const [open, setOpen] = useState<Tx | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [checking, setChecking] = useState(false);
  const [copied, setCopied] = useState(false);

  const load = useCallback(() => {
    // The wallet stores newest first; drop zero-amount rows and keep that order.
    call<Tx[]>("get_history")
      .then((t) => setItems(t.filter((x) => x.amount !== 0).sort((a, b) => b.timestamp - a.timestamp)))
      .catch(() => {});
    call<Receipt[]>("list_receipts").then(setReceipts).catch(() => {});
    call<HeldAsset[]>("held_assets")
      .then((a) => setTickers(Object.fromEntries(a.map((x) => [x.asset_id, x.ticker]))))
      .catch(() => {});
  }, []);
  useEffect(() => {
    if (active) load();
  }, [active, load, refreshTick]);

  const receiptFor = useMemo(() => {
    const byId = new Map(receipts.map((r) => [r.id, r]));
    const out = new Map<string, Receipt>();
    const taken = new Set<string>();
    for (const t of items) {
      const r = t.receipt_id ? byId.get(t.receipt_id) : undefined;
      if (r) {
        out.set(t.tx_id, r);
        taken.add(r.id);
      }
    }
    for (const t of items) {
      if (out.has(t.tx_id) || (t.kind !== "send" && t.kind !== "bearer")) continue;
      const r = receipts.find((x) => !taken.has(x.id) && x.asset_id === t.asset_id && x.amount === Math.abs(t.amount) && x.timestamp >= t.timestamp && x.timestamp <= t.timestamp + 3);
      if (r) {
        out.set(t.tx_id, r);
        taken.add(r.id);
      }
    }
    return out;
  }, [items, receipts]);

  const unit = (id: string) => (id === "0" ? "ZCRYPT" : tickers[id] ?? "");

  async function check(id: string) {
    setChecking(true);
    try {
      setVerdict(await call<Verdict>("check_receipt", { id }));
    } catch (e) {
      setVerdict({ on_chain: false, names_recipient: false, summary: String(e) });
    } finally {
      setChecking(false);
    }
  }

  const r = open ? receiptFor.get(open.tx_id) : undefined;
  const pages = Math.max(1, Math.ceil(items.length / PAGE));
  const cur = Math.min(page, pages - 1);
  const slice = items.slice(cur * PAGE, cur * PAGE + PAGE);

  return (
    <>
      <div className="m-head">
        <h1 className="m-title">History</h1>
      </div>
      {items.length === 0 ? (
        <div className="m-empty">
          <Icon name="history" size={36} />
          <div>No activity yet</div>
        </div>
      ) : (
        <div className="m-list">
          {slice.map((t) => {
            const pos = t.amount >= 0;
            const hasReceipt = receiptFor.has(t.tx_id);
            return (
              <button className="m-row" key={t.tx_id} onClick={() => { setOpen(t); setVerdict(null); setCopied(false); }}>
                <span className={`m-avatar ${pos ? "ok" : "soft"}`}>
                  <Icon name={ICON[t.kind] ?? (pos ? "receive" : "send")} size={18} />
                </span>
                <div className="grow">
                  <div className="primary">{LABEL[t.kind] ?? t.kind}</div>
                  <div className="secondary">{when(t.at)}{hasReceipt ? " · receipt" : ""}</div>
                </div>
                <div className="end m-num">
                  <div className="primary" style={{ color: pos ? "var(--ok)" : "var(--text)" }}>
                    {pos ? "+" : "−"}{fmtAsset(Math.abs(t.amount), t.decimals)}
                  </div>
                  <div className="secondary">{unit(t.asset_id)}</div>
                </div>
              </button>
            );
          })}
        </div>
      )}
      {pages > 1 && (
        <div className="m-pager">
          <button className="m-iconbtn" disabled={cur === 0} onClick={() => setPage(cur - 1)} aria-label="Newer">
            <Icon name="back" size={18} />
          </button>
          <span className="m-num">{cur * PAGE + 1}–{Math.min(items.length, cur * PAGE + PAGE)} of {items.length}</span>
          <button className="m-iconbtn" disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)} aria-label="Older">
            <Icon name="chevron" size={18} />
          </button>
        </div>
      )}
      <p className="m-hint m-center" style={{ marginTop: 16 }}>Finality is sub-second. Amounts are hidden on the chain; this list is kept on your phone.</p>

      <Sheet open={open !== null} onClose={() => setOpen(null)} title={open ? LABEL[open.kind] ?? open.kind : ""}>
        {open && (
          <>
            <div className="m-kv"><span>Amount</span><span className="m-num">{open.amount >= 0 ? "+" : "−"}{fmtAsset(Math.abs(open.amount), open.decimals)} {unit(open.asset_id)}</span></div>
            <div className="m-kv"><span>When</span><span className="m-num">{whenFull(open.at)}</span></div>
            <div className="m-kv"><span>Detail</span><span style={{ textAlign: "right", maxWidth: "60%", wordBreak: "break-word" }}>{open.counterparty || "—"}</span></div>
            <div className="m-kv"><span>Status</span><span style={{ color: "var(--ok)" }}>{open.status}</span></div>
            {r && (
              <>
                <div className="m-section" style={{ marginLeft: 0 }}>Payment receipt</div>
                <div className="m-mono">{r.text}</div>
                <div className="m-btnrow">
                  <Btn kind="secondary" small onClick={() => { copySensitive(r.text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
                    <Icon name={copied ? "check" : "copy"} size={16} /> {copied ? "Copied" : "Copy"}
                  </Btn>
                  <Btn kind="secondary" small disabled={checking} onClick={() => check(r.id)}>
                    {checking ? "Checking…" : "Check on chain"}
                  </Btn>
                </div>
                {verdict && <Banner tone={verdict.on_chain && verdict.names_recipient ? "ok" : verdict.on_chain ? "warn" : "bad"}>{verdict.summary}</Banner>}
                <p className="m-hint">The receipt proves the payment was made without revealing your other coins. The spend secret is not in it.</p>
              </>
            )}
          </>
        )}
      </Sheet>
    </>
  );
}
