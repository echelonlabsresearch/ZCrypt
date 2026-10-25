import { useCallback, useEffect, useMemo, useState } from "react";
import { call, copySensitive, fmtAsset, HeldAsset } from "../lib/api";
import { Banner, Btn, Icon, IconName, Sheet } from "./ui";

interface Tx {
  tx_id: string;
  kind: string;
  amount: number;
  counterparty: string;
  timestamp: number;
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

/** Every movement, newest first. A row with a receipt opens to show and check it. */
export default function HistoryScreen({ active, refreshTick }: { active: boolean; refreshTick: number }) {
  const [items, setItems] = useState<Tx[]>([]);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [tickers, setTickers] = useState<Record<string, string>>({});
  const [open, setOpen] = useState<Tx | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [checking, setChecking] = useState(false);
  const [copied, setCopied] = useState(false);

  const load = useCallback(() => {
    call<Tx[]>("get_history").then((t) => setItems([...t].reverse())).catch(() => {});
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
          {items.map((t) => {
            const pos = t.amount >= 0;
            const hasReceipt = receiptFor.has(t.tx_id);
            return (
              <button className="m-row" key={t.tx_id} onClick={() => { setOpen(t); setVerdict(null); setCopied(false); }}>
                <span className={`m-avatar ${pos ? "ok" : "soft"}`}>
                  <Icon name={ICON[t.kind] ?? (pos ? "receive" : "send")} size={18} />
                </span>
                <div className="grow">
                  <div className="primary">{LABEL[t.kind] ?? t.kind}</div>
                  <div className="secondary">{t.counterparty || "—"} · block {t.timestamp.toLocaleString()}</div>
                </div>
                <div className="end m-num">
                  <div className="primary" style={{ color: pos ? "var(--ok)" : "var(--text)" }}>
                    {pos ? "+" : "−"}{fmtAsset(Math.abs(t.amount), t.decimals)}
                  </div>
                  <div className="secondary">{unit(t.asset_id)}{hasReceipt ? " · receipt" : ""}</div>
                </div>
              </button>
            );
          })}
        </div>
      )}
      <p className="m-hint m-center" style={{ marginTop: 16 }}>Finality is sub-second. Amounts are hidden on the chain; this list is kept on your phone.</p>

      <Sheet open={open !== null} onClose={() => setOpen(null)} title={open ? LABEL[open.kind] ?? open.kind : ""}>
        {open && (
          <>
            <div className="m-kv"><span>Amount</span><span className="m-num">{open.amount >= 0 ? "+" : "−"}{fmtAsset(Math.abs(open.amount), open.decimals)} {unit(open.asset_id)}</span></div>
            <div className="m-kv"><span>Detail</span><span>{open.counterparty || "—"}</span></div>
            <div className="m-kv"><span>Block</span><span className="m-num">{open.timestamp.toLocaleString()}</span></div>
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
