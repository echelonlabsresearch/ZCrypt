import { useCallback, useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { call, copy, fmt } from "../lib/api";

/** The desk's posted terms (see impl/bridge/src/sale.rs `Quote`). */
interface Quote {
  price_sats: number;
  min_sats: number;
  max_sats: number;
  stock_atomic: number;
  min_conf: number;
  network: string;
  ttl_secs: number;
}

interface Order {
  id: string;
  btc_address: string;
  sats: number;
  price_sats: number;
  created: number;
  expires: number;
  status: "waiting" | "seen" | "paid" | "expired";
  paid_sats: number;
  confirmations: number;
  min_conf: number;
  zcrypt_atomic: number;
  zc_txhash: string;
}

interface SavedOrder {
  id: string;
  sale_url: string;
  created: number;
}

const SATS = 100_000_000;
const ATOMIC = 1_000_000;

const btc = (sats: number) => (sats / SATS).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
/** ZCRYPT (atomic) that `sats` buys at `price` sats per ZCRYPT, as the desk computes it. */
const zcryptFor = (sats: number, price: number) => (price > 0 ? Math.floor((sats * ATOMIC) / price) : 0);

function networkLabel(n: string): string {
  return n === "bitcoin" ? "Bitcoin" : n === "signet" ? "Bitcoin signet (test coins)" : n === "regtest" ? "Bitcoin regtest" : `Bitcoin ${n}`;
}

function statusLine(o: Order): { text: string; tone: "wait" | "ok" | "bad" } {
  switch (o.status) {
    case "waiting":
      return { text: "Waiting for your Bitcoin payment", tone: "wait" };
    case "seen":
      return {
        text:
          o.min_conf === 0
            ? "Payment seen, sending your ZCRYPT"
            : `Payment seen (${o.confirmations}/${o.min_conf} confirmation${o.min_conf === 1 ? "" : "s"})`,
        tone: "wait",
      };
    case "paid":
      return { text: `Done: ${fmt(o.zcrypt_atomic)} ZCRYPT sent to this wallet`, tone: "ok" };
    case "expired":
      return { text: "Expired without payment. A payment that still arrives is honoured.", tone: "bad" };
  }
}

/**
 * Buy: "send Bitcoin, get ZCRYPT". The foundation's sale desk posts a price; the wallet
 * opens an order against its own address, shows the Bitcoin address to pay, and polls until
 * the desk has sent the coins. The ZCRYPT lands like any other incoming transfer.
 */
export default function Buy({ active, onBought }: { active: boolean; onBought: (atomic: number) => void }) {
  const [quote, setQuote] = useState<Quote | null>(null);
  const [qErr, setQErr] = useState("");
  const [amount, setAmount] = useState("0.001");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [order, setOrder] = useState<Order | null>(null);
  const [qr, setQr] = useState("");
  const [saved, setSaved] = useState<SavedOrder[]>([]);
  const [copied, setCopied] = useState(false);
  // The parent passes a fresh callback on every render; keep the latest in a ref so the
  // polling interval below is not torn down and restarted before it ever fires.
  const onBoughtRef = useRef(onBought);
  onBoughtRef.current = onBought;
  const announced = useRef<Set<string>>(new Set());

  const loadQuote = useCallback(() => {
    setQErr("");
    call<Quote>("buy_quote")
      .then(setQuote)
      .catch((e) => {
        setQuote(null);
        setQErr(String(e?.message ?? e));
      });
  }, []);
  const loadSaved = useCallback(() => {
    call<SavedOrder[]>("buy_orders").then(setSaved).catch(() => {});
  }, []);

  useEffect(() => {
    if (!active) return;
    loadQuote();
    loadSaved();
    const t = setInterval(loadQuote, 60_000);
    return () => clearInterval(t);
  }, [active, loadQuote, loadSaved]);

  // Resume the newest unfinished order on open.
  useEffect(() => {
    if (!active || order || saved.length === 0) return;
    call<Order>("buy_status", { id: saved[0].id })
      .then((o) => {
        if (o.status !== "paid") setOrder(o);
      })
      .catch(() => {});
  }, [active, order, saved]);

  // Poll the open order every 15 s until it is paid. Keyed on the order id only, so a
  // status update does not restart the timer.
  const orderId = order?.id;
  const orderDone = order?.status === "paid";
  useEffect(() => {
    if (!active || !orderId || orderDone) return;
    const tick = () =>
      call<Order>("buy_status", { id: orderId })
        .then((o) => {
          setOrder(o);
          if (o.status === "paid" && !announced.current.has(o.id)) {
            announced.current.add(o.id);
            onBoughtRef.current(o.zcrypt_atomic);
          }
        })
        .catch(() => {});
    const t = setInterval(tick, 15_000);
    return () => clearInterval(t);
  }, [active, orderId, orderDone]);

  useEffect(() => {
    if (!order) return setQr("");
    const text = `bitcoin:${order.btc_address}?amount=${btc(order.sats)}`;
    QRCode.toDataURL(text, { margin: 4, scale: 5, errorCorrectionLevel: "M", color: { dark: "#000000", light: "#ffffff" } })
      .then(setQr)
      .catch(() => setQr(""));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [order?.id]);

  const sats = Math.round((parseFloat(amount) || 0) * SATS);
  const willGet = quote ? zcryptFor(sats, quote.price_sats) : 0;
  const closed = !!quote && quote.price_sats === 0;
  const soldOut = !!quote && !closed && quote.stock_atomic < ATOMIC;

  async function start() {
    if (!quote) return;
    setErr("");
    if (sats < quote.min_sats) return setErr(`Minimum is ${btc(quote.min_sats)} BTC.`);
    if (sats > quote.max_sats) return setErr(`Maximum is ${btc(quote.max_sats)} BTC.`);
    if (willGet > quote.stock_atomic) return setErr(`Only ${fmt(quote.stock_atomic)} ZCRYPT available right now.`);
    setBusy(true);
    try {
      const o = await call<Order>("buy_order", { sats });
      setOrder(o);
      loadSaved();
    } catch (e) {
      setErr(String((e as Error)?.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  async function doCopy() {
    if (!order) return;
    await copy(order.btc_address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  async function dismiss() {
    if (!order) return;
    await call("buy_forget", { id: order.id }).catch(() => {});
    setOrder(null);
    loadSaved();
  }

  const st = order ? statusLine(order) : null;

  return (
    <div>
      <div className="card hero">
        <h2>Buy ZCRYPT with Bitcoin</h2>
        {!quote && !qErr && <p className="dim">Fetching today's price…</p>}
        {qErr && <div className="msg err">The sale desk is unreachable: {qErr}</div>}
        {quote && closed && <div className="msg err">The sale desk is closed right now. Check back later.</div>}
        {quote && !closed && (
          <div className="buy-terms">
            <div className="buy-term">
              <span className="buy-term-label">Price</span>
              <span className="buy-term-value">1 ZCRYPT = {quote.price_sats.toLocaleString()} sats</span>
              <span className="buy-term-sub">{btc(quote.price_sats)} BTC</span>
            </div>
            <div className="buy-term">
              <span className="buy-term-label">Available now</span>
              <span className="buy-term-value">{fmt(quote.stock_atomic)} ZCRYPT</span>
              <span className="buy-term-sub">{soldOut ? "sold out, refills from rewards" : "paid from the foundation desk"}</span>
            </div>
            <div className="buy-term">
              <span className="buy-term-label">Pay on</span>
              <span className="buy-term-value">{networkLabel(quote.network)}</span>
              <span className="buy-term-sub">
                {quote.min_conf === 0 ? "credited on first sight" : `${quote.min_conf} confirmation${quote.min_conf === 1 ? "" : "s"}, about ${10 * quote.min_conf} min`}
              </span>
            </div>
          </div>
        )}
      </div>

      {!order && quote && !closed && (
        <div className="card">
          <div className="field">
            <label>You pay (BTC)</label>
            <input value={amount} onChange={(e) => setAmount(e.target.value)} inputMode="decimal" placeholder="0.001" />
            <div className="buy-hint">
              Between {btc(quote.min_sats)} and {btc(quote.max_sats)} BTC
            </div>
          </div>
          <div className="buy-receive">
            You get <b>{fmt(willGet)} ZCRYPT</b>
          </div>
          {err && <div className="msg err">{err}</div>}
          <button className="btn-primary btn-block" disabled={busy || soldOut || sats <= 0} onClick={start}>
            {busy ? "Opening order…" : soldOut ? "Sold out" : "Buy"}
          </button>
          <p className="dim" style={{ marginTop: "0.8rem", fontSize: "0.8rem" }}>
            You will get a Bitcoin address to pay from any Bitcoin wallet. The ZCRYPT is sent to this wallet's
            recoverable address once the payment confirms. No account, no email.
          </p>
        </div>
      )}

      {order && st && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Order {order.id.slice(0, 8)}</h3>
          <div className={`buy-status ${st.tone}`}>{st.text}</div>
          {order.status !== "paid" && (
            <div className="buy-pay">
              {qr && (
                <div className="qr-tile">
                  <img src={qr} alt="Bitcoin payment QR" />
                </div>
              )}
              <div className="buy-pay-text">
                <div className="buy-pay-amount">
                  Send <b>{btc(order.sats)} BTC</b>
                </div>
                <div className="buy-hint">
                  to this {networkLabel(quote?.network ?? "bitcoin")} address. Any amount you send is converted at{" "}
                  {order.price_sats.toLocaleString()} sats per ZCRYPT.
                </div>
                <code className="buy-addr">{order.btc_address}</code>
                <div className="addr-actions">
                  <button className="btn-secondary" onClick={doCopy}>
                    {copied ? "Copied" : "Copy address"}
                  </button>
                  <button className="btn-link" onClick={dismiss}>
                    Cancel order
                  </button>
                </div>
                {order.paid_sats > 0 && (
                  <div className="buy-hint">
                    Received {btc(order.paid_sats)} BTC, you get {fmt(zcryptFor(order.paid_sats, order.price_sats))} ZCRYPT.
                  </div>
                )}
                <div className="buy-hint">Open until {new Date(order.expires * 1000).toLocaleString()}</div>
              </div>
            </div>
          )}
          {order.status === "paid" && (
            <div className="addr-actions">
              <button className="btn-primary" onClick={dismiss}>
                Buy more
              </button>
            </div>
          )}
        </div>
      )}

      {saved.length > 1 && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Earlier orders</h3>
          {saved.slice(1).map((s) => (
            <div key={s.id} className="buy-earlier">
              <code>{s.id.slice(0, 8)}</code>
              <span className="dim">{new Date(s.created * 1000).toLocaleString()}</span>
              <button
                className="btn-link"
                onClick={() =>
                  call<Order>("buy_status", { id: s.id })
                    .then(setOrder)
                    .catch((e) => setErr(String(e?.message ?? e)))
                }
              >
                Open
              </button>
              <button className="btn-link" onClick={() => call("buy_forget", { id: s.id }).then(loadSaved).catch(() => {})}>
                Remove
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
