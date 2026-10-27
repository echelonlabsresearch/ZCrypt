import { useCallback, useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { call, copy, fmt } from "../lib/api";
import { Banner, Btn, dismissKeyboard, Field, Icon, Spinner } from "./ui";
import { useAuth } from "./MobileApp";

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
const zcryptFor = (sats: number, price: number) => (price > 0 ? Math.floor((sats * ATOMIC) / price) : 0);

/**
 * Buy: "send Bitcoin, get ZCRYPT". Shows the desk's price, opens an order for the amount
 * typed, and shows the Bitcoin address (and QR) to pay from any Bitcoin wallet. Polls until
 * the desk has sent the coins; they arrive in the portfolio like any transfer.
 */
export default function BuyScreen({ active, onBack, onBought }: { active: boolean; onBack: () => void; onBought: () => void }) {
  const { toast } = useAuth();
  const [quote, setQuote] = useState<Quote | null>(null);
  const [qErr, setQErr] = useState("");
  const [amount, setAmount] = useState("0.001");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [order, setOrder] = useState<Order | null>(null);
  const [qr, setQr] = useState("");
  const [copied, setCopied] = useState(false);
  // Latest callbacks in refs so the polling interval is not restarted on every render.
  const onBoughtRef = useRef(onBought);
  onBoughtRef.current = onBought;
  const toastRef = useRef(toast);
  toastRef.current = toast;

  const loadQuote = useCallback(() => {
    setQErr("");
    call<Quote>("buy_quote")
      .then(setQuote)
      .catch((e) => {
        setQuote(null);
        setQErr(String(e?.message ?? e));
      });
  }, []);

  useEffect(() => {
    if (!active) return;
    loadQuote();
    // Resume the newest unfinished order.
    call<SavedOrder[]>("buy_orders")
      .then((list) => (list[0] ? call<Order>("buy_status", { id: list[0].id }) : Promise.reject()))
      .then((o) => {
        if (o.status !== "paid") setOrder(o);
      })
      .catch(() => {});
    const t = setInterval(loadQuote, 60_000);
    return () => clearInterval(t);
  }, [active, loadQuote]);

  const orderId = order?.id;
  const orderDone = order?.status === "paid";
  useEffect(() => {
    if (!active || !orderId || orderDone) return;
    const tick = () =>
      call<Order>("buy_status", { id: orderId })
        .then((o) => {
          setOrder((prev) => {
            if (o.status === "paid" && prev?.status !== "paid") {
              toastRef.current("ZCRYPT bought", `+${fmt(o.zcrypt_atomic)} ZCRYPT arrived`);
              onBoughtRef.current();
            }
            return o;
          });
        })
        .catch(() => {});
    const t = setInterval(tick, 15_000);
    return () => clearInterval(t);
  }, [active, orderId, orderDone]);

  useEffect(() => {
    if (!order) return setQr("");
    const text = `bitcoin:${order.btc_address}?amount=${btc(order.sats)}`;
    const n = QRCode.create(text, { errorCorrectionLevel: "M" }).modules.size + 8;
    const scale = Math.max(2, Math.floor((window.innerWidth - 48) / n));
    QRCode.toDataURL(text, { margin: 4, scale, errorCorrectionLevel: "M", color: { dark: "#000000", light: "#ffffff" } })
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
    dismissKeyboard();
    setErr("");
    if (sats < quote.min_sats) return setErr(`Minimum is ${btc(quote.min_sats)} BTC.`);
    if (sats > quote.max_sats) return setErr(`Maximum is ${btc(quote.max_sats)} BTC.`);
    if (willGet > quote.stock_atomic) return setErr(`Only ${fmt(quote.stock_atomic)} ZCRYPT available right now.`);
    setBusy(true);
    try {
      setOrder(await call<Order>("buy_order", { sats }));
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
  }

  const status = order
    ? order.status === "waiting"
      ? { tone: "info" as const, text: "Waiting for your Bitcoin payment" }
      : order.status === "seen"
        ? { tone: "info" as const, text: order.min_conf === 0 ? "Payment seen, sending your ZCRYPT" : `Payment seen, ${order.confirmations}/${order.min_conf} confirmations` }
        : order.status === "paid"
          ? { tone: "ok" as const, text: `${fmt(order.zcrypt_atomic)} ZCRYPT sent to this wallet` }
          : { tone: "warn" as const, text: "Expired without payment. A late payment is still honoured." }
    : null;

  return (
    <div>
      <div className="m-head">
        <button className="m-iconbtn" onClick={onBack} aria-label="Back">
          <Icon name="back" size={18} />
        </button>
        <h1 className="m-title small">Buy ZCRYPT</h1>
        <span style={{ width: 40 }} />
      </div>

      {!quote && !qErr && (
        <div className="m-card" style={{ textAlign: "center" }}>
          <Spinner />
        </div>
      )}
      {qErr && <Banner tone="bad">The sale desk is unreachable: {qErr}</Banner>}
      {quote && closed && <Banner tone="warn">The sale desk is closed right now. Check back later.</Banner>}

      {quote && !closed && (
        <div className="m-card">
          <div className="m-kv">
            <span>Price</span>
            <span className="m-num">1 ZCRYPT = {quote.price_sats.toLocaleString()} sats</span>
          </div>
          <div className="m-kv">
            <span>Available</span>
            <span className="m-num">{fmt(quote.stock_atomic)} ZCRYPT</span>
          </div>
          <div className="m-kv">
            <span>Pay on</span>
            <span>{quote.network === "bitcoin" ? "Bitcoin" : `Bitcoin ${quote.network}`}</span>
          </div>
        </div>
      )}

      {!order && quote && !closed && (
        <>
          <Field label="You pay" hint={`Between ${btc(quote.min_sats)} and ${btc(quote.max_sats)} BTC`}>
            <div className="m-input-wrap" style={{ paddingLeft: 16 }}>
              <input className="m-input big" value={amount} onChange={(e) => setAmount(e.target.value)} placeholder="0.001" inputMode="decimal" autoCorrect="off" />
              <span style={{ color: "var(--text-2)", fontWeight: 600 }}>BTC</span>
            </div>
          </Field>
          <div className="m-card">
            <div className="m-kv">
              <span>You get</span>
              <span className="m-num">{fmt(willGet)} ZCRYPT</span>
            </div>
          </div>
          {err && <Banner tone="bad">{err}</Banner>}
          <Btn full disabled={busy || soldOut || sats <= 0} onClick={start} style={{ marginTop: 14 }}>
            {busy ? "Opening order…" : soldOut ? "Sold out" : "Buy"}
          </Btn>
          <p className="m-hint" style={{ marginTop: 10 }}>
            You get a Bitcoin address to pay from any Bitcoin wallet. The ZCRYPT is sent here once the payment confirms
            {quote.min_conf > 0 ? ` (about ${10 * quote.min_conf} minutes)` : ""}. No account, no email.
          </p>
        </>
      )}

      {order && status && (
        <>
          <Banner tone={status.tone}>{status.text}</Banner>
          {order.status !== "paid" && (
            <>
              {qr && (
                <div className="m-qr">
                  <img src={qr} alt="Bitcoin payment QR" />
                </div>
              )}
              <div className="m-card">
                <div className="m-kv">
                  <span>Send</span>
                  <span className="m-num">{btc(order.sats)} BTC</span>
                </div>
                <div className="m-kv">
                  <span>Rate</span>
                  <span className="m-num">{order.price_sats.toLocaleString()} sats / ZCRYPT</span>
                </div>
                {order.paid_sats > 0 && (
                  <div className="m-kv">
                    <span>Received</span>
                    <span className="m-num">{btc(order.paid_sats)} BTC</span>
                  </div>
                )}
              </div>
              <div className="m-mono" style={{ marginTop: 12, wordBreak: "break-all", fontSize: 13 }}>
                {order.btc_address}
              </div>
              <Btn full kind="secondary" onClick={doCopy} style={{ marginTop: 12 }}>
                <Icon name={copied ? "check" : "copy"} size={18} /> {copied ? "Copied" : "Copy address"}
              </Btn>
              <Btn full kind="ghost" onClick={dismiss} style={{ marginTop: 8 }}>
                Cancel order
              </Btn>
            </>
          )}
          {order.status === "paid" && (
            <Btn full onClick={dismiss} style={{ marginTop: 12 }}>
              Buy more
            </Btn>
          )}
        </>
      )}
    </div>
  );
}
