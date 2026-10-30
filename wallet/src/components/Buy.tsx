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
  /** Dollars per bitcoin as the desk last saw it; 0 = unknown. Display only. */
  btc_usd: number;
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

interface BtcWallet {
  connected: boolean;
  balance: number; // BTC
  deposit_address: string;
}

interface BtcQuote {
  amount_sats: number;
  fee_sats: number;
  fee_rate_sat_vb: number;
  inputs: number;
}

/// Payments this wallet made for its own orders (order id -> txid), so a reopened order
/// shows "paid from this wallet" instead of the address to pay.
const PAID_KEY = "buy.paidFromWallet";
function loadPaid(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem(PAID_KEY) || "{}");
  } catch {
    return {};
  }
}
function rememberPaid(id: string, txid: string) {
  try {
    localStorage.setItem(PAID_KEY, JSON.stringify({ ...loadPaid(), [id]: txid }));
  } catch {
    /* best effort */
  }
}

const SATS = 100_000_000;
const ATOMIC = 1_000_000;

const btc = (sats: number) => (sats / SATS).toFixed(8).replace(/0+$/, "").replace(/\.$/, "");
/** "$0.50" for `sats` at `btcUsd` dollars per bitcoin; empty when the desk gave no rate. */
function usd(sats: number, btcUsd: number): string {
  if (!(btcUsd > 0)) return "";
  const v = (sats / SATS) * btcUsd;
  return v >= 100 ? `$${Math.round(v).toLocaleString()}` : `$${v.toFixed(2)}`;
}
/** ZCRYPT (atomic) that `sats` buys at `price` sats per ZCRYPT, as the desk computes it. */
const zcryptFor = (sats: number, price: number) => (price > 0 ? Math.floor((sats * ATOMIC) / price) : 0);
/** Sats needed so that the desk's floor rounding still yields `atomic` ZCRYPT (the inverse of `zcryptFor`). */
const satsFor = (atomic: number, price: number) => (price > 0 ? Math.ceil((atomic * price) / ATOMIC) : 0);

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
  // The ZCRYPT field as the user typed it; cleared when the BTC field is edited so the two
  // inputs never fight (the BTC amount is the one the order is placed with).
  const [want, setWant] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [order, setOrder] = useState<Order | null>(null);
  const [qr, setQr] = useState("");
  const [saved, setSaved] = useState<SavedOrder[]>([]);
  const [copied, setCopied] = useState(false);
  // This wallet's own Bitcoin: when it holds some, the order is paid from it directly.
  const [btcw, setBtcw] = useState<BtcWallet | null>(null);
  const [payFrom, setPayFrom] = useState<"wallet" | "external">("wallet");
  const [paying, setPaying] = useState(false);
  const [payErr, setPayErr] = useState("");
  const [paid, setPaid] = useState<Record<string, string>>(loadPaid);
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
  const loadBtc = useCallback(() => {
    call<BtcWallet>("btc_wallet_info").then(setBtcw).catch(() => setBtcw(null));
  }, []);

  useEffect(() => {
    if (!active) return;
    loadQuote();
    loadSaved();
    loadBtc();
    const t = setInterval(loadQuote, 60_000);
    return () => clearInterval(t);
  }, [active, loadQuote, loadSaved, loadBtc]);

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
  const walletSats = btcw?.connected ? Math.round(btcw.balance * SATS) : 0;
  const canPayFromWallet = walletSats > 0;
  const fromWallet = canPayFromWallet && payFrom === "wallet";

  /** Pay an open order out of this wallet's own Bitcoin (self-custody send to the desk). */
  async function payFromWallet(o: Order) {
    setPayErr("");
    setPaying(true);
    try {
      const amt = btc(o.sats);
      const q = await call<BtcQuote>("estimate_btc_send", { address: o.btc_address, btc: amt, speed: "normal" });
      if (q.amount_sats + q.fee_sats > walletSats) {
        throw new Error(
          `This wallet holds ${btc(walletSats)} BTC; paying ${amt} BTC plus the ${q.fee_sats.toLocaleString()} sat network fee needs ${btc(q.amount_sats + q.fee_sats)}. Pay from another wallet using the address below, or cancel and lower the amount.`,
        );
      }
      const txid = await call<string>("withdraw_btc", { address: o.btc_address, btc: amt, speed: "normal" });
      rememberPaid(o.id, txid);
      setPaid(loadPaid());
      loadBtc();
    } catch (e) {
      setPayErr(String((e as Error)?.message ?? e));
    } finally {
      setPaying(false);
    }
  }

  /** Put everything this wallet can send (after the fee) into the BTC field. */
  async function useAll() {
    setErr("");
    try {
      const q = await call<BtcQuote>("btc_max_send", { speed: "normal" });
      const cap = quote ? Math.min(q.amount_sats, quote.max_sats) : q.amount_sats;
      setAmount(btc(cap));
      setWant("");
    } catch (e) {
      setErr(String((e as Error)?.message ?? e));
    }
  }

  async function start() {
    if (!quote) return;
    setErr("");
    setPayErr("");
    if (sats < quote.min_sats) return setErr(`Minimum is ${btc(quote.min_sats)} BTC.`);
    if (sats > quote.max_sats) return setErr(`Maximum is ${btc(quote.max_sats)} BTC.`);
    if (willGet > quote.stock_atomic) return setErr(`Only ${fmt(quote.stock_atomic)} ZCRYPT available right now.`);
    setBusy(true);
    let o: Order;
    try {
      o = await call<Order>("buy_order", { sats });
      setOrder(o);
      loadSaved();
    } catch (e) {
      setErr(String((e as Error)?.message ?? e));
      setBusy(false);
      return;
    }
    setBusy(false);
    if (fromWallet) await payFromWallet(o);
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
              <span className="buy-term-value">
                1 ZCRYPT = {quote.price_sats.toLocaleString()} sats{usd(quote.price_sats, quote.btc_usd) && <> (≈ {usd(quote.price_sats, quote.btc_usd)})</>}
              </span>
              <span className="buy-term-sub">
                {btc(quote.price_sats)} BTC{quote.btc_usd > 0 && <>, bitcoin at ${Math.round(quote.btc_usd).toLocaleString()}</>}
              </span>
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
            <input
              value={amount}
              onChange={(e) => {
                setAmount(e.target.value);
                setWant("");
              }}
              inputMode="decimal"
              placeholder="0.001"
            />
            <div className="buy-hint">
              Between {btc(quote.min_sats)} and {btc(quote.max_sats)} BTC{usd(sats, quote.btc_usd) && <>. About {usd(sats, quote.btc_usd)} at today's rate</>}
            </div>
          </div>
          <div className="field">
            <label>You get (ZCRYPT)</label>
            <input
              value={want !== "" ? want : willGet > 0 ? String(willGet / ATOMIC) : ""}
              onChange={(e) => {
                const v = e.target.value;
                setWant(v);
                const atomic = Math.round((parseFloat(v.replace(/,/g, "")) || 0) * ATOMIC);
                setAmount(atomic > 0 ? btc(satsFor(atomic, quote.price_sats)) : "0");
              }}
              inputMode="decimal"
              placeholder="10000"
            />
            <div className="buy-hint">Type the ZCRYPT you want and the BTC to send is worked out at today's price.</div>
          </div>
          {btcw?.connected && (
            <div className="buy-hint" style={{ marginBottom: "0.6rem" }}>
              Bitcoin in this wallet: <b>{btc(walletSats)} BTC</b>
              {canPayFromWallet && (
                <>
                  {" "}
                  <button className="btn-link" onClick={useAll}>
                    Use all
                  </button>
                  {" · "}
                  <button className="btn-link" onClick={() => setPayFrom(payFrom === "wallet" ? "external" : "wallet")}>
                    {payFrom === "wallet" ? "Pay from another wallet instead" : "Pay from this wallet"}
                  </button>
                </>
              )}
            </div>
          )}
          <div className="buy-receive">
            {fromWallet ? "Pay" : "Send"} <b>{btc(sats)} BTC</b> and you get <b>{fmt(willGet)} ZCRYPT</b>
          </div>
          {err && <div className="msg err">{err}</div>}
          <button className="btn-primary btn-block" disabled={busy || soldOut || sats <= 0} onClick={start}>
            {busy ? "Opening order…" : soldOut ? "Sold out" : fromWallet ? `Buy with ${btc(sats)} BTC from this wallet` : "Buy"}
          </button>
          <p className="dim" style={{ marginTop: "0.8rem", fontSize: "0.8rem" }}>
            {fromWallet
              ? "The Bitcoin is sent from this wallet to the sale desk in one step (plus the network fee). "
              : "You will get a Bitcoin address to pay from any Bitcoin wallet. "}
            The ZCRYPT is sent to this wallet's recoverable address once the payment confirms. No account, no email.
          </p>
        </div>
      )}

      {order && st && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Order {order.id.slice(0, 8)}</h3>
          <div className={`buy-status ${st.tone}`}>{st.text}</div>
          {paying && <div className="msg">Paying from this wallet…</div>}
          {payErr && <div className="msg err">{payErr}</div>}
          {order.status !== "paid" && paid[order.id] && (
            <div className="buy-pay-text">
              <div className="buy-pay-amount">
                Paid <b>{btc(order.sats)} BTC</b> from this wallet.
              </div>
              <div className="buy-hint">
                Bitcoin transaction <code>{paid[order.id]}</code>. The desk credits the order once it confirms
                {order.min_conf > 0 && <> ({order.min_conf} confirmation{order.min_conf === 1 ? "" : "s"})</>}.
              </div>
              {order.paid_sats > 0 && (
                <div className="buy-hint">
                  Received {btc(order.paid_sats)} BTC, you get {fmt(zcryptFor(order.paid_sats, order.price_sats))} ZCRYPT.
                </div>
              )}
              <div className="buy-hint">Open until {new Date(order.expires * 1000).toLocaleString()}</div>
            </div>
          )}
          {order.status !== "paid" && !paid[order.id] && (
            <div className="buy-pay">
              {qr && (
                <div className="qr-tile">
                  <img src={qr} alt="Bitcoin payment QR" />
                </div>
              )}
              <div className="buy-pay-text">
                <div className="buy-pay-amount">
                  Send <b>{btc(order.sats)} BTC</b>{quote && usd(order.sats, quote.btc_usd) && <> (≈ {usd(order.sats, quote.btc_usd)})</>}
                </div>
                <div className="buy-hint">
                  to this {networkLabel(quote?.network ?? "bitcoin")} address. Any amount you send is converted at{" "}
                  {order.price_sats.toLocaleString()} sats per ZCRYPT.
                </div>
                <code className="buy-addr">{order.btc_address}</code>
                <div className="addr-actions">
                  {canPayFromWallet && !paying && (
                    <button className="btn-primary" onClick={() => payFromWallet(order)}>
                      Pay {btc(order.sats)} BTC from this wallet
                    </button>
                  )}
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
