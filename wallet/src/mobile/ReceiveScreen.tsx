import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";

/** Upper case takes the QR alphanumeric mode: a 2,008-character address drops from version 40 to about 30. */
function qrText(text: string): string {
  return /^[a-z0-9]+$/.test(text) ? text.toUpperCase() : text;
}
import { call, copy, copySensitive, fmtAsset, saveFile } from "../lib/api";
import { authError, Banner, Btn, Icon, overlay, Sheet, shareFile, short, Spinner } from "./ui";

/**
 * Full-screen code for another phone to scan. Sized in DEVICE pixels, not CSS pixels: on a
 * 3x screen the modules can be 8 device pixels each (a third larger than the in-card code,
 * which is held to whole CSS pixels) and still land on the pixel grid the camera sees.
 */
function QrFull({ text, onClose, children }: { text: string; onClose: () => void; children?: React.ReactNode }) {
  const [src, setSrc] = useState("");
  const [css, setCss] = useState(0);
  useEffect(() => {
    const dpr = Math.max(1, Math.round(window.devicePixelRatio || 1));
    const n = QRCode.create(qrText(text), { errorCorrectionLevel: "L" }).modules.size + 8;
    const avail = Math.min(window.innerWidth, window.innerHeight - 230) * dpr;
    const scale = Math.max(1, Math.floor(avail / n));
    setCss((n * scale) / dpr);
    setSrc("");
    QRCode.toDataURL(qrText(text), { margin: 4, scale, errorCorrectionLevel: "L", color: { dark: "#000000", light: "#ffffff" } })
      .then(setSrc)
      .catch(() => setSrc(""));
  }, [text]);
  return overlay(
    <div className="m-qrfull" onClick={onClose} role="button" aria-label="Close">
      {src ? <img src={src} alt="Address QR code" style={{ width: css, height: css }} /> : <Spinner />}
      <div className="m-qrfull-addr">{short(text, 10, 8)}</div>
      {/* The buttons act on the address; a tap anywhere else closes the code. */}
      {children && <div className="m-qrfull-actions" onClick={(e) => e.stopPropagation()}>{children}</div>}
      <div className="m-qrfull-hint">Turn screen brightness up. Tap the code to close.</div>
    </div>
  );
}
import Success from "./Success";
import Waiting from "./Waiting";
import { useAuth } from "./MobileApp";

type Which = "normal" | "stealth";
interface Stealth {
  index: number;
  address: string;
  derived?: boolean;
}

/**
 * Receive, laid out like the desktop wallet: one centred stage where a payment file or
 * pasted coin lands, and the addresses as tiles. A tile opens its QR code at full size;
 * a tap on the code closes it. A file opened with the app is credited here on its own.
 */
export default function ReceiveScreen({
  active,
  incoming,
  onConsumed,
  onReceived,
}: {
  active: boolean;
  incoming: string;
  onConsumed: () => void;
  onReceived: () => void;
}) {
  const { toast, status, askPin } = useAuth();
  const [which, setWhich] = useState<Which>("normal");
  const [normal, setNormal] = useState("");
  const [stealth, setStealth] = useState<Stealth[]>([]);
  // The shielded address on show (the newest unless one was picked), the list sheet, and
  // one private key at a time: shown after Face ID or the PIN, dropped when the sheet closes.
  const [stealthIdx, setStealthIdx] = useState<number | null>(null);
  const [listOpen, setListOpen] = useState(false);
  const [key, setKey] = useState<{ index: number; hex: string } | null>(null);
  const [keyCopied, setKeyCopied] = useState(false);
  // The address whose code fills the screen, if any.
  const [full, setFull] = useState<Which | null>(null);
  const [copied, setCopied] = useState(false);
  const [newBusy, setNewBusy] = useState(false);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [state, setState] = useState<{ tone: "ok" | "warn" | "bad"; msg: string } | null>(null);
  const [credited, setCredited] = useState("");
  const [failed, setFailed] = useState("");
  const [pasted, setPasted] = useState(false);
  const [receiving, setReceiving] = useState<"coin" | "receipt">("coin");

  const load = useCallback(() => {
    call<string>("get_address").then(setNormal).catch(() => {});
    call<Stealth[]>("list_stealth_addresses").then(setStealth).catch(() => {});
  }, []);
  useEffect(() => {
    if (active) load();
  }, [active, load]);

  const shownStealth = stealth.find((x) => x.index === stealthIdx) ?? stealth[stealth.length - 1];
  const lastStealth = shownStealth?.address ?? "";
  const address = which === "normal" ? normal : lastStealth;

  async function receive(raw: string) {
    const s = raw.trim();
    if (!s) return;
    setBusy(true);
    setState(null);
    setReceiving(s.startsWith("zcrypt-receipt/1") ? "receipt" : "coin");
    try {
      if (s.startsWith("zcrypt-receipt/1")) {
        const r = await call<{ on_chain: boolean; names_recipient: boolean; summary: string }>("verify_receipt", { text: s });
        setState({ tone: r.on_chain && r.names_recipient ? "ok" : r.on_chain ? "warn" : "bad", msg: r.summary });
        return;
      }
      const bearer = s.startsWith("zcrypt-bearer/1");
      const r = await call<{ amount: number; ticker: string; decimals: number }>(bearer ? "claim_bearer" : "receive_coin", bearer ? { token: s } : { note: s });
      const pretty = `${fmtAsset(r.amount, r.decimals)} ${r.ticker}`;
      setState(null);
      setText("");
      setCredited(pretty);
      onReceived();
    } catch (e) {
      const msg = String(e instanceof Error ? e.message : e);
      if (s.startsWith("zcrypt-receipt/1")) setState({ tone: "bad", msg });
      else setFailed(msg);
    } finally {
      setBusy(false);
    }
  }

  // A file the OS handed to the app.
  useEffect(() => {
    if (!incoming || busy) return;
    setText(incoming);
    receive(incoming).finally(onConsumed);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incoming]);

  async function share() {
    // iOS and Android: the app's own share sheet (a plain sheet, not WebKit's popover), as a
    // text file the recipient can open or paste from. Elsewhere: the web share API with the
    // address as text, then the clipboard as a last resort.
    if (/iPhone|iPad|iPod|Android/.test(navigator.userAgent)) {
      await shareFile(address + "\n", "zcrypt-address.txt", saveFile);
      return;
    }
    try {
      await navigator.share({ text: address });
    } catch {
      /* dismissed or unsupported */
    }
  }
  async function pasteAndReceive() {
    let t = "";
    try {
      t = (await navigator.clipboard.readText()).trim();
    } catch {
      /* empty or denied */
    }
    if (!t) {
      toast("Clipboard is empty", "Copy a bearer coin, stealth note or receipt first.");
      return;
    }
    setText(t);
    setPasted(true);
    setTimeout(() => setPasted(false), 1500);
    await receive(t);
  }
  async function newStealth() {
    setNewBusy(true);
    try {
      await call("new_stealth_address");
      setStealthIdx(null); // show the new one
      load();
      return true;
    } catch (e) {
      toast("Could not create", String(e));
      return false;
    } finally {
      setNewBusy(false);
    }
  }

  if (busy) {
    return (
      <Waiting
        icon="receive"
        hint="Keep the app open."
        title={receiving === "receipt" ? "Checking receipt" : "Receiving payment"}
        subtitle={
          receiving === "receipt"
            ? "Looking the payment up on the chain."
            : "Checking the chain and building the claim proof on this phone. This takes a few seconds."
        }
      />
    );
  }
  if (credited) {
    return (
      <Success title={`${credited} received!`} subtitle="The coin is yours now and already counts in your portfolio." onDone={() => setCredited("")} />
    );
  }
  if (failed) {
    const claimed = /already|spent|claimed|nullifier/i.test(failed);
    return (
      <Success
        tone="bad"
        title={claimed ? "Already claimed" : "Could not receive"}
        subtitle={
          claimed
            ? "This coin was claimed before, by this wallet or by someone else who had the file. It cannot be received twice."
            : "The payment could not be credited. Nothing was taken from the sender."
        }
        onDone={() => { setFailed(""); setText(""); }}
      >
        {!claimed && <div className="m-done-detail">{failed}</div>}
      </Success>
    );
  }

  // A tile opens its code at full size at once; a tap on the code closes it. The
  // shielded tile makes the first shielded address when there is none.
  async function openTile(w: Which) {
    setWhich(w);
    if (w === "stealth" && !lastStealth && !(await newStealth())) return;
    setFull(w);
  }
  const oldStealth = which === "stealth" && !!shownStealth && !shownStealth.derived;

  async function showKey(index: number) {
    try {
      let hex = "";
      if (status.biometric) {
        try {
          hex = await call<string>("mobile_reveal_stealth", { index, pin: null });
        } catch (e) {
          if (authError(e).kind !== "biometric") throw e;
          // Face ID declined or unavailable: fall through to the PIN.
        }
      }
      if (!hex) {
        const ok = await askPin("Enter your PIN to show the key", (pin) => call<string>("mobile_reveal_stealth", { index, pin }).then((r) => { hex = r; }));
        if (!ok) return;
      }
      setKeyCopied(false);
      setKey({ index, hex });
    } catch (e) {
      toast("Could not show the key", String(e));
    }
  }
  function closeList() {
    setListOpen(false);
    setKey(null);
  }

  return (
    <>
      {/* The same stage as the desktop wallet: one centred place where a payment lands,
          and the addresses as tiles. */}
      <div className="m-rx">
        <div className="m-rx-kicker">Receive</div>
        <div className="m-rx-mark"><Icon name="file" size={30} /></div>
        <h2>Open a coin file here</h2>
        <p className="m-rx-lead">A .zcrypt file sent to you opens in this app on its own. Bearer coins, shielded notes and payment receipts all land here.</p>
        <div className="m-rx-paste">
          <textarea
            className="m-textarea compact"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onFocus={(e) => setTimeout(() => e.target.scrollIntoView({ block: "center", behavior: "smooth" }), 250)}
            placeholder="or paste a coin file, a shielded note, or a receipt"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
          <Btn full style={{ marginTop: 10 }} onClick={() => (text.trim() ? receive(text) : pasteAndReceive())}>
            {text.trim() ? "Receive" : pasted ? <><Icon name="check" size={18} /> Pasted</> : <><Icon name="paste" size={18} /> Paste and receive</>}
          </Btn>
          {state && <Banner tone={state.tone}>{state.msg}</Banner>}
          <p className="m-rx-fine">A receipt is only checked. It does not move funds.</p>
        </div>

        <div className="m-rx-dock">
          <button className="m-rx-tile" onClick={() => openTile("normal")}>
            <span className="m-rx-glyph z">Z</span>
            <span className="m-rx-name">ZCRYPT</span>
            <span className="m-rx-sub">{normal ? short(normal, 4, 4) : "…"}</span>
          </button>
          <button className="m-rx-tile" disabled={newBusy} onClick={() => openTile("stealth")}>
            <span className="m-rx-glyph s"><Icon name="shield" size={20} /></span>
            <span className="m-rx-name">Shielded</span>
            <span className="m-rx-sub">{newBusy ? "creating…" : lastStealth ? short(lastStealth, 4, 4) : "create"}</span>
          </button>
        </div>
        <p className="m-rx-fine">Tap an address to show its code.</p>
      </div>

      {full && address && (
        <QrFull text={address} onClose={() => setFull(null)}>
          <div className="m-btnrow">
            <Btn kind="secondary" onClick={async () => { await copy(address); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
              <Icon name={copied ? "check" : "copy"} size={18} /> {copied ? "Copied" : "Copy"}
            </Btn>
            <Btn kind="secondary" onClick={share}>
              <Icon name="share" size={18} /> Share
            </Btn>
          </div>
          {which === "stealth" && (
            <>
              <Btn full kind="ghost" small disabled={newBusy} onClick={newStealth}>{newBusy ? "Creating…" : oldStealth ? "This older address is not in your phrase: make a new one" : "New shielded address"}</Btn>
              <Btn full kind="ghost" small onClick={() => { setFull(null); setListOpen(true); }}>
                All shielded addresses and keys ({stealth.length})
              </Btn>
            </>
          )}
        </QrFull>
      )}

      <Sheet open={listOpen} onClose={closeList} title="Shielded addresses">
        <p className="m-hint" style={{ marginTop: 0 }}>
          Every address stays in this wallet and keeps receiving after you make a new one. A private key spends what was sent to its address: show it only to back it up.
        </p>
        <div className="m-list">
          {stealth.map((x) => (
            <div className="m-keyrow" key={x.index}>
              <div className="m-keyrow-head">
                <div className="grow">
                  <div className="primary">Shielded #{x.index} {x.index === shownStealth?.index && <span className="m-whitelisted">shown</span>}</div>
                  <div className="secondary m-mono">{short(x.address, 10, 8)}</div>
                  <div className={x.derived ? "secondary" : "m-unbacked"}>{x.derived ? "Restored by your recovery phrase" : "Not in your phrase: back this key up"}</div>
                </div>
              </div>
              <div className="m-btnrow">
                <Btn kind="secondary" small onClick={() => { setStealthIdx(x.index); setWhich("stealth"); closeList(); setFull("stealth"); }}>
                  Show code
                </Btn>
                <Btn kind="secondary" small onClick={() => (key?.index === x.index ? setKey(null) : showKey(x.index))}>
                  {key?.index === x.index ? "Hide key" : "Show key"}
                </Btn>
              </div>
              {key?.index === x.index && (
                <>
                  <div className="m-keybox">{key.hex}</div>
                  <Btn full kind="secondary" small onClick={() => { copySensitive(key.hex); setKeyCopied(true); setTimeout(() => setKeyCopied(false), 1800); }}>
                    <Icon name={keyCopied ? "check" : "copy"} size={16} /> {keyCopied ? "Copied · clears in 60 s" : "Copy key"}
                  </Btn>
                </>
              )}
            </div>
          ))}
        </div>
        <Btn full kind="ghost" small style={{ marginTop: 10 }} disabled={newBusy} onClick={newStealth}>{newBusy ? "Creating…" : "New shielded address"}</Btn>
      </Sheet>
    </>
  );
}
