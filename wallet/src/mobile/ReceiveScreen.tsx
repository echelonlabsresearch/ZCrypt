import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import { call, copy, fmtAsset, saveFile } from "../lib/api";
import { Banner, Btn, Icon, Segmented, shareFile, short, Spinner } from "./ui";
import Success from "./Success";
import { useAuth } from "./MobileApp";

type Which = "normal" | "stealth";
interface Stealth {
  index: number;
  address: string;
}

/**
 * Receive: your address as a QR code, and the place where a payment file lands. A file
 * opened with the app is credited here on its own.
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
  const { toast } = useAuth();
  const [which, setWhich] = useState<Which>("normal");
  const [normal, setNormal] = useState("");
  const [stealth, setStealth] = useState<Stealth[]>([]);
  const [qr, setQr] = useState("");
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

  const address = which === "normal" ? normal : stealth[stealth.length - 1]?.address ?? "";
  useEffect(() => {
    if (!address) return setQr("");
    QRCode.toDataURL(address, { margin: 4, width: 480, errorCorrectionLevel: "M", color: { dark: "#0b0f19", light: "#ffffff" } })
      .then(setQr)
      .catch(() => setQr(""));
  }, [address]);

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
    // iOS: the app's own share sheet (a plain sheet, not WebKit's popover), as a text file
    // the recipient can open or paste from. Elsewhere: the web share API with the address
    // as text, then the clipboard as a last resort.
    if (/iPhone|iPad|iPod/.test(navigator.userAgent)) {
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
      load();
    } catch (e) {
      toast("Could not create", String(e));
    } finally {
      setNewBusy(false);
    }
  }

  if (busy) {
    return (
      <Success
        tone="busy"
        title={receiving === "receipt" ? "Checking receipt" : "Receiving payment"}
        subtitle={
          receiving === "receipt"
            ? "Looking the payment up on the chain."
            : "Checking the chain and building the claim proof on this phone. This takes a few seconds."
        }
        onDone={() => {}}
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

  return (
    <>
      <div className="m-head">
        <h1 className="m-title">Receive</h1>
      </div>

      <Segmented<Which>
        value={which}
        onChange={setWhich}
        options={[
          { value: "normal", label: "My address" },
          { value: "stealth", label: "Stealth" },
        ]}
      />

      <div className="m-card" style={{ marginTop: 14, textAlign: "center" }}>
        {address ? (
          <>
            <div className="m-qr">{qr ? <img src={qr} alt="" /> : <Spinner />}</div>
            <div className="m-addr" title={address}>{short(address, 10, 8)}</div>
            <div className="m-btnrow">
              <Btn kind="secondary" onClick={async () => { await copy(address); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
                <Icon name={copied ? "check" : "copy"} size={18} /> {copied ? "Copied" : "Copy"}
              </Btn>
              <Btn kind="secondary" onClick={share}>
                <Icon name="share" size={18} /> Share
              </Btn>
            </div>
          </>
        ) : which === "stealth" ? (
          <div style={{ padding: "10px 0" }}>
            <p className="m-sub" style={{ margin: "0 0 14px" }}>No stealth address yet.</p>
            <Btn full disabled={newBusy} onClick={newStealth}>{newBusy ? "Creating…" : "Create a stealth address"}</Btn>
          </div>
        ) : (
          <div style={{ padding: 30 }}><Spinner /></div>
        )}
      </div>
      <p className="m-hint">
        {which === "normal"
          ? "Payments to this address settle on the chain and appear after a refresh. The amounts stay hidden from everyone else."
          : "A stealth payment arrives as an encrypted file, invisible even to your own view key. This address is not restored by your recovery phrase."}
      </p>
      {which === "stealth" && address && (
        <Btn full kind="ghost" small disabled={newBusy} onClick={newStealth}>{newBusy ? "Creating…" : "New stealth address"}</Btn>
      )}

      <div className="m-section">Open a payment file</div>
      <div className="m-card">
        <p className="m-hint" style={{ margin: "0 0 10px" }}>
          A .zcrypt file sent to you opens in this app on its own. Copied a coin, note or receipt instead? Paste it here.
        </p>
        <Btn full disabled={busy} onClick={pasteAndReceive}>
          {busy ? "Claiming…" : pasted ? <><Icon name="check" size={18} /> Pasted</> : <><Icon name="paste" size={18} /> Paste and receive</>}
        </Btn>
        <textarea
          className="m-textarea compact"
          style={{ marginTop: 10 }}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onFocus={(e) => setTimeout(() => e.target.scrollIntoView({ block: "center", behavior: "smooth" }), 250)}
          placeholder="or type it: zcrypt-bearer/1 …"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
        />
        {text.trim() && !busy && (
          <Btn full kind="secondary" style={{ marginTop: 10 }} onClick={() => receive(text)}>Receive what is typed</Btn>
        )}
        {state && <Banner tone={state.tone}>{state.msg}</Banner>}
      </div>
    </>
  );
}
