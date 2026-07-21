import { useState, DragEvent } from "react";
import { call, fmtAsset } from "../lib/api";

export interface ReceivedInfo {
  amount: number;
  ticker: string;
  decimals: number;
}

export default function Receive({ onReceived }: { onReceived: (r: ReceivedInfo) => void }) {
  const [blob, setBlob] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [state, setState] = useState<"idle" | "ok" | "err">("idle");
  const [msg, setMsg] = useState("");

  async function receive(text: string) {
    const s = text.trim();
    if (!s) return;
    setBusy(true);
    setState("idle");
    try {
      const isBearer = s.startsWith("zcb1");
      const cmd = isBearer ? "claim_bearer" : "receive_coin";
      const args = isBearer ? { token: s } : { note: s };
      const r = await call<{ amount: number; coin_id: string; ticker: string; decimals: number }>(cmd, args);
      setState("ok");
      setMsg(`Received ${fmtAsset(r.amount, r.decimals)} ${r.ticker}`);
      setBlob("");
      onReceived({ amount: r.amount, ticker: r.ticker, decimals: r.decimals });
    } catch (e) {
      setState("err");
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  }

  function onDragOver(e: DragEvent) {
    e.preventDefault();
    if (!dragging) setDragging(true);
  }
  function onDragLeave(e: DragEvent) {
    // only clear when leaving the dropzone itself, not a child
    if (e.currentTarget === e.target) setDragging(false);
  }
  async function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      const text = await file.text();
      setBlob(text.trim());
      receive(text);
      return;
    }
    const text = e.dataTransfer.getData("text");
    if (text) {
      setBlob(text.trim());
      receive(text);
    }
  }

  const cls = dragging ? "dragging" : state === "ok" ? "success" : state === "err" ? "error" : "";

  return (
    <div>
      <h2 className="view-title">📥 Receive Coins</h2>
      <div className={`dropzone ${cls}`} onDragOver={onDragOver} onDragEnter={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}>
        <div className="drop-icon">{dragging ? "⬇️" : state === "ok" ? "✓" : state === "err" ? "✗" : "💎"}</div>
        <div style={{ fontWeight: "bold", color: dragging ? "var(--color-cyan)" : undefined }}>
          {dragging ? "Drop the coin to receive it" : "Drag a coin file here, or paste below"}
        </div>
        <div style={{ maxWidth: 520, width: "100%", padding: "0 1.5rem" }}>
          <textarea
            className="mnemonic-input"
            value={blob}
            onChange={(e) => setBlob(e.target.value)}
            placeholder="paste an encrypted note or a bearer coin (zcb1…)"
            style={{ minHeight: 100 }}
          />
          <button className="btn-primary btn-block" style={{ marginTop: "0.8rem" }} disabled={busy} onClick={() => receive(blob)}>
            {busy ? "Verifying…" : "Receive"}
          </button>
          {state !== "idle" && !dragging && <div className={`msg ${state === "ok" ? "ok" : "err"}`}>{msg}</div>}
        </div>
      </div>

      <div className="card" style={{ marginTop: "1.2rem" }}>
        <h2>🔐 How it works</h2>
        <ol style={{ opacity: 0.85, lineHeight: 1.8 }}>
          <li>Coins sent to your <b>address</b> arrive on-chain — just hit <b>Refresh</b> to scan for them.</li>
          <li>A <b>bearer coin</b> (zcb1…) or an encrypted note can be dropped/pasted here to claim directly.</li>
          <li>Only your key can decrypt what's yours; amounts stay hidden on the ledger.</li>
        </ol>
        <div className="warn">Never drop or paste a coin into anything but your own wallet.</div>
      </div>
    </div>
  );
}
