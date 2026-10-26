import { useEffect, useRef, useState } from "react";
import { cancel, checkPermissions, Format, openAppSettings, requestPermissions, scan } from "@tauri-apps/plugin-barcode-scanner";
import { Btn, Icon, overlay } from "./ui";

/**
 * The address inside a scanned QR code, or null. Accepts the bare address the Receive
 * tab shows, and a `zcrypt:` URI with an optional query, so other wallets' codes work too.
 */
export function addressFromQr(text: string): string | null {
  let s = text.trim();
  if (/^zcrypt:/i.test(s)) s = s.slice("zcrypt:".length);
  s = s.split("?")[0].trim();
  return /^zc1[a-z0-9]+$/i.test(s) ? s : null;
}

/**
 * Full-screen QR scanner for the Send tab. The camera is a native layer the plugin puts
 * behind the webview, which it makes transparent for the duration. While it runs the shell
 * lifts its own backgrounds (`html.m-scanning`) so the preview shows through, and this
 * overlay paints only the darkened edges, the viewfinder and a cancel button.
 */
export default function ScanOverlay({ onResult, onClose, onError }: { onResult: (text: string) => void; onClose: () => void; onError: (msg: string) => void }) {
  const [state, setState] = useState<"starting" | "scanning" | "denied">("starting");
  const settled = useRef(false);

  useEffect(() => {
    const root = document.documentElement;
    let alive = true;
    (async () => {
      try {
        let p = await checkPermissions();
        if (p !== "granted") p = await requestPermissions();
        if (!alive) return;
        if (p !== "granted") return setState("denied");
        root.classList.add("m-scanning");
        setState("scanning");
        const r = await scan({ windowed: true, formats: [Format.QRCode] });
        if (alive) {
          settled.current = true;
          onResult(r.content);
        }
      } catch (e) {
        // A cancel (unmount) rejects the pending scan too; only a live failure is reported.
        if (alive && !settled.current) {
          settled.current = true;
          onError(String(e instanceof Error ? e.message : e));
        }
      } finally {
        root.classList.remove("m-scanning");
      }
    })();
    return () => {
      alive = false;
      root.classList.remove("m-scanning");
      if (!settled.current) cancel().catch(() => {});
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return overlay(
    <div className={`m-scan ${state}`}>
      <button className="m-iconbtn m-scan-close" onClick={onClose} aria-label="Cancel">
        <Icon name="close" size={20} />
      </button>
      {state === "denied" ? (
        <div className="m-scan-denied">
          <span className="m-avatar soft"><Icon name="scan" size={22} /></span>
          <h3>Camera access is off</h3>
          <p className="m-sub">Allow the camera for ZCrypt Wallet in Settings to scan an address.</p>
          <div className="m-btnrow">
            <Btn onClick={() => openAppSettings().catch(() => {})}>Open Settings</Btn>
            <Btn kind="secondary" onClick={onClose}>Cancel</Btn>
          </div>
        </div>
      ) : (
        <>
          <div className="m-scan-frame" />
          <p className="m-scan-hint">{state === "starting" ? "Starting the camera…" : "Point the camera at a ZCrypt address."}</p>
        </>
      )}
    </div>,
  );
}
