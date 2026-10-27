import { useEffect, useState } from "react";
import { call, saveFile } from "../lib/api";
import { CopyButton } from "./Share";

/** The compliance view key: revealed on demand, copied or saved to a file. Lives under Settings. */
export default function ViewKeyCard() {
  const [viewKey, setViewKey] = useState("");
  const [show, setShow] = useState(false);
  const [saved, setSaved] = useState("");
  useEffect(() => {
    call<string>("get_view_key").then(setViewKey).catch(() => {});
  }, []);
  return (
    <div className="card" style={{ marginTop: "1.2rem" }}>
      <h2>🔎 View key</h2>
      <div style={{ fontSize: "0.85rem", opacity: 0.85, lineHeight: 1.5, marginBottom: "0.6rem" }}>
        Give this to an auditor to let them <b>see the amounts</b> of payments to your recoverable address,
        and nothing more. It can never spend, and it cannot see shielded or bearer coins.
      </div>
      {show ? (
        <>
          <div className="mono-box" style={{ color: "var(--color-green)", wordBreak: "break-all" }}>{viewKey}</div>
          <div style={{ display: "flex", gap: "0.4rem", marginTop: "0.5rem", flexWrap: "wrap" }}>
            <CopyButton text={viewKey} label="⧉ Copy view key" />
            <button
              className="copy-btn"
              onClick={async () => {
                try {
                  setSaved(await saveFile("zcrypt-view-key.txt", viewKey));
                } catch (e) {
                  setSaved(`error: ${e}`);
                }
              }}
            >
              💾 Save file
            </button>
            <button className="btn-link" onClick={() => setShow(false)}>
              Hide
            </button>
          </div>
          {saved && (
            <div style={{ fontSize: "0.78rem", opacity: 0.7, marginTop: "0.4rem" }}>
              {saved.startsWith("error") ? (
                <span style={{ color: "var(--color-red, #e66)" }}>{saved}</span>
              ) : (
                <>
                  ✓ Saved to <code>{saved}</code>
                </>
              )}
            </div>
          )}
        </>
      ) : (
        <button className="btn-secondary" onClick={() => setShow(true)}>
          👁 Reveal my view key
        </button>
      )}
      <div className="warn" style={{ marginTop: "0.8rem" }}>
        A view key is a disclosure, and it cannot be un-shared.
      </div>
    </div>
  );
}
