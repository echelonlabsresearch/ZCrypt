import { useState } from "react";
import { copy, copySensitive, saveFile, openExternal } from "../lib/api";

/** A copy button that confirms with a transient "Copied!" state (non-secret text). */
export function CopyButton({ text, label = "⧉ Copy", className = "copy-btn" }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className={className}
      onClick={async () => {
        await copy(text);
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
    >
      {done ? "✓ Copied!" : label}
    </button>
  );
}

/**
 * Hand-off row for a payment SECRET (a bearer coin or a stealth note). Deliberately no
 * WhatsApp / Telegram / email links: those put the secret into a URL that leaves the
 * machine unencrypted and outside Tor, and a bearer coin IS the money. Copy (auto-cleared
 * from the clipboard after 60 s) or save to a private file, then deliver it over an
 * end-to-end encrypted channel of your choice.
 */
export function ShareBar({ text, filename }: { text: string; filename: string }) {
  const [saved, setSaved] = useState("");
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ marginTop: "0.6rem" }}>
      <div className="warn" style={{ marginBottom: "0.5rem" }}>
        This text is the payment itself. Do not paste it into a chat app, email or web form: send it
        over an end-to-end encrypted channel, or hand over the saved file in person. The clipboard is
        cleared automatically 60 seconds after copying.
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "center" }}>
        <button
          className="copy-btn"
          onClick={async () => {
            await copySensitive(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? "✓ Copied (clears in 60 s)" : "⧉ Copy (clears in 60 s)"}
        </button>
        <button
          className="copy-btn"
          onClick={async () => {
            try {
              const path = await saveFile(filename, text);
              setSaved(path);
            } catch (e) {
              setSaved(`error: ${e}`);
            }
          }}
        >
          💾 Save file
        </button>
        {saved && (
          <div style={{ flexBasis: "100%", fontSize: "0.78rem", opacity: 0.75, marginTop: "0.3rem" }}>
            {saved.startsWith("error") ? (
              <span style={{ color: "var(--color-red, #e66)" }}>{saved}</span>
            ) : (
              <>
                ✓ Saved to <code>{saved}</code>{" "}
                <button className="copy-btn" style={{ padding: "0 0.4rem" }} onClick={() => openExternal(saved)}>Open</button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
