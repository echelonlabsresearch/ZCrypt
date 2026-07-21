import { useState } from "react";
import { copy, saveFile, openExternal, shareLinks } from "../lib/api";

/** A copy button that confirms with a transient "Copied!" state. */
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

/** Save-to-file + WhatsApp / Telegram / Email share row for a text token. */
export function ShareBar({ text, filename, subject }: { text: string; filename: string; subject?: string }) {
  const [saved, setSaved] = useState("");
  const links = shareLinks(text, subject);
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginTop: "0.6rem", alignItems: "center" }}>
      <CopyButton text={text} />
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
      <button className="copy-btn" onClick={() => openExternal(links.whatsapp)}>🟢 WhatsApp</button>
      <button className="copy-btn" onClick={() => openExternal(links.telegram)}>🔵 Telegram</button>
      <button className="copy-btn" onClick={() => openExternal(links.email)}>✉️ Email</button>
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
  );
}
