import { ReactNode } from "react";

const R = 96;
const LEN = 2 * Math.PI * R;

/**
 * The big progress ring of the full-screen waiting moments (first sync, sending). The
 * arc fills to `pct`; a short arc circles it while work is going on, so the screen is
 * visibly alive between two steps. `paused` stops the circling and turns the arc amber.
 */
export default function Ring({ pct, paused = false, label, children }: { pct: number; paused?: boolean; label: string; children: ReactNode }) {
  const p = Math.min(100, Math.max(0, pct));
  return (
    <div className={`m-sync-ring ${paused ? "paused" : ""}`} role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(p)} aria-label={label}>
      <svg viewBox="0 0 220 220">
        <circle className="track" cx="110" cy="110" r={R} />
        <circle className="fill" cx="110" cy="110" r={R} strokeDasharray={LEN} strokeDashoffset={LEN * (1 - p / 100)} />
        {!paused && <circle className={`orbit ${p === 0 ? "wide" : ""}`} cx="110" cy="110" r={R} strokeDasharray={`${LEN * 0.08} ${LEN}`} />}
      </svg>
      <div className="m-sync-mid">{children}</div>
    </div>
  );
}
