import { ReactNode } from "react";
import { Icon, IconName, overlay } from "./ui";
import Ring from "./Ring";

/**
 * The one full-screen waiting moment: the ring, a title, one line of what is happening,
 * and a hint. Every wait long enough to notice uses it (creating or restoring a wallet,
 * the first sync, sending, receiving), so they all look and move the same.
 *
 * With `pct` the ring fills and the middle shows the number, unless an `icon` is given.
 * Without `pct` the wait has no measurable progress: the ring only circles.
 */
export default function Waiting({
  title,
  subtitle,
  hint,
  pct,
  icon,
  caption,
  paused = false,
  children,
  foot,
}: {
  title: string;
  subtitle?: string;
  hint?: string;
  pct?: number;
  icon?: IconName;
  /** The small line inside the ring, under the number or the icon. */
  caption?: string;
  /** The work stopped and needs the user: the ring stands still and turns amber. */
  paused?: boolean;
  /** Shown under the text in place of the hint (an error detail). */
  children?: ReactNode;
  /** Buttons at the bottom of the screen. */
  foot?: ReactNode;
}) {
  const p = Math.round(Math.min(100, Math.max(0, pct ?? 0)));
  return overlay(
    <div className="m-done busy m-sync">
      <div className="m-done-body">
        <Ring pct={p} paused={paused} label={title}>
          {icon ? <span className="m-sync-icon"><Icon name={icon} size={54} stroke={2} /></span> : <div className="m-sync-pct">{p}<span>%</span></div>}
          {caption && <div className={icon ? "m-sync-step" : "m-sync-coins"}>{caption}</div>}
        </Ring>
        <h1 className="m-done-title">{title}</h1>
        {subtitle && <p className="m-done-sub">{subtitle}</p>}
        {children ? <div className="m-done-extra">{children}</div> : hint && <p className="m-sync-hint">{hint}</p>}
      </div>
      {foot && <div className="m-done-foot">{foot}</div>}
    </div>
  );
}
