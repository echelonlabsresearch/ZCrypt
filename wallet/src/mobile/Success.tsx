import { ReactNode, useEffect, useRef } from "react";
import { Btn, Icon, overlay } from "./ui";

/**
 * Full-screen "done" moment: a burst of confetti, a big check, the amount in large type.
 * Used after a payment leaves and after a coin arrives. Respects reduced motion.
 */
export default function Success({
  title,
  subtitle,
  children,
  onDone,
  doneLabel = "Done",
  tone = "ok",
}: {
  title: string;
  subtitle?: string;
  children?: ReactNode;
  onDone: () => void;
  doneLabel?: string;
  /** "bad" is the red twin of this screen: no confetti, a cross instead of the check. */
  tone?: "ok" | "bad";
}) {
  const canvas = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const c = canvas.current;
    if (!c || tone !== "ok" || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = (c.width = c.clientWidth * dpr);
    const h = (c.height = c.clientHeight * dpr);
    const colors = ["#35e0ff", "#6d7cff", "#3ddc97", "#ffb547", "#ffffff", "#ff7ad9"];
    const parts = Array.from({ length: 140 }, () => {
      const angle = -Math.PI / 2 + (Math.random() - 0.5) * 1.6;
      const speed = (9 + Math.random() * 9) * dpr;
      return {
        x: w / 2,
        y: h * 0.42,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        rot: Math.random() * Math.PI,
        vr: (Math.random() - 0.5) * 0.3,
        size: (5 + Math.random() * 6) * dpr,
        color: colors[Math.floor(Math.random() * colors.length)],
        round: Math.random() < 0.3,
      };
    });
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const t = (now - start) / 1000;
      ctx.clearRect(0, 0, w, h);
      const alpha = t < 1.8 ? 1 : Math.max(0, 1 - (t - 1.8) / 0.9);
      for (const p of parts) {
        p.vy += 0.35 * dpr;
        p.vx *= 0.985;
        p.x += p.vx;
        p.y += p.vy;
        p.rot += p.vr;
        ctx.save();
        ctx.globalAlpha = alpha;
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rot);
        ctx.fillStyle = p.color;
        if (p.round) {
          ctx.beginPath();
          ctx.arc(0, 0, p.size / 2, 0, Math.PI * 2);
          ctx.fill();
        } else {
          ctx.fillRect(-p.size / 2, -p.size / 4, p.size, p.size / 2);
        }
        ctx.restore();
      }
      if (t < 2.8) raf = requestAnimationFrame(tick);
      else ctx.clearRect(0, 0, w, h);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [tone]);

  return overlay(
    <div className={`m-done ${tone}`}>
      <canvas ref={canvas} className="m-confetti" />
      <div className="m-done-body">
        <div className="m-done-check">
          <Icon name={tone === "ok" ? "check" : "close"} size={52} stroke={2.6} />
        </div>
        <h1 className="m-done-title">{title}</h1>
        {subtitle && <p className="m-done-sub">{subtitle}</p>}
        {children && <div className="m-done-extra">{children}</div>}
      </div>
      <div className="m-done-foot">
        <Btn full kind={tone === "ok" ? "primary" : "secondary"} onClick={onDone}>{doneLabel}</Btn>
      </div>
    </div>
  );
}
