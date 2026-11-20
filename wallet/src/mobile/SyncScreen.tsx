import { useCallback, useEffect, useRef, useState } from "react";
import { call } from "../lib/api";
import { Btn } from "./ui";
import Success from "./Success";
import Waiting from "./Waiting";

interface IndexJob {
  running: boolean;
  phase: string;
  at: number;
  total: number;
  percent: number;
  coins: number;
  detail: string;
}

function coinsLine(n: number) {
  return `${n} coin${n === 1 ? "" : "s"}`;
}

/**
 * The first sync after a restore, full screen: a ring that fills with the scan, the
 * number of coins found, then the confetti screen. The scan runs on a backend thread
 * and is polled, so a paused scan is shown as paused and resumes from where it stopped.
 */
export default function SyncScreen({ onDone }: { onDone: () => void }) {
  const [job, setJob] = useState<IndexJob | null>(null);
  const [failed, setFailed] = useState("");
  const run = useRef(0);

  const start = useCallback(() => {
    const id = ++run.current;
    let timer = 0;
    setFailed("");
    const poll = async () => {
      if (id !== run.current) return;
      try {
        const j = await call<IndexJob>("index_job");
        if (id !== run.current) return;
        setJob(j);
        if (j.running) timer = window.setTimeout(poll, 400);
        else if (j.phase === "error") setFailed(j.detail.replace(/^Rebuild failed:\s*/, ""));
      } catch {
        timer = window.setTimeout(poll, 1000);
      }
    };
    call<IndexJob>("sync_from_cursor")
      .then((j) => {
        if (id !== run.current) return;
        setJob(j);
        timer = window.setTimeout(poll, 400);
      })
      .catch((e) => id === run.current && setFailed(String(e)));
    return () => {
      run.current += 1;
      window.clearTimeout(timer);
    };
  }, []);

  useEffect(() => start(), [start]);

  if (job && !job.running && job.phase === "done" && !failed) {
    return (
      <Success
        title="You're all set"
        subtitle={job.coins > 0 ? `${coinsLine(job.coins)} recovered from the chain.` : "No coins were found for this phrase yet. New ones appear as they arrive."}
        doneLabel="Let's go"
        onDone={onDone}
      />
    );
  }

  const reading = job && job.total > 0 && job.at > 0 && job.phase === "fetching";

  return (
    <Waiting
      title={failed ? "Sync paused" : "Restoring your wallet"}
      subtitle={
        failed
          ? "The connection to the network dropped. Nothing is lost: the sync continues from where it stopped."
          : reading
            ? `Reading block ${job.at.toLocaleString()} of ${job.total.toLocaleString()}.`
            : job?.phase === "indexing"
              ? "Looking for your coins."
              : job?.phase === "saving"
                ? "Saving."
                : "Connecting to the network."
      }
      hint="Keep the app open. A full restore reads the whole chain and takes a few minutes."
      pct={job?.percent ?? 0}
      caption={job && job.coins > 0 ? `${coinsLine(job.coins)} found` : failed ? "paused" : "syncing"}
      paused={!!failed}
      foot={
        failed && (
          <>
            <Btn full onClick={start}>Continue syncing</Btn>
            <div style={{ height: 10 }} />
            <Btn full kind="ghost" onClick={onDone}>Finish later</Btn>
          </>
        )
      }
    >
      {failed && <div className="m-done-detail">{failed}</div>}
    </Waiting>
  );
}
