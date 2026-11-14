"use client";

import { useCallback, useEffect, useState } from "react";
import { BookOpen, Check, Info, KeyRound, ShieldCheck, TriangleAlert } from "lucide-react";
import { runWalkthrough } from "@/lib/protocol/walkthrough";
import { Trace, TraceStep } from "@/lib/protocol/trace";
import { ConsoleLayout, Metric, PanelTitle } from "./ui";

const isAttack = (step: TraceStep) => step.actor === "Attacker";

export default function KeyGenMode({ onBack }: { onBack: () => void }) {
  const [steps, setSteps] = useState<Trace>([]);
  const [active, setActive] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async () => {
    setError(null);
    try {
      setSteps(await runWalkthrough());
      setActive(0);
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  useEffect(() => {
    void run();
  }, [run]);

  const step = steps[active];
  const attacksBlocked = steps.filter(isAttack).filter((s) => s.status === "fail").length;
  const attacks = steps.filter(isAttack).length;

  return (
    <ConsoleLayout title="Key Gen Process" subtitle="// protocol trace debugger" onBack={onBack} onReset={run}>
      <section className="keygen-grid">
        <aside className="panel step-panel">
          <PanelTitle icon={<KeyRound size={16} />} title="Trace steps" />
          {steps.map((item, index) => (
            <button
              className={`step-button ${index === active ? "active" : ""} ${isAttack(item) ? "attack" : ""}`}
              type="button"
              key={`${item.title}-${index}`}
              onClick={() => setActive(index)}
            >
              <span>{String(index + 1).padStart(2, "0")}</span>
              {item.title}
            </button>
          ))}
        </aside>

        <section className="panel trace-panel">
          <div className="trace-heading">
            <span className="label">
              Step {active + 1} of {steps.length || "-"} · {step?.actor}
            </span>
            <h2>{error ?? step?.title ?? "Running the protocol..."}</h2>
          </div>
          {step && (
            <div className="trace-step">
              <Metric label="algorithm" value={step.algorithm} />
              <Metric label="input" value={step.input} />
              <Metric label="output" value={<span className="pre">{step.output}</span>} />
              <Metric
                label="verification"
                value={step.verification}
                tone={step.status === "success" || (isAttack(step) && step.status === "fail") ? "good" : step.status === "info" ? "info" : "bad"}
              />
              <Metric label="tamper / failure mode" value={step.failureMode} tone={isAttack(step) ? "warn" : "neutral"} />
              {step.paper && <Metric label="from the literature" value={step.paper} tone="info" />}
              <StatusBadge step={step} />
            </div>
          )}
          <div className="trace-actions">
            <button className="terminal-button secondary compact" type="button" onClick={() => setActive(Math.max(0, active - 1))}>
              Prev
            </button>
            <button
              className="terminal-button primary compact"
              type="button"
              onClick={() => setActive(Math.min(steps.length - 1, active + 1))}
            >
              Next -&gt;
            </button>
          </div>
        </section>

        <aside className="panel inspector-panel">
          <PanelTitle icon={<ShieldCheck size={16} />} title="Run summary" />
          <Metric label="steps executed" value={steps.length} />
          <Metric
            label="attacks rejected"
            value={`${attacksBlocked} / ${attacks}`}
            tone={attacks && attacksBlocked === attacks ? "good" : "bad"}
          />
          <Metric
            label="forward secrecy check"
            value={steps.find((s) => s.title.startsWith("Forward secrecy"))?.status === "success" ? "old messages unreadable" : "pending"}
            tone="good"
          />
          <Metric label="keys" value="fresh on every run: press reset to regenerate" />
          <PanelTitle icon={<BookOpen size={16} />} title="Pipeline" />
          <p className="pipeline">Authenticate → Establish keys offline → Ratchet → Encrypt → Delete old key material</p>
        </aside>
      </section>
    </ConsoleLayout>
  );
}

function StatusBadge({ step }: { step: TraceStep }) {
  if (step.status === "info") {
    return (
      <div className="verification-badge info">
        <Info size={15} /> Observation
      </div>
    );
  }
  if (isAttack(step)) {
    return step.status === "fail" ? (
      <div className="verification-badge">
        <ShieldCheck size={15} /> Attack rejected
      </div>
    ) : (
      <div className="verification-badge fail">
        <TriangleAlert size={15} /> Attack succeeded
      </div>
    );
  }
  return step.status === "success" ? (
    <div className="verification-badge">
      <Check size={15} /> Verified
    </div>
  ) : (
    <div className="verification-badge fail">
      <TriangleAlert size={15} /> Failed
    </div>
  );
}
