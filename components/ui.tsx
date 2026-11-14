import { ArrowLeft, RotateCcw } from "lucide-react";
import type { ReactNode } from "react";

export function ConsoleLayout({
  title,
  subtitle,
  children,
  onBack,
  onReset
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
  onBack: () => void;
  onReset: () => void;
}) {
  return (
    <section className="console-screen">
      <header className="console-header">
        <button className="icon-button" type="button" onClick={onBack} aria-label="Back to mode selector">
          <ArrowLeft size={18} />
        </button>
        <div>
          <p className="eyebrow">{subtitle}</p>
          <h1>{title}</h1>
        </div>
        <button className="icon-button" type="button" onClick={onReset} aria-label="Reset with fresh keys" title="Reset with fresh keys">
          <RotateCcw size={18} />
        </button>
      </header>
      {children}
    </section>
  );
}

export function PanelTitle({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <div className="panel-title">
      {icon}
      <span>{title}</span>
    </div>
  );
}

export function Metric({
  label,
  value,
  tone = "neutral"
}: {
  label: string;
  value: ReactNode;
  tone?: "neutral" | "good" | "bad" | "warn" | "info";
}) {
  return (
    <div className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "good" | "bad" | "warn" | "info" }) {
  return <em className={`badge ${tone}`}>{children}</em>;
}
