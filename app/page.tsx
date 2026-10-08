"use client";

import { useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  Binary,
  Check,
  KeyRound,
  Lock,
  MessageSquareText,
  RotateCcw,
  ShieldCheck,
  Terminal,
  TriangleAlert,
  Zap
} from "lucide-react";
import {
  createDemoBundle,
  decryptMessage,
  DemoBundle,
  EncryptedEnvelope,
  encryptMessage,
  preview,
  SessionState,
  VerificationStep
} from "@/lib/crypto-demo";

type Mode = "home" | "chat" | "keygen";

type ChatMessage = {
  id: string;
  side: "sent" | "received";
  label: string;
  plaintext: string;
  envelope: EncryptedEnvelope;
};

const sampleMessages = [
  "Prekey bundle verified. Opening secure channel.",
  "Message key advanced and previous key deleted.",
  "Ciphertext stored. Plaintext only exists after decrypt."
];

export default function Home() {
  const [mode, setMode] = useState<Mode>("home");
  const [bundle, setBundle] = useState<DemoBundle | null>(null);
  const [session, setSession] = useState<SessionState | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState(sampleMessages[0]);
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    createDemoBundle().then((created) => {
      setBundle(created);
      setSession(created.session);
      setLoading(false);
    });
  }, []);

  const keygenSteps = useMemo<VerificationStep[]>(() => {
    if (!bundle) {
      return [];
    }

    return [
      ...bundle.session.transcript,
      {
        title: "Message key generated",
        algorithm: "Simplified Double Ratchet chain with HKDF-SHA256",
        input: `Current chain key ${preview(String(bundle.session.messageNumber).padStart(4, "0"))}`,
        output: "One AES-GCM message key plus one next-chain key",
        verification: "The old message key is not retained after encryption.",
        failureMode: "A stolen current key cannot recover already deleted message keys.",
        status: "success"
      },
      {
        title: "Sample message encrypted",
        algorithm: "AES-GCM with authenticated associated data",
        input: "Plaintext + Alice/Bob identity fingerprints",
        output: "Ciphertext, IV, auth tag, and metadata envelope",
        verification: "Ciphertext can be opened only with the derived message key and matching associated data.",
        failureMode: "Ciphertext or identity metadata changes cause authentication failure.",
        status: "success"
      },
      {
        title: "Tampered signed prekey rejected",
        algorithm: "ECDSA verification",
        input: "Bob signature + modified prekey bytes",
        output: bundle.tamper.signedPreKeyRejected ? "Verification rejected" : "Unexpected acceptance",
        verification: "The signature binds Bob's identity key to the signed prekey.",
        failureMode: "Without this check, a man-in-the-middle could substitute their own prekey.",
        status: bundle.tamper.signedPreKeyRejected ? "success" : "fail"
      },
      {
        title: "Tampered associated data rejected",
        algorithm: "AES-GCM authentication",
        input: "Valid ciphertext + attacker-modified identity binding",
        output: bundle.tamper.aadRejected ? "Decryption rejected" : "Unexpected decrypt",
        verification: "Both participants' identities are authenticated with the ciphertext.",
        failureMode: "Without associated data, unknown key-share style misbinding becomes easier.",
        status: bundle.tamper.aadRejected ? "success" : "fail"
      },
      {
        title: "Old keys deleted",
        algorithm: "Forward secrecy by key erasure",
        input: "Ephemeral session key and previous message keys",
        output: `${bundle.session.deletedKeys.length} key material preview(s) marked erased`,
        verification: "The demo state advances to new chain material after each message.",
        failureMode: "Keeping old keys would allow later compromise to decrypt older ciphertext.",
        status: "success"
      }
    ];
  }, [bundle]);

  async function resetDemo() {
    setLoading(true);
    const created = await createDemoBundle();
    setBundle(created);
    setSession(created.session);
    setMessages([]);
    setDraft(sampleMessages[0]);
    setActiveStep(0);
    setLoading(false);
  }

  async function sendMessage() {
    if (!bundle || !session || !draft.trim()) {
      return;
    }

    const encrypted = await encryptMessage(session, bundle.alice, bundle.bob, draft.trim());
    const plaintext = await decryptMessage(session, encrypted.envelope);
    setSession(encrypted.session);
    setMessages((current) => [
      ...current,
      {
        id: encrypted.envelope.id,
        side: "sent",
        label: "Alice -> Bob",
        plaintext,
        envelope: encrypted.envelope
      }
    ]);
    setDraft(sampleMessages[(messages.length + 1) % sampleMessages.length]);
  }

  return (
    <main className="shell">
      <div className="scanline" />
      {mode === "home" && (
        <section className="login-frame" aria-labelledby="app-title">
          <div className="top-rule" />
          <div className="brand-block">
            <p className="eyebrow">// literature survey project</p>
            <h1 id="app-title">Cipher in Motion</h1>
            <p className="subtitle">forward secrecy messenger demo</p>
          </div>

          <div className="mode-stack">
            <button className="terminal-button primary" type="button" onClick={() => setMode("chat")}>
              <MessageSquareText size={18} />
              Chat Mode -&gt;
            </button>
            <button className="terminal-button secondary" type="button" onClick={() => setMode("keygen")}>
              <KeyRound size={18} />
              Key Gen Process -&gt;
            </button>
          </div>

          <div className="divider" />

          <div className="system-readout">
            <span>Protocol</span>
            <strong>ECDH + ECDSA + HKDF + AES-GCM</strong>
            <span>Status</span>
            <strong>{loading ? "GENERATING KEYS" : "READY"}</strong>
          </div>
        </section>
      )}

      {mode === "chat" && bundle && session && (
        <ConsoleLayout
          title="Chat Mode"
          subtitle="// final product simulation"
          onBack={() => setMode("home")}
          onReset={resetDemo}
        >
          <section className="chat-grid">
            <aside className="panel contacts-panel">
              <PanelTitle icon={<ShieldCheck size={16} />} title="Contacts" />
              <ContactRow name="Bob" detail="TOFU trusted" active fingerprint={bundle.bob.fingerprint} />
              <ContactRow name="Alice" detail="Local identity" fingerprint={bundle.alice.fingerprint} />
              <div className="warning-strip">
                <TriangleAlert size={15} />
                Key-change warnings enabled
              </div>
            </aside>

            <section className="panel conversation-panel">
              <div className="conversation-header">
                <div>
                  <span className="label">Secure channel</span>
                  <h2>Alice / Bob</h2>
                </div>
                <span className="status-pill">
                  <Lock size={14} />
                  E2EE ON
                </span>
              </div>

              <div className="message-list">
                {messages.length === 0 ? (
                  <div className="empty-state">
                    <Terminal size={28} />
                    <p>No messages yet. Send a sample to encrypt, store, decrypt, and advance the chain key.</p>
                  </div>
                ) : (
                  messages.map((message) => (
                    <article className={`message ${message.side}`} key={message.id}>
                      <span>{message.label}</span>
                      <p>{message.plaintext}</p>
                      <code>{preview(message.envelope.ciphertextB64, 18, 14)}</code>
                    </article>
                  ))
                )}
              </div>

              <div className="composer">
                <input
                  value={draft}
                  onChange={(event) => setDraft(event.target.value)}
                  placeholder="type secure message"
                />
                <button className="terminal-button primary compact" type="button" onClick={sendMessage}>
                  <Zap size={15} />
                  Encrypt + Send
                </button>
              </div>
            </section>

            <aside className="panel inspector-panel">
              <PanelTitle icon={<Binary size={16} />} title="Session Inspector" />
              <Metric label="ratchet index" value={String(session.messageNumber)} />
              <Metric label="deleted keys" value={String(session.deletedKeys.length)} />
              <Metric
                label="last envelope"
                value={messages.at(-1) ? `${messages.at(-1)?.envelope.envelopeBytes} bytes` : "none"}
              />
              <Metric label="bob fingerprint" value={bundle.bob.fingerprint} />
              <div className="key-log">
                {session.deletedKeys.slice(-4).map((item) => (
                  <code key={item}>{item}</code>
                ))}
              </div>
            </aside>
          </section>
        </ConsoleLayout>
      )}

      {mode === "keygen" && bundle && (
        <ConsoleLayout
          title="Key Gen Process"
          subtitle="// protocol trace debugger"
          onBack={() => setMode("home")}
          onReset={resetDemo}
        >
          <section className="keygen-grid">
            <aside className="panel step-panel">
              <PanelTitle icon={<KeyRound size={16} />} title="Trace Steps" />
              {keygenSteps.map((step, index) => (
                <button
                  className={`step-button ${index === activeStep ? "active" : ""}`}
                  type="button"
                  key={step.title}
                  onClick={() => setActiveStep(index)}
                >
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  {step.title}
                </button>
              ))}
            </aside>

            <section className="panel trace-panel">
              <div className="trace-heading">
                <span className="label">Active step</span>
                <h2>{keygenSteps[activeStep]?.title}</h2>
              </div>
              {keygenSteps[activeStep] && <TraceStep step={keygenSteps[activeStep]} />}
              <div className="trace-actions">
                <button
                  className="terminal-button secondary compact"
                  type="button"
                  onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
                >
                  Prev
                </button>
                <button
                  className="terminal-button primary compact"
                  type="button"
                  onClick={() => setActiveStep(Math.min(keygenSteps.length - 1, activeStep + 1))}
                >
                  Next -&gt;
                </button>
              </div>
            </section>

            <aside className="panel inspector-panel">
              <PanelTitle icon={<ShieldCheck size={16} />} title="Verification" />
              <Metric label="alice fingerprint" value={bundle.alice.fingerprint} />
              <Metric label="bob fingerprint" value={bundle.bob.fingerprint} />
              <Metric
                label="prekey tamper"
                value={bundle.tamper.signedPreKeyRejected ? "rejected" : "failed"}
                tone={bundle.tamper.signedPreKeyRejected ? "good" : "bad"}
              />
              <Metric
                label="aad tamper"
                value={bundle.tamper.aadRejected ? "rejected" : "failed"}
                tone={bundle.tamper.aadRejected ? "good" : "bad"}
              />
            </aside>
          </section>
        </ConsoleLayout>
      )}
    </main>
  );
}

function ConsoleLayout({
  title,
  subtitle,
  children,
  onBack,
  onReset
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
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
        <button className="icon-button" type="button" onClick={onReset} aria-label="Reset demo">
          <RotateCcw size={18} />
        </button>
      </header>
      {children}
    </section>
  );
}

function PanelTitle({ icon, title }: { icon: React.ReactNode; title: string }) {
  return (
    <div className="panel-title">
      {icon}
      <span>{title}</span>
    </div>
  );
}

function ContactRow({
  name,
  detail,
  fingerprint,
  active = false
}: {
  name: string;
  detail: string;
  fingerprint: string;
  active?: boolean;
}) {
  return (
    <div className={`contact-row ${active ? "active" : ""}`}>
      <div>
        <strong>{name}</strong>
        <span>{detail}</span>
      </div>
      <code>{fingerprint}</code>
    </div>
  );
}

function Metric({ label, value, tone = "neutral" }: { label: string; value: string; tone?: "neutral" | "good" | "bad" }) {
  return (
    <div className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function TraceStep({ step }: { step: VerificationStep }) {
  return (
    <div className="trace-step">
      <Metric label="algorithm" value={step.algorithm} />
      <Metric label="input" value={step.input} />
      <Metric label="output" value={step.output} />
      <Metric label="verification" value={step.verification} tone={step.status === "success" ? "good" : "bad"} />
      <Metric label="tamper / failure mode" value={step.failureMode} tone={step.status === "fail" ? "bad" : "neutral"} />
      <div className={`verification-badge ${step.status}`}>
        {step.status === "success" ? <Check size={15} /> : <TriangleAlert size={15} />}
        {step.status === "success" ? "Verified" : "Rejected"}
      </div>
    </div>
  );
}
