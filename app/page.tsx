"use client";

import { useState } from "react";
import { KeyRound, MessageSquareText } from "lucide-react";
import ChatMode from "@/components/ChatMode";
import KeyGenMode from "@/components/KeyGenMode";

type Mode = "home" | "chat" | "keygen";

export default function Home() {
  const [mode, setMode] = useState<Mode>("home");

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
            <span>Handshake</span>
            <strong>X3DH (signed + one-time prekeys)</strong>
            <span>Ratchet</span>
            <strong>Double Ratchet, HMAC + ECDH</strong>
            <span>Cipher</span>
            <strong>AES-256-GCM, identity-bound AAD</strong>
          </div>
        </section>
      )}
      {mode === "chat" && <ChatMode onBack={() => setMode("home")} />}
      {mode === "keygen" && <KeyGenMode onBack={() => setMode("home")} />}
    </main>
  );
}
