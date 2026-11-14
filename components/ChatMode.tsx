"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Binary,
  Hourglass,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Skull,
  Smartphone,
  Terminal,
  TriangleAlert,
  Zap
} from "lucide-react";
import { Device, Envelope, KeyChangedError, PreKeyServer } from "@/lib/protocol/device";
import { safetyNumber } from "@/lib/protocol/identity";
import { base64ToBytes, bytesToBase64, preview, previewBytes } from "@/lib/protocol/primitives";
import { RatchetState, attackerRead } from "@/lib/protocol/ratchet";
import type { KeyEvent } from "@/lib/protocol/trace";
import { Badge, ConsoleLayout, Metric, PanelTitle } from "./ui";

type Party = "alice" | "bob";
const other = (party: Party): Party => (party === "alice" ? "bob" : "alice");
const NAMES: Record<string, string> = { alice: "Alice", bob: "Bob", mallory: "Mallory" };

type Item = {
  id: string;
  envelope: Envelope;
  from: Party;
  to: Party;
  text: string;
  status: "transit" | "delivered" | "rejected" | "intercepted";
  received?: string;
  error?: string;
  notes: string[];
  attacker?: { ok: boolean; text?: string; when: "past" | "live" };
};

type World = {
  server: PreKeyServer;
  alice: Device;
  bob: Device;
  mallory: Device;
  seized: RatchetState | null;
};

const DRAFTS: Record<Party, string[]> = {
  alice: ["Prekey bundle verified. Hi Bob!", "Did the slides upload?", "Meet at the lab at 6.", "ok"],
  bob: ["Got it, I was offline.", "Yes, all 16 slides.", "See you there.", "ok"]
};

async function createWorld(): Promise<World> {
  const server = new PreKeyServer();
  const [alice, bob, mallory] = await Promise.all([
    Device.create("alice", "Alice"),
    Device.create("bob", "Bob"),
    Device.create("mallory", "Mallory")
  ]);
  server.publish(alice);
  server.publish(bob);
  return { server, alice, bob, mallory, seized: null };
}

export default function ChatMode({ onBack }: { onBack: () => void }) {
  const world = useRef<World | null>(null);
  const [, setVersion] = useState(0);
  const refresh = useCallback(() => setVersion((v) => v + 1), []);
  const [items, setItems] = useState<Item[]>([]);
  const [sender, setSender] = useState<Party>("alice");
  const [draft, setDraft] = useState(DRAFTS.alice[0]);
  const [hold, setHold] = useState(false);
  const [padded, setPadded] = useState(true);
  const [notice, setNotice] = useState<{ tone: "warn" | "bad" | "info"; text: string } | null>(null);
  const [numbers, setNumbers] = useState<{ alice: string | null; bob: string | null }>({ alice: null, bob: null });
  const [busy, setBusy] = useState(false);

  const reset = useCallback(async () => {
    setBusy(true);
    world.current = await createWorld();
    setItems([]);
    setSender("alice");
    setDraft(DRAFTS.alice[0]);
    setNotice(null);
    setBusy(false);
    refresh();
  }, [refresh]);

  useEffect(() => {
    void reset();
  }, [reset]);

  const w = world.current;

  // Safety numbers as each side currently sees them.
  const aliceContact = w?.alice.contacts.get("bob");
  const bobContact = w?.bob.contacts.get("alice");
  useEffect(() => {
    if (!w) return;
    void (async () => {
      setNumbers({
        alice: aliceContact ? await safetyNumber(w.alice.identity.fingerprintBytes, aliceContact.fingerprintBytes) : null,
        bob: bobContact ? await safetyNumber(w.bob.identity.fingerprintBytes, bobContact.fingerprintBytes) : null
      });
    })();
  }, [w, aliceContact, bobContact, aliceContact?.fingerprint, bobContact?.fingerprint]);

  const patch = (id: string, change: Partial<Item>) =>
    setItems((current) => current.map((item) => (item.id === id ? { ...item, ...change } : item)));

  async function deliver(item: Item) {
    if (!w) return;
    const env = item.envelope;
    const target = env.deliverTo === "mallory" ? w.mallory : env.deliverTo === "alice" ? w.alice : w.bob;
    try {
      const result = await target.receive(env);
      const notes = [...item.notes];
      if (result.newSession) notes.push(`${NAMES[env.deliverTo]} ran X3DH from the prekey header`);
      if (result.ratcheted) notes.push("DH ratchet step");
      if (result.usedSkippedKey) notes.push("late message: stored key used, then erased");
      let attacker = item.attacker;
      if (w.seized && env.deliverTo === "bob" && !attacker) {
        const read = await attackerRead(w.seized, "to-victim", env.header, env.ciphertext);
        if (read.ok) w.seized = read.state;
        attacker = { ok: read.ok, text: read.plaintext, when: "live" };
      }
      patch(item.id, {
        status: env.deliverTo === "mallory" ? "intercepted" : "delivered",
        received: result.plaintext,
        notes,
        attacker
      });
    } catch (error) {
      patch(item.id, { status: "rejected", error: (error as Error).message });
    }
    refresh();
  }

  async function send() {
    if (!w || !draft.trim() || busy) return;
    setBusy(true);
    setNotice(null);
    const from = sender;
    const to = other(from);
    try {
      const envelope = await w[from].send(w.server, to, draft.trim(), { padded });
      const notes: string[] = [];
      if (envelope.preKey) notes.push(`prekey message (OPK #${envelope.preKey.oneTimePreKeyId ?? "none"})`);
      let attacker: Item["attacker"];
      if (w.seized && from === "bob") {
        const read = await attackerRead(w.seized, "from-victim", envelope.header, envelope.ciphertext);
        attacker = { ok: read.ok, text: read.plaintext, when: "live" };
      }
      const item: Item = { id: envelope.id, envelope, from, to, text: draft.trim(), status: "transit", notes, attacker };
      setItems((current) => [...current, item]);
      const pool = DRAFTS[from];
      setDraft(pool[(pool.indexOf(draft.trim()) + 1) % pool.length]);
      if (!hold) await deliver(item);
    } catch (error) {
      if (error instanceof KeyChangedError) {
        setNotice({
          tone: "bad",
          text: `${NAMES[from]} refused to send: ${NAMES[to]}'s safety number changed. Compare it with ${NAMES[to]} before accepting the new key.`
        });
      } else {
        setNotice({ tone: "bad", text: (error as Error).message });
      }
    }
    setBusy(false);
    refresh();
  }

  async function bobReinstalls() {
    if (!w) return;
    setBusy(true);
    w.bob = await Device.create("bob", "Bob");
    w.server.publish(w.bob);
    w.alice.dropSession("bob");
    w.seized = null;
    setNotice({
      tone: "warn",
      text: "Bob reinstalled: new identity key, old sessions gone. Alice's next message fetches the new bundle and hits a key-change warning."
    });
    setBusy(false);
    refresh();
  }

  function serverSwapsKeys() {
    if (!w) return;
    w.server.substitute("bob", w.mallory);
    w.alice.dropSession("bob");
    setNotice({
      tone: "warn",
      text: aliceContact
        ? "The server now hands out Mallory's keys for Bob. Alice has Bob's key pinned, so her next send is blocked."
        : "The server now hands out Mallory's keys for Bob. This is first contact, so TOFU will accept them silently. Only the safety numbers show it."
    });
    refresh();
  }

  function serverBehaves() {
    if (!w) return;
    w.server.publish(w.bob);
    w.alice.dropSession("bob");
    setNotice({ tone: "info", text: "The server publishes Bob's real bundle again. Alice's next message starts a new session." });
    refresh();
  }

  async function seizeBob() {
    if (!w) return;
    const snapshot = w.bob.snapshot("alice");
    if (!snapshot) {
      setNotice({ tone: "info", text: "Bob has no session yet: exchange a message first." });
      return;
    }
    w.seized = snapshot;
    const evaluated = await Promise.all(
      items.map(async (item) => {
        if (item.envelope.deliverTo === "mallory") return item;
        const read = await attackerRead(
          snapshot,
          item.from === "bob" ? "from-victim" : "to-victim",
          item.envelope.header,
          item.envelope.ciphertext
        );
        return { ...item, attacker: { ok: read.ok, text: read.plaintext, when: "past" as const } };
      })
    );
    setItems(evaluated);
    const exposed = evaluated.filter((item) => item.attacker?.ok).length;
    setNotice({
      tone: "warn",
      text: `Bob's phone was imaged. Of ${evaluated.length} earlier message(s), the attacker can read ${exposed}${exposed ? " (only ones still in transit, whose keys were never erased)" : ""}. Keep chatting to watch the session heal.`
    });
    refresh();
  }

  if (!w) {
    return (
      <ConsoleLayout title="Chat Mode" subtitle="// generating keys" onBack={onBack} onReset={reset}>
        <div className="panel empty-state">Generating identity keys and prekeys...</div>
      </ConsoleLayout>
    );
  }

  const me = w[sender];
  const peer = other(sender);
  const contact = me.contacts.get(peer);
  const session = me.sessions.get(peer);
  const ratchet = session?.ratchet;
  const numbersMatch = numbers.alice !== null && numbers.alice === numbers.bob;
  const substituted = w.server.isSubstituted("bob");

  const trustBadge = !contact ? (
    <Badge>no contact yet</Badge>
  ) : contact.status === "changed" ? (
    <Badge tone="bad">key changed</Badge>
  ) : contact.status === "verified" ? (
    <Badge tone="good">verified</Badge>
  ) : (
    <Badge tone="info">TOFU, unverified</Badge>
  );

  const sessionLog = (ratchet?.log ?? []).slice(-6).reverse();
  const deviceLog = me.log.slice(-4).reverse();

  return (
    <ConsoleLayout title="Chat Mode" subtitle="// alice and bob, end to end" onBack={onBack} onReset={reset}>
      <section className="chat-grid">
        <aside className="panel contacts-panel">
          <PanelTitle icon={<ShieldCheck size={16} />} title={`${NAMES[sender]}'s contact`} />
          <div className={`contact-row active ${contact?.status === "changed" ? "danger" : ""}`}>
            <div>
              <strong>{NAMES[peer]}</strong>
              {trustBadge}
            </div>
            <code>{contact?.fingerprint ?? "fetched on first message"}</code>
            {contact?.pending && (
              <>
                <span className="small-label">server now presents</span>
                <code className="bad-text">{contact.pending.fingerprint}</code>
              </>
            )}
            <div className="row-actions">
              {contact?.status === "changed" ? (
                <button className="terminal-button danger compact" type="button" onClick={() => { me.acceptKeyChange(peer); refresh(); }}>
                  Accept new key
                </button>
              ) : (
                contact && contact.status !== "verified" && (
                  <button className="terminal-button secondary compact" type="button" onClick={() => { me.markVerified(peer); refresh(); }}>
                    Mark verified
                  </button>
                )
              )}
            </div>
          </div>

          <PanelTitle icon={<Binary size={16} />} title="Safety numbers" />
          <div className="safety">
            <span>Alice sees</span>
            <code>{numbers.alice ?? "no session"}</code>
            <span>Bob sees</span>
            <code>{numbers.bob ?? "no session"}</code>
            {numbers.alice && numbers.bob && (
              <Badge tone={numbersMatch ? "good" : "bad"}>{numbersMatch ? "match: no MITM" : "mismatch: someone is in the middle"}</Badge>
            )}
            <p className="hint">Compare these in person or over a call before marking a contact verified.</p>
          </div>

          <PanelTitle icon={<Skull size={16} />} title="Attack lab" />
          <div className="attack-stack">
            {substituted ? (
              <button className="terminal-button secondary compact" type="button" onClick={serverBehaves}>
                Server stops attacking
              </button>
            ) : (
              <button className="terminal-button danger compact" type="button" onClick={serverSwapsKeys}>
                <ShieldAlert size={14} /> Server swaps Bob&apos;s keys
              </button>
            )}
            <button className="terminal-button danger compact" type="button" onClick={bobReinstalls} disabled={busy}>
              <Smartphone size={14} /> Bob reinstalls app
            </button>
            <button className="terminal-button danger compact" type="button" onClick={seizeBob} disabled={busy || Boolean(w.seized)}>
              <Skull size={14} /> {w.seized ? "Bob's phone seized" : "Seize Bob's phone"}
            </button>
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
            {notice && <div className={`notice ${notice.tone}`}><TriangleAlert size={15} /> {notice.text}</div>}
            {items.length === 0 ? (
              <div className="empty-state">
                <Terminal size={28} />
                <p>
                  Bob is offline. Alice can still start a session from his prekey bundle. Send a message, switch
                  to Bob to reply, hold a message in transit to see out-of-order delivery, or try the attack lab.
                </p>
              </div>
            ) : (
              items.map((item) => <MessageCard key={item.id} item={item} onDeliver={() => deliver(item)} />)
            )}
          </div>

          <div className="composer-wrap">
            <div className="composer-options">
              <div className="segmented" role="group" aria-label="Send as">
                {(["alice", "bob"] as Party[]).map((party) => (
                  <button
                    key={party}
                    type="button"
                    className={sender === party ? "active" : ""}
                    onClick={() => {
                      setSender(party);
                      setDraft(DRAFTS[party][0]);
                    }}
                  >
                    {NAMES[party]}
                  </button>
                ))}
              </div>
              <label className="check">
                <input type="checkbox" checked={hold} onChange={(event) => setHold(event.target.checked)} />
                hold in transit
              </label>
              <label className="check">
                <input type="checkbox" checked={padded} onChange={(event) => setPadded(event.target.checked)} />
                pad length
              </label>
            </div>
            <form
              className="composer"
              onSubmit={(event) => {
                event.preventDefault();
                void send();
              }}
            >
              <input value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="type secure message" aria-label="Message" />
              <button className="terminal-button primary compact" type="submit" disabled={busy}>
                <Zap size={15} />
                {NAMES[sender]}: Encrypt + Send
              </button>
            </form>
          </div>
        </section>

        <aside className="panel inspector-panel">
          <PanelTitle icon={<Binary size={16} />} title={`${NAMES[sender]}'s session`} />
          {ratchet ? (
            <>
              <div className="metric-grid">
                <Metric label="DH ratchet steps" value={ratchet.dhRatchetSteps} />
                <Metric label="send n / recv n" value={`${ratchet.Ns} / ${ratchet.Nr}`} />
                <Metric label="prev chain (PN)" value={ratchet.PN} />
                <Metric label="stored late keys" value={ratchet.skipped.size} tone={ratchet.skipped.size ? "warn" : "neutral"} />
              </div>
              <Metric label="my ratchet key" value={previewBytes(ratchet.DHs.publicBytes)} />
              <Metric label="their ratchet key" value={ratchet.DHr ? previewBytes(base64ToBytes(ratchet.DHr)) : "not yet"} />
              <Metric label="root key" value={previewBytes(ratchet.RK)} />
              <Metric label="send / recv chain" value={`${previewBytes(ratchet.CKs, 6, 4)} / ${previewBytes(ratchet.CKr, 6, 4)}`} />
              {session?.preKeyHeader && <Metric label="status" value="waiting for first reply (prekey header attached)" tone="info" />}
            </>
          ) : (
            <Metric label="session" value={`none: ${NAMES[sender]}'s first message will run X3DH`} />
          )}
          <Metric label="Bob's one-time prekeys on server" value={w.server.oneTimePreKeysLeft("bob")} />
          {w.seized && <Metric label="attacker" value="holds a copy of Bob's state" tone="bad" />}
          <KeyLog title="session keys (newest first)" events={sessionLog} />
          <KeyLog title="device keys (newest first)" events={deviceLog} />
        </aside>
      </section>
    </ConsoleLayout>
  );
}

function KeyLog({ title, events }: { title: string; events: KeyEvent[] }) {
  if (!events.length) return null;
  return (
    <>
      <span className="small-label">{title}</span>
      <div className="key-log">
        {events.map((event, index) => (
          <code key={`${event.label}-${index}`} className={event.kind}>
            <b>{event.kind}</b> {event.label} <i>{event.preview}</i>
          </code>
        ))}
      </div>
    </>
  );
}

function MessageCard({ item, onDeliver }: { item: Item; onDeliver: () => void }) {
  const env = item.envelope;
  const label = `${NAMES[item.from]} -> ${NAMES[item.to]}`;
  return (
    <article className={`message ${item.from === "alice" ? "sent" : "received"} ${item.status}`}>
      <div className="message-top">
        <span>{label}</span>
        {item.status === "transit" && <Badge tone="warn"><Hourglass size={11} /> in transit</Badge>}
        {item.status === "delivered" && <Badge tone="good">decrypted by {NAMES[env.deliverTo]}</Badge>}
        {item.status === "intercepted" && <Badge tone="bad">delivered to Mallory</Badge>}
        {item.status === "rejected" && <Badge tone="bad">rejected</Badge>}
      </div>
      <p>
        {item.status === "transit" && <span className="dim">[encrypted; {NAMES[item.from]} typed: </span>}
        {item.status === "transit" ? <span className="dim">{item.text}]</span> : item.status === "rejected" ? <span className="bad-text">{item.error}</span> : item.received}
      </p>
      {item.status === "intercepted" && (
        <p className="bad-text small">Mallory decrypted this with the keys the server swapped in. Bob never received it.</p>
      )}
      <code>{preview(bytesToBase64(env.ciphertext), 22, 12)}</code>
      <div className="message-meta">
        n={env.header.n} pn={env.header.pn} · ratchet {preview(env.header.dh, 0, 8)} · {env.plaintextBytes} B text → {env.ciphertext.byteLength} B
        ciphertext{env.header.padded ? " (padded)" : " (unpadded: exact length leaks)"} · ~{env.wireBytes} B on wire
      </div>
      {(item.notes.length > 0 || item.attacker) && (
        <div className="badges">
          {item.notes.map((note) => (
            <Badge key={note} tone="info">{note}</Badge>
          ))}
          {item.attacker && (
            <Badge tone={item.attacker.ok ? "bad" : "good"}>
              {item.attacker.ok ? `attacker reads: "${item.attacker.text}"` : `attacker can't decrypt${item.attacker.when === "past" ? " (forward secrecy)" : " (healed)"}`}
            </Badge>
          )}
        </div>
      )}
      {item.status === "transit" && (
        <button className="terminal-button secondary compact deliver" type="button" onClick={onDeliver}>
          Deliver now
        </button>
      )}
    </article>
  );
}
