import { Identity, generateIdentity, publicIdentity } from "./identity";
import { bytesToBase64, erasePrivate, equalBytes } from "./primitives";
import { Header, RatchetState, cloneState, initInitiator, initResponder, ratchetDecrypt, ratchetEncrypt } from "./ratchet";
import { KeyEvent, Trace } from "./trace";
import {
  OneTimePreKey,
  PreKeyBundle,
  PreKeyHeader,
  SignedPreKey,
  generateOneTimePreKeys,
  generateSignedPreKey,
  initiateX3dh,
  respondX3dh
} from "./x3dh";

export type UserId = string;

/** What crosses the network. The server sees all of this; none of it reveals plaintext. */
export type Envelope = {
  id: string;
  from: UserId;
  /** Who the sender thinks they're talking to. */
  to: UserId;
  /** Where the server actually delivers it (differs only when the server is malicious). */
  deliverTo: UserId;
  preKey: PreKeyHeader | null;
  header: Header;
  ciphertext: Uint8Array;
  plaintextBytes: number;
  wireBytes: number;
};

type StoredBundle = {
  owner: UserId;
  identity: PreKeyBundle["identity"];
  signedPreKey: PreKeyBundle["signedPreKey"];
  oneTimePreKeys: { id: number; publicBytes: Uint8Array }[];
};

/**
 * Untrusted relay + key directory. It hands out one one-time prekey per fetch and can be told
 * to misbehave (swap a user's bundle) so the UI can show what authentication catches.
 */
export class PreKeyServer {
  private bundles = new Map<UserId, StoredBundle>();

  publish(owner: Device) {
    this.bundles.set(owner.id, owner.exportBundle());
  }

  /** Malicious server: answer requests for `victim` with `attacker`'s keys. */
  substitute(victim: UserId, attacker: Device) {
    this.bundles.set(victim, attacker.exportBundle());
  }

  isSubstituted(user: UserId) {
    const stored = this.bundles.get(user);
    return Boolean(stored && stored.owner !== user);
  }

  fetch(user: UserId): { bundle: PreKeyBundle; owner: UserId } {
    const stored = this.bundles.get(user);
    if (!stored) throw new Error(`No prekey bundle published for ${user}.`);
    const oneTimePreKey = stored.oneTimePreKeys.shift() ?? null;
    return {
      owner: stored.owner,
      bundle: { identity: stored.identity, signedPreKey: stored.signedPreKey, oneTimePreKey }
    };
  }

  oneTimePreKeysLeft(user: UserId) {
    return this.bundles.get(user)?.oneTimePreKeys.length ?? 0;
  }
}

export type TrustStatus = "tofu" | "verified" | "changed";

export type Contact = {
  fingerprint: string;
  fingerprintBytes: Uint8Array;
  status: TrustStatus;
  /** A new fingerprint the server presented that doesn't match the pinned one. */
  pending?: { fingerprint: string; fingerprintBytes: Uint8Array };
};

export type Session = {
  ratchet: RatchetState;
  remoteFingerprint: string;
  remoteFingerprintBytes: Uint8Array;
  /** Resent with every message until the peer replies (they may have been offline). */
  preKeyHeader: PreKeyHeader | null;
  /** Ephemeral key that created this session, to recognise retransmitted prekey messages. */
  origin: string;
  routeTo: UserId;
};

export class KeyChangedError extends Error {
  constructor(public peer: UserId, public pinned: string, public presented: string) {
    super(`${peer}'s identity key changed: pinned ${pinned}, server now presents ${presented}.`);
  }
}

export class Device {
  sessions = new Map<UserId, Session>();
  contacts = new Map<UserId, Contact>();
  log: KeyEvent[] = [];
  private signedPreKeys = new Map<number, SignedPreKey>();
  private oneTimePreKeys = new Map<number, OneTimePreKey>();
  private nextPreKeyId = 1;

  private constructor(public id: UserId, public name: string, public identity: Identity) {}

  static async create(id: UserId, name: string, oneTimePreKeyCount = 5): Promise<Device> {
    const device = new Device(id, name, await generateIdentity());
    device.log.push({ kind: "created", label: "Identity key pair", preview: device.identity.signing.privatePreview });
    const spk = await generateSignedPreKey(device.identity, 1);
    device.signedPreKeys.set(spk.id, spk);
    device.log.push({ kind: "created", label: `Signed prekey #${spk.id}`, preview: spk.pair.privatePreview });
    await device.topUpPreKeys(oneTimePreKeyCount);
    return device;
  }

  async topUpPreKeys(count: number) {
    for (const key of await generateOneTimePreKeys(this.nextPreKeyId, count)) {
      this.oneTimePreKeys.set(key.id, key);
    }
    this.nextPreKeyId += count;
    this.log.push({ kind: "created", label: `${count} one-time prekeys`, preview: `#${this.nextPreKeyId - count}..#${this.nextPreKeyId - 1}` });
  }

  get oneTimePreKeyCount() {
    return this.oneTimePreKeys.size;
  }

  exportBundle(): StoredBundle {
    const spk = Array.from(this.signedPreKeys.values()).at(-1)!;
    return {
      owner: this.id,
      identity: publicIdentity(this.identity),
      signedPreKey: { id: spk.id, publicBytes: spk.pair.publicBytes, signature: spk.signature },
      oneTimePreKeys: Array.from(this.oneTimePreKeys.values(), (key) => ({ id: key.id, publicBytes: key.pair.publicBytes }))
    };
  }

  /** Trust-on-first-use: pin the first fingerprint; flag (don't silently accept) any later change. */
  private checkTrust(peer: UserId, fingerprint: string, fingerprintBytes: Uint8Array, strict: boolean) {
    const contact = this.contacts.get(peer);
    if (!contact) {
      this.contacts.set(peer, { fingerprint, fingerprintBytes, status: "tofu" });
      return;
    }
    if (equalBytes(contact.fingerprintBytes, fingerprintBytes)) return;
    contact.status = "changed";
    contact.pending = { fingerprint, fingerprintBytes };
    if (strict) throw new KeyChangedError(peer, contact.fingerprint, fingerprint);
  }

  acceptKeyChange(peer: UserId) {
    const contact = this.contacts.get(peer);
    if (!contact?.pending) return;
    contact.fingerprint = contact.pending.fingerprint;
    contact.fingerprintBytes = contact.pending.fingerprintBytes;
    contact.pending = undefined;
    contact.status = "tofu";
    this.sessions.delete(peer);
  }

  markVerified(peer: UserId) {
    const contact = this.contacts.get(peer);
    if (contact && contact.status !== "changed") contact.status = "verified";
  }

  /** The peer reinstalled: the old session can't be continued. */
  dropSession(peer: UserId) {
    this.sessions.delete(peer);
  }

  async send(
    server: PreKeyServer,
    to: UserId,
    plaintext: string,
    options: { padded?: boolean; trace?: Trace } = {}
  ): Promise<Envelope> {
    const contact = this.contacts.get(to);
    if (contact?.status === "changed") {
      throw new KeyChangedError(to, contact.fingerprint, contact.pending?.fingerprint ?? "unknown");
    }
    let session = this.sessions.get(to);
    if (!session) {
      const { bundle, owner } = server.fetch(to);
      const x3dh = await initiateX3dh(this.identity, bundle, to.charAt(0).toUpperCase() + to.slice(1), options.trace, this.log);
      this.checkTrust(to, x3dh.remoteFingerprint, x3dh.remoteFingerprintBytes, true);
      session = {
        ratchet: await initInitiator(x3dh.sharedKey, x3dh.remoteSignedPreKey, x3dh.associatedData, options.trace),
        remoteFingerprint: x3dh.remoteFingerprint,
        remoteFingerprintBytes: x3dh.remoteFingerprintBytes,
        preKeyHeader: x3dh.header,
        origin: bytesToBase64(x3dh.header.ephemeralPublic),
        routeTo: owner
      };
      this.sessions.set(to, session);
    }
    const sealed = await ratchetEncrypt(session.ratchet, plaintext, {
      padded: options.padded,
      trace: options.trace,
      actor: this.name
    });
    session.ratchet = sealed.state;
    const wireBytes =
      sealed.ciphertext.byteLength +
      JSON.stringify(sealed.header).length +
      (session.preKeyHeader ? 91 * 3 + 72 + 8 : 0); // three SPKI keys + signature + ids
    return {
      id: crypto.randomUUID(),
      from: this.id,
      to,
      deliverTo: session.routeTo,
      preKey: session.preKeyHeader,
      header: sealed.header,
      ciphertext: sealed.ciphertext,
      plaintextBytes: new TextEncoder().encode(plaintext).byteLength,
      wireBytes
    };
  }

  async receive(
    envelope: Envelope,
    options: { trace?: Trace } = {}
  ): Promise<{ plaintext: string; usedSkippedKey: boolean; ratcheted: boolean; newSession: boolean }> {
    const peer = envelope.from;
    let session = this.sessions.get(peer);
    let newSession = false;
    const pendingOneTime = new Map(this.oneTimePreKeys);
    const pendingLog: KeyEvent[] = [];

    if (envelope.preKey && (!session || session.origin !== bytesToBase64(envelope.preKey.ephemeralPublic))) {
      const x3dh = await respondX3dh(
        this.identity,
        this.signedPreKeys,
        pendingOneTime,
        envelope.preKey,
        options.trace,
        pendingLog
      );
      session = {
        ratchet: initResponder(x3dh.sharedKey, x3dh.signedPreKey.pair, x3dh.associatedData),
        remoteFingerprint: x3dh.remoteFingerprint,
        remoteFingerprintBytes: x3dh.remoteFingerprintBytes,
        preKeyHeader: null,
        origin: bytesToBase64(envelope.preKey.ephemeralPublic),
        routeTo: peer
      };
      newSession = true;
    }
    if (!session) throw new Error(`No session with ${peer} and no prekey header to start one.`);

    const opened = await ratchetDecrypt(session.ratchet, envelope.header, envelope.ciphertext, {
      trace: options.trace,
      actor: this.name
    });

    // Commit only after the message authenticated.
    if (newSession) {
      this.checkTrust(peer, session.remoteFingerprint, session.remoteFingerprintBytes, false);
      for (const id of this.oneTimePreKeys.keys()) {
        if (!pendingOneTime.has(id)) {
          const key = this.oneTimePreKeys.get(id)!;
          erasePrivate(key.pair);
        }
      }
      this.oneTimePreKeys = pendingOneTime;
      this.log.push(...pendingLog);
    }
    session.ratchet = opened.state;
    session.preKeyHeader = null; // hearing from the peer proves they have the session
    this.sessions.set(peer, session);
    return { plaintext: opened.plaintext, usedSkippedKey: opened.usedSkippedKey, ratcheted: opened.ratcheted, newSession };
  }

  /** Copy of the live ratchet state, as an attacker who images the device would get it. */
  snapshot(peer: UserId): RatchetState | null {
    const session = this.sessions.get(peer);
    return session ? cloneState(session.ratchet) : null;
  }
}
