import {
  KeyPair,
  aesGcmDecrypt,
  aesGcmEncrypt,
  base64ToBytes,
  bytesToBase64,
  concatBytes,
  dh,
  fromUtf8,
  generateAgreementKeyPair,
  hkdf,
  hmac,
  importAgreementPublic,
  pad,
  previewBytes,
  unpad,
  utf8,
  wipe
} from "./primitives";
import { KeyEvent, Trace } from "./trace";

/**
 * Double Ratchet, following Signal's spec (Perrin & Marlinspike) with P-256 in place of X25519.
 *
 * - Symmetric ratchet: every message moves the chain key one way through HMAC, so a stolen
 *   current chain key can't be run backwards (forward secrecy).
 * - DH ratchet: each reply brings a fresh DH key into the root key, so a stolen state stops
 *   working after one round trip (post-compromise "healing").
 * - Skipped keys: late or out-of-order messages still decrypt. This fixes the late-message
 *   problem of time-based key deletion (Canetti et al.) without full puncturable encryption.
 *
 * Every operation works on a copy and only returns the new state on success, so a forged or
 * corrupted message can never damage a session.
 */

export const MAX_SKIP = 50;

export type Header = {
  /** Sender's current ratchet public key (SPKI, base64). */
  dh: string;
  /** Length of the sender's previous sending chain. */
  pn: number;
  /** Message number in the current sending chain. */
  n: number;
  /** Whether the plaintext was length-padded before encryption. */
  padded: boolean;
};

export type RatchetState = {
  DHs: KeyPair;
  DHr: string | null;
  RK: Uint8Array;
  CKs: Uint8Array | null;
  CKr: Uint8Array | null;
  Ns: number;
  Nr: number;
  PN: number;
  skipped: Map<string, Uint8Array>;
  associatedData: Uint8Array;
  log: KeyEvent[];
  dhRatchetSteps: number;
};

export type RatchetCiphertext = { header: Header; ciphertext: Uint8Array };

const RK_INFO = "CIM-ratchet-root";
const MSG_INFO = "CIM-message-keys";

export function cloneState(state: RatchetState): RatchetState {
  return {
    ...state,
    DHs: { ...state.DHs },
    RK: state.RK.slice(),
    CKs: state.CKs?.slice() ?? null,
    CKr: state.CKr?.slice() ?? null,
    skipped: new Map(Array.from(state.skipped, ([k, v]) => [k, v.slice()])),
    log: [...state.log]
  };
}

async function kdfRoot(rootKey: Uint8Array, dhOut: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
  const out = await hkdf(dhOut, rootKey, RK_INFO, 64);
  wipe(dhOut);
  return [out.slice(0, 32), out.slice(32)];
}

/** KDF_CK: message key = HMAC(CK, 0x01), next chain key = HMAC(CK, 0x02). */
export async function kdfChain(chainKey: Uint8Array): Promise<[Uint8Array, Uint8Array]> {
  const messageKey = await hmac(chainKey, Uint8Array.of(0x01));
  const nextChain = await hmac(chainKey, Uint8Array.of(0x02));
  return [nextChain, messageKey];
}

export const encodeHeader = (header: Header) =>
  utf8(JSON.stringify([header.dh, header.pn, header.n, header.padded ? 1 : 0]));

async function seal(messageKey: Uint8Array, plaintext: Uint8Array, aad: Uint8Array) {
  const material = await hkdf(messageKey, new Uint8Array(32), MSG_INFO, 44);
  // A message key is used exactly once, so a deterministic IV derived from it is safe.
  const ciphertext = await aesGcmEncrypt(material.slice(0, 32), material.slice(32), plaintext, aad);
  wipe(material);
  return ciphertext;
}

async function open(messageKey: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array) {
  const material = await hkdf(messageKey, new Uint8Array(32), MSG_INFO, 44);
  try {
    return await aesGcmDecrypt(material.slice(0, 32), material.slice(32), ciphertext, aad);
  } finally {
    wipe(material);
  }
}

const skipKey = (dhPub: string, n: number) => `${dhPub}:${n}`;

export async function initInitiator(
  sharedKey: Uint8Array,
  remoteSignedPreKey: Uint8Array,
  associatedData: Uint8Array,
  trace?: Trace
): Promise<RatchetState> {
  const DHs = await generateAgreementKeyPair();
  const remote = await importAgreementPublic(remoteSignedPreKey);
  const [RK, CKs] = await kdfRoot(sharedKey, await dh(DHs.privateKey, remote));
  trace?.push({
    title: "Alice starts the Double Ratchet",
    actor: "Alice",
    algorithm: "ECDH P-256 + HKDF-SHA256 (KDF_RK)",
    input: `SK as root key, new ratchet key ${previewBytes(DHs.publicBytes)}, Bob's SPK as first remote ratchet key`,
    output: `Root ${previewBytes(RK)} / sending chain ${previewBytes(CKs)}`,
    verification: "Alice can send immediately without waiting for Bob to come online.",
    failureMode: "Sending everything under SK alone would expose the whole conversation if SK leaked.",
    status: "success",
    paper: "Unger et al. 2015; Onik et al. 2025"
  });
  return {
    DHs,
    DHr: bytesToBase64(remoteSignedPreKey),
    RK,
    CKs,
    CKr: null,
    Ns: 0,
    Nr: 0,
    PN: 0,
    skipped: new Map(),
    associatedData,
    log: [{ kind: "created", label: "Ratchet key pair #1", preview: DHs.privatePreview }],
    dhRatchetSteps: 1
  };
}

export function initResponder(sharedKey: Uint8Array, signedPreKey: KeyPair, associatedData: Uint8Array): RatchetState {
  return {
    DHs: { ...signedPreKey },
    DHr: null,
    RK: sharedKey.slice(),
    CKs: null,
    CKr: null,
    Ns: 0,
    Nr: 0,
    PN: 0,
    skipped: new Map(),
    associatedData,
    log: [],
    dhRatchetSteps: 0
  };
}

export async function ratchetEncrypt(
  input: RatchetState,
  plaintext: string,
  options: { padded?: boolean; trace?: Trace; actor?: string } = {}
): Promise<{ state: RatchetState } & RatchetCiphertext> {
  const state = cloneState(input);
  if (!state.CKs) throw new Error("No sending chain yet: wait for the first message from the other side.");
  const [nextChain, messageKey] = await kdfChain(state.CKs);
  const padded = options.padded ?? true;
  const header: Header = { dh: bytesToBase64(state.DHs.publicBytes), pn: state.PN, n: state.Ns, padded };
  const body = padded ? pad(utf8(plaintext)) : utf8(plaintext);
  const ciphertext = await seal(messageKey, body, concatBytes(state.associatedData, encodeHeader(header)));

  options.trace?.push({
    title: `${options.actor ?? "Sender"} derives message key #${state.Ns} and encrypts`,
    actor: options.actor ?? "Sender",
    algorithm: "HMAC-SHA256 chain step + HKDF + AES-256-GCM",
    input: `Chain key ${previewBytes(state.CKs)}; plaintext ${utf8(plaintext).byteLength} B${padded ? ` padded to ${body.byteLength} B` : ""}; AAD = both identities + header`,
    output: `Ciphertext ${previewBytes(ciphertext)} (${ciphertext.byteLength} B incl. 16 B tag); next chain ${previewBytes(nextChain)}`,
    verification: "The message key is used once and erased; the chain key only moves forward.",
    failureMode: "Changing a ciphertext byte, the header, or the identity AAD makes the GCM tag check fail.",
    status: "success",
    paper: "Adebayo 2025 (AES-GCM); Frosch et al. 2016 (identity binding)"
  });

  state.log.push({ kind: "erased", label: `Sending message key ${state.dhRatchetSteps}.${state.Ns}`, preview: previewBytes(messageKey) });
  wipe(messageKey);
  state.CKs = nextChain;
  state.Ns += 1;
  return { state, header, ciphertext };
}

async function skipMessageKeys(state: RatchetState, until: number) {
  if (state.Nr + MAX_SKIP < until) throw new Error(`Refusing to skip more than ${MAX_SKIP} message keys.`);
  if (!state.CKr) return;
  while (state.Nr < until) {
    const [nextChain, messageKey] = await kdfChain(state.CKr);
    state.skipped.set(skipKey(state.DHr!, state.Nr), messageKey);
    state.log.push({ kind: "skipped", label: `Stored key for late message ${state.dhRatchetSteps}.${state.Nr}`, preview: previewBytes(messageKey) });
    state.CKr = nextChain;
    state.Nr += 1;
  }
}

async function dhRatchetStep(state: RatchetState, header: Header) {
  state.PN = state.Ns;
  state.Ns = 0;
  state.Nr = 0;
  state.DHr = header.dh;
  const remote = await importAgreementPublic(base64ToBytes(header.dh));
  [state.RK, state.CKr] = await kdfRoot(state.RK, await dh(state.DHs.privateKey, remote));
  state.log.push({ kind: "erased", label: "Old ratchet private key", preview: state.DHs.privatePreview });
  state.DHs = await generateAgreementKeyPair();
  state.dhRatchetSteps += 1;
  state.log.push({ kind: "ratchet", label: `DH ratchet step -> key pair #${state.dhRatchetSteps}`, preview: state.DHs.privatePreview });
  [state.RK, state.CKs] = await kdfRoot(state.RK, await dh(state.DHs.privateKey, remote));
}

export async function ratchetDecrypt(
  input: RatchetState,
  header: Header,
  ciphertext: Uint8Array,
  options: { trace?: Trace; actor?: string } = {}
): Promise<{ state: RatchetState; plaintext: string; usedSkippedKey: boolean; ratcheted: boolean }> {
  const state = cloneState(input);
  const aad = concatBytes(state.associatedData, encodeHeader(header));
  const finish = (body: Uint8Array) => fromUtf8(header.padded ? unpad(body) : body);

  const stored = state.skipped.get(skipKey(header.dh, header.n));
  if (stored) {
    const body = await open(stored, ciphertext, aad);
    state.skipped.delete(skipKey(header.dh, header.n));
    state.log.push({ kind: "erased", label: `Late message key ${header.n} used and erased`, preview: previewBytes(stored) });
    wipe(stored);
    return { state, plaintext: finish(body), usedSkippedKey: true, ratcheted: false };
  }

  let ratcheted = false;
  if (header.dh !== state.DHr) {
    await skipMessageKeys(state, header.pn);
    await dhRatchetStep(state, header);
    ratcheted = true;
  }
  await skipMessageKeys(state, header.n);
  const [nextChain, messageKey] = await kdfChain(state.CKr!);
  const body = await open(messageKey, ciphertext, aad); // throws on any tampering; `input` is untouched
  const plaintext = finish(body);
  options.trace?.push({
    title: `${options.actor ?? "Receiver"} decrypts message #${header.n}`,
    actor: options.actor ?? "Receiver",
    algorithm: ratcheted ? "DH ratchet step + HMAC chain + AES-256-GCM" : "HMAC chain + AES-256-GCM",
    input: `Header dh ${previewBytes(base64ToBytes(header.dh))}, n=${header.n}, pn=${header.pn}`,
    output: `GCM tag valid. ${body.byteLength} B recovered: "${plaintext}"`,
    verification: ratcheted
      ? "New remote ratchet key seen: root key mixed with a fresh DH, receiving chain restarted."
      : "Same remote ratchet key: receiving chain advanced one step.",
    failureMode: "A forged message fails the tag check and the session state is left unchanged.",
    status: "success"
  });
  state.log.push({ kind: "erased", label: `Receiving message key ${state.dhRatchetSteps}.${header.n}`, preview: previewBytes(messageKey) });
  wipe(messageKey);
  state.CKr = nextChain;
  state.Nr += 1;
  return { state, plaintext, usedSkippedKey: false, ratcheted };
}

/**
 * What an attacker who copied a device's ratchet state can read. Messages *to* the victim are
 * tried as the victim would; messages *from* the victim are readable only while they still use
 * the stolen sending chain.
 */
export async function attackerRead(
  stolen: RatchetState,
  direction: "to-victim" | "from-victim",
  header: Header,
  ciphertext: Uint8Array
): Promise<{ ok: boolean; plaintext?: string; state: RatchetState }> {
  try {
    if (direction === "to-victim") {
      const result = await ratchetDecrypt(stolen, header, ciphertext);
      return { ok: true, plaintext: result.plaintext, state: result.state };
    }
    if (!stolen.CKs || header.dh !== bytesToBase64(stolen.DHs.publicBytes) || header.n < stolen.Ns) {
      return { ok: false, state: stolen };
    }
    let chain: Uint8Array = stolen.CKs.slice();
    let messageKey: Uint8Array = new Uint8Array();
    for (let i = stolen.Ns; i <= header.n; i += 1) [chain, messageKey] = await kdfChain(chain);
    const body = await open(messageKey, ciphertext, concatBytes(stolen.associatedData, encodeHeader(header)));
    return { ok: true, plaintext: fromUtf8(header.padded ? unpad(body) : body), state: stolen };
  } catch {
    return { ok: false, state: stolen };
  }
}
