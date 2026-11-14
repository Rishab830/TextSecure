import { Identity, PublicIdentity, checkPublicIdentity, publicIdentity, signedPreKeyPayload } from "./identity";
import {
  KeyPair,
  concatBytes,
  dh,
  erasePrivate,
  generateAgreementKeyPair,
  hkdf,
  importAgreementPublic,
  previewBytes,
  sha256,
  sign,
  utf8,
  verify,
  wipe
} from "./primitives";
import { KeyEvent, Trace } from "./trace";

/**
 * X3DH-style asynchronous handshake (Frosch et al. -> Signal). Bob uploads a bundle once; Alice
 * can then start a session while Bob is offline (fixes Shen's online-only limitation), and the
 * signatures stop a server substituting keys (fixes SAKTI's unauthenticated exchange).
 */

export type SignedPreKey = { id: number; pair: KeyPair; signature: Uint8Array };
export type OneTimePreKey = { id: number; pair: KeyPair };

export type PreKeyBundle = {
  identity: PublicIdentity;
  signedPreKey: { id: number; publicBytes: Uint8Array; signature: Uint8Array };
  oneTimePreKey: { id: number; publicBytes: Uint8Array } | null;
};

/** Sent alongside messages until the initiator hears back, so the responder can rebuild the session. */
export type PreKeyHeader = {
  identity: PublicIdentity;
  ephemeralPublic: Uint8Array;
  signedPreKeyId: number;
  oneTimePreKeyId: number | null;
};

export type X3dhResult = {
  sharedKey: Uint8Array;
  associatedData: Uint8Array;
  remoteFingerprint: string;
  remoteFingerprintBytes: Uint8Array;
};

const X3DH_INFO = "CIM-X3DH-v1";
const F = new Uint8Array(32).fill(0xff); // domain separator, as in the X3DH spec
const ZERO_SALT = new Uint8Array(32);

export async function generateSignedPreKey(identity: Identity, id: number): Promise<SignedPreKey> {
  const pair = await generateAgreementKeyPair();
  const signature = await sign(identity.signing.privateKey!, signedPreKeyPayload(id, pair.publicBytes));
  return { id, pair, signature };
}

export async function generateOneTimePreKeys(startId: number, count: number): Promise<OneTimePreKey[]> {
  const keys: OneTimePreKey[] = [];
  for (let i = 0; i < count; i += 1) keys.push({ id: startId + i, pair: await generateAgreementKeyPair() });
  return keys;
}

/** AD = both identities (Frosch et al.'s fix for the unknown key-share attack). Initiator first. */
export function associatedData(initiatorFingerprint: Uint8Array, responderFingerprint: Uint8Array): Uint8Array {
  return concatBytes(utf8("CIM-AD"), initiatorFingerprint, responderFingerprint);
}

async function kdf(parts: Uint8Array[]): Promise<{ sharedKey: Uint8Array; materialHash: string }> {
  const material = concatBytes(F, ...parts);
  const sharedKey = await hkdf(material, ZERO_SALT, X3DH_INFO, 32);
  const materialHash = previewBytes(await sha256(material));
  wipe(material);
  parts.forEach(wipe);
  return { sharedKey, materialHash };
}

export async function initiateX3dh(
  self: Identity,
  bundle: PreKeyBundle,
  remoteName: string,
  trace?: Trace,
  log?: KeyEvent[]
): Promise<X3dhResult & { header: PreKeyHeader; remoteSignedPreKey: Uint8Array }> {
  // 1. Authenticate the bundle before using any key in it.
  const remote = await checkPublicIdentity(bundle.identity).catch((error) => {
    trace?.push({
      title: `Alice checks ${remoteName}'s identity certificate`,
      actor: "Alice",
      algorithm: "ECDSA P-256 / SHA-256",
      input: "Identity agreement key + signature from bundle",
      output: "Signature invalid",
      verification: "Rejected: the agreement key is not certified by the identity signing key.",
      failureMode: "Proceeding would let the server swap the identity agreement key.",
      status: "fail"
    });
    throw error;
  });
  const spkOk = await verify(
    remote.signingKey,
    bundle.signedPreKey.signature,
    signedPreKeyPayload(bundle.signedPreKey.id, bundle.signedPreKey.publicBytes)
  );
  trace?.push({
    title: `Alice verifies ${remoteName}'s signed prekey`,
    actor: "Alice",
    algorithm: "ECDSA P-256 / SHA-256",
    input: `SPK #${bundle.signedPreKey.id} ${previewBytes(bundle.signedPreKey.publicBytes)} + signature ${previewBytes(bundle.signedPreKey.signature)}`,
    output: spkOk ? `Valid. ${remoteName}'s fingerprint ${remote.fingerprint}` : "Signature invalid",
    verification: spkOk
      ? "The prekey is bound to the identity key, so the server could not have substituted it."
      : "Rejected before any DH is computed.",
    failureMode: "Without this check a man-in-the-middle can hand Alice their own prekey (SAKTI's flaw).",
    status: spkOk ? "success" : "fail",
    paper: "Frosch et al. 2016; Ab Halim et al. 2025"
  });
  if (!spkOk) throw new Error("Signed prekey signature is invalid.");

  // 2. Fresh ephemeral key, four DHs.
  const ephemeral = await generateAgreementKeyPair();
  log?.push({ kind: "created", label: "X3DH ephemeral key (EK_A)", preview: ephemeral.privatePreview });
  trace?.push({
    title: "Alice generates an ephemeral key",
    actor: "Alice",
    algorithm: "ECDH P-256 key generation",
    input: "crypto.getRandomValues (browser CSPRNG)",
    output: `EK_A public ${previewBytes(ephemeral.publicBytes)}`,
    verification: "Used for this handshake only, then erased.",
    failureMode: "Reusing an ephemeral key across sessions would link them and weaken forward secrecy.",
    status: "success"
  });

  const spk = await importAgreementPublic(bundle.signedPreKey.publicBytes);
  const parts = [
    await dh(self.agreement.privateKey, spk),
    await dh(ephemeral.privateKey, remote.agreementKey),
    await dh(ephemeral.privateKey, spk)
  ];
  if (bundle.oneTimePreKey) {
    parts.push(await dh(ephemeral.privateKey, await importAgreementPublic(bundle.oneTimePreKey.publicBytes)));
  }
  const { sharedKey, materialHash } = await kdf(parts);
  trace?.push({
    title: `X3DH: ${parts.length} Diffie-Hellman outputs`,
    actor: "Alice",
    algorithm: "ECDH P-256",
    input: bundle.oneTimePreKey
      ? `DH1(IK_A, SPK_B) DH2(EK_A, IK_B) DH3(EK_A, SPK_B) DH4(EK_A, OPK_B #${bundle.oneTimePreKey.id})`
      : "DH1(IK_A, SPK_B) DH2(EK_A, IK_B) DH3(EK_A, SPK_B) (no one-time prekey left)",
    output: `SHA-256 of F || DH1..DH${parts.length}: ${materialHash}`,
    verification: "DH1 and DH2 authenticate both parties; DH3/DH4 bring in fresh ephemeral secrets.",
    failureMode: "An attacker without IK_B, SPK_B and OPK_B private keys cannot compute the same values.",
    status: "success",
    paper: "Frosch et al. 2016; Unger et al. 2015"
  });
  trace?.push({
    title: "Shared secret SK derived",
    actor: "Alice",
    algorithm: "HKDF-SHA256",
    input: `F || DH outputs, salt = 32 zero bytes, info = "${X3DH_INFO}"`,
    output: `SK ${previewBytes(sharedKey)}`,
    verification: "DH outputs are wiped immediately; only SK remains.",
    failureMode: "Using raw DH output directly as a key skips extraction and domain separation.",
    status: "success"
  });

  erasePrivate(ephemeral);
  log?.push({ kind: "erased", label: "X3DH ephemeral key (EK_A)", preview: ephemeral.privatePreview });

  return {
    sharedKey,
    associatedData: associatedData(self.fingerprintBytes, remote.fingerprintBytes),
    remoteFingerprint: remote.fingerprint,
    remoteFingerprintBytes: remote.fingerprintBytes,
    remoteSignedPreKey: bundle.signedPreKey.publicBytes,
    header: {
      identity: publicIdentity(self),
      ephemeralPublic: ephemeral.publicBytes,
      signedPreKeyId: bundle.signedPreKey.id,
      oneTimePreKeyId: bundle.oneTimePreKey?.id ?? null
    }
  };
}

/**
 * Responder side. Consumes the one-time prekey: once its private half is erased, replaying the
 * same initial message can never rebuild the session (secure deletion, slide 15 step 6).
 */
export async function respondX3dh(
  self: Identity,
  signedPreKeys: Map<number, SignedPreKey>,
  oneTimePreKeys: Map<number, OneTimePreKey>,
  header: PreKeyHeader,
  trace?: Trace,
  log?: KeyEvent[]
): Promise<X3dhResult & { signedPreKey: SignedPreKey }> {
  const remote = await checkPublicIdentity(header.identity);
  const spk = signedPreKeys.get(header.signedPreKeyId);
  if (!spk) throw new Error(`Unknown signed prekey #${header.signedPreKeyId}.`);
  let opk: OneTimePreKey | undefined;
  if (header.oneTimePreKeyId !== null) {
    opk = oneTimePreKeys.get(header.oneTimePreKeyId);
    if (!opk) throw new Error(`One-time prekey #${header.oneTimePreKeyId} was already used and erased (replay?).`);
  }

  const ephemeral = await importAgreementPublic(header.ephemeralPublic);
  const parts = [
    await dh(spk.pair.privateKey, remote.agreementKey),
    await dh(self.agreement.privateKey, ephemeral),
    await dh(spk.pair.privateKey, ephemeral)
  ];
  if (opk) parts.push(await dh(opk.pair.privateKey, ephemeral));
  const { sharedKey, materialHash } = await kdf(parts);

  if (opk) {
    oneTimePreKeys.delete(opk.id);
    erasePrivate(opk.pair);
    log?.push({ kind: "erased", label: `One-time prekey OPK #${opk.id}`, preview: opk.pair.privatePreview });
  }

  trace?.push({
    title: "Bob rebuilds SK from the prekey message",
    actor: "Bob",
    algorithm: "ECDH P-256 + HKDF-SHA256",
    input: `Alice IK ${remote.fingerprint}, EK_A ${previewBytes(header.ephemeralPublic)}, SPK #${spk.id}${opk ? `, OPK #${opk.id}` : ""}`,
    output: `SK ${previewBytes(sharedKey)} (material ${materialHash})`,
    verification: "Bob was offline when Alice started; he computes the mirror-image DHs from his private prekeys.",
    failureMode: "If any key in the header was tampered with, Bob derives a different SK and the first message fails to decrypt.",
    status: "success",
    paper: "Frosch et al. 2016"
  });
  if (opk) {
    trace?.push({
      title: `One-time prekey #${opk.id} erased`,
      actor: "Bob",
      algorithm: "Secure deletion",
      input: `OPK #${opk.id} private ${opk.pair.privatePreview}`,
      output: `Removed. ${oneTimePreKeys.size} one-time prekey(s) left on device.`,
      verification: "A replay of the same initial message now fails: the private key no longer exists.",
      failureMode: "Keeping it would let anyone who later steals Bob's device redo the handshake.",
      status: "success",
      paper: "Canetti, Halevi & Katz 2003 (erasure); Frosch et al. 2016"
    });
  }

  return {
    sharedKey,
    associatedData: associatedData(remote.fingerprintBytes, self.fingerprintBytes),
    remoteFingerprint: remote.fingerprint,
    remoteFingerprintBytes: remote.fingerprintBytes,
    signedPreKey: spk
  };
}
