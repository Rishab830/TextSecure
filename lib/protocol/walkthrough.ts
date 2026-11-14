import { Device, PreKeyServer } from "./device";
import { safetyNumber, signedPreKeyPayload } from "./identity";
import { base64ToBytes, importSigningPublic, PAD_BLOCK, preview, previewBytes, utf8, verify } from "./primitives";
import { attackerRead, ratchetDecrypt } from "./ratchet";
import { Trace } from "./trace";
import { associatedData } from "./x3dh";

const flip = (bytes: Uint8Array, index: number) => {
  const copy = bytes.slice();
  copy[index % copy.byteLength] ^= 0x01;
  return copy;
};

/**
 * Runs the whole protocol once with fresh keys and records every stage, including the attacks
 * that must fail. Powers Key Gen Process mode; every value shown is real output.
 */
export async function runWalkthrough(sample = "Meet at the lab at 6."): Promise<Trace> {
  const trace: Trace = [];
  const server = new PreKeyServer();
  const alice = await Device.create("alice", "Alice");
  const bob = await Device.create("bob", "Bob", 5);

  trace.push({
    title: "Long-term identity keys generated",
    actor: "Alice + Bob",
    algorithm: "ECDSA P-256 (signing) + ECDH P-256 (agreement)",
    input: "crypto.getRandomValues (browser CSPRNG), on each device",
    output: `Alice ${alice.identity.fingerprint}\nBob   ${bob.identity.fingerprint}`,
    verification: "The signing key certifies the agreement key; the fingerprint hashes both.",
    failureMode: "An uncertified agreement key could be swapped by the server without changing the signature key.",
    status: "success",
    paper: "Unger et al. 2015 (trust establishment)"
  });

  server.publish(alice);
  server.publish(bob);
  const bundle = bob.exportBundle();
  trace.push({
    title: "Bob signs a prekey and uploads his bundle",
    actor: "Bob",
    algorithm: "ECDSA P-256 / SHA-256",
    input: `SPK #${bundle.signedPreKey.id} ${previewBytes(bundle.signedPreKey.publicBytes)} + ${bundle.oneTimePreKeys.length} one-time prekeys`,
    output: `Signature ${previewBytes(bundle.signedPreKey.signature)}; bundle stored on the (untrusted) server`,
    verification: "Bob can now go offline. Anyone can start a session with him from this bundle.",
    failureMode: "Without prekeys both sides must be online at once (Shen 2021's limitation).",
    status: "success",
    paper: "Frosch et al. 2016; Shen 2021"
  });

  // Alice's first message: X3DH + ratchet init + encrypt (all traced inside).
  const first = await alice.send(server, "bob", sample, { trace });
  trace.push({
    title: "Server stores the ciphertext for offline Bob",
    actor: "Server",
    algorithm: "Store and forward",
    input: "Envelope from Alice",
    output: `${first.wireBytes} B on the wire: prekey header, ratchet header (n=${first.header.n}), ciphertext ${previewBytes(first.ciphertext)}`,
    verification: "The server sees who talks to whom and roughly how much. It never sees keys or plaintext.",
    failureMode: "Size and timing are still visible: content confidentiality is not metadata privacy.",
    status: "info",
    paper: "Afzal et al. 2021"
  });

  // Bob comes online.
  const received = await bob.receive(first, { trace });
  if (received.plaintext !== sample) throw new Error("Walkthrough: Bob decrypted the wrong plaintext.");

  // Bob replies: DH ratchet.
  const reply = await bob.send(server, "alice", "On my way.", { trace });
  const replyOpened = await alice.receive(reply, { trace });
  trace.push({
    title: "A reply turns the DH ratchet",
    actor: "Alice",
    algorithm: "ECDH P-256 + HKDF-SHA256 (KDF_RK)",
    input: `Bob's new ratchet key ${previewBytes(base64ToBytes(reply.header.dh))}`,
    output: `"${replyOpened.plaintext}"; Alice now generates her next ratchet key for her next message`,
    verification: "Each round trip mixes a brand-new DH secret into the root key.",
    failureMode: "Without the DH ratchet, a stolen chain key would expose every future message (Threema-style static keys, Onik et al.).",
    status: replyOpened.ratcheted ? "success" : "fail",
    paper: "Onik et al. 2025; Afreen & Ivaturi 2025"
  });

  // ---- Attacks that must fail ----------------------------------------------------------------
  const bobSigning = await importSigningPublic(bundle.identity.signingPublic);
  const tamperedSpk = flip(bundle.signedPreKey.publicBytes, 40);
  const spkAccepted = await verify(
    bobSigning,
    bundle.signedPreKey.signature,
    signedPreKeyPayload(bundle.signedPreKey.id, tamperedSpk)
  );
  trace.push({
    title: "Tamper: server swaps Bob's signed prekey",
    actor: "Attacker",
    algorithm: "ECDSA P-256 verification",
    input: `Bob's signature + prekey with one bit flipped (${previewBytes(tamperedSpk)})`,
    output: spkAccepted ? "Accepted (this should never happen)" : "Rejected: signature does not match",
    verification: "Alice refuses the bundle before computing any DH.",
    failureMode: "This is exactly the man-in-the-middle SAKTI could not stop.",
    status: spkAccepted ? "success" : "fail",
    paper: "Ab Halim et al. 2025"
  });

  const next = await alice.send(server, "bob", "Bring the slides.");
  const bobSession = bob.sessions.get("alice")!;
  const ciphertextOk = await ratchetDecrypt(bobSession.ratchet, next.header, flip(next.ciphertext, 5)).then(
    () => true,
    () => false
  );
  trace.push({
    title: "Tamper: one ciphertext bit flipped in transit",
    actor: "Attacker",
    algorithm: "AES-256-GCM tag check",
    input: `Ciphertext ${previewBytes(next.ciphertext)} with byte 5 altered`,
    output: ciphertextOk ? "Decrypted (this should never happen)" : "Rejected: authentication tag mismatch",
    verification: "Bob's session state is untouched, so the genuine message still decrypts afterwards.",
    failureMode: "Unauthenticated encryption (e.g. plain CTR) would hand Bob attacker-chosen garbage.",
    status: ciphertextOk ? "success" : "fail",
    paper: "Adebayo 2025"
  });

  const mallory = await Device.create("mallory", "Mallory", 0);
  const forgedAd = associatedData(mallory.identity.fingerprintBytes, bob.identity.fingerprintBytes);
  const adOk = await ratchetDecrypt({ ...bobSession.ratchet, associatedData: forgedAd }, next.header, next.ciphertext).then(
    () => true,
    () => false
  );
  trace.push({
    title: "Tamper: message re-labelled as coming from Mallory",
    actor: "Attacker",
    algorithm: "AES-256-GCM associated data",
    input: `AAD = Mallory ${preview(mallory.identity.fingerprint, 9, 4)} -> Bob instead of Alice -> Bob`,
    output: adOk ? "Decrypted (this should never happen)" : "Rejected: identities are part of the authenticated data",
    verification: "Both identities are bound into every ciphertext.",
    failureMode: "Frosch et al.'s unknown key-share attack: a message gets attributed to the wrong sender.",
    status: adOk ? "success" : "fail",
    paper: "Frosch et al. 2016"
  });

  const replayOk = await bob.receive(first).then(
    () => true,
    () => false
  );
  trace.push({
    title: "Replay: Alice's first message sent again",
    actor: "Attacker",
    algorithm: "One-time prekey + message key erasure",
    input: `Original envelope, OPK #${first.preKey?.oneTimePreKeyId}, message n=${first.header.n}`,
    output: replayOk ? "Accepted (this should never happen)" : "Rejected: the keys it needs were erased after first use",
    verification: "Bob's device keeps no key that could open the same message twice.",
    failureMode: "Keeping used keys around would allow replays and help anyone who later steals the device.",
    status: replayOk ? "success" : "fail",
    paper: "Canetti, Halevi & Katz 2003"
  });

  const genuine = await bob.receive(next);

  // ---- Forward secrecy ---------------------------------------------------------------------
  const stolen = bob.snapshot("alice")!;
  const past = await attackerRead(stolen, "to-victim", first.header, first.ciphertext);
  const pastReply = await attackerRead(stolen, "from-victim", reply.header, reply.ciphertext);
  trace.push({
    title: "Forward secrecy: Bob's phone is seized now",
    actor: "Forensic examiner",
    algorithm: "Replay the stolen ratchet state on old ciphertexts",
    input: `Bob's full current state (root ${previewBytes(stolen.RK)}, ${stolen.skipped.size} stored keys) + 2 recorded old messages`,
    output: past.ok || pastReply.ok ? "An old message was readable!" : "Neither old message can be decrypted",
    verification: `The message and chain keys for them were erased (${bob.sessions.get("alice")!.ratchet.log.filter((e) => e.kind === "erased").length} erasures logged on Bob's session). Genuine message still read: "${genuine.plaintext}".`,
    failureMode: "Only messages still in transit (keys not yet erased) would be exposed. Puncturable encryption narrows even that (Green & Miers 2015).",
    status: past.ok || pastReply.ok ? "fail" : "success",
    paper: "Canetti et al. 2003; Green & Miers 2015; Wei et al. 2021"
  });

  const aliceSees = await safetyNumber(alice.identity.fingerprintBytes, alice.contacts.get("bob")!.fingerprintBytes);
  const bobSees = await safetyNumber(bob.identity.fingerprintBytes, bob.contacts.get("alice")!.fingerprintBytes);
  trace.push({
    title: "Safety number compared out of band",
    actor: "Alice + Bob",
    algorithm: "SHA-256 over both fingerprints",
    input: "Each side's own key + the key it pinned for the other",
    output: `Alice: ${aliceSees}\nBob:   ${bobSees}`,
    verification: aliceSees === bobSees ? "Identical: no one sat in the middle of the first handshake." : "Different: a man-in-the-middle is present.",
    failureMode: "TOFU alone trusts whatever key arrives first; only this comparison catches a first-contact MITM.",
    status: aliceSees === bobSees ? "success" : "fail",
    paper: "Unger et al. 2015"
  });

  trace.push({
    title: "Length padding against traffic analysis",
    actor: "Alice",
    algorithm: `ISO/IEC 7816-4 padding to ${PAD_BLOCK}-byte blocks`,
    input: `"ok" (${utf8("ok").byteLength} B) and "${sample}" (${utf8(sample).byteLength} B)`,
    output: `Both become ${PAD_BLOCK + 16} B ciphertexts (${PAD_BLOCK} B block + 16 B tag)`,
    verification: "An observer can no longer tell short replies from longer messages by size.",
    failureMode: "Timing and message count still leak; real systems add cover traffic or batching.",
    status: "info",
    paper: "Afzal et al. 2021"
  });

  return trace;
}
