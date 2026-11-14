import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { Device, Envelope, KeyChangedError, PreKeyServer } from "../lib/protocol/device";
import { checkPublicIdentity, generateIdentity, publicIdentity, safetyNumber } from "../lib/protocol/identity";
import { PAD_BLOCK, equalBytes, generateAgreementKeyPair, hkdf, pad, unpad, utf8 } from "../lib/protocol/primitives";
import { attackerRead, kdfChain } from "../lib/protocol/ratchet";
import { generateSignedPreKey, initiateX3dh, respondX3dh } from "../lib/protocol/x3dh";
import { runWalkthrough } from "../lib/protocol/walkthrough";

async function pair() {
  const server = new PreKeyServer();
  const alice = await Device.create("alice", "Alice");
  const bob = await Device.create("bob", "Bob");
  server.publish(alice);
  server.publish(bob);
  return { server, alice, bob };
}

const flip = (bytes: Uint8Array, index = 0) => {
  const copy = bytes.slice();
  copy[index] ^= 0x01;
  return copy;
};

describe("identity and prekeys", () => {
  test("identity certificate verifies, and a swapped agreement key is rejected", async () => {
    const a = await generateIdentity();
    const b = await generateIdentity();
    await checkPublicIdentity(publicIdentity(a));
    await assert.rejects(checkPublicIdentity({ ...publicIdentity(a), agreementPublic: b.agreement.publicBytes }));
  });

  test("signed prekey verifies; a tampered prekey is rejected before any DH", async () => {
    const { server, alice } = await pair();
    const { bundle } = server.fetch("bob");
    const tampered = { ...bundle, signedPreKey: { ...bundle.signedPreKey, publicBytes: flip(bundle.signedPreKey.publicBytes, 40) } };
    await assert.rejects(initiateX3dh(alice.identity, tampered, "bob"), /signature/i);
    await initiateX3dh(alice.identity, bundle, "bob");
  });

  test("safety numbers match on both sides and change with the key", async () => {
    const a = await generateIdentity();
    const b = await generateIdentity();
    const m = await generateIdentity();
    const ab = await safetyNumber(a.fingerprintBytes, b.fingerprintBytes);
    assert.equal(ab, await safetyNumber(b.fingerprintBytes, a.fingerprintBytes));
    assert.notEqual(ab, await safetyNumber(a.fingerprintBytes, m.fingerprintBytes));
    assert.match(ab, /^(\d{5} ){11}\d{5}$/);
  });
});

describe("X3DH", () => {
  test("both sides derive the same SK and AD; the one-time prekey is consumed", async () => {
    const alice = await generateIdentity();
    const bob = await generateIdentity();
    const spk = await generateSignedPreKey(bob, 7);
    const opk = { id: 1, pair: await generateAgreementKeyPair() };
    const opks = new Map([[1, opk]]);
    const bundle = {
      identity: publicIdentity(bob),
      signedPreKey: { id: 7, publicBytes: spk.pair.publicBytes, signature: spk.signature },
      oneTimePreKey: { id: 1, publicBytes: opk.pair.publicBytes }
    };
    const init = await initiateX3dh(alice, bundle, "bob");
    const resp = await respondX3dh(bob, new Map([[7, spk]]), opks, init.header);
    assert.ok(equalBytes(init.sharedKey, resp.sharedKey));
    assert.ok(equalBytes(init.associatedData, resp.associatedData));
    assert.equal(opks.size, 0);
    await assert.rejects(respondX3dh(bob, new Map([[7, spk]]), opks, init.header), /already used/);
  });

  test("works without a one-time prekey (server ran out)", async () => {
    const server = new PreKeyServer();
    const alice = await Device.create("alice", "Alice");
    const bob = await Device.create("bob", "Bob", 0);
    server.publish(bob);
    const envelope = await alice.send(server, "bob", "no OPK left");
    assert.equal(envelope.preKey?.oneTimePreKeyId, null);
    assert.equal((await bob.receive(envelope)).plaintext, "no OPK left");
  });
});

describe("Double Ratchet", () => {
  test("HKDF and the chain KDF produce distinct keys", async () => {
    const ikm = utf8("input keying material");
    const salt = new Uint8Array(32);
    const root = await hkdf(ikm, salt, "root", 32);
    const chain = await hkdf(ikm, salt, "chain", 32);
    assert.ok(!equalBytes(root, chain));
    const [next, message] = await kdfChain(chain);
    assert.ok(!equalBytes(next, message));
    assert.ok(!equalBytes(next, chain));
  });

  test("Alice can message an offline Bob, and both can then talk", async () => {
    const { server, alice, bob } = await pair();
    const e1 = await alice.send(server, "bob", "hi bob");
    const e2 = await alice.send(server, "bob", "you there?");
    assert.ok(e1.preKey && e2.preKey, "prekey header repeats until Bob replies");
    assert.equal((await bob.receive(e1)).plaintext, "hi bob");
    assert.equal((await bob.receive(e2)).plaintext, "you there?");
    const r1 = await bob.send(server, "alice", "here");
    const got = await alice.receive(r1);
    assert.equal(got.plaintext, "here");
    assert.ok(got.ratcheted, "a reply triggers a DH ratchet step");
    const e3 = await alice.send(server, "bob", "great");
    assert.equal(e3.preKey, null, "prekey header dropped once Bob replied");
    assert.equal((await bob.receive(e3)).plaintext, "great");
    assert.equal(server.oneTimePreKeysLeft("bob"), 4);
    assert.equal(bob.oneTimePreKeyCount, 4);
  });

  test("every message uses a new key and the ratchet key changes each round trip", async () => {
    const { server, alice, bob } = await pair();
    const seen = new Set<string>();
    for (let round = 0; round < 3; round += 1) {
      const a = await alice.send(server, "bob", `a${round}`);
      await bob.receive(a);
      const b = await bob.send(server, "alice", `b${round}`);
      await alice.receive(b);
      seen.add(a.header.dh);
      seen.add(b.header.dh);
    }
    assert.equal(seen.size, 6);
    const erased = alice.sessions.get("bob")!.ratchet.log.filter((e) => e.kind === "erased" && e.label.includes("message key"));
    assert.equal(erased.length, 6);
  });

  test("tampered ciphertext, header, or associated data fail and leave the session intact", async () => {
    const { server, alice, bob } = await pair();
    await bob.receive(await alice.send(server, "bob", "setup"));
    const good = await alice.send(server, "bob", "real message");
    const before = bob.sessions.get("alice")!.ratchet.Nr;
    await assert.rejects(bob.receive({ ...good, ciphertext: flip(good.ciphertext, 3) }));
    await assert.rejects(bob.receive({ ...good, header: { ...good.header, n: good.header.n, pn: good.header.pn + 1 } }));
    const session = bob.sessions.get("alice")!;
    const realAd = session.ratchet.associatedData;
    session.ratchet.associatedData = flip(realAd, 10);
    await assert.rejects(bob.receive(good));
    session.ratchet.associatedData = realAd;
    assert.equal(bob.sessions.get("alice")!.ratchet.Nr, before);
    assert.equal((await bob.receive(good)).plaintext, "real message");
  });

  test("out-of-order and late messages decrypt via stored skipped keys", async () => {
    const { server, alice, bob } = await pair();
    const msgs: Envelope[] = [];
    for (const text of ["one", "two", "three"]) msgs.push(await alice.send(server, "bob", text));
    assert.equal((await bob.receive(msgs[0])).plaintext, "one");
    assert.equal((await bob.receive(msgs[2])).plaintext, "three");
    assert.equal(bob.sessions.get("alice")!.ratchet.skipped.size, 1);
    // Bob replies and Alice ratchets before the late message shows up.
    await alice.receive(await bob.send(server, "alice", "reply"));
    const late = await bob.receive(msgs[1]);
    assert.equal(late.plaintext, "two");
    assert.ok(late.usedSkippedKey);
    assert.equal(bob.sessions.get("alice")!.ratchet.skipped.size, 0);
    await assert.rejects(bob.receive(msgs[1]), "a replayed message fails: its key is gone");
  });

  test("padding hides exact length to the nearest block", async () => {
    const { server, alice } = await pair();
    const short = await alice.send(server, "bob", "ok");
    const longer = await alice.send(server, "bob", "a somewhat longer message");
    assert.equal(short.ciphertext.byteLength, longer.ciphertext.byteLength);
    assert.equal(short.ciphertext.byteLength, PAD_BLOCK + 16);
    const raw = await alice.send(server, "bob", "ok", { padded: false });
    assert.equal(raw.ciphertext.byteLength, 2 + 16);
    assert.deepEqual(unpad(pad(utf8("x".repeat(64)))), utf8("x".repeat(64)));
  });
});

describe("compromise", () => {
  test("a stolen state can't read the past, and heals after one round trip", async () => {
    const { server, alice, bob } = await pair();
    const past: Envelope[] = [];
    for (let i = 0; i < 2; i += 1) {
      const a = await alice.send(server, "bob", `old a${i}`);
      await bob.receive(a);
      const b = await bob.send(server, "alice", `old b${i}`);
      await alice.receive(b);
      past.push(a, b);
    }

    const stolen = bob.snapshot("alice")!;
    for (const env of past) {
      const res = await attackerRead(stolen, env.from === "alice" ? "to-victim" : "from-victim", env.header, env.ciphertext);
      assert.equal(res.ok, false, "forward secrecy: past messages stay unreadable");
    }

    let attacker = stolen;
    // Bob's next message still uses the stolen sending chain: readable.
    const b1 = await bob.send(server, "alice", "after compromise");
    await alice.receive(b1);
    assert.equal((await attackerRead(attacker, "from-victim", b1.header, b1.ciphertext)).ok, true);
    // Alice replies to Bob's current key, which the attacker also holds: readable.
    const a1 = await alice.send(server, "bob", "still exposed");
    await bob.receive(a1);
    const r = await attackerRead(attacker, "to-victim", a1.header, a1.ciphertext);
    assert.equal(r.ok, true);
    attacker = r.state;
    // Bob's reply uses a fresh key the attacker never saw, and so does everything after it.
    const b2 = await bob.send(server, "alice", "healed");
    await alice.receive(b2);
    assert.equal((await attackerRead(attacker, "from-victim", b2.header, b2.ciphertext)).ok, false);
    const a2 = await alice.send(server, "bob", "healed too");
    await bob.receive(a2);
    assert.equal((await attackerRead(attacker, "to-victim", a2.header, a2.ciphertext)).ok, false);
  });
});

describe("trust", () => {
  test("a substituted bundle is caught by the pinned fingerprint", async () => {
    const { server, alice, bob } = await pair();
    await bob.receive(await alice.send(server, "bob", "first contact"));
    const mallory = await Device.create("mallory", "Mallory");
    server.substitute("bob", mallory);
    alice.dropSession("bob");
    await assert.rejects(alice.send(server, "bob", "secret"), KeyChangedError);
    assert.equal(alice.contacts.get("bob")!.status, "changed");
    await assert.rejects(alice.send(server, "bob", "secret"), KeyChangedError, "stays blocked until the user decides");
  });

  test("first contact through a malicious server: TOFU accepts, only the safety number exposes it", async () => {
    const server = new PreKeyServer();
    const alice = await Device.create("alice", "Alice");
    const bob = await Device.create("bob", "Bob");
    const mallory = await Device.create("mallory", "Mallory");
    server.publish(bob);
    server.substitute("bob", mallory);
    const env = await alice.send(server, "bob", "for bob only");
    assert.equal(env.deliverTo, "mallory");
    assert.equal((await mallory.receive(env)).plaintext, "for bob only");
    const aliceView = await safetyNumber(alice.identity.fingerprintBytes, alice.contacts.get("bob")!.fingerprintBytes);
    const bobView = await safetyNumber(bob.identity.fingerprintBytes, alice.identity.fingerprintBytes);
    assert.notEqual(aliceView, bobView);
  });
});

describe("walkthrough", () => {
  test("every Key Gen step runs on real values and the tamper steps fail as expected", async () => {
    const steps = await runWalkthrough();
    assert.ok(steps.length >= 15);
    const unexpected = steps.filter((s) => s.status === "fail" && !s.title.toLowerCase().includes("tamper") && !s.title.toLowerCase().includes("replay"));
    assert.deepEqual(unexpected, []);
    const tamper = steps.filter((s) => /tamper|replay/i.test(s.title));
    assert.ok(tamper.length >= 4);
    assert.ok(tamper.every((s) => s.status === "fail"));
  });
});
