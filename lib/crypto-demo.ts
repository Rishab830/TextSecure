export type DemoUser = {
  id: "alice" | "bob";
  name: string;
  identitySigning: SigningKeyPair;
  identityAgreement: AgreementKeyPair;
  signedPreKey: SignedPreKey;
  oneTimePreKey: AgreementKeyPair;
  fingerprint: string;
};

export type SigningKeyPair = {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyB64: string;
  privateKeyPreview: string;
};

export type AgreementKeyPair = {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyB64: string;
  privateKeyPreview: string;
};

export type SignedPreKey = {
  agreement: AgreementKeyPair;
  signatureB64: string;
  verified: boolean;
};

export type PreKeyBundle = {
  userId: DemoUser["id"];
  identitySigningPublicKey: CryptoKey;
  identityAgreementPublicKey: CryptoKey;
  signedPreKeyPublicKey: CryptoKey;
  signedPreKeyPublicKeyB64: string;
  signedPreKeySignatureB64: string;
  oneTimePreKeyPublicKey: CryptoKey;
};

export type SessionState = {
  rootKey: Uint8Array;
  chainKey: Uint8Array;
  messageNumber: number;
  deletedKeys: string[];
  transcript: VerificationStep[];
};

export type EncryptedEnvelope = {
  id: string;
  from: DemoUser["id"];
  to: DemoUser["id"];
  plaintextPreview: string;
  ciphertextB64: string;
  ivB64: string;
  aadB64: string;
  envelopeBytes: number;
  messageNumber: number;
};

export type VerificationStep = {
  title: string;
  algorithm: string;
  input: string;
  output: string;
  verification: string;
  failureMode: string;
  status: "pending" | "success" | "fail";
};

export type DemoBundle = {
  alice: DemoUser;
  bob: DemoUser;
  session: SessionState;
  tamper: {
    signedPreKeyRejected: boolean;
    aadRejected: boolean;
  };
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function preview(value: string, head = 12, tail = 8): string {
  if (value.length <= head + tail + 3) {
    return value;
  }
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", asArrayBuffer(bytes));
  return new Uint8Array(digest);
}

export async function fingerprintFromBase64(value: string): Promise<string> {
  const digest = await sha256(base64ToBytes(value));
  return Array.from(digest.slice(0, 12))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join(":")
    .toUpperCase();
}

async function exportKeyB64(format: KeyFormat, key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey(format, key);
  if (!(exported instanceof ArrayBuffer)) {
    throw new Error("JWK export is not supported for this demo helper.");
  }
  return bytesToBase64(new Uint8Array(exported));
}

export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
  const pair = await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ["sign", "verify"]
  );
  const publicKeyB64 = await exportKeyB64("spki", pair.publicKey);
  const privateKeyB64 = await exportKeyB64("pkcs8", pair.privateKey);
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    publicKeyB64,
    privateKeyPreview: preview(privateKeyB64)
  };
}

export async function generateAgreementKeyPair(): Promise<AgreementKeyPair> {
  const pair = await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true,
    ["deriveBits"]
  );
  const publicKeyB64 = await exportKeyB64("spki", pair.publicKey);
  const privateKeyB64 = await exportKeyB64("pkcs8", pair.privateKey);
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    publicKeyB64,
    privateKeyPreview: preview(privateKeyB64)
  };
}

export async function signBytes(privateKey: CryptoKey, data: Uint8Array): Promise<string> {
  const signature = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: "SHA-256"
    },
    privateKey,
    asArrayBuffer(data)
  );
  return bytesToBase64(new Uint8Array(signature));
}

export async function verifySignature(
  publicKey: CryptoKey,
  signatureB64: string,
  data: Uint8Array
): Promise<boolean> {
  return crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: "SHA-256"
    },
    publicKey,
    asArrayBuffer(base64ToBytes(signatureB64)),
    asArrayBuffer(data)
  );
}

export async function generateDemoUser(id: DemoUser["id"], name: string): Promise<DemoUser> {
  const identitySigning = await generateSigningKeyPair();
  const identityAgreement = await generateAgreementKeyPair();
  const signedPreKeyAgreement = await generateAgreementKeyPair();
  const oneTimePreKey = await generateAgreementKeyPair();
  const signatureB64 = await signBytes(
    identitySigning.privateKey,
    encoder.encode(signedPreKeyAgreement.publicKeyB64)
  );
  const verified = await verifySignature(
    identitySigning.publicKey,
    signatureB64,
    encoder.encode(signedPreKeyAgreement.publicKeyB64)
  );
  const fingerprint = await fingerprintFromBase64(identitySigning.publicKeyB64);

  return {
    id,
    name,
    identitySigning,
    identityAgreement,
    signedPreKey: {
      agreement: signedPreKeyAgreement,
      signatureB64,
      verified
    },
    oneTimePreKey,
    fingerprint
  };
}

export function createPreKeyBundle(user: DemoUser): PreKeyBundle {
  return {
    userId: user.id,
    identitySigningPublicKey: user.identitySigning.publicKey,
    identityAgreementPublicKey: user.identityAgreement.publicKey,
    signedPreKeyPublicKey: user.signedPreKey.agreement.publicKey,
    signedPreKeyPublicKeyB64: user.signedPreKey.agreement.publicKeyB64,
    signedPreKeySignatureB64: user.signedPreKey.signatureB64,
    oneTimePreKeyPublicKey: user.oneTimePreKey.publicKey
  };
}

export async function deriveDh(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array> {
  const bits = await crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: publicKey
    },
    privateKey,
    256
  );
  return new Uint8Array(bits);
}

async function importHkdfKey(input: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", asArrayBuffer(input), "HKDF", false, ["deriveBits", "deriveKey"]);
}

export async function hkdfBytes(
  input: Uint8Array,
  salt: Uint8Array,
  info: string,
  lengthBytes = 32
): Promise<Uint8Array> {
  const key = await importHkdfKey(input);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asArrayBuffer(salt),
      info: asArrayBuffer(encoder.encode(info))
    },
    key,
    lengthBytes * 8
  );
  return new Uint8Array(bits);
}

export async function hkdfAesKey(
  input: Uint8Array,
  salt: Uint8Array,
  info: string
): Promise<CryptoKey> {
  const key = await importHkdfKey(input);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asArrayBuffer(salt),
      info: asArrayBuffer(encoder.encode(info))
    },
    key,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function establishSession(alice: DemoUser, bob: DemoUser): Promise<SessionState> {
  const bobBundle = createPreKeyBundle(bob);
  const aliceEphemeral = await generateAgreementKeyPair();
  const verified = await verifySignature(
    bobBundle.identitySigningPublicKey,
    bobBundle.signedPreKeySignatureB64,
    encoder.encode(bobBundle.signedPreKeyPublicKeyB64)
  );

  if (!verified) {
    throw new Error("Signed prekey verification failed.");
  }

  const dh1 = await deriveDh(alice.identityAgreement.privateKey, bobBundle.signedPreKeyPublicKey);
  const dh2 = await deriveDh(aliceEphemeral.privateKey, bobBundle.identityAgreementPublicKey);
  const dh3 = await deriveDh(aliceEphemeral.privateKey, bobBundle.signedPreKeyPublicKey);
  const dh4 = await deriveDh(aliceEphemeral.privateKey, bobBundle.oneTimePreKeyPublicKey);
  const material = concatBytes(dh1, dh2, dh3, dh4);
  const rootKey = await hkdfBytes(material, encoder.encode("x3dh-demo"), "root-key");
  const chainKey = await hkdfBytes(rootKey, encoder.encode("double-ratchet-demo"), "sending-chain");

  return {
    rootKey,
    chainKey,
    messageNumber: 0,
    deletedKeys: [`alice ephemeral private ${aliceEphemeral.privateKeyPreview}`],
    transcript: [
      {
        title: "Identity keys generated",
        algorithm: "ECDSA P-256 + ECDH P-256",
        input: "Browser secure random source",
        output: `Alice ${alice.fingerprint} / Bob ${bob.fingerprint}`,
        verification: "Public fingerprints are available for TOFU or manual verification.",
        failureMode: "If identity keys change later, the contact warning state is triggered.",
        status: "success"
      },
      {
        title: "Bob signed his prekey",
        algorithm: "ECDSA with SHA-256",
        input: `Bob signed prekey ${preview(bob.signedPreKey.agreement.publicKeyB64)}`,
        output: `Signature ${preview(bob.signedPreKey.signatureB64)}`,
        verification: verified ? "Signature verified with Bob's identity signing key." : "Rejected.",
        failureMode: "A modified prekey cannot be verified against Bob's identity key.",
        status: verified ? "success" : "fail"
      },
      {
        title: "Alice created an ephemeral session key",
        algorithm: "ECDH P-256",
        input: "Fresh browser randomness for this session only",
        output: `Ephemeral public key ${preview(aliceEphemeral.publicKeyB64)}`,
        verification: "The private half is deleted after session setup in the demo state.",
        failureMode: "Reusing this key would weaken forward secrecy.",
        status: "success"
      },
      {
        title: "X3DH-style shared secrets derived",
        algorithm: "Four ECDH operations",
        input: "Alice identity/ephemeral keys with Bob identity/signed/one-time prekeys",
        output: `DH material hash ${preview(bytesToBase64(await sha256(material)))}`,
        verification: "Only holders of matching private keys can derive the same material.",
        failureMode: "Wrong or attacker-substituted keys produce different session material.",
        status: "success"
      },
      {
        title: "Root and chain keys derived",
        algorithm: "HKDF-SHA256",
        input: `Combined DH material ${material.byteLength} bytes`,
        output: `Root ${preview(bytesToBase64(rootKey))} / Chain ${preview(bytesToBase64(chainKey))}`,
        verification: "Separate info labels produce separate keys for protocol stages.",
        failureMode: "Skipping HKDF separation risks key reuse across operations.",
        status: "success"
      }
    ]
  };
}

export async function nextMessageKey(session: SessionState): Promise<{
  messageKey: CryptoKey;
  nextChainKey: Uint8Array;
  deletedPreview: string;
}> {
  const salt = encoder.encode(`message-${session.messageNumber}`);
  const rawMessageKey = await hkdfBytes(session.chainKey, salt, "message-key");
  const messageKey = await hkdfAesKey(rawMessageKey, salt, "aes-gcm-message");
  const nextChainKey = await hkdfBytes(session.chainKey, salt, "next-chain-key");
  return {
    messageKey,
    nextChainKey,
    deletedPreview: preview(bytesToBase64(rawMessageKey))
  };
}

export async function encryptMessage(
  session: SessionState,
  from: DemoUser,
  to: DemoUser,
  plaintext: string
): Promise<{ session: SessionState; envelope: EncryptedEnvelope }> {
  const { messageKey, nextChainKey, deletedPreview } = await nextMessageKey(session);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aadText = `${from.id}:${from.fingerprint}->${to.id}:${to.fingerprint}`;
  const aad = encoder.encode(aadText);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: asArrayBuffer(iv),
      additionalData: asArrayBuffer(aad)
    },
    messageKey,
    asArrayBuffer(encoder.encode(plaintext))
  );
  const ciphertextBytes = new Uint8Array(ciphertext);
  const envelope: EncryptedEnvelope = {
    id: crypto.randomUUID(),
    from: from.id,
    to: to.id,
    plaintextPreview: plaintext,
    ciphertextB64: bytesToBase64(ciphertextBytes),
    ivB64: bytesToBase64(iv),
    aadB64: bytesToBase64(aad),
    envelopeBytes: ciphertextBytes.byteLength + iv.byteLength + aad.byteLength,
    messageNumber: session.messageNumber
  };

  return {
    envelope,
    session: {
      ...session,
      chainKey: nextChainKey,
      messageNumber: session.messageNumber + 1,
      deletedKeys: [...session.deletedKeys, `message key ${session.messageNumber}: ${deletedPreview}`]
    }
  };
}

export async function decryptMessage(
  session: SessionState,
  envelope: EncryptedEnvelope
): Promise<string> {
  const { messageKey } = await nextMessageKey(session);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: asArrayBuffer(base64ToBytes(envelope.ivB64)),
      additionalData: asArrayBuffer(base64ToBytes(envelope.aadB64))
    },
    messageKey,
    asArrayBuffer(base64ToBytes(envelope.ciphertextB64))
  );
  return decoder.decode(plaintext);
}

export async function runTamperChecks(alice: DemoUser, bob: DemoUser, session: SessionState) {
  const tamperedPreKey = `${bob.signedPreKey.agreement.publicKeyB64.slice(0, -2)}AA`;
  const signedPreKeyRejected = !(await verifySignature(
    bob.identitySigning.publicKey,
    bob.signedPreKey.signatureB64,
    encoder.encode(tamperedPreKey)
  ));
  const { envelope } = await encryptMessage(session, alice, bob, "tamper check");
  const badEnvelope = {
    ...envelope,
    aadB64: bytesToBase64(encoder.encode("mallory:fake->bob:fake"))
  };
  let aadRejected = false;
  try {
    await decryptMessage(session, badEnvelope);
  } catch {
    aadRejected = true;
  }

  return {
    signedPreKeyRejected,
    aadRejected
  };
}

export async function createDemoBundle(): Promise<DemoBundle> {
  const alice = await generateDemoUser("alice", "Alice");
  const bob = await generateDemoUser("bob", "Bob");
  const session = await establishSession(alice, bob);
  const tamper = await runTamperChecks(alice, bob, session);
  return { alice, bob, session, tamper };
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, item) => sum + item.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  arrays.forEach((item) => {
    output.set(item, offset);
    offset += item.byteLength;
  });
  return output;
}
