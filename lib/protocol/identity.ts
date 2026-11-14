import {
  KeyPair,
  bytesToBase64,
  bytesToHex,
  concatBytes,
  generateAgreementKeyPair,
  generateSigningKeyPair,
  importAgreementPublic,
  importSigningPublic,
  sha256,
  sign,
  utf8,
  verify
} from "./primitives";

/**
 * Long-term identity. Web Crypto can't use one P-256 key for both ECDSA and ECDH, so an identity
 * is a signing key plus an agreement key, and the signing key certifies the agreement key.
 * Without that certificate a server could swap the agreement key unnoticed.
 */
export type Identity = {
  signing: KeyPair;
  agreement: KeyPair;
  agreementSignature: Uint8Array;
  fingerprint: string;
  fingerprintBytes: Uint8Array;
};

export type PublicIdentity = {
  signingPublic: Uint8Array;
  agreementPublic: Uint8Array;
  agreementSignature: Uint8Array;
};

const ID_CERT_LABEL = "CIM-identity-agreement-key";
const SPK_LABEL = "CIM-signed-prekey";

export const identityCertPayload = (agreementPublic: Uint8Array) => concatBytes(utf8(ID_CERT_LABEL), agreementPublic);
export const signedPreKeyPayload = (id: number, publicBytes: Uint8Array) =>
  concatBytes(utf8(`${SPK_LABEL}:${id}:`), publicBytes);

export async function fingerprintOf(signingPublic: Uint8Array, agreementPublic: Uint8Array) {
  const digest = await sha256(concatBytes(utf8("CIM-fingerprint"), signingPublic, agreementPublic));
  const bytes = digest.slice(0, 16);
  const fingerprint = (bytesToHex(bytes).toUpperCase().match(/.{4}/g) ?? []).join(" ");
  return { fingerprint, fingerprintBytes: bytes };
}

export async function generateIdentity(): Promise<Identity> {
  const signing = await generateSigningKeyPair();
  const agreement = await generateAgreementKeyPair();
  const agreementSignature = await sign(signing.privateKey!, identityCertPayload(agreement.publicBytes));
  return {
    signing,
    agreement,
    agreementSignature,
    ...(await fingerprintOf(signing.publicBytes, agreement.publicBytes))
  };
}

export function publicIdentity(identity: Identity): PublicIdentity {
  return {
    signingPublic: identity.signing.publicBytes,
    agreementPublic: identity.agreement.publicBytes,
    agreementSignature: identity.agreementSignature
  };
}

/** Verify the identity certificate; returns the imported keys and fingerprint, or throws. */
export async function checkPublicIdentity(identity: PublicIdentity) {
  const signingKey = await importSigningPublic(identity.signingPublic);
  const ok = await verify(signingKey, identity.agreementSignature, identityCertPayload(identity.agreementPublic));
  if (!ok) throw new Error("Identity agreement key is not signed by the identity signing key.");
  const agreementKey = await importAgreementPublic(identity.agreementPublic);
  return {
    signingKey,
    agreementKey,
    ...(await fingerprintOf(identity.signingPublic, identity.agreementPublic))
  };
}

/**
 * Safety number both people can read aloud or compare in person (trust establishment, Unger SoK).
 * Order-independent, so Alice and Bob see the same 60 digits iff they hold each other's real keys.
 */
export async function safetyNumber(fingerprintA: Uint8Array, fingerprintB: Uint8Array): Promise<string> {
  const [first, second] = [fingerprintA, fingerprintB].sort((a, b) =>
    bytesToBase64(a) < bytesToBase64(b) ? -1 : 1
  );
  const digest = await sha256(concatBytes(utf8("CIM-safety-number"), first, second));
  const groups: string[] = [];
  for (let i = 0; i < 12; i += 1) {
    const chunk = digest.slice(i * 2, i * 2 + 3);
    const value = ((chunk[0] << 16) | (chunk[1] << 8) | chunk[2]) % 100000;
    groups.push(String(value).padStart(5, "0"));
  }
  return groups.join(" ");
}
