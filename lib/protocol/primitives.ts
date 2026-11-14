/**
 * Thin wrappers over the Web Crypto API. Everything here is a standard, audited primitive
 * (survey takeaway from SAKTI / Adebayo: never roll a custom cipher).
 *
 * Web Crypto has no X25519/Ed25519 in every browser yet, so the demo uses the NIST P-256
 * equivalents: ECDH P-256 for agreement and ECDSA P-256 for signatures.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (text: string): Uint8Array => encoder.encode(text);
export const fromUtf8 = (bytes: Uint8Array): string => decoder.decode(bytes);

export function buf(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, item) => sum + item.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays) {
    output.set(item, offset);
    offset += item.byteLength;
  }
  return output;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Overwrite a buffer in place. JS can't guarantee no copies survive, but this is the intent. */
export function wipe(bytes: Uint8Array | null | undefined): void {
  if (bytes) bytes.fill(0);
}

export function preview(value: string, head = 12, tail = 8): string {
  if (value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

export const previewBytes = (bytes: Uint8Array | null | undefined, head = 10, tail = 6): string =>
  bytes ? preview(bytesToBase64(bytes), head, tail) : "none";

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf(bytes)));
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

// ---------------------------------------------------------------------------------------------
// Key pairs

export type KeyPair = {
  publicKey: CryptoKey;
  privateKey: CryptoKey | null; // null once erased
  /** SPKI bytes of the public key, used for signing, hashing and wire headers. */
  publicBytes: Uint8Array;
  publicB64: string;
  privatePreview: string;
};

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;
const ECDSA = { name: "ECDSA", namedCurve: "P-256" } as const;

async function finishPair(pair: CryptoKeyPair): Promise<KeyPair> {
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  // Private keys are extractable only so the UI can show a short preview of what gets erased.
  const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const privatePreview = preview(bytesToBase64(privateBytes.slice(-32)), 8, 6);
  wipe(privateBytes);
  return {
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    publicBytes,
    publicB64: bytesToBase64(publicBytes),
    privatePreview
  };
}

export async function generateAgreementKeyPair(): Promise<KeyPair> {
  return finishPair(await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]));
}

export async function generateSigningKeyPair(): Promise<KeyPair> {
  return finishPair(await crypto.subtle.generateKey(ECDSA, true, ["sign", "verify"]));
}

export async function importAgreementPublic(spki: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", buf(spki), ECDH, true, []);
}

export async function importSigningPublic(spki: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", buf(spki), ECDSA, true, ["verify"]);
}

/** Drop our reference to a private key; the UI log records that it happened. */
export function erasePrivate(pair: KeyPair): void {
  pair.privateKey = null;
}

// ---------------------------------------------------------------------------------------------
// Signatures, DH, KDFs, AEAD

export async function sign(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, buf(data)));
}

export async function verify(publicKey: CryptoKey, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  try {
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, buf(signature), buf(data));
  } catch {
    return false;
  }
}

export async function dh(privateKey: CryptoKey | null, publicKey: CryptoKey): Promise<Uint8Array> {
  if (!privateKey) throw new Error("Private key has already been erased.");
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256));
}

export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string, lengthBytes: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", buf(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: buf(salt), info: buf(utf8(info)) },
    key,
    lengthBytes * 8
  );
  return new Uint8Array(bits);
}

export async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", buf(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, buf(data)));
}

export async function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", buf(key), "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: buf(iv), additionalData: buf(aad) }, imported, buf(plaintext))
  );
}

export async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array
): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey("raw", buf(key), "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf(iv), additionalData: buf(aad) }, imported, buf(ciphertext))
  );
}

// ---------------------------------------------------------------------------------------------
// Length padding (metadata awareness, Afzal et al.)

export const PAD_BLOCK = 64;

/** ISO/IEC 7816-4 padding: 0x80 then zeros, up to the next multiple of PAD_BLOCK bytes. */
export function pad(plaintext: Uint8Array, block = PAD_BLOCK): Uint8Array {
  const padded = new Uint8Array(Math.ceil((plaintext.byteLength + 1) / block) * block);
  padded.set(plaintext);
  padded[plaintext.byteLength] = 0x80;
  return padded;
}

export function unpad(padded: Uint8Array): Uint8Array {
  for (let i = padded.byteLength - 1; i >= 0; i -= 1) {
    if (padded[i] === 0x80) return padded.slice(0, i);
    if (padded[i] !== 0) break;
  }
  throw new Error("Invalid padding.");
}
