# Cipher in Motion

Cipher in Motion is an interactive, browser-based secure messenger that demonstrates forward secrecy. It accompanies the literature survey in this repository (11 papers, from Frosch et al.'s *How Secure is TextSecure?* to recent SLRs) and implements the design direction that survey arrives at:

**Authenticate → Establish keys offline → Ratchet → Encrypt → Delete old key material**

Two parties, Alice and Bob, run a real X3DH handshake and a full Double Ratchet in the browser. Each has their own device state; the receiver derives every key independently. A built-in "attack lab" shows what each defence stops and what it doesn't.

> [!IMPORTANT]
> This is an educational prototype, not a production messenger. It keeps all state in memory, uses P-256 instead of Signal's Curve25519, and has not been audited.

## Features

**Chat Mode**: a working two-party messenger
- Alice can message Bob while he is offline (prekey bundle on an untrusted server); Bob rebuilds the session from the prekey header when he comes online.
- Both sides can send. Every reply triggers a Diffie–Hellman ratchet step; every message uses a new key that is erased after use.
- **Hold in transit**: delay a message, send more, then deliver it late. It still decrypts via a stored skipped key, which is then erased.
- **Pad length**: toggle ISO/IEC 7816-4 padding to 64-byte blocks and compare ciphertext sizes (traffic-analysis awareness).
- Contact trust: trust-on-first-use pinning, a 60-digit safety number shown from *both* sides, manual "mark verified", and a blocking key-change warning.
- Attack lab:
  - **Server swaps Bob's keys**: a malicious server hands out Mallory's bundle. With Bob already pinned, Alice is blocked; on first contact, TOFU accepts it and only the safety-number mismatch reveals it. Accepting anyway shows Mallory reading the message.
  - **Bob reinstalls app**: a legitimate key change, which triggers the same warning.
  - **Seize Bob's phone**: an attacker copies Bob's current ratchet state. Every earlier delivered message stays unreadable (forward secrecy); the next messages on the stolen chain are readable; after one round trip with fresh DH keys the attacker is locked out again (post-compromise healing).
- Session inspector: ratchet counters, root/chain key previews, stored late keys, one-time prekeys left on the server, and logs of every key created and erased.

**Key Gen Process**: a 22-step protocol trace from one real run with fresh keys
- Identity generation, signed prekey upload, prekey verification, ephemeral key, the four X3DH DH outputs, HKDF, ratchet initialisation, encryption, Bob's side of X3DH, one-time-prekey erasure, decryption, a DH ratchet step.
- Four attacks that must fail: tampered signed prekey, flipped ciphertext bit, identity re-labelling (unknown key-share), and replay of the first message.
- A forward-secrecy check against a seized device, a safety-number comparison, and a padding observation.
- Each step lists the algorithm, inputs, outputs, verification, failure mode, and the paper it comes from.

## Cryptographic model

All primitives come from the browser's Web Crypto API. No custom ciphers.

| Purpose | Implementation |
| --- | --- |
| Identity | ECDSA P-256 signing key + ECDH P-256 agreement key; the signing key certifies the agreement key |
| Fingerprint / safety number | SHA-256 over both identity public keys / over both parties' fingerprints |
| Handshake | X3DH: signed prekey + one-time prekey, 4 ECDH outputs (3 if prekeys run out), HKDF-SHA256 |
| Ratchet | Double Ratchet per Signal's spec: `KDF_RK` = HKDF-SHA256, `KDF_CK` = HMAC-SHA256, `MAX_SKIP` = 50 |
| Message encryption | AES-256-GCM; key and IV derived from the single-use message key |
| Identity binding | AD = both fingerprints, plus the ratchet header, authenticated on every message |
| Metadata | Optional length padding to 64-byte blocks |

Every decrypt works on a copy of the session state and only commits on success, so a forged or corrupted message can't damage a session.

## Getting started

Requires Node.js 20.9+ and a modern browser.

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Scripts

```bash
npm run dev    # Development server
npm run build  # Production build
npm run start  # Serve the production build
npm run lint   # TypeScript type check
npm test       # Protocol unit tests (node:test via tsx)
```

The test suite (`tests/protocol.test.ts`) covers the PLAN.md test plan and more: identity certificates, signed-prekey tampering, matching X3DH secrets, one-time prekey consumption and replay, HKDF separation, two-way messaging with DH ratchet steps, ciphertext/header/AD tampering leaving state intact, out-of-order delivery, padding, forward secrecy and healing after compromise, key-change detection, and first-contact MITM detection via safety numbers.

## Project structure

```text
.
|-- app/
|   |-- globals.css          # Terminal-inspired styling
|   |-- layout.tsx
|   `-- page.tsx             # Mode selector
|-- components/
|   |-- ChatMode.tsx         # Two-party messenger + attack lab
|   |-- KeyGenMode.tsx       # Protocol trace debugger
|   `-- ui.tsx               # Shared panels, metrics, badges
|-- lib/protocol/
|   |-- primitives.ts        # Web Crypto wrappers, padding
|   |-- identity.ts          # Identity keys, fingerprints, safety numbers
|   |-- x3dh.ts              # Prekeys and the X3DH handshake
|   |-- ratchet.ts           # Double Ratchet, skipped keys, compromise model
|   |-- device.ts            # Per-user device, sessions, TOFU, prekey server
|   |-- walkthrough.ts       # Runs the protocol once for Key Gen mode
|   `-- trace.ts             # Trace and key-event types
|-- tests/protocol.test.ts
|-- literature_survey.md
`-- How_Secure_is_TextSecure.pdf
```

## From the literature to the code

| Survey finding | Where it lives |
| --- | --- |
| Prekeys let a recipient be offline (Frosch et al.; fixes Shen's online-only handshake) | `x3dh.ts`, `PreKeyServer` in `device.ts` |
| Ephemeral keys alone allow MITM; the handshake must be authenticated (SAKTI) | Signed prekeys + identity certificate, `initiateX3dh` |
| Bind both identities into the MAC to stop unknown key-share (Frosch et al.) | `associatedData` in `x3dh.ts`, used as AEAD AD |
| Trust establishment is its own problem (Unger et al. SoK) | TOFU pinning, safety numbers, key-change blocking |
| Ratcheting matters in deployed apps (Onik et al.; Afreen & Ivaturi) | `ratchet.ts` |
| Forward security by erasing old keys (Canetti, Halevi & Katz) | Message keys, ephemeral keys and one-time prekeys erased after use |
| Late messages break time-based erasure (Canetti et al.; Green & Miers) | Skipped-key store with `MAX_SKIP` |
| Encryption doesn't hide traffic patterns (Afzal et al.) | Length padding toggle, wire-size display |
| Use standard primitives (Adebayo; SAKTI's custom cipher as counter-example) | Web Crypto only: ECDH, ECDSA, HKDF, HMAC, AES-GCM |

## Limitations and future work

- State is in memory in one tab; there is no real network, account system, or persistent key store.
- Private keys are created extractable only so the UI can preview what gets erased; "erasure" drops references and zeroes buffers, which JavaScript can't strictly guarantee.
- P-256 rather than X25519/Ed25519, so it is not wire-compatible with Signal.
- Signed prekeys are never rotated, and there's no one-time prekey replenishment.
- Padding hides length, not timing or message count.
- Not implemented from the survey's advanced layer: puncturable encryption (Green & Miers; Wei et al.), MLS group messaging, post-quantum hybrid key exchange (PQXDH).

## License

No license has been specified. Unless a license is added, all rights remain with the repository owner.
