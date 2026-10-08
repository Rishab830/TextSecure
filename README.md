# Cipher in Motion

Cipher in Motion is an interactive, browser-based demonstration of secure messaging with forward secrecy. It accompanies the literature survey in this repository and makes the major stages of a TextSecure/Signal-inspired session visible: identity generation, signed prekey verification, X3DH-style key agreement, chain-key evolution, authenticated encryption, tamper detection, and key erasure.

> [!IMPORTANT]
> This project is an educational prototype, not a production messenger or a complete implementation of the Signal Protocol. It keeps all state in memory, uses a deliberately simplified ratchet, and has not undergone a security audit.

## Features

- **Chat Mode** simulates a one-to-one encrypted conversation between Alice and Bob.
- **Key Gen Process** walks through the cryptographic setup and verification flow step by step.
- Generates fresh identity, signed prekey, one-time prekey, and ephemeral key pairs in the browser.
- Verifies Bob's signed prekey before establishing a session.
- Combines four ECDH results in an X3DH-style exchange and derives separate keys with HKDF-SHA256.
- Encrypts messages with AES-256-GCM and binds both identities as authenticated associated data.
- Advances the sending chain and records old message keys as erased to illustrate forward secrecy.
- Demonstrates rejection of a modified signed prekey and modified associated data.
- Displays fingerprints, ratchet counters, deleted-key records, and ciphertext envelope sizes.

## Cryptographic model

The demo uses the browser's Web Crypto API; private key material never needs to be sent to a server.

| Purpose | Implementation |
| --- | --- |
| Identity signatures | ECDSA P-256 with SHA-256 |
| Key agreement | ECDH P-256 |
| Session setup | Four-DH, X3DH-style construction |
| Key derivation | HKDF-SHA256 |
| Message encryption | AES-256-GCM with a fresh 96-bit IV |
| Identity binding | Alice and Bob fingerprints in AES-GCM associated data |
| Forward-secrecy illustration | One-way chain-key advancement and old-key erasure |

This is inspired by the protocol concepts discussed in the included literature, but it is not wire-compatible with Signal. In particular, it uses P-256 primitives supported by Web Crypto instead of Signal's Curve25519-based primitives and implements only a simplified, one-direction chain rather than the full Double Ratchet.

## Getting started

### Prerequisites

- Node.js 20.9 or newer
- npm
- A modern browser with Web Crypto support

### Install and run

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser. Choose **Chat Mode** to exchange sample encrypted messages, or **Key Gen Process** to inspect each protocol stage and tamper check.

## Available scripts

```bash
npm run dev    # Start the development server
npm run build  # Create a production build
npm run start  # Serve the production build
npm run lint   # Run the TypeScript type checker
```

## Project structure

```text
.
|-- app/
|   |-- globals.css       # Terminal-inspired interface and responsive layout
|   |-- layout.tsx        # Root layout and page metadata
|   `-- page.tsx          # Mode selector, chat UI, and protocol walkthrough
|-- lib/
|   `-- crypto-demo.ts    # Web Crypto primitives and demo protocol state
|-- literature_survey.md  # Review of secure-messaging research
|-- How_Secure_is_TextSecure.pdf
|-- PLAN.md               # Original implementation plan
`-- package.json
```

## How the demo works

1. Alice and Bob receive fresh signing, identity-agreement, signed-prekey, and one-time-prekey material.
2. Bob signs his prekey, and Alice verifies that signature before continuing.
3. Alice creates a fresh ephemeral key and performs four ECDH operations against Bob's bundle.
4. HKDF-SHA256 converts the combined shared material into root and sending-chain keys.
5. Each message derives a unique AES-GCM key and the next chain key.
6. The ciphertext authenticates the sender and receiver fingerprints as associated data.
7. After sending, the session advances and the previous message key is no longer retained.

The protocol trace also modifies a signed prekey and the authenticated identity data to show that signature verification and AES-GCM authentication reject tampering.

## Security limitations

- All users, sessions, and messages exist only in the current browser tab and disappear on refresh.
- There is no backend, account system, persistent key store, multi-device support, or network transport.
- Exportable private keys are used so the interface can display educational previews; production keys should use hardened, non-exportable storage where possible.
- The ratchet is a teaching model and does not provide the complete guarantees of the Signal Double Ratchet.
- Trust-on-first-use and fingerprint verification are displayed, but no real verification ceremony is enforced.
- The application has not been formally verified, audited, or penetration tested.

## Background material

See [`literature_survey.md`](literature_survey.md) for the research summary that motivated the demo. The repository also includes Frosch et al.'s *How Secure is TextSecure?* paper as [`How_Secure_is_TextSecure.pdf`](How_Secure_is_TextSecure.pdf).

## Tech stack

- Next.js 16
- React 19
- TypeScript
- Web Crypto API
- Lucide React

## License

No license has been specified. Unless a license is added, all rights remain with the repository owner.
