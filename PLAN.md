# Secure Messaging Web App With Forward Secrecy

## Summary
Build a Next.js web app based on the literature survey in [literature_survey.md](D:/Sem7/Cryptography/EndSem/literature_survey.md). The app will have two main modes from the first page:

- **Chat Mode**: a polished view of what the final secure messaging product would look like.
- **Key Gen Process Mode**: an educational walkthrough that shows the internal cryptographic mechanisms step by step.

The project is an educational prototype, not a production secure messenger. The implementation should use reputable browser-compatible crypto libraries for primitives, while keeping the protocol flow visible and easy to explain.

## App Structure
- Use **Next.js + TypeScript** for the full app.
- Use a first-page mode selector with two clear actions:
  - Enter Chat Mode.
  - Enter Key Gen Process Mode.
- Keep all cryptographic demo logic client-side so private keys never need to be sent to a backend.
- Use mock/in-memory app state for users, contacts, prekeys, sessions, and encrypted messages.
- Avoid a separate Python or Express backend for v1.

## Visual Style
- Match the provided reference image: a dark, terminal-inspired interface with a restrained cyber/retro workshop feel.
- Use a near-black background with subtle horizontal scanlines/noise texture across the full viewport.
- Use a centered framed panel for the first page, with thin borders, a bright neon green top rule, and generous vertical spacing.
- Use monospaced typography throughout the app.
- Use neon green as the primary accent for main headings and primary actions.
- Use cyan/teal as a secondary accent for alternate actions, verification states, and technical highlights.
- Use muted gray labels and helper text so the neon accents stand out.
- Use rectangular controls with sharp or very small-radius corners; avoid soft rounded cards.
- Buttons should feel like terminal commands:
  - Uppercase labels.
  - Wide letter spacing.
  - Thin borders for secondary actions.
  - Filled neon green for primary actions.
  - Optional arrow suffixes such as `CHAT MODE ->` or `BEGIN KEYGEN ->`.
- Add subtle glow only around active or primary elements; avoid large gradients, orbs, bokeh, or decorative illustrations.
- Use panel dividers as thin horizontal rules.
- Preserve the same visual language across Chat Mode and Key Gen Process Mode so both feel like parts of one secure terminal product.

## Chat Mode
- Present a realistic one-to-one secure chat interface:
  - Contact list.
  - Active conversation panel.
  - Message composer.
  - Sent/received encrypted messages.
  - Contact verification status.
  - Key-change warning state.
- Show subtle security metadata without overwhelming the chat UI:
  - Current session status.
  - Contact fingerprint.
  - Whether the contact is trusted by TOFU or manually verified.
  - Ciphertext size or envelope size for sent messages.
- Simulate the final product behavior:
  - Alice and Bob can exchange messages in the same browser demo.
  - Messages are encrypted before being placed into the message store.
  - Messages are decrypted only by the intended receiver session.
  - Old message keys are deleted after use to demonstrate forward secrecy.
- Style Chat Mode like a secure operations console:
  - Left column for contacts and trust status.
  - Main terminal-like conversation panel.
  - Right or lower inspector panel for fingerprints, session state, ciphertext size, and ratchet counters.
  - Message bubbles should be rectangular, low-contrast, and monospaced, with neon accents only for status and verification.

## Key Gen Process Mode
- Build a step-by-step educational flow that explains and visualizes the protocol:
  1. Generate long-term identity key pairs for Alice and Bob.
  2. Generate Bob's signed prekey.
  3. Sign Bob's prekey using Bob's identity signing key.
  4. Verify the signed prekey before Alice trusts it.
  5. Generate Alice's ephemeral key pair for the session.
  6. Derive shared secrets using X3DH-style Diffie-Hellman operations.
  7. Combine shared secrets with HKDF-SHA256 into a root/session key.
  8. Derive message keys using a simplified Double Ratchet-style chain.
  9. Encrypt a sample message with AES-GCM.
  10. Authenticate both users' identities as associated data to prevent unknown key-share style attacks.
  11. Decrypt and verify the message on the receiver side.
  12. Delete old ephemeral/message keys and show why this gives forward secrecy.
- For each step, display:
  - What algorithm is being used.
  - What input material is used.
  - What output is produced.
  - What verification happens.
  - What would fail if an attacker tampers with the data.
- Use short, readable encoded key previews instead of dumping full raw keys everywhere.
- Include a tamper demo:
  - Modify a signed prekey and show signature verification failure.
  - Modify ciphertext or associated data and show AES-GCM authentication failure.
- Style Key Gen Process Mode like a cryptographic trace/debugger:
  - Step list or timeline on one side.
  - Active step details in a large terminal panel.
  - Algorithm name, inputs, outputs, verification result, and failure mode shown as labeled rows.
  - Encoded key previews shown in fixed-width blocks.
  - Successful verification shown in neon green.
  - Tamper/failure states shown with a restrained warning color such as amber or red.

## Cryptographic Model
- Use browser-compatible primitives:
  - X25519 or equivalent ECDH for Diffie-Hellman shared secrets.
  - Ed25519 or equivalent digital signatures for signed prekey verification.
  - HKDF-SHA256 for deriving root, chain, and message keys.
  - AES-GCM for authenticated encryption.
- Do not use custom symmetric ciphers such as LAO-3D.
- Bind both participants' identities into encryption associated data to avoid identity-misbinding and unknown key-share style flaws.
- Make the implementation clearly labeled as simplified and educational, especially around the Double Ratchet model.

## Main Types
- `DemoUser`
- `IdentityKeyPair`
- `SignedPreKey`
- `OneTimePreKey`
- `PreKeyBundle`
- `SessionState`
- `RatchetState`
- `EncryptedEnvelope`
- `VerificationStep`
- `ContactTrustState`

## Test Plan
- Unit tests:
  - Identity keys and prekeys are generated successfully.
  - Signed prekeys verify correctly.
  - Tampered prekeys fail verification.
  - Alice and Bob derive matching session secrets.
  - HKDF produces separate root, chain, and message keys.
  - AES-GCM decrypts valid messages and rejects tampered ciphertext.
  - Associated data mismatch fails decryption.
  - Message keys advance and old keys are removed after use.
- UI/demo tests:
  - First page shows both modes.
  - Chat Mode can send and receive an encrypted message.
  - Key Gen Process Mode can advance through every protocol step.
  - Tamper demo visibly fails at the correct verification stage.
  - Contact fingerprint and trust state are visible in Chat Mode.

## Assumptions
- The project targets an end-semester demonstration.
- Scope is one-to-one messaging only; group chat and MLS/TreeKEM are future work.
- The first version is a fully local browser demo with no real user accounts.
- The app should prioritize clarity, presentation quality, and accurate explanation of the surveyed cryptographic ideas.
- Production concerns such as secure device storage, multi-device sync, push notifications, formal verification, and post-quantum hybrid key exchange are documented as future work.
