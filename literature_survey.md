# Literature Review: Secure Messaging with Forward Secrecy
### Prep notes for building a Secure Messaging App

---

## 1. Frosch et al., "How Secure is TextSecure?" (IEEE EuroS&P 2016)

| Category | Notes |
|---|---|
| **Problem** | TextSecure/Signal's protocol had never been formally, completely documented or proven secure. |
| **Objective** | Reverse-engineer and document the full protocol; give formal security proofs; find/fix flaws. |
| **Threat model** | Active network adversary controlling messages; registered malicious participants (for the UKS attack); server assumed honest for the main proofs. |
| **Architecture** | Three building blocks: cached One-Round Key Exchange (cORKE) → Key Derivation Function (KDF/HKDF) → Authenticated Encryption. Server relays via push (GCM), never sees plaintext. |
| **Cryptography** | Curve25519 ECDH, AES (CTR for messages, CBC for server→GCM layer), HMAC-SHA256, HKDF. |
| **Key exchange** | Precursor to X3DH: sender combines 3 DH values — (their identity key × recipient prekey), (their ephemeral key × recipient identity key), (their ephemeral key × recipient prekey) — into a root key via HKDF. |
| **Forward secrecy** | Yes. Ephemeral DH private shares deleted immediately after use; ratchet (precursor to the Double Ratchet / "Axolotl") advances root key + chaining key every message. |
| **Key management** | Long-term identity keypair + 100 one-time "prekeys" + one "last-resort" key pre-uploaded to server; prekeys deleted once consumed. |
| **Authentication** | Weak in early version — registration protected only by a password stored in plaintext on-device; later versions added Ed25519 signatures on prekeys, but keys still not bound to identity (didn't fully fix it). |
| **Encryption** | Encrypt-then-MAC: AES-CTR then HMAC-SHA256 over ciphertext — proven IND-CCA + INT-CTXT secure. |
| **Message flow** | Sender fetches recipient prekey+identity key from server → derives root key → ratchets → sends ciphertext+MAC to server → server re-encrypts metadata for GCM → recipient decrypts. |
| **Server trust** | Cannot read message content; but can enable an **Unknown Key-Share (UKS)** attack if it colludes, or if an attacker steals a user's registration password. |
| **Compromise scenario** | Found a real UKS/identity-misbinding flaw: attacker can register a victim's prekeys under their own account, causing message misattribution. Proposed fix: bind both parties' phone numbers into the MAC. |
| **Performance** | Not benchmarked (this is a security-proof paper, not a systems paper). |
| **Implementation** | None shipped — analysis was done against the real Android source. |
| **Results** | Formal proofs: cORKE is a secure key-exchange protocol (Gap-DH assumption), the KDF is secure, and the encryption scheme is IND-CCA/INT-CTXT secure — *if* key registration is honest. |
| **Limitations** | Only proves the building blocks individually, not their composition; deniability only holds in theory (server logs delivery, which is provable metadata evidence); PFS is a "weaker" variant since keys must be retained until acknowledged. |
| **Future work** | Replace password-based prekey registration with a zero-knowledge Schnorr proof-of-possession of the identity key. |
| **Useful for your app** | **This is your blueprint.** It's the clearest description of what became X3DH + Double Ratchet. Copy the pattern: long-term identity key + signed one-time prekeys fetched from server + per-message ratcheting via HKDF + encrypt-then-MAC. Also: don't repeat their mistake — bind both parties' identities into the authenticated data to prevent UKS attacks, and never rely on a password alone to protect key registration. |

---

## 2. Afzal et al., "Encrypted Network Traffic Analysis of Signal Messenger App" (Applied Sciences 2021)

| Category | Notes |
|---|---|
| **Problem** | Not a crypto-design paper — a forensics paper: can an investigator learn *what a user was doing* on Signal just from encrypted traffic, without breaking the encryption? |
| **Objective** | Fingerprint app behaviors (open app, typing, calls, media, close) from packet size/timing patterns. |
| **Threat model** | Network forensic examiner (passive observer with firewall access); no attempt to decrypt content. |
| **Architecture** | pfSense firewall + Wireshark capturing traffic between an Android phone and Signal's servers. |
| **Cryptography** | Not analyzed — traffic is TLS 1.2 + Signal Protocol; paper treats it as a black box. |
| **Key exchange** | Observed only at the metadata level: DNS → list of ~8 chat servers, STUN (Google) + TURN (Signal) servers for calls. |
| **Forward secrecy** | N/A. |
| **Key management** | N/A. |
| **Authentication** | TLS certificate exchange observed, not evaluated. |
| **Encryption** | TLS 1.2 transport layer; app payload is opaque (Signal Protocol, not inspected). |
| **Message flow** | Client → DNS query for chat servers → TCP+TLS handshake (port 443) → encrypted app data. Calls: DNS for STUN/TURN → UDP binding → relayed media. |
| **Server trust** | Confirms Signal servers can't read content, but traffic *metadata* (packet size sequences, ports, IP lists) reliably reveals: app open/close, who's typing, call start/end, media sent — even without decryption. |
| **Compromise scenario** | Not a crypto compromise — a **metadata/side-channel** privacy leak. Relevant lesson: encryption alone does not hide behavior. |
| **Performance** | N/A. |
| **Implementation** | Signal Android v4.58.5, pfSense 2.4.4, Wireshark 3.0.6, physical test rig. |
| **Results** | Concrete byte-length signatures for each activity type (Table 4 in the paper) and a working list of Signal's server IP ranges/ports. |
| **Limitations** | Version-dependent (patterns break when Signal updates); no device-level forensics; can't recover plaintext. |
| **Future work** | GUI tool; generalize the method to other IM apps. |
| **Useful for your app** | Not a crypto reference, but an important **QA/red-team checklist item**: after you build your app, capture your own traffic with Wireshark and check whether packet sizes/timing leak "typing," "call started," etc. If metadata privacy matters to your users, consider padding messages to fixed sizes and adding artificial jitter — this paper shows exactly why that matters. |

---

## 3. Ab Halim et al., "SAKTI©: Secured Chatting Tool Through Forward Secrecy" (JARAST 2025)

| Category | Notes |
|---|---|
| **Problem** | Build a simple Android chat app that provides Perfect Forward Secrecy as an alternative security story to WhatsApp/Telegram/Signal. |
| **Objective** | Implement ECDHE key exchange + a custom lightweight symmetric cipher (LAO-3D) for session encryption. |
| **Threat model** | Loosely defined — mainly "eavesdropper on the session key." **Explicitly does not defend against MITM** (acknowledged as a limitation). |
| **Architecture** | 3 phases: Registration → Key Exchange → Transfer Data. |
| **Cryptography** | ECDHE on curve **SECP256k1**; custom **LAO-3D** symmetric block cipher for message encryption; a KDF turns the DH pre-master secret into the session key. |
| **Key exchange** | Alice and Bob each generate a fresh ephemeral keypair (PrvKA/PrvKB) per session, exchange public points, compute pre-master secret = PrvKA·PrvKB·G, then KDF(PMS) → session key. |
| **Forward secrecy** | Yes — ephemeral keys destroyed at session end; each new session gets fresh keys with no cross-session correlation. |
| **Key management** | Client-side generation and deletion only; **no long-term signing key / certificate** to bind ephemeral keys to an identity yet. |
| **Authentication** | **None.** This is the paper's core weakness — raw, unauthenticated ECDHE is trivially MITM-able. The authors know this and list it as future work (want to add RSA/ECDSA signatures). |
| **Encryption** | LAO-3D custom cipher keyed by the session key. |
| **Message flow** | Sender picks a friend from a list → presses key icon to generate/send public key → receiver accepts/declines/times-out (30s) → on success, session key derived → data encrypted and transferred. |
| **Server trust** | Not fully specified; key transfer appears to go through the app's backend, three possible outcomes (success/fail/decline). |
| **Compromise scenario** | MITM is the explicit, acknowledged failure mode — no way today to verify you're really talking to who you think you are. |
| **Performance** | Solid ECC-vs-RSA key-generation benchmarks: a 256-bit ECC keypair generates in ~270–607ms vs. a 3072-bit RSA keypair at ~9.8–16.7s for equivalent ~128-bit security — a strong argument for ECC on mobile. |
| **Implementation** | Working Android prototype with registration/login UI and key-exchange sequence diagrams. |
| **Results** | Confirms ECC is dramatically faster than RSA at matched security levels; forward secrecy achieved and demonstrated per their own testing. |
| **Limitations** | No MITM protection (no auth), Android-only, currently **one-way** communication (one party sends, other only reads — not yet a real bidirectional chat). |
| **Future work** | Add digital signatures/certificates (RSA or ECDSA) for identity verification; extend to bidirectional/group chat. |
| **Useful for your app** | Good, simple reference architecture for the 3-phase flow (Register → Exchange → Transfer), and useful ECC-vs-RSA benchmark data to justify your curve choice. But treat it as a **cautionary example**: don't ship ECDHE without authentication. You need to either (a) sign the ephemeral public key with a long-term identity key (like Signal's Signed PreKey), or (b) support manual out-of-band fingerprint verification (like Signal's safety numbers), or ideally both. |

---

## 4. Shen, "End-to-End Encrypted Messaging Based on PGP with Forward Secrecy" (J. Phys. Conf. Ser. 2021)

| Category | Notes |
|---|---|
| **Problem** | Classic PGP has no forward secrecy — a leaked long-term private key exposes every past message ever sent. |
| **Objective** | Combine PGP's decentralized web-of-trust (for authentication) with per-session Diffie–Hellman (for forward secrecy), without any central authority. |
| **Threat model** | Network/MITM adversary; assumes Alice and Bob have already exchanged PGP public keys securely (e.g., in person / key-signing party). |
| **Architecture** | Browser-based client (Flask web server + GPGME) connects through a **WebSocket Secure relay server** that only forwards packets and stores nothing; anyone can run their own relay (decentralized). |
| **Cryptography** | PGP/GPG for identity, signing, and encrypting the handshake; classic Diffie–Hellman for the ephemeral per-session key; symmetric cipher for the actual chat messages. |
| **Key exchange** | Every new session triggers a DH exchange **wrapped inside a PGP-signed-and-encrypted packet** — this is the key idea: PGP authenticates the DH handshake, DH gives PGP forward secrecy. |
| **Forward secrecy** | Yes, proven: even if an attacker later obtains both users' long-term PGP private keys, they still can't decrypt past sessions because the ephemeral DH key was discarded when the session ended. |
| **Key management** | Long-term PGP keypair persists indefinitely; ephemeral DH keypair generated and destroyed per session. |
| **Authentication** | PGP digital signatures on every handshake packet — an attacker without the private key cannot forge the DH exchange, which directly prevents MITM. |
| **Encryption** | Symmetric cipher keyed by the DH shared secret for chat content; PGP encrypts/signs the surrounding protocol packets. |
| **Message flow** | Import each other's PGP public keys (out of band) → DH handshake (signed+encrypted via PGP) → derive session key → symmetric-encrypt messages → relay through WebSocket server. |
| **Server trust** | Relay-only, stores nothing, cannot read content (PGP+DH end-to-end); fully decentralized — no dependency on a specific provider. |
| **Compromise scenario** | Formally proven (Theorem 1 + follow-on analysis): PGP compromise alone ≠ message compromise, because the session key isn't derivable from long-term keys alone. Replay attacks blocked via timestamps + sequence numbers. |
| **Performance** | Not benchmarked quantitatively — simple demo implementation. |
| **Implementation** | Cross-platform browser client (any OS with Python + browser) + a lightweight relay server. |
| **Results** | Working proof-of-concept; clean theoretical proof of confidentiality/completeness and MITM resistance. |
| **Limitations** | Both parties must be online simultaneously to complete the initial DH handshake (**no offline/async messaging**); one-on-one chat only, no groups. |
| **Future work** | Extend the protocol to group conversations without weakening security. |
| **Useful for your app** | This is the direct fix for SAKTI's missing piece: **wrap your ephemeral ECDHE exchange inside something signed by a long-term identity key**, so the handshake itself is authenticated and MITM-resistant, while the ephemeral key still gives you forward secrecy. It's also a good decentralization pattern if you don't want to depend on one company's servers — though note its big limitation (both users online at once) is exactly what prekeys (paper #1/#6) solve. |

---

## 5. Unger et al., "SoK: Secure Messaging" (IEEE S&P 2015)

This is a **systematization paper**, not one specific protocol — it's the master reference for every design decision you'll face.

| Category | Notes |
|---|---|
| **Problem** | Dozens of "secure" messaging tools existed with inconsistent threat models, vague claims, and no unified comparison. |
| **Objective** | Build an evaluation framework across three problem areas — **trust establishment**, **conversation security**, **transport privacy** — and score every known approach. |
| **Threat model** | Local network adversary, global (nation-state) adversary, and the service provider itself, all potentially colluding. |
| **Architecture** | N/A — a comparative framework, not one system. |
| **Cryptography** | Surveys: OTR, TextSecure/Axolotl (double ratchet), 3-DH handshake, prekeys, OpenPGP/S/MIME, Forward-Secure IBE, puncturable encryption, DC-nets, onion routing, PIR, blockchain naming. |
| **Key exchange** | Compares TOFU, manual fingerprint verification, Short Authentication Strings (SAS/ZRTP), Socialist Millionaire Protocol, authority-based (key directories/CAs), transparency logs, web-of-trust, blockchains. |
| **Forward secrecy** | Extensively analyzed. Their conclusion: the **Double Ratchet (Axolotl)**, combined with a **3-DH handshake** and **prekeys** (i.e., what became Signal/TextSecure) is the best-balanced design — it gives forward secrecy *and* backward/post-compromise secrecy *and* asynchronous (offline) messaging, at the cost of some implementation complexity. |
| **Key management** | Compares 9+ trust-establishment schemes on 20 usability/security/adoption axes (Table I) — none score perfectly on everything. |
| **Authentication** | SAS, SMP, mandatory manual verification (SafeSlinger), authority-based trust, transparency logs. |
| **Encryption** | Static asymmetric crypto (loses repudiation), authenticated DH/AKE, double ratchet, FS-IBE, puncturable encryption. |
| **Message flow** | N/A (survey). |
| **Server trust** | Deep dive on what a malicious/coerced server operator can and can't do under each scheme; transparency logs give "operator accountability" even authority-based trust alone doesn't. |
| **Compromise scenario** | Formal deniability framework (message repudiation vs. participation repudiation) — relevant if you ever want your app to offer "this proves nothing in court" guarantees like OTR/Signal. |
| **Performance** | Qualitative scoring tables only (usability/adoption), not runtime benchmarks. |
| **Implementation** | Surveys real tools: OTR, TextSecure/Signal, Threema, iMessage, S/MIME, Wickr, Confide, etc. |
| **Results** | Key conclusion for you: **layered design wins** — start from a usable baseline (central key directory + TOFU), then layer optional stronger verification (QR-code fingerprint scan) for security-conscious users, plus TOFU warnings when a contact's key changes. TextSecure/Threema are cited as good examples of this pattern. |
| **Limitations** | No single trust-establishment scheme achieves all usability + security + adoption properties simultaneously — it's a fundamental trade-off, not an engineering gap. |
| **Future work** | More research on transparency logs, end-user mental models for trust establishment, group-chat consistency guarantees. |
| **Useful for your app** | **The single most useful reference for your overall design.** Use it to consciously choose your trade-offs: (1) Trust establishment → TOFU by default + optional QR-code fingerprint verification for paranoid users (Signal's actual approach). (2) Conversation security → Double Ratchet + 3-DH + Prekeys (i.e., re-implement or use libsignal). (3) Transport privacy → be honest with yourself that hiding *who's talking to whom* is extremely hard and costly; most apps (including Signal) don't fully solve it. |

---

## 6. Afreen & Ivaturi, "A Systematic Literature Review on E2E Cryptographic Protocols in Secure Messaging" (2025)

| Category | Notes |
|---|---|
| **Problem** | No up-to-date (2015–2025) comparison of Signal/WhatsApp/Telegram/MLS/post-quantum crypto across forward secrecy, post-compromise security, metadata protection, and quantum resistance. |
| **Objective** | Run a formal SLR (PRISMA-style, 250→30 papers) scoring these protocols on those four axes. |
| **Threat model** | Passive/active eavesdroppers, mass surveillance states, **future quantum adversaries**, and device-level attackers (e.g., spyware bypassing crypto entirely). |
| **Architecture** | Compares Signal (X3DH + Double Ratchet), WhatsApp (Signal Protocol + Sender Keys for groups), Telegram (MTProto, E2EE only in opt-in "Secret Chats"), MLS (TreeKEM), and experimental PQC prototypes. |
| **Cryptography** | X3DH, Double Ratchet, TreeKEM, CRYSTALS-Kyber, Dilithium, hybrid X25519+Kyber; flags that today's ECC is **vulnerable to Shor's algorithm** on a future quantum computer. |
| **Key exchange** | X3DH (Signal); TreeKEM (MLS) — solves Signal's group-messaging weakness by updating only the affected branch of a key tree instead of re-keying pairwise with every member (avoids Signal's O(n²)-ish overhead). |
| **Forward secrecy** | Signal/WhatsApp/MLS: Yes. Telegram (default chats): **No** — regular chats aren't E2E at all. DTLS: No (transport-only). |
| **Key management** | Ratchet-based; MLS's tree structure makes group rekeying scale far better than Signal's per-pair approach. |
| **Authentication** | Implied via long-term identity keys in Double Ratchet/X3DH and signatures in TreeKEM; not deeply detailed in this SLR. |
| **Encryption** | AES-GCM typical across all reviewed protocols. |
| **Message flow** | High-level only — this is a survey, not an implementation paper. |
| **Server trust** | Important finding: **even Signal's "sealed sender" doesn't fully hide metadata** — recipient identity and traffic timing still leak. WhatsApp explicitly shares metadata with Meta. |
| **Compromise scenario** | Real-world case studies: **Pegasus spyware** bypassed encryption entirely by compromising the *device*, not the protocol — a reminder that crypto is necessary but not sufficient. Post-compromise security (PCS) via ratchet key updates is how Signal/MLS recover after a key leak. |
| **Performance** | A weighted scoring rubric (Security 30%, Metadata 20%, Usability 15%, Scalability 15%, Agility 10%, Maturity 10%) rates: **MLS 4.3/5, Signal 4.1/5, WhatsApp 4.0/5, PQC 3.5/5, Telegram 3.1/5, DTLS 2.2/5.** |
| **Implementation** | None — pure literature review, no original code. |
| **Results** | Signal/WhatsApp = best today for security+maturity but weak metadata protection; Telegram = usable but cryptographically weak by default; MLS = best future-facing design (scalable + cryptographically agile) but still maturing; PQC = promising but not production-ready on mobile. |
| **Limitations** | Excludes non-peer-reviewed/proprietary docs; few real user studies; PQC results are mostly lab-only, not tested on real mobile constraints. |
| **Future work** | Sealed-sender-by-default + mixnets/cover traffic for metadata; hybrid PQC (X25519+Kyber) migration path; formal verification via ProVerif/Tamarin/CryptoVerif; secure-by-default UX (no opt-in encryption, unlike Telegram); open governance/no backdoors. |
| **Useful for your app** | Gives you a **forward-looking checklist** so your app doesn't look dated in 2–3 years: (1) build on X3DH+Double Ratchet now; (2) if you ever need group chat at scale, plan a migration path toward MLS/TreeKEM instead of Signal's pairwise approach; (3) budget for a future hybrid PQC key-exchange upgrade; (4) make encryption on-by-default, never opt-in (Telegram's biggest mistake); (5) before shipping, run your handshake through a formal verifier like ProVerif or Tamarin. |

---



### 7. Canetti, Halevi & Katz — "A Forward-Secure Public-Key Encryption Scheme" (EUROCRYPT 2003)

| Category | Details |
|---|---|
| **Problem** | Key exposure on insecure devices compromises all past communications |
| **Objective** | Non-interactive forward-secure PKE — first of its kind |
| **Threat model** | Adversary who fully compromises the secret key at some time period *i* |
| **Architecture** | Binary Tree Encryption (BTE) — HIBE-like tree where secret keys evolve down a path |
| **Cryptography** | Bilinear pairings (Bilinear Diffie-Hellman) |
| **Key exchange** | None — this is public-key encryption, not interactive |
| **Forward secrecy** | Yes — core contribution. Secret key updates each period; old key erased |
| **Key management** | Key evolves via `Upd` function; O(log N) update/decrypt time in standard model, O(1) in random oracle model |
| **Authentication** | Not addressed directly |
| **Encryption** | CPA-secure; extendable to CCA via Sahai/Fujisaki-Okamoto |
| **Message flow** | Sender uses fixed public key + time period; receiver decrypts with evolved key |
| **Server trust** | N/A — theoretical primitive, not a messaging system |
| **Compromise scenario** | Compromise at period *i* only affects that and future periods; past is secure |
| **Performance** | Practical — "roughly as efficient as log₂N invocations of Boneh-Franklin IBE" |
| **Implementation** | Theoretical/cryptographic, no software artifact |
| **Limitations** | Losing decryption capacity entirely after update — can't decrypt late-arriving messages from before update (this is exactly what the two later papers fix) |
| **Useful for your app** | This is the **foundational primitive** — your app's "epoch-based key rotation" should follow this idea, but you'll want the puncturable-encryption fix below for practical async messaging |

---

### 8. Onik, Brown, Walker & Baggili — "Systematic Literature Review of Secure Instant Messaging Apps" (2025)

| Category | Details |
|---|---|
| **Problem** | Forensic/security landscape across real deployed apps |
| **Objective** | Survey WhatsApp, Signal, Telegram, Wickr, Threema — encryption + forensics |
| **Architecture** | Details real-world E2EE flows (diagrams) for each app |
| **Cryptography** | Signal Protocol (X3DH + Double Ratchet), MTProto 2.0 (Telegram), NaCl/XSalsa20+Poly1305 (Threema), ECDH-521+AES-256-GCM (Wickr) |
| **Key exchange** | Signal: Identity Key + Signed Prekey + One-Time Prekey (X3DH); Telegram: DH; Threema: static ECDH, **no ratchet** — weaker |
| **Forward secrecy** | Signal/WhatsApp: yes, via Double Ratchet. Telegram: partial. Threema: static keys = **weaker FS** |
| **Server trust** | Signal stores minimal metadata (phone, last-seen); WhatsApp retains richer metadata |
| **Compromise scenario** | Threema table shows real attacks: key compromise, cloning via exported private key, replay attacks |
| **Results** | Comparison table (Table 3) scoring apps on confidentiality, integrity, PFS, deniability, multidevice |
| **Limitations** | This is descriptive, not a new construction — no novel crypto proposed |
| **Useful for your app** | Best reference for **practical design choices**: how real apps structure keys, what metadata leaks even with E2EE, and Signal's Double Ratchet as the gold-standard architecture to imitate |

---

### 9. Wei, Chen, Ma, Hu & Ren — "Communication-Efficient Fine-Grained Forward-Secure Asynchronous Messaging" (IEEE/ACM ToN 2021)

| Category | Details |
|---|---|
| **Problem** | Green-Miers' FSPE has ciphertext size linear in number of tags; not standard-model secure |
| **Objective** | Constant-ciphertext-size FSPE, secure in standard model |
| **Threat model** | Selective-security adversary; secret key exposure at time τ shouldn't reveal earlier periods or already-decrypted (punctured) messages |
| **Architecture** | Binary tree over time periods (leaf-based, unlike Canetti et al.'s internal-node approach) + puncturable component per-message |
| **Cryptography** | Bilinear pairings, q-DBDHE assumption, Boneh-Boyen programmable hash |
| **Forward secrecy** | Fine-grained: puncturing after each decrypted message revokes only that message's key, not the whole period |
| **Key management** | `Update` (per time period) + `Puncture` (per message) — both unidirectional, keys erased after |
| **Encryption** | Constant ciphertext size (~1.73 KB), independent of tag-set size |
| **Performance** | Decryption ~1.75 s worst case (100 punctures) on desktop; outsourced-decryption variant cuts user cost to 1 exponentiation |
| **Implementation** | Charm framework (Python), BN254 curve |
| **Limitations** | Pairing-based crypto is heavy for mobile; standard-model security comes at a computation cost vs. random-oracle schemes |
| **Useful for your app** | If you want **fine-grained deletion of individual received messages** (not just periodic key rotation) — e.g., "forget this specific message even after key rotation" — this is the model. Likely overkill for a first version but great research grounding |

---

### 10. Green & Miers — "Forward Secure Asynchronous Messaging from Puncturable Encryption" (IEEE S&P 2015)

| Category | Details |
|---|---|
| **Problem** | FS-PKE (Canetti et al.) is too blunt — updating the key loses **ALL undelivered messages** from the prior period |
| **Objective** | Fine-grained revocation: delete individual messages/senders without losing others |
| **Architecture** | Puncturable Encryption (tag-based, built on Ostrovsky-Sahai-Waters non-monotonic ABE) combined with FS-PKE via HIBE (Boneh-Boyen-Goh) |
| **Cryptography** | Bilinear pairings; DBDH / DBDHI assumptions |
| **Forward secrecy** | Dual: coarse-grained (time-period, like Canetti) + fine-grained (per-message tag puncture) |
| **Key management** | `Puncture(SK, tag)` removes decryption ability for just that tag; `NextInterval` advances time period, cryptographically **binding** the two key components so they can't be recombined post-compromise |
| **Message flow** | Sender attaches unique tag (e.g., GUID) to each message; receiver punctures tag after reading |
| **Compromise scenario** | Explicitly analyzes active-attacker message-blocking and key recombination attacks |
| **Performance** | ~4,000 lines of C++ (`libforwardsec`), decrypt <1.75 s even after 100 punctures; designed to integrate with **GnuPG** |
| **Implementation** | Real software library, tested on desktop/laptop/ARM (mobile) |
| **Results** | Benchmarks show ~55 ms decrypt on ARM at 1 msg/sec — practical for mobile |
| **Applications** | Also proposes puncturable encryption for **secure file deletion** (tag files by subject/classification/author) |
| **Useful for your app** | This is the **direct precursor** to Wei et al.'s paper (#3) — read this first for intuition, since it's more implementation-focused with real ARM/mobile benchmarks |

---

### 11. Adebayo — "End-to-End Secure Messaging with PFS in JCA" (2025)

| Category | Details |
|---|---|
| **Problem** | Practical implementation gap: how to actually build E2EE + PFS in Java |
| **Objective** | Systematic JCA-based implementation methodology |
| **Architecture** | Client app + crypto engine + communication channel; ephemeral DH per session |
| **Cryptography** | AES-GCM (symmetric), ECDHE/DH (key exchange), JCA's `KeyPairGenerator` / `KeyAgreement` / `Cipher` / `Signature` |
| **Key exchange** | Ephemeral Diffie-Hellman per session, discarded after use |
| **Forward secrecy** | Yes, via ephemeral session keys not tied to long-term identity keys |
| **Key management** | Long-term keys in Java `KeyStore`; session keys derived and destroyed per exchange |
| **Authentication** | Optional digital signatures per message |
| **Performance** | AES-GCM encrypt/decrypt <5 ms desktop, <12 ms mobile; ~2–3 MB memory/session; ~2–3% network overhead |
| **Implementation** | Prototype-level, Java-only |
| **Limitations** | Not benchmarked at scale; no group messaging; no multi-device sync design |
| **Useful for your app** | Practical starting point for implementing E2EE + PFS in Java/JCA, especially for key generation, ephemeral DH, AES-GCM encryption, and secure key handling |
