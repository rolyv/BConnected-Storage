# Owned group manifest version 1

This implementation is an **unregistered** snapshot signer/verifier. It adds no route, key provisioning, trust bootstrap, admission adapter, gateway or client enablement. Those are remaining integration work under the approved strict-controls policy, not a new product approval prerequisite. A signed historical snapshot is never a current membership, role, device or send grant.

## Standard and library

Use [RFC 7515 compact JWS](https://www.rfc-editor.org/rfc/rfc7515), with the fully specified `Ed25519` algorithm identifier from [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864). The pinned implementation is `com.nimbusds:nimbus-jose-jwt:10.10` with its Ed25519 provider `com.google.crypto.tink:tink:1.23.0`. [Nimbus's Ed25519 documentation](https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-eddsa) documents the fully specified algorithm and the requirement to establish public-key trust independently. This is ordinary JWS signing with the library's Ed25519 implementation, not a new signature algorithm or proof of ACI-to-encrypted-principal equivalence.

The RFC signing input is the exact ASCII `BASE64URL(protected-header) + "." + BASE64URL(payload)`. Verify these received bytes, never JSON reserialization. All three segments are nonempty canonical unpadded base64url (`[A-Za-z0-9_-]+` and decode/encode round-trip equality); the signature is exactly 64 bytes. Detached payloads, unencoded payloads and alternate encodings are unsupported.

## Frozen wire contract

The in-process envelope contains `nativeGroup` (exact protobuf Group bytes) and `compactJws` (ASCII compact JWS). Future JSON transport must carry nativeGroup as canonical unpadded base64url and enforce transport size bounds before decoding; this checkpoint does not define or register an HTTP response route.

The protected header contains exactly these three JSON fields (header field order is immaterial):

```json
{"alg":"Ed25519","kid":"group-manifest-key-1","typ":"bconnected-group-manifest-v1"}
```

`kid` is case-sensitive ASCII `[A-Za-z0-9_-]{1,64}`. Reject duplicate or unknown fields, including `crit`, `b64`, `jku`, `jwk` and X.509 discovery fields; reject `EdDSA`, `none`, alternate types and alternate algorithms.

The UTF-8 payload has exactly the following fields **in this insertion order**, without whitespace, with the nested field orders shown below. This is a versioned, schema-defined deterministic serialization, **not** a claim of generic RFC 8785/JCS compatibility. All strings in this schema are ASCII with the restricted values described below, so no JSON string escape is emitted. JSON numbers are unsigned base-10 integer tokens without leading zeroes, a decimal point, exponent, negative sign or coercion from strings. Duplicate names (including escaped duplicate spellings), unknown/missing fields, nulls, trailing tokens, invalid UTF-8 and alternate serialization are rejected.

```json
{"schemaVersion":1,"iss":"bconnected-group-authority","aud":"bconnected-owned-clients","groupId":"BASE64URL_32_BYTES","publicParamsSha256":"BASE64URL_32_BYTES","authorityRevision":0,"nativeRevision":0,"nativeSha256":"BASE64URL_32_BYTES","announcementsOnly":true,"terminated":false,"access":{"attributes":"ADMINISTRATOR","members":"ADMINISTRATOR","addFromInviteLink":"UNSATISFIABLE","memberLabel":"UNKNOWN"},"directoryListed":false,"roster":[{"aci":"LOWERCASE_CANONICAL_UUID","state":"ACTIVE","role":"ADMINISTRATOR","declaredPrincipal":"BASE64URL_NATIVE_UUID_CIPHERTEXT"}]}
```

* `schemaVersion` is exactly 1; issuer and audience are exact constants above, not deployment host names. They separate this snapshot type from enrollment/registration tokens.
* Revisions are 0 through 4294967295 inclusive. Both revisions equal the unsigned native `Group.version`. The group ID equals the identifier derived by libsignal from native Group.publicKey. `publicParamsSha256` hashes those public parameter bytes, and `nativeSha256` hashes **exact envelope nativeGroup bytes**.
* Booleans match the native group. Access values are exactly the values shown; directory listing remains false. Native invite-link password, pending-admin-approval and banned-member lists are empty for this authority foundation.
* Roster is nonempty, at most 8000 entries, strictly sorted by canonical lowercase UUID text, with no duplicate/zero ACI or duplicate declared ciphertext principal. Entries contain exactly `aci`, `state`, `role`, `declaredPrincipal` in that order. State is `ACTIVE` or `INVITED`; role is `DEFAULT` or `ADMINISTRATOR`. Invited entries must be DEFAULT. At least one ACTIVE administrator remains, including in a terminated snapshot's historical roster.
* Declared principals are valid native `UuidCiphertext` encodings (base64url decode bound 128 bytes). Roster entries match native active and invited members one-for-one with identical roles and principal bytes. Active native members have profile keys; invited members do not. Credential presentations are empty in the normalized native state. Unknown protobuf fields are rejected recursively. The codec checks encrypted structure, **not** decryption or proof that a declared clear ACI encrypts to its principal.
* Internal enrollment IDs, approval epochs, permit IDs, member IDs and creator audit identity are not exposed. Native and authority data retain those separately for current authorization.

Maximum decoded native group is 8 MiB, decoded JWS payload 4 MiB, compact JWS 6 MiB characters, decoded header 1024 bytes and signature 64 bytes. JSON nesting depth is at most 8, strings at most 2048 characters, numeric tokens at most 20 characters. Request/response transport must enforce bounded input buffering too. The 8000-entry codec case tests projection capacity; it is not 8000 credential enrollments or message deliveries.

## Explicit trust and rotation

Verifier construction requires 1 to 8 explicit pinned public JWKs. Each uses `kty=OKP`, `crv=Ed25519`, exactly 32 public bytes, `alg=Ed25519`, `use=sig`, the configured kid, and **no private `d` or key URL/certificate chain**. No empty trust set, TOFU, network JWKS fetch, embedded key, default key or fallback algorithm is accepted. Production has no provisioned key or runtime registration in this checkpoint. Tests generate keys only in memory; interoperability fixtures contain public keys and synthetic ciphertext only.

Each pin explicitly allows current responses or historical verification only. Roll out a new public pin through an authenticated owned configuration/app update before switching the signing key. Keep a retired public key as historical-only only for the history retention period. Remove a compromised key from both categories according to incident policy; an old signature cannot serve as evidence of current authorization even while a key remains pinned. A signing key must match a current public pin exactly. Private keys never appear in an envelope, fixture, log or public configuration.

`Purpose.CURRENT_RESPONSE` means the pin is permitted for that use; it does **not** establish response freshness. The caller still needs a current authenticated request/response context and admitted group authority. `Purpose.HISTORICAL_SNAPSHOT` authenticates stored bytes without granting access, enqueue, fanout or display.

After full client validation, persist `(authorityRevision, nativeSha256, payloadSha256)` atomically, where `payloadSha256` hashes exact canonical payload bytes. Reject lower revisions and any equal-revision mismatch in either hash. Changing only the pinned signing key preserves payload identity. First use can specify `KnownState.none()` only when no validated local state exists. Historical replay must use its original stamped context/history policy rather than resetting a current rollback floor to accept an old grant.

## Current issuance boundary

`GroupManifestService.current` freezes the caller's original ACI, enrollment identity, approval epoch and local monotonic deadline (at most four seconds). It obtains a real `GroupAuthority.get` snapshot; a bounded executor (two running, 32 queued) signs outside SQL locks. It rechecks the same original proof before/after signing, then rereads the authority using that same frozen proof, requiring exact snapshot equality and checking again before releasing the envelope. Any revocation, membership/role/native change, epoch change, expiry, signer failure, key mismatch, executor saturation or service closure suppresses the result. It never renews admission, silently rereads-and-resigns changed state, performs remote checks while holding a SQL lock, or interprets a signature as a grant. Queue closure fails pending responses; caller cancellation cannot release the underlying worker until actual signing finishes.

The second read establishes a bounded current response point, not a distributed transaction extending through network receipt. A state change immediately after that read is handled by the next operation's current authoritative check; messages require their own enqueue/context enforcement. Future remote key providers require separate bounded provider lifecycle/deadline integration; this checkpoint uses a local injected library signer only.

## Receiver integration prerequisites

The owned client must retain immutable authenticated outer sender/device/type/group-or-audience/revision/destination and payload digest; check outer admission/context before decryption side effects, then compare exact native bytes/hash and **all raw decrypted** roster/roles/revision/policy fields against the verified manifest. Do not normalize away duplicates, malformed invites or unrecognized fields. Native ZK is an additional relationship check; this manifest does not prove an ACI-to-ciphertext mapping. Clients supply that comparison before accepting state, sender-key distribution, control messages, Stories, persistence/notification, attachment downloads or display. A valid signature with a plaintext roster discrepancy fails closed.

The receiver's native manifest/context comparison, durable rollback transaction, linked-device restriction, restart/NSE replay and group/audience routing remain separate integration work. The institution knows declared identities and roles under the selected policy; content remains encrypted. No hidden-ciphertext semantic inference, anonymous route enablement, invitation secret distribution or 8000 delivery claim is introduced.

## Interoperability fixture

`bconnected/test-vectors/group-manifest-v1.json` contains a Java-generated standard compact JWS, exact canonical payload/native bytes/hashes, public Ed25519 JWK, and **synthetic** libsignal GroupSecretParams/expected ACIs solely for cross-language receiver decryption tests. It contains no signing private key and no real alumni/group data. `sameRevisionDifferentClearRosterJws` has a valid signature but deliberately changes one declared clear ACI while preserving all encrypted native bytes: a saved-state verifier rejects payload-hash divergence, and a first-use client must reject the decrypted-principal mismatch. `wrongSigningPublicKey` tests pinned-key substitution failure. The test-only `GroupManifestVectorGenerator` can generate replacement synthetic vectors offline; it is not a production trust/key generator.
