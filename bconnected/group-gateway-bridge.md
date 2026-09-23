# Group authorization bridge and gateway foundation

These components remain **unregistered**. Their presence in a package does not enable public or
private endpoints, establish live Signal connectivity, provision a manifest signer, or authorize
messages/Stories. Enrollment, invite/accept, avatar and legacy owned-group paths stay closed.

`GroupAuthorizationResolver` calls one fixed Signal HTTPS origin using a Groups runtime OIDC ID
token with that exact origin as audience. It sends an unpredictable private handle, fresh 256-bit
nonce and exact operation binding. The Signal verifier must independently verify Google's
signature, issuer/audience and the pinned numeric Groups subject; Cloud Run IAM alone is not an
account proof. Redirects, compression, non-200 status and unexpected content types are rejected.
The response is bounded to 4,096 bytes while streaming. Connect timeout is one second, complete
HTTP response timeout at most two seconds, and the resolver's caller-facing future times out after
four seconds including token acquisition/queue work. Cancellation interrupts workers on a best-effort
basis; it cannot guarantee a credential provider stops. The local deadline is checked before and
after token acquisition and immediately before dispatch, so even an uninterruptible provider's late
return cannot send a callback after that budget. Worker/queue capacity remains bounded during a
stalled provider. Saturation and shutdown fail closed.

The strict version-one JSON codec rejects duplicates, unknown/missing keys, trailing values,
noncanonical UUIDs/base64url, nonintegral/overflowing counters, unsupported methods/kinds and
nonprimary device IDs. Resolution must echo the exact nonce, method, kind, group ID, request ID
and SHA-256 of the exact public request bytes. No returned field is accepted from an iOS request.
The full binding retains member ID, approval epoch, signal operation ID, permit ID and ACI. The
existing authority `enrollmentId` slot maps to the authoritative **signal operation ID**.

The immutable lease can only be constructed by a successful resolver. Its monotonic deadline is
the local time before executor/RPC work plus Signal's remaining original lifetime, at most four
seconds. Network/queue time consumes freshness; response arrival cannot renew it. Every later
check is local. An injected established revocation projection may shorten this lease, but must
never perform HTTP or block under group SQL locks. There is no installed revocation projection
in this checkpoint. This is bounded-staleness authorization, not an instantaneous distributed
transaction. Signal must still recheck its original proof before dispatch and after the result;
a post-commit failure suppresses response, not the committed database mutation.

`GroupGateway` is an application layer with no HTTP annotations or launcher registration. It
validates only the initial REST contract:

* `POST /v1/bconnected/groups`: exact `requestId`, `groupPublicParams`, `groupAuthPresentation`,
  `nativeGroup` keys. Native group parameters must agree; only the actual caller can become the
  initial administrator through the existing authority.
* `POST /v1/bconnected/groups/{groupId}/state`: exact `requestNonce`, `groupPublicParams`,
  `groupAuthPresentation`. `requestNonce` is a canonical UUID. Returns native bytes and a signed
  authoritative manifest through the existing frozen-proof service, echoing that nonce. The
  nonce is transport correlation, not an additional claim inside the snapshot signature.
* `POST /v1/bconnected/groups/{groupId}/changes`: exact `requestId`, `expectedRevision`,
  `groupPublicParams`, `groupAuthPresentation`, `kind`; `ANNOUNCEMENTS` additionally requires
  boolean `enabled`, while `TERMINATE` has no additional keys. Revision is uint32.
* `GET /v1/bconnected/group-operations/{requestId}`: empty body and no content type. Returns only
  same-enrollment/epoch historical group ID, revision and native hash, not a membership grant.

All POST requests require `application/json`, no compression, a 64 KiB body cap, canonical UUIDs
and unpadded base64url. Native ZK relationship verification remains separate from authenticated
account identity. The resolver runs before any authority connection/lock. Gateway mutations bind
the exact public request digest into the existing durable idempotency ledger; even whitespace or
a new ZK presentation requires the client to use a new request ID. An identical retry uses the
same ID/body and a fresh original account proof/handle. This does not add a database migration.

Tests exercise native ZK/PostgreSQL creation, signed state, announcements, termination and lost
response outcome, exact-byte replay/conflict, enrollment epoch change, malformed/unsupported
requests, and no SQL connection while a delayed callback expires. Separate protocol/lease and
HTTP fault-injection tests cover bounded parsing, nonce/operation substitution, timer conservation,
queue saturation, cancellation/shutdown, local revocation, strict transport headers/statuses,
redirect rejection, streaming oversize and slow response/token acquisition. HTTP/token fault
tests use injected clients; they do not prove live TLS, metadata-server tokens or Google key
refresh. Signal-side native registry and real synthetic RSA signature tests are independent,
not a deployed end-to-end bridge test.

The complete clean package regression passes 417 tests with zero failures/errors/skips: 370 prior
cases plus 26 protocol/lease, eight HTTP/token fault-injection and 13 native gateway cases. The
uninterruptible token-provider case explicitly returns after the caller's deadline and verifies
that no HTTP callback is sent. Runtime dependency versions/count are unchanged by this slice.

Before enablement, implement authenticated Signal REST dispatch with primary-device proof,
per-account input/rate/in-flight limits, stable denied-error bodies and precise status mappings;
register only the exact approved transports; enforce `Cache-Control: no-store`; pin and verify
the fixed private callback with its runtime subject; bound the callback's Google signing-key
refresh/execution; provision independent signer/trust pins; and exercise original-proof churn
across actual callback/queue/SQL/signing and lost responses. Multi-instance registry routing needs
an explicit owner contract. Group invitation consent/bootstrap, sender-key distribution,
receiver/NSE durable context enforcement, Stories and measured 8,000-recipient fanout remain
required separate implementation/acceptance. No fanout capacity follows from these tests.
