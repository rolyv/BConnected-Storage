# New-group authority foundation

This checkpoint implements an internal PostgreSQL service, `GroupAuthority`, for entirely new groups under the clear-roster authority model. It registers no HTTP route and adds no runtime configuration or admission adapter. Enrollment, owned group routing, avatar issuance to these groups, Stories and delivery remain closed until their separate enforcement is integrated.

The institution may know clear account identities and group membership/roles. Native Signal group content remains encrypted. A declared encrypted principal is checked against the native ZK relationship and profile credential, but neither check proves that it encrypts the authenticated clear ACI. A future owned client must compare the decrypted native roster/roles to the authenticated clear manifest before effects or display. This foundation introduces no new cryptographic identity proof.

## Implemented transitions

`create` accepts one native group with version zero, exactly one creator member with an administrator profile presentation, administrator-only member/attribute access, disabled invite links and no pending or banned members. It validates and normalizes the presentation with existing libsignal operations. The actual authenticated caller becomes the first clear administrator. The group identifier is derived from the submitted native public parameters; it is not a caller-selected owner lookup. Existing native groups, old namespace reservations, and terminated owned groups cannot be adopted.

`change` takes the exact expected authority revision and a typed operation:

- `Invite`: current clear administrator adds a unique clear ACI and unique declared native principal as a pending default member. The target must have a trusted current account-directory binding. Both enrollment identity and approval epoch are retained on the invitation.
- `Accept`: the invited account itself presents current account authorization and a native profile credential matching its declared encrypted principal. Exact invitation enrollment and epoch must match. Acceptance promotes it to a default member; an administrator cannot silently accept for another account.
- `SetRole`: current administrator promotes/demotes an active member. The final active administrator cannot be removed or demoted.
- `Remove`: current administrator removes an active or invited entry, with the same last-administrator protection.
- `Announcements`: current administrator changes the native announcement policy.
- `Terminate`: current administrator permanently terminates the group; subsequent protected reads/mutations are refused.

There is no arbitrary state-replacement API. Attribute edits, self-leave, account re-enrollment migration, institutional roster overrides, directory publication, PNI promotion, invite links, bans and legacy group migration are unsupported. `directory_listed` is always false. These are deliberate boundaries of this foundation, not claims that the complete client group lifecycle is available.

Every successful transition increments both native version and authority revision once. Versions stop at the native unsigned 32-bit maximum; they never wrap. The service produces native `GroupChange` actions and signs them with the existing server notary key. The authority snapshot is an internal persistence protobuf, **not** a signed manifest, admission grant, delivery context or public API wire contract.

## Trusted account boundary

`Authorization` and invitation `AccountBinding` are nonserializable in-process interfaces. They must only be supplied by future trusted adapters, never by deserializing caller identity fields. They expose actual ACI, enrollment identity, approval epoch, original monotonic expiration and a local nonblocking `requireCurrent` check. For the current admission model the enrollment identity maps to the signal operation identity; the adapter must validate the complete native binding (member ID, approval epoch, signal operation ID, permit ID and ACI), original account/device snapshot and entitlement receipt. Persisting enrollment/epoch here is not a replacement for that full check.

The operation captures identity, enrollment, epoch and deadline once. Epochs are restricted to the existing community safe-integer domain, `0..9007199254740991`. Receipts may have at most four seconds remaining. Checks run before work, after executor and connection acquisition, after locks, before/after persistence, immediately before/after commit and after connection close. Invitation operations retain both original proofs; SQL waits use the earlier deadline. A fresh proof cannot extend an already queued operation. There are no automatic retries.

The future adapters must make checks local; no remote admission/network call may run while a group SQL lock is held. Their implementation, bounded executor/connection-pool configuration and real cross-service revocation tests are still required. The interface and synthetic test proofs are not a deployed alumni authorization control. Commit can finish after a proof expires or changes; a post-commit failure suppresses the response but cannot undo the committed transaction.

## Atomic state and recovery

Migration `002-group-authority.sql` adds permanent namespace reservations, a marker separating owned groups from legacy groups, authority heads, normalized clear roster, idempotency records and an immutable outbox. Each mutation takes an actor/request advisory lock followed by the existing group advisory lock. The same transaction writes native group state, native history, clear roster, authority revision, exact normalized native bytes and SHA-256, actor/enrollment/epoch-scoped request binding and outbox snapshot. SQL or authorization failure before commit rolls everything back, including namespace reservation. Different creators or expected-revision writers cannot both win.

Structural validation enforces one-to-one native and clear roster entries, matching roles/states, unique ACI/principal, valid native public parameters, exact group/version/hash consistency, and agreement between stored native bytes, authority snapshot and SQL roster. The exact bytes in `native_group` are the bytes a future manifest must authenticate; clients must not reconstruct a different serialization and assume its hash matches. A future manifest signer/outbox publisher is absent.

Request IDs are scoped to the actual actor. Their digest binds operation, group, expected revision, exact operation input, enrollment and approval epoch; invitation target binding is included. Identical authorized retries return the original committed bytes. Reusing an ID for different input/group/enrollment/epoch fails. A retry that no longer has current group permission (for example after self-demotion or termination) does not reexecute or return the historical full roster.

`outcome` provides recovery for that case: a fresh current account proof with the **same** actor/enrollment/epoch can obtain only the committed group ID, revision and native hash for its own request ID. Missing requests return empty. This is a historical acknowledgment, carries no current permission and exposes no roster or ciphertext. New enrollment/epoch cannot retrieve an older outcome. Callers must not interpret a historical committed result as current authority.

## Legacy isolation and migration

The updated `PostgresStorage` refuses native-only reads of owned namespace IDs, including reservations without a current group row. It also refuses legacy updates/appends and returns no legacy history for owned groups. In particular, owned absence must not be represented as a missing group to the legacy pre-creation avatar uploader: it fails before any GCS operation. The SQL trigger makes the group ownership marker immutable and reserves legacy namespaces automatically.

Apply `001`, then `002`, as the migration identity inside the operator's transaction. `002` intentionally has no transaction wrapper. Upgrade all legacy-reading binaries before any owned group can be created; old binaries do not know this isolation rule. Do not enable new routes during a mixed-version rollout. There is no downgrade-safe way to expose owned groups to the old native-only service.

In addition to existing native group/storage grants, the runtime needs schema usage and:

- Namespace reservations: `SELECT, INSERT` only. Never grant deletion or purge tombstones.
- Authority heads: `SELECT, INSERT, UPDATE`.
- Roster: `SELECT, INSERT, UPDATE, DELETE`.
- Idempotency and outbox: `SELECT, INSERT` only.

The namespace trigger runs with invoker rights; the default function execute grant must remain available or be granted explicitly to the runtime. Readiness checks require all authority tables. Migration, runtime IAM and deployment remain operator-owned; this source checkpoint performs no cloud mutation.

## Validation and remaining integration

`GroupAuthorityPostgresTest` uses disposable PostgreSQL databases and freshly generated native libsignal credentials. It checks atomic state/history/outbox bytes and signatures, namespace ownership, invitation acceptance, identity/epoch mismatches, role restrictions, duplicate principals, last-admin protection, concurrent creation/update/replay, failure at the final outbox write, actor/target revocation after writes and commits, executor/SQL-lock expiry, minimal outcome recovery, legacy/avatar isolation and minimal runtime SQL permissions. Existing native storage, group controller, authentication and GCS avatar regressions also run.

Before end-to-end enablement: implement actual account/directory adapters and owned gateway routing; authenticated signed manifests and revocation-aware distribution; immutable authenticated sender/context/revision/destination binding through messaging; strict iOS raw-roster and all-field receiver checks before control/visible effects; Stories audience authority; enqueue/device binding; and measured 8,000-recipient fanout. No storage test here proves those delivery properties.
