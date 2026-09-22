# Owned private group avatars

This opt-in implementation replaces the PostgreSQL deployment's unavailable avatar operation with Google Cloud Storage V4 capabilities. Group creation, encrypted avatar bytes, libsignal ZK authentication, group attribute permissions and stored opaque avatar paths retain their existing semantics. It does not establish current alumni entitlement. The default configuration remains unavailable, and this source checkpoint has no live GCS or iPhone acceptance claim.

## Configuration and cloud prerequisite

Set both `GROUP_AVATAR_BUCKET` and `GROUP_AVATAR_SIGNING_SERVICE_ACCOUNT`, or neither. Partial or malformed settings fail startup configuration. No exported service-account private key is supported. Attached application credentials read object metadata; IAM `signBlob` signs capabilities as the configured identity. The avatar executor has four workers and a queue of sixteen; rejection returns `503`. Metadata calls use a five-second connect timeout, ten-second read timeout, and a two-attempt/fifteen-second retry budget. IAM signing uses the Google auth library's transport; its timeouts are not controlled by the storage retry settings. Saturated or failed signing cannot produce a successful response.

Before opting in, the deployment owner must provision and verify:

- A dedicated private bucket with uniform bucket-level access and enforced public-access prevention. No public ACL or anonymous IAM grant is allowed. Bucket privacy is an IAM prerequisite, not something the signer can infer from a bucket name.
- Runtime `storage.objects.get` restricted to that bucket, and `iam.serviceAccounts.signBlob` restricted to the signing identity.
- Signing-identity `storage.objects.create` and `storage.objects.get` restricted to the bucket. **No `storage.objects.delete`**, including inherited/project grants: overwriting an existing name needs both create and delete. The absence of delete makes one randomized upload key immutable after its first successful upload. This requirement must be verified before activation. [GCS permissions](https://docs.cloud.google.com/storage/docs/access-control/iam-permissions)
- Matching deployment/IaC configuration, audit-log redaction of signed query strings and policy bodies, and usage monitoring. Abandoned pre-creation uploads can leave encrypted orphan objects; automatic reference-aware cleanup is not implemented. Do not apply an indiscriminate age-delete policy to active avatars.

Cloud/IAM provisioning, lifecycle cleanup and client routing are separate release work. This change never grants a public invoker or enables enrollment.

## Client wire contract

`GET /v2/groups/avatar/form` retains the existing Basic-authenticated ZK presentation and protobuf response. `/v1/groups/avatar/form` inherits the same additive behavior. Upload before group creation is permitted for a valid group-scoped principal. For an existing group, the principal must currently be permitted to modify attributes; terminated groups reject uploads with `423`.

`AvatarUploadAttributes` fields 1–7 are unchanged. New fields are `upload_url = 8`, `expires_at = 9` (UTC epoch seconds) and `max_content_length = 10`. The algorithm is `GOOG4-RSA-SHA256`. Proto3 omits an empty `acl`; clients must interpret absence as empty **only for this algorithm**, and must not submit an ACL. The key is `groups/<32-byte group ID as unpadded base64url>/<random 16 bytes as canonical unpadded base64url>`.

Post a UTF-8 multipart form to the returned HTTPS `upload_url`, whose only supported authority is `storage.googleapis.com` and whose path is the configured bucket. Fields are `key`, `policy`, `x-goog-algorithm`, `x-goog-credential`, `x-goog-date`, `x-goog-signature`, and `content-type=application/octet-stream`; the SDK emits the content-type field in lowercase, so clients should preserve that spelling. The `file` part is last and contains the existing group-encrypted avatar, with no service-side decrypt/re-encrypt. The policy is exact-object scoped, lasts five minutes and permits 1–3,145,728 encrypted bytes. Require success before setting the group's `avatarUrl` to the returned key. Do not derive a public CDN URL. [GCS form protocol](https://docs.cloud.google.com/storage/docs/xml-api/post-object-forms)

`GET /v2/groups/avatar/{objectId}` returns `AvatarDownloadAttributes`: `url = 1`, `expires_at = 2`, `content_length = 3`. The object leaf must be exactly 22 canonical base64url characters decoding to 16 bytes. The authenticated group ID supplies the prefix; callers cannot submit another bucket, group or URL. The same endpoint is inherited by `/v1/groups`. The signed GET lasts five minutes, pins the existing object generation and permits no operation besides GET. Missing objects return `404`; invalid/oversized metadata or signer failure returns generic `503` without provider details. Capability responses use `Cache-Control: no-store`.

Full members and pending-profile-key members may read avatars, including historical objects in that group and terminated-group history. Invite previews may read only the group's **current** avatar: the principal must be pending admin approval, or present the currently valid sixteen-byte `inviteLinkPassword` query value under an enabled invite-link policy. Banned users are rejected; terminated groups reject previews. Membership, role, termination, password/current-avatar and expiry are rechecked after provider work, so changes during signing suppress the response. PostgreSQL locks are not held across remote signing calls.

The iOS consumer must fetch this capability using the group's ZK credentials, validate the returned HTTPS authority/path and expiry, use a session without Signal/Google bearer credentials for GCS, refuse redirects to another authority, enforce both the advertised length and the existing encrypted/decrypted size limits, and then call the existing group avatar decryptor. An expired capability requires a new authorization request. Keep existing encryption and caches keyed by the full group/avatar identity. Never attach the group Basic credential to GCS, log signed URLs, or expose the unencrypted avatar to this service.

## Revocation and privacy limits

Already released upload/download capabilities remain usable until expiry; a later role removal, group termination, invite password change or alumni suspension cannot retract them. Download generation binding prevents a later overwrite from changing the bytes selected by an existing URL. A recipient who already downloaded ciphertext or possesses group keys cannot be made to forget it. The five-minute capability lifetime is not a five-minute alumni-revocation bound: storage only sees encrypted group identities, and previously issued group authentication credentials may still mint new capabilities. A separate approved admission policy and implementation is required before public enrollment.

Google sees the requesting network endpoint, bucket/object path, timing and encrypted byte sizes. Group storage sees a group-scoped ZK principal and requested group/object; the new route does not add a clear alumni ACI. Existing private group roster semantics remain unchanged.

## Local validation

`GcsGroupAvatarStorageTest` uses the real Google SDK and fresh local RSA keys to inspect the signed policy, independently verify its RSA signature, confirm exact group/object/size/expiry scope, pin generation-bound downloads, and reject malformed keys and missing/oversized objects. It makes no cloud request.

`GroupAvatarsPostgresTest` uses disposable PostgreSQL databases, native libsignal identities and real HTTP/ZK authentication. It covers wire parsing/no-store, unauthorized callers, pre-creation upload, existing permissions, role/removal races, invite rotation, pending membership/approval, bans, terminated read/preview rules, expired capabilities, missing objects, signing failure and executor saturation. The group/storage/authentication regression suite runs alongside it. These tests establish source behavior; successful GCS upload/download, IAM overwrite denial and two-iPhone compatibility remain activation checks.
