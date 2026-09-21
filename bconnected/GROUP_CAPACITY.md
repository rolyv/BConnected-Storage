# Synthetic encrypted-group capacity characterization

`GroupsControllerCapacityTest` is an opt-in local characterization of 50, 500, 2,000 and 8,000 distinct encrypted group members. It uses the actual group controller, native PostgreSQL persistence and libsignal 0.101.2. It creates no Signal accounts and uses no real alumni, phone numbers, provider credentials or deployed resources.

Each case generates fresh test server/group parameters and distinct synthetic ACI/profile keys. Every group member has a real issued, received and presented expiring profile-key credential. The two requesting identities additionally authenticate through the real `GroupUserAuthenticator` using libsignal authentication credentials. The controller verifies every membership presentation, persists the validated ciphertext state, issues group-send endorsements and signs subsequent group changes. The test verifies the combined endorsement token and signed change history with the corresponding client/public-key operations.

The group starts with one administrator, `announcements_only=true`, administrator-only membership/attribute changes and disabled invite-link joining. An ordinary member can read the state but cannot disable announcements, promote itself, edit the title, remove another member or restore that member. An administrator can update the encrypted title and remove/re-add a member using a valid profile credential. Two competing changes for one revision produce one successful write, one conflict and one matching signed history record. PostgreSQL state and history are checked after those operations, including verification of all four signed changes and the restored full-membership endorsements. A separate, deliberately structural test confirms that 10,001 entries still fail the configured 10,000-member limit; it is not a cryptographic test at 10,001 members.

## Run locally

Use Java 25 or later and an existing **disposable loopback PostgreSQL test server**. The evidence records the actual JVM version. The operator URL must name a database ending in `_test`, use a loopback host, and contain no query, user-info or fragment. The fixture creates a new randomly named database, applies only `bconnected/migrations/001-postgres.sql`, then force-drops that database during teardown. It does not truncate the operator database or use any production schema. The test operator needs permission to create/drop a database on that disposable server.

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home \
BCONNECTED_GROUP_CAPACITY=true \
BCONNECTED_GROUP_TEST_JDBC_URL=jdbc:postgresql://127.0.0.1:55432/bconnected_test \
BCONNECTED_TEST_POSTGRES_PASSWORD=bconnected-local-test \
./mvnw -B -ntp -Dtest=GroupsControllerCapacityTest test
```

The opt-in variable prevents the expensive synthetic population generation in ordinary test runs. Generation is sequential and SQL work uses two threads. Each test has a 15-minute timeout; PostgreSQL connections and statements have bounded timeouts. A terminated JVM can leave its disposable database behind, so inspect only databases with the fixture's `bconnected_capacity_*_test` prefix after an interrupted run.

## Real local HTTP harness

`GroupsHttpCapacityTest` uses the same synthetic cryptographic generator and disposable-database helper but starts the actual `BConnectedStorageLauncher` in a separate JVM with `-Xmx512m`. The launcher selects its normal PostgreSQL/Jetty configuration. Only the database, fresh test keys and loopback ports differ from a normal launcher invocation. The application and admin ports are both loopback-only; a release/bind race permits no more than three bounded startup attempts. No production configuration, entity-size setting or member limit is modified to make the test pass.

The source inspection found no explicit protobuf request-body size override in `BConnectedStorageLauncher` or `StorageService`. `ProtocolBufferMessageBodyProvider` passes the entity stream to the ordinary protobuf `builder.mergeFrom(InputStream)` parser. The test therefore exercises those inherited limits rather than assuming a large DTO proves HTTP acceptance.

The test sends an actual HTTP/1.1 protobuf PUT containing 8,000 valid membership presentations, receives/parses the complete response, verifies client endorsements and compares PostgreSQL state. It then performs an ordinary-member GET, an unauthenticated GET that must return 401, an ordinary-member PATCH that must return 403 without advancing state, and an administrator PATCH whose signature and SQL history must agree. The test client caps response bodies at 2 MiB, requests time out after 30 seconds and the whole test has a five-minute deadline.

The child receives no inherited cloud/provider credentials, proxies or configuration override. It reads a fresh fixture-only bundle in a private directory with file mode `0600`; application output is discarded. Teardown stops the child before dropping the disposable database and removes the bundle and launcher-generated configuration. No fixture keys, authorization headers or ciphertext contents are included in the aggregate evidence.

Run with the same environment above and `-Dtest=GroupsControllerCapacityTest,GroupsHttpCapacityTest` to execute all six cases. HTTP observations are written separately to `target/group-http-capacity-evidence.json`. They do not demonstrate Google ingress, TLS, IAM, Cloud SQL connectivity, production latency or mobile behavior.

`target/group-capacity-evidence.json` records only aggregate observations: fixture generation time, controller/storage phase elapsed times, serialized request/state/response/endorsement byte sizes, successful assertions and basic JVM context. It does not emit identity, credential, ciphertext, password or key values. Only cases reaching all assertions appear in the measurements array; a valid complete run also requires Maven success, five executed tests and all four expected population sizes. Timings are single-run observations on the local developer machine, including JIT and competing workloads. They are not throughput, percentile latency or production capacity estimates.

## Recorded local run

On 2026-09-21 at 17:45:13 UTC, all five tests passed with no failures, errors or skips in 62.11 seconds (69 seconds including Maven). The actual JVM was OpenJDK 26.0.2.1; libsignal was 0.101.2. Teardown was independently checked afterward: no capacity-fixture database remained on the disposable PostgreSQL server.

The 8,000-member case produced a 5,832,176-byte create request, a 1,112,176-byte persisted group, and a 1,368,273-byte response including 256,089 bytes of endorsements. Local creation took 7,835 ms, client endorsement verification 92 ms, ordinary-member read 399 ms, signed title update 445 ms and administrator removal/re-addition 965 ms. All four tested sizes passed the authorization, signature, membership-restoration and optimistic-conflict assertions. These observations apply only to the scope below.

The subsequent combined run at 17:59:30 UTC passed all six tests with no failures, errors or skips: five direct-controller cases in 67.12 seconds and the actual launcher/HTTP case in 48.76 seconds (125 seconds including Maven). On the same JVM/libsignal versions, the 512 MiB HTTP child became ready on its first startup attempt in 2,962 ms. It accepted the unchanged 5,832,176-byte create body and returned the complete 1,368,273-byte response. HTTP creation took 8,333 ms, member GET 421 ms and signed administrator PATCH 466 ms; the expected 401/403 rejections and SQL/history comparisons passed. The child stopped, fixture secrets were removed and an independent query found no remaining fixture databases. These are local HTTP observations, not Google ingress or deployment evidence.

## Evidence limits

The four-size `GroupsControllerCapacityTest` invokes authenticated controller methods directly. Its observations alone do not exercise HTTP or Jetty limits; the separate `GroupsHttpCapacityTest` covers those locally at 8,000 members. Neither harness tests Google ingress, TLS, Google IAM, Cloud SQL networking or iOS. Existing service/body/member limits are not changed.

The storage service controls who can change group settings and membership. Its inherited implementation returns group-send endorsements to ordinary full members even when announcements are enabled. Consequently these tests **do not establish administrator-only message sending**. The iOS source separately blocks ordinary message sends (with exceptions for reactions, poll votes and deletion), discards visible messages from non-administrators, drops their typing indicators and rejects their group Stories in `MessageSender`, `GroupMessageProcessor`, `MessageReceiver` and `StoryManager`. Those are static source findings, not an end-to-end result. An endorsement response alone neither proves send authorization nor proves that a malicious sender can publish a visible announcement. Adversarial direct-send-to-recipient rejection tests remain necessary.

The 8,000-member create request is several megabytes and credential validation takes seconds on the developer machine. The local Jetty body path passed; Google ingress/body-limit checks remain necessary. The future community-admission gate must also recheck current authority after cryptographic validation and any SQL wait, at the protected use/commit boundary; it cannot assume a four-second receipt obtained before validation remains fresh. No such storage-service admission gate is implemented or tested by this harness.

Still required: full client create/read/update behavior; Google ingress request and response limits; iPhone memory and endorsement processing; actual announcement send permissions; message fanout, queue persistence, reconnect/history, APNs, rate limits and sustained concurrency at 8,000 recipients. The local synthetic group-state result must not be described as 8,000 working alumni accounts or successful delivery to 8,000 users.
