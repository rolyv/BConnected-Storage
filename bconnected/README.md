# BConnected group storage

Personal fork for the Belen alumni pilot. `group-capacity.yaml` sets the existing server-side limit to 10,000, with matching iOS/remote-config settings. `GroupValidator.checkGroupSize` enforces the limit on actual and invited members; pending approvals and banned-member counts are checked separately.

No storage service is deployed yet. The upstream service needs complete authentication/cryptographic parameters and Bigtable/CDN configuration. This fragment must be merged with that complete configuration; do not run it alone. An 8,000-member end-to-end load test remains required. Encrypted group membership stays with Signal's group system. The directory sidecar stores only voluntarily submitted, admin-approved listing metadata, never private groups or message plaintext.
