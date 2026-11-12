# Offline mixed-ledger history check

`verifyOfflineReconciliationCandidateDetails` checks only caller-supplied JSON. It does not open a store, decrypt a credential, write a candidate, or authorize installation. It first runs the sealed control and mixed-ledger structure checks, then compares every candidate request and audit row with the sealed app snapshot. Shared generation-2 rows must match the trusted decrypted envelope. App-only rows, including all their details and order, must survive exactly. A donor request that was still open may have reached a terminal state in the app snapshot; its original action and every already-recorded lifecycle field must agree. Terminal donor requests and shared audit events must match exactly. Unknown envelope fields, missing or extra IDs, redaction conflicts, duplicate JSON keys, and mismatched anchors fail closed.

The caller supplies `OfflineDecryptedDonorEvidence`:

- `decryptedDonorMetadataRaw`: authenticated plaintext of the **exact** donor `sensitiveMetadata` box, with `requests` and `audit` objects in the generation-2 format.
- `generationTwoLedgerSha256`: SHA-256 of the **exact UTF-8 generation-2 ledger bytes** from the trusted paired snapshot. This anchors agent identities and every other donor field, not just the encrypted box.
- `donorMetadataBoxSha256`: SHA-256 of the canonical donor `sensitiveMetadata` object passed to that decryptor.
- `sealedAppLedgerSha256`: SHA-256 of the **exact UTF-8 sealed-app ledger bytes** from the trusted paired snapshot. This anchors cache and grant bookkeeping that the control fingerprint does not include.
- `sealedAppHistorySha256`: an independently captured SHA-256 of canonical `{ requests, audit }` from the app snapshot.

Canonical JSON recursively sorts object keys and preserves array order. The hashes bind the supplied comparison to these snapshots; a hash recomputed from an untrusted snapshot is not an independent anchor. The trusted caller must capture the paired snapshot and its hashes before supplying details, and authenticate decryption of the exact encrypted box. This pure function cannot establish either provenance step itself. Keep raw details out of logs. The result stays `migrationBlocked: true`: the checked mixed candidate still contains plaintext app history and an opaque generation-2 box, and there is no compatible live writer, sealed journal/recovery migration, or installed rollback proof.

One legitimate transition remains unverified: the current app writer can add `resolvedCommand` while claiming an approved generation-2 environment command. The strict detail check rejects that action difference because this offline verifier cannot prove which executable path was pinned at claim time. It does not ignore action fields to accept that case.
