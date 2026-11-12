# Sealed history generation prototype

`SealedHistoryPrototype` lives in `tests/support/` and is not part of the product build or npm package. It takes an explicit home, recovery home, and independent 32-byte key. It runs only in s-gw test mode under the configured isolated test root and refuses homes with v1 ledger or recovery evidence. The test-mode path checks reduce accidental overlap; they are not an installed broker boundary.

Each staged generation writes encrypted request and audit detail bodies to a primary file, a compacted journal, and a recovery copy. IDs, timestamps, request states, and revisions remain plaintext index metadata. The authenticated `head.json` is committed last. A reader accepts only copies matching that head's generation and hashes. It can read full detail without the master passphrase when the caller supplies the history key.

The head lives in the same recovery tree as the data. Because old generation files are retained, replacing **only the head** with an older authenticated head replays that generation; a matching old head and data tree can also be restored. The tests reject stale rows only against the current trusted head. An installed writer needs a broker-owned OS-protected key, a separate monotonic generation anchor, and an OS-enforced fence against old binaries.

The prototype refuses nested symlinks and paths with unexpected owner or access mode before its file operations. These path checks are not atomic against a same-UID process that can replace directories between check and open. A crash can leave `.commit.lock`, preventing later commits while reads still work. A first-generation stage that crashes before commit leaves files without a head; later stages fail closed and need manual cleanup. A path-derived instance ID also prevents restoring the files under a different home or recovery path, even with the same key.

This prototype does not migrate the v1 store, encrypt its existing backups or journal, preserve its authority fields, or serve Usage Flow in the app. Its journal is a complete snapshot per generation for crash tests, not a production retention design. Mac, Windows, and Linux installed acceptance remains open.
