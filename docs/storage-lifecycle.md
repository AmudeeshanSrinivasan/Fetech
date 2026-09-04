# Local storage lifecycle

Fetech applies one Python-owned lifecycle policy to the SQLite ledger, snapshot metadata, runtime
provenance projection, and filesystem content-addressed store used by a single daemon instance.
Maintenance runs during gateway startup, after interrupted runs are finalized and before new work is
accepted.

## Defaults

| Setting | Environment variable | Default |
|---|---|---:|
| Data-directory content quota | `FETECH_STORAGE_MAX_BYTES` | 10 GiB |
| Finished-run retention | `FETECH_STORAGE_RUN_RETENTION_SECONDS` | `0` (disabled) |
| Expired snapshot retention | `FETECH_STORAGE_SNAPSHOT_RETENTION_SECONDS` | 7 days |
| Recent-orphan grace period | `FETECH_STORAGE_ORPHAN_GRACE_SECONDS` | 24 hours |
| Snapshot record limit | `FETECH_STORAGE_MAX_SNAPSHOT_RECORDS` | 100,000 |
| Run retirement batch | `FETECH_STORAGE_MAX_RETIRED_RUNS_PER_STARTUP` | 1,000 |
| Inventory entry bound | `FETECH_STORAGE_MAX_SCAN_ENTRIES` | 200,000 |

Run retention is deliberately opt-in because it makes old runs unavailable through the public run,
event, provenance, and artifact interfaces. Configure it only after choosing an operational evidence
retention period. Age is currently measured from run submission because that timestamp exists in the
v1 ledger schema.

The quota counts regular-file content under `FETECH_DATA_DIR`, including SQLite files, CAS bodies,
snapshot metadata, and the runtime graph. It serializes daemon writes and leaves up to 1 MiB of
headroom for terminal ledger records. Artifact, snapshot, ledger, and runtime-graph writes all use
the same quota object. A storage-full artifact operation becomes a `BUDGET_EXHAUSTED` result, and
the reserved ledger headroom lets the terminal result remain durable.

This application quota does not count filesystem directory metadata, guarantee physical free space,
control another process writing into the directory, or replace an operating-system/filesystem quota.
Production deployments still need a host disk ceiling and free-space monitoring.

## Startup order

```text
initialize ledger schema
  -> finalize interrupted QUEUED/PLANNING/RUNNING runs
  -> retire eligible finished runs into bounded tombstones
  -> remove abandoned snapshot staging files
  -> prune expired/excess snapshot metadata
  -> collect old CAS blobs not referenced by live ledger results or retained snapshots
  -> verify the complete data-directory content quota
  -> accept new work
```

Retiring a run atomically removes its detailed events and result and creates an immutable tombstone
containing the run ID, submission/retirement times, result-document SHA-256, and event/artifact
counts. A retired run ID cannot be reused. The tombstone proves which exact record was retired but
does not preserve its content or lineage; export required evidence before enabling retention.

Snapshot records are derivative cache metadata. Records are removed after their expiry plus the
configured retention interval. If the global record limit is still exceeded, the oldest remaining
records are retired first. A new snapshot write fails before publication when the limit is full.

CAS collection computes its live set from current ledger artifact metadata plus all retained
snapshot records. It deletes only canonical SHA-256 blob paths that are outside that live set and
older than the orphan grace period. Recent unreferenced blobs are preserved so a crash between CAS
publication and terminal ledger commit does not immediately destroy recoverable bytes. Abandoned
`.write-*` and snapshot `.tmp` staging files are removed at startup. Symbolic links, special files,
identity/path contradictions, malformed snapshot metadata, and overlarge inventories fail closed.

## Confidentiality and deletion boundary

Retention and garbage collection use ordinary filesystem unlink and SQLite row deletion. They are
not cryptographic erasure and cannot guarantee removal from filesystem journals, SSD remapping,
SQLite free pages, backups, replicas, or snapshots. The CAS remains globally content-deduplicated and
unencrypted. Sensitive deployments must use encrypted storage, controlled backups, an appropriate
SQLite maintenance procedure, and storage-provider deletion controls.

The in-process lock assumes one Fetech daemon owns the configured data directory. Sharing one local
directory between daemon processes is unsupported in v1. Postgres and S3-compatible lifecycle
implementations remain extension points and must provide equivalent atomicity, quota, retention,
reference, and deletion semantics before use.
