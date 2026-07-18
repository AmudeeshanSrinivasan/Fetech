# Linux daemon and worker containment

> **Covered offline-worker gate: implemented; release evidence pending.**
> Required mode now has a fail-closed per-worker Linux boundary for the built-in
> document, archive, image, offline-browser, and native-media paths. Publishing
> v0.4 still requires the mandatory `containment-linux` CI job to pass on the
> release commit and the installed systemd unit to be verified on the target
> distribution.

Fetech has two deliberately distinct worker modes:

- `development` keeps the portable bounded subprocess runner and marks each
  internal process-runner result as `development_unsandboxed`. It is suitable
  for local development, including macOS, but is not an operating-system
  sandbox.
- `required` is Linux-only. Daemon construction fails if Bubblewrap or the
  delegated cgroup-v2 root is missing, invalid, or not writable. A profile setup,
  namespace, mount, cgroup, rlimit, seccomp, or inner-readiness failure never
  retries through the development runner.

Configure required mode explicitly:

```text
FETECH_WORKER_ISOLATION_MODE=required
FETECH_WORKER_BWRAP_EXECUTABLE=/usr/bin/bwrap
FETECH_WORKER_CGROUP_ROOT=/sys/fs/cgroup
FETECH_BROWSER_ARTIFACTS_PATH=/opt/fetech/browser-artifacts
FETECH_DOCLING_ARTIFACTS_PATH=/opt/fetech/docling-models/2.113.0
FETECH_DOCLING_ARTIFACTS_SHA256=e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76
```

The browser-artifact path is optional only when the installed Playwright package
already resolves a reviewed Chromium bundle from another mounted runtime root.
Production deployments should configure an immutable explicit bundle.

## Required-mode launch sequence

For each hostile worker invocation:

1. Python selects a canonical immutable profile; callers cannot supply
   Bubblewrap flags, writable mounts, a cgroup path, a seccomp policy, or a
   network mode.
2. The daemon enables and reverifies the delegated CPU, memory, and PID
   controllers, creates one random leaf in that subtree, and writes
   `memory.max`, `memory.swap.max=0`, `memory.oom.group=1`, `pids.max`, and
   `cpu.max`.
3. A fixed bootstrap moves itself into that leaf before Bubblewrap can create
   descendants. It installs defense-in-depth CPU, core, file-size,
   file-descriptor and address-space rlimits.
4. Bubblewrap creates explicit user, mount, PID, IPC, UTS and cgroup namespaces.
   Offline profiles also receive a new network namespace. The root starts empty;
   only reviewed system, Python, Fetech, tool, browser, and model paths are
   mounted read-only at their original absolute locations.
5. `/tmp` and `/dev/shm` are private size-limited tmpfs mounts. `/proc` and
   `/dev` are new namespace-local mounts. The worker receives a fixed
   environment, private home/cache/config directories, no daemon working
   directory, no CAS/ledger/data mount, no credential store, and no host home.
6. The inner isolated bootstrap installs strict rlimits, `no_new_privileges`,
   and the profile's libseccomp syscall denylist, then emits a second readiness
   marker before replacing itself with the fixed worker command.
7. Only after Bubblewrap reports an isolated child and the inner marker is
   validated does the parent send bounded stdin.
8. Completion, timeout, cancellation, or startup failure triggers
   `cgroup.kill`; the parent waits for `populated 0` and removes the leaf.

The Python parent remains authoritative for request policy, authorization,
budgets, bounded input/output, result schemas, artifact acceptance, provenance,
and original-source authority.

## Canonical profiles

| Profile | Built-in workers | Network | Aggregate profile |
|---|---|---|---|
| `document_parser` | document worker and optional Docling path | denied | 32 PIDs; caller-selected 512 MiB or reviewed 1–8 GiB Docling memory; 128 MiB scratch |
| `archive_parser` | ZIP/TAR worker | denied | 16 PIDs; 512 MiB memory; 64 MiB scratch |
| `image_decoder` | Pillow full decoder | denied | 16 PIDs; 512 MiB memory; 64 MiB scratch |
| `browser_offline` | Playwright reader and renderer | denied | 256 PIDs; 4 GiB resident memory; 1 GiB scratch; 512 MiB `/dev/shm` |
| `media_native_offline` | FFprobe, FFmpeg, Tesseract | denied | 32 PIDs; 1 GiB memory; 128 MiB scratch |
| `media_ytdlp_network` | built-in yt-dlp acquisition | development only | required mode refuses it until an allowlisting egress broker is available |

The browser keeps its separate 2 TiB `RLIMIT_AS` compatibility ceiling because
V8 reserves a very large virtual address range. That value is never used as
`memory.max`; the cgroup's aggregate resident-memory ceiling is 4 GiB.
The browser profile also permits nested user-namespace setup and omits
namespace-management calls from its seccomp denylist for Chromium
compatibility. That allowance is not evidence that Chromium's own sandbox is
active: the outer Bubblewrap namespaces, mounts, network denial, cgroup
ceilings, capability drop, and remaining seccomp rules are the authoritative
boundary.

Injected PDF OCR, transcription, Git LFS, Puppeteer/Selenium, and other custom
provider implementations do not become isolated merely because the built-in
workers are. Required deployments must use separately reviewed service
connectors for those providers or leave them disabled.

Clingo, SWI-Prolog, and optional curl HTTP/3 processes also remain outside these
five hostile-data profiles. Required deployments must isolate those process
families separately or leave the corresponding optional backends disabled.

yt-dlp legitimately contacts multiple public YouTube/Google hosts. Sharing the
daemon's host network would provide unrestricted egress, so required mode fails
closed for the local provider. Its Python URL/DNS/redirect checks remain useful
in development but are not a replacement for a brokered kernel network
boundary.

## Docling model bundle deployment

The optional `fetech[documents]` path uses
`docling-slim[convert-core,format-pdf,models-local]==2.113.0`. Its v0.4 reference
model is `docling-project/docling-layout-heron` at revision
`8f39ad3c0b4c58e9c2d2c84a38465abf757272d8`; the expected canonical bundle
SHA-256 is
`e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76`.

For local preparation, provision and verify under the ignored project data
root:

```bash
uv run python scripts/provision_docling_artifacts.py \
  --output-dir runtime-data/docling-models/2.113.0 \
  --cache-dir runtime-data/docling-download-cache \
  --revision 8f39ad3c0b4c58e9c2d2c84a38465abf757272d8 \
  --expected-sha256 e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76
uv run python scripts/provision_docling_artifacts.py \
  --verify-only \
  --output-dir runtime-data/docling-models/2.113.0 \
  --expected-sha256 e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76
```

`runtime-data/` is ignored and is never a production mount source by itself.
Copy the verified tree to `/opt/fetech/docling-models/2.113.0`, make it
root-owned, service-readable, and non-writable. For example, use `0555`
directories and `0444` files, or a dedicated service group with `0550`
directories and `0440` files. Rerun `--verify-only` as the `fetech` service
account against the installed path before starting the service. Set both
environment values shown above; the expected digest is the independent trust
anchor, while the path only selects the mounted tree.

If a local development environment supplies only
`FETECH_DOCLING_ARTIFACTS_PATH`, the environment loader uses the compiled v0.4
reference digest and therefore admits only that exact reference bundle. Any
custom bundle, and direct SDK construction, must supply an explicit matching
expected digest. Production deployments should keep both values explicit.

The Python audit hook constrains reviewed interpreter-level operations and the
parent revalidates the worker result, but neither mechanism contains native
Docling, PyTorch, or parser code. For hostile PDFs, the `document_parser`
required profile supplies the authoritative network namespace, read-only
mounts, cgroup ceilings, bounded scratch, capabilities, and seccomp boundary.
A successful development-mode artifact smoke does not prove this Linux
containment. The manifest's `apache-2.0` model-card field also does not close
human notice or redistribution review for the exact model files.

## Reference systemd deployment

[`deploy/systemd/fetech.service.example`](../deploy/systemd/fetech.service.example)
is the reference single-tenant Linux unit. Before installing it:

1. Create a dedicated unprivileged `fetech` account.
2. Install the application, virtual environment, browser bundle, and model
   bundles under root-owned read-only paths below `/opt/fetech`; install FFmpeg,
   FFprobe, and Tesseract from reviewed distribution packages under `/usr`.
3. Create `/var/lib/fetech` owned only by `fetech`.
4. Install root-owned immutable Bubblewrap and libseccomp packages from the
   distribution.
5. Use systemd 257 or newer. `DelegateSubgroup=daemon` keeps the service root
   empty for worker leaves, while the newer `ProtectControlGroups=private` mode
   gives the service a private writable cgroup view.

Validate the installed unit and backend:

```text
systemd-analyze verify /etc/systemd/system/fetech.service
systemd-analyze security fetech.service
sudo -u fetech /usr/bin/bwrap --version
```

The unit uses `ProtectControlGroups=private` together with
`Delegate=cpu memory pids`; inside that private view the configured worker root
is `/sys/fs/cgroup`. Do not change the unit to expose the host control-group
tree. Do not give the daemon a Docker socket or rootful container API.

The service-wide `MemoryMax` and `TasksMax` remain outer emergency ceilings.
They must be larger than any permitted worker leaf plus the daemon itself.

## Verification

Cross-platform tests validate profile schemas, exact shell-free command
construction, fail-closed required mode, explicit development status, hidden
data/home roots, bounded tmpfs declarations, and unsupported network profiles.

The `containment-linux` CI job runs as the unprivileged service user inside a
transient delegated systemd service and must not skip enforcement tests.
Ubuntu 24.04's systemd supports delegation and `DelegateSubgroup` but predates
the reference unit's `ProtectControlGroups=private` value, so CI uses the normal
delegated cgroup view and points the runtime at the transient service's exact
`/sys/fs/cgroup/system.slice/fetech-containment-ci.service` subtree. The final
target-systemd verification separately checks the complete reference unit.
Ubuntu's `apparmor-profiles` package supplies the reviewed
`bwrap-userns-restrict` profile used by CI. The job loads that restrictive
profile and runs a non-root user/network-namespace preflight; it never disables
AppArmor's host-wide unprivileged-user-namespace policy. Failed worker startup
reports only bounded, fixed-category diagnostics; raw Bubblewrap stderr is
suppressed so paths, URLs and credential-like material cannot enter results or
logs. CI checks:

- read-only selected mounts and absence of unmounted host secrets;
- private default-deny networking for parsers;
- bounded writable tmpfs scratch with a non-zero usable range;
- libseccomp denial of a self-read syscall that would otherwise be permitted;
- exact cgroup CPU controls plus functional PID and aggregate resident-memory ceilings;
- a real Playwright/Chromium launch in the required browser profile; and
- unconditional leaf cleanup.

Linux distribution policy may forbid unprivileged user namespaces. Required
mode treats that as an unavailable backend; operators must use a reviewed
distribution policy or a separately supervised OCI worker implementation. Do
not disable a host-wide security policy merely to make Fetech start.

macOS development still receives startup/runtime, output, CPU, core,
file-size, file-descriptor, process-group, and Python audit-hook controls. It
has no equivalent required backend and must never be represented as
Linux-enforced containment.
