# Reproducible builds

Beta CI builds Fetech twice from independent clean copies of the same Git commit and requires the
wheel and source distribution to be byte-for-byte identical. The resulting receipt is development
evidence for build stability; it does not modify or replace the frozen v0.4 release evidence.

## Gate

Run the complete check from a clean Git worktree:

```bash
uv run python scripts/verify_reproducible_builds.py \
  --output /tmp/fetech-beta-reproducible-build.json
```

The checker:

1. rejects tracked changes and untracked files;
2. binds the run to the checked-out commit and uses that commit timestamp as
   `SOURCE_DATE_EPOCH`;
3. copies only tracked regular files into two independent temporary source trees;
4. builds a wheel and source distribution from each tree with `uv build`;
5. requires identical filenames, sizes, SHA-256 digests, bytes, and archive inventories;
6. validates bounded canonical archive paths, regular file/directory types, safe permissions,
   fixed timestamps, package identity, and wheel `RECORD` hashes and sizes; and
7. installs one wheel and one source distribution into separate clean virtual environments and
   verifies the package version, bundled capability manifest, and a basic public-contract import.

CI runs the complete gate on pushes to `main` and `beta` and on pull requests. It retains the
machine-readable `fetech.beta.reproducible-build.v1` JSON receipt for 30 days. The receipt contains
the commit, epoch, builder versions, artifact hashes and sizes, archive summaries, and clean-install
outcomes; it intentionally excludes temporary paths and command output.

`--skip-install-smoke` is available only for local comparison debugging. A receipt produced with
that option is not complete CI evidence.

## Evidence boundary

This gate proves deterministic Fetech archives across two sequential builds on the same host,
Python runtime, `uv` frontend, source commit, and resolved build toolchain. It does not prove
cross-operating-system or cross-toolchain reproducibility, authenticate the runner, sign the
artifacts, approve dependency licenses, or publish a release. Dependency resolution for installing
the artifacts also remains governed by package metadata and the selected package index.

Before a release candidate, the project should additionally pin the release builder toolchain,
repeat the comparison on each supported release platform where applicable, and bind signed release
attestations to the approved artifact digests. The frozen v0.4 verifier and publication gates remain
separate until the external approvals recorded in the v0.4 release contract are completed.
