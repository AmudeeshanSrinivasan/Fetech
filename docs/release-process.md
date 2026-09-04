# Fetech v0.4 release process

This runbook closes the four external publication gates without treating a
file's existence as approval. Run the steps in order. Any tracked-source,
dependency-lock, unit, model-bundle, wheel, source-distribution, SPDX, or
dependency-report change invalidates later evidence and restarts the process
from the clean candidate build.

## 1. Prepare the clean release candidate

Use Python 3.12 and the locked environment:

```bash
git status --short
uv lock --check
uv run pytest
uv run ruff check .
uv run mypy src/fetech
uv run python scripts/generate_release_evidence.py --check-published
uv run python scripts/check_v04_release_readiness.py --check
uv run python scripts/generate_release_evidence.py \
  --overlay-profile scripts/release_v04_candidate.toml --check
git diff --check
```

After the exact release commit passes the default-branch `verify` and
`containment-linux` jobs, build and verify the candidate using the commands in
[`docs/releases/v0.4.0a0.md`](releases/v0.4.0a0.md). Retain these canonical
files under ignored `dist/`:

```text
SHA256SUMS
fetech-0.4.0a0-py3-none-any.whl
fetech-0.4.0a0.tar.gz
fetech-0.4.0a0-artifacts.json
fetech-v0.4.0a0-smoke.json
fetech-v0.4.0a0-github-ci.json
```

## 2. Establish independent signature trust

Systemd operators and legal reviewers sign different namespaces with
OpenSSH-compatible signing keys. Private keys never enter the repository,
release assets, CI variables, logs, Graphify, or Obsidian. The release owner
obtains each public key independently and creates two local allowed-signers
files using the OpenSSH format:

```text
operator@example.org ssh-ed25519 AAAA...
lawyer@example.org ssh-ed25519 AAAA...
```

Keep each file outside the repository, owned by the release operator, and not
group- or world-writable. Point the verifier at them:

```bash
export FETECH_SYSTEMD_ATTESTORS_FILE=/secure/release/systemd.allowed_signers
export FETECH_LEGAL_REVIEWERS_FILE=/secure/release/legal.allowed_signers
```

Adding a public key to one file is the governance decision that its principal
may attest that specific role. The software verifies identity, signature and
release binding; it cannot determine whether a person is legally qualified.

## 3. Collect the systemd 257+ target attestation

Use the intended Linux deployment host or VM. systemd must be PID 1, version
257 or newer, and backed by real cgroup v2. The collector rejects containers
and nested systemd labs.

Install the exact candidate wheel, dependencies, model/browser artifacts, and
[`deploy/systemd/fetech.service.example`](../deploy/systemd/fetech.service.example)
under the paths pinned by the unit. Keep `/opt/fetech` root-owned and
read-only, `/var/lib/fetech` owned by the unprivileged `fetech` account, and
the installed unit byte-identical to the repository reference.

Start and inspect it:

```bash
sudo systemd-analyze verify /etc/systemd/system/fetech.service
sudo systemd-analyze security fetech.service
sudo systemctl daemon-reload
sudo systemctl enable --now fetech.service
sudo systemctl is-active fetech.service
```

From the clean release checkout on that host, collect the receipt as root:

```bash
sudo --preserve-env=PATH uv run python \
  scripts/collect_v04_systemd_attestation.py \
  --artifact-dir dist \
  --installed-unit /etc/systemd/system/fetech.service \
  --target-label production-linux-amd64 \
  --attestor-principal operator@example.org \
  --output dist/fetech-v0.4.0a0-systemd-attestation.json
```

The collector checks PID 1, non-container execution, systemd version, cgroup
v2, exact unit bytes, `systemd-analyze`, effective security properties,
required environment, unprivileged Bubblewrap availability, active daemon
state, and the live 13-category/155-capability endpoint. It never reads the
journal or fetched content.

Copy the receipt to the attestor's secure workstation. After reviewing it, the
authorized operator signs the exact bytes:

```bash
ssh-keygen -Y sign \
  -f /secure/release/operator-signing-key \
  -n fetech-systemd-attestation-v1 \
  dist/fetech-v0.4.0a0-systemd-attestation.json
```

Verify both receipt and signature in the clean candidate checkout:

```bash
uv run python scripts/verify_v04_systemd_attestation.py \
  --artifact-dir dist \
  --receipt dist/fetech-v0.4.0a0-systemd-attestation.json \
  --signature dist/fetech-v0.4.0a0-systemd-attestation.json.sig
```

The receipt expires after 14 days. Collect it again if the release has not
been published within that window.

## 4. Obtain human legal approval

Give the independently selected open-source/licensing counsel or authorized
legal/compliance reviewer the exact candidate wheel, source distribution,
SPDX report, dependency-license report, referenced model and binary notices,
and the scope described in the release notes. The v0.4 approval covers only
the Fetech wheel and source distribution; it does not approve a container,
system image, model mirror, browser bundle, NVIDIA bundle, FFmpeg build,
PDFium binary, or Tesseract data redistribution.

After completing the review, the authorized reviewer creates the canonical
approval document on the clean candidate checkout:

```bash
uv run python scripts/verify_v04_legal_approval.py \
  --artifact-dir dist \
  --create \
  --reviewer-principal lawyer@example.org \
  --reviewer-name "Qualified Reviewer" \
  --reviewer-organization "Reviewing organization" \
  --reviewer-role "Open-source counsel" \
  --approval-reference "PRIVATE-MATTER-REFERENCE" \
  --jurisdiction Australia \
  --output dist/fetech-v0.4.0a0-legal-approval.json
```

Do not put privileged advice or personal contact details in the receipt. The
approval reference should be a bounded locator into the organization's private
record system, not the private record itself.

The reviewer signs the exact bytes:

```bash
ssh-keygen -Y sign \
  -f /secure/release/reviewer-signing-key \
  -n fetech-legal-approval-v1 \
  dist/fetech-v0.4.0a0-legal-approval.json
```

Verify it:

```bash
uv run python scripts/verify_v04_legal_approval.py \
  --artifact-dir dist \
  --receipt dist/fetech-v0.4.0a0-legal-approval.json \
  --signature dist/fetech-v0.4.0a0-legal-approval.json.sig
```

Conditional, rejected, stale, incorrectly scoped, unsigned, untrusted, or
hash-mismatched decisions do not close the gate. An unconditional approval
expires after 90 days.

## 5. Reach the publishable state

Run the complete artifact-aware checker:

```bash
uv run python scripts/check_v04_release_readiness.py \
  --release-artifacts-dir dist \
  --require-publishable
```

The expected prepublication result is 12 of 14 gates passed with state
`publishable`. The GitHub Release and PyPI gates remain blocked until those
services contain the exact release.

## 6. Configure PyPI Trusted Publishing

Before publishing the GitHub Release, configure a PyPI Trusted Publisher with:

```text
PyPI project: fetech
GitHub owner: AmudeeshanSrinivasan
GitHub repository: Fetech
Workflow: release.yml
Environment: pypi
```

Create a GitHub environment named `pypi`, require a human reviewer, prevent
self-review when the repository plan supports it, and restrict it to release
tags. Add these two environment secrets, each containing the corresponding
complete OpenSSH allowed-signers file established in step 2:

```text
FETECH_SYSTEMD_ALLOWED_SIGNERS
FETECH_LEGAL_ALLOWED_SIGNERS
```

These are public-key trust anchors, not private signing keys. The protected
job uses them to revalidate both detached signatures, the signed tag, exact
release inventory, artifact receipt, CI receipt, and complete smoke receipt
before requesting the short-lived PyPI OIDC token.
[`.github/workflows/release.yml`](../.github/workflows/release.yml) contains no
long-lived PyPI credential.

## 7. Create the signed tag and draft GitHub Release

Confirm the worktree and publishability again, then create a signed tag:

```bash
RELEASE_COMMIT="$(git rev-parse HEAD)"
git status --short
git tag -s v0.4.0a0 "$RELEASE_COMMIT" -m "Fetech v0.4.0a0"
git tag -v v0.4.0a0
git push origin refs/tags/v0.4.0a0
```

Create a draft prerelease containing exactly the inventory checked by
`verify_v04_github_release.py`:

```bash
gh release create v0.4.0a0 \
  --verify-tag \
  --draft \
  --prerelease \
  --latest=false \
  --title "Fetech v0.4.0a0" \
  --notes-file docs/releases/v0.4.0a0.md \
  dist/fetech-0.4.0a0-py3-none-any.whl \
  dist/fetech-0.4.0a0.tar.gz \
  dist/SHA256SUMS \
  dist/fetech-0.4.0a0-artifacts.json \
  dist/fetech-v0.4.0a0-smoke.json \
  dist/fetech-v0.4.0a0-github-ci.json \
  dist/fetech-v0.4.0a0-systemd-attestation.json \
  dist/fetech-v0.4.0a0-systemd-attestation.json.sig \
  dist/fetech-v0.4.0a0-legal-approval.json \
  dist/fetech-v0.4.0a0-legal-approval.json.sig \
  release/fetech-0.4.0a0-candidate.spdx.json \
  release/dependency-licenses-0.4.0a0-candidate.md
```

Review the draft in GitHub, then publish it as a prerelease. Do not add extra
assets. The release event starts the `Publish approved release` workflow, but
the `pypi` environment prevents upload until its reviewer approves the job.

Verify the live GitHub state:

```bash
uv run python scripts/verify_v04_github_release.py --artifact-dir dist
```

The result is 13 of 14 gates.

## 8. Approve and verify PyPI publication

In GitHub Actions, review the waiting `pypi` environment deployment. Confirm
the tag, commit and checksum step, then approve it. The workflow downloads only
the fixed 12-asset inventory, revalidates every machine-verifiable release
gate, and publishes only the two exact distributions using PyPI Trusted
Publishing.

After it succeeds:

```bash
uv run python scripts/verify_v04_pypi_publication.py --artifact-dir dist
uv run python scripts/check_v04_release_readiness.py \
  --release-artifacts-dir dist
```

The verifier queries PyPI over the canonical HTTPS JSON endpoint and requires
exactly the approved wheel and source distribution, with matching names,
types, sizes and SHA-256 digests. The final readiness state is 14 of 14 gates
passed and `published`.

## 9. Record immutable publication history

After publication, add the v0.4 tag, commit, dates and final evidence hashes to
`scripts/release_published.toml`, regenerate the tracked readiness and release
evidence projections, run the full verification suite, and commit that
bookkeeping separately. Never rebuild or replace already published artifacts.
