from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from release_attestation_common import (  # noqa: E402
    ARTIFACT_RECEIPT_FILENAME,
    SDIST_FILENAME,
    TARGET_VERSION,
    WHEEL_FILENAME,
    ReleaseAttestationError,
    canonical_json,
    sha256_file,
)


def _load_script(name: str) -> ModuleType:
    path = SCRIPTS / name
    spec = importlib.util.spec_from_file_location(f"test_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SYSTEMD = _load_script("verify_v04_systemd_attestation.py")
LEGAL = _load_script("verify_v04_legal_approval.py")
GITHUB = _load_script("verify_v04_github_release.py")
PYPI = _load_script("verify_v04_pypi_publication.py")


def _git(project: Path, *arguments: str) -> str:
    process = subprocess.run(
        ("git", "-C", str(project), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return process.stdout.strip()


def _candidate(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    project = tmp_path / "project"
    artifact_dir = project / "dist"
    (project / "deploy" / "systemd").mkdir(parents=True)
    (project / "release").mkdir()
    artifact_dir.mkdir()
    (project / ".gitignore").write_text("dist/\n", encoding="utf-8")
    (project / "deploy" / "systemd" / "fetech.service.example").write_text(
        "[Service]\nUser=fetech\n",
        encoding="utf-8",
    )
    (project / LEGAL.SBOM_PATH).write_text(
        '{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8"
    )
    (project / LEGAL.LICENSE_REPORT_PATH).write_text(
        "# Licenses\n", encoding="utf-8"
    )
    _git(project, "init", "-q")
    _git(project, "config", "user.name", "Fetech Tests")
    _git(project, "config", "user.email", "tests@example.invalid")
    _git(project, "add", ".")
    _git(project, "commit", "-q", "-m", "candidate")
    commit = _git(project, "rev-parse", "HEAD")

    wheel = artifact_dir / WHEEL_FILENAME
    sdist = artifact_dir / SDIST_FILENAME
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    wheel_sha, wheel_size = sha256_file(wheel, "test wheel")
    sdist_sha, sdist_size = sha256_file(sdist, "test sdist")
    checksums = artifact_dir / "SHA256SUMS"
    checksums.write_text(
        f"{wheel_sha}  {WHEEL_FILENAME}\n{sdist_sha}  {SDIST_FILENAME}\n",
        encoding="ascii",
    )
    checksums_sha, checksums_size = sha256_file(checksums, "test checksums")
    receipt: dict[str, object] = {
        "schema": "fetech.v0.4.release-artifacts.v1",
        "project": "fetech",
        "version": TARGET_VERSION,
        "source_commit": commit,
        "artifacts": [
            {
                "filename": WHEEL_FILENAME,
                "kind": "wheel",
                "sha256": wheel_sha,
                "size": wheel_size,
            },
            {
                "filename": SDIST_FILENAME,
                "kind": "sdist",
                "sha256": sdist_sha,
                "size": sdist_size,
            },
        ],
        "checksums": {
            "filename": "SHA256SUMS",
            "sha256": checksums_sha,
            "size": checksums_size,
        },
    }
    (artifact_dir / ARTIFACT_RECEIPT_FILENAME).write_bytes(canonical_json(receipt))
    return project, artifact_dir, receipt


def _artifact_digests(receipt: dict[str, object]) -> dict[str, str]:
    values = receipt["artifacts"]
    assert isinstance(values, list)
    return {
        str(value["kind"]): str(value["sha256"])
        for value in values
        if isinstance(value, dict)
    }


def _systemd_document(
    project: Path,
    artifact_dir: Path,
    receipt: dict[str, object],
) -> dict[str, object]:
    digests = _artifact_digests(receipt)
    artifact_receipt_sha, _ = sha256_file(
        artifact_dir / ARTIFACT_RECEIPT_FILENAME,
        "artifact receipt",
    )
    unit_sha, _ = sha256_file(
        project / SYSTEMD.REFERENCE_UNIT,
        "reference unit",
    )
    return {
        "schema": SYSTEMD.SCHEMA,
        "version": TARGET_VERSION,
        "source_commit": receipt["source_commit"],
        "collected_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "target_label": "debian-production-amd64",
        "attestor_principal": "operator@example.com",
        "platform": {
            "os_id": "debian",
            "os_version_id": "13",
            "kernel_release": "6.12.0",
            "architecture": "x86_64",
            "virtualization": "kvm",
            "systemd_version": 257,
            "pid1": "systemd",
            "cgroup_v2": True,
            "containerized": False,
        },
        "artifacts": {
            "artifact_receipt_sha256": artifact_receipt_sha,
            "wheel_sha256": digests["wheel"],
            "sdist_sha256": digests["sdist"],
            "unit_sha256": unit_sha,
            "docling_bundle_sha256": SYSTEMD.DOCLING_SHA256,
        },
        "service": {
            "unit_name": "fetech.service",
            "systemd_verify_passed": True,
            "systemd_security_completed": True,
            "active_state": "active",
            "sub_state": "running",
            "main_pid": 1234,
            "bubblewrap_version": "bubblewrap 0.11.0",
            "capability_category_count": 13,
            "capability_count": 155,
            "required_properties": dict(SYSTEMD._EXPECTED_PROPERTIES),
            "required_environment": list(SYSTEMD._EXPECTED_ENVIRONMENT),
        },
    }


def test_systemd_attestation_accepts_exact_fresh_target_and_rejects_lab(
    tmp_path: Path,
) -> None:
    project, artifact_dir, receipt = _candidate(tmp_path)
    document = _systemd_document(project, artifact_dir, receipt)

    assert SYSTEMD.validate_attestation(
        document,
        project_root=project,
        artifact_dir=artifact_dir,
    )["source_commit"] == receipt["source_commit"]

    old_systemd = copy.deepcopy(document)
    old_platform = old_systemd["platform"]
    assert isinstance(old_platform, dict)
    old_platform["systemd_version"] = 256
    with pytest.raises(ReleaseAttestationError, match="257 or newer"):
        SYSTEMD.validate_attestation(
            old_systemd,
            project_root=project,
            artifact_dir=artifact_dir,
        )

    container = copy.deepcopy(document)
    container_platform = container["platform"]
    assert isinstance(container_platform, dict)
    container_platform["containerized"] = True
    with pytest.raises(ReleaseAttestationError, match="containerized must be false"):
        SYSTEMD.validate_attestation(
            container,
            project_root=project,
            artifact_dir=artifact_dir,
        )

    overridden = copy.deepcopy(document)
    service = overridden["service"]
    assert isinstance(service, dict)
    properties = service["required_properties"]
    assert isinstance(properties, dict)
    properties["DropInPaths"] = "/etc/systemd/system/fetech.service.d/override.conf"
    with pytest.raises(ReleaseAttestationError, match="effective systemd properties"):
        SYSTEMD.validate_attestation(
            overridden,
            project_root=project,
            artifact_dir=artifact_dir,
        )


def test_systemd_collector_hashes_the_installed_docling_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = _load_script("collect_v04_systemd_attestation.py")
    monkeypatch.setattr(
        collector,
        "verify_docling_artifact_bundle",
        lambda *args, **kwargs: SimpleNamespace(bundle_sha256=collector.DOCLING_SHA256),
    )
    assert collector._docling_bundle_digest() == collector.DOCLING_SHA256

    def reject_bundle(*args: object, **kwargs: object) -> object:
        raise collector.DoclingArtifactBundleError("changed")

    monkeypatch.setattr(collector, "verify_docling_artifact_bundle", reject_bundle)
    with pytest.raises(ReleaseAttestationError, match="trust anchor"):
        collector._docling_bundle_digest()


def test_legal_approval_requires_exact_scope_components_and_signature(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, artifact_dir, _ = _candidate(tmp_path)
    approval = LEGAL.create_approval(
        project,
        artifact_dir,
        reviewer_principal="lawyer@example.com",
        reviewer_name="Qualified Reviewer",
        reviewer_organization="Example Legal",
        reviewer_role="Open-source counsel",
        approval_reference="MATTER-1234",
        jurisdictions=("Australia",),
    )
    receipt_path = artifact_dir / LEGAL.RECEIPT_FILENAME
    receipt_path.write_bytes(canonical_json(approval))
    signature_path = artifact_dir / LEGAL.SIGNATURE_FILENAME
    observed: dict[str, object] = {}

    def verify_signature(*args: object, **kwargs: object) -> None:
        observed["arguments"] = args
        observed["principal"] = kwargs["principal"]

    monkeypatch.setattr(LEGAL, "verify_ssh_signature", verify_signature)
    assert LEGAL.verify_approval(
        project,
        artifact_dir,
        receipt_path,
        signature_path,
        tmp_path / "legal.allowed_signers",
    )["decision"] == "approved"
    assert observed["principal"] == "lawyer@example.com"

    conditional = copy.deepcopy(approval)
    conditional["conditions"] = ["Add a notice"]
    with pytest.raises(ReleaseAttestationError, match="conditional"):
        LEGAL.validate_approval(
            conditional,
            project_root=project,
            artifact_dir=artifact_dir,
        )


def test_github_release_requires_exact_tag_commit_and_asset_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_assets = {
        name: (f"{index:064x}", index)
        for index, name in enumerate(GITHUB.REQUIRED_ASSET_LOCATIONS, 1)
    }
    commit = "a" * 40
    release = {
        "id": 123,
        "tag_name": GITHUB.TAG,
        "draft": False,
        "prerelease": True,
        "html_url": f"https://github.com/owner/repository/releases/tag/{GITHUB.TAG}",
        "published_at": "2026-09-04T00:00:00Z",
        "assets": [
            {
                "name": name,
                "state": "uploaded",
                "digest": f"sha256:{digest}",
                "size": size,
            }
            for name, (digest, size) in expected_assets.items()
        ],
    }
    monkeypatch.setattr(
        GITHUB,
        "load_release_artifacts",
        lambda *args: {"source_commit": commit},
    )
    monkeypatch.setattr(
        GITHUB, "_repository_from_origin", lambda root: "owner/repository"
    )
    monkeypatch.setattr(GITHUB, "_tag_commit", lambda repository: commit)
    monkeypatch.setattr(GITHUB, "_expected_assets", lambda *args: expected_assets)
    monkeypatch.setattr(GITHUB, "_gh_json", lambda endpoint: release)

    assert GITHUB.verify_release(tmp_path, tmp_path)["release_id"] == 123

    raw_assets = release["assets"]
    assert isinstance(raw_assets, list)
    raw_assets.append(
        {
            "name": "unreviewed.bin",
            "state": "uploaded",
            "digest": "sha256:" + "f" * 64,
            "size": 1,
        }
    )
    with pytest.raises(ReleaseAttestationError, match="inventory"):
        GITHUB.verify_release(tmp_path, tmp_path)


def test_github_release_requires_a_valid_signed_annotated_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "a" * 40
    tag_sha = "b" * 40
    responses: dict[str, dict[str, object]] = {
        f"repos/owner/repository/git/ref/tags/{GITHUB.TAG}": {
            "object": {"type": "tag", "sha": tag_sha}
        },
        f"repos/owner/repository/git/tags/{tag_sha}": {
            "object": {"type": "commit", "sha": commit},
            "verification": {"verified": True, "reason": "valid"},
        },
    }
    monkeypatch.setattr(GITHUB, "_gh_json", responses.__getitem__)
    assert GITHUB._tag_commit("owner/repository") == commit

    verification = responses[f"repos/owner/repository/git/tags/{tag_sha}"][
        "verification"
    ]
    assert isinstance(verification, dict)
    verification["verified"] = False
    with pytest.raises(ReleaseAttestationError, match="valid signature"):
        GITHUB._tag_commit("owner/repository")


def test_pypi_publication_requires_only_exact_approved_distributions() -> None:
    receipt = {
        "artifacts": [
            {
                "filename": WHEEL_FILENAME,
                "kind": "wheel",
                "sha256": "a" * 64,
                "size": 10,
            },
            {
                "filename": SDIST_FILENAME,
                "kind": "sdist",
                "sha256": "b" * 64,
                "size": 20,
            },
        ]
    }
    document = {
        "info": {"name": "fetech", "version": TARGET_VERSION},
        "urls": [
            {
                "filename": WHEEL_FILENAME,
                "packagetype": "bdist_wheel",
                "yanked": False,
                "digests": {"sha256": "a" * 64},
                "size": 10,
                "url": f"https://files.pythonhosted.org/packages/{WHEEL_FILENAME}",
                "upload_time_iso_8601": "2026-09-04T00:00:00Z",
            },
            {
                "filename": SDIST_FILENAME,
                "packagetype": "sdist",
                "yanked": False,
                "digests": {"sha256": "b" * 64},
                "size": 20,
                "url": f"https://files.pythonhosted.org/packages/{SDIST_FILENAME}",
                "upload_time_iso_8601": "2026-09-04T00:00:00Z",
            },
        ],
    }

    assert PYPI.verify_document(document, release_receipt=receipt)["version"] == TARGET_VERSION
    raw_urls = document["urls"]
    assert isinstance(raw_urls, list)
    first_url = raw_urls[0]
    assert isinstance(first_url, dict)
    digests = first_url["digests"]
    assert isinstance(digests, dict)
    digests["sha256"] = "c" * 64
    with pytest.raises(ReleaseAttestationError, match="digest"):
        PYPI.verify_document(document, release_receipt=receipt)

    digests["sha256"] = "a" * 64
    first_url["url"] = (
        f"https://files.pythonhosted.org/packages/{WHEEL_FILENAME}?untrusted=1"
    )
    with pytest.raises(ReleaseAttestationError, match="canonical HTTPS"):
        PYPI.verify_document(document, release_receipt=receipt)


def test_release_workflow_is_oidc_scoped_and_publishes_only_two_files() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    assert "environment:\n      name: pypi" in workflow
    assert "id-token: write" in workflow
    assert "actions/checkout@v6" in workflow
    assert "actions/setup-python@v6" in workflow
    assert "--trusted-publishing always" in workflow
    assert "verify_v04_systemd_attestation.py" in workflow
    assert "verify_v04_legal_approval.py" in workflow
    assert "verify_v04_github_release.py" in workflow
    assert "FETECH_SYSTEMD_ALLOWED_SIGNERS" in workflow
    assert "FETECH_LEGAL_ALLOWED_SIGNERS" in workflow
    assert WHEEL_FILENAME in workflow
    assert SDIST_FILENAME in workflow
    assert "dist/*" not in workflow
    assert "pull_request" not in workflow
