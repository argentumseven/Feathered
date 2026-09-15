from types import SimpleNamespace

import core
import repository_transport
from build_spec import RepositoryRecord, SourceSpec, BuildSpec, repositories_from
from feathered_app.build_runner import signature_verification_summary
from feathered_app.build_sources import BuildSourcesMixin


class _MirrorMetadataHost(BuildSourcesMixin):
    def _profile(self):
        return SimpleNamespace(
            label="Fixture Linux",
            package_family="rpm",
            codename=lambda release: release,
        )

    def _selected_arch(self):
        return "x86_64"

    def _selected_init_system(self):
        return "systemd"

    def _active_source_method(self):
        return "Fixture repositories"


_STATE = SimpleNamespace(
    intent=SimpleNamespace(value="repository-mirror"),
    capability=SimpleNamespace(value="repository-mirror"),
    analysis=SimpleNamespace(value="none"),
    publication=SimpleNamespace(value="mirror"),
    verification_scope=SimpleNamespace(value="repository"),
)


def test_signature_summary_uses_verified_facts_not_keyring_configuration():
    repo = core.RepoSpec(
        "Configured but skipped",
        "https://repo.example/",
        keyring="archive-key.gpg",
        verification_strategy="skip-provenance",
    )
    repo.trust = core.RepoTrust(repo=repo.name)

    summary = signature_verification_summary([
        repo.trust.archive_signature_verified,
    ])
    assert summary == {
        "signature_verification": "none",
        "repository_signature_verification": "none",
        "signature_verification_scheme": "none",
        "repository_signature_verified_count": 0,
        "repository_count": 1,
    }


def test_keyring_plus_skip_provenance_remains_unverified_in_bundle_summary(tmp_path):
    repodata = tmp_path / "repodata"
    repodata.mkdir()
    (repodata / "repomd.xml").write_text(
        '<repomd xmlns="http://linux.duke.edu/metadata/repo"></repomd>',
        encoding="utf-8",
    )
    repo = core.RepoSpec(
        "Skipped signature",
        tmp_path.as_uri() + "/",
        keyring=str(tmp_path / "unused-keyring.gpg"),
        verification_strategy="skip-provenance",
    )
    core.get_repo_data(repo, core.Reporter())
    assert repo.trust.archive_signature_verified is False
    assert signature_verification_summary(
        [repo.trust.archive_signature_verified])["repository_signature_verification"] == "none"


def test_signature_summary_distinguishes_partial_and_all_verification():
    partial = signature_verification_summary([True, False, True])
    assert partial["signature_verification"] == "none"
    assert partial["repository_signature_verification"] == "partial"
    assert partial["signature_verification_scheme"] == "openpgp"
    assert partial["repository_signature_verified_count"] == 2
    assert partial["repository_count"] == 3

    complete = signature_verification_summary([True, True])
    assert complete["signature_verification"] == "openpgp"
    assert complete["repository_signature_verification"] == "all"
    assert complete["repository_signature_verified_count"] == 2
    assert complete["repository_count"] == 2


def test_mirror_metadata_does_not_treat_configured_keyring_as_verified():
    host = _MirrorMetadataHost()
    reporter = SimpleNamespace(warnings=[])
    records = [{"keyring_configured": True, "signature_verified": False}]
    meta = host._mirror_bundle_metadata(_STATE, "9", reporter, records)
    assert meta["signature_verification"] == "none"
    assert meta["repository_signature_verification"] == "none"
    assert meta["signature_verification_scheme"] == "none"
    assert meta["repository_signature_verified_count"] == 0
    assert meta["repository_count"] == 1


def test_custom_query_credential_is_detected_and_redacted():
    secret = "vendor-bearer-123456789"
    repo = core.RepoSpec(
        "Vendor",
        f"https://repo.example/root/?license_token={secret}&channel=stable",
        sensitive_query_keys=["license_token"],
    )

    assert repository_transport.repo_has_endpoint_credentials(repo)
    redacted = core.redact_url(repo.url)
    assert secret not in redacted
    assert "license_token=REDACTED" in redacted
    assert "channel=stable" in redacted
    assert secret not in core.redact_text(f"GET {repo.url}")


def test_custom_query_credential_inheritance_is_explicit_and_same_origin_only():
    base = "https://repo.example/root/?license_token=abc123"
    sensitive_only = core.RepoSpec(
        "Sensitive only",
        base,
        sensitive_query_keys=["license_token"],
    )
    child = repository_transport.inherit_sensitive_query_credentials(
        base, "https://repo.example/root/Packages.gz", sensitive_only)
    assert "license_token" not in child

    inheritable = core.RepoSpec(
        "Inheritable",
        base,
        sensitive_query_keys=["license_token"],
        inheritable_query_credential_keys=["license_token"],
    )
    child = repository_transport.inherit_sensitive_query_credentials(
        base, "https://repo.example/root/Packages.gz", inheritable)
    assert "license_token=abc123" in child

    external = repository_transport.inherit_sensitive_query_credentials(
        base, "https://cdn.example/Packages.gz", inheritable)
    assert "license_token" not in external


def test_custom_query_credential_policy_round_trips_in_build_spec():
    repo = core.RepoSpec(
        "Vendor",
        "https://repo.example/root/?license_token=secret",
        sensitive_query_keys=["license_token", "subscription_key"],
        inheritable_query_credential_keys=["license_token"],
    )
    record = RepositoryRecord.capture(repo)
    assert record.sensitive_query_keys == ("license_token", "subscription_key")
    assert record.inheritable_query_credential_keys == ("license_token",)

    spec = BuildSpec(sources=SourceSpec(repositories=(record,)))
    rebuilt = repositories_from(spec, core.RepoSpec)[0]
    assert rebuilt.sensitive_query_keys == ["license_token", "subscription_key"]
    assert rebuilt.inheritable_query_credential_keys == ["license_token"]
    assert repository_transport.repo_has_endpoint_credentials(rebuilt)


def test_custom_inheritable_query_field_flows_through_repository_url_helpers():
    repo = core.RepoSpec(
        "Vendor",
        "https://repo.example/root/?license_token=abc123",
        sensitive_query_keys=["license_token"],
        inheritable_query_credential_keys=["license_token"],
    )
    metadata = core.url_join(repo.normalized_url, "repodata/repomd.xml", repo)
    package = core.repo_relative_url(repo.normalized_url, "Packages/tool.rpm", repo)
    assert "license_token=abc123" in metadata
    assert "license_token=abc123" in package


def test_custom_query_credential_enables_redirect_confinement():
    import urllib.request

    repo = core.RepoSpec(
        "Vendor",
        "https://repo.example/root/?license_token=abc123",
        sensitive_query_keys=["license_token"],
    )
    handler = repository_transport.RepositoryRedirectHandler(repo)
    request = urllib.request.Request(
        "https://repo.example/root/repodata/repomd.xml?license_token=abc123")
    try:
        handler.redirect_request(
            request, None, 302, "Found", {}, "https://other.example/repomd.xml")
    except RuntimeError as exc:
        assert "credentialed repository redirect" in str(exc).lower()
    else:
        raise AssertionError("custom query credential did not activate redirect confinement")


def test_builtin_signed_url_fields_cannot_be_made_inheritable():
    base = "https://repo.example/root/?X-Amz-Signature=resource-signature"
    repo = core.RepoSpec(
        "Signed URL",
        base,
        inheritable_query_credential_keys=["x-amz-signature"],
    )
    assert repo.inheritable_query_credential_keys == []
    child = repository_transport.inherit_sensitive_query_credentials(
        base, "https://repo.example/root/Packages.gz", repo)
    assert "X-Amz-Signature" not in child
    assert "x-amz-signature" not in child.lower()
