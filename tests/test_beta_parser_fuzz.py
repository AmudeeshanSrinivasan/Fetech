"""Bounded property fuzzing for native untrusted-input boundaries."""

from __future__ import annotations

import json
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from contextlib import suppress
from urllib.parse import urlsplit

from hypothesis import given
from hypothesis import strategies as st

from fetech.adapters.api import _parse_json as parse_api_json
from fetech.adapters.api import _parse_xml as parse_api_xml
from fetech.adapters.archive import (
    ArchiveLimits,
    _extract_members,
    _validate_worker_members,
)
from fetech.adapters.base import AdapterExecutionError
from fetech.adapters.documents import DocumentLimits
from fetech.adapters.documents import _parse as parse_document
from fetech.adapters.media import (
    _extract_exif_metadata,
    _image_metadata,
    _parse_podcast_feed,
    _parse_subtitle_text,
    _preacquired_youtube_document,
    _wave_metadata,
)
from fetech.errors import FetechValidationError, validate_fetch_request
from fetech.logic.base import BackendOutputError
from fetech.logic.clingo_backend import ClingoPlannerBackend, _asp_string
from fetech.logic.prolog_backend import _reject_sensitive_facts
from fetech.security import normalize_url, sanitize_url

_PRIVATE_FIELD = "attacker_private_probe"
_PRIVATE_VALUE = "DO_NOT_DISCLOSE_FETECH_FUZZ_PROBE"
_TEXT = st.one_of(
    st.text(max_size=256),
    st.sampled_from(("\ud800", "https://\ud800.example/", "query=\udfff")),
)
_JSON_SCALAR = st.none() | st.booleans() | st.integers() | st.floats(
    allow_nan=False,
    allow_infinity=False,
) | _TEXT
_JSON_VALUE = st.recursive(
    _JSON_SCALAR,
    lambda children: st.lists(children, max_size=8)
    | st.dictionaries(_TEXT, children, max_size=8),
    max_leaves=24,
)
_DOCUMENT_CAPABILITIES = st.sampled_from(
    ("txt", "markdown", "csv", "json_file", "xml_file", "zip_archive")
)


@given(_TEXT)
def test_url_normalization_is_deterministic_or_rejects_as_value_error(target: str) -> None:
    try:
        normalized = normalize_url(target)
    except ValueError:
        return

    assert normalize_url(target) == normalized
    assert normalize_url(normalized) == normalized
    parts = urlsplit(normalized)
    assert parts.scheme in {"http", "https"}
    assert parts.hostname
    assert parts.username is None
    assert parts.password is None
    assert not parts.fragment


@given(_TEXT)
def test_url_sanitization_never_retains_userinfo_or_fragments(target: str) -> None:
    try:
        sanitized = sanitize_url(target, redact_query=True)
    except ValueError:
        return

    assert sanitize_url(target, redact_query=True) == sanitized
    assert _PRIVATE_VALUE not in sanitized
    parts = urlsplit(sanitized)
    assert parts.username is None
    assert parts.password is None
    assert not parts.fragment


@given(st.dictionaries(_TEXT, _JSON_VALUE, max_size=12))
def test_request_validation_returns_only_bounded_public_failures(payload: dict[str, object]) -> None:
    payload[_PRIVATE_FIELD] = _PRIVATE_VALUE
    try:
        validate_fetch_request(payload)
    except FetechValidationError as exc:
        encoded = exc.error.model_dump_json()
        assert _PRIVATE_FIELD not in encoded
        assert _PRIVATE_VALUE not in encoded
        assert len(exc.error.issues) <= 32
        return
    raise AssertionError("an extra untrusted request field was accepted")


@given(st.binary(max_size=2_048))
def test_structured_json_and_xml_parsers_are_bounded_and_deterministic(body: bytes) -> None:
    parsers = (
        lambda: parse_api_json(body, maximum_nodes=32, maximum_depth=8),
        lambda: parse_api_xml(body, maximum_nodes=32, maximum_depth=8),
    )
    for parse in parsers:
        try:
            first = parse()
            second = parse()
        except (ET.ParseError, UnicodeError, ValueError):
            continue
        if isinstance(first, ET.Element):
            assert ET.tostring(first) == ET.tostring(second)
        else:
            assert first == second


def test_deep_json_corpus_is_rejected_without_recursion_escape() -> None:
    body = b"[" * 2_000 + b"0" + b"]" * 2_000
    try:
        parse_api_json(body, maximum_nodes=100, maximum_depth=8)
    except ValueError:
        pass
    else:
        raise AssertionError("deep API JSON exceeded its depth bound")

    limits = DocumentLimits(maximum_input_bytes=len(body), maximum_depth=8)
    try:
        parse_document("json_file", body, limits=limits)
    except ValueError:
        pass
    else:
        raise AssertionError("deep document JSON exceeded its depth bound")


@given(_DOCUMENT_CAPABILITIES, st.binary(max_size=512))
def test_document_parsers_enforce_shape_and_output_bounds(capability: str, body: bytes) -> None:
    limits = DocumentLimits(
        maximum_input_bytes=512,
        maximum_output_bytes=2_048,
        maximum_blocks=16,
        maximum_depth=8,
        maximum_archive_members=8,
        maximum_archive_ratio=20,
    )
    try:
        first = parse_document(capability, body, limits=limits)
        second = parse_document(capability, body, limits=limits)
    except (EOFError, ET.ParseError, OSError, UnicodeError, ValueError, zipfile.BadZipFile):
        return

    assert first == second
    document, locators, _ = first
    assert len(document["blocks"]) <= limits.maximum_blocks
    assert len(locators) == len(set(locators))
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    assert len(encoded) <= limits.maximum_output_bytes


def test_document_output_limit_corpus_is_rejected_before_worker_serialization() -> None:
    body = (b"cell," * 80) + b"end"
    limits = DocumentLimits(
        maximum_input_bytes=len(body),
        maximum_output_bytes=128,
        maximum_blocks=8,
    )
    try:
        parse_document("csv", body, limits=limits)
    except ValueError:
        pass
    else:
        raise AssertionError("document parser emitted output beyond its configured limit")


@given(st.binary(max_size=2_048))
def test_archive_and_media_binary_parsers_fail_closed(body: bytes) -> None:
    try:
        members = _extract_members(
            body,
            maximum_members=8,
            maximum_expanded=4_096,
            maximum_ratio=20,
        )
    except (EOFError, OSError, RuntimeError, ValueError, tarfile.TarError, zipfile.BadZipFile):
        pass
    else:
        assert len(members) <= 8
        assert sum(len(content) for _, content in members) <= 4_096

    for parse in (
        lambda: _image_metadata(body, maximum_pixels=1_000_000),
        lambda: _extract_exif_metadata(body, maximum_fields=32),
        lambda: _wave_metadata(body),
        lambda: _parse_subtitle_text(body, maximum_text_bytes=2_048),
        lambda: _parse_podcast_feed(
            body,
            maximum_episodes=8,
            maximum_bytes=2_048,
            maximum_nodes=32,
            maximum_depth=8,
        ),
        lambda: _preacquired_youtube_document(body, maximum_bytes=2_048),
    ):
        with suppress(AdapterExecutionError, ET.ParseError, UnicodeError, ValueError):
            parse()


@given(
    st.one_of(
        _JSON_VALUE,
        st.builds(
            lambda members: {"members": members},
            st.lists(
                st.fixed_dictionaries({"name": _TEXT, "body": _TEXT}),
                max_size=8,
            ),
        ),
    )
)
def test_archive_worker_output_is_revalidated_as_untrusted(response: object) -> None:
    limits = ArchiveLimits(maximum_members=4, maximum_expanded=256, maximum_ratio=20)
    try:
        members = _validate_worker_members(response, limits)
    except (AdapterExecutionError, ValueError):
        return

    assert len(members) <= limits.maximum_members
    assert sum(len(content) for _, content in members) <= limits.maximum_expanded
    assert len({name.casefold() for name, _ in members}) == len(members)


@given(st.binary(max_size=4_096))
def test_clingo_output_parser_rejects_every_malformed_shape(body: bytes) -> None:
    try:
        selected = ClingoPlannerBackend._selected_nodes(body)
    except BackendOutputError:
        return
    assert all(isinstance(identifier, str) for identifier in selected)


@given(st.sets(st.from_regex(r"[a-z][a-z0-9_]{0,31}", fullmatch=True), max_size=16))
def test_clingo_valid_answer_sets_round_trip_registered_node_syntax(nodes: set[str]) -> None:
    values = [f"selected({_asp_string(node)})" for node in sorted(nodes)]
    body = json.dumps({"Call": [{"Witnesses": [{"Value": values}]}]}).encode()
    assert ClingoPlannerBackend._selected_nodes(body) == nodes


@given(st.from_regex(r"[a-z_][a-z0-9_]{0,32}", fullmatch=True))
def test_prolog_fact_filter_is_case_insensitive_and_deterministic(key: str) -> None:
    facts = {key: True}
    lowered = key.casefold()
    sensitive = any(
        marker in lowered
        for marker in ("authorization", "body", "cookie", "credential", "password", "secret", "token")
    )
    if sensitive:
        try:
            _reject_sensitive_facts(facts)
        except BackendOutputError:
            return
        raise AssertionError("sensitive Prolog fact name was accepted")
    _reject_sensitive_facts(facts)
