# Parser fuzzing

Fetech uses deterministic property tests and curated malformed-input corpora to exercise native
trust boundaries. These tests complement, but do not replace, resource-isolated parsing, fixture
conformance, dependency review, or external fuzzing campaigns.

## Reproducible profile

The shared profile in `tests/conftest.py` runs 50 examples per property with a 500 ms example
deadline. Hypothesis derandomization is enabled and its example database is disabled, so a clean
checkout and GitHub CI explore the same bounded sequence without creating repository state.
Hypothesis is a development-only dependency and is present in the universal lock used by CI.

Run the current slice with:

```bash
uv sync --frozen --all-extras
uv run pytest tests/test_beta_parser_fuzz.py tests/test_beta_format_fuzz.py
```

## Covered boundaries

| Boundary | Properties and malformed corpus |
| --- | --- |
| Public request validation | Arbitrary bounded JSON-like mappings must become either a valid contract or a bounded `FetechValidationError`; attacker field names and values never appear in the public envelope. |
| URL normalization and sanitization | Arbitrary Unicode is rejected as `ValueError` or yields deterministic HTTP(S), credential-free, fragment-free output. Sanitized URLs redact all query values in authenticated-style mode. |
| Structured APIs and feeds | Bounded arbitrary bytes exercise strict JSON and XML parsing with node/depth ceilings. Valid generated RSS, Atom, sitemap, and OpenAPI YAML documents prove deterministic normalization, record/path truncation, locator uniqueness, and omitted-record accounting. Generated duplicate OpenAPI paths are rejected by the unique-key safe loader. A 2,000-level JSON corpus proves recursion errors do not escape the parser boundary. |
| HTML reader, discovery, and navigation | Generated visible/hidden content and HTTP(S), `javascript:`, and `mailto:` links prove deterministic text extraction, script/style removal, scheme-bounded discovery, relation classification, and canonical/OpenGraph/meta-refresh/JavaScript navigation extraction. These parsers do not execute scripts or acquire URLs. |
| Native documents | Text, Markdown, CSV, JSON, XML, and ZIP routing exercise block, depth, archive, input, and serialized-output limits. A CSV amplification corpus proves output is rejected before worker serialization. Generated document-worker envelopes must produce a schema-valid bounded result or a typed `AdapterExecutionError`, including for invalid Unicode. |
| Browser worker envelopes | Generated browser-render text and screenshots prove byte accounting and typed Unicode rejection. Non-finite observations and malformed UTF-8 subprocess responses are rejected as bounded `AdapterExecutionError` values by both render and reader boundaries. No generated example launches Chromium. |
| Archives | Bounded ZIP/TAR bytes exercise member, expanded-byte, ratio, nesting, and path checks. Arbitrary JSON-like worker responses are revalidated for schema, base64, duplicate paths, and output limits. Valid generated stored ZIPs round-trip within member/expanded limits, while generated traversal paths and structured central-directory truncations fail closed. |
| Media | Bounded bytes exercise image headers, EXIF/TIFF offsets, WAV headers, subtitle decoding, podcast XML, and pre-acquired yt-dlp JSON. |
| Logic engines | Arbitrary Clingo bytes and JSON shapes must return a typed `BackendOutputError`; valid selected-node atoms round-trip exactly. Generated Prolog fact names prove case-insensitive sensitive-name rejection. |

The first run exposed and fixed three defects: raw CSV parser errors could escape, document-native
parsers did not centrally enforce the serialized-output ceiling, and malformed Clingo bytes could
escape as an untyped Unicode/schema exception. The format-aware expansion found three more boundary
classes: invalid Unicode could escape browser/document serialization, malformed UTF-8 worker JSON
was not consistently converted to a typed adapter failure, and browser observations accepted
non-finite floats. Each now fails closed with a stable regression property.

## Evidence boundary and remaining work

The suite is regression evidence, not a claim that parsing is vulnerability-free. The remaining
format campaign is Linux-isolated OOXML/PDF generation and mutation plus broader TAR/container
corruption and sustained external fuzzing. Those cases must run inside the required parser worker
profile; the in-process property suite is not containment evidence. Stateful storage and ledger
behavior belongs to the separate storage-lifecycle increment.

Keep every future fuzz target bounded. Do not invoke the network, shell, credential store, or an
unrestricted filesystem from generated examples. A discovered failure must be reduced to a stable
regression example before increasing example counts or input sizes.
