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
uv run pytest tests/test_beta_parser_fuzz.py
```

## Covered boundaries

| Boundary | Properties and malformed corpus |
| --- | --- |
| Public request validation | Arbitrary bounded JSON-like mappings must become either a valid contract or a bounded `FetechValidationError`; attacker field names and values never appear in the public envelope. |
| URL normalization and sanitization | Arbitrary Unicode is rejected as `ValueError` or yields deterministic HTTP(S), credential-free, fragment-free output. Sanitized URLs redact all query values in authenticated-style mode. |
| Structured APIs | Bounded arbitrary bytes exercise strict JSON and XML parsing with node/depth ceilings. A 2,000-level JSON corpus proves recursion errors do not escape the parser boundary. |
| Native documents | Text, Markdown, CSV, JSON, XML, and ZIP routing exercise block, depth, archive, input, and serialized-output limits. A CSV amplification corpus proves output is rejected before worker serialization. |
| Archives | Bounded ZIP/TAR bytes exercise member, expanded-byte, ratio, nesting, and path checks. Arbitrary JSON-like worker responses are revalidated for schema, base64, duplicate paths, and output limits. |
| Media | Bounded bytes exercise image headers, EXIF/TIFF offsets, WAV headers, subtitle decoding, podcast XML, and pre-acquired yt-dlp JSON. |
| Logic engines | Arbitrary Clingo bytes and JSON shapes must return a typed `BackendOutputError`; valid selected-node atoms round-trip exactly. Generated Prolog fact names prove case-insensitive sensitive-name rejection. |

The first run exposed and fixed three defects: raw CSV parser errors could escape, document-native
parsers did not centrally enforce the serialized-output ceiling, and malformed Clingo bytes could
escape as an untyped Unicode/schema exception.

## Evidence boundary and remaining work

The suite is regression evidence, not a claim that parsing is vulnerability-free. Random byte
generation mostly explores rejection paths. The next expansion should add format-aware generation
and mutation for valid RSS/Atom/sitemap/OpenAPI YAML, HTML/reader/discovery parsers, browser and
document worker IPC envelopes, OOXML/PDF fixtures inside required Linux isolation, and structured
archive corruption. Stateful storage and ledger behavior belongs to the separate storage-lifecycle
increment.

Keep every future fuzz target bounded. Do not invoke the network, shell, credential store, or an
unrestricted filesystem from generated examples. A discovered failure must be reduced to a stable
regression example before increasing example counts or input sizes.
