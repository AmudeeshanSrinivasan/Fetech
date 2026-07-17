# Fetech 0.3.0a0 dependency-license report

This is deterministic engineering evidence, not legal advice. License declarations
were reviewed for the exact versions in `uv.lock`; SPDX `licenseConcluded` remains
`NOASSERTION` for third-party packages because this report does not make legal conclusions.

## Inputs and coverage

- Generator: `fetech-release-evidence-generator/1`
- Evidence timestamp: `2026-07-17T00:00:00Z`
- `uv.lock` SHA-256: `b0f149e119743287a45a95405ffd417005b395c7b810e42a9da8edc152d364ea`
- Third-party locked packages: **113**
- Coverage: base runtime, every declared optional extra, development dependencies,
  and all platform-marker alternatives represented by the universal lock.
- Package evidence links point to version-specific PyPI release pages. The reviewed
  catalog also uses package metadata, bundled notices, and upstream license files;
  special review notes remain attached to affected rows.

## Automated policy observations

- Missing or `NOASSERTION` declared licenses: **0**
- Declared AGPL expressions: **0**
- Ambiguous `LicenseRef` declarations: **1**
- Disjunctive GPL/LGPL choice expressions: **1**
- AGPL policy check: **pass** — no locked package declares AGPL.
- License-choice review: `tld==0.13.2`. Preserve the selected upstream license and notices when redistributing.
- Exact-license review: `sgmllib3k==1.0.0`. The package metadata does not identify a precise SPDX license.

## Separately installed and future runtime tools

These executables and downloaded artifacts are not Python packages distributed in
the v0.3 wheel, so they are not added as packages in this lock-derived SBOM. If a
future Fetech distribution bundles them, generate a distribution-specific SBOM and
carry their exact versions, build options, licenses, notices, and transitive libraries.

| Component | v0.3 status | License observation | Required review | Primary source |
|---|---|---|---|---|
| SWI-Prolog | Optional v0.3 logic executable; installed separately and not shipped by Fetech. | `BSD-2-Clause` for the core. | The selected build may link GMP or load add-ons with additional terms; inspect the build with SWI-Prolog's `license.` predicate. | [Upstream](https://www.swi-prolog.org/license.html) |
| curl | Optional v0.3 HTTP/3 executable; installed separately and not shipped by Fetech. | SPDX `curl`. | Record and review the selected curl build and its linked libraries before redistributing a system image. | [Upstream](https://curl.se/docs/copyright.html) |
| Playwright browser binaries | Downloaded separately by the Playwright CLI; not contained in the Python wheel. | Varies by browser and build. | The Python `playwright` package is in the SBOM; browser binaries are separate artifacts whose bundled licenses and notices must be reviewed. | [Upstream](https://playwright.dev/python/docs/browsers) |
| FFmpeg | Planned for v0.4 media support; not shipped or required by v0.3. | `LGPL-2.1-or-later` baseline. | Optional GPL-covered parts change the license of the complete FFmpeg build to GPL; inspect configure flags and linked libraries before distribution. | [Upstream](https://ffmpeg.org/legal.html) |

## Scope counts

| Scope | Packages |
|---|---:|
| `runtime` | 26 |
| `extra:all` | 78 |
| `extra:browser` | 20 |
| `extra:dev` | 27 |
| `extra:documents` | 9 |
| `extra:logic` | 3 |
| `extra:mcp` | 31 |
| `extra:media` | 2 |
| `extra:server` | 14 |
| `extra:web` | 26 |

A package may appear in multiple scopes. The `all` extra intentionally overlaps
the narrower feature extras.

## License-expression summary

| Declared SPDX expression | Packages |
|---|---:|
| `0BSD` | 1 |
| `Apache-2.0` | 14 |
| `Apache-2.0 AND CNRI-Python` | 1 |
| `Apache-2.0 OR BSD-2-Clause` | 1 |
| `Apache-2.0 OR BSD-3-Clause` | 2 |
| `BSD-2-Clause` | 4 |
| `BSD-3-Clause` | 18 |
| `ISC` | 1 |
| `LicenseRef-BSD-Unknown` | 1 |
| `MIT` | 57 |
| `MIT AND PSF-2.0` | 1 |
| `MIT OR Apache-2.0` | 3 |
| `MIT-0` | 1 |
| `MIT-CMU` | 1 |
| `MPL-1.1 OR GPL-2.0-only OR LGPL-2.1-or-later` | 1 |
| `MPL-2.0` | 2 |
| `PSF-2.0` | 3 |
| `Unlicense` | 1 |

## Dependency inventory

| Package | Version | Scope(s) | Declared license | Evidence |
|---|---|---|---|---|
| `aiosqlite` | `0.22.1` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/aiosqlite/0.22.1/) |
| `annotated-doc` | `0.0.4` | `runtime`, `extra:all`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/annotated-doc/0.0.4/) |
| `annotated-types` | `0.7.0` | `runtime`, `extra:all`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/annotated-types/0.7.0/) |
| `anyio` | `4.14.2` | `runtime`, `extra:all`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/anyio/4.14.2/) |
| `ast-serialize` | `0.6.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/ast-serialize/0.6.0/) |
| `attrs` | `26.1.0` | `extra:all`, `extra:browser`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/attrs/26.1.0/) |
| `babel` | `2.18.0` | `extra:all`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/babel/2.18.0/) |
| `beautifulsoup4` | `4.15.0` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/beautifulsoup4/4.15.0/) |
| `certifi` | `2026.6.17` | `runtime`, `extra:all`, `extra:browser`, `extra:mcp`, `extra:web` | `MPL-2.0` | [PyPI release](https://pypi.org/project/certifi/2026.6.17/) |
| `cffi` | `2.1.0` | `extra:all`, `extra:browser`, `extra:logic`, `extra:mcp` | `MIT-0` | [PyPI release](https://pypi.org/project/cffi/2.1.0/) |
| `cfgv` | `3.5.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/cfgv/3.5.0/) |
| `chardet` | `7.4.3` | `extra:all`, `extra:web` | `0BSD` | [PyPI release](https://pypi.org/project/chardet/7.4.3/) |
| `charset-normalizer` | `3.4.9` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/charset-normalizer/3.4.9/) |
| `click` | `8.4.2` | `extra:all`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/click/8.4.2/) |
| `clingo` | `5.8.0` | `extra:all`, `extra:logic` | `MIT` | [PyPI release](https://pypi.org/project/clingo/5.8.0/) |
| `colorama` | `0.4.6` | `runtime`, `extra:all`, `extra:dev`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/colorama/0.4.6/) |
| `courlan` | `1.4.0` | `extra:all`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/courlan/1.4.0/) |
| `coverage` | `7.15.2` | `extra:dev` | `Apache-2.0` | [PyPI release](https://pypi.org/project/coverage/7.15.2/) |
| `cryptography` | `49.0.0` | `extra:all`, `extra:mcp` | `Apache-2.0 OR BSD-3-Clause` | [PyPI release](https://pypi.org/project/cryptography/49.0.0/) |
| `cssselect` | `1.4.0` | `extra:all`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/cssselect/1.4.0/) |
| `dateparser` | `1.4.1` | `extra:all`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/dateparser/1.4.1/) |
| `distlib` | `0.4.3` | `extra:dev` | `PSF-2.0` | [PyPI release](https://pypi.org/project/distlib/0.4.3/) |
| `et-xmlfile` | `2.0.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/et-xmlfile/2.0.0/) |
| `fastapi` | `0.139.1` | `extra:all`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/fastapi/0.139.1/) |
| `feedparser` | `6.0.12` | `extra:all`, `extra:web` | `BSD-2-Clause` | [PyPI release](https://pypi.org/project/feedparser/6.0.12/) |
| `filelock` | `3.30.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/filelock/3.30.0/) |
| `greenlet` | `3.5.3` | `runtime`, `extra:all`, `extra:browser` | `MIT AND PSF-2.0` | [PyPI release](https://pypi.org/project/greenlet/3.5.3/) |
| `h11` | `0.16.0` | `runtime`, `extra:all`, `extra:browser`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/h11/0.16.0/) |
| `h2` | `4.3.0` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/h2/4.3.0/) |
| `hpack` | `4.2.0` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/hpack/4.2.0/) |
| `htmldate` | `1.10.0` | `extra:all`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/htmldate/1.10.0/) |
| `httpcore` | `1.0.9` | `runtime`, `extra:all`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/httpcore/1.0.9/) |
| `httpx` | `0.28.1` | `runtime`, `extra:all`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/httpx/0.28.1/) |
| `httpx-sse` | `0.4.3` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/httpx-sse/0.4.3/) |
| `hyperframe` | `6.1.0` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/hyperframe/6.1.0/) |
| `identify` | `2.6.19` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/identify/2.6.19/) |
| `idna` | `3.18` | `runtime`, `extra:all`, `extra:browser`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/idna/3.18/) |
| `iniconfig` | `2.3.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/iniconfig/2.3.0/) |
| `jsonschema` | `4.26.0` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/jsonschema/4.26.0/) |
| `jsonschema-specifications` | `2025.9.1` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/jsonschema-specifications/2025.9.1/) |
| `justext` | `3.0.2` | `extra:all`, `extra:web` | `BSD-2-Clause` | [PyPI release](https://pypi.org/project/justext/3.0.2/) |
| `librt` | `0.13.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/librt/0.13.0/) |
| `lxml` | `6.1.1` | `extra:all`, `extra:documents`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/lxml/6.1.1/) |
| `lxml-html-clean` | `0.4.5` | `extra:all`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/lxml-html-clean/0.4.5/) |
| `markdown-it-py` | `4.2.0` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/markdown-it-py/4.2.0/) |
| `mcp` | `1.28.1` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/mcp/1.28.1/) |
| `mdurl` | `0.1.2` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/mdurl/0.1.2/) |
| `mypy` | `2.3.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/mypy/2.3.0/) |
| `mypy-extensions` | `1.1.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/mypy-extensions/1.1.0/) |
| `nodeenv` | `1.10.0` | `extra:dev` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/nodeenv/1.10.0/) |
| `openpyxl` | `3.1.5` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/openpyxl/3.1.5/) |
| `outcome` | `1.3.0.post0` | `extra:all`, `extra:browser` | `MIT OR Apache-2.0` | [PyPI release](https://pypi.org/project/outcome/1.3.0.post0/) |
| `packaging` | `26.2` | `extra:dev` | `Apache-2.0 OR BSD-2-Clause` | [PyPI release](https://pypi.org/project/packaging/26.2/) |
| `pathspec` | `1.1.1` | `extra:dev` | `MPL-2.0` | [PyPI release](https://pypi.org/project/pathspec/1.1.1/) |
| `pillow` | `12.3.0` | `extra:all`, `extra:documents`, `extra:media` | `MIT-CMU` | [PyPI release](https://pypi.org/project/pillow/12.3.0/) |
| `platformdirs` | `4.10.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/platformdirs/4.10.0/) |
| `playwright` | `1.61.0` | `extra:all`, `extra:browser` | `Apache-2.0` | [PyPI release](https://pypi.org/project/playwright/1.61.0/) |
| `pluggy` | `1.6.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/pluggy/1.6.0/) |
| `pre-commit` | `4.6.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/pre-commit/4.6.0/) |
| `pycparser` | `3.0` | `extra:all`, `extra:browser`, `extra:logic`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/pycparser/3.0/) |
| `pydantic` | `2.13.4` | `runtime`, `extra:all`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/pydantic/2.13.4/) |
| `pydantic-core` | `2.46.4` | `runtime`, `extra:all`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/pydantic-core/2.46.4/) |
| `pydantic-settings` | `2.14.2` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/pydantic-settings/2.14.2/) |
| `pyee` | `13.0.1` | `extra:all`, `extra:browser` | `MIT` | [PyPI release](https://pypi.org/project/pyee/13.0.1/) |
| `pygments` | `2.20.0` | `runtime`, `extra:dev` | `BSD-2-Clause` | [PyPI release](https://pypi.org/project/pygments/2.20.0/) |
| `pyjwt` | `2.13.0` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/pyjwt/2.13.0/) |
| `pypdf` | `6.14.2` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/pypdf/6.14.2/) |
| `pysocks` | `1.7.1` | `extra:all`, `extra:browser` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/pysocks/1.7.1/) |
| `pytest` | `9.1.1` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/pytest/9.1.1/) |
| `pytest-asyncio` | `1.4.0` | `extra:dev` | `Apache-2.0` | [PyPI release](https://pypi.org/project/pytest-asyncio/1.4.0/) |
| `python-dateutil` | `2.9.0.post0` | `extra:all`, `extra:web` | `Apache-2.0 OR BSD-3-Clause` | [PyPI release](https://pypi.org/project/python-dateutil/2.9.0.post0/) |
| `python-discovery` | `1.4.4` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/python-discovery/1.4.4/) |
| `python-docx` | `1.2.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/python-docx/1.2.0/) |
| `python-dotenv` | `1.2.2` | `extra:all`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/python-dotenv/1.2.2/) |
| `python-multipart` | `0.0.32` | `extra:all`, `extra:mcp` | `Apache-2.0` | [PyPI release](https://pypi.org/project/python-multipart/0.0.32/) |
| `python-pptx` | `1.0.2` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/python-pptx/1.0.2/) |
| `pytz` | `2026.2` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/pytz/2026.2/) |
| `pywin32` | `312` | `extra:all`, `extra:mcp` | `PSF-2.0` | [PyPI release](https://pypi.org/project/pywin32/312/)<br>Review: Upstream states that files use a mixture of licenses; PSF-2.0 is package metadata, and bundled notices remain authoritative. |
| `pyyaml` | `6.0.3` | `runtime`, `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/pyyaml/6.0.3/) |
| `readability-lxml` | `0.8.4.1` | `extra:all`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/readability-lxml/0.8.4.1/) |
| `referencing` | `0.37.0` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/referencing/0.37.0/) |
| `regex` | `2026.7.10` | `extra:all`, `extra:web` | `Apache-2.0 AND CNRI-Python` | [PyPI release](https://pypi.org/project/regex/2026.7.10/) |
| `rich` | `15.0.0` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/rich/15.0.0/) |
| `rpds-py` | `2026.6.3` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/rpds-py/2026.6.3/) |
| `ruff` | `0.15.21` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/ruff/0.15.21/) |
| `selenium` | `4.46.0` | `extra:all`, `extra:browser` | `Apache-2.0` | [PyPI release](https://pypi.org/project/selenium/4.46.0/) |
| `sgmllib3k` | `1.0.0` | `extra:all`, `extra:web` | `LicenseRef-BSD-Unknown` | [PyPI release](https://pypi.org/project/sgmllib3k/1.0.0/)<br>Review: PyPI declares only BSD License without identifying the exact BSD variant; resolve the variant before redistribution. |
| `shellingham` | `1.5.4` | `runtime` | `ISC` | [PyPI release](https://pypi.org/project/shellingham/1.5.4/) |
| `six` | `1.17.0` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/six/1.17.0/) |
| `sniffio` | `1.3.1` | `extra:all`, `extra:browser` | `MIT OR Apache-2.0` | [PyPI release](https://pypi.org/project/sniffio/1.3.1/) |
| `sortedcontainers` | `2.4.0` | `extra:all`, `extra:browser` | `Apache-2.0` | [PyPI release](https://pypi.org/project/sortedcontainers/2.4.0/) |
| `soupsieve` | `2.8.4` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/soupsieve/2.8.4/) |
| `sqlalchemy` | `2.0.51` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/sqlalchemy/2.0.51/) |
| `sse-starlette` | `3.4.5` | `extra:all`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/sse-starlette/3.4.5/) |
| `starlette` | `1.3.1` | `extra:all`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/starlette/1.3.1/) |
| `tld` | `0.13.2` | `extra:all`, `extra:web` | `MPL-1.1 OR GPL-2.0-only OR LGPL-2.1-or-later` | [PyPI release](https://pypi.org/project/tld/0.13.2/)<br>Review: The upstream declaration is a disjunctive choice that includes GPL and LGPL alternatives; preserve the chosen license and notices when redistributing. |
| `trafilatura` | `2.1.0` | `extra:all`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/trafilatura/2.1.0/) |
| `trio` | `0.33.0` | `extra:all`, `extra:browser` | `MIT OR Apache-2.0` | [PyPI release](https://pypi.org/project/trio/0.33.0/) |
| `trio-websocket` | `0.12.2` | `extra:all`, `extra:browser` | `MIT` | [PyPI release](https://pypi.org/project/trio-websocket/0.12.2/) |
| `typer` | `0.27.0` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/typer/0.27.0/) |
| `types-openpyxl` | `3.1.5.20260518` | `extra:dev` | `Apache-2.0` | [PyPI release](https://pypi.org/project/types-openpyxl/3.1.5.20260518/) |
| `types-pyyaml` | `6.0.12.20260518` | `extra:dev` | `Apache-2.0` | [PyPI release](https://pypi.org/project/types-pyyaml/6.0.12.20260518/) |
| `typing-extensions` | `4.16.0` | `runtime`, `extra:all`, `extra:browser`, `extra:dev`, `extra:documents`, `extra:mcp`, `extra:server`, `extra:web` | `PSF-2.0` | [PyPI release](https://pypi.org/project/typing-extensions/4.16.0/) |
| `typing-inspection` | `0.4.2` | `runtime`, `extra:all`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/typing-inspection/0.4.2/) |
| `tzdata` | `2026.3` | `extra:all`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/tzdata/2026.3/) |
| `tzlocal` | `5.4.4` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/tzlocal/5.4.4/) |
| `urllib3` | `2.7.0` | `extra:all`, `extra:browser`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/urllib3/2.7.0/) |
| `uvicorn` | `0.51.0` | `extra:all`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/uvicorn/0.51.0/) |
| `virtualenv` | `21.6.1` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/virtualenv/21.6.1/) |
| `websocket-client` | `1.9.0` | `extra:all`, `extra:browser` | `Apache-2.0` | [PyPI release](https://pypi.org/project/websocket-client/1.9.0/) |
| `wsproto` | `1.3.2` | `extra:all`, `extra:browser` | `MIT` | [PyPI release](https://pypi.org/project/wsproto/1.3.2/) |
| `xlsxwriter` | `3.2.9` | `extra:all`, `extra:documents` | `BSD-2-Clause` | [PyPI release](https://pypi.org/project/xlsxwriter/3.2.9/) |
| `yt-dlp` | `2026.7.4` | `extra:all`, `extra:media` | `Unlicense` | [PyPI release](https://pypi.org/project/yt-dlp/2026.7.4/) |

## Reproduction

Run from the repository root:

```console
uv run python scripts/generate_release_evidence.py --check
```

`--check` regenerates both artifacts in memory and fails if tracked evidence
differs from `pyproject.toml`, `uv.lock`, or the reviewed catalog.
