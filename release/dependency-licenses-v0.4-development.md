# Fetech v0.4 development overlay dependency-license report

This is deterministic development engineering evidence, not legal advice and not
a published-release license report. The package metadata and universal lock remain
`0.3.0a0`; the overlay label does not relabel the Python distribution.
License declarations were reviewed for the exact versions in `uv.lock`; SPDX
`licenseConcluded` remains `NOASSERTION` for third-party packages because this
report does not make legal conclusions.

## Inputs and coverage

- Generator: `fetech-release-evidence-generator/2`
- Evidence timestamp: `2026-07-18T00:00:00Z`
- Overlay status: `unreleased-development`
- Package version: `0.3.0a0`
- `uv.lock` SHA-256: `46bc657e706f28318b563c70bb41da0000dabd6a97b48f60683fe254ff65515d`
- Third-party locked packages: **167**
- Overlay capabilities: **36**
- Cumulative registered capabilities: **155**
- Coverage: base runtime, every declared optional extra, development dependencies,
  and all platform-marker alternatives represented by the universal lock.
- Package evidence links point to version-specific PyPI release pages. The reviewed
  catalog also uses package metadata, bundled notices, and upstream license files;
  special review notes remain attached to affected rows.

### Hashed development-overlay inputs

| Input | SHA-256 |
|---|---|
| `scripts/release_v04_development.toml` | `c1844797d78270b78154e5640eb3f74a89f52a1f777bba5d9ebbacf7a7d4216c` |
| `README.md` | `4d1024d8ba46b6ef8eb57e9bca4ad42639daf0d49c1ccd72658ce99ab35103f9` |
| `SECURITY.md` | `d6a5930c9e4b9b5a303f037328670e39b48c1694b0d19382907bbcc00eaf1f60` |
| `CONTRIBUTING.md` | `47cdbd6a71e73b5baf071a276b97f8db631764341a91f51307fa1b146a40e636` |
| `pyproject.toml` | `4b97a94bb4d7e62abb3b91e2ea8cce8076d4ac51c10c7d5f96b436be65f94252` |
| `uv.lock` | `46bc657e706f28318b563c70bb41da0000dabd6a97b48f60683fe254ff65515d` |
| `capabilities/manifest.yaml` | `0e51a9d84fb92fe35aa1fb4e486f5729a453dd17ffc6b3df524b5e9562ed6039` |
| `.github/workflows/ci.yml` | `bf71f27275ba1ae7c0b8bcb66f675330c1e30f57e9a27237c34662fb384732b4` |
| `deploy/systemd/fetech.service.example` | `06b944096aafcf6b6971efb9acbc8583acdd6b24f75379fb73184af8f49f2ab1` |
| `docs/architecture.md` | `c097081a43ff306074d2ae30c168d358cb121a5c45d719271c1af6e63f2d9b0f` |
| `docs/capability-catalog.md` | `781255c61d4043665012db8968f5bb141b7bb3c90c45881feb9d58138efa9639` |
| `docs/competitor-matrix.md` | `087a2b6eec7c4c39f1fd01eca1557559e8fe8154da9917f4799a5df2c1a95836` |
| `docs/deployment-containment.md` | `29542cceaa77e1439c1ce67f4bbb10753b32e7e8cb046130d9aa79cebcf242fd` |
| `docs/security-threat-model.md` | `e90f7a4d45a4b2559fb1d95fb5e519aafedff9cda3fe30cc38db00fd3beff001` |
| `docs/v0.4-conformance.md` | `6f92b7de0bebd894110c1fd26396d0e66de96f4532e5e72f06e0e15fe4e8f513` |
| `docs/releases/v0.4.0a0.md` | `68b61b13da43663271b2e6294df964ea17e8cb3814e398367115847dd48b474f` |
| `scripts/generate_release_evidence.py` | `02e72426fe567df88995c1101229c51ec7f2b795f22a707e7461e6693ee2303a` |
| `scripts/release_license_catalog.toml` | `eb2332a9f2fa9d1280f24fdfc3cb80d54f15f7ba54dc0d20ef5c3f66c29de93c` |
| `scripts/release_published.toml` | `9ec0d58866ac9fdcda7b2c21b8a5957ecf0aef8c5909390f12f7712087e35731` |
| `scripts/collect_v04_smoke_evidence.py` | `c774fa0252e324ecb65692fa0966424392842183ed551639b589a4e60d2411f6` |
| `scripts/provision_docling_artifacts.py` | `256c3b94862c7c27548cef120f1aad863536471d8b4bcfad3cc2a419bbd0bcb0` |
| `release/fetech-v0.4-docling-development-smoke.json` | `e14bc2b33fcf7c492db7582d61c5733a13530c24d210c126b1921716dfaf930d` |
| `release/fetech-v0.4-docling-wheel-smoke.json` | `b37e0b634bf09adfc6e8dc665f2ba6bf8954ae92ec94f635b0ac9ece2e1add44` |
| `src/fetech/__init__.py` | `efe1c20f61df4caf7196357d16887290cddbec371c191389e700cea3eea13b87` |
| `src/fetech/adapters/archive.py` | `79b57c11d928f21b25135d504794c34b1625e912427f3094adbd736788c590bb` |
| `src/fetech/adapters/base.py` | `23beecf1478e6af71b29a98862db3ca0d5d480f69f8e8375d929c8cf7bd772b8` |
| `src/fetech/adapters/browser.py` | `42dd3d29b2aa3a54da8f509915a2becd19b81774b481d9502996d7cfbd588d22` |
| `src/fetech/adapters/cache.py` | `04fca368b572d496af3a63128452fb0f5593700192c56f6465a49336bc1f58f1` |
| `src/fetech/adapters/documents.py` | `3dd5dc4bd831f80721a70202dfb0e6e8072e210b74af454e809c3ac494dcc239` |
| `src/fetech/adapters/http.py` | `26ccb390ae217519bedf339dcced0e3d1a7beb1993308a1c739b32557d744cf6` |
| `src/fetech/adapters/media.py` | `fdaf44b67fa59f3e84a056b9465ca75e1e6e330de705f011d14242027df2faac` |
| `src/fetech/adapters/reader.py` | `9a83ed34a71634074eddd7b5b784de6098b5ae8640bf8017f334262da4dcf6b3` |
| `src/fetech/archive_worker.py` | `b3f98277d97ac390227b274b38345476c8c1cda8ab2c19cff027b6240d222006` |
| `src/fetech/browser_reader.py` | `0cd6fda68f869c61ac66f819f0b72e1645eb0e448a3515bc1ba200d439d34b95` |
| `src/fetech/browser_render.py` | `0b8f6ea9672d809c5c43e2a60fcfda056aabaf881d00e56a824e65e6b2797296` |
| `src/fetech/client.py` | `ddf7232510b992a1320cf8c48dd23be59b3f7c1f052781e02086f1a56971264c` |
| `src/fetech/conformance.py` | `f0b3f8d063939e0cc323c05fd54cb2b9dde36ffc95dbe31d769b4824679e61fa` |
| `src/fetech/config.py` | `f9988132d0d967b6696e3ec3c88ae1ac69f8cbe609bdc27d106bdfac38429f69` |
| `src/fetech/daemon.py` | `4cc17adc9daaef5b4caafcd9c74d785a14332236cf1c7330f45659233e4589f7` |
| `src/fetech/docling_artifacts.py` | `1708370b8e7fb0f47511c2303e18e274a61fba62742e6f6c20d73833715ac278` |
| `src/fetech/document_worker.py` | `ae08b37f715d2d2a1d3d4532845c7547eb487ee8a4077f4bb9c6d665faca23a9` |
| `src/fetech/executor.py` | `77e670bc1362fba7d1df9ac9f59f08311ab214f8689e80f4769e994a524f2df1` |
| `src/fetech/gateway.py` | `6bee44ed9f5ea535d3c04afccec53ec1483aeb1f82d3b57036f4002b2e86a109` |
| `src/fetech/image_worker.py` | `393b558ecfe71e0e5aec0e9287566b11f64da4753491b02840528781efeb4163` |
| `src/fetech/logic/clingo_backend.py` | `602bb047275a3cc6ee44b1d704c3f9840dd4ad45244583b66be60c9d90ac5642` |
| `src/fetech/logic/coordinator.py` | `ee5e7fcfe5364af3c4223c18e2fbd05d7b23eac3efe1b422559b0530bf5ac48e` |
| `src/fetech/logic/process.py` | `2be39744944aa86dad7b3364cf68fbb47ddd23df5cbfb8d25a79bb771b02c3b3` |
| `src/fetech/logic/process_bootstrap.py` | `7b45a97ebcd615b792de6d1851320b8ef94987569b8330daa24ef86ed09e8b4f` |
| `src/fetech/mcp_server.py` | `b4b2a410eb49b3eba879dbbd74cd602bf1aaf61e7cc0c5e699a829cf92c1b0ed` |
| `src/fetech/models.py` | `d0ec9d1a0aa97de6507271048ebcfa536b3a2af193aa2902dabc7d19ac047101` |
| `src/fetech/planning.py` | `26a9bf4babf195056a5a04cd6c0dbeaa606eb379c0e839c6528ad3ebc72bc852` |
| `src/fetech/registry.py` | `fc3a736674b73b2838be537fd2bd3d145454885daf757bd4963aeea8cd5cf7b0` |
| `src/fetech/scheduling.py` | `f77f7c6e45939fffddfd83f8753086a32418320e06f24415a302387aa573ee1e` |
| `src/fetech/storage.py` | `77f80698d88fa9104b34af735b95ce942a1af06d563f95a651adb5c4c82df193` |
| `src/fetech/wayback.py` | `f8f475b236abd73444c56c45dbc0f2f1b282b62180ae2a5d632eed88f2f12650` |
| `src/fetech/worker_isolation.py` | `2f95ac2b70e2d36d0d2a77cdf6ffe4378fd0da29f076af3b13e7ae18ce2aa65a` |
| `src/fetech/worker_isolation_bootstrap.py` | `7317aa1dc4edff4e61df5acdfa72134b1661c6a5f8944ae76544bfb148a2868c` |
| `src/fetech/worker_audit.py` | `e0cdf47daae5f1291462450aa5c66d96719f7fac161104a1ec50d413473e14ae` |
| `src/fetech/yt_dlp.py` | `3e452221b0a5428dd68b46d7e80254ffad0ea3795b8abfd509c788836f467de9` |
| `src/fetech/yt_dlp_worker.py` | `0c0defe1fcdd76dd525bc3346d10289548801c3e5e13ae57bdd46b357911352f` |
| `tests/test_docling_artifacts.py` | `0afa8f95feaab5372231c70125fb136e63a5666425b44e2973fe425d54896983` |
| `tests/test_http_adapter.py` | `776a640dd37a9980b4636d9842c4db05054a77c7bc46f3f96eea2a9876425005` |
| `tests/test_logic_backends.py` | `9140c1c49e7ba6577e8e79fdf6f1b5180c0e8ae28e4fc78b8a2c381612c6901c` |
| `tests/test_network_scheduling.py` | `4fb30a591f98a64432be57551d7de86693777d0fa1af66f2ca16eb7c758f71c7` |
| `tests/test_release_evidence.py` | `463c4f2687e2a2120cb3c28e6a69b2348a84383de50157de87c924cc8148012f` |
| `tests/test_storage_cas.py` | `f11e443948cddace9df0c9efa834f7e8d0837c65a48472ab1ef0075e6da76381` |
| `tests/test_v01_conformance.py` | `e46f7f357d291c109ea6678d3e794e70bee8f4a5e1d095ddb2239f12a675dd05` |
| `tests/test_v02_browser.py` | `b43a868f9cd608d1d73d2116c3453e80c69fbeddccd0a2fc40a9552dbeaa2b59` |
| `tests/test_v02_conformance.py` | `564606b8dbf1d62333a0d0f87660f379063869ac9161718e46f4102705b8e101` |
| `tests/test_v03_auth.py` | `7a13cb5f117f81fa28d17cee68baef90958d5666c080a36bc777cda5041c463e` |
| `tests/test_v03_integration.py` | `683df884a402ccaae797c8f8cf5700eabf6dc2120598728d185366f79cd2922f` |
| `tests/test_v03_interfaces.py` | `b3d863ac00dacda5f7db25580bc2d24503af73bc67b3db1afc0acd4312cbb3a7` |
| `tests/test_v04_budget_accounting.py` | `463e909d34128404d58d7f6a572d01ffb09a77ea184b4a0ae3c29c24196aff62` |
| `tests/test_v04_cache_archives.py` | `a60e3e9d35dafc05f5a3191ba7f85f3772db58e29a8ea0a8ae544934b70853e0` |
| `tests/test_v04_cache_expiry_provenance.py` | `96be3e7afbad9ee44c6c224f3d4050996fe090f1621ac390f76f4a84478b93d4` |
| `tests/test_v04_capability_matrix.py` | `470d584a635f658e3d4476bfa43eeaedf4d750a8dfed73f4d3e6cf75a68ab656` |
| `tests/test_v04_docling.py` | `248da3752ce6102f6bac4bc8def4c240f1d737c631c0d6970516b5f6a8c5253b` |
| `tests/test_v04_document_providers_integration.py` | `9f24fc5bd3b7564fff2e8a5794651028e47cea4dd171098288098e8c0c9d58e0` |
| `tests/test_v04_documents.py` | `a2997bb19a7513d28977d0d120dbd52ca0b6167be96a74b90de9c2b5fed53f58` |
| `tests/test_v04_integration.py` | `cec0ee9aabbd24cce89df7af2b8245220d4404f1401822a61dee133926778e8e` |
| `tests/test_v04_interfaces.py` | `9a1cb4a78285a5357f066be87d71c58121fe359f4816ce27b9a4b7ec1c15a1dc` |
| `tests/test_v04_media.py` | `73526a75954eedf574c2cb9f861721b61f6f8d1c850cf8fad3dcc1f4bff89d0c` |
| `tests/test_v04_planning.py` | `f42935c8bfd85760a53af067b938de52edd06b942ced22577d8268937d9240c2` |
| `tests/test_v04_smoke_evidence.py` | `8487f56159ddd1f266ef61928fd668b8f9254e36e598d51560368a2707479de1` |
| `tests/test_v04_ytdlp.py` | `70ae4e2d2228794882becd0063dfa9a644c6fe10d0b75584c9bdf2adfd57bcef` |
| `tests/test_wayback.py` | `dbedb5aaf13aacb294c7066563c041c9a7e3a5d077ec90a90ebbd4dae459ff83` |
| `tests/test_worker_audit.py` | `3544ff10e69ecea8533ac50338148c82fa84950d5894a9f74f0cb5d041629de0` |
| `tests/test_worker_isolation.py` | `3367dd22647767d16eea47e1e2eb9a6a001d9ab303c5e9180155b96945710121` |
| `tests/test_worker_isolation_linux.py` | `7d5f9ba5a3a9bc1aeb21c41160fb130a1ed9854086ecac2004fb65202be2270e` |

## Automated policy observations

- Missing or `NOASSERTION` declared licenses: **0**
- Declared AGPL expressions: **0**
- Ambiguous `LicenseRef` declarations: **17**
- Disjunctive GPL/LGPL choice expressions: **1**
- AGPL policy check: **pass** — no locked package declares AGPL.
- License-choice review: `tld==0.13.2`. Preserve the selected upstream license and notices when redistributing.
- Exact-license review: `cuda-bindings==13.3.1`, `cuda-toolkit==13.0.3.0`, `nvidia-cublas==13.1.1.3`, `nvidia-cuda-cupti==13.0.85`, `nvidia-cuda-nvrtc==13.0.88`, `nvidia-cuda-runtime==13.0.96`, `nvidia-cudnn-cu13==9.20.0.48`, `nvidia-cufft==12.0.0.61`, `nvidia-cufile==1.15.1.6`, `nvidia-curand==10.4.0.35`, `nvidia-cusolver==12.0.4.66`, `nvidia-cusparse==12.6.3.3`, `nvidia-cusparselt-cu13==0.8.1`, `nvidia-nvjitlink==13.3.33`, `nvidia-nvshmem-cu13==3.4.5`, `pypdfium2==5.12.1`, `sgmllib3k==1.0.0`. The package metadata does not identify a precise SPDX license.

## Separately installed tools and configured boundaries

These executables, downloaded artifacts, and provider boundaries are not Python
packages distributed in the current `0.3.0a0` wheel, so they are excluded from
the lock-derived SPDX package inventory. Their rows are development inputs, not
proof that a particular executable build, browser download, service, or connector
was installed or exercised. A distribution that bundles one must record its exact
version, build options, licenses, notices, and transitive libraries.

| Component | Development-overlay status | License observation | Required review | Primary source |
|---|---|---|---|---|
| SWI-Prolog | Optional logic executable installed separately and not shipped by Fetech. | `BSD-2-Clause` for the core. | The selected build may link GMP or load add-ons with additional terms. Inspect it with the `license.` predicate. | [Upstream](https://www.swi-prolog.org/license.html) |
| curl | Optional HTTP/3 executable installed separately and not shipped by Fetech. | SPDX `curl`. | Record the selected build, linked libraries, license texts, and notices before redistributing a system image. | [Upstream](https://curl.se/docs/copyright.html) |
| Playwright browser binaries | Downloaded separately by the Playwright CLI and not contained in the Python wheel. | Varies by browser and build. | Record each selected browser build and preserve its bundled licenses and notices. | [Upstream](https://playwright.dev/python/docs/browsers) |
| Tesseract OCR | Optional OCR executable discovered at runtime and not shipped by Fetech. | Apache-2.0 for the upstream engine. | Record the exact executable, trained-data packages, linked libraries, licenses, and notices used by a distribution. | [Upstream](https://github.com/tesseract-ocr/tesseract/blob/main/LICENSE) |
| FFmpeg and FFprobe | Optional media executables discovered at runtime and not shipped by Fetech. | `LGPL-2.1-or-later` baseline. | GPL-covered build options can change the complete build license. Record configure flags and linked libraries. | [Upstream](https://ffmpeg.org/legal.html) |
| Docling Layout Heron model artifacts | Operator-provisioned local artifact bundle for the preferred offline Docling path; not contained in the Python wheel or universal lock. | Reference bundle e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76 records docling-project/docling-layout-heron@8f39ad3c0b4c58e9c2d2c84a38465abf757272d8 with published Apache-2.0 metadata. | The canonical content manifest and smoke evidence provide technical provenance, not legal approval. Review the bundled model card, license text, notices, and redistribution terms before release or image publication. | [Upstream](https://huggingface.co/docling-project/docling-layout-heron/tree/8f39ad3c0b4c58e9c2d2c84a38465abf757272d8) |

## Scope counts

| Scope | Packages |
|---|---:|
| `runtime` | 27 |
| `extra:all` | 142 |
| `extra:browser` | 20 |
| `extra:dev` | 27 |
| `extra:documents` | 100 |
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
| `Apache-2.0` | 25 |
| `Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND BSD-2-Clause AND BSD-3-Clause AND BSL-1.0 AND MIT` | 1 |
| `Apache-2.0 AND BSD-3-Clause` | 1 |
| `Apache-2.0 AND CNRI-Python` | 1 |
| `Apache-2.0 OR BSD-2-Clause` | 1 |
| `Apache-2.0 OR BSD-3-Clause` | 2 |
| `BSD-2-Clause` | 4 |
| `BSD-3-Clause` | 27 |
| `BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0` | 1 |
| `BSD-3-Clause AND BSD-3-Clause-Open-MPI AND (GPL-3.0-or-later WITH GCC-exception-3.1) AND LGPL-2.1-or-later` | 1 |
| `BSD-3-Clause AND MIT` | 1 |
| `ISC` | 1 |
| `LicenseRef-BSD-Unknown` | 1 |
| `LicenseRef-NVIDIA-CUDA-13.0-EULA` | 2 |
| `LicenseRef-NVIDIA-CUDA-13.3-EULA` | 1 |
| `LicenseRef-NVIDIA-CUDNN-SLA` | 1 |
| `LicenseRef-NVIDIA-NVSHMEM-SDK` | 1 |
| `LicenseRef-NVIDIA-SOFTWARE-LICENSE` | 1 |
| `LicenseRef-nvidia-cublas-13.1.1.3-Proprietary` | 1 |
| `LicenseRef-nvidia-cuda-cupti-13.0.85-Proprietary` | 1 |
| `LicenseRef-nvidia-cuda-nvrtc-13.0.88-Proprietary` | 1 |
| `LicenseRef-nvidia-cufft-12.0.0.61-Proprietary` | 1 |
| `LicenseRef-nvidia-cufile-1.15.1.6-Proprietary` | 1 |
| `LicenseRef-nvidia-curand-10.4.0.35-Proprietary` | 1 |
| `LicenseRef-nvidia-cusolver-12.0.4.66-Proprietary` | 1 |
| `LicenseRef-nvidia-cusparse-12.6.3.3-Proprietary` | 1 |
| `LicenseRef-nvidia-cusparselt-cu13-0.8.1-Proprietary` | 1 |
| `LicenseRef-pypdfium2-5.12.1-Mixed` | 1 |
| `MIT` | 68 |
| `MIT AND PSF-2.0` | 1 |
| `MIT OR Apache-2.0` | 3 |
| `MIT-0` | 1 |
| `MIT-CMU` | 1 |
| `MPL-1.1 OR GPL-2.0-only OR LGPL-2.1-or-later` | 1 |
| `MPL-2.0` | 2 |
| `MPL-2.0 AND MIT` | 1 |
| `PSF-2.0` | 4 |
| `Unlicense` | 1 |

## Dependency inventory

| Package | Version | Scope(s) | Declared license | Evidence |
|---|---|---|---|---|
| `accelerate` | `1.14.0` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/accelerate/1.14.0/) |
| `aiosqlite` | `0.22.1` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/aiosqlite/0.22.1/) |
| `annotated-doc` | `0.0.4` | `runtime`, `extra:all`, `extra:documents`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/annotated-doc/0.0.4/) |
| `annotated-types` | `0.7.0` | `runtime`, `extra:all`, `extra:documents`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/annotated-types/0.7.0/) |
| `anyio` | `4.14.2` | `runtime`, `extra:all`, `extra:documents`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/anyio/4.14.2/) |
| `ast-serialize` | `0.6.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/ast-serialize/0.6.0/) |
| `attrs` | `26.1.0` | `extra:all`, `extra:browser`, `extra:documents`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/attrs/26.1.0/) |
| `babel` | `2.18.0` | `extra:all`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/babel/2.18.0/) |
| `beautifulsoup4` | `4.15.0` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/beautifulsoup4/4.15.0/) |
| `certifi` | `2026.6.17` | `runtime`, `extra:all`, `extra:browser`, `extra:documents`, `extra:mcp`, `extra:web` | `MPL-2.0` | [PyPI release](https://pypi.org/project/certifi/2026.6.17/) |
| `cffi` | `2.1.0` | `extra:all`, `extra:browser`, `extra:logic`, `extra:mcp` | `MIT-0` | [PyPI release](https://pypi.org/project/cffi/2.1.0/) |
| `cfgv` | `3.5.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/cfgv/3.5.0/) |
| `chardet` | `7.4.3` | `extra:all`, `extra:web` | `0BSD` | [PyPI release](https://pypi.org/project/chardet/7.4.3/) |
| `charset-normalizer` | `3.4.9` | `extra:all`, `extra:documents`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/charset-normalizer/3.4.9/) |
| `click` | `8.4.2` | `runtime`, `extra:all`, `extra:documents`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/click/8.4.2/) |
| `clingo` | `5.8.0` | `extra:all`, `extra:logic` | `MIT` | [PyPI release](https://pypi.org/project/clingo/5.8.0/) |
| `colorama` | `0.4.6` | `runtime`, `extra:all`, `extra:dev`, `extra:documents`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/colorama/0.4.6/) |
| `courlan` | `1.4.0` | `extra:all`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/courlan/1.4.0/) |
| `coverage` | `7.15.2` | `extra:dev` | `Apache-2.0` | [PyPI release](https://pypi.org/project/coverage/7.15.2/) |
| `cryptography` | `49.0.0` | `extra:all`, `extra:mcp` | `Apache-2.0 OR BSD-3-Clause` | [PyPI release](https://pypi.org/project/cryptography/49.0.0/) |
| `cssselect` | `1.4.0` | `extra:all`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/cssselect/1.4.0/) |
| `cuda-bindings` | `13.3.1` | `extra:all`, `extra:documents` | `LicenseRef-NVIDIA-SOFTWARE-LICENSE` | [PyPI release](https://pypi.org/project/cuda-bindings/13.3.1/)<br>Review: Exact PyPI metadata declares NVIDIA proprietary software terms; redistribution requires review of the bundled governing agreement. |
| `cuda-pathfinder` | `1.5.6` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/cuda-pathfinder/1.5.6/) |
| `cuda-toolkit` | `13.0.3.0` | `extra:all`, `extra:documents` | `LicenseRef-NVIDIA-CUDA-13.0-EULA` | [PyPI release](https://pypi.org/project/cuda-toolkit/13.0.3.0/)<br>Review: The exact wheel is a metadata-only CUDA Toolkit metapackage with blank license fields; NVIDIA's CUDA 13.0 documentation states that the CUDA Toolkit EULA governs the toolkit. |
| `dateparser` | `1.4.1` | `extra:all`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/dateparser/1.4.1/) |
| `defusedxml` | `0.7.1` | `extra:all`, `extra:documents` | `PSF-2.0` | [PyPI release](https://pypi.org/project/defusedxml/0.7.1/) |
| `distlib` | `0.4.3` | `extra:dev` | `PSF-2.0` | [PyPI release](https://pypi.org/project/distlib/0.4.3/) |
| `doclang` | `0.7.3` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/doclang/0.7.3/) |
| `docling-core` | `2.87.1` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/docling-core/2.87.1/) |
| `docling-ibm-models` | `3.13.3` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/docling-ibm-models/3.13.3/) |
| `docling-parse` | `7.8.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/docling-parse/7.8.0/) |
| `docling-slim` | `2.113.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/docling-slim/2.113.0/) |
| `et-xmlfile` | `2.0.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/et-xmlfile/2.0.0/) |
| `fastapi` | `0.139.1` | `extra:all`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/fastapi/0.139.1/) |
| `feedparser` | `6.0.12` | `extra:all`, `extra:web` | `BSD-2-Clause` | [PyPI release](https://pypi.org/project/feedparser/6.0.12/) |
| `filelock` | `3.30.0` | `extra:all`, `extra:dev`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/filelock/3.30.0/) |
| `filetype` | `1.2.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/filetype/1.2.0/) |
| `fsspec` | `2026.6.0` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/fsspec/2026.6.0/) |
| `greenlet` | `3.5.3` | `runtime`, `extra:all`, `extra:browser` | `MIT AND PSF-2.0` | [PyPI release](https://pypi.org/project/greenlet/3.5.3/) |
| `h11` | `0.16.0` | `runtime`, `extra:all`, `extra:browser`, `extra:documents`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/h11/0.16.0/) |
| `h2` | `4.3.0` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/h2/4.3.0/) |
| `hf-xet` | `1.5.2` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/hf-xet/1.5.2/) |
| `hpack` | `4.2.0` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/hpack/4.2.0/) |
| `htmldate` | `1.10.0` | `extra:all`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/htmldate/1.10.0/) |
| `httpcore` | `1.0.9` | `runtime`, `extra:all`, `extra:documents`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/httpcore/1.0.9/) |
| `httpx` | `0.28.1` | `runtime`, `extra:all`, `extra:documents`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/httpx/0.28.1/) |
| `httpx-sse` | `0.4.3` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/httpx-sse/0.4.3/) |
| `huggingface-hub` | `1.24.0` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/huggingface-hub/1.24.0/) |
| `hyperframe` | `6.1.0` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/hyperframe/6.1.0/) |
| `identify` | `2.6.19` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/identify/2.6.19/) |
| `idna` | `3.18` | `runtime`, `extra:all`, `extra:browser`, `extra:documents`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/idna/3.18/) |
| `iniconfig` | `2.3.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/iniconfig/2.3.0/) |
| `jinja2` | `3.1.6` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/jinja2/3.1.6/) |
| `jsonlines` | `4.0.0` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/jsonlines/4.0.0/) |
| `jsonref` | `1.1.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/jsonref/1.1.0/) |
| `jsonschema` | `4.26.0` | `extra:all`, `extra:documents`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/jsonschema/4.26.0/) |
| `jsonschema-specifications` | `2025.9.1` | `extra:all`, `extra:documents`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/jsonschema-specifications/2025.9.1/) |
| `justext` | `3.0.2` | `extra:all`, `extra:web` | `BSD-2-Clause` | [PyPI release](https://pypi.org/project/justext/3.0.2/) |
| `latex2mathml` | `3.81.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/latex2mathml/3.81.0/) |
| `librt` | `0.13.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/librt/0.13.0/) |
| `lxml` | `6.1.1` | `extra:all`, `extra:documents`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/lxml/6.1.1/) |
| `lxml-html-clean` | `0.4.5` | `extra:all`, `extra:web` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/lxml-html-clean/0.4.5/) |
| `markdown-it-py` | `4.2.0` | `runtime`, `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/markdown-it-py/4.2.0/) |
| `markupsafe` | `3.0.3` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/markupsafe/3.0.3/) |
| `mcp` | `1.28.1` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/mcp/1.28.1/) |
| `mdurl` | `0.1.2` | `runtime`, `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/mdurl/0.1.2/) |
| `mpmath` | `1.3.0` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/mpmath/1.3.0/) |
| `mypy` | `2.3.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/mypy/2.3.0/) |
| `mypy-extensions` | `1.1.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/mypy-extensions/1.1.0/) |
| `networkx` | `3.6.1` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/networkx/3.6.1/) |
| `nodeenv` | `1.10.0` | `extra:dev` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/nodeenv/1.10.0/) |
| `numpy` | `2.5.1` | `extra:all`, `extra:documents` | `BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0` | [PyPI release](https://pypi.org/project/numpy/2.5.1/) |
| `nvidia-cublas` | `13.1.1.3` | `extra:all`, `extra:documents` | `LicenseRef-nvidia-cublas-13.1.1.3-Proprietary` | [PyPI release](https://pypi.org/project/nvidia-cublas/13.1.1.3/)<br>Review: Exact PyPI metadata declares LicenseRef-NVIDIA-Proprietary; review the bundled NVIDIA terms before redistribution. |
| `nvidia-cuda-cupti` | `13.0.85` | `extra:all`, `extra:documents` | `LicenseRef-nvidia-cuda-cupti-13.0.85-Proprietary` | [PyPI release](https://pypi.org/project/nvidia-cuda-cupti/13.0.85/)<br>Review: Exact PyPI metadata declares LicenseRef-NVIDIA-Proprietary; review the bundled NVIDIA terms before redistribution. |
| `nvidia-cuda-nvrtc` | `13.0.88` | `extra:all`, `extra:documents` | `LicenseRef-nvidia-cuda-nvrtc-13.0.88-Proprietary` | [PyPI release](https://pypi.org/project/nvidia-cuda-nvrtc/13.0.88/)<br>Review: Exact PyPI metadata declares LicenseRef-NVIDIA-Proprietary; review the bundled NVIDIA terms before redistribution. |
| `nvidia-cuda-runtime` | `13.0.96` | `extra:all`, `extra:documents` | `LicenseRef-NVIDIA-CUDA-13.0-EULA` | [PyPI release](https://pypi.org/project/nvidia-cuda-runtime/13.0.96/)<br>Review: Exact PyPI metadata has blank license fields; the package is the CUDA 13.0 runtime and is recorded against the governing CUDA Toolkit EULA pending artifact-level legal review. |
| `nvidia-cudnn-cu13` | `9.20.0.48` | `extra:all`, `extra:documents` | `LicenseRef-NVIDIA-CUDNN-SLA` | [PyPI release](https://pypi.org/project/nvidia-cudnn-cu13/9.20.0.48/)<br>Review: Exact PyPI metadata has blank license fields; NVIDIA's versioned cuDNN documentation identifies the cuDNN software license agreement as governing. |
| `nvidia-cufft` | `12.0.0.61` | `extra:all`, `extra:documents` | `LicenseRef-nvidia-cufft-12.0.0.61-Proprietary` | [PyPI release](https://pypi.org/project/nvidia-cufft/12.0.0.61/)<br>Review: Exact PyPI metadata declares LicenseRef-NVIDIA-Proprietary; review the bundled NVIDIA terms before redistribution. |
| `nvidia-cufile` | `1.15.1.6` | `extra:all`, `extra:documents` | `LicenseRef-nvidia-cufile-1.15.1.6-Proprietary` | [PyPI release](https://pypi.org/project/nvidia-cufile/1.15.1.6/)<br>Review: Exact PyPI metadata declares LicenseRef-NVIDIA-Proprietary; review the bundled NVIDIA terms before redistribution. |
| `nvidia-curand` | `10.4.0.35` | `extra:all`, `extra:documents` | `LicenseRef-nvidia-curand-10.4.0.35-Proprietary` | [PyPI release](https://pypi.org/project/nvidia-curand/10.4.0.35/)<br>Review: Exact PyPI metadata declares LicenseRef-NVIDIA-Proprietary; review the bundled NVIDIA terms before redistribution. |
| `nvidia-cusolver` | `12.0.4.66` | `extra:all`, `extra:documents` | `LicenseRef-nvidia-cusolver-12.0.4.66-Proprietary` | [PyPI release](https://pypi.org/project/nvidia-cusolver/12.0.4.66/)<br>Review: Exact PyPI metadata declares LicenseRef-NVIDIA-Proprietary; review the bundled NVIDIA terms before redistribution. |
| `nvidia-cusparse` | `12.6.3.3` | `extra:all`, `extra:documents` | `LicenseRef-nvidia-cusparse-12.6.3.3-Proprietary` | [PyPI release](https://pypi.org/project/nvidia-cusparse/12.6.3.3/)<br>Review: Exact PyPI metadata declares LicenseRef-NVIDIA-Proprietary; review the bundled NVIDIA terms before redistribution. |
| `nvidia-cusparselt-cu13` | `0.8.1` | `extra:all`, `extra:documents` | `LicenseRef-nvidia-cusparselt-cu13-0.8.1-Proprietary` | [PyPI release](https://pypi.org/project/nvidia-cusparselt-cu13/0.8.1/)<br>Review: Exact PyPI metadata declares NVIDIA Proprietary Software; review the bundled NVIDIA terms before redistribution. |
| `nvidia-nccl-cu13` | `2.29.7` | `extra:all`, `extra:documents` | `Apache-2.0 AND BSD-3-Clause` | [PyPI release](https://pypi.org/project/nvidia-nccl-cu13/2.29.7/) |
| `nvidia-nvjitlink` | `13.3.33` | `extra:all`, `extra:documents` | `LicenseRef-NVIDIA-CUDA-13.3-EULA` | [PyPI release](https://pypi.org/project/nvidia-nvjitlink/13.3.33/)<br>Review: Exact PyPI metadata has blank license fields; NVIDIA's CUDA 13.3 documentation identifies this component and the CUDA Toolkit EULA as governing. |
| `nvidia-nvshmem-cu13` | `3.4.5` | `extra:all`, `extra:documents` | `LicenseRef-NVIDIA-NVSHMEM-SDK` | [PyPI release](https://pypi.org/project/nvidia-nvshmem-cu13/3.4.5/)<br>Review: The exact v3.4.5-0 source tag uses custom NVIDIA NVSHMEM SDK terms and includes additional component notices; do not apply the later Apache-2.0 default-branch label retroactively. |
| `nvidia-nvtx` | `13.0.85` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/nvidia-nvtx/13.0.85/) |
| `openpyxl` | `3.1.5` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/openpyxl/3.1.5/) |
| `outcome` | `1.3.0.post0` | `extra:all`, `extra:browser` | `MIT OR Apache-2.0` | [PyPI release](https://pypi.org/project/outcome/1.3.0.post0/) |
| `packaging` | `26.2` | `extra:all`, `extra:dev`, `extra:documents` | `Apache-2.0 OR BSD-2-Clause` | [PyPI release](https://pypi.org/project/packaging/26.2/) |
| `pandas` | `3.0.3` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/pandas/3.0.3/) |
| `pathspec` | `1.1.1` | `extra:dev` | `MPL-2.0` | [PyPI release](https://pypi.org/project/pathspec/1.1.1/) |
| `pillow` | `12.3.0` | `extra:all`, `extra:documents`, `extra:media` | `MIT-CMU` | [PyPI release](https://pypi.org/project/pillow/12.3.0/) |
| `platformdirs` | `4.10.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/platformdirs/4.10.0/) |
| `playwright` | `1.61.0` | `extra:all`, `extra:browser` | `Apache-2.0` | [PyPI release](https://pypi.org/project/playwright/1.61.0/) |
| `pluggy` | `1.6.0` | `extra:all`, `extra:dev`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/pluggy/1.6.0/) |
| `pre-commit` | `4.6.0` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/pre-commit/4.6.0/) |
| `psutil` | `7.2.2` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/psutil/7.2.2/) |
| `pycparser` | `3.0` | `extra:all`, `extra:browser`, `extra:logic`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/pycparser/3.0/) |
| `pydantic` | `2.13.4` | `runtime`, `extra:all`, `extra:documents`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/pydantic/2.13.4/) |
| `pydantic-core` | `2.46.4` | `runtime`, `extra:all`, `extra:documents`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/pydantic-core/2.46.4/) |
| `pydantic-settings` | `2.14.2` | `extra:all`, `extra:documents`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/pydantic-settings/2.14.2/) |
| `pyee` | `13.0.1` | `extra:all`, `extra:browser` | `MIT` | [PyPI release](https://pypi.org/project/pyee/13.0.1/) |
| `pygments` | `2.20.0` | `runtime`, `extra:all`, `extra:dev`, `extra:documents` | `BSD-2-Clause` | [PyPI release](https://pypi.org/project/pygments/2.20.0/) |
| `pyjwt` | `2.13.0` | `extra:all`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/pyjwt/2.13.0/) |
| `pypdf` | `6.14.2` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/pypdf/6.14.2/) |
| `pypdfium2` | `5.12.1` | `extra:all`, `extra:documents` | `LicenseRef-pypdfium2-5.12.1-Mixed` | [PyPI release](https://pypi.org/project/pypdfium2/5.12.1/)<br>Review: Exact metadata declares BSD-3-Clause, Apache-2.0, and dependency licenses; the bundled PDFium binary has build-specific notices that require artifact review. |
| `pysocks` | `1.7.1` | `extra:all`, `extra:browser` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/pysocks/1.7.1/) |
| `pytest` | `9.1.1` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/pytest/9.1.1/) |
| `pytest-asyncio` | `1.4.0` | `extra:dev` | `Apache-2.0` | [PyPI release](https://pypi.org/project/pytest-asyncio/1.4.0/) |
| `python-dateutil` | `2.9.0.post0` | `extra:all`, `extra:documents`, `extra:web` | `Apache-2.0 OR BSD-3-Clause` | [PyPI release](https://pypi.org/project/python-dateutil/2.9.0.post0/) |
| `python-discovery` | `1.4.4` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/python-discovery/1.4.4/) |
| `python-docx` | `1.2.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/python-docx/1.2.0/) |
| `python-dotenv` | `1.2.2` | `extra:all`, `extra:documents`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/python-dotenv/1.2.2/) |
| `python-multipart` | `0.0.32` | `extra:all`, `extra:mcp` | `Apache-2.0` | [PyPI release](https://pypi.org/project/python-multipart/0.0.32/) |
| `python-pptx` | `1.0.2` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/python-pptx/1.0.2/) |
| `pytz` | `2026.2` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/pytz/2026.2/) |
| `pywin32` | `312` | `extra:all`, `extra:documents`, `extra:mcp` | `PSF-2.0` | [PyPI release](https://pypi.org/project/pywin32/312/)<br>Review: Upstream states that files use a mixture of licenses; PSF-2.0 is package metadata, and bundled notices remain authoritative. |
| `pyyaml` | `6.0.3` | `runtime`, `extra:all`, `extra:dev`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/pyyaml/6.0.3/) |
| `readability-lxml` | `0.8.4.1` | `extra:all`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/readability-lxml/0.8.4.1/) |
| `referencing` | `0.37.0` | `extra:all`, `extra:documents`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/referencing/0.37.0/) |
| `regex` | `2026.7.10` | `extra:all`, `extra:documents`, `extra:web` | `Apache-2.0 AND CNRI-Python` | [PyPI release](https://pypi.org/project/regex/2026.7.10/) |
| `requests` | `2.34.2` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/requests/2.34.2/) |
| `rich` | `15.0.0` | `runtime`, `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/rich/15.0.0/) |
| `rpds-py` | `2026.6.3` | `extra:all`, `extra:documents`, `extra:mcp` | `MIT` | [PyPI release](https://pypi.org/project/rpds-py/2026.6.3/) |
| `rtree` | `1.4.1` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/rtree/1.4.1/) |
| `ruff` | `0.15.21` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/ruff/0.15.21/) |
| `safetensors` | `0.8.0` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/safetensors/0.8.0/) |
| `scipy` | `1.18.0` | `extra:all`, `extra:documents` | `BSD-3-Clause AND BSD-3-Clause-Open-MPI AND (GPL-3.0-or-later WITH GCC-exception-3.1) AND LGPL-2.1-or-later` | [PyPI release](https://pypi.org/project/scipy/1.18.0/) |
| `selenium` | `4.46.0` | `extra:all`, `extra:browser` | `Apache-2.0` | [PyPI release](https://pypi.org/project/selenium/4.46.0/) |
| `setuptools` | `83.0.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/setuptools/83.0.0/) |
| `sgmllib3k` | `1.0.0` | `extra:all`, `extra:web` | `LicenseRef-BSD-Unknown` | [PyPI release](https://pypi.org/project/sgmllib3k/1.0.0/)<br>Review: PyPI declares only BSD License without identifying the exact BSD variant; resolve the variant before redistribution. |
| `shellingham` | `1.5.4` | `runtime`, `extra:all`, `extra:documents` | `ISC` | [PyPI release](https://pypi.org/project/shellingham/1.5.4/) |
| `six` | `1.17.0` | `extra:all`, `extra:documents`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/six/1.17.0/) |
| `sniffio` | `1.3.1` | `extra:all`, `extra:browser` | `MIT OR Apache-2.0` | [PyPI release](https://pypi.org/project/sniffio/1.3.1/) |
| `sortedcontainers` | `2.4.0` | `extra:all`, `extra:browser` | `Apache-2.0` | [PyPI release](https://pypi.org/project/sortedcontainers/2.4.0/) |
| `soupsieve` | `2.8.4` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/soupsieve/2.8.4/) |
| `sqlalchemy` | `2.0.51` | `runtime` | `MIT` | [PyPI release](https://pypi.org/project/sqlalchemy/2.0.51/) |
| `sse-starlette` | `3.4.5` | `extra:all`, `extra:mcp` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/sse-starlette/3.4.5/) |
| `starlette` | `1.3.1` | `extra:all`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/starlette/1.3.1/) |
| `sympy` | `1.14.0` | `extra:all`, `extra:documents` | `BSD-3-Clause AND MIT` | [PyPI release](https://pypi.org/project/sympy/1.14.0/)<br>Review: The exact tag is primarily BSD-3-Clause and also identifies MIT-licensed latex2sympy-derived files. |
| `tabulate` | `0.10.0` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/tabulate/0.10.0/) |
| `tld` | `0.13.2` | `extra:all`, `extra:web` | `MPL-1.1 OR GPL-2.0-only OR LGPL-2.1-or-later` | [PyPI release](https://pypi.org/project/tld/0.13.2/)<br>Review: The upstream declaration is a disjunctive choice that includes GPL and LGPL alternatives; preserve the chosen license and notices when redistributing. |
| `tokenizers` | `0.22.2` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/tokenizers/0.22.2/) |
| `torch` | `2.13.0` | `extra:all`, `extra:documents` | `Apache-2.0 AND Apache-2.0 WITH LLVM-exception AND BSD-2-Clause AND BSD-3-Clause AND BSL-1.0 AND MIT` | [PyPI release](https://pypi.org/project/torch/2.13.0/) |
| `torchvision` | `0.28.0` | `extra:all`, `extra:documents` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/torchvision/0.28.0/) |
| `tqdm` | `4.69.0` | `extra:all`, `extra:documents` | `MPL-2.0 AND MIT` | [PyPI release](https://pypi.org/project/tqdm/4.69.0/) |
| `trafilatura` | `2.1.0` | `extra:all`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/trafilatura/2.1.0/) |
| `transformers` | `5.14.1` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/transformers/5.14.1/) |
| `transformers` | `5.8.1` | `extra:all`, `extra:documents` | `Apache-2.0` | [PyPI release](https://pypi.org/project/transformers/5.8.1/) |
| `trio` | `0.33.0` | `extra:all`, `extra:browser` | `MIT OR Apache-2.0` | [PyPI release](https://pypi.org/project/trio/0.33.0/) |
| `trio-websocket` | `0.12.2` | `extra:all`, `extra:browser` | `MIT` | [PyPI release](https://pypi.org/project/trio-websocket/0.12.2/) |
| `triton` | `3.7.1` | `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/triton/3.7.1/) |
| `typer` | `0.24.2` | `runtime`, `extra:all`, `extra:documents` | `MIT` | [PyPI release](https://pypi.org/project/typer/0.24.2/) |
| `types-openpyxl` | `3.1.5.20260518` | `extra:dev` | `Apache-2.0` | [PyPI release](https://pypi.org/project/types-openpyxl/3.1.5.20260518/) |
| `types-pyyaml` | `6.0.12.20260518` | `extra:dev` | `Apache-2.0` | [PyPI release](https://pypi.org/project/types-pyyaml/6.0.12.20260518/) |
| `typing-extensions` | `4.16.0` | `runtime`, `extra:all`, `extra:browser`, `extra:dev`, `extra:documents`, `extra:mcp`, `extra:server`, `extra:web` | `PSF-2.0` | [PyPI release](https://pypi.org/project/typing-extensions/4.16.0/) |
| `typing-inspection` | `0.4.2` | `runtime`, `extra:all`, `extra:documents`, `extra:mcp`, `extra:server` | `MIT` | [PyPI release](https://pypi.org/project/typing-inspection/0.4.2/) |
| `tzdata` | `2026.3` | `extra:all`, `extra:documents`, `extra:web` | `Apache-2.0` | [PyPI release](https://pypi.org/project/tzdata/2026.3/) |
| `tzlocal` | `5.4.4` | `extra:all`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/tzlocal/5.4.4/) |
| `urllib3` | `2.7.0` | `extra:all`, `extra:browser`, `extra:documents`, `extra:web` | `MIT` | [PyPI release](https://pypi.org/project/urllib3/2.7.0/) |
| `uvicorn` | `0.51.0` | `extra:all`, `extra:mcp`, `extra:server` | `BSD-3-Clause` | [PyPI release](https://pypi.org/project/uvicorn/0.51.0/) |
| `virtualenv` | `21.6.1` | `extra:dev` | `MIT` | [PyPI release](https://pypi.org/project/virtualenv/21.6.1/) |
| `websocket-client` | `1.9.0` | `extra:all`, `extra:browser` | `Apache-2.0` | [PyPI release](https://pypi.org/project/websocket-client/1.9.0/) |
| `wsproto` | `1.3.2` | `extra:all`, `extra:browser` | `MIT` | [PyPI release](https://pypi.org/project/wsproto/1.3.2/) |
| `xlsxwriter` | `3.2.9` | `extra:all`, `extra:documents` | `BSD-2-Clause` | [PyPI release](https://pypi.org/project/xlsxwriter/3.2.9/) |
| `yt-dlp` | `2026.7.4` | `extra:all`, `extra:media` | `Unlicense` | [PyPI release](https://pypi.org/project/yt-dlp/2026.7.4/) |

## Publication gaps

- Package metadata remains `0.3.0a0`; draft v0.4 notes exist, but finalized notes, checksums, tag, wheel, and source distribution do not.
- Focused installed Docling 2.113 source-tree and development-wheel contract/content subsets pass against the exact reference bundle; the final clean tagged v0.4 wheel still needs the complete retained artifact-bound smoke evidence from the release environment.
- Built-in yt-dlp and exact-host Wayback paths have hermetic tests and share top-level admission, but exact-version live evidence is not captured; required mode refuses local yt-dlp until an allowlisting egress broker mediates its internal multi-host requests.
- The reference Linux boundary is implemented for covered built-in offline workers, but release-commit CI and target-systemd evidence are pending; development mode and uncovered processes remain outside it.
- Exact live versions and smoke evidence for external tools, browser downloads, providers, and connectors are not captured.
- The exact-version catalog covers all 167 third-party identities in the current universal lock and the v0.4 development reports regenerate; published v0.3 evidence remains immutable and profile-verified. Artifact-level notice and redistribution legal review remains required for the explicit NVIDIA proprietary/EULA and pypdfium2 mixed-distribution LicenseRefs before final release evidence can be approved.

## Reproduction

Run from the repository root:

```console
uv run python scripts/generate_release_evidence.py --overlay-profile scripts/release_v04_development.toml --check
```

`--check` regenerates both artifacts in memory and fails if tracked evidence
differs from `pyproject.toml`, `uv.lock`, the reviewed catalog, or any hashed development-overlay input.
