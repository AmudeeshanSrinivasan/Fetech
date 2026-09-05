# Fetech v0.5.0b1 Beta candidate dependency-license report

This is deterministic unreleased engineering evidence, not legal advice and not
a published-release license report. The package metadata and universal lock remain
`0.5.0b1`; the overlay label does not relabel the Python distribution.
License declarations were reviewed for the exact versions in `uv.lock`; SPDX
`licenseConcluded` remains `NOASSERTION` for third-party packages because this
report does not make legal conclusions.

## Inputs and coverage

- Generator: `fetech-release-evidence-generator/2`
- Evidence timestamp: `2026-09-05T00:00:00Z`
- Overlay status: `unreleased-candidate`
- Package version: `0.5.0b1`
- `uv.lock` SHA-256: `bc8e1f9ba74465628df5ad8512b3136ad180fcebcd1ec2a989abf1a1028d157f`
- Third-party locked packages: **168**
- Overlay capabilities: **36**
- Cumulative registered capabilities: **155**
- Coverage: base runtime, every declared optional extra, development dependencies,
  and all platform-marker alternatives represented by the universal lock.
- Package evidence links point to version-specific PyPI release pages. The reviewed
  catalog also uses package metadata, bundled notices, and upstream license files;
  special review notes remain attached to affected rows.

### Hashed unpublished-overlay inputs

| Input | SHA-256 |
|---|---|
| `scripts/release_v05_beta.toml` | `c60f4a915cf8106ebf493f039a37b3ab9cf65ceebfd9c9b02cee5da717e2a409` |
| `README.md` | `ed9079318f18ea38adbbc73d6aaf7a7a21ef00ece6a807846c52978ae77f76e9` |
| `LICENSE` | `29f6bf2bd90a2e8ab6f01c805e4b28d47760597cea2f7474782221f3c283e594` |
| `SECURITY.md` | `d6a5930c9e4b9b5a303f037328670e39b48c1694b0d19382907bbcc00eaf1f60` |
| `CONTRIBUTING.md` | `2cb0d10bfbac3bc811e6e87a9d362ec69634ed96982dfeaa384f80a8f824b891` |
| `pyproject.toml` | `711d7e73a5c03ccd85608b0414cbfccade7b641078c550e7acb2f5263827c93c` |
| `uv.lock` | `bc8e1f9ba74465628df5ad8512b3136ad180fcebcd1ec2a989abf1a1028d157f` |
| `capabilities/manifest.yaml` | `0e51a9d84fb92fe35aa1fb4e486f5729a453dd17ffc6b3df524b5e9562ed6039` |
| `compatibility/beta-v1.json` | `04df1bc150cb88f5f88f4822593f7c92697bf7c7c78080f843b7fd56bd7ef7ff` |
| `compatibility/fixtures/v0.4.0a0-contracts.json` | `df9c7beabdcc0cc99a7f4ee2124e77faccb51ac9458cec5d1d1fe8da3b67d6c8` |
| `.github/workflows/ci.yml` | `9e9b4d8bcd30e2609c6be52a8ec7e762acdbea6f592aed0428d3dbbb7ab6ba3b` |
| `benchmarks/context-tasks.yaml` | `8e81787876e599c443579c2313c17f5f76a2ba60e081a4d802914b6da26f3305` |
| `docs/adr/0001-polyglot-logic-backends.md` | `f5c217f5ac68eeae5745f667d7b3fcde7452d80fe6b5e7c3f49003e65838fbe3` |
| `docs/api-compatibility.md` | `cc3d56b6687b7b8854ea6e3cf601d878a240df1356735c168625644ae0f0ecba` |
| `docs/architecture.md` | `852c532f9dd2b07593a7a0ec14712c57f2bd80da8713f15ce8a9bfd7f248a3d7` |
| `docs/beta-development.md` | `fe14095122373f6be5ad007f268353008e6acf0d44828dfac7ee323118c74002` |
| `docs/capability-catalog.md` | `90ee03e51598c54ac848915d94576331f712fc7acff327b3f7f751821995ac65` |
| `docs/context-broker.md` | `2e4b05302931ec00c026227a5800738f7a2bc3350e8db130a9746e3776c4362d` |
| `docs/extraction-provenance.md` | `c75c33e2e5dfc2558eaec526565c0f333cd43443c4e913637f01c0c7429dabd5` |
| `docs/failure-semantics.md` | `23c036607e5290b0c94f695c3ade9556bcf089ba60fa2619d658087c117148af` |
| `docs/fuzzing.md` | `b193e2a8f4ec09bff3080179328dfed677c0cde35ce2452147c8bb974f4b9673` |
| `docs/reproducible-builds.md` | `81eb3508983349cbdf88c4071f4186eb9f8d08214054cab84ce5a237612df10a` |
| `docs/security-threat-model.md` | `4ca84531f90fddb56b8f9e39588c4faf84da0d8ea7c410adc0c090b2f9dbe956` |
| `docs/storage-lifecycle.md` | `b7b88891c1ff9554e988ab8935298c05f96c0510db6bfe4a2455726d40057e9c` |
| `docs/releases/v0.5.0b1.md` | `b3e13fafd7f47993134864959c38977030f402a512e03b61bc10317279ecad05` |
| `release/fetech-v0.4.0a0-freeze.toml` | `234704314b9aaae1d3acdbe6b92c69ae250bb1db194f0c4971b34e16d3f143e6` |
| `scripts/check_beta_compatibility.py` | `791ce2343645712199d00cf3b47277f5a8f4297d79fae0bc3c1e6f771df0648f` |
| `scripts/generate_release_evidence.py` | `13efee887298c94e4ece0cc317fc189bbaa02847b0c7296075b7fa98eb8fb9db` |
| `scripts/run_context_benchmark.py` | `835d54e9c69bfcf4a7e51192018d8e7a5ef9fabcb3ae6c0eb226c71fae23e89d` |
| `scripts/release_license_catalog.toml` | `a5beffe5706530e99915a21b03835d7bdf2db186f68d2e1c18f127f63cc3d956` |
| `scripts/release_published.toml` | `9ec0d58866ac9fdcda7b2c21b8a5957ecf0aef8c5909390f12f7712087e35731` |
| `scripts/verify_reproducible_builds.py` | `b108340e29e37c9701ed6b68941d38e071bab6bf84d59685897535633ab93c70` |
| `src/fetech/__init__.py` | `afcb469c4a41656517d11b46f6a7e0ca9e5a81a054ae4d3e901979a91788404c` |
| `src/fetech/adapters/__init__.py` | `79f9136a60c82f9749f1b934b5f9bad6219727ed92de476ff3fa5d47e11b3ab9` |
| `src/fetech/adapters/api.py` | `138ac4bb98e85639c9134ba661b59b2f850ff07a775e843985be32a2c3cf9ce2` |
| `src/fetech/adapters/archive.py` | `79b57c11d928f21b25135d504794c34b1625e912427f3094adbd736788c590bb` |
| `src/fetech/adapters/auth.py` | `660347f6a9abe6446ebeda0ffe4c1c848bdf199adc8863c0cf53481b9863e193` |
| `src/fetech/adapters/base.py` | `7e99bcd47d13637483325ec0d9416cedada902b33c261d1f8dff57fb4cfee7e0` |
| `src/fetech/adapters/browser.py` | `d2961e8c44193410a3c8296fd537b176c7616f6df8daa5d74e1690cd160f6c9d` |
| `src/fetech/adapters/cache.py` | `d0ff59e457ff44232a89c5075e6777cbf776e013689c34881357163263a39ecd` |
| `src/fetech/adapters/discovery.py` | `5538ab4d6a68b44c81e99739052ba61f31007aef2d2e4c4a2764ffdeedb95b6e` |
| `src/fetech/adapters/documents.py` | `bf3face48ee8a6a8b735b0405da7d77ba98678fd7476191489864f04db45fde6` |
| `src/fetech/adapters/http.py` | `0a6f6f0cf64cb1c2496cfa9d07edd307df06523d95dcbcbb47a9e6f020c666e6` |
| `src/fetech/adapters/media.py` | `615280e6214ea6a57b93af93e26c44f6f57e975c67a773bed5f54b93a96f05e1` |
| `src/fetech/adapters/reader.py` | `95a2b736c13bb7e991aaf3ddca327981a56c822b1c952901604bd473e649f59d` |
| `src/fetech/adapters/structured.py` | `effe525033f811a0ef732bc416f8fd22d1b1b4623596fa29e0f0a8680cb9abcf` |
| `src/fetech/adapters/variants.py` | `4edbf7102ef254d0653ea5b5504df174883bddda2c13f4c6ea5673141ce5c939` |
| `src/fetech/archive_worker.py` | `b3f98277d97ac390227b274b38345476c8c1cda8ab2c19cff027b6240d222006` |
| `src/fetech/auth.py` | `e04a7e5f65fded534d27615ac037e518fc76ca14cac99c7a199e772f07637edd` |
| `src/fetech/auth_flows.py` | `5d86b1e4b37cb8d33a21bd836c666f071419a5464f73131d70c9e6e9e1a78e50` |
| `src/fetech/browser_reader.py` | `4b931a036ca93e042aa26478360aae3c528e11b1b4f59c8a13451770292a6b9d` |
| `src/fetech/browser_render.py` | `6937884c81c5b1246b836db4036e6c157e2aec77e30475ebd3dd17fab6808e83` |
| `src/fetech/browser_worker.py` | `8de4f6ce6e2c5b2882e70795f69c15cd11df0f40a70032cf3ff19061982e688b` |
| `src/fetech/cli.py` | `3720e2df5eed6c40d33693d60696dd458fc7b6ff340b8dd7ce2ed0f779594aa4` |
| `src/fetech/client.py` | `7886225bb9797b2d205f4aa8ecf49763444a28fc72e89b23eaeecf78b67fa8e3` |
| `src/fetech/compatibility.py` | `22de6643415c02624bfecf38de810c0054d475348446b2a0f778bf2cdba1eeca` |
| `src/fetech/config.py` | `4d3bec5ccdd8c842f1e6200df91ab66d619eae66ad0b2dd6d8bc0b90b40a434a` |
| `src/fetech/conformance.py` | `f0b3f8d063939e0cc323c05fd54cb2b9dde36ffc95dbe31d769b4824679e61fa` |
| `src/fetech/context.py` | `55d6f38af5b24eec443c2027cd58e1229c695ce3af865d22a9a84109a86e5740` |
| `src/fetech/context_benchmark.py` | `5d5f608bb8564608fd958a6059dbe227779c0dfec513a8734292496a118ccf34` |
| `src/fetech/contracts.py` | `0c679893740cd2fb70384cfa2746a5dccc70b9b63e51b0e991e6510c2842761d` |
| `src/fetech/daemon.py` | `127ac576c2e4336e1d3ada62ff8ae09e459394b07d30be1ad3c4c017b5ea6fd4` |
| `src/fetech/docling_artifacts.py` | `1708370b8e7fb0f47511c2303e18e274a61fba62742e6f6c20d73833715ac278` |
| `src/fetech/document_worker.py` | `ae08b37f715d2d2a1d3d4532845c7547eb487ee8a4077f4bb9c6d665faca23a9` |
| `src/fetech/errors.py` | `891508b29d467ae974e3498dd877d4e185abdb2243a1f526ecaad2b3e7e657d7` |
| `src/fetech/executor.py` | `99c68aaa47efd851b26d655b7bad4feefb288e531b960d6a77e98ecc5b8999d3` |
| `src/fetech/failures.py` | `a8f3c6b946b398663282e8f20ed55d58197325ee510357ed35a48e402162d79f` |
| `src/fetech/gateway.py` | `bd64621d21ac9903ee1939268c08c88e6dad058b422e3a0ee13c28b54abc14ed` |
| `src/fetech/http3.py` | `37ce6da90653ba8dd6752570211a06ab87b98db80148d113307268ce065ca876` |
| `src/fetech/image_worker.py` | `393b558ecfe71e0e5aec0e9287566b11f64da4753491b02840528781efeb4163` |
| `src/fetech/ledger.py` | `898d9f1322504d8e44db9f52dcd16301becc6d10a1ed97526893b5584182288a` |
| `src/fetech/logic/__init__.py` | `5d3854dd9347c77cbb46a5534a995dc03e23d8a06f0f0a8093a633b26e4c134f` |
| `src/fetech/logic/base.py` | `a8d80fc03a24def4a7abb2ff9b7f25ee080df66e4d83f9beeef8fe3e73a76837` |
| `src/fetech/logic/clingo_backend.py` | `eb0ca2809d0e9fcee89bdb76edb772af618d8b105edf3bdd74cbef5e988fb5cf` |
| `src/fetech/logic/coordinator.py` | `ee5e7fcfe5364af3c4223c18e2fbd05d7b23eac3efe1b422559b0530bf5ac48e` |
| `src/fetech/logic/models.py` | `8f618ca8b75622e4d3f71ef6a1b175e19c503376b5780e0e292eaa1af57a7331` |
| `src/fetech/logic/process.py` | `51ce2da5d0d0f28af96e259d91c2a688ab99be9dae97d6f20aad7be10737a80e` |
| `src/fetech/logic/process_bootstrap.py` | `7b45a97ebcd615b792de6d1851320b8ef94987569b8330daa24ef86ed09e8b4f` |
| `src/fetech/logic/prolog_backend.py` | `8e1bb0b1b3f13d2cfab8a47e88387901a980d4a8ba532d3d3bfdafe23ed14d01` |
| `src/fetech/logic/python_backend.py` | `fb4ad1ba8aafe4f1030229ccf32658f42e65e5c84e166bfff53972418eb605e8` |
| `src/fetech/logic/rules/planner.lp` | `99f1ead4432fd28301ca16ae4cb4cafeb22e057185d98cf83e576df0fd1c849e` |
| `src/fetech/logic/rules/reasoner.pl` | `21fa433331cd3fc549d9a3a7f04bec01c2e0145a228a96959e5a8943ae80892d` |
| `src/fetech/mcp_server.py` | `eb43fee5df323cde4b362ea7950e2c3cc3ba5f3cd7706925b2aa5870b5ee0585` |
| `src/fetech/models.py` | `25881a1ec792862fb46b16fbf6fdc8ea86844239fcccd6ad39ca34c80d2dd3fc` |
| `src/fetech/planning.py` | `26a9bf4babf195056a5a04cd6c0dbeaa606eb379c0e839c6528ad3ebc72bc852` |
| `src/fetech/provenance.py` | `32a9d3aae3d7ffc75ef5500be3f1a92951b3084acbdfda814b150ea378bddd97` |
| `src/fetech/quality.py` | `c998156f9d16bfad2ffa11ff85c86893720cf48d5c5714121b9287b6dd13fd29` |
| `src/fetech/registry.py` | `fc3a736674b73b2838be537fd2bd3d145454885daf757bd4963aeea8cd5cf7b0` |
| `src/fetech/scheduling.py` | `f77f7c6e45939fffddfd83f8753086a32418320e06f24415a302387aa573ee1e` |
| `src/fetech/search.py` | `88ec5655693b9780a23e5bbc306944a212493b1307e486969f36951e80c7683b` |
| `src/fetech/security.py` | `5150011f8823cc05f045ab72fc1696e04971e77387aa203dbb19d2fa7a9460df` |
| `src/fetech/storage.py` | `d3398c95ac5be8c96f4c8105bda760c1f9f71b1e23eddec0604d0a2afc2dccc8` |
| `src/fetech/storage_lifecycle.py` | `7b7088a0dfb9470a6ca1ea673e49763def8bc80f48eb848b956a76015332ecc8` |
| `src/fetech/transport.py` | `a39140a689a5b6c490a26c9415183fbda72bfdde47d9d252db06e31d25e10dd2` |
| `src/fetech/variants.py` | `71d7e8c36fe13672587dfe233d0d2eae722e364f26093fbfdf562fd87a562843` |
| `src/fetech/version.py` | `eee76eae00603dd147c05a93e6f031bbb2cc66281172e2d84071aa5de8aa800d` |
| `src/fetech/wayback.py` | `442d3b1b1d3d3439507d6cbae2d138cc8a75a6991664c026c6ba186024ee42da` |
| `src/fetech/worker_audit.py` | `e0cdf47daae5f1291462450aa5c66d96719f7fac161104a1ec50d413473e14ae` |
| `src/fetech/worker_isolation.py` | `20cd41906055fd262bec6881ce956f3a0f5ef02bc9edefb1cc5e13209894c8e9` |
| `src/fetech/worker_isolation_bootstrap.py` | `7317aa1dc4edff4e61df5acdfa72134b1661c6a5f8944ae76544bfb148a2868c` |
| `src/fetech/yt_dlp.py` | `3e452221b0a5428dd68b46d7e80254ffad0ea3795b8abfd509c788836f467de9` |
| `src/fetech/yt_dlp_worker.py` | `0c0defe1fcdd76dd525bc3346d10289548801c3e5e13ae57bdd46b357911352f` |
| `tests/conftest.py` | `fb4a3165aa507a9f792ae87f60da6f0e1acb1e7a6a0b7d5d534cf936703e27da` |
| `tests/test_beta_compatibility.py` | `85bffc7675636b44639c64272412390d875c8d9ce2facbe7741bb2edf4b0e8e6` |
| `tests/test_beta_context.py` | `c9db3a137cb0e749190433252c1f676d5e1f1b6d2f9328bee5511a7abbf44934` |
| `tests/test_beta_contracts.py` | `7c7d820c8b0484c73378ed719d058e56329ab33b0e2a2b0c8a276c6666b8119b` |
| `tests/test_beta_failure_catalogue.py` | `91cde39f8b08f14fa7a51e838f7781b1cbbc229224c4a263107d01fba471c4fb` |
| `tests/test_beta_format_fuzz.py` | `2968bf9f20e551aa40664d45988a7bdbb5728c7aa0229635b4bc4a2d2bb440c6` |
| `tests/test_beta_lifecycle.py` | `fe23a0efb346cd01a25d03c4580f8fb0326a4e1f3082dfa8c4b3e087825d1a55` |
| `tests/test_beta_parser_fuzz.py` | `36af25b64835406d43823f476b879d4f72d1d47be4c5fac8052f5cf39955e68d` |
| `tests/test_beta_release_evidence.py` | `7e07b417386de159ff649d75ba21de0293e8f0194490b8ef9c5a704b7a3ba730` |
| `tests/test_beta_reproducible_builds.py` | `5af5223b4cd9f2aa0d1ff3c9be3a9dbba64b7e4d5675da5773c4ea4878cf8dda` |
| `tests/test_beta_storage_lifecycle.py` | `8aa8efbef8fb8dc479ba44ccfdede66bc4eb4a1e7cc5143280195dca5363c941` |
| `tests/test_beta_validation_errors.py` | `e99b0f1c9624404ebda6b8118991bc5ee8ae332e9bdb71a2d11c06afae6813c2` |
| `tests/test_context_benchmark.py` | `28039720c58677706503203acc71c47d11579b2f187bdbe321f54043e4b6b0e8` |
| `tests/test_beta_version.py` | `1ee8c0031ab9535b6383eb103234637ac1e2de658b4209c9fa117f4da67b357c` |
| `tests/test_docling_artifacts.py` | `0afa8f95feaab5372231c70125fb136e63a5666425b44e2973fe425d54896983` |
| `tests/test_enma_invariants.py` | `44af8dce736609ce18519aa2efa13bdb5c2d0464faf75de3ef50da661417e8f8` |
| `tests/test_http_adapter.py` | `b316c62063d6e8e204455f15599694962ea65f7d2af75e3d7ab1c19e9b603a38` |
| `tests/test_logic_backends.py` | `9140c1c49e7ba6577e8e79fdf6f1b5180c0e8ae28e4fc78b8a2c381612c6901c` |
| `tests/test_network_scheduling.py` | `5cb5bc78bd6a0cc216749aadd5b3670b4d99feee1ebeb18d72f808caa0b9c462` |
| `tests/test_pinned_transport.py` | `c1a0547c2cca892057907ae103ec04ea5a115150bc3973ce230b53e77797a18c` |
| `tests/test_release_evidence.py` | `712c647def4fac2a1453440703f5c3c2fe72f842cbde2298dde334a5bbd5d5e4` |
| `tests/test_runtime_bugfixes.py` | `1359d5549feb6cf5cf525b50a1b7169c0d3219adfd74862b54e126bf1f1fa6ff` |
| `tests/test_runtime_conformance.py` | `6311a8f6aae74eb31ac0047661819398989ad648f8b6a9c6289b0ab16994ba2e` |
| `tests/test_storage_cas.py` | `f11e443948cddace9df0c9efa834f7e8d0837c65a48472ab1ef0075e6da76381` |
| `tests/test_v01_conformance.py` | `e46f7f357d291c109ea6678d3e794e70bee8f4a5e1d095ddb2239f12a675dd05` |
| `tests/test_v02_browser.py` | `b43a868f9cd608d1d73d2116c3453e80c69fbeddccd0a2fc40a9552dbeaa2b59` |
| `tests/test_v02_conformance.py` | `564606b8dbf1d62333a0d0f87660f379063869ac9161718e46f4102705b8e101` |
| `tests/test_v02_discovery.py` | `05846b3e8124955f03fe073e419cc2b1086772d180675a5b2753e101bac3488f` |
| `tests/test_v02_interfaces.py` | `d7a864b9b972e48690f87076eed0299d23532fdc8ad15c03559f3f326231c428` |
| `tests/test_v02_variants.py` | `57bcf5dcb0534a51baeca7545a2347e32aa9092499a91b36ae7f729a8de0d5c4` |
| `tests/test_v03_api.py` | `7a4d9ee406e38bb10734454a16c1e74ce7827cfa2531476d5a9557e2de44aaf9` |
| `tests/test_v03_auth.py` | `7a13cb5f117f81fa28d17cee68baef90958d5666c080a36bc777cda5041c463e` |
| `tests/test_v03_auth_flows.py` | `ec7a2fb68e3b96de5f69d3e3c513a315e50df51ebd66e931d32f3c6d217600bd` |
| `tests/test_v03_capability_matrix.py` | `cccbc487bd7b3d4656a49547291a9764e37eb66f2775c31811570772c660bf8c` |
| `tests/test_v03_integration.py` | `683df884a402ccaae797c8f8cf5700eabf6dc2120598728d185366f79cd2922f` |
| `tests/test_v03_interfaces.py` | `7527481bbc1bf65d6de4ecc42215fd1cde9a07d5243b5158ea1f3d691716abaf` |
| `tests/test_v03_login_cookie_handoff.py` | `a82f2ed02cbc7dea30e5535f73790894ba57bb1129d96d560f182f65c1330062` |
| `tests/test_v03_runtime_regressions.py` | `5373ae27819404ab92116091a06b1a2b340c75da8ab5232bc71b8b4c919276b4` |
| `tests/test_v03_security_regressions.py` | `bd3a078ee693876a548eb629742e08d64ae47dfe21f3517b11f8ed47de9a1335` |
| `tests/test_v03_session_connector.py` | `d6ebafa3b903cd57edde186b853b6b3299acee13fbe36bc0a517ea444904e538` |
| `tests/test_v04_budget_accounting.py` | `463e909d34128404d58d7f6a572d01ffb09a77ea184b4a0ae3c29c24196aff62` |
| `tests/test_v04_cache_archives.py` | `73f0327635a8562ab748d10353f4e4df763598e70daf7f1b4ffeec4251d8508c` |
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
| `tests/test_v04_ytdlp_release_claim.py` | `3227ed4434f226f3be41baee1577fb243a0b3214ea76777dd12d347f3e4970c6` |
| `tests/test_wayback.py` | `988c8d23d8109ddd5de9c057c4bab3ac0dd704c52d8866ef9161077aa23078c5` |
| `tests/test_worker_audit.py` | `3544ff10e69ecea8533ac50338148c82fa84950d5894a9f74f0cb5d041629de0` |
| `tests/test_worker_isolation.py` | `04fa64ee748056527c276a676154dbd0d3f74c10f6051ab8817f410977ac73db` |

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
packages distributed in the current `0.5.0b1` wheel, so they are excluded from
the lock-derived SPDX package inventory. Their rows are development inputs, not
proof that a particular executable build, browser download, service, or connector
was installed or exercised. A distribution that bundles one must record its exact
version, build options, licenses, notices, and transitive libraries.

| Component | Development-overlay status | License observation | Required review | Primary source |
|---|---|---|---|---|
| SWI-Prolog | Optional logic executable installed separately and not shipped by Fetech. | `BSD-2-Clause` for the core. | The selected build may link GMP or load add-ons with additional terms. Inspect it with the `license.` predicate. | [Upstream](https://www.swi-prolog.org/license.html) |
| curl | Optional HTTP/3 executable installed separately and not shipped by Fetech. | SPDX `curl`. | Record the selected build, linked libraries, license texts, and notices before redistributing a system image. | [Upstream](https://curl.se/docs/copyright.html) |
| GitHub CLI | Release executable installed separately and not shipped by Fetech. | MIT license. | Use an authenticated, reviewed gh installation only in the release environment; it is not a runtime dependency. | [Upstream](https://github.com/cli/cli/blob/trunk/LICENSE) |
| Playwright browser binaries | Downloaded separately by the Playwright CLI and not contained in the Python wheel. | Varies by browser and build. | Record each selected browser build and preserve its bundled licenses and notices. | [Upstream](https://playwright.dev/python/docs/browsers) |
| Tesseract OCR | Optional OCR executable discovered at runtime and not shipped by Fetech. | Apache-2.0 for the upstream engine. | Record the exact executable, trained-data packages, linked libraries, licenses, and notices used by a distribution. | [Upstream](https://github.com/tesseract-ocr/tesseract/blob/main/LICENSE) |
| FFmpeg and FFprobe | Optional media executables discovered at runtime and not shipped by Fetech. | `LGPL-2.1-or-later` baseline. | GPL-covered build options can change the complete build license. Record configure flags and linked libraries. | [Upstream](https://ffmpeg.org/legal.html) |
| Docling Layout Heron model artifacts | Operator-provisioned local artifact bundle for the preferred offline Docling path; not contained in the Python wheel or universal lock. | Reference bundle e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76 records docling-project/docling-layout-heron@8f39ad3c0b4c58e9c2d2c84a38465abf757272d8 with published Apache-2.0 metadata. | Technical provenance is not legal approval. Review the bundled model card, license text, notices, and redistribution terms before release or image publication. | [Upstream](https://huggingface.co/docling-project/docling-layout-heron/tree/8f39ad3c0b4c58e9c2d2c84a38465abf757272d8) |

## Scope counts

| Scope | Packages |
|---|---:|
| `runtime` | 27 |
| `extra:all` | 142 |
| `extra:browser` | 20 |
| `extra:dev` | 29 |
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
| `MPL-2.0` | 3 |
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
| `hypothesis` | `6.167.1` | `extra:dev` | `MPL-2.0` | [PyPI release](https://pypi.org/project/hypothesis/6.167.1/) |
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
| `sortedcontainers` | `2.4.0` | `extra:all`, `extra:browser`, `extra:dev` | `Apache-2.0` | [PyPI release](https://pypi.org/project/sortedcontainers/2.4.0/) |
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

- The Beta package is untagged and unpublished; this evidence is an unreleased snapshot and not release approval.
- Same-host reproducible-build CI is implemented, but final signed release checksums and publication receipts do not exist.
- Exact-version live smoke evidence for separately installed tools, browser downloads, model artifacts, and configured services or connectors is incomplete.
- The reviewed catalog covers all 168 third-party identities in the current universal lock. Artifact-level notice and redistribution legal review remains required for the explicit NVIDIA proprietary or EULA and pypdfium2 mixed-distribution LicenseRefs before bundled redistribution can be approved.
- The competitor matrix predates the Beta surface and must be refreshed before product-positioning claims are reviewed.
- The 100-task context-efficiency harness is implemented; the measured provider run and complete independent answer-correctness evaluation remain required before the acceptance gate can pass.
- Platform-specific deployment attestations and format-fuzz campaigns are deliberately deferred and outside this evidence scope.
- The separate v0.4.0a0 publication contract remains frozen at 10 of 14 gates; this Beta evidence does not relabel or satisfy it.

## Reproduction

Run from the repository root:

```console
uv run python scripts/generate_release_evidence.py --overlay-profile scripts/release_v05_beta.toml --check
```

`--check` regenerates both artifacts in memory and fails if tracked evidence
differs from `pyproject.toml`, `uv.lock`, the reviewed catalog, or any hashed unpublished-overlay input.
