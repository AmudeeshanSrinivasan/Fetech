# Context answer-generation protocol

Version: 2.0

Use the same answer system, version, decoding settings, system instructions, output limits, and
question text for both candidate runs. The only permitted difference is the supplied context:

- `full_context` receives the complete documents explicitly listed in the task's `baseline_files`;
- `broker` receives only the exact `ContextBundle` returned for that task.

For each task, answer the question directly from the supplied context. Do not browse, use memory,
call tools, or add information that is absent from that context. Prefer a concise answer with exact
source locations. If the supplied context cannot support an answer, state that it is insufficient.
Do not reveal which context mode produced an answer inside the answer text.

Run all 100 tasks from one clean source commit. Record the answer system and immutable version or
configuration identifier in the `producer` field of both candidate files. Those two fields must be
identical. Fetech hashes this protocol file and rejects candidate sets that use different protocol
hashes or producer identifiers.

The curated v2 baseline is a different experiment from loading every repository document. Freeze
the file selection before generating answers; do not change it based on broker output or scores.
Use `build_task_baseline_contexts` to obtain exactly the complete texts measured by the harness.
The 100,000-token bound uses the harness estimator, so also count the final request with the chosen
model's tokenizer, including instructions and answer allowance. Never silently truncate a file.

Runtime and decision tasks currently use repository documents as baseline proxies. They cannot
support the final paired answer-correctness claim until both answer conditions use the same frozen
runtime events and selected note snapshots. Do not score those proxy tasks as if they contain the
actual events or notes. Do not load a complete vault to construct a baseline.

`freeze_context_evidence.py` prepares those bounded local inputs and verifies event/projection
parity. Its `AWAITING_BROKER_REPLAY` stage is not authorization to generate final answers: the
broker bundles and candidate/review artifacts must also be bound to the same frozen snapshot.
Never use a dirty development snapshot as clean-commit acceptance evidence.
