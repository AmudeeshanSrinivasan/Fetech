# Context answer-generation protocol

Version: 1.0

Use the same answer system, version, decoding settings, system instructions, output limits, and
question text for both candidate runs. The only permitted difference is the supplied context:

- `full_context` receives every tracked document selected by the task's full-context baseline;
- `broker` receives only the exact `ContextBundle` returned for that task.

For each task, answer the question directly from the supplied context. Do not browse, use memory,
call tools, or add information that is absent from that context. Prefer a concise answer with exact
source locations. If the supplied context cannot support an answer, state that it is insufficient.
Do not reveal which context mode produced an answer inside the answer text.

Run all 100 tasks from one clean source commit. Record the answer system and immutable version or
configuration identifier in the `producer` field of both candidate files. Those two fields must be
identical. Fetech hashes this protocol file and rejects candidate sets that use different protocol
hashes or producer identifiers.
