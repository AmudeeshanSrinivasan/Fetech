# Independent context-answer evaluation

Fetech's retrieval benchmark does not infer answer quality from evidence recall. The final
correctness gate requires two complete answer runs and a separate reviewer who judges their answers
without knowing which run used full context and which used the bounded broker bundle.

The workflow is deliberately local. Questions, candidate answers, review notes, and the blinding
map are written under ignored `runtime-data/` paths by default. They are never copied into the
prompt-free benchmark report.

## Roles and evidence boundary

Use three distinct responsibilities:

1. An operator runs the same identified answer system over both context modes.
2. An independent reviewer inspects only the blinded packet and ratings template, verifies claims
   against the source commit when needed, and records boolean judgments.
3. A release operator retains the blinding map, finalizes the ratings, and runs the benchmark.

The reviewer must not have implemented the context broker, produced the candidate answers, or see
`blinding-map.json` before completing the review. The workflow validates hashes, coverage, order,
types, and the attestation; it cannot prove that a person was genuinely independent or that an
operator described an answer system truthfully.

## 1. Freeze the evaluated source

Commit the intended changes and begin from a clean worktree. All later commands refuse a dirty
worktree and bind their files to the exact 40-character source commit, the benchmark suite hash,
and the checked-in generation-protocol hash.

Review [`../benchmarks/context-answer-protocol.md`](../benchmarks/context-answer-protocol.md), then
create both 100-task templates:

```bash
uv run python scripts/run_context_answer_evaluation.py templates
```

The command creates:

- `runtime-data/context-answer-evaluation/full-context-answers.json`;
- `runtime-data/context-answer-evaluation/broker-answers.json`.

It refuses to overwrite either file unless `--force` is explicitly supplied.

## 2. Produce the two candidate sets

Run the same answer system, immutable version/configuration, instructions, output limits, and
decoding settings for both files. Set the identical `producer` value in both files and fill every
`answer` value:

- for `full_context`, supply the tracked documents selected by that task's `baseline_globs` in
  `benchmarks/context-tasks.yaml`;
- for `broker`, supply only that task's returned `ContextBundle`.

Do not browse, use remembered facts, or disclose the context mode in answer text. The candidate
files already contain canonical questions and question hashes. Do not change their task IDs,
questions, suite hash, source commit, source kind, or generation-protocol hash.

## 3. Create the blinded review

After both candidate files are complete, run:

```bash
uv run python scripts/run_context_answer_evaluation.py blind
```

This randomly assigns the two answers to labels A and B independently for every task, then writes:

- `review-packet.json`, containing questions and A/B answers but no source labels;
- `review-ratings.json`, containing empty boolean judgments;
- `blinding-map.json`, containing the A/B mapping and mode `0600` permissions.

Give the independent reviewer only `review-packet.json`, `review-ratings.json`, this rubric, and
read-only access to the exact source commit. Keep `blinding-map.json` and both candidate files away
from the reviewer.

## 4. Complete the independent review

For every task, the reviewer decides independently whether candidate A and candidate B correctly
answer the question from authoritative source evidence. Correct means factually accurate,
responsive to the question, and not dependent on unsupported claims. Apply the same rubric to both
candidates; style differences alone are not correctness failures.

In `review-ratings.json`, the reviewer must:

- set `evaluator` to their name or stable review identity;
- set `independence_attestation` exactly to:
  `I independently judged both blinded answers without knowing which source produced them.`;
- set both `candidate_a_correct` and `candidate_b_correct` to JSON booleans for all 100 tasks;
- optionally add a bounded `note` explaining a judgment.

Strings such as `"true"`, missing tasks, reordered tasks, changed question hashes, partial reviews,
or a missing attestation are rejected.

## 5. Finalize and measure

Return the completed ratings file to the release operator and run:

```bash
uv run python scripts/run_context_answer_evaluation.py finalize

uv run python scripts/run_context_benchmark.py \
  --answer-evaluations runtime-data/context-answer-evaluation/answer-evaluations.json \
  --enforce-targets
```

Finalization verifies the exact blinded-packet hash, suite, source commit, task order, question
hashes, reviewer identity, attestation, and 200 boolean judgments before unblinding. The resulting
evaluation uses schema `2.0` and retains the answer producer, generation-protocol hash, reviewer,
review-packet hash, and source binding. The benchmark independently verifies the suite and commit
binding before accepting any correctness scores.

Passing requires the broker's correctness to be no more than two percentage points below the
full-context baseline, in addition to every retrieval, token, lineage, and vault-bound gate. A
successful mechanical finalization is evidence integrity, not automatic proof that the human
judgments were qualified.
