# M2 fuzz runs (.env parser, plan.md §13 M2)

A local Jazzer campaign for `DotEnvFuzzTest`, which feeds arbitrary bytes to
`pm.domain.env.DotEnv.parse`. The harness requires that the parser either returns entries that
meet every documented limit, or throws `DotEnvException`. Any other exception, a hang or an OOM is
a finding. CI replays only the committed seeds in
`modules/pm-fuzz/src/test/resources/pm/fuzz/DotEnvFuzzTestInputs/` as regression tests; it does
not fuzz.

**The M2 exit criterion asks for 24 CPU-hours. This file records 30 minutes.** The full campaign
needs a long-running machine and is the owner's to schedule. It stays open in
`docs/security/milestone-signoff.md` until a run of at least 24 CPU-hours is appended here.

## How the runs were made

```sh
for i in 1 2 3 4 5 6; do
  JAZZER_FUZZ=1 JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew --console=plain -q \
    -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 \
    :modules:pm-fuzz:test --tests pm.fuzz.DotEnvFuzzTest --rerun-tasks
done
```

- Each run is bounded by the `@FuzzTest` default `maxDuration` of 5 minutes. The
  `JAZZER_MAX_DURATION` environment variable is not read by jazzer-junit, so the campaign is six
  back-to-back runs. Each run resumes from the corpus the previous run left.
- `modules/pm-fuzz/build.gradle.kts` sets
  `jazzer.instrument=pm.vault.**,pm.domain.**,pm.fuzz.**`, so the parser gets coverage feedback.
- Jazzer 0.24.0 (jazzer-junit), OpenJDK 21.0.12.1, macOS 27.0 arm64, one fuzzing process.
- The runs used a separate git worktree at the M2.7 tree. The generated corpus
  (`modules/pm-fuzz/.cifuzz-corpus/`, 1263 files at the end) was deleted with the worktree and is
  not committed. Only the five hand-made seeds are committed.
- Run 1 resumed from a corpus left by a short smoke run of the harness in the same worktree,
  which is why it loaded 572 inputs at `INITED`.

## Results (2026-10-03, run end times in CDT, UTC−5)

| Run | Ended | Duration | Executions | exec/s (libFuzzer) | Edges (cov) | Features (ft) | Corpus at end | Crashes | Gradle |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 14:13:55 | 301 s | 41,070,908 | 136,448 | 242 | 1113 → 1114 | 252 / 9686 B | 0 | exit 0 |
| 2 | 14:19:03 | 301 s | 34,694,715 | 115,264 | 242 | 1114 | 253 / 8793 B | 0 | exit 0 |
| 3 | 14:24:10 | 301 s | 41,663,621 | 138,417 | 242 | 1114 | 254 / 8686 B | 0 | exit 0 |
| 4 | 14:29:17 | 301 s | 40,866,552 | 135,769 | 242 | 1114 | 254 / 8182 B | 0 | exit 0 |
| 5 | 14:34:24 | 301 s | 42,647,179 | 141,684 | 242 | 1114 | 257 / 8021 B | 0 | exit 0 |
| 6 | 14:39:31 | 301 s | 42,268,030 | 140,425 | 242 | 1114 | 256 / 7939 B | 0 | exit 0 |
| **Total** | | **1806 s** | **243,211,005** | | | | | **0** | |

Each run's JUnit report showed 0 failures and 0 errors. The test count in the reports grew from 292 to
1255 because Jazzer replays the growing corpus as tests. No `crash-*`, `timeout-*` or `oom-*`
file was written.

Edges stayed at 242 from the first `INITED` onward, and features gained one in run 1. The parser
is small (one byte-level state machine), so coverage saturates early. Over the rest of the
campaign libFuzzer only shrank the corpus (`REDUCE`). This is consistent with the parser's limits
being reachable and enforced. It is not a substitute for the 24 CPU-hour run, which exercises far
more input combinations at the same coverage.
