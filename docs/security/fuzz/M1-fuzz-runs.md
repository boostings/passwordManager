# M1 fuzz runs (T-FUZZ-VAULT, SR-021)

Local Jazzer campaigns for the three M1 parsers, run as sprint plan §6 Lane D asks. CI replays
only the committed seed corpora (`modules/pm-fuzz/src/test/resources/pm/fuzz/<Harness>Inputs/`)
as regression tests; it does not fuzz.

## How the runs were made

```sh
JAZZER_FUZZ=1 JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew --console=plain \
  -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 \
  :modules:pm-fuzz:test --rerun --tests '*<Harness>'
```

- Run time is bounded by the `@FuzzTest` default `maxDuration` of 5 minutes. None of the
  harnesses override it, and libFuzzer reported `Done <n> runs in 301 second(s)` for each.
- `modules/pm-fuzz/build.gradle.kts` sets `jazzer.instrument=pm.vault.**,pm.fuzz.**`, so the
  parsers under test get coverage feedback even though pm-vault reaches pm-fuzz as a jar.
- Jazzer 0.24.0 (jazzer-junit), OpenJDK 21.0.12.1, macOS 27.0 arm64.
- Jazzer writes the generated corpus to `modules/pm-fuzz/.cifuzz-corpus/`. That corpus was
  deleted after the runs and is not committed; only the hand-made seeds are.

## Results (2026-10-03)

| Harness | Target | Start (UTC) | Duration | Executions | exec/s (avg) | Crashes | Seeds in | Corpus out (libFuzzer) | Edges (cov) | Features (ft) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `CborReaderFuzzTest` | `CborReader.decode(in, CborLimits.HEADER)` | 15:28:52 | 301 s | 19,445,362 | ~64,600 | 0 | 5 | 262 entries / 22 KB (250 files saved) | 167 → 288 | 223 → 1691 |
| `RecordCodecFuzzTest` | `RecordCodec.decodePayload(SecretBytes.copyOf(in))` + re-encode | 15:33:56 | 301 s | 13,976,479 | ~46,400 | 0 | 5 | 149 entries / 16 KB (144 files saved) | 539 → 646 | 807 → 1679 |
| `EnvelopeFuzzTest` | `EnvelopeCodec.decode(byte[])` | 15:39:01 | 301 s | 17,807,331 | ~59,200 | 0 | 4 | 157 entries / 49 KB (180 files saved) | 190 → 306 | 263 → 1012 |

Each Gradle run ended with `BUILD SUCCESSFUL` (exit 0). No crash, timeout, OOM or
non-documented exception was reported, so no reproducer was added and no pm-vault bug was found.

"Seeds in" counts the inputs libFuzzer loaded at `INITED`. `EnvelopeFuzzTest` reports 4 because
this commit adds three envelopes to the existing `valid-envelope.bin`:

| Seed | What it covers |
| --- | --- |
| `valid-envelope.bin` | Floor KDF, passphrase + recovery slots, 42-byte ciphertext (existing) |
| `passphrase-only.bin` | One passphrase slot, zero timestamps, 64-byte ciphertext |
| `max-kdf-recovery-first.bin` | KDF at every upper bound, recovery slot listed first, `save_seq = 2^63-1`, tag-only ciphertext |
| `large-ciphertext.bin` | Mid-range KDF, 1 KiB ciphertext |

All three were written once with `EnvelopeCodec.encode` and checked with `EnvelopeCodec.decode`.
`EnvelopeFuzzTest.seedCorpusIsAccepted` replays them in every build.
