# M3 fuzz runs (LAN protocol layer, plan.md §13 M3, T-FUZZ-LAN)

This is a local Jazzer campaign over the four M3.7 harnesses. Each harness drives the real
pm-sharing code and checks it against its own oracle. An oracle is recomputed independently of the
code under test, not read back from it. Any exception outside the documented ones, any oracle
violation, any hang and any OOM count as findings. CI does not fuzz. It replays only the committed
seeds, as regression tests in the gate.

| Harness | Drives | Oracle |
| --- | --- | --- |
| `pm.fuzz.LanCodecFuzzTest` | `Frames.read` over arbitrary bytes, then `Messages.decode` on each body and on the whole input | Only `CLOSED`/`TRUNCATED`/`FRAME_SIZE` from framing and `MALFORMED`/`UNKNOWN_TYPE`/`BAD_FIELD`/`VERSION` from decoding. Every body is 1..1 MiB. Every accepted message is within the `docs/schemas/lan-share.cddl` bounds, restated in the harness (`Cddl`), not read from `pm.sharing.wire`: 16-byte ids, 32-byte pairing values, 1..32 and 1..512 labels with no control or format characters, at most 16 cap tokens, 1..1 048 320-byte payload, expiry ≥ 1, error code ≤ 65 535. Every accepted body re-encodes to the same bytes (one spelling per message) |
| `pm.sharing.pair.PairingSessionFuzzTest` | One `PairingSession` per input, either role. The script delivers well-formed or crafted messages (right or wrong peer, right or wrong commitment, correct, reflected, foreign or garbage MAC, any sequence number), confirms, rejects, and changes the peer's nonce mid-run | `DONE` only when the human confirmed. The responder's revealed nonce must open the commitment under the peer key. The accepted MAC must equal `confirmation(sasKey(...), peer key)`, recomputed with `pm.crypto.Pairing`. The commitment and MAC oracles call the same `pm.crypto.Pairing` the session uses, so they are independent of the state machine only; a bug inside `Pairing` itself is `PairingTest`'s job (pm-crypto, fixed vectors). The shown SAS must match. The result is the peer key. `FAILED` is absorbing. A nonce or reveal is sent only in protocol order. Only `PairingException`, plus `IllegalStateException` from `result()` before `DONE` |
| `pm.fuzz.ShareSessionFuzzTest` | One sender `Shares` store with `SendSession`s to two receivers, each a `ReceiveSession` with its own `ReceivedShares`. Open, revoke one, revoke the device, move the clock, connect, deliver, drop, replay from history, craft messages, accept, decline, applied | Released data must come from a window that exists, targets that device, is not revoked and has not expired. A one-use window is released at most once. Each payload is byte-exact against the bytes the harness itself chose when it opened the window, not against the store's copy. A receiver is never offered an expired share or one already applied, and never applies the same id twice. Only `ShareException`, after which the session is failed |
| `pm.sharing.web.WebRouteFuzzTest` | Routing and request-head parsing only. Each input opens a `WebServer` on loopback for an instance, but the fuzzer never connects to it: `requestLine` and `route` are called directly with raw bytes or assembled heads (method, page/data/near-miss/junk path, version, headers). The script moves the clock and revokes (`close()`) | Neither method throws. The request line has no CRLF and stays within the head limit. Status is 200/400/404/405/410. 200 only before expiry and revocation. Ciphertext only after the page, at most once, and equal to the sealed bytes. The accept loop, TLS, the watchdog and in-flight revocation are not fuzzed: `seedsGiveTheSameOutcomeOverRealTls` replays every seed over real loopback TLS connections under the same oracle in the gate, and `WebServerTest` covers the watchdog and in-flight cut |

## How the runs were made

```sh
for t in pm.fuzz.LanCodecFuzzTest pm.sharing.pair.PairingSessionFuzzTest \
         pm.fuzz.ShareSessionFuzzTest pm.sharing.web.WebRouteFuzzTest; do
  for i in 1 2; do
    JAZZER_FUZZ=1 JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew --console=plain -i \
      -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 \
      :modules:pm-fuzz:test --tests $t --rerun
  done
done
```

- The `@FuzzTest` default `maxDuration` of 5 minutes bounds each run. Each harness got two
  back-to-back runs, and run 2 resumed from the corpus run 1 left. That is 10 minutes per harness
  and 40 minutes in all.
- `modules/pm-fuzz/build.gradle.kts` sets
  `jazzer.instrument=pm.vault.**,pm.domain.**,pm.sharing.**,pm.fuzz.**`, so the protocol code
  gets coverage feedback.
- Environment: Jazzer 0.24.0 (jazzer-junit), OpenJDK 21.0.12.1, macOS 27.0 arm64, one fuzzing
  process.
- Every run 1 started from the committed seeds only. The generated corpus was not committed:
  `modules/pm-fuzz/.cifuzz-corpus/` (gitignored) had 2415 files at the end and was deleted.

## Results (2026-10-03, run end times in CDT, UTC−5)

| Harness | Run | Ended | Duration | Executions | exec/s (libFuzzer) | Edges (cov) | Features (ft) | Corpus at end | Crashes | Gradle |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| LanCodec | 1 | 16:06:17 | 301 s | 2,441,915 | 8,112 | 482 → 562 | 739 → 2540 | 287 / 71 KB | 0 | exit 0 |
| LanCodec | 2 | 16:11:23 | 301 s | 1,591,937 | 5,288 | 562 → 563 | 2540 → 2741 | 274 / 70 KB | 0 | exit 0 |
| PairingSession | 1 | 16:16:33 | 301 s | 1,351,530 | 4,490 | 290 → 338 | 408 → 932 | 81 / 2188 B | 0 | exit 0 |
| PairingSession | 2 | 16:21:39 | 301 s | 4,539,560 | 15,081 | 335 | 929 | 78 / 2070 B | 0 | exit 0 |
| ShareSession | 1 | 16:26:52 | 301 s | 3,785,376 | 12,576 | 399 → 593 | 604 → 3360 | 628 / 27 KB | 0 | exit 0 |
| ShareSession | 2 | 16:32:09 | 301 s | 5,261,021 | 17,478 | 578 | 3342 → 3382 | 573 / 23 KB | 0 | exit 0 |
| WebRoute | 1 | 16:37:28 | 301 s | 176,956 | 587 | 196 → 216 | 292 → 955 | 187 / 10561 B | 0 | exit 0 |
| WebRoute | 2 | 16:43:20 | 301 s | 200,556 | 666 | 216 | 949 → 959 | 166 / 9577 B | 0 | exit 0 |
| **Total** | | | **2408 s** | **19,348,851** | | | | | **0** | |

Every run's JUnit report showed 0 failures and 0 errors. The test counts were LanCodec 18 and 293,
PairingSession 10 and 85, ShareSession 8 and 632, and WebRoute 8 and 193. A run 2 count is larger
because Jazzer replays the corpus it loads as tests. No `crash-*`, `timeout-*` or `oom-*` file was
written, and the logs have no Jazzer finding.

Reading the numbers:

- **WebRoute is slow by design.** About 600 exec/s, because every input binds a listener socket
  on loopback (never connected to) and closes it again. That makes 377k executions in 10 minutes, the thinnest result
  of the four.
- **Coverage plateaued in run 2.** Edges were flat or nearly flat in run 2 for all four harnesses,
  and libFuzzer mostly shrank the corpus. A run 2 that starts below run 1's last edge count
  (ShareSession 593 → 578) is libFuzzer re-counting the merged, reduced corpus. It is not lost
  coverage.
- **Limits.** Ten minutes per harness is a smoke-level campaign, not an exhaustive one. A longer
  run, like M2's open 24 CPU-hour item, can be scheduled on the same command line. The oracles are
  shown not to be vacuous by each harness's seed test. Every seed must end in a labelled state:
  the honest pairing reaches `DONE`, a bad reveal or reflected MAC reaches `FAILED`, a one-use
  share is released once, and the web share gets page then data, refused after expiry and after
  revocation. So the accepting branches of every oracle run in the gate.

## Oracle checks after the adversarial review (2026-10-04)

The M3.7 review planted bugs in pm-sharing main code and found the first oracles too weak. Each
fix below was proven by planting the bug again, running, and reverting. `git diff
modules/pm-sharing/src/main` was empty afterwards, and the gate ran on the reverted code.

| Planted bug | Before the fix | Check added | Result with the bug planted |
| --- | --- | --- | --- |
| `Checks.length` never throws (no field-length bound) | 2.26M executions, no assertion: a 31-byte `PAIR_COMMIT` decoded and re-encoded fine | `LanCodecFuzzTest.withinSchema`, an independent bounds oracle from the CDDL; `everyFixedSizeFieldOneByteOffIsRefused` (every 16- and 32-byte field one byte short and long, 20 bodies); seeds `pair-commit-31-byte-commit.frame`, `hello-17-byte-device-id.frame` | Fuzzing (`JAZZER_FUZZ=1`, same command as above, LanCodec only, from the committed seeds): finding after 2,621,457 runs in 87 s, `PairSasOk.mac size ==> expected: <32> but was: <61>`. Regression replay without fuzzing: 3 of 25 tests fail (the new test and both new seeds) at the `size` assertion |
| `Frames.read` bound loosened to `16 × MAX_BODY` | Caught only by accident: libFuzzer inputs stop at 4096 bytes, so an oversized header always ended as `TRUNCATED` | `anOversizedHeaderIsRefusedBeforeAnyBodyByteIsRead`: 4103 headers from `MAX_BODY + 1` to 2^32 − 1 (including 16 × MAX and 16 × MAX + 1) over a stream that never ends must give `FRAME_SIZE` with zero body bytes read; `headersUpToTheBoundReadExactlyTheirBody` checks 1, 4096 and `MAX_BODY` | 1 of 25 fails: `length 1048577 ==> Expected WireException to be thrown, but nothing was thrown` |

Also added in the same change:
- Duplicate map keys: `LanCodecFuzzTestInputs/pair-req-duplicate-seq.frame` (`{"t": "pair_req",
  "seq": 1, "seq": 1}`, otherwise canonical) and `CborReaderFuzzTestInputs/map-duplicate-key.cbor`.
  Both are refused, each with its own test.
- `ShareSessionFuzzTest` keeps its own copy of each window's payload and expiry instead of reading
  them back from the `Share` it opened.
- `WebRouteFuzzTest` was described as fuzzing "against a real listener". It never connected to the
  listener. The wording above is corrected, and the seeds now also run over real TLS in the gate.
- Jazzer writes findings (`crash-*`, `timeout-*`, `oom-*`, `slow-unit-*`, `leak-*`) next to the
  seeds, under `modules/pm-fuzz/src/test/resources/`. `.gitignore` now ignores those names, so a raw
  reproducer cannot be committed by accident. A finding that has been fixed is committed on purpose,
  renamed to a descriptive seed. The planted-bug reproducer above was deleted with the corpus.
