# M5 fuzz runs (browser bridge, plan.md §13 M5, T-FUZZ-NM, T-FUZZ-ORIGIN)

A local Jazzer campaign over the two M5.5 harnesses. Each drives the real pm-browser code through
its production entry point and checks it against its own oracle, written from ADR 0014 and the
RFCs it names, not from the code under test: no constant, regular expression or helper is shared
with `pm.browser`. Any exception outside the documented ones, any oracle violation, any hang and
any OOM count as findings. CI does not fuzz; it replays the committed seeds as regression tests in
the gate, and each harness has a seed test that checks every seed ends in its labelled state.

| Harness | Drives | Oracle |
| --- | --- | --- |
| `pm.fuzz.NativeHostFuzzTest` (T-FUZZ-NM; also tagged T-EXT-02, T-EXT-05) | `NativeHost.runWithoutPasskeys(args, allowlist, stdin, stdout, factory)`, the method `pm browser-host` calls (switched from `run` on 2026-10-07, m55b-001: v1 serves no passkeys, ADR 0016 v1 addendum, so `webauthn.create`/`webauthn.get` are decided from `type` alone and get the unknown-type reply the oracle predicts; two seeds, `webauthn-get.bin` and `webauthn-create.bin`, hold that), and nothing below it. Per input: fuzzer-chosen command-line arguments (the two allowlisted IDs, the Windows parent-window form, a well-formed but foreign ID, 26 near misses, or raw text), a fuzzer-chosen stdin, and a scripted handler that answers, throws `HostException` with any code, throws a runtime exception, returns an unencodable reply or pads its reply to just under, at or just past the 1 MiB outbound limit. Inputs are stretched (`Stretch`, cap 1 MiB + 64 KiB) so a 4 KiB libFuzzer input can carry a full-size frame or one just past the limit | Caller: its own reading of ADR 0014 §4 (`callerOf`, no regex). A refused caller must exit 2 with **0 stdin bytes read**, 0 bytes written and no handler created. Otherwise a stream model of ADR 0014 §2–§3 (`Model`) predicts the exit status, the exact number of stdin bytes read, every request delivered to the handler (field by field) and every reply (parsed back by the oracle, compared exactly, including the error code and whether `id` is echoed). JSON and UTF-8 are judged by `JsonOracle` (RFC 3629, RFC 8259, plus the ADR's depth 8, 256 members, 65,536-unit strings, 15-digit integers and duplicate-name refusal). Every `save` password must be wiped once answered. The thread's allocation, measured around every run after a warm-up pass, must stay under 8 × the 1 MiB inbound limit + 64 B per input byte + 64 MiB per padded reply (see "The allocation check") |
| `pm.fuzz.OriginFuzzTest` (T-FUZZ-ORIGIN; also tagged T-EXT-01, T-EXT-03) | The production handler `Bridge.factory(vault, ApprovalPort.inProcess(broker, 5 s), clock, generator)`, as the host creates it, over a real `ApprovalBroker` (in-memory policy store, fixed clock). Per input: two page origins, up to 72 logins with fuzzer-chosen URLs, titles and usernames (near misses of the page origins one mutation away; lone surrogates), and up to four `lookup`/`fill`/`save`/`generate` requests from one of two extension IDs. The harness plays the user and answers each prompt deny, once or for the session | `OriginOracle`, its own reading of ADR 0014 §5 (no regex, no `toLowerCase`, no `java.net`): `Origin.parse` and `Origin.ofUrl` must agree with it on every page origin and every stored URL (accept or refuse, triple, and the canonical text, which leaves out only the scheme's own default port). The text is what approvals are keyed on (session scope, prompt project, reply `origin`), so `https://h:80` and `https://h` must stay apart; 8 fixed pairs and 2 seeds (`default-port-https.bin`, `default-port-http.bin`) put an explicit 80 or 443 under each scheme. Locked: `DENIED_LOCKED`, no prompt, no vault read. Refused page origin: `BAD_ORIGIN`. `lookup`: exactly the logins with a URL whose oracle origin equals the page's, in order, at most 64, titles and usernames with unpaired surrogates replaced. `fill` of a login not registered for that exact origin: `NOT_FOUND`, no prompt, no release. Otherwise exactly one prompt with the request ADR 0014 §6 describes (requester, `AUTOFILL`, project = canonical origin, profile `fill-<base 36>`/`save`/`generate`, display text, effect), or none if an earlier session approval covers the same extension, origin and profile. Denied: `DENIED`, nothing released or saved. Approved: exactly one release or save and the exact reply |

Neither harness uses temporary files (Semgrep bans them), so the allowlist **file** parser
(`ExtensionAllowlist.read`: comments, size cap, links) is covered only by `ExtensionAllowlistTest`,
not fuzzed. The origin harness calls the bridge handler directly, not through `NativeHost`; the
host layer in front of it is the first harness's subject.

## The allocation check

Every host input is measured once, on its one run in the JVM after the warm-up, and that
measurement is judged. This is close to how a hostile header meets the host in production: Chrome starts a new host process for each
connection, so a buffer that is grown once and then kept is paid for in full by the first frame
that grows it. The first run along a path also loads its classes on the measured thread (and, in
fuzzing mode, instruments them), which costs about 52 MB on a first path. So before the first
measurement, `NativeHostFuzzTest` runs a warm-up pass (the `Warm` holder, forced by both the fuzz
method and the allocation tests). The pass covers:

- each request type (and `webauthn.get`/`webauthn.create`, which the production host answers like
  an unknown type) with all 256 handler script bytes;
- the 45 schema edges;
- each decode and framing error, including a full 1 MiB frame and a 1 MiB + 1 header;
- every caller form;
- the committed seeds found on the class path.

The warm-up's replies are not judged, and an unchecked exception out of the host is not judged on
the spot: the seeds, edges and caller forms among the warm-up inputs are each judged again by a test
that names the input (the 256 script bytes are judged only through `every-type.bin` and
`scripted-faults.bin`, and in fuzzing mode). One thing is judged (m55b-002, 2026-10-07): each input
that threw is run a second time, and one that no longer throws is a fault only the first call in a
process shows, which production, with a new process per connection, would hit on every
connection. `noFaultShowsOnlyOnTheFirstCallInAProcess` and every fuzz input fail on it, and
`everySeedEndsAsItsNameSays` walks the seeds in a fixed order so its result does not depend on
`Map.ofEntries` iteration order.
A first version let such an exception escape. With plant B3 in, the "policy 129" edge then broke
the warm-up, and every test in the class failed with the same `ExceptionInInitializerError`
instead of the one precise failure (see the B3 row below).

The warm-up's largest header is 1 MiB + 1, so only a measured input can grow a header-sized buffer kept
between calls past the ceiling. The seed proofs withhold the seeds, and then the frames the warm-up
builds itself stand alone.

The gate also measures allocation without fuzzing, so a hostile header that allocates by its length
fails CI and not only a local campaign:

- `aHostileHeaderAllocatesLessThanTheCeiling` holds headers of 64 MiB, 1 GiB and 2^32 − 1 to the 8 MiB base.
- `anOversizedHeaderIsRefusedBeforeAnyBodyByteIsRead` does the same for each of its 70 headers
  (0, and 1 MiB + 1 up to 2^32 − 1).

Plants D and Dx below show both checks catching a buffer sized from the header, whether it is
grown once and kept (D) or allocated on every call (Dx).

## Limits that fuzzing did not reach

Fuzzing alone catches none of the limit off-by-ones that the M5.5 review planted. With every seed
withheld, no harness reached one past the limit in 2 minutes (plants B1–B3 below). Each limit is
pinned at and one past its value by a deterministic test that runs in the gate:

- **Origin text, 256 characters (B1).** Guarded **only** by
  `pm.browser.bridge.OriginTest.overlongTextAndLabelsAreRefused`. No pm-fuzz test fails on it.
  `OriginFuzzTest` has no 256- or 257-character origin among its seeds or pairs, and the host
  harness cannot bring a 257-character origin to `Origin.parse`, because `Messages` refuses an
  `origin` member longer than 256 first.
- **JSON nesting depth 8 (B2).** `NativeHostFuzzTest.limitsHoldAtAndJustPastTheirValues` (edges
  "depth 8" and "depth 9", through `NativeHost.run`) and
  `JsonTextTest.acceptsTheLargestValuesAndRefusesOneMore`.
- **Generated password length 128 (B3).** `NativeHostFuzzTest.limitsHoldAtAndJustPastTheirValues`
  (edge "policy 129") and `MessagesTest.outOfRangeValuesAreRefused`.

The other schema limits (256 members, 65,536-unit strings, 15-digit integers, field lengths) are
pinned by the same 45 edges. None of them was planted, so how far fuzzing reaches them is
unmeasured. The frame limit is the exception: plant 1 widened it and fuzzing found that in under a
second, because a header past the limit changes how many bytes the host reads.

## Rules the harnesses restate

Where ADR 0014 is silent, the oracles restate the host's documented behaviour instead of inventing
one. Each is a place where a change to the code would need a matching change to the oracle:

- `type` must be a string of 1–16 UTF-16 units without control characters, else `BAD_FIELD`; this
  is checked before `UNKNOWN_TYPE`.
- A `hello` is checked for `VERSION` before its `id`.
- "No control characters" means U+0000–U+001F and U+007F. C1 controls (U+0080–U+009F) are accepted
  in a `save` username (the `limitsHoldAtAndJustPastTheirValues` edge "username C1" expects `save`);
  the prompt text replaces them (`Bridge.shown`, `Character.isISOControl`).
- "Printable ASCII" in an origin means U+0021–U+007E: the host excludes space as well.
- The Windows parent-window argument is `--parent-window=` followed by 1–20 digits.
- Prompt text for a title or username: the first 64 code points, C0, DEL and C1 replaced by `?`.

## How the runs were made

```sh
for t in pm.fuzz.NativeHostFuzzTest pm.fuzz.OriginFuzzTest; do
  JAZZER_FUZZ=1 JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew --no-daemon --console=plain -i \
    -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 \
    :modules:pm-fuzz:test --tests $t --rerun
  rm -rf modules/pm-fuzz/.cifuzz-corpus
done
```

- The `@FuzzTest` default `maxDuration` of 5 minutes bounds each run. Each final run tested the whole
  class: the deterministic tests, the seed replay and the fuzzing phase.
- `modules/pm-fuzz/build.gradle.kts` adds `pm.browser.**` and `pm.approval.**` to
  `jazzer.instrument`, so the host, the bridge and the broker get coverage feedback.
- Environment: Jazzer 0.24.0 (jazzer-junit), OpenJDK 21.0.12.1, macOS 27.0 arm64, one fuzzing
  process. Other agents' builds were running on the same machine.
- Each run started from the committed seeds only (15 for the host, 10 for the origin harness). The
  generated corpus was not committed and was deleted after each run.

## Results on the committed harnesses (2026-10-06, run end times in CDT, UTC−5)

| Harness | Ended | Fuzzing time | Executions | exec/s (libFuzzer) | Edges (cov) | Features (ft) | Corpus at end | Crashes | Gradle |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| NativeHost | 10:01:07 | 301 s | 322,355 | 1,070 | 976 → 1121 | 2077 → 3972 | 325 / 72 KB | 0 | `BUILD SUCCESSFUL in 5m 9s` |
| Origin | 10:06:15 | 301 s | 1,124,299 | 3,735 | 1295 → 1377 | 3134 → 6948 | 635 / 82 KB | 0 | `BUILD SUCCESSFUL in 5m 7s` |
| **Total** | | **602 s** | **1,446,654** | | | | | **0** | |

The JUnit reports showed 0 failures and 0 errors: NativeHost 24 tests and Origin 15. Each count is
the deterministic tests, the seeds, the empty input and the fuzzing phase. No `crash-*`,
`timeout-*`, `oom-*` or `slow-unit-*` file was written, and no log has a Jazzer finding. The
generated corpora (350 and 647 files) were deleted.

Reading the numbers:

- **The host harness is the slower one by design.** Inputs are stretched to as much as 1 MiB,
  every run re-parses its replies through the oracle, and the thread allocation counter is read
  around each run.
  - Edges were still rising at the end: 1098 by execution 21,584, and 1121 first at execution
    305,777, about 288 s in.
  - Its rate, 1,070 exec/s, is under half of run 1's 2,411 below. The machine was shared with other
    builds, so this run is a five-minute smoke run of the committed harness, not a deeper campaign
    than run 1.
  - The edge counts are not comparable with the earlier runs. The warm-up runs inside the first
    input, so the starting coverage already includes the paths it drives.
- **The origin harness plateaued early.** It reached 1377 edges at execution 228,574 (about 24 s)
  and then only grew features (input shapes). Five minutes covered what this harness can reach;
  more time would mostly re-mix the same paths.
- **Limits.** Five minutes per harness is a smoke-level campaign. It is backed by the planted-bug
  proofs below. Of the eight M5.5 plants, six were found from an empty corpus and two only with
  seeds. Of the review's plants, fuzzing found D and Dx but none of B1–B4. "Limits that fuzzing did
  not reach" names the deterministic tests that carry those.

## Second review fixes (2026-10-07)

Two harness defects from the second review were fixed, and the NativeHost harness was run again:

- **m55b-001.** The harness now drives `NativeHost.runWithoutPasskeys`, the production entry point.
  It used to drive `run`, which serves passkeys. Decoding WebAuthn bodies is out of v1 scope (ADR
  0016 v1 addendum), so a `webauthn.*` request must get the unknown-type reply. The oracle's
  schema already predicts that reply. Two seeds hold it: `webauthn-get.bin` and
  `webauthn-create.bin`.
- **m55b-002.** A fault that only the first call in a process shows is now caught. The warm-up
  used to absorb any such fault (see "The allocation check"). The seed test also walks the seeds in
  sorted order now.
  - Plant: `Messages.decodeWithoutPasskeys` throws `IllegalStateException` on its first call
    only, a lazy initialiser that fails once. With the plant in, three runs of the class in a row
    each failed `noFaultShowsOnlyOnTheFirstCallInAProcess`, `everySeedEndsAsItsNameSays`,
    `limitsHoldAtAndJustPastTheirValues` and every fuzz seed. Before the fix, the review caught it
    in about two runs out of three.
  - The plant was reverted, and `git diff` of `Messages.java` was empty afterwards.
- **NativeHost campaign on the fixed harness:** `JAZZER_FUZZ=1`, whole class, 306 s wall clock.
  It made 467,665 executions (cov 1131, ft 4518, corpus 361) with 0 findings and no crash, timeout
  or OOM files.

## Earlier runs on earlier harness versions (2026-10-05)

These runs are kept for the record. They are **not** counted in the totals above, because the host
harness changed after them.

| Harness | Ended | Duration | Executions | exec/s (libFuzzer) | Edges (cov) | Features (ft) | Corpus at end | Crashes | Gradle |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| NativeHost, run 1 (first harness: one measurement, no warm-up) | 12:10:52 | 301 s | 725,860 | 2,411 | 922 → 1077 | 1893 → 4461 | 406 / 128 KB | 0 | `BUILD SUCCESSFUL` |
| Origin (before the default-port pairs, seeds and text check) | 12:16:28 | 301 s | 1,447,446 | 4,808 | 1219 → 1302 | 2688 → 6701 | 648 / 82 KB | 0 | `BUILD SUCCESSFUL` |
| NativeHost, run 2 (second harness: re-run on a breach) | 16:16:10 | 320 s | 84,834 | 265 | 924 → 1059 | 1895 → 3717 | 278 / 74 KB | 0 | `BUILD SUCCESSFUL` in 5m 55s |

- **Run 1** used the first version of `NativeHostFuzzTest`, which measured allocation once per
  input with no warm-up. Its edges rose through the run: 1048 at about 20 s, 1072 at about 138 s,
  and 1077 at the end.
- **Run 2** used the second version, which ran an input again when it breached the ceiling and
  judged only the repeat. Run 2 used `--tests pm.fuzz.NativeHostFuzzTest.fuzz`, so it ran the fuzz
  method only (17 tests). Other builds were loading the machine, and it made about 1/9 of run 1's
  executions.
- **The Origin run** came before the canonical-text check in `assertOfUrl`, the 8 default-port pairs
  and the 2 default-port seeds were added.

All three ran clean, with no crash or oracle violation. Their corpora (436, 679 and 299 files) were
deleted. Run 2 flagged two inputs as slow units (see "Slow units").

## Planted bugs (2026-10-05)

Eight one-line bugs, each a different kind, were planted in `pm-browser` main code one at a time
by exact-text replacement (scratchpad script, never committed). A shell trap reverted each with
`git checkout -- <file>`. After every plant, `git status --porcelain modules/pm-browser/src/main`
was empty. Each plant was run twice:

1. **Fuzz mode, seeds withheld.** The harness's committed seeds were moved out of its `Inputs`
   directory and `.cifuzz-corpus` was deleted, so libFuzzer started from an empty input. Then
   `JAZZER_FUZZ=1 … :modules:pm-fuzz:test --tests pm.fuzz.<Harness>.fuzz --rerun` ran with the
   5-minute budget. "Time" is the time Jazzer reports for its `Fuzzing...` test case, which runs
   until the first finding, and "#" is the last libFuzzer execution count it printed.
2. **Gate mode.** The seeds were restored and the corpus deleted. Then the whole class ran as
   the gate runs it, without `JAZZER_FUZZ`, so it replays the committed seeds and runs the
   deterministic tests.

| # | Kind | Planted change | Harness | Fuzz mode, seeds withheld | Finding | Gate mode (failing tests) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Frame limit too loose | `NativeFrames`: `length > MAX_INBOUND` → `length > 2L * MAX_INBOUND` | NativeHost | **Caught** 0.28 s, #2,151 | `stdin bytes read expected 4 but was 6`: the stream model stops reading at an over-limit header and the host read on | 3: `everySeedEndsAsItsNameSays`, `one-mib-plus-one.bin`, `anOversizedHeaderIsRefusedBeforeAnyBodyByteIsRead` |
| 2 | Caller check ignores the allowlist | `ExtensionAllowlist.caller`: `ids.contains(origin.group(1))` → `!ids.isEmpty()` | NativeHost | **Caught** 0.25 s, #41 | `refused caller expected 2 but was 0` | 3: `everySeedEndsAsItsNameSays`, `caller-other.bin`, `onlyTheExactCallerFormsAreServed` |
| 3 | Duplicate JSON name accepted, last one wins | `JsonText`: `putIfAbsent(name, member) != null` → `put(name, member) != null && depth < 0` | NativeHost | **Missed** with every seed withheld (5 min, 68,792 execs, no finding). **Caught** in 140 s (#23,936) with 14 seeds kept and only `decode-errors.bin`, the seed that carries a duplicate name, withheld | `replies` differ: the oracle expects `MALFORMED` for the frame with a duplicate name | 2: `everySeedEndsAsItsNameSays`, `decode-errors.bin` |
| 4 | Request accepts extra members | `Messages.fields`: `names().equals(expected)` → `names().containsAll(expected)` | NativeHost | **Missed** with every seed withheld (5 min, 1,288,989 execs, no finding). With 14 seeds kept and only `decode-errors.bin` withheld, it was **missed** once (15:21; only 20,003 execs at 50 exec/s on a loaded machine) and **caught** once, in 297 s (#71,599, 16:29), just inside the 5-minute budget | `requests delivered to the handler`: the model expects a single `lookup`, but a second `lookup` that carried an extra member was delivered too | 3: `everySeedEndsAsItsNameSays`, `limitsHoldAtAndJustPastTheirValues`, `decode-errors.bin` |
| 5 | Lone surrogate let into a JSON string | `Json.Str.of`: surrogate check disabled (`&& units.length < 0`) | Origin | **Caught** 224 s, #335,748 | `IllegalArgumentException: MALFORMED_CHARS` from `SecretChars.toUtf8` via `JsonText.toUtf8`: an unpaired surrogate in a title reached the encoder instead of being replaced | 2: `everySeedEndsAsItsNameSays`, `surrogate-titles.bin` |
| 6 | Host label accepts any Unicode letter | `Origin` label pattern `[a-z0-9]…` → `[\p{L}0-9]…` | Origin | **Caught** 38 s, #259,414 | `parse https://9…9htΏ expected <null>`: the oracle refuses a non-ASCII host and `Origin.parse` accepted it | 3: `everySeedEndsAsItsNameSays`, `confusables.bin`, `subdomainSchemePortAndLookalikeConfusionIsRefused` |
| 7 | Port grammar admits 0 and leading zeros | `Origin` port pattern `[1-9][0-9]{0,4}` → `[0-9]{1,5}` | Origin | **Caught** 37 s, #232,906 | `IllegalArgumentException: BAD_ORIGIN` thrown from the `Origin` constructor for port 0, which the parser had accepted | 1: `subdomainSchemePortAndLookalikeConfusionIsRefused` (no seed carries a zero-led port) |
| 8 | `fill` not bound to the page origin | `Bridge`: dropped `&& registeredFor(l, origin)` from the `fill` lookup | Origin | **Caught** 5.8 s, #91,418 | `expected NOT_FOUND`: a login registered for another origin was released | 2: `everySeedEndsAsItsNameSays`, `fill-once.bin` |

Every plant fails the gate as committed. Six of eight were caught by fuzzing from an empty corpus,
in 0.25 s to 224 s. The two misses are both NativeHost plants that need a well-formed request
with an exact defect: a repeated name (3) or one extra member (4). An accepted extra member
follows the same code path as a normal request, so coverage feedback gives libFuzzer nothing to
climb toward it. The committed seeds and `limitsHoldAtAndJustPastTheirValues` catch both plants on
every gate run. Given the other seeds, the fuzzer found plant 3 in 140 s. It found plant 4 in one
of two runs, in 297 s, so plant 4 counts as unreliable for fuzzing alone.

**Slow units.** NativeHost run 2 flagged two inputs as slow units (libFuzzer's slowest was 27 s).
Both were found at 16:11–16:13, while other builds were loading the machine. Replayed in gate mode,
they took 0.067 s and 0.002 s, so they show the load, not a slow path in the host. libFuzzer had
written them into `NativeHostFuzzTestInputs/fuzz/`; they were moved out and not committed.

**How the rounds went.** `NativeHostFuzzTest` has had three allocation checks:

1. **Round 1 (12:16–12:18) measured each input once, with no warm-up.** Plants 1, 3 and 4 then
   "failed" on the allocation ceiling, with about 52 MB allocated for inputs of a few bytes. Class
   loading and Jazzer instrumentation on the first run along a new path are charged to the thread.
   Those were false positives, not catches, and are not counted.
2. **Rounds 2 and 3 used a second version.** When an input breached the ceiling, it was run again
   and only the second measurement was judged. The M5.5 review showed that this was wrong. A buffer
   grown once and then kept allocates nothing on the second run, so its breach was forgiven: plant
   D below survived 335,734 executions and the gate.
3. **The committed harness measures each input once, after a warm-up pass** (see "The allocation
   check"). The re-run is gone.

The verdicts in the table above come from the second version. No verdict there depends on the
allocation check:

- plant 1's finding is the stdin byte count;
- plant 2's is the refused caller's exit status;
- plants 3 and 4 are decided by reply and delivery checks;
- plants 5–8 are on the Origin harness, which has no allocation check.

Plants 1 and 2 were re-run on the committed harness, and their verdicts are in the next section.
The round-2 runs of plants 4 and 5 were discarded, because the plant script was edited while it
was running. Both were re-run cleanly in round 3. In round 1, which had the same seeds withheld,
plants 5–8 were caught in 11.9 s, 4.3 s, 2.8 s and 4.6 s. The table gives the later, slower runs.

## Review plants on the committed harness (fix round, 2026-10-05 and 2026-10-06)

The M5.5 adversarial review planted six more bugs (D, Dx and B1 to B4) and filed five defects
against the harnesses and this record (m55-001 to m55-005). After the fixes, the review's own driver
was re-run on the committed harness for each of its plants, and for plants 1 and 2 (as P1 and P2),
one at a time:

1. **Fuzz mode** for 2 minutes (`maxDuration = "2m"`), with every seed withheld and an empty corpus.
2. **Gate mode**, with the seeds back.
3. `:modules:pm-browser:test`.

The driver reverted the plant and the harness after each run, and then checked that
`git status --porcelain` was empty. The tree was clean after every run. NONE plants nothing. It
checks that the warm-up removed the round-1 false positive.

| ID | Planted change (pm-browser main) | Harness | Before the fixes (review of 1f04ecc) | Fuzz, seeds withheld, 2 min | Gate mode (`pm.fuzz.<Harness>`) | `:modules:pm-browser:test` |
| --- | --- | --- | --- | --- | --- | --- |
| D | `NativeFrames`, before the limit check: keep a buffer and grow it to min(length, 64 MiB) when a longer header arrives (grown once, then reused) | NativeHost | Fuzz missed (335,734 execs); gate passed | **Caught** 0.382 s, #502: `allocated 67115008 > 8388992` | **Fails**, 1 test: `aHostileHeaderAllocatesLessThanTheCeiling` (`allocated 67113632 for header 67108864`) | passes |
| Dx | The same allocation on every call (control for D) | NativeHost | Fuzz caught (0.23 s); gate passed, 22 of 22 | **Caught** 0.261 s, #1,124: `allocated 67114904 > 8388992` | **Fails**, 2 tests: `aHostileHeaderAllocatesLessThanTheCeiling` (67,113,632 B for a 64 MiB header) and `anOversizedHeaderIsRefusedBeforeAnyBodyByteIsRead` (67,113,632 B for a 2^31 − 1 header) | passes |
| NONE | Nothing: checks for false positives | NativeHost | With one measurement and no warm-up, a false positive at #44 (`allocated 51875176`) | **No finding**, 121 s, #707,384 | passes, 23 of 23 | passes |
| B4 | `Origin.text`: port 80 or 443 left out under either scheme (`port == HTTP_PORT \|\| port == HTTPS_PORT`) | Origin | Fuzz missed (886,680 execs); gate passed, 12 of 12 | **Missed**, 121 s, #945,571 | **Fails**, 4 tests: `everySeedEndsAsItsNameSays`, `default-port-http.bin`, `default-port-https.bin` (`https://example.com:80` shown as `https://example.com`), `subdomainSchemePortAndLookalikeConfusionIsRefused` (`ofUrl text https://example.com:80/`) | `OriginTest.caseAndDefaultPortsAreCanonicalised` fails |
| B1 | `Origin.parse`: `text.length() > MAX_TEXT` → `> MAX_TEXT + 1` | Origin | Fuzz missed; gate passed | **Missed**, 121 s, #687,886 | **Passes**, 14 of 14 (missed) | `OriginTest.overlongTextAndLabelsAreRefused` fails |
| B2 | `JsonText`: `depth > MAX_DEPTH` → `> MAX_DEPTH + 1` | NativeHost | Fuzz missed; gate failed, 1 test | **Missed**, 121 s, #1,251,899 | **Fails**, 1 test: `limitsHoldAtAndJustPastTheirValues` ("depth 9 expected MALFORMED but was BAD_FIELD") | `JsonTextTest.acceptsTheLargestValuesAndRefusesOneMore` fails |
| B3 | `Messages`: `length > Policy.MAX_LENGTH` → `> MAX_LENGTH + 1` | NativeHost | Fuzz missed; gate failed, 1 test | **Missed**, 121 s, #1,078,305 | **Fails**, 1 test: `limitsHoldAtAndJustPastTheirValues` (`IllegalArgumentException: BAD_POLICY`) | `MessagesTest.outOfRangeValuesAreRefused` fails |
| P1 | Plant 1 again: `length > MAX_INBOUND` → `length > 2L * MAX_INBOUND` | NativeHost | (plant 1: caught in 0.28 s) | **Caught** 0.519 s, #4,127: `stdin bytes read expected 4 but was 6` | **Fails**, 3 tests: `everySeedEndsAsItsNameSays`, `one-mib-plus-one.bin`, `anOversizedHeaderIsRefusedBeforeAnyBodyByteIsRead` | `NativeFramesTest` and `NativeHostTest` fail |
| P2 | Plant 2 again: `ids.contains(...)` → `!ids.isEmpty()` | NativeHost | (plant 2: caught in 0.25 s) | **Caught** 0.156 s, #7: `refused caller expected 2 but was 0` | **Fails**, 3 tests: `everySeedEndsAsItsNameSays`, `caller-other.bin`, `onlyTheExactCallerFormsAreServed` | `ExtensionAllowlistTest` and `NativeHostTest` fail |

What these runs show:

- **D and Dx are now caught both ways:**
  - fuzzing from an empty corpus finds each in under half a second;
  - the gate fails on each without fuzzing.

  With D, only one gate test fails, because the grown buffer is kept for the rest of the JVM:
  whichever allocation test runs first pays for it.
- **NONE ran clean.** With nothing planted, 707,384 executions gave no allocation finding, so the
  round-1 false positive (about 52 MB on a first path) has not returned.
- **B4 is caught by the gate.** It fails 4 tests: the 8 default-port pairs, the 2 default-port seeds
  and the text check in `assertOfUrl`.
  - Fuzzing from an empty corpus still does not build an explicit default port under the other
    scheme in 2 minutes.
  - The `default-port-http.bin` seed shows what B4 would cost: a session approval given to
    `http://example.com:443` also covered `http://example.com`, so a `generate` that should have
    prompted, and been denied, was answered without a prompt.
- **Fuzzing alone catches none of B1, B2 and B3** (see "Limits that fuzzing did not reach"). B2 and
  B3 each fail one precise gate test. B1 passes the whole pm-fuzz gate and is caught only by
  `OriginTest` in pm-browser.
- **B3 also shows a robustness gap that only a planted bug opens.** A range check loosened in
  `Messages` lets the `Request.Policy` constructor throw an unchecked `IllegalArgumentException`.
  That exception escapes `NativeHost.run`, which would end the host process. Today `Messages` and
  the constructor agree on every limit, so this cannot happen without a code change.
  `limitsHoldAtAndJustPastTheirValues` would report it.
- **Plants 1 and 2 are still caught** on the committed harness, by fuzzing and by the gate.

The first version of the warm-up (commit 1532189 in this fix round) gave the same verdicts for D, Dx,
NONE (232,164 executions, no finding), B2, P1 and P2. The exception was B3: there the warm-up itself
broke, as described in "The allocation check", and all 21 tests that use it failed with
`ExceptionInInitializerError` or `NoClassDefFoundError`. The NativeHost rows above are from the
committed harness. B4 and B1 use `OriginFuzzTest`, which the warm-up change did not touch, and were
run on 1532189: B4 on 2026-10-05, and B1 on 2026-10-06, because its first run was cut off at the
`pm-browser` step.
