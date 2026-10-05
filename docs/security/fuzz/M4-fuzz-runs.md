# M4 fuzz runs (ssh keys, ssh-agent replies, breach ranges; plan.md §13 M4, T-FUZZ-SSH, T-FUZZ-BREACH)

This is a local Jazzer campaign over the three M4.5 harnesses. Each harness drives the real parser
and checks it against oracles that do not read their answers back from the code under test. Any
exception outside the documented ones, any oracle violation, any hang and any OOM count as
findings. CI does not fuzz. It replays only the committed seeds, as regression tests in the gate.

This file was rewritten at the M4.5 review. The adversarial review of the first M4.5 commit planted
9 bugs in main code and the first harnesses missed 4 of them in 2-minute runs: an armour trailer
check (the harness had no armour grammar), the `ENCRYPTED_KEY` code (the harness only checked that
some documented code was raised), the 1,024-identity cap and the 256 KiB frame cap (no input could
cheaply reach 1,025 identities or a frame near 256 KiB, and the allocation bound was too loose to
notice a 1 MiB buffer). The breach harness also tested `BoundedBody(512)`, not the production
1 MiB cap. The harnesses below are the rebuilt ones; all 9 plants were re-run against them.

| Harness | Drives | Oracles |
| --- | --- | --- |
| `pm.crypto.ssh.OpenSshKeyFuzzTest` (T-FUZZ-SSH) | `SshKey.parse` on the strict `openssh-key-v1` parser, in three input modes. **Armour edits** (`'A'` first): a valid seed key, armoured at a line length the input picks (or one line), then 4-byte edits (`u16` position, top bit counting from the end; op; value): insert, delete, replace, a line break (LF, CRLF, CR, blank line), a trailer byte, a prefix byte, a base64 or `=` character, a short deletion. **Binary** (the magic, after an optional stretch): armoured by the harness in the ssh-keygen layout, so mutations reach the binary format and the 4 KiB comment and 64 KiB file limits. **Text** (anything else): passed as it is | **Exact expected code**, computed before the parse: a file over 64 KiB, or text the harness's own **armour grammar** rejects, must be `MALFORMED_KEY`. The grammar is pm's own (ADR 0013, SR-062), not OpenSSH's (see below): BEGIN at offset 0 then a line break; the first END preceded by a line break and followed only by CR/LF; a body of alphabet, `=` and CR/LF; base64 length a multiple of 4, `=` only as final padding, zero unused bits. Otherwise a **header model** reads magic, cipher, kdf, kdf options, key count, the two outer strings, block size, check integers and type, and names the one code the parser must raise (`ENCRYPTED_KEY` for a cipher other than `none`, `UNSUPPORTED_KEY` for another key type, `MALFORMED_KEY` for the rest). Past the header the parser may only accept or raise `MALFORMED_KEY`, and a binary equal to a valid seed key must be accepted. Also: limits written in the harness (file ≤ 64 KiB, comment ≤ 4096 UTF-8 bytes with no control/format/separator characters, type ≤ 64 bytes, public blob exactly 51 or 104 bytes, from ADR 0013 and RFC 8709/5656); the message is the code name alone; the caller's buffer is unchanged; allocation ≤ 4 MiB + 512 B per input byte per call; and a round trip: `OpenSshFormat.encode` of the parsed key, read back through the strict grammar, equals the grammar's binary except the two random check integers, and parses to the same type, comment and blob |
| `pm.fuzz.AgentReplyFuzzTest` (T-FUZZ-SSH) | The real `SshAgentClient` through its public API (`list` or `removeAll`, picked by byte 0) against a fake agent on a Unix socket in an owner-only `@TempDir`. No thread: the client's connect completes from the listen backlog, then the harness accepts, writes the reply non-blocking (1 MiB send buffer), records exactly what was sent, and shuts its output. The reply is raw bytes (optionally stretched) or a **frame near a limit** (`'#'` mode, signed delta, unit): mode 0 counts `1024 + delta` identities, each a copy of the unit; mode 1 is a complete answer of exactly `256 KiB + delta` bytes, filled with identities at the blob and comment limits; modes 2 and 3 are a header claiming `1 MiB + delta` or `256 KiB + delta` bytes followed only by the unit | Differential: the outcome (identities, `AGENT_REFUSED` or `BAD_REPLY`) equals `reference`, a separate reading of the ADR 0013 wire format with the limits written in the harness: frames 1 B to 256 KiB, ≤ 1024 identities, blob ≤ 16 KiB whose first string is ≤ 64 bytes, comment ≤ 4096 bytes, no trailing bytes, and exactly one byte for success or failure (a FAILURE with trailing bytes is `BAD_REPLY` for `list` too). Comments and types are sanitised by the reference's own rule. No other exception and no other code: a `TIMEOUT` would mean the client hung on a reply that had already ended. Every printed field is free of control, format and separator characters. Allocation, measured around the client call alone, is ≤ 512 KiB (one 256 KiB frame plus 256 KiB) + 64 B per byte sent, so a buffer sized from a 1 MiB header followed by one byte fails it |
| `pm.domain.health.BreachRangeFuzzTest` (T-FUZZ-BREACH) | `BreachClient.match` (package-private) on the body of a range response, and the production collector `BreachClient.boundedBody()` (the 1 MiB subscriber `fetch` uses; package-private accessor added at M4.5) fed the same bytes in input-chosen chunks. Bodies may be stretched to 1 MiB + 1 | Differential against a regex reading of ADR 0012 §8: each line is 35 uppercase hex characters, `:`, then 1 to 18 digits, with an optional CR. Blank lines are skipped, a body with no lines is `MALFORMED`, and the result is the largest count on a matching line. The collector returns exactly the bytes when they are ≤ 1 MiB (written in the harness) and fails with `BodyTooLarge` when they are not. Only `MALFORMED`. The suffix buffer is zero-filled on every path. Allocation is ≤ 1 MiB + 4 × body |

**Limits beyond libFuzzer's 4096-byte inputs.** The 64 KiB file, 16 KiB blob, 256 KiB frame and
1 MiB body limits cannot be reached with raw 4 KiB inputs. All three harnesses therefore accept a
*stretched* input (`pm.fuzz.Stretch`): `'+' u16 offset, u24 count, u8 fill, rest`. This inserts
`count` fill bytes into `rest` at `offset`, so the fuzzer picks a length header and the size of the
body behind it independently. The agent harness also has the frame-near-a-limit mode above, so
1,024 and 1,025 identities, or a frame of exactly 256 KiB ± a few bytes, are one mutation of a
5-byte input apart. The limits are also pinned deterministically, at and one past each value, in
the gate:
- `OpenSshKeyFuzzTest.limitsHoldAtAndJustPastTheirValues`: a 4096-byte comment is accepted and a
  4097-byte one refused; a file of exactly 64 KiB (a valid key padded with line breaks) is
  accepted and one of 64 KiB + 1 refused.
- `AgentReplyFuzzTest.limitsHoldAtAndJustPastTheirValues`: 1024/1025 identities, a 16 KiB / 16 KiB + 1
  blob, a 64/65-byte name, a 4096/4097-byte comment, and a frame of exactly 256 KiB against 256 KiB + 1.
  Each frame is checked to have been sent whole. This test is the only guard for an off-by-one on
  the agent comment limit: the re-verify planted `MAX_COMMENT_BYTES + 1` in `SshAgentClient`, and
  1,540,281 fuzz runs (121 s) did not reach a 4,097-byte comment, while this test failed.
- `BreachRangeFuzzTest.productionBodyLimitHoldsAtAndJustPastOneMebibyte`: the production 1 MiB
  collector, through `fuzz` with stretched bodies of 1 MiB and 1 MiB + 1, and fed directly.

**pm's grammar against OpenSSH.** The M4.5 re-verify ran `ssh-keygen -y` (OpenSSH 10.3p1) and
`SshKey.parse` on 12 real keys (Ed25519, ECDSA P-256/384/521, RSA 2048/3072, each plain and
encrypted) and variants of each. They agree on: re-wrapped lines (64, 70, 76 columns, one line),
trailing blank lines, unpadded base64, non-zero unused bits, `=` mid-string (all refused by both),
a BOM, leading blank lines and spaces after END (refused by both). pm is stricter than OpenSSH in
two places, which OpenSSH accepts and pm refuses as `MALFORMED_KEY`: a space or tab inside the
base64 body, and any bytes after the END line. pm is laxer in two, which OpenSSH refuses and pm
accepts: CR or CRLF line breaks, and no line break after END. The harness's oracle models pm's
grammar, so the 'lax variants' its sanity test refuses include these two OpenSSH-valid forms.

Each oracle is shown not to be vacuous by a deterministic test: `headerModelNamesTheExactCode`
(each header field changed on a valid key gives the code ADR 0013 assigns, and the parser
agrees), `armourGrammarAcceptsOpenSshArmourAndRefusesLaxVariants` and
`roundTripOracleCatchesAnAcceptedNonCanonicalFile`.

**Seeds** come from published test vectors only: the RFC 8032 §7.1 TEST 1 Ed25519 key and the RFC
6979 A.2.5 P-256 key. They are in binary form, so no armoured private key is committed (gitleaks).
They were generated by the script below. Duplicate, at-limit and over-limit seeds are included:
`two-keys.bin`, `stretch-comment-4096/4097.bin`, `duplicate-identity.bin`,
`count-over-limit.bin`, `stretch-frame-over-limit.bin`, `stretch-blob-at-limit.bin`,
`duplicate-suffix.txt`, `nineteen-digits.txt` and `over-body-limit.txt` (named for the earlier
512-byte harness limit; it is a 624-byte body within the production 1 MiB). The M4.5 review added
`armour-edit-{crlf,one-line}.bin` (accepted) and `armour-edit-{trailer,unpadded,noncanonical,end-mid-line}.bin`
(refused), and `count-1024.bin`, `count-1025.bin`, `frame-at-limit.bin`,
`frame-over-limit-by-one.bin`, `frame-claims-1MiB.bin` and `failure-trailing-byte.bin`. Each
harness's seed test checks that every seed ends in its labelled outcome. The `@BeforeAll` warm-ups
build their inputs in code and assert nothing, so a planted-bug run can withhold any seed.

**Real defects found.** Before the main-code fixes, the armour grammar oracle failed on three
inputs the parser accepted: unpadded base64, base64 with non-zero unused bits before the padding
(both taken by the JDK decoder, refused by OpenSSH's `b64_pton`), and an END line that did not
start a line. The review also found that `SshAgentClient.list` took a FAILURE reply with
trailing bytes as `AGENT_REFUSED`, where every other request requires a one-byte FAILURE, and that
the harness's reference agreed with it; the reference now refuses it. All three are fixed (`OpenSshFormat` re-encodes the decoded binary and requires an exact match,
and requires a line break before END; `list` requires a one-byte FAILURE), with regression tests
`SshKeyTest.refusesLaxBase64AndAnEndLineThatDoesNotStartALine` and
`SshAgentClientTest.malformedIdentityListsAreRejected`.

## How the runs were made

```sh
for t in pm.crypto.ssh.OpenSshKeyFuzzTest pm.fuzz.AgentReplyFuzzTest pm.domain.health.BreachRangeFuzzTest; do
  JAZZER_FUZZ=1 JAVA_HOME=/opt/homebrew/opt/openjdk@21 ./gradlew --no-daemon --console=plain \
    -Dorg.gradle.java.installations.paths=/opt/homebrew/opt/openjdk@21 \
    :modules:pm-fuzz:test --tests "$t.fuzz"
done
```

- The `@FuzzTest` default `maxDuration` of 5 minutes bounds each campaign run. Planted-bug runs
  set `maxDuration = "2m"` on the `fuzz` method for the run and cleared it afterwards. Each run
  started from the committed seeds only, with no corpus carried over.
- `modules/pm-fuzz/build.gradle.kts` adds `pm.crypto.**` to `jazzer.instrument`, so
  `pm.crypto.ssh` gets coverage feedback (pm-crypto reaches pm-fuzz as a jar).
- Environment: Jazzer 0.24.0 (jazzer-junit), OpenJDK 21.0.12.1, macOS 27.0 arm64, one fuzzing
  process, on a machine shared with other builds.
- After each run the generated corpus (`modules/pm-fuzz/.cifuzz-corpus/`, gitignored) and any
  finding file were deleted, not committed.
- A first attempt at this campaign (2026-10-04) is not counted: the machine slept during the
  OpenSshKey run, which then reported 66,157 s and wrote one `slow-unit` file, and a reboot
  ended the AgentReply run. The slow unit (a 4 KiB-comment key) replays in 2 ms in regression
  mode.

## Results (2026-10-05, CDT, UTC−5)

| Harness | Ended | Duration | Executions | exec/s (libFuzzer) | Edges (cov) | Features (ft) | Corpus at end | Crashes | Gradle |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OpenSshKey | 09:34:55 | 301 s | 1,170,913 | 3,890 | 518 → 609 | 859 → 1283 | 153 / 16047 B | 0 | exit 0 |
| AgentReply | 09:24:29 | 301 s | 3,969,400 | 13,187 | 335 → 371 | 579 → 1030 | 109 / 3303 B | 0 | exit 0 |
| BreachRange | 09:29:36 | 301 s | 76,632 | 254 | 127 → 157 | 235 → 471 | 53 / 3240 B | 0 | exit 0 |
| **Total** | | **903 s** | **5,216,945** | | | | | **0** | |

No `crash-*`, `timeout-*` or `oom-*` file was written, and the JUnit reports had 0 failures and 0
errors. The OpenSshKey row ran on the harness as it was before the gate's static-analysis fixes
(`Optional` in place of null, `ConstantTime.equals` in place of `Arrays.equals`, renamed fields;
no oracle changed). It was made with `--rerun`, because Gradle had reported the batch's first
attempt up to date.

The OpenSshKey campaign was repeated on the final harness at 09:42, but the laptop lid was closed
during it. `pmset -g log` shows a clamshell sleep at 09:43:36 for 38 s, then a maintenance sleep at
09:44:29 for 902 s. The run reported 510,132 executions in 1,043 s and 0 crashes, about 100 s of it
awake, and two `slow-unit` files of 37 s and 901 s, which match the two sleeps. Both were deleted.
This run counts as a crash-free smoke run of the final harness, not as a 5-minute campaign.

Earlier runs, not counted above:
- **The first M4.5 commit's campaign** (2026-10-04, first harnesses): 1,075,585 + 6,182,269 +
  21,453,791 executions, 0 crashes. Its harnesses missed 4 of the review's 9 plants (see below).
- **OpenSshKey, 2026-10-04 01:10, a false positive.** After 15,262 executions, the allocation
  oracle (then a flat 4 MiB) fired on a stretched 24 KiB-binary key: 4,856,616 bytes. Replaying
  the same file without fuzzing (regression mode, no instrumentation) passed under the same
  4 MiB bound. The allocation came from Jazzer's per-comparison instrumentation over the 32 KiB
  armoured text, not from the parser. The bound now grows by 512 B per input byte, at most
  36 MiB for a 64 KiB file, which still catches any buffer sized from a hostile `uint32` (up to
  4 GiB) and any quadratic work. The agent bound has a per-byte term too (64 B).

Reading the numbers:
- **Coverage is small and saturates fast.** These parsers are small, which is why the edge counts
  are low. Five minutes per harness is a smoke-level campaign, not an exhaustive one. A longer
  run, like M2's open 24 CPU-hour item, uses the same command line.
- **BreachRange is now the slowest, at about 250 exec/s.** Every input can stretch to a 1 MiB body
  (the production cap), and each body goes through the regex reference, `match` and the
  production collector. The first harness ran 21 M executions in 5 minutes on bodies under
  4 KiB, but it never exercised the production cap. Both D plants were still found within
  21,000 executions.
- **OpenSshKey runs at about 3,900 exec/s.** Every accepted mutation does a real Ed25519 or P-256
  probe signature and a full re-encode and re-parse.
- **Not fuzzed here:** connecting to the agent socket and checking its owner and mode
  (`SshAgentClient.connect` path checks, covered by `SshAgentClientTest`), the HTTP layer of the
  breach client (`BreachClientTest`, loopback server), and `ssh-agent` request encoding (the client
  only writes fixed-shape requests).

## Planted-bug proofs

These are the 9 bugs the M4.5 review planted in main code. Only A3's diff was given verbatim; the
others were reconstructed from the review's plant names and are listed exactly as run. Each was
applied, fuzzed for up to 2 minutes (`fuzz` method only, `maxDuration = "2m"`), and reverted from a
saved copy; the finding file and the corpus were deleted. After each run, `git status` showed only
this phase's own changes under `modules/pm-crypto/src/main` and `modules/pm-domain/src/main`, and
the main files hashed the same before and after. Every plant was first run with all seeds, as the
review ran it. Where a committed seed trips a plant directly, the plant was run again with those
seeds moved out, so the finding comes from mutation alone. The `@BeforeAll` warm-ups build their
own inputs, so withholding a seed never breaks them.

Runs on 2026-10-05, CDT: the agent and breach plants at 09:18–09:19, and the key-file plants at
09:41–09:42, on the final `OpenSshKeyFuzzTest` (it was re-run after the gate's static-analysis fixes
to the harness: `Optional` instead of null, `ConstantTime.equals` and renamed fields; the verdicts
before those fixes, at 09:17–09:19, were the same).

| ID | Planted bug | Review (first harnesses) | All seeds | Seeds withheld | Mutation only |
| --- | --- | --- | --- | --- | --- |
| A1 | `OpenSshFormat`: check integers not compared (`check1 != check2 && check1 < 0`) | caught | **caught** after 1,562 runs: header model, "check integers or key type string ==> expected MALFORMED_KEY but was UNSUPPORTED_KEY" | none trip it | (same run) |
| A2 | `OpenSshFormat`: `r.expectEnd()` removed, so bytes after the private section are accepted | caught | **caught** after 93 runs: header model, "outer strings, trailing bytes or block size ==> expected MALFORMED_KEY but was UNSUPPORTED_KEY" | none trip it | (same run) |
| A3 | `OpenSshFormat`: any ASCII byte accepted after the END line (`!isNewline(text[i]) && text[i] < 0`, the review's diff) | **missed** | **caught** by seed `armour-edit-trailer.bin` (4 runs): armour grammar, "accepted, expected MALFORMED_KEY" | `armour-edit-trailer.bin` | **caught** after 169 runs: armour grammar |
| B1 | `OpenSshFormat`: a cipher other than `none` no longer gives `ENCRYPTED_KEY` (`&& cipher.isEmpty()`) | **missed** | **caught** by seed `encrypted-header.bin` (10 runs): header model, "cipher aes256-ctr ==> expected ENCRYPTED_KEY but was MALFORMED_KEY" | `encrypted-header.bin` | **caught** after 242 runs: the cipher `none` mutated to `n\tne`, the same assertion |
| C1 | `SshAgentClient`: identity cap off by one (`n > MAX_IDENTITIES + 1`) | **missed** | **caught** by seed `count-1025.bin` (13 runs): differential | `count-1025.bin`, `count-over-limit.bin` | **caught** after 95,356 runs (6 s): a 16-byte frame-mode input, 1,025 identities accepted where the reference says `BAD_REPLY` |
| C2 | `SshAgentClient`: frame limit removed (`if (n == 0)`) | caught | **caught** by seeds `frame-claims-1MiB.bin` (allocation) and `frame-over-limit-by-one.bin` (differential), 2 runs | those two and `stretch-frame-over-limit.bin` | **caught** after 18 runs: allocation 84,678,048 B against a 524,672 B ceiling |
| C2b | `SshAgentClient`: frame limit raised to 1 MiB (`MAX_MESSAGE = 1024 * 1024`) | **missed** | **caught** by the same two seeds, 2 runs | the same three | **caught** after 203 runs: allocation 532,752 B against a 525,120 B ceiling |
| D1 | `BreachClient`: last suffix character not checked (`i < colon - 1`) | caught | **caught** after 7,116 runs: differential | none trip it | (same run) |
| D2 | `BreachClient`: `-` accepted among the count digits | caught | **caught** after 20,982 runs: differential | none trip it | (same run) |

All 9 caught with all seeds, and all 9 caught by mutation alone. Notes:
- **C2b's allocation margin is thin.** The ceiling is 512 KiB plus 64 B per byte sent, so a header
  claiming more than about 520 KiB trips it. A header between 256 KiB + 1 and about 512 KiB that
  is followed by a truncated body is not detected by either oracle, because the reference and the
  planted client both answer `BAD_REPLY` and the buffer fits under the ceiling. A *complete*
  frame over 256 KiB is caught by the differential (`frame-over-limit-by-one.bin`; frame mode 1
  with a positive delta), and that seed is replayed in the gate.
- A first round of the same 14 runs was made on 2026-10-04, before a reboot cleared the run logs.
  It gave the same verdicts. For example, C1 with seeds withheld was caught after 79,162 runs,
  and C2b after 436 runs at 529,680 B.

## Seed script

Run as `python3 seeds.py modules/pm-fuzz/src/test/resources` (verbatim):

```python
# Writes the M4.5 fuzz seeds under modules/pm-fuzz/src/test/resources. Keys are published test
# vectors only (RFC 8032 §7.1 TEST 1, RFC 6979 A.2.5), not credentials.
import os
import struct
import sys

RES = sys.argv[1]


def u32(n):
    return struct.pack('>I', n)


def s(b):
    if isinstance(b, str):
        b = b.encode()
    return u32(len(b)) + b


MAGIC = b'openssh-key-v1\0'
ED_SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
ED_PUB = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
EC_D = bytes.fromhex('00c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721')
EC_Q = bytes.fromhex('04' '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6'
                     '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299')
ED_BLOB = s('ssh-ed25519') + s(ED_PUB)
EC_BLOB = s('ecdsa-sha2-nistp256') + s('nistp256') + s(EC_Q)


def keyfile(blob, fields, comment, cipher='none', kdf='none', check=0x5eed5eed):
    priv = u32(check) + u32(check) + fields + s(comment)
    i = 1
    while len(priv) % 8:
        priv += bytes([i])
        i += 1
    return MAGIC + s(cipher) + s(kdf) + s(b'') + u32(1) + s(blob) + s(priv)


def w(d, name, data):
    os.makedirs(os.path.join(RES, d), exist_ok=True)
    with open(os.path.join(RES, d, name), 'wb') as f:
        f.write(data)


K = 'pm/crypto/ssh/OpenSshKeyFuzzTestInputs'
ed_fields = s('ssh-ed25519') + s(ED_PUB) + s(ED_SEED + ED_PUB)
ec_fields = s('ecdsa-sha2-nistp256') + s('nistp256') + s(EC_Q) + s(EC_D)
w(K, 'ed25519-rfc8032.bin', keyfile(ED_BLOB, ed_fields, 'rfc8032 test 1'))
w(K, 'ecdsa-p256-rfc6979.bin', keyfile(EC_BLOB, ec_fields, 'rfc6979 a.2.5'))
w(K, 'ed25519-no-padding.bin', keyfile(ED_BLOB, ed_fields, 'rfc8032 test'))
w(K, 'encrypted-header.bin',
  MAGIC + s('aes256-ctr') + s('bcrypt') + s(b'\0' * 24) + u32(1) + s(ED_BLOB) + s(b'\0' * 16))
w(K, 'unsupported-rsa.bin', keyfile(s('ssh-rsa') + s(b'\1\0\1'), s('ssh-rsa') + s(b'\1\0\1'), 'rsa'))
w(K, 'armour-short.txt', b'-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n')

A = 'pm/fuzz/AgentReplyFuzzTestInputs'
LIST, SIMPLE = b'\0', b'\1'
w(A, 'two-identities.bin', LIST + s(bytes([12]) + u32(2) + s(ED_BLOB) + s('rfc8032 test 1')
                                    + s(EC_BLOB) + s('rfc6979 a.2.5')))
w(A, 'no-identities.bin', LIST + s(bytes([12]) + u32(0)))
w(A, 'list-refused.bin', LIST + s(bytes([5])))
w(A, 'unsafe-comment.bin', LIST + s(bytes([12]) + u32(1) + s(ED_BLOB) + s('a\x1b[31m‮b'.encode())))
w(A, 'trailing-byte.bin', LIST + s(bytes([12]) + u32(0) + b'\0'))
w(A, 'success.bin', SIMPLE + s(bytes([6])))
w(A, 'failure.bin', SIMPLE + s(bytes([5])))
w(A, 'oversized-frame.bin', LIST + u32(256 * 1024 + 1) + bytes([12]))

B = 'pm/domain/health/BreachRangeFuzzTestInputs'
HIT = '1E4C9B93F3F0682250B6CF8331B7EE68FD8'
w(B, 'hit-crlf.txt', ('0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n' + HIT
                      + ':9545824\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n').encode())
w(B, 'padding-only.txt', ('0018A45C4D1DEF81644B54AB7F969B88D65:0\n' + HIT + ':0\n').encode())
w(B, 'miss-no-final-newline.txt',
  '0018A45C4D1DEF81644B54AB7F969B88D65:3\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:17'.encode())
w(B, 'lowercase.txt', (HIT.lower() + ':1\n').encode())
w(B, 'nineteen-digits.txt', (HIT + ':1234567890123456789\n').encode())
w(B, 'blank-lines.txt', b'\r\n\n\r\n')


# Seeds added after the M3.7 review: duplicates and over-limit cases. Stretched inputs are
# '+' u16 offset, u24 count, u8 fill, rest (pm.fuzz.Stretch): count fill bytes inserted at offset.
def stretch(offset, count, rest, fill=0):
    return b'+' + struct.pack('>H', offset) + struct.pack('>I', count)[1:] + bytes([fill]) + rest


def ed_stretched_comment(n):
    # A well-formed key whose comment is n letters 'c': the file is built in full, then all but
    # the first letter is cut out and given back by the stretch.
    f = keyfile(ED_BLOB, ed_fields, b'c' * n)
    at = f.rindex(s(b'c' * n)) + 4 + 1
    return stretch(at, n - 1, f[:at] + f[at + n - 1:], ord('c'))


w(K, 'two-keys.bin', MAGIC + s('none') + s('none') + s(b'') + u32(2) + s(ED_BLOB) + s(EC_BLOB) + s(b'\0' * 8))
w(K, 'stretch-comment-4097.bin', ed_stretched_comment(4097))
w(K, 'stretch-comment-4096.bin', ed_stretched_comment(4096))

ident = s(ED_BLOB) + s('dup')
w(A, 'duplicate-identity.bin', LIST + s(bytes([12]) + u32(2) + ident + ident))
w(A, 'count-over-limit.bin', LIST + s(bytes([12]) + u32(1025) + ident))
# A frame header one past 256 KiB, its body a zero run the stretch supplies in full.
w(A, 'stretch-frame-over-limit.bin', LIST + stretch(5, 256 * 1024, u32(256 * 1024 + 1) + bytes([12])))
# One identity whose blob is exactly 16 KiB (its name, then zeros), the frame sized to match.
blob_head = s('ssh-ed25519')
body_len = 1 + 4 + 4 + 16384 + 4
w(A, 'stretch-blob-at-limit.bin', LIST + stretch(4 + 1 + 4 + 4 + len(blob_head), 16384 - len(blob_head),
                                                 u32(body_len) + bytes([12]) + u32(1) + u32(16384) + blob_head + u32(0)))

w(B, 'duplicate-suffix.txt', (HIT + ':5\r\n' + HIT + ':7\r\n').encode())
w(B, 'over-body-limit.txt', ('0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n' * 16).encode())


# Seeds added after the M4.5 review. Armour-edit inputs are 'A' u8 key, u8 line length, then
# 4-byte edits u16 position (top bit: from the end), u8 op, u8 value (OpenSshKeyFuzzTest.edited).
import base64
BEGIN = '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----'
END = '-----END OPENSSH ' + 'PRIVATE KEY-----'
ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
VALID_KEYS = [keyfile(ED_BLOB, ed_fields, 'rfc8032 test 1'), keyfile(EC_BLOB, ec_fields, 'rfc6979 a.2.5')]


def armour_text(key, line):
    b = base64.b64encode(VALID_KEYS[key]).decode()
    step = line or len(b)
    return (BEGIN + '\n' + ''.join(b[i:i + step] + '\n' for i in range(0, len(b), step)) + END + '\n').encode()


def edit(pos, op, val, from_end=False):
    return struct.pack('>H', pos | (0x8000 if from_end else 0)) + bytes([op, val & 0xff])


def armour_input(key, line, edits=b''):
    return b'A' + bytes([key, line]) + edits


# Each CRLF edit inserts '\r' before an LF, last first so earlier positions stay put.
t = armour_text(1, 64)
crlf = b''.join(edit(i, 0, 13) for i in reversed([i for i, c in enumerate(t) if c == 10]))
w(K, 'armour-edit-crlf.bin', armour_input(1, 64, crlf))
w(K, 'armour-edit-one-line.bin', armour_input(0, 0))
w(K, 'armour-edit-trailer.bin', armour_input(0, 70, edit(0, 4, ord('x'))))
k = len(END) + 3  # from the end: final LF, END, LF before it, then the last '='
t = armour_text(0, 70)
assert t[len(t) - k] == ord('=') and t[len(t) - k - 1] == ord('=')
w(K, 'armour-edit-unpadded.bin', armour_input(0, 70, edit(k, 1, 0, True) + edit(k, 1, 0, True)))
before = t[len(t) - k - 2]
w(K, 'armour-edit-noncanonical.bin', armour_input(0, 70, edit(k + 2, 6, ALPHA.index(chr(before)) | 1, True)))
w(K, 'armour-edit-end-mid-line.bin', armour_input(0, 70, edit(len(END) + 2, 1, 0, True)))

# Frames near a limit: '#' u8 mode, i8 delta, unit (AgentReplyFuzzTest.frame). The unit is the
# smallest identity: a 4-byte blob naming an empty type, and an empty comment.
MIN_ID = u32(4) + u32(0) + u32(0)


def near(mode, delta, unit):
    return LIST + b'#' + bytes([mode, delta & 0xff]) + unit


w(A, 'count-1024.bin', near(0, 0, MIN_ID))
w(A, 'count-1025.bin', near(0, 1, MIN_ID))
w(A, 'frame-at-limit.bin', near(1, 0, MIN_ID))
w(A, 'frame-over-limit-by-one.bin', near(1, 1, MIN_ID))
w(A, 'frame-claims-1MiB.bin', near(2, 0, bytes([12])))
w(A, 'failure-trailing-byte.bin', LIST + s(bytes([5, 0])))
```
