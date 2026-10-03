# ADR 0012: Password generation, health checks and the breach client

- Status: Accepted
- Date: 2026-10-03

## Decision

### 1. Randomness (MSC02-J, SR-017, SR-070)
Generators live in `pm.domain.generate` and read bytes only through `RandomSource`. Production
code uses `RandomSource.secure()`, which reads `pm.crypto.Csprng`, the one `SecureRandom` in the
codebase. Tests inject a fixed-seed HMAC-SHA256 counter-mode DRBG so the statistical tests are
reproducible. Nothing in `pm-domain` touches `java.security` (ArchUnit `onlyCryptoUsesJca`).

Every index is drawn by **rejection sampling** (`Uniform.below`): a 32-bit big-endian draw `x` is
accepted only below `2^32 - (2^32 mod n)`, the largest multiple of `n` that fits, and reduced
`x mod n`; anything at or above the limit is discarded and redrawn. Each of the `n` results then
has exactly the same number of preimages. Plain `x mod n` would favour the low residues; the test
`chiSquareDetectsModuloBias` shows the chi-square check catches that on a byte modulo 94. The
expected number of draws is below 2 for every `n`, and exactly 1 for powers of two such as the
8,192-word list.

### 2. Character passwords (SR-071, SR-072)
`PasswordPolicy(length 4..1024, classes, excludeAmbiguous)`. Classes are lowercase, uppercase,
digits and the 32 ASCII punctuation characters (94 printable characters in all). "Exclude
ambiguous" drops `0 O o 1 l I |` and the three quote characters (84 remain).

Each character is an independent uniform draw from the union of the chosen alphabets. A
candidate that lacks a chosen class is zero-filled and **discarded whole**, and a new candidate is
drawn. This keeps the output uniform over exactly the set of strings that satisfy the policy. The
common alternative, forcing one character per class into fixed or shuffled slots, is not uniform
over that set, and its entropy is harder to state honestly. The worst acceptance rate (length 4,
four classes, ambiguous excluded) is about 6%, so the loop costs at most a few dozen draws.

The reported entropy is `log2` of the exact number of valid passwords, counted by
inclusion-exclusion over the classes left out:
`sum over S of (-1)^|S| * (N - |S's characters|)^L`. The defaults (20 characters, all four classes)
give about 130.9 bits. Characters are written into a `char[]` that becomes a `SecretChars`
(ADR 0008); no `String` or growing buffer holds the password.

### 3. Passphrases (SR-071, SR-073)
`PassphrasePolicy(words 3..64, separator)`, where the separator is printable ASCII and not a
lowercase letter. Words are uniform draws from the bundled list; with 8,192 words each carries
exactly **13 bits**, and the separator adds none. The default of 6 words is 78 bits.

**Wordlist provenance.** The EFF large wordlist could not be reproduced reliably offline, so the
list is derived deterministically from `/usr/share/dict/web2` (Webster's Second International,
1934, public domain; SHA-256 of the source file used:
`be41ad97963bf8dabedd5871d5d691596175269d540956b0f9965a885c2bbab9`):

```sh
grep -E '^[a-z]{4,5}$' /usr/share/dict/web2 | LC_ALL=C sort -u \
  | grep -vxF -f modules/pm-domain/wordlist/excluded.txt \
  | awk '{w[NR-1]=$0} END{n=NR; for(i=0;i<8192;i++){print w[int(i*n/8192)]}}'
```

The pipeline is checked in as `modules/pm-domain/wordlist/build-wordlist.sh`. It keeps the 12,866
distinct all-lowercase four- and five-letter words (capitalised proper nouns drop out). It then
removes every word on the screening list `modules/pm-domain/wordlist/excluded.txt`: 186 slurs,
obscenities and sexual terms, 102 of which occur in the source, leaving 12,764. Finally it takes
8,192 words evenly spaced through the sorted remainder, so every initial letter is represented and
the count stays exactly 8,192 (13 bits). The committed resource
`modules/pm-domain/src/main/resources/pm/domain/generate/wordlist.txt` has SHA-256
`f7c69775d54405922e40f76f33856eb8fff104859572e556632fdc76aebd4c62`. `Wordlist` checks the size,
the word shape, strict sort order and uniqueness on load, so a damaged resource fails instead of
quietly lowering entropy.

Honest limits: many web2 words are obscure (`bedur`, `abmho`), so these passphrases are harder to
remember than EFF ones. That costs usability, not security: the 13 bits per word assume the
attacker knows the list. The screening is a best-effort word list, not a guarantee. Ordinary words
that have a slur sense (for example `spade`, `paddy`, `slope`) were kept, and new reports go into
`excluded.txt`, after which the list is rebuilt. Swapping in the EFF list
later (7,776 words, 12.92 bits each) only changes the resource, `SIZE` and `BITS_PER_WORD`.

### 4. Statistical acceptance (plan.md §13 M4)
With the fixed-seed DRBG: per-position and pooled chi-square over a single class (20,000
passwords of 12), per-class chi-square with all four classes (the at-least-one rule moves weight
between classes but leaves the characters inside a class equally likely), and chi-square over all
8,192 word indices plus 256 buckets per word position (30,000 six-word passphrases). Each statistic
must stay under the p = 0.0001 critical value (Wilson-Hilferty). A `SecureRandom` smoke test runs
both generators on the real source.

### 5. Weak passwords: a heuristic, not a guarantee (SR-075)
`StrengthMeter` estimates the guessing cost of a password the user typed. It is deliberately simple
and needs no new dependency (no zxcvbn). It works on Unicode code points, so an emoji or other
supplementary character is one symbol, not two UTF-16 units.

What is detected:

- **Pool.** Each code point costs log2 of the pool its classes span (lower 26, upper 26, digit 10,
  printable ASCII symbol 33, anything else 100).
- **Runs.** A code point that repeats the previous one, or continues a run, costs 1 bit. A run is
  alphabetic or numeric (`abc`, `987`), or a step along a US-QWERTY row or column in either
  direction (`qwe`, `zxc`, `1qaz`, `zaq1`, `m,./`). Shifted symbols count as their key, so
  `!QAZ@WSX` is a column walk. A run of 3 or more adds `REPEATED` or `SEQUENCE`.
- **Repeated unit.** If the whole password, ignoring ASCII case, is a shorter unit repeated
  (`acacac`, `Monkey!Monkey!Monkey!`, `PASSWORDpassword`), `REPEATED` is added and the cost is the
  unit plus log2 of the repeat count. This is found with a prefix-function (KMP) in linear time.
- **Common passwords.** A bundled list of 185 well-known passwords (sorted, `[a-z0-9]+`, checked on
  load) is used two ways, ignoring ASCII case and also after undoing `@4310$5!7+` to `aaeiossitt`:
  - `COMMON`: the whole password, or the whole password minus a trailing run of non-letters, is on
    the list. The estimate is capped at log2(185) + 3.3 bits per dropped character, and the rating
    is always `VERY_WEAK`.
  - `CONTAINS_COMMON`: any list entry of 4 or more characters appears as a substring. Each such
    span (longest match first, left to right) costs at most log2(185) in total. A list entry
    padded with enough random characters can still rate `STRONG`, because the padding carries
    real entropy.
  All lookups are binary searches over `int[]` code points, so no `String` of the password is built.
- **Other flags.** `SINGLE_CLASS` for one class only. `TOO_SHORT` for fewer than 10 code points,
  which caps the rating at `WEAK`.
- **Rating.** Under 30 bits `VERY_WEAK`, under 50 `WEAK`, under 70 `FAIR`, else `STRONG`. A
  password is *patterned* if it is a repeated unit, or if it has a `REPEATED`/`SEQUENCE` run and at
  least half its code points are predictable. A patterned password is never above `FAIR`. A short
  run that occurs by chance in a random password lowers only the bits. A deterministic test over
  400 generated secrets checks that the generators still rate `STRONG`.

Checked inputs (`StrengthMeterTest.structuredPasswordsAreNeverStrong`): `Password1!Password1!`,
`Monkey!Monkey!Monkey!`, `PASSWORDpassword`, `acacacacacacacacac`, `1qaz2wsx3edc4rfv`,
`zaq1xsw2cde3vfr4` and `!QAZ@WSX#EDC$RFV` are all below `STRONG`. Six emoji repeated is
`VERY_WEAK` with `REPEATED` and `TOO_SHORT`.

What is not detected: dictionary words, names, dates, years and phrases outside the 185-entry list.
Near-repeats (`Password1!Password2!`), non-QWERTY layouts, keyboard diagonals other than the
columns above, and l33t forms beyond the ten substitutions are also missed. All of these rate
higher than they deserve. The meter is a nudge for the health report, not an acceptance gate, and
the generator (§2, §3) is the real answer to a weak password. UTF-8 input is decoded with
replacement, and every working buffer (chars, code points, case-folded copies) is zero-filled.

### 6. Reused passwords: keyed tags, no plaintext map (SR-076)
`ReuseCheck` draws a fresh 32-byte key from `Csprng` per call and computes
HMAC-SHA-256(key, password) for each entry. Tags are bucketed by their first four bytes and
compared inside a bucket with `ConstantTime.equals`; groups are joined with union-find. No map,
set or list keyed by a password, its `String` or an unkeyed hash ever exists, so a heap dump
during the check yields tags that cannot be tested against a dictionary once the key is gone. The
key and every tag are zero-filled before return. Empty passwords (open Wi-Fi) are skipped. The
result is only lists of record ids, largest group first, in input order.

Constant-time comparison matters little here (the attacker does not choose the inputs or time the
call) but costs nothing, so the rule stays uniform with pm-crypto.

Unicode normalisation: reuse and breach checks both work on the stored UTF-8 bytes, without NFC
or NFKC normalisation. Two passwords that look the same but are encoded differently (precomposed
`é` against `e` + combining accent) count as different. That matches what a login form receives,
because sites compare bytes too. Normalising here would report reuse the sites themselves do not
see, and would hash a different string than the user's password for the breach check. Both
checks are exact by design.

### 7. Old passwords: injected clock (SR-077)
`AgeCheck` measures `clock.instant() - record.updated()` against a `Clock` passed in by the caller
(default threshold 365 days; strictly greater is old). A timestamp in the future counts as age 0,
so clock skew cannot flag or hide a record. Records have no separate password-changed time, so any
edit resets the age; this is noted as a limit, not hidden.

`HealthCheck` runs §5 to §7 over logins and Wi-Fi records, entirely offline. It never closes or
keeps the caller's secrets.

### 8. Breach check: k-anonymity range API, opt-in network (SR-074, SR-078, TM-70)
`BreachClient` implements the Pwned Passwords range protocol:

1. SHA-1 of the UTF-8 password, computed by `pm.crypto.Hash.sha1ForBreachRange` (SR-017 keeps the
   JCA in pm-crypto). SHA-1 is required by the service; it is used only as a lookup key and never
   for integrity or authentication, which is why FindSecBugs `WEAK_MESSAGE_DIGEST_SHA1` is ledgered
   as CE-015 for that one method.
2. Only the first 5 hex characters (20 bits) go on the wire: `GET {base}range/{PREFIX}`. The other
   35 are matched locally with `ConstantTime.equals` against each response line, and the suffix
   buffer is zero-filled afterwards. There are 1,048,576 prefixes and each real bucket holds
   hundreds of breached hashes, so the server learns only that the password's hash shares 20 bits
   with one bucket, not which entry (if any) matched.
3. `Add-Padding: true` is sent so every response is padded with count-0 lines to a similar size;
   that hides the bucket's real size from an on-path observer of response length. Padding lines are
   never a hit.
4. The response is parsed strictly: lines of exactly 35 uppercase hex, `:`, 1 to 18 digits, an
   optional CR. Anything else is `MALFORMED`. An empty body, or one of blank lines only, is also
   `MALFORMED`: a padded real response is never empty, and reading "no lines" as "not breached"
   would fail open. The body is collected by a bounded subscriber that cancels the exchange as
   soon as it would pass 1 MiB (`TOO_LARGE`). Errors carry a code only.

Network policy:
- Off unless invoked. Nothing in pm-domain calls `BreachClient`; `HealthCheck` is offline. A
  request happens only when a caller constructs a client and calls `occurrences`. The CLI and TUI
  (M4.4) must make this an explicit user action.
- HTTPS only, except `http` on loopback for tests. No user info, query or fragment in the base.
- Redirects are never followed (a 3xx is `HTTP_STATUS`), so the prefix cannot be bounced to
  another host. No cookies, no credentials, a fixed `User-Agent`.
- One deadline (default 10 s) covers the whole exchange: connect, headers and the complete body.
  The client waits on `sendAsync(...).get(timeout)` and cancels the exchange when it expires
  (`TIMEOUT`). `HttpRequest.timeout` alone bounds only the response headers, so a server that
  drips or stalls the body could otherwise hold the call open indefinitely.
  `BreachClientTest.oneDeadlineCoversHeadersAndTheWholeBody` checks that a 1-byte-per-100-ms drip
  and a stalled body each end with `TIMEOUT` in under 4 s with a 1 s deadline. `close()` aborts
  anything still running.
- The base URI is injected, so tests use a fake loopback server.

T-HEALTH-01 (`BreachClientTest`) runs that fake server, records every request (method, path,
query, headers, body), and asserts the server only ever sees `/range/` plus 5 uppercase hex
characters: no query, no body, and neither the full hash, the suffix, any 8 characters of it, nor
the password anywhere in the request.

What remains visible: the service and anyone on path at the TLS endpoint learn the time of the
check, the client's IP address and a 20-bit prefix. Repeated checks of the same password repeat
the prefix. That is the accepted cost of an opt-in check.

## Alternatives considered
- `SecureRandom.nextInt(bound)` directly: also unbiased, but would put `SecureRandom` outside
  pm-crypto (SR-017) and could not be replaced by a deterministic source in tests.
- Fixed slots for the required classes: biased, see §2.
- EFF large wordlist: preferred for memorability, not reproducible offline at the time; see §3.
- zxcvbn-style meter: better estimates, but a new dependency with its own dictionaries; §5 keeps a
  small, auditable heuristic.
- Reuse by plain `HashMap<String, …>` or an unkeyed SHA-256: simple, but leaves a dictionary-testable
  map of every password on the heap; rejected for §6.
- Sending the full hash, or checking against a downloaded corpus: the first leaks the password's
  hash; the second is ~30 GB and still needs a network fetch. The range API is the least-revealing
  online option.

## Consequences
The generators return `Generated(SecretChars, entropyBits)`; callers (CLI and TUI, M4.4) own and
close it. The entropy figure is the guessing cost for an attacker who knows the policy, not a
strength estimate of an arbitrary password.

`pm.domain` now `requires java.net.http`, used only by `BreachClient`. The health and breach APIs
are public and UI-free; M4.4 wires them to commands and must keep the breach check an explicit,
per-invocation action. `pm.crypto.Hash` gains one SHA-1 entry point whose name says what it is for.

## CERT rules referenced
MSC02-J, MSC03-J, IDS00-J, OBJ13-J, MSC00-J (TLS-only network), IDS01-J (strict response parsing), TPS02-J (interrupt status kept).
