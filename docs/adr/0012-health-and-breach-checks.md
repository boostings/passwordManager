# ADR 0012: Password generation, health checks and the breach client

- Status: Accepted
- Date: 2026-10-03

## Decision

### 1. Randomness (MSC02-J, SR-017, SR-060)
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

### 2. Character passwords (SR-061, SR-062)
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

### 3. Passphrases (SR-061, SR-063)
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

## Alternatives considered
- `SecureRandom.nextInt(bound)` directly: also unbiased, but would put `SecureRandom` outside
  pm-crypto (SR-017) and could not be replaced by a deterministic source in tests.
- Fixed slots for the required classes: biased, see §2.
- EFF large wordlist: preferred for memorability, not reproducible offline at the time; see §3.

## Consequences
The generators return `Generated(SecretChars, entropyBits)`; callers (CLI and TUI, M4.4) own and
close it. The entropy figure is the guessing cost for an attacker who knows the policy, not a
strength estimate of an arbitrary password.

## CERT rules referenced
MSC02-J, MSC03-J, IDS00-J, OBJ13-J.
