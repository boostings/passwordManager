# Password Manager Project Rules

This file selects the project-applicable rules from [`RULES.md`](RULES.md), using the classifications in [`docs/security/cert-applicability.md`](docs/security/cert-applicability.md). Enforced and Review-only rules are included; rules classified Not applicable are omitted. Rule guidance and risk summaries come from `RULES.md`; project status and implementation notes come from the applicability table. Each rule links to one representative source location. Some rules prohibit patterns, so a single line is illustrative and does not by itself prove repository-wide absence.

Applicable rules: 145 (Enforced: 72; Review-only: 73).

## Rules

### [IDS01-J. Normalize strings before validating them](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Normalize Unicode input before applying validation or blacklist/allowlist checks. Validate the same canonical representation that will be stored, compared, or interpreted so equivalent spellings cannot bypass the check.
**Risk:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [Cli.java:141](modules/pm-cli/src/main/java/pm/cli/Cli.java#L141) - representative project code for this rule family.

### [IDS03-J. Do not log unsanitized user input](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids03-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.FIO13-J.log-secret; redacting logger (SR-500)
**Rule guidance:** Sanitize and validate untrusted text before logging it; neutralize CR/LF and other record/control delimiters, prefer structured logging, and keep sensitive fields out of the log altogether.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [Cli.java:141](modules/pm-cli/src/main/java/pm/cli/Cli.java#L141) - representative project code for this rule family.

### [IDS04-J. Safely extract files from ZipInputStream](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids04-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.FIO03-J.temp-file + SafePath in pm-storage (SR-700); T-BKP-01
**Rule guidance:** For every ZipEntry, canonicalize the destination under a trusted extraction root and reject absolute paths, traversal, and unsafe link-like entries before writing. Create directories and files with secure permissions.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [Cli.java:141](modules/pm-cli/src/main/java/pm/cli/Cli.java#L141) - representative project code for this rule family.

### [IDS06-J. Exclude unsanitized user input from format strings](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids06-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Keep format strings constant and pass user data only as ordinary formatting arguments after validation. Never let untrusted text supply conversion directives that can leak data or trigger denial of service.
**Risk:** Severity=Medium; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [Cli.java:141](modules/pm-cli/src/main/java/pm/cli/Cli.java#L141) - representative project code for this rule family.

### [IDS07-J. Sanitize untrusted data passed to the Runtime.exec() method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids07-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.IDS07-J.runtime-exec / processbuilder-outside-approval; ArchUnit onlyTheEnvRunnerSpawnsProcesses
**Rule guidance:** Treat command and argument data as untrusted. Prefer an allowlisted executable plus a ProcessBuilder argument list, validate each argument, and never build a shell command from concatenated input.
**Risk:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
**Example:** [Cli.java:141](modules/pm-cli/src/main/java/pm/cli/Cli.java#L141) - representative project code for this rule family.

### [IDS08-J. Sanitize untrusted data included in a regular expression](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids08-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not splice untrusted text into regex syntax. Quote literal input with Pattern.quote or use a strict allowlist/fixed pattern, and bound regex complexity and input size to resist regex denial of service.
**Risk:** Severity=Medium; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [Cli.java:141](modules/pm-cli/src/main/java/pm/cli/Cli.java#L141) - representative project code for this rule family.

### [IDS11-J. Perform any string modifications before validation](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids11-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Perform every decoding, normalization, filtering, and transformation before the final validation. Do not modify a value after it has passed a security check, because the transformation can create a dangerous sequence.
**Risk:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [Cli.java:141](modules/pm-cli/src/main/java/pm/cli/Cli.java#L141) - representative project code for this rule family.

### [IDS15-J. Do not allow sensitive information to leak outside a trust boundary](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids15-j)

**Project status:** Enforced
**Project applicability:** ArchUnit module boundaries; logger type check; certReport
**Rule guidance:** Stub page. Do not let sensitive data or capabilities cross from one trust domain to another without an explicit, minimized, authorized, and appropriately protected interface; apply the specialized rules it references.
**Risk:** Not stated in the family risk summary
**Example:** [Cli.java:141](modules/pm-cli/src/main/java/pm/cli/Cli.java#L141) - representative project code for this rule family.

### [DCL00-J. Prevent class initialization cycles](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl/dcl00-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Avoid cycles among static field initializers and static initialization blocks. Make initialization dependencies explicit or lazy so loading one class cannot recursively wait on another class that is waiting back.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [CborReader.java:44](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L44) - representative project code for this rule family.

### [DCL01-J. Do not reuse public identifiers from the Java Standard Library](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl/dcl01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not give application classes, packages, or public identifiers names that shadow public Java Standard Library types. Prefer names that make the owning package and type unambiguous.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [CborReader.java:44](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L44) - representative project code for this rule family.

### [DCL02-J. Do not modify the collection's elements during an enhanced for statement](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl/dcl02-j)

**Project status:** Enforced
**Project applicability:** Error Prone ModifyCollectionInEnhancedForLoop; PMD
**Rule guidance:** Do not mutate collection elements through an enhanced-for traversal in a way that obscures or violates the collection's iteration contract. Use a deliberate iterator, index-based update, or separate transformation pass.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [CborReader.java:44](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L44) - representative project code for this rule family.

### [EXP00-J. Do not ignore values returned by methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp00-j)

**Project status:** Enforced
**Project applicability:** Error Prone CheckReturnValue (error)
**Rule guidance:** Inspect and act on method return values, especially boolean, status, count, and result values that signal failure or changed behavior. Do not confuse a getter-like status method with the operation that performs the change.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [Vault.java:247](modules/pm-vault/src/main/java/pm/vault/Vault.java#L247) - representative project code for this rule family.

### [EXP01-J. Do not use a null in a case where an object is required](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not pass null where an object is required. Establish non-null preconditions at the boundary or use an API that explicitly models absence, rather than relying on a later NullPointerException.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=No; Repairable=Yes; Priority=P6; Level=L2
**Example:** [Vault.java:247](modules/pm-vault/src/main/java/pm/vault/Vault.java#L247) - representative project code for this rule family.

### [EXP02-J. Do not use the Object.equals() method to compare two arrays](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp02-j)

**Project status:** Enforced
**Project applicability:** Error Prone ArrayEquals (error)
**Rule guidance:** Use Arrays.equals or Arrays.deepEquals for array-content equality; reserve == and != for reference identity. Object.equals on an array does not compare its elements.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=Yes; Priority=P9; Level=L2
**Example:** [Vault.java:247](modules/pm-vault/src/main/java/pm/vault/Vault.java#L247) - representative project code for this rule family.

### [EXP03-J. Do not use the equality operators when comparing values of boxed primitives](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp03-j)

**Project status:** Enforced
**Project applicability:** Error Prone BoxedPrimitiveEquality (error); PMD CompareObjectsWithEquals
**Rule guidance:** Compare boxed primitive values by unboxing or equals, not with == or !=. Reference identity may appear to work for cached wrapper values and then fail for other values.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=Yes; Priority=P9; Level=L2
**Example:** [Vault.java:247](modules/pm-vault/src/main/java/pm/vault/Vault.java#L247) - representative project code for this rule family.

### [EXP04-J. Do not pass arguments to certain Java Collections Framework methods that are a different type than the collection parameter type](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp04-j)

**Project status:** Enforced
**Project applicability:** Error Prone CollectionIncompatibleType (error)
**Rule guidance:** For collection methods whose signatures accept Object, pass keys and lookup arguments compatible with the collection's generic element/key type. Do not rely on a permissive API signature to hide a type mistake.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L2
**Example:** [Vault.java:247](modules/pm-vault/src/main/java/pm/vault/Vault.java#L247) - representative project code for this rule family.

### [EXP05-J. Do not follow a write by a subsequent write or read of the same object within an expression](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp05-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Deprecated page. Keep reads and writes to the same object out of ambiguous side-effecting expressions; use separate statements so sequencing and the value being observed are explicit.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [Vault.java:247](modules/pm-vault/src/main/java/pm/vault/Vault.java#L247) - representative project code for this rule family.

### [EXP06-J. Expressions used in assertions must not produce side effects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp06-j)

**Project status:** Enforced
**Project applicability:** Error Prone AssertionFailureIgnored; assertions disabled in release
**Rule guidance:** Assertion expressions must be side-effect free because assertions may be disabled. Put required validation, mutation, logging, and state changes in ordinary code outside assert.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=Yes; Priority=P3; Level=L3
**Example:** [Vault.java:247](modules/pm-vault/src/main/java/pm/vault/Vault.java#L247) - representative project code for this rule family.

### [EXP07-J. Prevent loss of useful data due to weak references](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp07-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Stub page. Do not allow weak references or reachability assumptions to discard data that the program still needs. Retain a strong owner for useful state and handle reclamation explicitly.
**Risk:** Not stated in the family risk summary
**Example:** [Vault.java:247](modules/pm-vault/src/main/java/pm/vault/Vault.java#L247) - representative project code for this rule family.

### [NUM00-J. Detect or prevent integer overflow](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num00-j)

**Project status:** Enforced
**Project applicability:** Error Prone IntLongMath, NarrowingCompoundAssignment; SpotBugs
**Rule guidance:** Check or prevent integer overflow/underflow before arithmetic that can exceed the type range. Use range checks, exact Math methods, BigInteger, or a type with sufficient capacity.
**Risk:** Severity=Medium; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM01-J. Do not perform bitwise and arithmetic operations on the same data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Give an integer variable one clear meaning: numeric quantity or bit set. Keep arithmetic and bitwise operations separate so a bit trick cannot silently change a numeric value or obscure intent.
**Risk:** Severity=Medium; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM02-J. Ensure that division and remainder operations do not result in divide-by-zero errors](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num02-j)

**Project status:** Enforced
**Project applicability:** SpotBugs; PMD
**Rule guidance:** Check an integer divisor for zero before / or %. This rule does not require the same check for floating-point division, whose exceptional values have different semantics.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=No; Repairable=Yes; Priority=P6; Level=L2
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM03-J. Use integer types that can fully represent the possible range of unsigned data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num03-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Represent unsigned values in a Java type wide enough for their complete range, especially at native-language boundaries. For example, use long when storing an unsigned 32-bit value.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM04-J. Do not use floating-point numbers if precise computation is required](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num04-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Deprecated page. Do not use floating-point arithmetic where exact decimal/integer computation is required; use integer scaling, BigDecimal, or another exact representation.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM07-J. Do not attempt comparisons with NaN](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num07-j)

**Project status:** Enforced
**Project applicability:** PMD BadComparison; Error Prone
**Rule guidance:** Test NaN with isNaN rather than <, <=, >, >=, ==, or !=. NaN is unordered and ordinary comparisons do not express a valid NaN check.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM08-J. Check floating-point inputs for exceptional values](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num08-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Validate floating-point inputs and intermediate results for NaN, positive infinity, and negative infinity using the appropriate API before they influence control flow, limits, or persisted state.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=Yes; Priority=P4; Level=L3
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM09-J. Do not use floating-point variables as loop counters](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num09-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Use an integral counter for loop induction. Floating-point rounding can skip the termination value or accumulate error, producing incorrect or nonterminating loops.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM10-J. Do not construct BigDecimal objects from floating-point literals](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num10-j)

**Project status:** Enforced
**Project applicability:** PMD AvoidDecimalLiteralsInBigDecimalConstructor
**Rule guidance:** Do not construct BigDecimal from an imprecise floating-point literal when decimal exactness matters. Use a decimal String, integer-based constructor, or valueOf with a deliberate precision policy.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM11-J. Do not compare or inspect the string representation of floating-point values](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num11-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not compare or parse the formatted string representation of a floating-point value as if it were stable numeric data. Compare numbers with an explicit tolerance/ordering policy.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=Yes; Priority=P9; Level=L2
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM12-J. Ensure conversions of numeric types to narrower types do not result in lost or misinterpreted data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num12-j)

**Project status:** Enforced
**Project applicability:** Error Prone NarrowingCompoundAssignment, LossyPrimitiveCompare; -Xlint:cast
**Rule guidance:** Before narrowing a numeric value, prove that it lies in the target type's range and that the conversion preserves the intended meaning. Use exact conversion helpers where available.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=Yes; Priority=P3; Level=L3
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM13-J. Avoid loss of precision when converting primitive integers to floating-point](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num13-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Account for precision loss when converting int/long to float/double, especially for identifiers and money. Keep an exact integer/decimal representation when all bits matter.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [NUM14-J. Use shift operators correctly](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num14-j)

**Project status:** Enforced
**Project applicability:** SpotBugs (ICAST/BSHIFT)
**Rule guidance:** Use shift counts and signedness deliberately: int shifts use 0..31 and long shifts 0..63, with Java's masking rules understood. Validate data and choose >>> versus >> intentionally.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [CborReader.java:79](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L79) - representative project code for this rule family.

### [STR00-J. Don't form strings containing partial characters from variable-width encodings](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str00-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not cut a byte sequence in the middle of a variable-width character. Decode complete sequences with an explicit charset/decoder and preserve incomplete trailing bytes until the next input chunk.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [CborReader.java:109](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L109) - representative project code for this rule family.

### [STR01-J. Do not assume that a Java char fully represents a Unicode code point](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** A Java char is a UTF-16 code unit, not always a complete Unicode code point. Use codePointAt, codePoints, Character APIs, and correct surrogate handling for supplementary characters.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [CborReader.java:109](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L109) - representative project code for this rule family.

### [STR02-J. Specify an appropriate locale when comparing locale-dependent data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str02-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Specify a locale for locale-dependent comparisons and case conversions. Use Locale.ROOT/ENGLISH for protocol, identifier, and security logic; use the user's locale only for presentation.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [CborReader.java:109](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L109) - representative project code for this rule family.

### [STR03-J. Do not encode noncharacter data as a string](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str03-j)

**Project status:** Enforced
**Project applicability:** SecretBytes has no String conversion; Semgrep cert.MSC03-J.secret-in-string
**Rule guidance:** Do not store arbitrary binary/noncharacter data in String. Keep it as byte[] or encode it with a defined binary-to-text scheme such as Base64 and a documented charset.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [CborReader.java:109](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L109) - representative project code for this rule family.

### [STR04-J. Use compatible character encodings when communicating string data between JVMs](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str04-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.FIO11-J.default-charset
**Rule guidance:** Agree on and specify the same charset at every JVM boundary, normally UTF-8. Never rely on the platform default for serialization, network messages, files, or interprocess data.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [CborReader.java:109](modules/pm-vault/src/main/java/pm/vault/cbor/CborReader.java#L109) - representative project code for this rule family.

### [OBJ01-J. Limit accessibility of fields](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj01-j)

**Project status:** Enforced
**Project applicability:** PMD; -Xlint; JPMS exports minimal
**Rule guidance:** Keep fields private or package-private and expose validated operations instead of public/protected mutable state. A final reference does not make the referenced object immutable.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ02-J. Preserve dependencies in subclasses when changing superclasses](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj02-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** When changing a superclass, review inherited behavior, constructors, visibility, and contracts against every subclass invariant. Preserve assumptions that subclasses rely on for safety.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ03-J. Prevent heap pollution](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj03-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Avoid raw types and unchecked generic operations that can put the wrong runtime type into a parameterized object. Parameterize APIs and isolate any unavoidable unchecked conversion behind a proven invariant.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ04-J. Provide mutable classes with copy functionality to safely allow passing instances to untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj04-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Mutable classes should provide a copy constructor or static copy factory so disposable copies can be passed to untrusted code. Only a final class can safely advertise clone-based copying.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P3; Level=L3
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ05-J. Do not return references to private mutable class members](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj05-j)

**Project status:** Enforced
**Project applicability:** PMD MethodReturnsInternalArray
**Rule guidance:** Never return a reference to a private mutable member. Return a defensive copy or a carefully constrained immutable/read-only representation.
**Risk:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ06-J. Defensively copy mutable inputs and mutable internal components](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj06-j)

**Project status:** Enforced
**Project applicability:** PMD ArrayIsStoredDirectly
**Rule guidance:** Defensively copy mutable inputs before validation/use and copy mutable internal components on output. This prevents time-of-check/time-of-use races and caller-driven invariant corruption.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ07-J. Sensitive classes must not let themselves be copied](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj07-j)

**Project status:** Enforced
**Project applicability:** SecretBytes design (ADR 0008); T-MEM-01
**Rule guidance:** Sensitive classes must not be cloneable or otherwise freely copyable. Disable or hide copy mechanisms so cloning cannot bypass constructor checks, singleton identity, or sensitive-state controls.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ08-J. Do not expose private members of an outer class from within a nested class](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj08-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not expose an outer class's private mutable state through public nested-class methods, constructors, or returned references. Keep the nested class's boundary no wider than necessary.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ09-J. Compare classes and not class names](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj09-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Compare Class objects or exact class identity, not class-name strings. Names can collide across packages or class loaders even when the runtime types are distinct.
**Risk:** Severity=High; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P6; Level=L2
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ10-J. Do not use public static nonfinal fields](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj10-j)

**Project status:** Enforced
**Project applicability:** PMD MutableStaticState, AssignmentToNonFinalStatic
**Rule guidance:** Do not expose public static nonfinal fields. Keep shared state private/static-final where possible and expose controlled accessors that validate updates and synchronize as needed.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ11-J. Be wary of letting constructors throw exceptions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj11-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** A constructor that fails can leave a partially initialized object; do not let it escape through callbacks, threads, or shared fields. Keep construction private/contained and clean up partial resources.
**Risk:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ12-J. Respect object-based annotations](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj12-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Stub page. Treat object-based annotations as part of the API contract: preserve their semantic constraints in constructors, accessors, reflection, and generated/inherited code.
**Risk:** Not stated in the family risk summary
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ13-J. Ensure that references to mutable objects are not exposed](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj13-j)

**Project status:** Enforced
**Project applicability:** PMD MethodReturnsInternalArray; Error Prone
**Rule guidance:** Do not expose mutable object references through inputs, accessors, public constants, or static fields. Copy on ingress/egress or expose an immutable view with no mutation channel.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [OBJ14-J. Do not use an object that has been freed.](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj14-j)

**Project status:** Enforced
**Project applicability:** SecretBytes use-after-close throws; T-MEM-01
**Rule guidance:** Stub page. Respect object/resource lifecycle states and do not use an object after close, free, invalidation, or other operation that ends its validity. Make invalid states explicit.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [SecretBytes.java:32](modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L32) - representative project code for this rule family.

### [MET00-J. Validate method arguments](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met00-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Validate method arguments at the interface that owns the contract, including null, range, size, format, and authorization preconditions. Reject invalid input before it can corrupt invariants or trigger unsafe work.
**Risk:** Severity=High; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P9; Level=L2
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET01-J. Never use assertions to validate method arguments](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Never use assert for public argument validation because assertions can be disabled. Throw the documented runtime exception or return an explicit failure according to the API contract.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=Yes; Priority=P8; Level=L2
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET02-J. Do not use deprecated or obsolete classes or methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met02-j)

**Project status:** Enforced
**Project applicability:** -Xlint:deprecation -Werror; Semgrep cert.SEC-superseded.security-manager
**Rule guidance:** Do not introduce deprecated or obsolete APIs in new code. Replace them with the supported API and plan migrations for existing calls whose semantics or security properties have changed.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET03-J. Methods that perform a security check must be declared private or final](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met03-j)

**Project status:** Enforced
**Project applicability:** ArchUnit (broker classes final) added M2; PMD
**Rule guidance:** Declare a method that enforces a security check private or final so a subclass cannot override it and silently remove the check. Keep the check close to the sensitive operation.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET04-J. Do not increase the accessibility of overridden or hidden methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met04-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not widen the accessibility of an overridden or hidden method beyond its original contract. Prefer final methods/classes where inheritance is not required and preserve the intended access boundary.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET05-J. Ensure that constructors do not call overridable methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met05-j)

**Project status:** Enforced
**Project applicability:** PMD ConstructorCallsOverridableMethod
**Rule guidance:** Constructors must not call overridable instance methods. Use private/final helpers or post-construction initialization so a subclass cannot observe or mutate partially initialized state.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET06-J. Do not invoke overridable methods in clone()](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met06-j)

**Project status:** Enforced
**Project applicability:** PMD CloneMethodMustImplementCloneable/ProperCloneImplementation
**Rule guidance:** clone() must not invoke overridable methods; a subclass could alter cloning while the object is partially initialized. Prefer a copy constructor/factory or private/final copy steps.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET07-J. Never declare a class method that hides a method declared in a superclass or superinterface](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met07-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not declare a static method that hides a method in a superclass or superinterface. Rename or redesign the method so callers cannot receive different behavior based on the reference type.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET08-J. Preserve the equality contract when overriding the equals() method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met08-j)

**Project status:** Enforced
**Project applicability:** Error Prone EqualsHashCode, EqualsIncompatibleType
**Rule guidance:** Implement equals with the full reflexive, symmetric, transitive, consistent, and non-null contract. Decide deliberately between exact-class and instanceof semantics and compare the same logical state everywhere.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET09-J. Classes that define an equals() method must also define a hashCode() method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met09-j)

**Project status:** Enforced
**Project applicability:** Error Prone EqualsHashCode (error); PMD OverrideBothEqualsAndHashcode
**Rule guidance:** Whenever equals is overridden, override hashCode so equal objects have equal hashes. Use the same equality fields and do not mutate them while an object is used as a hash key.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET10-J. Follow the general contract when implementing the compareTo() method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met10-j)

**Project status:** Enforced
**Project applicability:** Error Prone ComparableType; SpotBugs
**Rule guidance:** Implement compareTo with sign symmetry, transitivity, consistency, and safe numeric comparison. Do not subtract values to compare them when overflow can change the ordering.
**Risk:** Severity=Medium; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET11-J. Ensure that keys used in comparison operations are immutable](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met11-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Keep fields used by equals, hashCode, or compareTo immutable while an object is a key in a map/set or ordered collection. Remove/reinsert after a deliberate key change.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET12-J. Do not use finalizers](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met12-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.MET12-J.finalizer; PMD Finalize* rules
**Rule guidance:** Do not use finalizers for resource management or security cleanup. Implement explicit close/AutoCloseable ownership and make cleanup deterministic.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [MET13-J. Do not assume that reassigning method arguments modifies the calling environment](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met13-j)

**Project status:** Enforced
**Project applicability:** PMD AvoidReassigningParameters
**Rule guidance:** Stub page. Java passes arguments by value: reassigning a parameter changes only the local variable. Return a new value or intentionally mutate a documented object when caller-visible change is required.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [FieldRules.java:55](modules/pm-vault/src/main/java/pm/vault/record/FieldRules.java#L55) - representative project code for this rule family.

### [ERR00-J. Do not suppress or ignore checked exceptions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err00-j)

**Project status:** Enforced
**Project applicability:** PMD EmptyCatchBlock; -Xlint
**Rule guidance:** Every checked-exception catch must recover, rethrow, or translate to a context-appropriate exception. Never use an empty or cosmetic catch that lets execution continue without restored invariants.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [ERR01-J. Do not allow exceptions to expose sensitive information](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err01-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.FIO13-J.log-secret; error-code catalogue (SR-501); T-ERR-01
**Rule guidance:** Do not expose filesystem layout, query details, credentials, stack traces, or sensitive exception types/messages across a trust boundary. Log a controlled diagnostic internally and return a safe external error.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=Yes; Priority=P8; Level=L2
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [ERR02-J. Prevent exceptions while logging data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err02-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Make logging failure-tolerant so an exception during logging cannot hide the security event being logged. Use a guarded logger or fallback path and preserve the original failure.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [ERR03-J. Restore prior object state on method failure](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err03-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** A mutating method must leave its object in the prior valid state when it fails. Validate before mutation or use rollback/transaction-like restoration, including cleanup on every exceptional path.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [ERR04-J. Do not complete abruptly from a finally block](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err04-j)

**Project status:** Enforced
**Project applicability:** PMD ReturnFromFinallyBlock, DoNotThrowExceptionInFinally
**Rule guidance:** Do not use return, break, continue, or throw in finally. Let finally perform cleanup without replacing or suppressing the outcome and exception from the try/catch path.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [ERR05-J. Do not let checked exceptions escape from a finally block](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err05-j)

**Project status:** Enforced
**Project applicability:** PMD DoNotThrowExceptionInFinally
**Rule guidance:** Catch and handle checked exceptions raised during finally cleanup, or use try-with-resources so cleanup exceptions are managed as suppressed exceptions. Do not lose the primary failure.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [ERR06-J. Do not throw undeclared checked exceptions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err06-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not use sneaky throws, unsafe reflection, bytecode tricks, or obsolete APIs to emit undeclared checked exceptions. Declare or handle every checked exception and use correctly typed constructors/APIs.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [ERR07-J. Do not throw RuntimeException, Exception, or Throwable](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err07-j)

**Project status:** Enforced
**Project applicability:** PMD AvoidThrowingRawExceptionTypes
**Rule guidance:** Throw a specific exception type that communicates the failure and supports recovery. Do not throw the generic RuntimeException, Exception, or Throwable types as the public failure contract.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P6; Level=L2
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [ERR08-J. Do not catch NullPointerException or any of its ancestors](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err08-j)

**Project status:** Enforced
**Project applicability:** PMD AvoidCatchingNPE, AvoidCatchingThrowable
**Rule guidance:** Do not catch NullPointerException or a broad ancestor to mask a bug. Identify the null-producing operation and validate or repair that precondition explicitly.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [ERR09-J. Do not allow untrusted code to terminate the JVM](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err09-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.ERR09-J.system-exit; PMD DoNotTerminateVM
**Rule guidance:** Prevent untrusted code from calling System.exit or otherwise terminating the JVM. Use a controlled shutdown path with cleanup and authorization instead of process-wide termination from request code.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [Vault.java:160](modules/pm-vault/src/main/java/pm/vault/Vault.java#L160) - representative project code for this rule family.

### [VNA00-J. Ensure visibility when accessing shared primitive variables](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna00-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Make shared primitive reads/writes visible with volatile or consistent synchronization. Remember that visibility alone does not make a read-modify-write operation atomic.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [VNA01-J. Ensure visibility of shared references to immutable objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Safely publish shared references even when the referenced object is immutable. Use final-field construction plus a happens-before publication mechanism such as volatile, locking, or static initialization.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [VNA02-J. Ensure that compound operations on shared variables are atomic](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna02-j)

**Project status:** Enforced
**Project applicability:** Error Prone GuardedBy (error); SpotBugs IS/VO
**Rule guidance:** Protect compound operations on shared state with a lock, atomic class, or CAS loop. ++, --, and compound assignments are read-modify-write sequences, not single atomic actions.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [VNA03-J. Do not assume that a group of calls to independently atomic methods is atomic](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna03-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not infer whole-operation atomicity from individually thread-safe calls. Guard the invariant across the complete sequence with one lock, an atomic API, or a transaction-like operation.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [VNA04-J. Ensure that calls to chained methods are atomic](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna04-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** A chain of independently atomic fluent calls is not atomic as a whole. Lock the complete chain or expose one method that performs the invariant-preserving operation atomically.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [VNA05-J. Ensure atomicity when reading and writing 64-bit values](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna05-j)

**Project status:** Enforced
**Project applicability:** SpotBugs
**Rule guidance:** Use volatile, synchronized access, or an atomic holder for shared long/double values when a torn 64-bit read/write would be unsafe. Do not rely on incidental platform atomicity.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK00-J. Use private final lock objects to synchronize classes that may interact with untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck00-j)

**Project status:** Enforced
**Project applicability:** PMD AvoidSynchronizedAtMethodLevel/Statement (private final locks only)
**Rule guidance:** Synchronize on a private final lock object, not this or another object visible to untrusted code. Keep the lock's ownership and scope internal to the class.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK01-J. Do not synchronize on objects that may be reused](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Never lock on reusable or publicly reachable objects such as interned strings, boxed values, collection elements, or caller-supplied objects. Use a private stable lock.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK02-J. Do not synchronize on the class object returned by getClass()](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck02-j)

**Project status:** Enforced
**Project applicability:** SpotBugs (synchronization on getClass)
**Rule guidance:** Do not synchronize on getClass(), because subclasses have different Class objects and can split the protection. Use a deliberately chosen private instance or static lock.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK03-J. Do not synchronize on the intrinsic locks of high-level concurrency objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck03-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Use the Lock and Condition APIs for high-level concurrency objects; do not mix their intrinsic monitors with their explicit locks. Synchronize on the mechanism that actually protects the state.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK04-J. Do not synchronize on a collection view if the backing collection is accessible](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck04-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** When iterating a collection view, synchronize on the accessible backing collection using the collection's documented policy, not on the view object that may not protect the backing data.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK05-J. Synchronize access to static fields that can be modified by untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck05-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Guard mutable static state internally whenever untrusted code can call the mutating method. Do not depend on clients to acquire a lock consistently.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK06-J. Do not use an instance lock to protect shared static data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck06-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Protect shared static data with a class/static lock or another shared synchronization object; an instance lock protects only one instance and fails when multiple instances exist.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK07-J. Avoid deadlock by requesting and releasing locks in the same order](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck07-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Define a global lock order and acquire/release nested locks in that same order everywhere. Avoid cycles in the wait-for graph and document ordering assumptions.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P3; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK08-J. Ensure actively held locks are released on exceptional conditions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck08-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** After acquiring a lock, release it in a finally path even when work throws. Track ownership correctly and do not unlock from a thread that does not own the lock.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=Yes; Priority=P9; Level=L2
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK09-J. Do not perform operations that can block while holding a lock](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck09-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not perform network, file, console, serialization, indefinite wait, or other blocking work while holding a lock. Snapshot state under lock, then do slow work outside it.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK10-J. Use a correct form of the double-checked locking idiom](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck10-j)

**Project status:** Enforced
**Project applicability:** Error Prone DoubleCheckedLocking (error); PMD
**Rule guidance:** Use volatile publication plus a synchronized second check, or the initialization-on-demand holder idiom, for lazy initialization. The design must establish happens-before for both the reference and complete object construction.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [LCK11-J. Avoid client-side locking when using classes that do not commit to their locking strategy](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck11-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not client-lock on a library object whose locking strategy is undocumented or not guaranteed. Expose/use an atomic library operation or guard the invariant with a lock you own.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [Vault.java:53](modules/pm-vault/src/main/java/pm/vault/Vault.java#L53) - representative project code for this rule family.

### [THI00-J. Do not invoke Thread.run()](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi00-j)

**Project status:** Enforced
**Project applicability:** PMD DontCallThreadRun; SpotBugs
**Rule guidance:** Start a thread with start() or submit work to an executor; calling run() directly executes on the current thread and may bypass the intended concurrency model.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
**Example:** [IdleLock.java:56](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L56) - representative project code for this rule family.

### [THI02-J. Notify all waiting threads rather than a single thread](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi02-j)

**Project status:** Enforced
**Project applicability:** PMD UseNotifyAllInsteadOfNotify
**Rule guidance:** Notify all waiters when more than one predicate or waiter may become eligible. Hold the same monitor used for waiting, and let each waiter recheck its own condition.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=Yes; Priority=P2; Level=L3
**Example:** [IdleLock.java:56](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L56) - representative project code for this rule family.

### [THI03-J. Always invoke wait() and await() methods inside a loop](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi03-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Call wait() or await() only while holding the associated monitor/lock and inside a loop that checks the condition predicate. Handle spurious wakeups, interrupts, and timeouts.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [IdleLock.java:56](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L56) - representative project code for this rule family.

### [THI04-J. Ensure that threads performing blocking operations can be terminated](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi04-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Every task that can block on I/O or another indefinite operation needs an explicit cancellation/termination path, such as interrupt plus close/deadline, so it cannot pin a thread forever.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [IdleLock.java:56](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L56) - representative project code for this rule family.

### [THI05-J. Do not use Thread.stop() to terminate threads](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi05-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.THI05-J.thread-stop
**Rule guidance:** Never use Thread.stop to terminate work. Use cooperative cancellation, interruption, state flags, deadlines, and resource closure so invariants remain intact.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [IdleLock.java:56](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L56) - representative project code for this rule family.

### [TPS00-J. Use thread pools to enable graceful degradation of service during traffic bursts](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps00-j)

**Project status:** Enforced
**Project applicability:** PMD DoNotUseThreads (executors only)
**Rule guidance:** Use bounded thread pools, queues, admission control, timeouts, and backpressure to absorb bursts with graceful degradation. Do not create an unbounded thread per request.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [IdleLock.java:93](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L93) - representative project code for this rule family.

### [TPS01-J. Do not execute interdependent tasks in a bounded thread pool](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not submit a task to a bounded pool when it synchronously waits for another task that must run in the same pool. Use separate capacity or nonblocking composition to avoid thread-starvation deadlock.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [IdleLock.java:93](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L93) - representative project code for this rule family.

### [TPS02-J. Ensure that tasks submitted to a thread pool are interruptible](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps02-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Tasks submitted to a pool that must shut down/cancel must respond to interruption, clean up, and preserve the interrupt status when appropriate. Do not submit uninterruptible work to that pool.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [IdleLock.java:93](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L93) - representative project code for this rule family.

### [TPS03-J. Ensure that tasks executing in a thread pool do not fail silently](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps03-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Make every pooled task failure observable through Future.get, a task wrapper, an uncaught-exception handler, or equivalent reporting. Log/alert and clean up rather than allowing silent failure.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [IdleLock.java:93](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L93) - representative project code for this rule family.

### [TPS04-J. Ensure ThreadLocal variables are reinitialized when using thread pools](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps04-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Reinitialize request/task-specific ThreadLocal state for every pooled task and remove it in finally. Never let credentials, tenant IDs, transactions, or user data bleed into the next task.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [IdleLock.java:93](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L93) - representative project code for this rule family.

### [TSM00-J. Do not override thread-safe methods with methods that are not thread-safe](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm00-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** A subclass must preserve the thread-safety contract of an inherited method. Do not replace synchronized/atomic behavior with an unsynchronized implementation, and document any inheritance locking policy.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [IdleLock.java:107](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L107) - representative project code for this rule family.

### [TSM01-J. Do not let the this reference escape during object construction](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Do not let this escape from a constructor via callbacks, listener registration, shared fields, static state, or a started thread. Publish the object only after construction completes.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [IdleLock.java:107](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L107) - representative project code for this rule family.

### [TSM02-J. Do not use background threads during class initialization](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm02-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Complete class initialization before starting background threads. Static initialization that starts work can create circular waits or deadlock between the initializer and its worker.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [IdleLock.java:107](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L107) - representative project code for this rule family.

### [TSM03-J. Do not publish partially initialized objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm03-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Publish shared objects only after complete initialization and with safe-publication semantics such as final fields, volatile, synchronization, or an immutable holder. Never expose a partially built object.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
**Example:** [IdleLock.java:107](modules/pm-tui/src/main/java/pm/tui/IdleLock.java#L107) - representative project code for this rule family.

### [FIO00-J. Do not operate on files in shared directories](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio00-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.FIO03-J.temp-file; pm-storage sole file writer (ArchUnit added M1); T-FS-01
**Rule guidance:** Operate only in secure, non-shared directories. Resolve and create files safely, account for links and special files, and prevent another user/process from swapping a path between check and use.
**Risk:** Severity=Medium; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO01-J. Create files with appropriate access permissions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio01-j)

**Project status:** Enforced
**Project applicability:** pm-storage sets perms before write; T-FS-01
**Rule guidance:** Create files with restrictive permissions atomically, before sensitive contents are exposed. Use least privilege and verify the resulting owner/mode where the platform permits it.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO02-J. Detect and handle file-related errors](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio02-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Check boolean, count, and status returns from file APIs and handle failure deliberately. Do not assume a file operation succeeded merely because no exception was thrown.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P12; Level=L1
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO03-J. Remove temporary files before termination](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio03-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.FIO03-J.temp-file
**Rule guidance:** Create temporary files in a secure location with secure permissions and delete them on every normal/error path, typically with try/finally or try-with-resources plus a bounded cleanup strategy.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO04-J. Release resources when they are no longer needed](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio04-j)

**Project status:** Enforced
**Project applicability:** PMD CloseResource, UseTryWithResources
**Rule guidance:** Release files, streams, descriptors, database connections, locks, semaphores, and other non-memory resources as soon as ownership ends. Prefer try-with-resources and do not depend on finalizers.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO05-J. Do not expose buffers or their backing arrays methods to untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio05-j)

**Project status:** Enforced
**Project applicability:** SecretBytes withBytes scoping (ADR 0008)
**Rule guidance:** Do not give untrusted callers a buffer or backing array that aliases protected mutable data. Copy it or expose a genuinely read-only/isolated view with a clear ownership contract.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO06-J. Do not create multiple buffered wrappers on a single byte or character stream](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio06-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Use at most one buffered wrapper for a given byte or character stream. Share that wrapper or pass it to consumers; multiple look-ahead buffers can consume and reorder data unpredictably.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO07-J. Do not let external processes block on IO buffers](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio07-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** When starting an external process, continuously drain its stdout and stderr, provide/close stdin as appropriate, and wait with cancellation/timeouts so child processes cannot block on full pipes.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO08-J. Distinguish between characters or bytes read from a stream and -1](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio08-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Keep InputStream.read and Reader.read results in an int until testing for -1. Only then convert a valid byte/character value; -1 means end-of-stream, not data.
**Risk:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P18; Level=L1
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO09-J. Do not rely on the write() method to output integers outside the range 0 to 255](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio09-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** OutputStream.write(int) emits only the low eight bits. Range-check the integer or use an explicit byte/character encoding API when values outside 0..255 must be preserved.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=Yes; Priority=P2; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO10-J. Ensure the array is filled when using read() to fill an array](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio10-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** A read into an array can be partial. Loop using the returned count until the requested region is filled or EOF/error occurs; never treat one read call as a fill guarantee.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO11-J. Do not convert between strings and bytes without specifying a valid character encoding](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio11-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.FIO11-J.default-charset; Error Prone DefaultCharset (error)
**Rule guidance:** Deprecated/moved page. Always specify a charset when converting between bytes and strings; use StandardCharsets or STR04-J rather than a platform default.
**Risk:** Not stated in the family risk summary
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO12-J. Provide methods to read and write little-endian data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio12-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Make little-endian encoding explicit at the API boundary, using a tested byte-order helper or ByteBuffer with LITTLE_ENDIAN. Do not assume Java's default big-endian order matches the peer.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO13-J. Do not log sensitive information outside a trust boundary](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio13-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.FIO13-J.log-secret; logger type check; CI canary grep (SR-500)
**Rule guidance:** Do not place passwords, tokens, keys, full payment data, or other sensitive values in logs outside the authorized trust boundary. Redact, minimize, protect, and retain only what incident response needs.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO14-J. Perform proper cleanup at program termination](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio14-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** When failing fast or terminating, release resources, flush/close streams, remove temporary data, and leave durable state consistent. Use a carefully scoped shutdown hook only for cleanup that must survive normal termination.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [FIO16-J. Canonicalize path names before validating them](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio16-j)

**Project status:** Enforced
**Project applicability:** SafePath in pm-storage (M1); T-BKP-01
**Rule guidance:** Canonicalize/normalize a path before validating it, resolve it under a trusted base directory, and reject traversal, alternate spellings, links, or any result outside the allowed root.
**Risk:** Severity=Medium; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [VaultFileStore.java:237](modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L237) - representative project code for this rule family.

### [SER00-J. Enable serialization compatibility during class evolution](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser00-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Choose and declare a serialization evolution strategy, including serialVersionUID and custom compatibility behavior where needed. Test old streams against new classes before treating the wire form as stable.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
**Example:** [RecordCodec.java:126](modules/pm-vault/src/main/java/pm/vault/record/RecordCodec.java#L126) - representative project code for this rule family.

### [SER02-J. Sign then seal objects before sending them outside a trust boundary](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser02-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Protect an object crossing a trust boundary with confidentiality/integrity: seal or encrypt the serialized data first, then sign the sealed representation, and verify before deserializing/using it.
**Risk:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
**Example:** [RecordCodec.java:126](modules/pm-vault/src/main/java/pm/vault/record/RecordCodec.java#L126) - representative project code for this rule family.

### [SER03-J. Do not serialize unencrypted sensitive data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser03-j)

**Project status:** Enforced
**Project applicability:** SecretBytes not Serializable; Semgrep cert.SER12-J; ArchUnit noNativeSerialization
**Rule guidance:** Never serialize plaintext secrets, keys, certificates, or sensitive object graphs. Mark fields transient or implement encrypted custom serialization with deliberate key management.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [RecordCodec.java:126](modules/pm-vault/src/main/java/pm/vault/record/RecordCodec.java#L126) - representative project code for this rule family.

### [SER12-J. Prevent deserialization of untrusted data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser12-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.SER12-J.native-serialization; ArchUnit noNativeSerialization
**Rule guidance:** Do not deserialize untrusted data. Prefer a constrained data format; if legacy serialization is unavoidable, allowlist/filter classes, validate size and graph shape, isolate the operation, and apply least privilege.
**Risk:** Severity=High; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P9; Level=L2
**Example:** [RecordCodec.java:126](modules/pm-vault/src/main/java/pm/vault/record/RecordCodec.java#L126) - representative project code for this rule family.

### [SEC00-J. Do not allow privileged blocks to leak sensitive information across a trust boundary](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec00-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Keep doPrivileged blocks small and non-leaking: validate before entry, perform only the required privileged action, and do not return sensitive data or capabilities to less-trusted callers.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [SEC01-J. Do not allow tainted variables in privileged blocks](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Never use tainted/unvalidated values inside a privileged block. Hard-code safe parameters when possible and validate/sanitize all remaining values before privilege is acquired.
**Risk:** Severity=High; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P9; Level=L2
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [SEC02-J. Do not base security checks on untrusted sources](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec02-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Base authorization checks on trusted snapshots, not mutable caller-controlled objects. Use a deep defensive copy or immutable representation before checking security-sensitive properties.
**Risk:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [SEC05-J. Do not use reflection to increase accessibility of classes, methods, or fields](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec05-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.SEC05-J.set-accessible
**Rule guidance:** Do not use reflection to bypass access controls (for example setAccessible) on security-sensitive classes, fields, or methods. Prefer an explicit safe API and enforce authorization before reflective work.
**Risk:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [ENV00-J. Do not sign code that performs only unprivileged operations](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env00-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Sign code only when it needs the elevated authority associated with a trusted signer. Keep code that performs only unprivileged work unsigned so users do not grant it unnecessary privilege.
**Risk:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [ENV01-J. Place all security-sensitive code in a single JAR and sign and seal it](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env01-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Keep security-sensitive code together in one signed and sealed JAR. Prevent mix-and-match loading that lets trusted privileged code be combined with attacker-controlled classes or packages.
**Risk:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [ENV02-J. Do not trust the values of environment variables](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env02-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.ENV02-J.getenv-outside-accessor
**Rule guidance:** Deprecated page. If environment variables are still used, treat their values as attacker-controlled configuration rather than as an authorization or integrity signal; prefer a current, explicit configuration boundary.
**Risk:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P6; Level=L2
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [ENV04-J. Do not disable bytecode verification](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env04-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.ENV04-J.verify-none
**Rule guidance:** Never disable JVM bytecode verification or ship around it. Let the verifier check class-file structure, types, and operand-stack safety before code executes.
**Risk:** Severity=High; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P9; Level=L2
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [ENV05-J. Do not deploy an application that can be remotely monitored](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env05-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.ENV05-J.jmx-jdwp; T-PKG-01
**Rule guidance:** Disable remote JVMTI, JPDA, JMX, and related monitoring/debug access in production, or protect it with a tightly controlled authenticated boundary. Remote inspection can expose data and control execution.
**Risk:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [ENV06-J. Production code must not contain debugging entry points](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env06-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.ENV05-J.jmx-jdwp; release build has no debug commands; T-PKG-01
**Rule guidance:** Remove debug entry points, back doors, test hooks, and accidental production main methods from deployable code. Test-only access must not be reachable in the production artifact.
**Risk:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [VaultPaths.java:44](modules/pm-cli/src/main/java/pm/cli/VaultPaths.java#L44) - representative project code for this rule family.

### [MSC00-J. Use SSLSocket rather than Socket for secure data exchange](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc00-j)

**Project status:** Enforced
**Project applicability:** ArchUnit: raw Socket/ServerSocket only in pm-sharing TLS wrapper (added M3)
**Rule guidance:** Use SSLSocket or another correctly configured TLS client for sensitive data instead of raw Socket. Verify the peer certificate and hostname and use current protocol/cipher settings.
**Risk:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [Csprng.java:8](modules/pm-crypto/src/main/java/pm/crypto/Csprng.java#L8) - representative project code for this rule family.

### [MSC01-J. Do not use an empty infinite loop](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc01-j)

**Project status:** Enforced
**Project applicability:** PMD EmptyControlStatement
**Rule guidance:** Do not ship an empty infinite loop. Every loop must have a meaningful wait/progress condition, termination/cancellation behavior, or explicit blocking primitive.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=Yes; Priority=P3; Level=L3
**Example:** [Csprng.java:8](modules/pm-crypto/src/main/java/pm/crypto/Csprng.java#L8) - representative project code for this rule family.

### [MSC02-J. Generate strong random numbers](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc02-j)

**Project status:** Enforced
**Project applicability:** Semgrep cert.MSC02-J.*; SpotBugs PREDICTABLE_RANDOM (proven in Phase 9)
**Rule guidance:** Use SecureRandom for keys, tokens, nonces, reset codes, and other security decisions. java.util.Random and predictable seeds are not security randomness.
**Risk:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [Csprng.java:8](modules/pm-crypto/src/main/java/pm/crypto/Csprng.java#L8) - representative project code for this rule family.

### [MSC03-J. Never hard code sensitive information](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc03-j)

**Project status:** Enforced
**Project applicability:** gitleaks; Semgrep cert.MSC03-J.secret-in-string; PMD HardCodedCryptoKey
**Rule guidance:** Never hard-code passwords, API keys, private keys, encryption material, or other sensitive configuration in source or class files. Inject secrets through a controlled secret/configuration mechanism.
**Risk:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
**Example:** [Csprng.java:8](modules/pm-crypto/src/main/java/pm/crypto/Csprng.java#L8) - representative project code for this rule family.

### [MSC04-J. Do not leak memory](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc04-j)

**Project status:** Review-only
**Project applicability:** Code-review checklist item; no reliable automated check
**Rule guidance:** Release references, listeners, caches, handles, and other reachability roots when their work ends so unused objects can be collected. Bound caches and unregister callbacks.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
**Example:** [Csprng.java:8](modules/pm-crypto/src/main/java/pm/crypto/Csprng.java#L8) - representative project code for this rule family.

### [MSC05-J. Do not exhaust heap space](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc05-j)

**Project status:** Enforced
**Project applicability:** All parsers size-bounded (ADR 0006); fuzz harnesses T-FUZZ-*
**Rule guidance:** Bound all attacker-influenced allocations, input sizes, recursion, decompression, and accumulation. Reject or stream oversized data before an OutOfMemoryError can terminate the service.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [Csprng.java:8](modules/pm-crypto/src/main/java/pm/crypto/Csprng.java#L8) - representative project code for this rule family.

### [MSC06-J. Do not modify the underlying collection when an iteration is in progress](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc06-j)

**Project status:** Enforced
**Project applicability:** Error Prone ModifyCollectionInEnhancedForLoop; SpotBugs
**Rule guidance:** Do not structurally modify a collection during iteration except through the iterator's supported remove operation. Use a snapshot, separate pass, or synchronized mutation strategy.
**Risk:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
**Example:** [Csprng.java:8](modules/pm-crypto/src/main/java/pm/crypto/Csprng.java#L8) - representative project code for this rule family.

### [MSC07-J. Prevent multiple instantiations of singleton objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc07-j)

**Project status:** Enforced
**Project applicability:** PMD NonThreadSafeSingleton
**Rule guidance:** Enforce one singleton instance under concurrency and across reflection, cloning, and deserialization as applicable. Prefer a robust holder/enum design and keep construction inaccessible.
**Risk:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
**Example:** [Csprng.java:8](modules/pm-crypto/src/main/java/pm/crypto/Csprng.java#L8) - representative project code for this rule family.