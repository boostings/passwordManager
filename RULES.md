# SEI CERT Oracle Coding Standard for Java — Rules and Sub-rules

> Source-of-truth index captured from the CMU/SEI CERT Secure Coding site on 2026-08-27 via the Chrome computer-use workflow. Exact rule titles and source links are preserved; the implementation readings below are concise original digests, not a verbatim mirror of the source pages.

## Coverage and interpretation

- The Java rules index contains 19 non-Android top-level families: Rule 00 through Rule 17 and Rule 49.
- The current index exposes 177 individual Java `*-J` detail pages across Rules 00–49.
- Android Rule 50 entries are intentionally omitted per the request for non-Android Java rules.
- Several source pages are explicitly marked deprecated, moved, under construction, or stubbed. Those states are preserved; do not treat an incomplete page as a complete normative specification.
- Recommendations are intentionally out of scope here. This file covers the non-Android Rules section.

## Counts by family

| Rule family | Code | Entries on the source page | Family source |
| --- | --- | ---: | --- |
| Rule 00. Input Validation and Data Sanitization | IDS | 12 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids) |
| Rule 01. Declarations and Initialization | DCL | 3 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl) |
| Rule 02. Expressions | EXP | 8 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp) |
| Rule 03. Numeric Types and Operations | NUM | 13 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num) |
| Rule 04. Characters and Strings | STR | 5 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str) |
| Rule 05. Object Orientation | OBJ | 14 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj) |
| Rule 06. Methods | MET | 14 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met) |
| Rule 07. Exceptional Behavior | ERR | 10 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err) |
| Rule 08. Visibility and Atomicity | VNA | 6 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna) |
| Rule 09. Locking | LCK | 12 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck) |
| Rule 10. Thread APIs | THI | 6 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi) |
| Rule 11. Thread Pools | TPS | 5 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps) |
| Rule 12. Thread-Safety Miscellaneous | TSM | 4 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm) |
| Rule 13. Input Output | FIO | 17 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio) |
| Rule 14. Serialization | SER | 13 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser) |
| Rule 15. Platform Security | SEC | 11 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec) |
| Rule 16. Runtime Environment | ENV | 7 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env) |
| Rule 17. Java Native Interface | JNI | 5 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni) |
| Rule 49. Miscellaneous | MSC | 12 | [family page](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc) |

## Agent-wide enforcement patterns

1. Establish trust boundaries and ownership first. Treat request data, files, environment variables, serialized bytes, reflection inputs, native inputs, and Android IPC as untrusted until the relevant rule says otherwise.
2. Normalize/canonicalize before validation, then validate the final representation for its exact destination. Encode/parameterize at interpreter boundaries instead of relying on a general-purpose blacklist.
3. Preserve invariants across errors and lifecycles: validate before mutation, roll back on failure, close resources deterministically, and never publish partially initialized or invalid objects.
4. Make concurrency properties explicit: safe publication for shared references, atomicity for compound operations, private stable locks, bounded executors, cooperative cancellation, and cleared pooled-thread context.
5. Minimize privilege and exposure: private fields/locks, narrow privileged blocks, explicit authorization, least-permission artifacts, no debug/monitoring backdoors, and no plaintext secrets in code/logs/serialized data.

## Detailed hierarchy

## <a id="rule-00-input-validation-and-data-sanitization-ids"></a>Rule 00. Input Validation and Data Sanitization (IDS)

**Family source:** [Rule 00. Input Validation and Data Sanitization (IDS)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids)

**Family reading:** Treat external data as untrusted until it has been normalized, validated, and safely encoded for its destination interpreter or trust boundary.

**Individual entries:** 12

### [IDS00-J. Prevent SQL injection](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids00-j)

- **Agent enforcement cue:** Use parameterized SQL or stored procedures and bind values with typed PreparedStatement setters. Validate shape and size at the boundary, and never concatenate untrusted data into SQL syntax.
- **Risk summary:** Severity=High; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P18; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids00-j

### [IDS01-J. Normalize strings before validating them](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids01-j)

- **Agent enforcement cue:** Normalize Unicode input before applying validation or blacklist/allowlist checks. Validate the same canonical representation that will be stored, compared, or interpreted so equivalent spellings cannot bypass the check.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids01-j

### [IDS03-J. Do not log unsanitized user input](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids03-j)

- **Agent enforcement cue:** Sanitize and validate untrusted text before logging it; neutralize CR/LF and other record/control delimiters, prefer structured logging, and keep sensitive fields out of the log altogether.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids03-j

### [IDS04-J. Safely extract files from ZipInputStream](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids04-j)

- **Agent enforcement cue:** For every ZipEntry, canonicalize the destination under a trusted extraction root and reject absolute paths, traversal, and unsafe link-like entries before writing. Create directories and files with secure permissions.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids04-j

### [IDS06-J. Exclude unsanitized user input from format strings](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids06-j)

- **Agent enforcement cue:** Keep format strings constant and pass user data only as ordinary formatting arguments after validation. Never let untrusted text supply conversion directives that can leak data or trigger denial of service.
- **Risk summary:** Severity=Medium; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids06-j

### [IDS07-J. Sanitize untrusted data passed to the Runtime.exec() method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids07-j)

- **Agent enforcement cue:** Treat command and argument data as untrusted. Prefer an allowlisted executable plus a ProcessBuilder argument list, validate each argument, and never build a shell command from concatenated input.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids07-j

### [IDS08-J. Sanitize untrusted data included in a regular expression](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids08-j)

- **Agent enforcement cue:** Do not splice untrusted text into regex syntax. Quote literal input with Pattern.quote or use a strict allowlist/fixed pattern, and bound regex complexity and input size to resist regex denial of service.
- **Risk summary:** Severity=Medium; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids08-j

### [IDS11-J. Perform any string modifications before validation](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids11-j)

- **Agent enforcement cue:** Perform every decoding, normalization, filtering, and transformation before the final validation. Do not modify a value after it has passed a security check, because the transformation can create a dangerous sequence.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids11-j

### [IDS14-J. Do not trust the contents of hidden form fields](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids14-j)

- **Agent enforcement cue:** Treat hidden form fields exactly like visible request parameters: untrusted and attacker-modifiable. Recompute server state or validate authorization, integrity, type, and range on every request.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids14-j

### [IDS15-J. Do not allow sensitive information to leak outside a trust boundary](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids15-j)

- **Agent enforcement cue:** Stub page. Do not let sensitive data or capabilities cross from one trust domain to another without an explicit, minimized, authorized, and appropriately protected interface; apply the specialized rules it references.
- **Source-page status:** Stub on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids15-j

### [IDS16-J. Prevent XML Injection](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids16-j)

- **Agent enforcement cue:** Build XML with a safe XML API and encode untrusted values as text or attributes. Do not concatenate raw input into markup; validate the resulting document against the intended structure.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids16-j

### [IDS17-J. Prevent XML External Entity Attacks](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids17-j)

- **Agent enforcement cue:** Configure XML parsers to disable external general/parameter entities, external DTDs, and unintended external schema/URI access; reject unsafe doctypes where possible and use a hardened parser configuration.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids17-j

## <a id="rule-01-declarations-and-initialization-dcl"></a>Rule 01. Declarations and Initialization (DCL)

**Family source:** [Rule 01. Declarations and Initialization (DCL)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl)

**Family reading:** Keep declarations, names, static initialization, and enhanced-iteration behavior unambiguous and invariant-preserving.

**Individual entries:** 3

### [DCL00-J. Prevent class initialization cycles](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl/dcl00-j)

- **Agent enforcement cue:** Avoid cycles among static field initializers and static initialization blocks. Make initialization dependencies explicit or lazy so loading one class cannot recursively wait on another class that is waiting back.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl/dcl00-j

### [DCL01-J. Do not reuse public identifiers from the Java Standard Library](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl/dcl01-j)

- **Agent enforcement cue:** Do not give application classes, packages, or public identifiers names that shadow public Java Standard Library types. Prefer names that make the owning package and type unambiguous.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl/dcl01-j

### [DCL02-J. Do not modify the collection's elements during an enhanced for statement](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl/dcl02-j)

- **Agent enforcement cue:** Do not mutate collection elements through an enhanced-for traversal in a way that obscures or violates the collection's iteration contract. Use a deliberate iterator, index-based update, or separate transformation pass.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/declarations-and-initialization-dcl/dcl02-j

## <a id="rule-02-expressions-exp"></a>Rule 02. Expressions (EXP)

**Family source:** [Rule 02. Expressions (EXP)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp)

**Family reading:** Use Java expression semantics deliberately: consume return values, handle nulls and equality correctly, and keep required behavior free of hidden side effects.

**Individual entries:** 8

### [EXP00-J. Do not ignore values returned by methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp00-j)

- **Agent enforcement cue:** Inspect and act on method return values, especially boolean, status, count, and result values that signal failure or changed behavior. Do not confuse a getter-like status method with the operation that performs the change.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp00-j

### [EXP01-J. Do not use a null in a case where an object is required](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp01-j)

- **Agent enforcement cue:** Do not pass null where an object is required. Establish non-null preconditions at the boundary or use an API that explicitly models absence, rather than relying on a later NullPointerException.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=No; Repairable=Yes; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp01-j

### [EXP02-J. Do not use the Object.equals() method to compare two arrays](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp02-j)

- **Agent enforcement cue:** Use Arrays.equals or Arrays.deepEquals for array-content equality; reserve == and != for reference identity. Object.equals on an array does not compare its elements.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=Yes; Priority=P9; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp02-j

### [EXP03-J. Do not use the equality operators when comparing values of boxed primitives](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp03-j)

- **Agent enforcement cue:** Compare boxed primitive values by unboxing or equals, not with == or !=. Reference identity may appear to work for cached wrapper values and then fail for other values.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=Yes; Priority=P9; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp03-j

### [EXP04-J. Do not pass arguments to certain Java Collections Framework methods that are a different type than the collection parameter type](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp04-j)

- **Agent enforcement cue:** For collection methods whose signatures accept Object, pass keys and lookup arguments compatible with the collection's generic element/key type. Do not rely on a permissive API signature to hide a type mistake.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp04-j

### [EXP05-J. Do not follow a write by a subsequent write or read of the same object within an expression](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp05-j)

- **Agent enforcement cue:** Deprecated page. Keep reads and writes to the same object out of ambiguous side-effecting expressions; use separate statements so sequencing and the value being observed are explicit.
- **Source-page status:** Deprecated or moved on the source page.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp05-j

### [EXP06-J. Expressions used in assertions must not produce side effects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp06-j)

- **Agent enforcement cue:** Assertion expressions must be side-effect free because assertions may be disabled. Put required validation, mutation, logging, and state changes in ordinary code outside assert.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=Yes; Priority=P3; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp06-j

### [EXP07-J. Prevent loss of useful data due to weak references](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp07-j)

- **Agent enforcement cue:** Stub page. Do not allow weak references or reachability assumptions to discard data that the program still needs. Retain a strong owner for useful state and handle reclamation explicitly.
- **Source-page status:** Stub on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp07-j

## <a id="rule-03-numeric-types-and-operations-num"></a>Rule 03. Numeric Types and Operations (NUM)

**Family source:** [Rule 03. Numeric Types and Operations (NUM)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num)

**Family reading:** Make integer ranges, floating-point special values, precision, narrowing conversions, and bit shifts explicit and safe.

**Individual entries:** 13

### [NUM00-J. Detect or prevent integer overflow](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num00-j)

- **Agent enforcement cue:** Check or prevent integer overflow/underflow before arithmetic that can exceed the type range. Use range checks, exact Math methods, BigInteger, or a type with sufficient capacity.
- **Risk summary:** Severity=Medium; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num00-j

### [NUM01-J. Do not perform bitwise and arithmetic operations on the same data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num01-j)

- **Agent enforcement cue:** Give an integer variable one clear meaning: numeric quantity or bit set. Keep arithmetic and bitwise operations separate so a bit trick cannot silently change a numeric value or obscure intent.
- **Risk summary:** Severity=Medium; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num01-j

### [NUM02-J. Ensure that division and remainder operations do not result in divide-by-zero errors](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num02-j)

- **Agent enforcement cue:** Check an integer divisor for zero before / or %. This rule does not require the same check for floating-point division, whose exceptional values have different semantics.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=No; Repairable=Yes; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num02-j

### [NUM03-J. Use integer types that can fully represent the possible range of unsigned data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num03-j)

- **Agent enforcement cue:** Represent unsigned values in a Java type wide enough for their complete range, especially at native-language boundaries. For example, use long when storing an unsigned 32-bit value.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num03-j

### [NUM04-J. Do not use floating-point numbers if precise computation is required](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num04-j)

- **Agent enforcement cue:** Deprecated page. Do not use floating-point arithmetic where exact decimal/integer computation is required; use integer scaling, BigDecimal, or another exact representation.
- **Source-page status:** Deprecated or moved on the source page.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num04-j

### [NUM07-J. Do not attempt comparisons with NaN](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num07-j)

- **Agent enforcement cue:** Test NaN with isNaN rather than <, <=, >, >=, ==, or !=. NaN is unordered and ordinary comparisons do not express a valid NaN check.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num07-j

### [NUM08-J. Check floating-point inputs for exceptional values](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num08-j)

- **Agent enforcement cue:** Validate floating-point inputs and intermediate results for NaN, positive infinity, and negative infinity using the appropriate API before they influence control flow, limits, or persisted state.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=Yes; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num08-j

### [NUM09-J. Do not use floating-point variables as loop counters](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num09-j)

- **Agent enforcement cue:** Use an integral counter for loop induction. Floating-point rounding can skip the termination value or accumulate error, producing incorrect or nonterminating loops.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num09-j

### [NUM10-J. Do not construct BigDecimal objects from floating-point literals](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num10-j)

- **Agent enforcement cue:** Do not construct BigDecimal from an imprecise floating-point literal when decimal exactness matters. Use a decimal String, integer-based constructor, or valueOf with a deliberate precision policy.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num10-j

### [NUM11-J. Do not compare or inspect the string representation of floating-point values](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num11-j)

- **Agent enforcement cue:** Do not compare or parse the formatted string representation of a floating-point value as if it were stable numeric data. Compare numbers with an explicit tolerance/ordering policy.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=Yes; Priority=P9; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num11-j

### [NUM12-J. Ensure conversions of numeric types to narrower types do not result in lost or misinterpreted data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num12-j)

- **Agent enforcement cue:** Before narrowing a numeric value, prove that it lies in the target type's range and that the conversion preserves the intended meaning. Use exact conversion helpers where available.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=Yes; Priority=P3; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num12-j

### [NUM13-J. Avoid loss of precision when converting primitive integers to floating-point](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num13-j)

- **Agent enforcement cue:** Account for precision loss when converting int/long to float/double, especially for identifiers and money. Keep an exact integer/decimal representation when all bits matter.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num13-j

### [NUM14-J. Use shift operators correctly](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num14-j)

- **Agent enforcement cue:** Use shift counts and signedness deliberately: int shifts use 0..31 and long shifts 0..63, with Java's masking rules understood. Validate data and choose >>> versus >> intentionally.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num14-j

## <a id="rule-04-characters-and-strings-str"></a>Rule 04. Characters and Strings (STR)

**Family source:** [Rule 04. Characters and Strings (STR)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str)

**Family reading:** Handle Unicode code points, locales, character encodings, and binary data without assuming a character or string is a byte container.

**Individual entries:** 5

### [STR00-J. Don't form strings containing partial characters from variable-width encodings](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str00-j)

- **Agent enforcement cue:** Do not cut a byte sequence in the middle of a variable-width character. Decode complete sequences with an explicit charset/decoder and preserve incomplete trailing bytes until the next input chunk.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str00-j

### [STR01-J. Do not assume that a Java char fully represents a Unicode code point](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str01-j)

- **Agent enforcement cue:** A Java char is a UTF-16 code unit, not always a complete Unicode code point. Use codePointAt, codePoints, Character APIs, and correct surrogate handling for supplementary characters.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str01-j

### [STR02-J. Specify an appropriate locale when comparing locale-dependent data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str02-j)

- **Agent enforcement cue:** Specify a locale for locale-dependent comparisons and case conversions. Use Locale.ROOT/ENGLISH for protocol, identifier, and security logic; use the user's locale only for presentation.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str02-j

### [STR03-J. Do not encode noncharacter data as a string](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str03-j)

- **Agent enforcement cue:** Do not store arbitrary binary/noncharacter data in String. Keep it as byte[] or encode it with a defined binary-to-text scheme such as Base64 and a documented charset.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str03-j

### [STR04-J. Use compatible character encodings when communicating string data between JVMs](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str04-j)

- **Agent enforcement cue:** Agree on and specify the same charset at every JVM boundary, normally UTF-8. Never rely on the platform default for serialization, network messages, files, or interprocess data.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/characters-and-strings-str/str04-j

## <a id="rule-05-object-orientation-obj"></a>Rule 05. Object Orientation (OBJ)

**Family source:** [Rule 05. Object Orientation (OBJ)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj)

**Family reading:** Protect object invariants and encapsulation across fields, mutability, copying, inheritance, nested classes, and object lifetime.

**Individual entries:** 14

### [OBJ01-J. Limit accessibility of fields](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj01-j)

- **Agent enforcement cue:** Keep fields private or package-private and expose validated operations instead of public/protected mutable state. A final reference does not make the referenced object immutable.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj01-j

### [OBJ02-J. Preserve dependencies in subclasses when changing superclasses](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj02-j)

- **Agent enforcement cue:** When changing a superclass, review inherited behavior, constructors, visibility, and contracts against every subclass invariant. Preserve assumptions that subclasses rely on for safety.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj02-j

### [OBJ03-J. Prevent heap pollution](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj03-j)

- **Agent enforcement cue:** Avoid raw types and unchecked generic operations that can put the wrong runtime type into a parameterized object. Parameterize APIs and isolate any unavoidable unchecked conversion behind a proven invariant.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj03-j

### [OBJ04-J. Provide mutable classes with copy functionality to safely allow passing instances to untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj04-j)

- **Agent enforcement cue:** Mutable classes should provide a copy constructor or static copy factory so disposable copies can be passed to untrusted code. Only a final class can safely advertise clone-based copying.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P3; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj04-j

### [OBJ05-J. Do not return references to private mutable class members](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj05-j)

- **Agent enforcement cue:** Never return a reference to a private mutable member. Return a defensive copy or a carefully constrained immutable/read-only representation.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj05-j

### [OBJ06-J. Defensively copy mutable inputs and mutable internal components](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj06-j)

- **Agent enforcement cue:** Defensively copy mutable inputs before validation/use and copy mutable internal components on output. This prevents time-of-check/time-of-use races and caller-driven invariant corruption.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj06-j

### [OBJ07-J. Sensitive classes must not let themselves be copied](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj07-j)

- **Agent enforcement cue:** Sensitive classes must not be cloneable or otherwise freely copyable. Disable or hide copy mechanisms so cloning cannot bypass constructor checks, singleton identity, or sensitive-state controls.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj07-j

### [OBJ08-J. Do not expose private members of an outer class from within a nested class](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj08-j)

- **Agent enforcement cue:** Do not expose an outer class's private mutable state through public nested-class methods, constructors, or returned references. Keep the nested class's boundary no wider than necessary.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj08-j

### [OBJ09-J. Compare classes and not class names](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj09-j)

- **Agent enforcement cue:** Compare Class objects or exact class identity, not class-name strings. Names can collide across packages or class loaders even when the runtime types are distinct.
- **Risk summary:** Severity=High; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj09-j

### [OBJ10-J. Do not use public static nonfinal fields](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj10-j)

- **Agent enforcement cue:** Do not expose public static nonfinal fields. Keep shared state private/static-final where possible and expose controlled accessors that validate updates and synchronize as needed.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj10-j

### [OBJ11-J. Be wary of letting constructors throw exceptions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj11-j)

- **Agent enforcement cue:** A constructor that fails can leave a partially initialized object; do not let it escape through callbacks, threads, or shared fields. Keep construction private/contained and clean up partial resources.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj11-j

### [OBJ12-J. Respect object-based annotations](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj12-j)

- **Agent enforcement cue:** Stub page. Treat object-based annotations as part of the API contract: preserve their semantic constraints in constructors, accessors, reflection, and generated/inherited code.
- **Source-page status:** Stub on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj12-j

### [OBJ13-J. Ensure that references to mutable objects are not exposed](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj13-j)

- **Agent enforcement cue:** Do not expose mutable object references through inputs, accessors, public constants, or static fields. Copy on ingress/egress or expose an immutable view with no mutation channel.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj13-j

### [OBJ14-J. Do not use an object that has been freed.](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj14-j)

- **Agent enforcement cue:** Stub page. Respect object/resource lifecycle states and do not use an object after close, free, invalidation, or other operation that ends its validity. Make invalid states explicit.
- **Source-page status:** Stub on the source page.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj14-j

## <a id="rule-06-methods-met"></a>Rule 06. Methods (MET)

**Family source:** [Rule 06. Methods (MET)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met)

**Family reading:** Honor method contracts, visibility, overriding, equality/ordering contracts, argument validation, and resource-lifecycle APIs.

**Individual entries:** 14

### [MET00-J. Validate method arguments](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met00-j)

- **Agent enforcement cue:** Validate method arguments at the interface that owns the contract, including null, range, size, format, and authorization preconditions. Reject invalid input before it can corrupt invariants or trigger unsafe work.
- **Risk summary:** Severity=High; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P9; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met00-j

### [MET01-J. Never use assertions to validate method arguments](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met01-j)

- **Agent enforcement cue:** Never use assert for public argument validation because assertions can be disabled. Throw the documented runtime exception or return an explicit failure according to the API contract.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=Yes; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met01-j

### [MET02-J. Do not use deprecated or obsolete classes or methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met02-j)

- **Agent enforcement cue:** Do not introduce deprecated or obsolete APIs in new code. Replace them with the supported API and plan migrations for existing calls whose semantics or security properties have changed.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met02-j

### [MET03-J. Methods that perform a security check must be declared private or final](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met03-j)

- **Agent enforcement cue:** Declare a method that enforces a security check private or final so a subclass cannot override it and silently remove the check. Keep the check close to the sensitive operation.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met03-j

### [MET04-J. Do not increase the accessibility of overridden or hidden methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met04-j)

- **Agent enforcement cue:** Do not widen the accessibility of an overridden or hidden method beyond its original contract. Prefer final methods/classes where inheritance is not required and preserve the intended access boundary.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met04-j

### [MET05-J. Ensure that constructors do not call overridable methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met05-j)

- **Agent enforcement cue:** Constructors must not call overridable instance methods. Use private/final helpers or post-construction initialization so a subclass cannot observe or mutate partially initialized state.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met05-j

### [MET06-J. Do not invoke overridable methods in clone()](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met06-j)

- **Agent enforcement cue:** clone() must not invoke overridable methods; a subclass could alter cloning while the object is partially initialized. Prefer a copy constructor/factory or private/final copy steps.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met06-j

### [MET07-J. Never declare a class method that hides a method declared in a superclass or superinterface](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met07-j)

- **Agent enforcement cue:** Do not declare a static method that hides a method in a superclass or superinterface. Rename or redesign the method so callers cannot receive different behavior based on the reference type.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met07-j

### [MET08-J. Preserve the equality contract when overriding the equals() method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met08-j)

- **Agent enforcement cue:** Implement equals with the full reflexive, symmetric, transitive, consistent, and non-null contract. Decide deliberately between exact-class and instanceof semantics and compare the same logical state everywhere.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met08-j

### [MET09-J. Classes that define an equals() method must also define a hashCode() method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met09-j)

- **Agent enforcement cue:** Whenever equals is overridden, override hashCode so equal objects have equal hashes. Use the same equality fields and do not mutate them while an object is used as a hash key.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met09-j

### [MET10-J. Follow the general contract when implementing the compareTo() method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met10-j)

- **Agent enforcement cue:** Implement compareTo with sign symmetry, transitivity, consistency, and safe numeric comparison. Do not subtract values to compare them when overflow can change the ordering.
- **Risk summary:** Severity=Medium; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met10-j

### [MET11-J. Ensure that keys used in comparison operations are immutable](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met11-j)

- **Agent enforcement cue:** Keep fields used by equals, hashCode, or compareTo immutable while an object is a key in a map/set or ordered collection. Remove/reinsert after a deliberate key change.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met11-j

### [MET12-J. Do not use finalizers](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met12-j)

- **Agent enforcement cue:** Do not use finalizers for resource management or security cleanup. Implement explicit close/AutoCloseable ownership and make cleanup deterministic.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met12-j

### [MET13-J. Do not assume that reassigning method arguments modifies the calling environment](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met13-j)

- **Agent enforcement cue:** Stub page. Java passes arguments by value: reassigning a parameter changes only the local variable. Return a new value or intentionally mutate a documented object when caller-visible change is required.
- **Source-page status:** Stub on the source page.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met13-j

## <a id="rule-07-exceptional-behavior-err"></a>Rule 07. Exceptional Behavior (ERR)

**Family source:** [Rule 07. Exceptional Behavior (ERR)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err)

**Family reading:** Preserve control-flow, state, diagnostic, and information-security properties when operations fail.

**Individual entries:** 10

### [ERR00-J. Do not suppress or ignore checked exceptions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err00-j)

- **Agent enforcement cue:** Every checked-exception catch must recover, rethrow, or translate to a context-appropriate exception. Never use an empty or cosmetic catch that lets execution continue without restored invariants.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err00-j

### [ERR01-J. Do not allow exceptions to expose sensitive information](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err01-j)

- **Agent enforcement cue:** Do not expose filesystem layout, query details, credentials, stack traces, or sensitive exception types/messages across a trust boundary. Log a controlled diagnostic internally and return a safe external error.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=Yes; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err01-j

### [ERR02-J. Prevent exceptions while logging data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err02-j)

- **Agent enforcement cue:** Make logging failure-tolerant so an exception during logging cannot hide the security event being logged. Use a guarded logger or fallback path and preserve the original failure.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err02-j

### [ERR03-J. Restore prior object state on method failure](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err03-j)

- **Agent enforcement cue:** A mutating method must leave its object in the prior valid state when it fails. Validate before mutation or use rollback/transaction-like restoration, including cleanup on every exceptional path.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err03-j

### [ERR04-J. Do not complete abruptly from a finally block](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err04-j)

- **Agent enforcement cue:** Do not use return, break, continue, or throw in finally. Let finally perform cleanup without replacing or suppressing the outcome and exception from the try/catch path.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err04-j

### [ERR05-J. Do not let checked exceptions escape from a finally block](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err05-j)

- **Agent enforcement cue:** Catch and handle checked exceptions raised during finally cleanup, or use try-with-resources so cleanup exceptions are managed as suppressed exceptions. Do not lose the primary failure.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err05-j

### [ERR06-J. Do not throw undeclared checked exceptions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err06-j)

- **Agent enforcement cue:** Do not use sneaky throws, unsafe reflection, bytecode tricks, or obsolete APIs to emit undeclared checked exceptions. Declare or handle every checked exception and use correctly typed constructors/APIs.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err06-j

### [ERR07-J. Do not throw RuntimeException, Exception, or Throwable](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err07-j)

- **Agent enforcement cue:** Throw a specific exception type that communicates the failure and supports recovery. Do not throw the generic RuntimeException, Exception, or Throwable types as the public failure contract.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err07-j

### [ERR08-J. Do not catch NullPointerException or any of its ancestors](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err08-j)

- **Agent enforcement cue:** Do not catch NullPointerException or a broad ancestor to mask a bug. Identify the null-producing operation and validate or repair that precondition explicitly.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err08-j

### [ERR09-J. Do not allow untrusted code to terminate the JVM](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err09-j)

- **Agent enforcement cue:** Prevent untrusted code from calling System.exit or otherwise terminating the JVM. Use a controlled shutdown path with cleanup and authorization instead of process-wide termination from request code.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/exceptional-behavior-err/err09-j

## <a id="rule-08-visibility-and-atomicity-vna"></a>Rule 08. Visibility and Atomicity (VNA)

**Family source:** [Rule 08. Visibility and Atomicity (VNA)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna)

**Family reading:** Use the Java memory model, synchronization, volatile state, and atomic utilities so shared state is visible and compound actions are indivisible.

**Individual entries:** 6

### [VNA00-J. Ensure visibility when accessing shared primitive variables](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna00-j)

- **Agent enforcement cue:** Make shared primitive reads/writes visible with volatile or consistent synchronization. Remember that visibility alone does not make a read-modify-write operation atomic.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna00-j

### [VNA01-J. Ensure visibility of shared references to immutable objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna01-j)

- **Agent enforcement cue:** Safely publish shared references even when the referenced object is immutable. Use final-field construction plus a happens-before publication mechanism such as volatile, locking, or static initialization.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna01-j

### [VNA02-J. Ensure that compound operations on shared variables are atomic](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna02-j)

- **Agent enforcement cue:** Protect compound operations on shared state with a lock, atomic class, or CAS loop. ++, --, and compound assignments are read-modify-write sequences, not single atomic actions.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna02-j

### [VNA03-J. Do not assume that a group of calls to independently atomic methods is atomic](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna03-j)

- **Agent enforcement cue:** Do not infer whole-operation atomicity from individually thread-safe calls. Guard the invariant across the complete sequence with one lock, an atomic API, or a transaction-like operation.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna03-j

### [VNA04-J. Ensure that calls to chained methods are atomic](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna04-j)

- **Agent enforcement cue:** A chain of independently atomic fluent calls is not atomic as a whole. Lock the complete chain or expose one method that performs the invariant-preserving operation atomically.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna04-j

### [VNA05-J. Ensure atomicity when reading and writing 64-bit values](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna05-j)

- **Agent enforcement cue:** Use volatile, synchronized access, or an atomic holder for shared long/double values when a torn 64-bit read/write would be unsafe. Do not rely on incidental platform atomicity.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/visibility-and-atomicity-vna/vna05-j

## <a id="rule-09-locking-lck"></a>Rule 09. Locking (LCK)

**Family source:** [Rule 09. Locking (LCK)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck)

**Family reading:** Choose private, stable locks; acquire and release them consistently; avoid deadlock, blocking while locked, and assumptions about undocumented locking.

**Individual entries:** 12

### [LCK00-J. Use private final lock objects to synchronize classes that may interact with untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck00-j)

- **Agent enforcement cue:** Synchronize on a private final lock object, not this or another object visible to untrusted code. Keep the lock's ownership and scope internal to the class.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck00-j

### [LCK01-J. Do not synchronize on objects that may be reused](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck01-j)

- **Agent enforcement cue:** Never lock on reusable or publicly reachable objects such as interned strings, boxed values, collection elements, or caller-supplied objects. Use a private stable lock.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck01-j

### [LCK02-J. Do not synchronize on the class object returned by getClass()](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck02-j)

- **Agent enforcement cue:** Do not synchronize on getClass(), because subclasses have different Class objects and can split the protection. Use a deliberately chosen private instance or static lock.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck02-j

### [LCK03-J. Do not synchronize on the intrinsic locks of high-level concurrency objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck03-j)

- **Agent enforcement cue:** Use the Lock and Condition APIs for high-level concurrency objects; do not mix their intrinsic monitors with their explicit locks. Synchronize on the mechanism that actually protects the state.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck03-j

### [LCK04-J. Do not synchronize on a collection view if the backing collection is accessible](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck04-j)

- **Agent enforcement cue:** When iterating a collection view, synchronize on the accessible backing collection using the collection's documented policy, not on the view object that may not protect the backing data.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck04-j

### [LCK05-J. Synchronize access to static fields that can be modified by untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck05-j)

- **Agent enforcement cue:** Guard mutable static state internally whenever untrusted code can call the mutating method. Do not depend on clients to acquire a lock consistently.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck05-j

### [LCK06-J. Do not use an instance lock to protect shared static data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck06-j)

- **Agent enforcement cue:** Protect shared static data with a class/static lock or another shared synchronization object; an instance lock protects only one instance and fails when multiple instances exist.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck06-j

### [LCK07-J. Avoid deadlock by requesting and releasing locks in the same order](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck07-j)

- **Agent enforcement cue:** Define a global lock order and acquire/release nested locks in that same order everywhere. Avoid cycles in the wait-for graph and document ordering assumptions.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P3; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck07-j

### [LCK08-J. Ensure actively held locks are released on exceptional conditions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck08-j)

- **Agent enforcement cue:** After acquiring a lock, release it in a finally path even when work throws. Track ownership correctly and do not unlock from a thread that does not own the lock.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=Yes; Priority=P9; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck08-j

### [LCK09-J. Do not perform operations that can block while holding a lock](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck09-j)

- **Agent enforcement cue:** Do not perform network, file, console, serialization, indefinite wait, or other blocking work while holding a lock. Snapshot state under lock, then do slow work outside it.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck09-j

### [LCK10-J. Use a correct form of the double-checked locking idiom](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck10-j)

- **Agent enforcement cue:** Use volatile publication plus a synchronized second check, or the initialization-on-demand holder idiom, for lazy initialization. The design must establish happens-before for both the reference and complete object construction.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck10-j

### [LCK11-J. Avoid client-side locking when using classes that do not commit to their locking strategy](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck11-j)

- **Agent enforcement cue:** Do not client-lock on a library object whose locking strategy is undocumented or not guaranteed. Expose/use an atomic library operation or guard the invariant with a lock you own.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/locking-lck/lck11-j

## <a id="rule-10-thread-apis-thi"></a>Rule 10. Thread APIs (THI)

**Family source:** [Rule 10. Thread APIs (THI)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi)

**Family reading:** Use thread lifecycle and wait/notify APIs correctly, with cooperative cancellation and predicates that remain true after wake-up.

**Individual entries:** 6

### [THI00-J. Do not invoke Thread.run()](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi00-j)

- **Agent enforcement cue:** Start a thread with start() or submit work to an executor; calling run() directly executes on the current thread and may bypass the intended concurrency model.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi00-j

### [THI01-J. Do not invoke ThreadGroup methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi01-j)

- **Agent enforcement cue:** Avoid ThreadGroup convenience/control methods. Use explicit Thread/Executor lifecycle, interruption, and task tracking so ownership and termination remain understandable.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi01-j

### [THI02-J. Notify all waiting threads rather than a single thread](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi02-j)

- **Agent enforcement cue:** Notify all waiters when more than one predicate or waiter may become eligible. Hold the same monitor used for waiting, and let each waiter recheck its own condition.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=Yes; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi02-j

### [THI03-J. Always invoke wait() and await() methods inside a loop](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi03-j)

- **Agent enforcement cue:** Call wait() or await() only while holding the associated monitor/lock and inside a loop that checks the condition predicate. Handle spurious wakeups, interrupts, and timeouts.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi03-j

### [THI04-J. Ensure that threads performing blocking operations can be terminated](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi04-j)

- **Agent enforcement cue:** Every task that can block on I/O or another indefinite operation needs an explicit cancellation/termination path, such as interrupt plus close/deadline, so it cannot pin a thread forever.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi04-j

### [THI05-J. Do not use Thread.stop() to terminate threads](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi05-j)

- **Agent enforcement cue:** Never use Thread.stop to terminate work. Use cooperative cancellation, interruption, state flags, deadlines, and resource closure so invariants remain intact.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-apis-thi/thi05-j

## <a id="rule-11-thread-pools-tps"></a>Rule 11. Thread Pools (TPS)

**Family source:** [Rule 11. Thread Pools (TPS)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps)

**Family reading:** Bound concurrency, preserve cancellation and failure signals, avoid starvation deadlocks, and clear per-thread state in pooled workers.

**Individual entries:** 5

### [TPS00-J. Use thread pools to enable graceful degradation of service during traffic bursts](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps00-j)

- **Agent enforcement cue:** Use bounded thread pools, queues, admission control, timeouts, and backpressure to absorb bursts with graceful degradation. Do not create an unbounded thread per request.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps00-j

### [TPS01-J. Do not execute interdependent tasks in a bounded thread pool](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps01-j)

- **Agent enforcement cue:** Do not submit a task to a bounded pool when it synchronously waits for another task that must run in the same pool. Use separate capacity or nonblocking composition to avoid thread-starvation deadlock.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps01-j

### [TPS02-J. Ensure that tasks submitted to a thread pool are interruptible](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps02-j)

- **Agent enforcement cue:** Tasks submitted to a pool that must shut down/cancel must respond to interruption, clean up, and preserve the interrupt status when appropriate. Do not submit uninterruptible work to that pool.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps02-j

### [TPS03-J. Ensure that tasks executing in a thread pool do not fail silently](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps03-j)

- **Agent enforcement cue:** Make every pooled task failure observable through Future.get, a task wrapper, an uncaught-exception handler, or equivalent reporting. Log/alert and clean up rather than allowing silent failure.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps03-j

### [TPS04-J. Ensure ThreadLocal variables are reinitialized when using thread pools](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps04-j)

- **Agent enforcement cue:** Reinitialize request/task-specific ThreadLocal state for every pooled task and remove it in finally. Never let credentials, tenant IDs, transactions, or user data bleed into the next task.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-pools-tps/tps04-j

## <a id="rule-12-thread-safety-miscellaneous-tsm"></a>Rule 12. Thread-Safety Miscellaneous (TSM)

**Family source:** [Rule 12. Thread-Safety Miscellaneous (TSM)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm)

**Family reading:** Do not weaken inherited thread-safety guarantees or publish objects before their construction and initialization are complete.

**Individual entries:** 4

### [TSM00-J. Do not override thread-safe methods with methods that are not thread-safe](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm00-j)

- **Agent enforcement cue:** A subclass must preserve the thread-safety contract of an inherited method. Do not replace synchronized/atomic behavior with an unsynchronized implementation, and document any inheritance locking policy.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm00-j

### [TSM01-J. Do not let the this reference escape during object construction](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm01-j)

- **Agent enforcement cue:** Do not let this escape from a constructor via callbacks, listener registration, shared fields, static state, or a started thread. Publish the object only after construction completes.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm01-j

### [TSM02-J. Do not use background threads during class initialization](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm02-j)

- **Agent enforcement cue:** Complete class initialization before starting background threads. Static initialization that starts work can create circular waits or deadlock between the initializer and its worker.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm02-j

### [TSM03-J. Do not publish partially initialized objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm03-j)

- **Agent enforcement cue:** Publish shared objects only after complete initialization and with safe-publication semantics such as final fields, volatile, synchronization, or an immutable holder. Never expose a partially built object.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P8; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/thread-safety-miscellaneous-tsm/tsm03-j

## <a id="rule-13-input-output-fio"></a>Rule 13. Input Output (FIO)

**Family source:** [Rule 13. Input Output (FIO)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio)

**Family reading:** Use secure paths and permissions, check I/O results, close resources, handle stream contracts, and clean up reliably.

**Individual entries:** 17

### [FIO00-J. Do not operate on files in shared directories](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio00-j)

- **Agent enforcement cue:** Operate only in secure, non-shared directories. Resolve and create files safely, account for links and special files, and prevent another user/process from swapping a path between check and use.
- **Risk summary:** Severity=Medium; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio00-j

### [FIO01-J. Create files with appropriate access permissions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio01-j)

- **Agent enforcement cue:** Create files with restrictive permissions atomically, before sensitive contents are exposed. Use least privilege and verify the resulting owner/mode where the platform permits it.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio01-j

### [FIO02-J. Detect and handle file-related errors](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio02-j)

- **Agent enforcement cue:** Check boolean, count, and status returns from file APIs and handle failure deliberately. Do not assume a file operation succeeded merely because no exception was thrown.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio02-j

### [FIO03-J. Remove temporary files before termination](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio03-j)

- **Agent enforcement cue:** Create temporary files in a secure location with secure permissions and delete them on every normal/error path, typically with try/finally or try-with-resources plus a bounded cleanup strategy.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio03-j

### [FIO04-J. Release resources when they are no longer needed](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio04-j)

- **Agent enforcement cue:** Release files, streams, descriptors, database connections, locks, semaphores, and other non-memory resources as soon as ownership ends. Prefer try-with-resources and do not depend on finalizers.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio04-j

### [FIO05-J. Do not expose buffers or their backing arrays methods to untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio05-j)

- **Agent enforcement cue:** Do not give untrusted callers a buffer or backing array that aliases protected mutable data. Copy it or expose a genuinely read-only/isolated view with a clear ownership contract.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio05-j

### [FIO06-J. Do not create multiple buffered wrappers on a single byte or character stream](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio06-j)

- **Agent enforcement cue:** Use at most one buffered wrapper for a given byte or character stream. Share that wrapper or pass it to consumers; multiple look-ahead buffers can consume and reorder data unpredictably.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio06-j

### [FIO07-J. Do not let external processes block on IO buffers](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio07-j)

- **Agent enforcement cue:** When starting an external process, continuously drain its stdout and stderr, provide/close stdin as appropriate, and wait with cancellation/timeouts so child processes cannot block on full pipes.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio07-j

### [FIO08-J. Distinguish between characters or bytes read from a stream and -1](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio08-j)

- **Agent enforcement cue:** Keep InputStream.read and Reader.read results in an int until testing for -1. Only then convert a valid byte/character value; -1 means end-of-stream, not data.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P18; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio08-j

### [FIO09-J. Do not rely on the write() method to output integers outside the range 0 to 255](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio09-j)

- **Agent enforcement cue:** OutputStream.write(int) emits only the low eight bits. Range-check the integer or use an explicit byte/character encoding API when values outside 0..255 must be preserved.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=Yes; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio09-j

### [FIO10-J. Ensure the array is filled when using read() to fill an array](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio10-j)

- **Agent enforcement cue:** A read into an array can be partial. Loop using the returned count until the requested region is filled or EOF/error occurs; never treat one read call as a fill guarantee.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio10-j

### [FIO11-J. Do not convert between strings and bytes without specifying a valid character encoding](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio11-j)

- **Agent enforcement cue:** Deprecated/moved page. Always specify a charset when converting between bytes and strings; use StandardCharsets or STR04-J rather than a platform default.
- **Source-page status:** Deprecated or moved on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio11-j

### [FIO12-J. Provide methods to read and write little-endian data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio12-j)

- **Agent enforcement cue:** Make little-endian encoding explicit at the API boundary, using a tested byte-order helper or ByteBuffer with LITTLE_ENDIAN. Do not assume Java's default big-endian order matches the peer.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio12-j

### [FIO13-J. Do not log sensitive information outside a trust boundary](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio13-j)

- **Agent enforcement cue:** Do not place passwords, tokens, keys, full payment data, or other sensitive values in logs outside the authorized trust boundary. Redact, minimize, protect, and retain only what incident response needs.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio13-j

### [FIO14-J. Perform proper cleanup at program termination](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio14-j)

- **Agent enforcement cue:** When failing fast or terminating, release resources, flush/close streams, remove temporary data, and leave durable state consistent. Use a carefully scoped shutdown hook only for cleanup that must survive normal termination.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio14-j

### [FIO15-J. Do not reset a servlet's output stream after committing it](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio15-j)

- **Agent enforcement cue:** Choose status, headers, encoding, and response behavior before a servlet response is committed. After commit, do not reset the output stream or buffer to undo the already-sent response.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio15-j

### [FIO16-J. Canonicalize path names before validating them](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio16-j)

- **Agent enforcement cue:** Canonicalize/normalize a path before validating it, resolve it under a trusted base directory, and reject traversal, alternate spellings, links, or any result outside the allowed root.
- **Risk summary:** Severity=Medium; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio16-j

## <a id="rule-14-serialization-ser"></a>Rule 14. Serialization (SER)

**Family source:** [Rule 14. Serialization (SER)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser)

**Family reading:** Treat serialization as a public, security-sensitive construction and transport mechanism with explicit compatibility, integrity, confidentiality, and validation.

**Individual entries:** 13

### [SER00-J. Enable serialization compatibility during class evolution](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser00-j)

- **Agent enforcement cue:** Choose and declare a serialization evolution strategy, including serialVersionUID and custom compatibility behavior where needed. Test old streams against new classes before treating the wire form as stable.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser00-j

### [SER01-J. Do not deviate from the proper signatures of serialization methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser01-j)

- **Agent enforcement cue:** Use the exact private signatures required for readObject, writeObject, readObjectNoData, and related serialization hooks. A near-match silently fails to provide the intended security/compatibility behavior.
- **Risk summary:** Severity=High; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P18; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser01-j

### [SER02-J. Sign then seal objects before sending them outside a trust boundary](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser02-j)

- **Agent enforcement cue:** Protect an object crossing a trust boundary with confidentiality/integrity: seal or encrypt the serialized data first, then sign the sealed representation, and verify before deserializing/using it.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser02-j

### [SER03-J. Do not serialize unencrypted sensitive data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser03-j)

- **Agent enforcement cue:** Never serialize plaintext secrets, keys, certificates, or sensitive object graphs. Mark fields transient or implement encrypted custom serialization with deliberate key management.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser03-j

### [SER04-J. Do not allow serialization and deserialization to bypass the security manager](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser04-j)

- **Agent enforcement cue:** Repeat constructor/security-manager checks during deserialization because constructors can be bypassed. Reject unauthorized state before the object becomes usable.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P18; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser04-j

### [SER05-J. Do not serialize instances of inner classes](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser05-j)

- **Agent enforcement cue:** Do not serialize non-static inner, local, or anonymous classes. Use a top-level or static nested transfer type with explicit stable fields instead of compiler-generated outer references.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser05-j

### [SER06-J. Make defensive copies of private mutable components during deserialization](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser06-j)

- **Agent enforcement cue:** In readObject, defensively copy private mutable fields and validate them before storing. Never allow attacker-supplied serialized references to become the object's internal mutable components.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=Yes; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser06-j

### [SER07-J. Do not use the default serialized form for classes with implementation-defined invariants](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser07-j)

- **Agent enforcement cue:** Do not use the default serialized form for classes with invariants, transient state, derived state, or representation constraints. Define a controlled form and re-establish invariants during readObject.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser07-j

### [SER08-J. Minimize privileges before deserializing from a privileged context](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser08-j)

- **Agent enforcement cue:** Avoid deserialization from a privileged context. If privileges are unavoidable, strip everything except the minimum permission set before reading attacker-influenced bytes.
- **Risk summary:** Severity=High; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P18; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser08-j

### [SER09-J. Do not invoke overridable methods from the readObject() method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser09-j)

- **Agent enforcement cue:** readObject is constructor-like and runs before initialization is complete. It must not call overridable methods; use private/final validation helpers until the object is fully established.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser09-j

### [SER10-J. Avoid memory and resource leaks during serialization](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser10-j)

- **Agent enforcement cue:** Do not retain serialized object graphs indefinitely through ObjectOutputStream handle tables or open streams. Reset/close streams at logical boundaries and release references after serialization.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser10-j

### [SER11-J. Prevent overwriting of externalizable objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser11-j)

- **Agent enforcement cue:** Control when readExternal/writeExternal may run and validate their state transitions. Prevent untrusted callers from invoking externalization hooks to overwrite an object at an arbitrary time.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser11-j

### [SER12-J. Prevent deserialization of untrusted data](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser12-j)

- **Agent enforcement cue:** Do not deserialize untrusted data. Prefer a constrained data format; if legacy serialization is unavoidable, allowlist/filter classes, validate size and graph shape, isolate the operation, and apply least privilege.
- **Risk summary:** Severity=High; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P9; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/serialization-ser/ser12-j

## <a id="rule-15-platform-security-sec"></a>Rule 15. Platform Security (SEC)

**Family source:** [Rule 15. Platform Security (SEC)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec)

**Family reading:** Constrain privilege, reflection, class loading, custom permissions, and trust-boundary crossings.

**Individual entries:** 11

### [SEC00-J. Do not allow privileged blocks to leak sensitive information across a trust boundary](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec00-j)

- **Agent enforcement cue:** Keep doPrivileged blocks small and non-leaking: validate before entry, perform only the required privileged action, and do not return sensitive data or capabilities to less-trusted callers.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec00-j

### [SEC01-J. Do not allow tainted variables in privileged blocks](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec01-j)

- **Agent enforcement cue:** Never use tainted/unvalidated values inside a privileged block. Hard-code safe parameters when possible and validate/sanitize all remaining values before privilege is acquired.
- **Risk summary:** Severity=High; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P9; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec01-j

### [SEC02-J. Do not base security checks on untrusted sources](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec02-j)

- **Agent enforcement cue:** Base authorization checks on trusted snapshots, not mutable caller-controlled objects. Use a deep defensive copy or immutable representation before checking security-sensitive properties.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec02-j

### [SEC03-J. Do not load trusted classes after allowing untrusted code to load arbitrary classes](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec03-j)

- **Agent enforcement cue:** If untrusted code can load classes, preload all trusted classes needed later before allowing that activity. Prevent a malicious class with a matching name from replacing the intended trusted type.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec03-j

### [SEC04-J. Protect sensitive operations with security manager checks](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec04-j)

- **Agent enforcement cue:** Protect sensitive operations with an authorization/security-manager check at the operation boundary, and fail closed when the caller lacks permission. On modern Java, map the principle to the application's explicit authorization layer.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=Yes; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec04-j

### [SEC05-J. Do not use reflection to increase accessibility of classes, methods, or fields](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec05-j)

- **Agent enforcement cue:** Do not use reflection to bypass access controls (for example setAccessible) on security-sensitive classes, fields, or methods. Prefer an explicit safe API and enforce authorization before reflective work.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec05-j

### [SEC06-J. Do not rely on the default automatic signature verification provided by URLClassLoader and java.util.jar](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec06-j)

- **Agent enforcement cue:** Do not trust URLClassLoader or JAR default signature behavior as the whole verification policy. Explicitly verify signer identity and certificate expectations before executing privileged code.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec06-j

### [SEC07-J. Call the superclass's getPermissions() method when writing a custom class loader](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec07-j)

- **Agent enforcement cue:** A custom class loader's getPermissions must call the superclass implementation first, then add only justified permissions. Ignoring the system policy can grant elevated rights to untrusted classes.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=Yes; Repairable=No; Priority=P12; Level=L1
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec07-j

### [SEC08-J Trusted code must discard or clean any arguments provided by untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec08-j)

- **Agent enforcement cue:** Under-construction page. Trusted code must discard, sanitize, or otherwise clean arguments received from untrusted code before using them in security-sensitive operations; do not pass them through unchanged.
- **Source-page status:** Under construction/incomplete on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec08-j

### [SEC09-J Never leak the results of certain standard API methods from trusted code to untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec09-j)

- **Agent enforcement cue:** Under-construction page. Do not leak results of the identified sensitive standard APIs from trusted to untrusted code, including through transitive return paths; audit the call graph and escapes.
- **Source-page status:** Under construction/incomplete on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec09-j

### [SEC10-J Never permit untrusted code to invoke any API that may (possibly transitively) invoke the reflection APIs](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec10-j)

- **Agent enforcement cue:** Under-construction page. Do not expose any API to untrusted code if it can eventually invoke reflection with trusted authority. Review indirect/transitive calls, not only direct reflection calls.
- **Source-page status:** Under construction/incomplete on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec10-j

## <a id="rule-16-runtime-environment-env"></a>Rule 16. Runtime Environment (ENV)

**Family source:** [Rule 16. Runtime Environment (ENV)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env)

**Family reading:** Keep signing, permissions, bytecode verification, monitoring, and production/runtime configuration from creating unintended authority or attack surface.

**Individual entries:** 7

### [ENV00-J. Do not sign code that performs only unprivileged operations](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env00-j)

- **Agent enforcement cue:** Sign code only when it needs the elevated authority associated with a trusted signer. Keep code that performs only unprivileged work unsigned so users do not grant it unnecessary privilege.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env00-j

### [ENV01-J. Place all security-sensitive code in a single JAR and sign and seal it](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env01-j)

- **Agent enforcement cue:** Keep security-sensitive code together in one signed and sealed JAR. Prevent mix-and-match loading that lets trusted privileged code be combined with attacker-controlled classes or packages.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env01-j

### [ENV02-J. Do not trust the values of environment variables](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env02-j)

- **Agent enforcement cue:** Deprecated page. If environment variables are still used, treat their values as attacker-controlled configuration rather than as an authorization or integrity signal; prefer a current, explicit configuration boundary.
- **Source-page status:** Deprecated or moved on the source page.
- **Risk summary:** Severity=Low; Likelihood=Likely; Detectable=Yes; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env02-j

### [ENV03-J. Do not grant dangerous combinations of permissions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env03-j)

- **Agent enforcement cue:** Do not grant permission combinations that create more capability than intended, and avoid broad grants such as AllPermission. Grant the minimum permissions to the smallest trusted code set.
- **Risk summary:** Severity=High; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P9; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env03-j

### [ENV04-J. Do not disable bytecode verification](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env04-j)

- **Agent enforcement cue:** Never disable JVM bytecode verification or ship around it. Let the verifier check class-file structure, types, and operand-stack safety before code executes.
- **Risk summary:** Severity=High; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P9; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env04-j

### [ENV05-J. Do not deploy an application that can be remotely monitored](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env05-j)

- **Agent enforcement cue:** Disable remote JVMTI, JPDA, JMX, and related monitoring/debug access in production, or protect it with a tightly controlled authenticated boundary. Remote inspection can expose data and control execution.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env05-j

### [ENV06-J. Production code must not contain debugging entry points](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env06-j)

- **Agent enforcement cue:** Remove debug entry points, back doors, test hooks, and accidental production main methods from deployable code. Test-only access must not be reachable in the production artifact.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env06-j

## <a id="rule-17-java-native-interface-jni"></a>Rule 17. Java Native Interface (JNI)

**Family source:** [Rule 17. Java Native Interface (JNI)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni)

**Family reading:** Treat native code as outside Java's safety checks; wrap it, validate boundaries, and use JNI reference and string semantics correctly.

**Individual entries:** 5

### [JNI00-J. Define wrappers around native methods](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni00-j)

- **Agent enforcement cue:** Make each native method private and expose it only through a Java wrapper that performs authorization, argument validation, defensive copying, native-call error handling, and return-value validation.
- **Risk summary:** Severity=Medium; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P4; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni00-j

### [JNI01-J. Safely invoke standard APIs that perform tasks using the immediate caller's class loader instance (loadLibrary)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni01-j)

- **Agent enforcement cue:** Only trusted code should invoke caller-sensitive APIs such as System.loadLibrary. Do not let untrusted callers choose a class loader or native library path that bypasses Java security checks.
- **Source-page status:** Under construction/incomplete on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni01-j

### [JNI02-J. Do not assume object references are constant or unique](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni02-j)

- **Agent enforcement cue:** JNI reference values are not stable identifiers. Never compare them with == or !=; use IsSameObject when testing whether two references denote the same Java object.
- **Source-page status:** Under construction/incomplete on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni02-j

### [JNI03-J. Do not use direct pointers to Java objects in JNI code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni03-j)

- **Agent enforcement cue:** Use JNI local/global/weak-global references and manage their lifetime. Never retain raw native pointers to movable Java objects; keep a valid JNI reference while the object is in use.
- **Source-page status:** Under construction/incomplete on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni03-j

### [JNI04-J. Do not assume that Java strings are null-terminated](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni04-j)

- **Agent enforcement cue:** Java strings are UTF-16 and are not null-terminated; U+0000 can occur in the middle. Use JNI-provided lengths and string accessors rather than C-string termination assumptions.
- **Source-page status:** Under construction/incomplete on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni04-j

## <a id="rule-49-miscellaneous-msc"></a>Rule 49. Miscellaneous (MSC)

**Family source:** [Rule 49. Miscellaneous (MSC)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc)

**Family reading:** Cover cross-cutting secure networking, randomness, secrets, memory, collections, singletons, servlet state, and OAuth behavior.

**Individual entries:** 12

### [MSC00-J. Use SSLSocket rather than Socket for secure data exchange](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc00-j)

- **Agent enforcement cue:** Use SSLSocket or another correctly configured TLS client for sensitive data instead of raw Socket. Verify the peer certificate and hostname and use current protocol/cipher settings.
- **Risk summary:** Severity=Medium; Likelihood=Likely; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc00-j

### [MSC01-J. Do not use an empty infinite loop](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc01-j)

- **Agent enforcement cue:** Do not ship an empty infinite loop. Every loop must have a meaningful wait/progress condition, termination/cancellation behavior, or explicit blocking primitive.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=Yes; Priority=P3; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc01-j

### [MSC02-J. Generate strong random numbers](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc02-j)

- **Agent enforcement cue:** Use SecureRandom for keys, tokens, nonces, reset codes, and other security decisions. java.util.Random and predictable seeds are not security randomness.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc02-j

### [MSC03-J. Never hard code sensitive information](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc03-j)

- **Agent enforcement cue:** Never hard-code passwords, API keys, private keys, encryption material, or other sensitive configuration in source or class files. Inject secrets through a controlled secret/configuration mechanism.
- **Risk summary:** Severity=High; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P6; Level=L2
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc03-j

### [MSC04-J. Do not leak memory](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc04-j)

- **Agent enforcement cue:** Release references, listeners, caches, handles, and other reachability roots when their work ends so unused objects can be collected. Bound caches and unregister callbacks.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=No; Repairable=No; Priority=P1; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc04-j

### [MSC05-J. Do not exhaust heap space](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc05-j)

- **Agent enforcement cue:** Bound all attacker-influenced allocations, input sizes, recursion, decompression, and accumulation. Reject or stream oversized data before an OutOfMemoryError can terminate the service.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc05-j

### [MSC06-J. Do not modify the underlying collection when an iteration is in progress](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc06-j)

- **Agent enforcement cue:** Do not structurally modify a collection during iteration except through the iterator's supported remove operation. Use a snapshot, separate pass, or synchronized mutation strategy.
- **Risk summary:** Severity=Low; Likelihood=Probable; Detectable=No; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc06-j

### [MSC07-J. Prevent multiple instantiations of singleton objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc07-j)

- **Agent enforcement cue:** Enforce one singleton instance under concurrency and across reflection, cloning, and deserialization as applicable. Prefer a robust holder/enum design and keep construction inaccessible.
- **Risk summary:** Severity=Low; Likelihood=Unlikely; Detectable=Yes; Repairable=No; Priority=P2; Level=L3
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc07-j

### [MSC08-J. Do not store nonserializable objects as attributes in an HTTP session](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc08-j)

- **Agent enforcement cue:** Stub page. Store only serializable, version-tolerant state in an HTTP session, or use an explicit external/session store for nonserializable resources; never serialize live handles accidentally.
- **Source-page status:** Stub on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc08-j

### [MSC09-J. For OAuth, ensure (a) [relying party receiving user's ID in last step] is same as (b) [relying party the access token was granted to].](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc09-j)

- **Agent enforcement cue:** Under-construction page. Bind the relying party that receives the user's identity in the final OAuth step to the same relying party to which the access token was granted; reject an identity/token audience mismatch.
- **Source-page status:** Under construction/incomplete on the source page.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc09-j

### [MSC10-J. Do not use OAuth 2.0 implicit grant (unmodified) for authentication](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc10-j)

- **Agent enforcement cue:** Do not use the unmodified OAuth 2.0 implicit grant as an authentication mechanism. It may authorize access, but authentication requires a protocol such as a properly validated identity flow.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc10-j

### [MSC11-J. Do not let session information leak within a servlet](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc11-j)

- **Agent enforcement cue:** Keep per-client state in HttpSession or request-scoped structures, not servlet instance fields shared by concurrent requests. Prevent cross-session data leaks and races.
- **Risk summary:** Not stated in the family risk summary
- **Source:** https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc11-j

## Source-page caveats

- [ENV02-J. Do not trust the values of environment variables](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/runtime-environment-env/env02-j) — Deprecated or moved on the source page.
- [EXP05-J. Do not follow a write by a subsequent write or read of the same object within an expression](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp05-j) — Deprecated or moved on the source page.
- [EXP07-J. Prevent loss of useful data due to weak references](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/expressions-exp/exp07-j) — Stub on the source page.
- [FIO11-J. Do not convert between strings and bytes without specifying a valid character encoding](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-output-fio/fio11-j) — Deprecated or moved on the source page.
- [IDS15-J. Do not allow sensitive information to leak outside a trust boundary](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids15-j) — Stub on the source page.
- [JNI01-J. Safely invoke standard APIs that perform tasks using the immediate caller's class loader instance (loadLibrary)](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni01-j) — Under construction/incomplete on the source page.
- [JNI02-J. Do not assume object references are constant or unique](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni02-j) — Under construction/incomplete on the source page.
- [JNI03-J. Do not use direct pointers to Java objects in JNI code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni03-j) — Under construction/incomplete on the source page.
- [JNI04-J. Do not assume that Java strings are null-terminated](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/java-native-interface-jni/jni04-j) — Under construction/incomplete on the source page.
- [MET13-J. Do not assume that reassigning method arguments modifies the calling environment](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/methods-met/met13-j) — Stub on the source page.
- [MSC08-J. Do not store nonserializable objects as attributes in an HTTP session](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc08-j) — Stub on the source page.
- [MSC09-J. For OAuth, ensure (a) [relying party receiving user's ID in last step] is same as (b) [relying party the access token was granted to].](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/miscellaneous-msc/msc09-j) — Under construction/incomplete on the source page.
- [NUM04-J. Do not use floating-point numbers if precise computation is required](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/numeric-types-and-operations-num/num04-j) — Deprecated or moved on the source page.
- [OBJ12-J. Respect object-based annotations](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj12-j) — Stub on the source page.
- [OBJ14-J. Do not use an object that has been freed.](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/object-orientation-obj/obj14-j) — Stub on the source page.
- [SEC08-J Trusted code must discard or clean any arguments provided by untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec08-j) — Under construction/incomplete on the source page.
- [SEC09-J Never leak the results of certain standard API methods from trusted code to untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec09-j) — Under construction/incomplete on the source page.
- [SEC10-J Never permit untrusted code to invoke any API that may (possibly transitively) invoke the reflection APIs](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/platform-security-sec/sec10-j) — Under construction/incomplete on the source page.
- The standards site itself warns that the Java standard is a work in progress and that pages may be incomplete or contain errors. Re-check the linked page when a rule is used as a release gate or when Java/Android platform behavior has changed.

## Primary source

[SEI CERT Oracle Coding Standard for Java](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/)

1