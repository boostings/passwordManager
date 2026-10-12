# SEI CERT Oracle Coding Standard for Java: Recommendations (Rec. 05, 06, 07, 13)

Every recommendation in the four selected families. Titles and codes come from the [CERT recommendations index](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/); the guidance lines are short summaries in our own words. Recommendations are advice, not requirements like the rules in [`RULES.md`](RULES.md).

| Family | Code | Recommendations |
| --- | --- | ---: |
| Rec. 05. Object Orientation (OBJ) | OBJ | 9 |
| Rec. 06. Methods (MET) | MET | 7 |
| Rec. 07. Exceptional Behavior (ERR) | ERR | 5 |
| Rec. 13. Input Output (FIO) | FIO | 4 |
| **Total** | | **25** |

## Rec. 05. Object Orientation (OBJ)

### [OBJ50-J. Never confuse the immutability of a reference with that of the referenced object](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj50-j)

**Guidance:** A final field only stops the reference from being reassigned; the object it points to can still change. Use immutable or defensively copied objects when the contents must not change.

### [OBJ51-J. Minimize the accessibility of classes and their members](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj51-j)

**Guidance:** Give classes, fields and methods the narrowest access they need (private or package-private) so less code can misuse them.

### [OBJ52-J. Write garbage-collection-friendly code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj52-j)

**Guidance:** Prefer short-lived objects and avoid patterns that work against the garbage collector, such as needless finalizers or explicit System.gc() calls.

### [OBJ53-J. Do not use direct buffers for short-lived, infrequently used objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj53-j)

**Guidance:** Direct (off-heap) buffers are expensive to allocate and free, so they should not be used for small, short-lived data.

### [OBJ54-J. Do not attempt to help the garbage collector by setting local reference variables to null](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj54-j)

**Guidance:** Setting local variables to null to "help" the collector adds clutter and rarely helps; let variables go out of scope.

### [OBJ55-J. Remove short-lived objects from long-lived container objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj55-j)

**Guidance:** When objects stored in a long-lived collection are no longer needed, remove them so they are not kept in memory indefinitely.

### [OBJ56-J. Provide sensitive mutable classes with unmodifiable wrappers](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj56-j)

**Guidance:** When sensitive mutable data must be shared, hand out an unmodifiable view or copy so callers cannot change it.

### [OBJ57-J. Do not rely on methods that can be overridden by untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj57-j)

**Guidance:** Security decisions should not depend on methods (such as toString) that a subclass could override.

### [OBJ58-J. Limit the extensibility of classes and methods with invariants](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj58-j)

**Guidance:** Declare classes and methods that protect invariants as final so subclasses cannot break them.

## Rec. 06. Methods (MET)

### [MET50-J. Avoid ambiguous or confusing uses of overloading](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met50-j)

**Guidance:** Overloads with similar parameter types make it unclear which method will be called; use distinct method names instead.

### [MET51-J. Do not use overloaded methods to differentiate between runtime types](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met51-j)

**Guidance:** Overload resolution uses the compile-time type, not the runtime type, so overloading cannot be used to dispatch on the actual object type.

### [MET52-J. Do not use the clone() method to copy untrusted method parameters](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met52-j)

**Guidance:** A parameter's clone() could be overridden by a malicious subclass; copy untrusted inputs with a trusted method instead.

### [MET53-J. Ensure that the clone() method calls super.clone()](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met53-j)

**Guidance:** A clone() implementation should call super.clone() so subclasses get a correctly typed copy.

### [MET54-J. Always provide feedback about the resulting value of a method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met54-j)

**Guidance:** Methods should report whether they succeeded (a return value or an exception) instead of failing silently.

### [MET55-J. Return an empty array or collection instead of a null value for methods that return an array or collection](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met55-j)

**Guidance:** Returning an empty collection instead of null saves callers from null checks and prevents NullPointerExceptions.

### [MET56-J. Do not use Object.equals() to compare cryptographic keys](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met56-j)

**Guidance:** Key classes may not compare key material in equals(); compare the encoded key bytes directly, ideally in constant time.

## Rec. 07. Exceptional Behavior (ERR)

### [ERR50-J. Use exceptions only for exceptional conditions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err50-j)

**Guidance:** Do not use exceptions for normal control flow; expected outcomes should be ordinary return values.

### [ERR51-J. Prefer user-defined exceptions over more general exception types](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err51-j)

**Guidance:** Throw specific, project-defined exceptions rather than generic Exception or RuntimeException so callers can handle each failure deliberately.

### [ERR52-J. Avoid in-band error indicators](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err52-j)

**Guidance:** Do not signal errors with special return values like -1, null or an empty string that look like valid data; use exceptions or Optional.

### [ERR53-J. Try to gracefully recover from system errors](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err53-j)

**Guidance:** Where possible, leave the program and its data in a safe state even when an Error such as OutOfMemoryError occurs.

### [ERR54-J. Use a try-with-resources statement to safely handle closeable resources](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err54-j)

**Guidance:** Open closeable resources in try-with-resources so they are always closed, and close failures are kept as suppressed exceptions.

## Rec. 13. Input Output (FIO)

### [FIO50-J. Do not make assumptions about file creation](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/input-output-fio/fio50-j)

**Guidance:** Do not assume a file does not exist because a check said so; create it atomically and fail if something is already there.

### [FIO51-J. Identify files using multiple file attributes](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/input-output-fio/fio51-j)

**Guidance:** A file name alone can be swapped; confirm identity with attributes such as the file key (device and inode) and file type.

### [FIO52-J. Do not store unencrypted sensitive information on the client side](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/input-output-fio/fio52-j)

**Guidance:** Sensitive data stored locally (files, cookies, caches) must be encrypted or not stored at all.

### [FIO53-J. Use the serialization methods writeUnshared() and readUnshared() with care](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/input-output-fio/fio53-j)

**Guidance:** writeUnshared/readUnshared do not fully prevent shared references in object graphs, so they should be used carefully.
