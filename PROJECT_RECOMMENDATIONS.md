# Password Manager Project Recommendations

This file selects the recommendations from [`RECOMMENDATIONS.md`](RECOMMENDATIONS.md) (Rec. 05, 06, 07 and 13) that the project actually follows. Each one links to one representative source location at commit `4ea8514`. A single line is illustrative, not proof that the whole repository follows the recommendation.

Recommendations used: 18 of 25.

| Code | Title | Example |
| --- | --- | --- |
| OBJ50-J | Never confuse the immutability of a reference with that of the referenced object | [OwnerOnly.java:50](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-storage/src/main/java/pm/storage/OwnerOnly.java#L50) |
| OBJ51-J | Minimize the accessibility of classes and their members | [OwnerOnly.java:66](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-storage/src/main/java/pm/storage/OwnerOnly.java#L66) |
| OBJ55-J | Remove short-lived objects from long-lived container objects | [Vault.java:470](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/Vault.java#L470) |
| OBJ56-J | Provide sensitive mutable classes with unmodifiable wrappers | [ApprovalRequest.java:118](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-approval/src/main/java/pm/approval/ApprovalRequest.java#L118) |
| OBJ57-J | Do not rely on methods that can be overridden by untrusted code | [SafeLog.java:157](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-crypto/src/main/java/pm/crypto/log/SafeLog.java#L157) |
| OBJ58-J | Limit the extensibility of classes and methods with invariants | [SecretBytes.java:20](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L20) |
| MET52-J | Do not use the clone() method to copy untrusted method parameters | [SecretBytes.java:31](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L31) |
| MET54-J | Always provide feedback about the resulting value of a method | [VaultFileStore.java:377](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L377) |
| MET55-J | Return an empty array or collection instead of a null value for methods that return an array or collection | [GitGuard.java:101](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-cli/src/main/java/pm/cli/GitGuard.java#L101) |
| MET56-J | Do not use Object.equals() to compare cryptographic keys | [AgentIdentity.java:44](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-crypto/src/main/java/pm/crypto/ssh/AgentIdentity.java#L44) |
| ERR50-J | Use exceptions only for exceptional conditions | [ExtensionAllowlist.java:77](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-browser/src/main/java/pm/browser/host/ExtensionAllowlist.java#L77) |
| ERR51-J | Prefer user-defined exceptions over more general exception types | [VaultException.java:9](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/VaultException.java#L9) |
| ERR52-J | Avoid in-band error indicators | [Origin.java:93](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-browser/src/main/java/pm/browser/bridge/Origin.java#L93) |
| ERR53-J | Try to gracefully recover from system errors | [VaultService.java:324](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/VaultService.java#L324) |
| ERR54-J | Use a try-with-resources statement to safely handle closeable resources | [Vault.java:539](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/Vault.java#L539) |
| FIO50-J | Do not make assumptions about file creation | [RunDir.java:184](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-approval/src/main/java/pm/approval/ipc/RunDir.java#L184) |
| FIO51-J | Identify files using multiple file attributes | [SshCommands.java:408](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-cli/src/main/java/pm/cli/SshCommands.java#L408) |
| FIO52-J | Do not store unencrypted sensitive information on the client side | [Vault.java:534](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/Vault.java#L534) |

## Rec. 05. Object Orientation (OBJ)

### [OBJ50-J. Never confuse the immutability of a reference with that of the referenced object](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj50-j)

**Guidance:** A final field only stops the reference from being reassigned; the object it points to can still change. Use immutable or defensively copied objects when the contents must not change.  
**How the project follows it:** `OwnerOnly` stores its permission sets in final fields AND makes the sets themselves immutable with `Set.copyOf`.  
**Example:** [OwnerOnly.java:50](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-storage/src/main/java/pm/storage/OwnerOnly.java#L50)

### [OBJ51-J. Minimize the accessibility of classes and their members](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj51-j)

**Guidance:** Give classes, fields and methods the narrowest access they need (private or package-private) so less code can misuse them.  
**How the project follows it:** `OwnerOnly` has a private constructor, and `creationAttributes` is package-private so only the storage package can call it.  
**Example:** [OwnerOnly.java:66](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-storage/src/main/java/pm/storage/OwnerOnly.java#L66)

### [OBJ55-J. Remove short-lived objects from long-lived container objects](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj55-j)

**Guidance:** When objects stored in a long-lived collection are no longer needed, remove them so they are not kept in memory indefinitely.  
**How the project follows it:** When the vault locks, every held and retired record is closed and both collections are cleared.  
**Example:** [Vault.java:470](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/Vault.java#L470)

### [OBJ56-J. Provide sensitive mutable classes with unmodifiable wrappers](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj56-j)

**Guidance:** When sensitive mutable data must be shared, hand out an unmodifiable view or copy so callers cannot change it.  
**How the project follows it:** `ApprovalRequest` wraps its variable set with `Collections.unmodifiableSortedSet` and copies records with `List.copyOf`.  
**Example:** [ApprovalRequest.java:118](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-approval/src/main/java/pm/approval/ApprovalRequest.java#L118)

### [OBJ57-J. Do not rely on methods that can be overridden by untrusted code](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj57-j)

**Guidance:** Security decisions should not depend on methods (such as toString) that a subclass could override.  
**How the project follows it:** `SafeLog` only logs date and path values whose runtime class is a JDK class in `java.base`, so a project subclass cannot override `toString()` to smuggle data into logs.  
**Example:** [SafeLog.java:157](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-crypto/src/main/java/pm/crypto/log/SafeLog.java#L157)

### [OBJ58-J. Limit the extensibility of classes and methods with invariants](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/object-orientation-obj/obj58-j)

**Guidance:** Declare classes and methods that protect invariants as final so subclasses cannot break them.  
**How the project follows it:** `SecretBytes` is `final` with a private constructor.  
**Example:** [SecretBytes.java:20](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L20)

## Rec. 06. Methods (MET)

### [MET52-J. Do not use the clone() method to copy untrusted method parameters](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met52-j)

**Guidance:** A parameter's clone() could be overridden by a malicious subclass; copy untrusted inputs with a trusted method instead.  
**How the project follows it:** `SecretBytes.copyOf` copies its input with `Arrays.copyOf` rather than calling a caller-supplied `clone()`.  
**Example:** [SecretBytes.java:31](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-crypto/src/main/java/pm/crypto/SecretBytes.java#L31)

### [MET54-J. Always provide feedback about the resulting value of a method](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met54-j)

**Guidance:** Methods should report whether they succeeded (a return value or an exception) instead of failing silently.  
**How the project follows it:** `VaultFileStore.deleteSibling` returns whether the file was deleted, and `VaultService` counts and acts on that result.  
**Example:** [VaultFileStore.java:377](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-storage/src/main/java/pm/storage/VaultFileStore.java#L377)

### [MET55-J. Return an empty array or collection instead of a null value for methods that return an array or collection](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met55-j)

**Guidance:** Returning an empty collection instead of null saves callers from null checks and prevents NullPointerExceptions.  
**How the project follows it:** `GitGuard.readIgnore` returns `List.of()` when the file is missing, too large or unreadable.  
**Example:** [GitGuard.java:101](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-cli/src/main/java/pm/cli/GitGuard.java#L101)

### [MET56-J. Do not use Object.equals() to compare cryptographic keys](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/methods-met/met56-j)

**Guidance:** Key classes may not compare key material in equals(); compare the encoded key bytes directly, ideally in constant time.  
**How the project follows it:** `AgentIdentity.matches` compares key blobs with `ConstantTime.equals`.  
**Example:** [AgentIdentity.java:44](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-crypto/src/main/java/pm/crypto/ssh/AgentIdentity.java#L44)

## Rec. 07. Exceptional Behavior (ERR)

### [ERR50-J. Use exceptions only for exceptional conditions](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err50-j)

**Guidance:** Do not use exceptions for normal control flow; expected outcomes should be ordinary return values.  
**How the project follows it:** An unknown browser caller is an expected outcome, so `ExtensionAllowlist.caller` returns an empty `Optional` instead of throwing.  
**Example:** [ExtensionAllowlist.java:77](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-browser/src/main/java/pm/browser/host/ExtensionAllowlist.java#L77)

### [ERR51-J. Prefer user-defined exceptions over more general exception types](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err51-j)

**Guidance:** Throw specific, project-defined exceptions rather than generic Exception or RuntimeException so callers can handle each failure deliberately.  
**How the project follows it:** `VaultException` carries a fixed `Code` enum (`WRONG_CREDENTIAL`, `CORRUPT`, `STORAGE`, ...).  
**Example:** [VaultException.java:9](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/VaultException.java#L9)

### [ERR52-J. Avoid in-band error indicators](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err52-j)

**Guidance:** Do not signal errors with special return values like -1, null or an empty string that look like valid data; use exceptions or Optional.  
**How the project follows it:** `Origin.ofUrl` returns `Optional.empty()` for a URL it cannot parse instead of null.  
**Example:** [Origin.java:93](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-browser/src/main/java/pm/browser/bridge/Origin.java#L93)

### [ERR53-J. Try to gracefully recover from system errors](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err53-j)

**Guidance:** Where possible, leave the program and its data in a safe state even when an Error such as OutOfMemoryError occurs.  
**How the project follows it:** During migration, a `finally` block puts the original vault back even if an `Error` (for example `OutOfMemoryError`) is thrown.  
**Example:** [VaultService.java:324](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/VaultService.java#L324)

### [ERR54-J. Use a try-with-resources statement to safely handle closeable resources](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/exceptional-behavior-err/err54-j)

**Guidance:** Open closeable resources in try-with-resources so they are always closed, and close failures are kept as suppressed exceptions.  
**How the project follows it:** `Vault.sealFile` opens the data key and plaintext with try-with-resources, so both are wiped on every path.  
**Example:** [Vault.java:539](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/Vault.java#L539)

## Rec. 13. Input Output (FIO)

### [FIO50-J. Do not make assumptions about file creation](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/input-output-fio/fio50-j)

**Guidance:** Do not assume a file does not exist because a check said so; create it atomically and fail if something is already there.  
**How the project follows it:** `RunDir.createOwnerOnly` opens files with `CREATE_NEW` and `NOFOLLOW_LINKS`.  
**Example:** [RunDir.java:184](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-approval/src/main/java/pm/approval/ipc/RunDir.java#L184)

### [FIO51-J. Identify files using multiple file attributes](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/input-output-fio/fio51-j)

**Guidance:** A file name alone can be swapped; confirm identity with attributes such as the file key (device and inode) and file type.  
**How the project follows it:** `SshCommands.readKeyFile` checks the file is regular and that its `fileKey()` is unchanged before and after opening.  
**Example:** [SshCommands.java:408](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-cli/src/main/java/pm/cli/SshCommands.java#L408)

### [FIO52-J. Do not store unencrypted sensitive information on the client side](https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/recommendations/input-output-fio/fio52-j)

**Guidance:** Sensitive data stored locally (files, cookies, caches) must be encrypted or not stored at all.  
**How the project follows it:** Vault records are encrypted with AES-256-GCM before they are written to disk.  
**Example:** [Vault.java:534](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-vault/src/main/java/pm/vault/Vault.java#L534)

## Not used

These recommendations from the same families are not claimed for this project:

- **OBJ52-J. Write garbage-collection-friendly code**: Not demonstrated. No specific code in the repo shows this recommendation, so it is not claimed.
- **OBJ53-J. Do not use direct buffers for short-lived, infrequently used objects**: Deliberate deviation. `WireWriter` intentionally uses short-lived direct buffers for SSH key bytes, so the JDK does not copy secrets into a cached buffer that is never cleared. The buffer is zero-filled afterwards (ADR 0013). ([WireWriter.java:91](https://github.com/boostings/passwordManager/blob/4ea8514c33813ebc62b87e880e846b466dfabdac/modules/pm-crypto/src/main/java/pm/crypto/ssh/WireWriter.java#L91))
- **OBJ54-J. Do not attempt to help the garbage collector by setting local reference variables to null**: Not demonstrated. No specific code in the repo shows this recommendation, so it is not claimed.
- **MET50-J. Avoid ambiguous or confusing uses of overloading**: Not demonstrated. No specific code in the repo shows this recommendation, so it is not claimed.
- **MET51-J. Do not use overloaded methods to differentiate between runtime types**: Not demonstrated. No specific code in the repo shows this recommendation, so it is not claimed.
- **MET53-J. Ensure that the clone() method calls super.clone()**: Not applicable. The project implements no copying `clone()`; `SecretBytes.clone()` always throws (OBJ07-J).
- **FIO53-J. Use the serialization methods writeUnshared() and readUnshared() with care**: Not applicable. The project does not use Java object serialization at all.
