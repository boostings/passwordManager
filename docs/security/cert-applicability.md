# CERT Rule Applicability

Every one of the 177 rules in `RULES.md` is classified here per
`plan.md` Part III. Default is Enforced; Review-only and Not applicable require
a justification. Not-applicable rules are backed by an ArchUnit or Semgrep
guard that fails if the construct appears. Tools referenced: Error Prone
(compiler), PMD (`tools/cert-rules/pmd-cert.xml`), SpotBugs + FindSecBugs,
Semgrep (`tools/cert-rules/semgrep/`), ArchUnit (`pm-arch-tests`), gitleaks.
Guards marked "added M1/M2/M3" are committed to in that milestone; until then
the rule is Review-only in practice and the certReport notes it.

| Status | Count |
| --- | ---: |
| Enforced | 72 |
| Review-only | 73 |
| Not applicable | 32 |
| **Total** | **177** |

| Rule | Title | Status | Enforcement / justification |
| --- | --- | --- | --- |
| IDS00-J | Prevent SQL injection | Not applicable | No SQL; ArchUnit forbids java.sql |
| IDS01-J | Normalize strings before validating them | Review-only | Code-review checklist item; no reliable automated check |
| IDS03-J | Do not log unsanitized user input | Enforced | Semgrep cert.FIO13-J.log-secret; redacting logger (SR-500) |
| IDS04-J | Safely extract files from ZipInputStream | Enforced | Semgrep cert.FIO03-J.temp-file + SafePath in pm-storage (SR-700); T-BKP-01 |
| IDS06-J | Exclude unsanitized user input from format strings | Review-only | Code-review checklist item; no reliable automated check |
| IDS07-J | Sanitize untrusted data passed to the Runtime.exec() method | Enforced | Semgrep cert.IDS07-J.runtime-exec / processbuilder-outside-approval; ArchUnit onlyTheEnvRunnerSpawnsProcesses |
| IDS08-J | Sanitize untrusted data included in a regular expression | Review-only | Code-review checklist item; no reliable automated check |
| IDS11-J | Perform any string modifications before validation | Review-only | Code-review checklist item; no reliable automated check |
| IDS14-J | Do not trust the contents of hidden form fields | Not applicable | No web forms served; browser share page has no form input |
| IDS15-J | Do not allow sensitive information to leak outside a trust boundary | Enforced | ArchUnit module boundaries; logger type check; certReport |
| IDS16-J | Prevent XML Injection | Not applicable | No XML; ArchUnit forbids javax.xml/org.w3c.dom |
| IDS17-J | Prevent XML External Entity Attacks | Not applicable | No XML parsing; same guard |
| DCL00-J | Prevent class initialization cycles | Review-only | Code-review checklist item; no reliable automated check |
| DCL01-J | Do not reuse public identifiers from the Java Standard Library | Review-only | Code-review checklist item; no reliable automated check |
| DCL02-J | Do not modify the collection's elements during an enhanced for statement | Enforced | Error Prone ModifyCollectionInEnhancedForLoop; PMD |
| EXP00-J | Do not ignore values returned by methods | Enforced | Error Prone CheckReturnValue (error) |
| EXP01-J | Do not use a null in a case where an object is required | Review-only | Code-review checklist item; no reliable automated check |
| EXP02-J | Do not use the Object.equals() method to compare two arrays | Enforced | Error Prone ArrayEquals (error) |
| EXP03-J | Do not use the equality operators when comparing values of boxed primitives | Enforced | Error Prone BoxedPrimitiveEquality (error); PMD CompareObjectsWithEquals |
| EXP04-J | Do not pass arguments to certain Java Collections Framework methods that are a different type than the collection parameter type | Enforced | Error Prone CollectionIncompatibleType (error) |
| EXP05-J | Do not follow a write by a subsequent write or read of the same object within an expression | Review-only | Code-review checklist item; no reliable automated check |
| EXP06-J | Expressions used in assertions must not produce side effects | Enforced | Error Prone AssertionFailureIgnored; assertions disabled in release |
| EXP07-J | Prevent loss of useful data due to weak references | Review-only | Code-review checklist item; no reliable automated check |
| NUM00-J | Detect or prevent integer overflow | Enforced | Error Prone IntLongMath, NarrowingCompoundAssignment; SpotBugs |
| NUM01-J | Do not perform bitwise and arithmetic operations on the same data | Review-only | Code-review checklist item; no reliable automated check |
| NUM02-J | Ensure that division and remainder operations do not result in divide-by-zero errors | Enforced | SpotBugs; PMD |
| NUM03-J | Use integer types that can fully represent the possible range of unsigned data | Review-only | Code-review checklist item; no reliable automated check |
| NUM04-J | Do not use floating-point numbers if precise computation is required | Review-only | Code-review checklist item; no reliable automated check |
| NUM07-J | Do not attempt comparisons with NaN | Enforced | PMD BadComparison; Error Prone |
| NUM08-J | Check floating-point inputs for exceptional values | Review-only | Code-review checklist item; no reliable automated check |
| NUM09-J | Do not use floating-point variables as loop counters | Review-only | Code-review checklist item; no reliable automated check |
| NUM10-J | Do not construct BigDecimal objects from floating-point literals | Enforced | PMD AvoidDecimalLiteralsInBigDecimalConstructor |
| NUM11-J | Do not compare or inspect the string representation of floating-point values | Review-only | Code-review checklist item; no reliable automated check |
| NUM12-J | Ensure conversions of numeric types to narrower types do not result in lost or misinterpreted data | Enforced | Error Prone NarrowingCompoundAssignment, LossyPrimitiveCompare; -Xlint:cast |
| NUM13-J | Avoid loss of precision when converting primitive integers to floating-point | Review-only | Code-review checklist item; no reliable automated check |
| NUM14-J | Use shift operators correctly | Enforced | SpotBugs (ICAST/BSHIFT) |
| STR00-J | Don't form strings containing partial characters from variable-width encodings | Review-only | Code-review checklist item; no reliable automated check |
| STR01-J | Do not assume that a Java char fully represents a Unicode code point | Review-only | Code-review checklist item; no reliable automated check |
| STR02-J | Specify an appropriate locale when comparing locale-dependent data | Review-only | Code-review checklist item; no reliable automated check |
| STR03-J | Do not encode noncharacter data as a string | Enforced | SecretBytes has no String conversion; Semgrep cert.MSC03-J.secret-in-string |
| STR04-J | Use compatible character encodings when communicating string data between JVMs | Enforced | Semgrep cert.FIO11-J.default-charset |
| OBJ01-J | Limit accessibility of fields | Enforced | PMD; -Xlint; JPMS exports minimal |
| OBJ02-J | Preserve dependencies in subclasses when changing superclasses | Review-only | Code-review checklist item; no reliable automated check |
| OBJ03-J | Prevent heap pollution | Review-only | Code-review checklist item; no reliable automated check |
| OBJ04-J | Provide mutable classes with copy functionality to safely allow passing instances to untrusted code | Review-only | Code-review checklist item; no reliable automated check |
| OBJ05-J | Do not return references to private mutable class members | Enforced | PMD MethodReturnsInternalArray |
| OBJ06-J | Defensively copy mutable inputs and mutable internal components | Enforced | PMD ArrayIsStoredDirectly |
| OBJ07-J | Sensitive classes must not let themselves be copied | Enforced | SecretBytes design (ADR 0008); T-MEM-01 |
| OBJ08-J | Do not expose private members of an outer class from within a nested class | Review-only | Code-review checklist item; no reliable automated check |
| OBJ09-J | Compare classes and not class names | Review-only | Code-review checklist item; no reliable automated check |
| OBJ10-J | Do not use public static nonfinal fields | Enforced | PMD MutableStaticState, AssignmentToNonFinalStatic |
| OBJ11-J | Be wary of letting constructors throw exceptions | Review-only | Code-review checklist item; no reliable automated check |
| OBJ12-J | Respect object-based annotations | Review-only | Code-review checklist item; no reliable automated check |
| OBJ13-J | Ensure that references to mutable objects are not exposed | Enforced | PMD MethodReturnsInternalArray; Error Prone |
| OBJ14-J | Do not use an object that has been freed. | Enforced | SecretBytes use-after-close throws; T-MEM-01 |
| MET00-J | Validate method arguments | Review-only | Code-review checklist item; no reliable automated check |
| MET01-J | Never use assertions to validate method arguments | Review-only | Code-review checklist item; no reliable automated check |
| MET02-J | Do not use deprecated or obsolete classes or methods | Enforced | -Xlint:deprecation -Werror; Semgrep cert.SEC-superseded.security-manager |
| MET03-J | Methods that perform a security check must be declared private or final | Enforced | ArchUnit (broker classes final) added M2; PMD |
| MET04-J | Do not increase the accessibility of overridden or hidden methods | Review-only | Code-review checklist item; no reliable automated check |
| MET05-J | Ensure that constructors do not call overridable methods | Enforced | PMD ConstructorCallsOverridableMethod |
| MET06-J | Do not invoke overridable methods in clone() | Enforced | PMD CloneMethodMustImplementCloneable/ProperCloneImplementation |
| MET07-J | Never declare a class method that hides a method declared in a superclass or superinterface | Review-only | Code-review checklist item; no reliable automated check |
| MET08-J | Preserve the equality contract when overriding the equals() method | Enforced | Error Prone EqualsHashCode, EqualsIncompatibleType |
| MET09-J | Classes that define an equals() method must also define a hashCode() method | Enforced | Error Prone EqualsHashCode (error); PMD OverrideBothEqualsAndHashcode |
| MET10-J | Follow the general contract when implementing the compareTo() method | Enforced | Error Prone ComparableType; SpotBugs |
| MET11-J | Ensure that keys used in comparison operations are immutable | Review-only | Code-review checklist item; no reliable automated check |
| MET12-J | Do not use finalizers | Enforced | Semgrep cert.MET12-J.finalizer; PMD Finalize* rules |
| MET13-J | Do not assume that reassigning method arguments modifies the calling environment | Enforced | PMD AvoidReassigningParameters |
| ERR00-J | Do not suppress or ignore checked exceptions | Enforced | PMD EmptyCatchBlock; -Xlint |
| ERR01-J | Do not allow exceptions to expose sensitive information | Enforced | Semgrep cert.FIO13-J.log-secret; error-code catalogue (SR-501); T-ERR-01 |
| ERR02-J | Prevent exceptions while logging data | Review-only | Code-review checklist item; no reliable automated check |
| ERR03-J | Restore prior object state on method failure | Review-only | Code-review checklist item; no reliable automated check |
| ERR04-J | Do not complete abruptly from a finally block | Enforced | PMD ReturnFromFinallyBlock, DoNotThrowExceptionInFinally |
| ERR05-J | Do not let checked exceptions escape from a finally block | Enforced | PMD DoNotThrowExceptionInFinally |
| ERR06-J | Do not throw undeclared checked exceptions | Review-only | Code-review checklist item; no reliable automated check |
| ERR07-J | Do not throw RuntimeException, Exception, or Throwable | Enforced | PMD AvoidThrowingRawExceptionTypes |
| ERR08-J | Do not catch NullPointerException or any of its ancestors | Enforced | PMD AvoidCatchingNPE, AvoidCatchingThrowable |
| ERR09-J | Do not allow untrusted code to terminate the JVM | Enforced | Semgrep cert.ERR09-J.system-exit; PMD DoNotTerminateVM |
| VNA00-J | Ensure visibility when accessing shared primitive variables | Review-only | Code-review checklist item; no reliable automated check |
| VNA01-J | Ensure visibility of shared references to immutable objects | Review-only | Code-review checklist item; no reliable automated check |
| VNA02-J | Ensure that compound operations on shared variables are atomic | Enforced | Error Prone GuardedBy (error); SpotBugs IS/VO |
| VNA03-J | Do not assume that a group of calls to independently atomic methods is atomic | Review-only | Code-review checklist item; no reliable automated check |
| VNA04-J | Ensure that calls to chained methods are atomic | Review-only | Code-review checklist item; no reliable automated check |
| VNA05-J | Ensure atomicity when reading and writing 64-bit values | Enforced | SpotBugs |
| LCK00-J | Use private final lock objects to synchronize classes that may interact with untrusted code | Enforced | PMD AvoidSynchronizedAtMethodLevel/Statement (private final locks only) |
| LCK01-J | Do not synchronize on objects that may be reused | Review-only | Code-review checklist item; no reliable automated check |
| LCK02-J | Do not synchronize on the class object returned by getClass() | Enforced | SpotBugs (synchronization on getClass) |
| LCK03-J | Do not synchronize on the intrinsic locks of high-level concurrency objects | Review-only | Code-review checklist item; no reliable automated check |
| LCK04-J | Do not synchronize on a collection view if the backing collection is accessible | Review-only | Code-review checklist item; no reliable automated check |
| LCK05-J | Synchronize access to static fields that can be modified by untrusted code | Review-only | Code-review checklist item; no reliable automated check |
| LCK06-J | Do not use an instance lock to protect shared static data | Review-only | Code-review checklist item; no reliable automated check |
| LCK07-J | Avoid deadlock by requesting and releasing locks in the same order | Review-only | Code-review checklist item; no reliable automated check |
| LCK08-J | Ensure actively held locks are released on exceptional conditions | Review-only | Code-review checklist item; no reliable automated check |
| LCK09-J | Do not perform operations that can block while holding a lock | Review-only | Code-review checklist item; no reliable automated check |
| LCK10-J | Use a correct form of the double-checked locking idiom | Enforced | Error Prone DoubleCheckedLocking (error); PMD |
| LCK11-J | Avoid client-side locking when using classes that do not commit to their locking strategy | Review-only | Code-review checklist item; no reliable automated check |
| THI00-J | Do not invoke Thread.run() | Enforced | PMD DontCallThreadRun; SpotBugs |
| THI01-J | Do not invoke ThreadGroup methods | Not applicable | ThreadGroup banned (Semgrep cert.THI05-J.thread-stop + PMD AvoidThreadGroup + ArchUnit noThreadGroup) |
| THI02-J | Notify all waiting threads rather than a single thread | Enforced | PMD UseNotifyAllInsteadOfNotify |
| THI03-J | Always invoke wait() and await() methods inside a loop | Review-only | Code-review checklist item; no reliable automated check |
| THI04-J | Ensure that threads performing blocking operations can be terminated | Review-only | Code-review checklist item; no reliable automated check |
| THI05-J | Do not use Thread.stop() to terminate threads | Enforced | Semgrep cert.THI05-J.thread-stop |
| TPS00-J | Use thread pools to enable graceful degradation of service during traffic bursts | Enforced | PMD DoNotUseThreads (executors only) |
| TPS01-J | Do not execute interdependent tasks in a bounded thread pool | Review-only | Code-review checklist item; no reliable automated check |
| TPS02-J | Ensure that tasks submitted to a thread pool are interruptible | Review-only | Code-review checklist item; no reliable automated check |
| TPS03-J | Ensure that tasks executing in a thread pool do not fail silently | Review-only | Code-review checklist item; no reliable automated check |
| TPS04-J | Ensure ThreadLocal variables are reinitialized when using thread pools | Review-only | Code-review checklist item; no reliable automated check |
| TSM00-J | Do not override thread-safe methods with methods that are not thread-safe | Review-only | Code-review checklist item; no reliable automated check |
| TSM01-J | Do not let the this reference escape during object construction | Review-only | Code-review checklist item; no reliable automated check |
| TSM02-J | Do not use background threads during class initialization | Review-only | Code-review checklist item; no reliable automated check |
| TSM03-J | Do not publish partially initialized objects | Review-only | Code-review checklist item; no reliable automated check |
| FIO00-J | Do not operate on files in shared directories | Enforced | Semgrep cert.FIO03-J.temp-file; pm-storage sole file writer (ArchUnit added M1); T-FS-01 |
| FIO01-J | Create files with appropriate access permissions | Enforced | pm-storage sets perms before write; T-FS-01 |
| FIO02-J | Detect and handle file-related errors | Review-only | Code-review checklist item; no reliable automated check |
| FIO03-J | Remove temporary files before termination | Enforced | Semgrep cert.FIO03-J.temp-file |
| FIO04-J | Release resources when they are no longer needed | Enforced | PMD CloseResource, UseTryWithResources |
| FIO05-J | Do not expose buffers or their backing arrays methods to untrusted code | Enforced | SecretBytes withBytes scoping (ADR 0008) |
| FIO06-J | Do not create multiple buffered wrappers on a single byte or character stream | Review-only | Code-review checklist item; no reliable automated check |
| FIO07-J | Do not let external processes block on IO buffers | Review-only | Code-review checklist item; no reliable automated check |
| FIO08-J | Distinguish between characters or bytes read from a stream and -1 | Review-only | Code-review checklist item; no reliable automated check |
| FIO09-J | Do not rely on the write() method to output integers outside the range 0 to 255 | Review-only | Code-review checklist item; no reliable automated check |
| FIO10-J | Ensure the array is filled when using read() to fill an array | Review-only | Code-review checklist item; no reliable automated check |
| FIO11-J | Do not convert between strings and bytes without specifying a valid character encoding | Enforced | Semgrep cert.FIO11-J.default-charset; Error Prone DefaultCharset (error) |
| FIO12-J | Provide methods to read and write little-endian data | Review-only | Code-review checklist item; no reliable automated check |
| FIO13-J | Do not log sensitive information outside a trust boundary | Enforced | Semgrep cert.FIO13-J.log-secret; logger type check; CI canary grep (SR-500) |
| FIO14-J | Perform proper cleanup at program termination | Review-only | Code-review checklist item; no reliable automated check |
| FIO15-J | Do not reset a servlet's output stream after committing it | Not applicable | No servlets; ArchUnit forbids jakarta.servlet/javax.servlet |
| FIO16-J | Canonicalize path names before validating them | Enforced | SafePath in pm-storage (M1); T-BKP-01 |
| SER00-J | Enable serialization compatibility during class evolution | Review-only | Code-review checklist item; no reliable automated check |
| SER01-J | Do not deviate from the proper signatures of serialization methods | Not applicable | No native serialization: no readObject/writeObject signatures exist |
| SER02-J | Sign then seal objects before sending them outside a trust boundary | Review-only | Code-review checklist item; no reliable automated check |
| SER03-J | Do not serialize unencrypted sensitive data | Enforced | SecretBytes not Serializable; Semgrep cert.SER12-J; ArchUnit noNativeSerialization |
| SER04-J | Do not allow serialization and deserialization to bypass the security manager | Not applicable | Superseded: no SecurityManager and no native serialization |
| SER05-J | Do not serialize instances of inner classes | Not applicable | No native serialization |
| SER06-J | Make defensive copies of private mutable components during deserialization | Not applicable | No native serialization (CBOR codecs copy bytes: OBJ06-J) |
| SER07-J | Do not use the default serialized form for classes with implementation-defined invariants | Not applicable | No native serialization |
| SER08-J | Minimize privileges before deserializing from a privileged context | Not applicable | Superseded: no privileged contexts and no native serialization |
| SER09-J | Do not invoke overridable methods from the readObject() method | Not applicable | No native serialization |
| SER10-J | Avoid memory and resource leaks during serialization | Not applicable | No native serialization |
| SER11-J | Prevent overwriting of externalizable objects | Not applicable | No native serialization |
| SER12-J | Prevent deserialization of untrusted data | Enforced | Semgrep cert.SER12-J.native-serialization; ArchUnit noNativeSerialization |
| SEC00-J | Do not allow privileged blocks to leak sensitive information across a trust boundary | Review-only | Code-review checklist item; no reliable automated check |
| SEC01-J | Do not allow tainted variables in privileged blocks | Review-only | Code-review checklist item; no reliable automated check |
| SEC02-J | Do not base security checks on untrusted sources | Review-only | Code-review checklist item; no reliable automated check |
| SEC03-J | Do not load trusted classes after allowing untrusted code to load arbitrary classes | Not applicable | No dynamic class loading; same guard |
| SEC04-J | Protect sensitive operations with security manager checks | Not applicable | Superseded: SecurityManager not used (ADR 0002); JPMS + ArchUnit |
| SEC05-J | Do not use reflection to increase accessibility of classes, methods, or fields | Enforced | Semgrep cert.SEC05-J.set-accessible |
| SEC06-J | Do not rely on the default automatic signature verification provided by URLClassLoader and java.util.jar | Not applicable | No URLClassLoader / jar signature reliance; updates verified by pinned key (SR-602) |
| SEC07-J | Call the superclass's getPermissions() method when writing a custom class loader | Not applicable | No custom class loaders; ArchUnit forbids ClassLoader subclasses |
| SEC08-J | Trusted code must discard or clean any arguments provided by untrusted code | Not applicable | No untrusted code runs in-process (no plugins, no dynamic loading); JPMS + ArchUnit |
| SEC09-J | Never leak the results of certain standard API methods from trusted code to untrusted code | Not applicable | No untrusted code runs in-process |
| SEC10-J | Never permit untrusted code to invoke any API that may (possibly transitively) invoke the reflection APIs | Not applicable | No untrusted code runs in-process; Semgrep cert.SEC05-J.set-accessible |
| ENV00-J | Do not sign code that performs only unprivileged operations | Review-only | Code-review checklist item; no reliable automated check |
| ENV01-J | Place all security-sensitive code in a single JAR and sign and seal it | Review-only | Code-review checklist item; no reliable automated check |
| ENV02-J | Do not trust the values of environment variables | Enforced | Semgrep cert.ENV02-J.getenv-outside-accessor |
| ENV03-J | Do not grant dangerous combinations of permissions | Not applicable | Superseded: no permission policy files |
| ENV04-J | Do not disable bytecode verification | Enforced | Semgrep cert.ENV04-J.verify-none |
| ENV05-J | Do not deploy an application that can be remotely monitored | Enforced | Semgrep cert.ENV05-J.jmx-jdwp; T-PKG-01 |
| ENV06-J | Production code must not contain debugging entry points | Enforced | Semgrep cert.ENV05-J.jmx-jdwp; release build has no debug commands; T-PKG-01 |
| JNI00-J | Define wrappers around native methods | Not applicable | No JNI in v1; ArchUnit forbids native methods (revisit if platform adapters need JNA/JNI) |
| JNI01-J | Safely invoke standard APIs that perform tasks using the immediate caller's class loader instance (loadLibrary) | Not applicable | No JNI |
| JNI02-J | Do not assume object references are constant or unique | Not applicable | No JNI |
| JNI03-J | Do not use direct pointers to Java objects in JNI code | Not applicable | No JNI |
| JNI04-J | Do not assume that Java strings are null-terminated | Not applicable | No JNI |
| MSC00-J | Use SSLSocket rather than Socket for secure data exchange | Enforced | ArchUnit: raw Socket/ServerSocket only in pm-sharing TLS wrapper (added M3) |
| MSC01-J | Do not use an empty infinite loop | Enforced | PMD EmptyControlStatement |
| MSC02-J | Generate strong random numbers | Enforced | Semgrep cert.MSC02-J.*; SpotBugs PREDICTABLE_RANDOM (proven in Phase 9) |
| MSC03-J | Never hard code sensitive information | Enforced | gitleaks; Semgrep cert.MSC03-J.secret-in-string; PMD HardCodedCryptoKey |
| MSC04-J | Do not leak memory | Review-only | Code-review checklist item; no reliable automated check |
| MSC05-J | Do not exhaust heap space | Enforced | All parsers size-bounded (ADR 0006); fuzz harnesses T-FUZZ-* |
| MSC06-J | Do not modify the underlying collection when an iteration is in progress | Enforced | Error Prone ModifyCollectionInEnhancedForLoop; SpotBugs |
| MSC07-J | Prevent multiple instantiations of singleton objects | Enforced | PMD NonThreadSafeSingleton |
| MSC08-J | Do not store nonserializable objects as attributes in an HTTP session | Not applicable | No HTTP sessions (servlet) |
| MSC09-J | For OAuth, ensure (a) [relying party receiving user's ID in last step | Not applicable | No OAuth |
| MSC10-J | Do not use OAuth 2.0 implicit grant (unmodified) for authentication | Not applicable | No OAuth |
| MSC11-J | Do not let session information leak within a servlet | Not applicable | No servlets |
