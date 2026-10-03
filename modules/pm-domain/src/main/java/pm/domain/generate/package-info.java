/**
 * Password and passphrase generation (plan.md §13 M4, ADR 0012, MSC02-J).
 *
 * <p>{@link pm.domain.generate.PasswordGenerator} draws characters from the chosen
 * {@link pm.domain.generate.CharClass} alphabets and {@link pm.domain.generate.PassphraseGenerator}
 * draws words from the bundled {@link pm.domain.generate.Wordlist}. Both read randomness only from a
 * {@link pm.domain.generate.RandomSource}, whose production implementation is {@code pm.crypto.Csprng}
 * (the one {@code SecureRandom}, SR-017), map it to indices by rejection sampling (no modulo bias),
 * return the result in a {@link pm.crypto.SecretChars} and report its entropy in bits.
 */
package pm.domain.generate;
