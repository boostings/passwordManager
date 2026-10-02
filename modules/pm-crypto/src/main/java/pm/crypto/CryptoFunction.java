package pm.crypto;

import java.security.GeneralSecurityException;

/** A function that may throw a JCA checked exception; see {@link SecretBytes#applyCrypto}. */
@FunctionalInterface
interface CryptoFunction<T, R> {
    /** Applies this function to {@code t}. */
    R apply(T t) throws GeneralSecurityException;
}
