package pm.crypto.passkey.internal;

import java.lang.invoke.MethodHandles;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import pm.crypto.CryptoException;
import pm.crypto.SecretBytes;
import pm.crypto.passkey.PasskeyKey;

/**
 * The one link between {@link PasskeyKey} and {@code pm.crypto.passkey.storage} (ADR 0016,
 * SR-080). {@code PasskeyKey} installs its storage codec here from its static initializer; the
 * storage package reads it. This package is not exported, so no module outside {@code pm.crypto}
 * can install or read the codec, and the storage form is reachable from outside only through
 * {@code pm.crypto.passkey.storage}, which is exported to {@code pm.vault} alone.
 */
public final class PasskeyAccess {
    private static final AtomicReference<Storage> INSTALLED = new AtomicReference<>();

    private PasskeyAccess() {
    }

    /** Converts a key to and from its storage form. */
    public interface Storage {
        /** The storage form of {@code key}, a new secret owned by the caller. */
        SecretBytes toStorage(PasskeyKey key);

        /** A key loaded strictly from {@code stored}; the caller keeps ownership of {@code stored}. */
        PasskeyKey fromStorage(SecretBytes stored) throws CryptoException;
    }

    /**
     * Installs the codec; called once, by {@code PasskeyKey}'s static initializer.
     *
     * @throws IllegalStateException {@code ALREADY_INSTALLED} on any later call
     */
    public static void install(Storage codec) {
        if (!INSTALLED.compareAndSet(null, Objects.requireNonNull(codec, "codec"))) {
            throw new IllegalStateException("ALREADY_INSTALLED");
        }
    }

    /** The codec, after making sure {@code PasskeyKey} has been initialized and installed it. */
    public static Storage storage() {
        try {
            MethodHandles.lookup().ensureInitialized(PasskeyKey.class);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("PASSKEY_INIT");
        }
        return INSTALLED.get();
    }
}
