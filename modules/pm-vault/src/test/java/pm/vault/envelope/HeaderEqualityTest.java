package pm.vault.envelope;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Header values compare every field and the contents of their byte arrays (EXP02-J, SR-016). */
class HeaderEqualityTest {
    private static final byte[] SALT = new byte[32];

    @Test
    void kdfHeadersDifferInAnyField() {
        KdfHeader base = new KdfHeader("argon2id", 65_536, 3, 1, SALT);
        assertEquals(base, new KdfHeader("argon2id", 65_536, 3, 1, SALT.clone()));
        assertEquals(base.hashCode(), new KdfHeader("argon2id", 65_536, 3, 1, SALT.clone()).hashCode());
        byte[] otherSalt = SALT.clone();
        otherSalt[31] = 1;
        for (KdfHeader other : List.of(
                new KdfHeader("scrypt", 65_536, 3, 1, SALT),
                new KdfHeader("argon2id", 32_768, 3, 1, SALT),
                new KdfHeader("argon2id", 65_536, 2, 1, SALT),
                new KdfHeader("argon2id", 65_536, 3, 2, SALT),
                new KdfHeader("argon2id", 65_536, 3, 1, otherSalt),
                new KdfHeader("argon2id", 65_536, 3, 1, new byte[16]))) {
            assertNotEquals(base, other, other.toString());
        }
        assertNotEquals(base, (Object) "argon2id");
    }

    @Test
    void slotHeadersDifferInAnyField() {
        UUID id = UUID.randomUUID();
        byte[] wrapped = new byte[40];
        SlotHeader base = new SlotHeader(id, SlotHeader.MASTER, wrapped);
        assertEquals(base, new SlotHeader(id, SlotHeader.MASTER, wrapped.clone()));
        byte[] otherKey = wrapped.clone();
        otherKey[0] = 1;
        for (SlotHeader other : List.of(
                new SlotHeader(UUID.randomUUID(), SlotHeader.MASTER, wrapped),
                new SlotHeader(id, SlotHeader.RECOVERY, wrapped),
                new SlotHeader(id, SlotHeader.MASTER, otherKey))) {
            assertNotEquals(base, other, other.toString());
        }
        assertNotEquals(base, (Object) id);
    }
}
