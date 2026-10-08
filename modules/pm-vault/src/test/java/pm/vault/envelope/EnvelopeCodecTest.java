package pm.vault.envelope;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import pm.crypto.Argon2Params;
import pm.vault.VaultException;
import pm.vault.cbor.CborException;
import pm.vault.cbor.CborValue;
import pm.vault.cbor.CborWriter;

/** ADR 0003 envelope layout: round trip plus one crafted file per decode check (M1.2 C 2a). */
final class EnvelopeCodecTest {

    private static final int PREFIX = 14;
    private static final int SALT = 32;
    private static final int TAG = 16;
    private static final UUID MASTER_ID = new UUID(0x1111L, 0x2222L);
    private static final UUID RECOVERY_ID = new UUID(0x3333L, 0x4444L);

    // ---- round trip ---------------------------------------------------------------------

    @Test
    void roundTripPreservesEveryField() throws VaultException {
        EnvelopeHeader h = header();
        byte[] dataSalt = filled(SALT, 0x5A);
        byte[] ciphertext = filled(TAG + 7, 0xC3);

        byte[] file = EnvelopeCodec.encode(h, dataSalt, ciphertext);
        ParsedEnvelope parsed = EnvelopeCodec.decode(file);

        assertEquals(h, parsed.header());
        assertArrayEquals(dataSalt, parsed.dataSalt());
        assertArrayEquals(ciphertext, parsed.ciphertext());
    }

    @Test
    void aadIsExactlyTheFilePrefixBeforeTheCiphertext() throws VaultException {
        EnvelopeHeader h = header();
        byte[] dataSalt = filled(SALT, 0x01);
        byte[] ciphertext = filled(TAG, 0x02);
        byte[] headerCbor = EnvelopeCodec.encodeHeader(h);

        byte[] file = EnvelopeCodec.encode(h, dataSalt, ciphertext);
        byte[] aad = EnvelopeCodec.aadOf(headerCbor, dataSalt);

        assertEquals(PREFIX + headerCbor.length + SALT, aad.length);
        assertArrayEquals(Arrays.copyOfRange(file, 0, aad.length), aad);
        assertArrayEquals(aad, EnvelopeCodec.decode(file).aad());
    }

    @Test
    void layoutIsMagicVersionLengthHeaderSaltCiphertext() {
        EnvelopeHeader h = header();
        byte[] headerCbor = EnvelopeCodec.encodeHeader(h);
        byte[] file = EnvelopeCodec.encode(h, filled(SALT, 0x01), filled(TAG, 0x02));
        ByteBuffer buf = ByteBuffer.wrap(file);

        assertArrayEquals(EnvelopeCodec.magic(), Arrays.copyOfRange(file, 0, 8));
        assertEquals(EnvelopeCodec.VERSION, buf.getShort(8));
        assertEquals(headerCbor.length, buf.getInt(10));
        assertArrayEquals(headerCbor, Arrays.copyOfRange(file, PREFIX, PREFIX + headerCbor.length));
    }

    @Test
    void headerEncodingIsDeterministic() {
        assertArrayEquals(EnvelopeCodec.encodeHeader(header()), EnvelopeCodec.encodeHeader(header()));
    }

    @Test
    void unknownHeaderKeysAreIgnored() throws VaultException {
        Map<String, CborValue> top = headerMap();
        top.put("future_field", new CborValue.Text("ignored"));

        assertEquals(header(), EnvelopeCodec.decode(file(top)).header());
    }

    @Test
    void magicAccessorReturnsACopy() {
        byte[] m = EnvelopeCodec.magic();
        m[0] = 0;
        assertEquals('P', EnvelopeCodec.magic()[0]);
    }

    // ---- check 1: minimum length --------------------------------------------------------

    @Test
    void rejectsEmptyFile() {
        assertCode(VaultException.Code.CORRUPT, new byte[0]);
    }

    @Test
    void rejectsFileShorterThanFixedFields() {
        byte[] file = validFile();
        assertCode(VaultException.Code.CORRUPT, Arrays.copyOf(file, PREFIX + SALT + TAG - 1));
    }

    // ---- check 2: magic -----------------------------------------------------------------

    @Test
    void rejectsWrongMagic() {
        byte[] file = validFile();
        file[3] ^= 0x01;
        assertCode(VaultException.Code.CORRUPT, file);
    }

    // ---- check 3: version ---------------------------------------------------------------

    @Test
    void rejectsNewerVersionAsUnsupported() {
        byte[] file = validFile();
        ByteBuffer.wrap(file).putShort(8, (short) 2);
        assertCode(VaultException.Code.UNSUPPORTED_VERSION, file);
    }

    @Test
    void readsVersionAsUnsigned() {
        byte[] file = validFile();
        ByteBuffer.wrap(file).putShort(8, (short) 0xFFFF);
        assertCode(VaultException.Code.UNSUPPORTED_VERSION, file);
    }

    @Test
    void rejectsOlderVersionAsCorrupt() {
        byte[] file = validFile();
        ByteBuffer.wrap(file).putShort(8, (short) 0);
        assertCode(VaultException.Code.CORRUPT, file);
    }

    // ---- versioned decode (ADR 0015) ----------------------------------------------------

    @Test
    void peekVersionReadsOnlyThePrefix() throws VaultException {
        byte[] file = validFile();
        assertEquals(EnvelopeCodec.VERSION, EnvelopeCodec.peekVersion(file));
        ByteBuffer.wrap(file).putShort(8, (short) 0xFFFF);
        assertEquals(0xFFFF, EnvelopeCodec.peekVersion(file));
        byte[] badMagic = validFile();
        badMagic[0] ^= 1;
        assertEquals(VaultException.Code.CORRUPT,
                assertThrows(VaultException.class, () -> EnvelopeCodec.peekVersion(badMagic)).code());
        assertEquals(VaultException.Code.CORRUPT,
                assertThrows(VaultException.class, () -> EnvelopeCodec.peekVersion(new byte[3])).code());
    }

    @Test
    void decodeAtAnOlderVersionAcceptsOnlyThatVersion() throws VaultException {
        EnvelopeHeader h = header();
        byte[] dataSalt = filled(SALT, 0x11);
        byte[] aad = EnvelopeCodec.aadOf(0, EnvelopeCodec.encodeHeader(h), dataSalt);
        byte[] file = Arrays.copyOf(aad, aad.length + TAG);
        assertEquals(0, ByteBuffer.wrap(file).getShort(8));
        ParsedEnvelope parsed = EnvelopeCodec.decode(file, 0);
        assertEquals(h, parsed.header());
        assertArrayEquals(aad, parsed.aad());
        assertCode(VaultException.Code.CORRUPT, file);
        assertEquals(VaultException.Code.CORRUPT,
                assertThrows(VaultException.class, () -> EnvelopeCodec.decode(validFile(), 0)).code());
        byte[] newer = validFile();
        ByteBuffer.wrap(newer).putShort(8, (short) 2);
        assertEquals(VaultException.Code.UNSUPPORTED_VERSION,
                assertThrows(VaultException.class, () -> EnvelopeCodec.decode(newer, 0)).code());
    }

    @Test
    void versionArgumentsOutsideTheReadableRangeAreProgrammingErrors() {
        byte[] headerCbor = EnvelopeCodec.encodeHeader(header());
        byte[] dataSalt = filled(SALT, 0);
        assertThrows(IllegalArgumentException.class, () -> EnvelopeCodec.aadOf(-1, headerCbor, dataSalt));
        assertThrows(IllegalArgumentException.class,
                () -> EnvelopeCodec.aadOf(EnvelopeCodec.VERSION + 1, headerCbor, dataSalt));
        assertThrows(IllegalArgumentException.class, () -> EnvelopeCodec.decode(validFile(), -1));
        assertThrows(IllegalArgumentException.class,
                () -> EnvelopeCodec.decode(validFile(), EnvelopeCodec.VERSION + 1));
    }

    // ---- check 4: header length ---------------------------------------------------------

    @Test
    void rejectsZeroHeaderLength() {
        byte[] file = validFile();
        ByteBuffer.wrap(file).putInt(10, 0);
        assertCode(VaultException.Code.CORRUPT, file);
    }

    @Test
    void rejectsHeaderLengthAboveMax() {
        byte[] file = Arrays.copyOf(validFile(), EnvelopeCodec.MAX_HEADER * 2);
        ByteBuffer.wrap(file).putInt(10, EnvelopeCodec.MAX_HEADER + 1);
        assertCode(VaultException.Code.CORRUPT, file);
    }

    @Test
    void rejectsHeaderLengthWithTopBitSetWithoutOverflow() {
        byte[] file = validFile();
        ByteBuffer.wrap(file).putInt(10, 0xFFFFFFFF);
        assertCode(VaultException.Code.CORRUPT, file);
    }

    @Test
    void rejectsHeaderLengthThatLeavesNoRoomForSaltAndTag() {
        byte[] file = validFile();
        ByteBuffer.wrap(file).putInt(10, file.length - PREFIX - SALT - TAG + 1);
        assertCode(VaultException.Code.CORRUPT, file);
    }

    @Test
    void rejectsTruncatedCiphertext() {
        byte[] file = validFile();
        assertCode(VaultException.Code.CORRUPT, Arrays.copyOf(file, file.length - TAG));
    }

    // ---- check 5: header CBOR and fields ------------------------------------------------

    @Test
    void rejectsHeaderThatIsNotCbor() {
        byte[] headerCbor = {(byte) 0xFF, 0x00, 0x01};
        VaultException e = assertThrows(VaultException.class, () -> EnvelopeCodec.decode(fileFromCbor(headerCbor)));
        assertEquals(VaultException.Code.CORRUPT, e.code());
        assertInstanceOf(CborException.class, e.getCause());
    }

    @Test
    void rejectsHeaderThatIsNotAMap() {
        assertCode(VaultException.Code.CORRUPT, fileFromCbor(CborWriter.encode(new CborValue.UInt(1))));
    }

    @Test
    void rejectsWrongSchemaVersion() {
        Map<String, CborValue> top = headerMap();
        top.put("schema_version", new CborValue.UInt(2));
        assertCode(VaultException.Code.CORRUPT, file(top));
    }

    @Test
    void rejectsMissingRequiredKey() {
        for (String key : List.of("schema_version", "kdf", "slots", "created", "saved", "save_seq")) {
            Map<String, CborValue> top = headerMap();
            top.remove(key);
            assertCode(VaultException.Code.CORRUPT, file(top));
        }
    }

    @Test
    void rejectsWrongValueType() {
        Map<String, CborValue> top = headerMap();
        top.put("created", new CborValue.Text("yesterday"));
        assertCode(VaultException.Code.CORRUPT, file(top));
    }

    @Test
    void rejectsZeroSaveSeq() {
        Map<String, CborValue> top = headerMap();
        top.put("save_seq", new CborValue.UInt(0));
        assertCode(VaultException.Code.CORRUPT, file(top));
    }

    @Test
    void rejectsUnknownKdfAlgorithm() {
        assertCode(VaultException.Code.CORRUPT, fileWithKdf("alg", new CborValue.Text("pbkdf2")));
    }

    @Test
    void rejectsKdfSaltOfWrongLength() {
        assertCode(VaultException.Code.CORRUPT, fileWithKdf("salt", new CborValue.Bytes(new byte[SALT - 1])));
    }

    @Test
    void rejectsKdfMemoryBelowFloor() {
        long m = Argon2Params.FLOOR.memoryKiB() - 1L;
        assertCode(VaultException.Code.CORRUPT, fileWithKdf("m", new CborValue.UInt(m)));
    }

    @Test
    void rejectsKdfMemoryAboveCap() {
        long m = EnvelopeCodec.MAX_MEMORY_KIB + 1L;
        assertCode(VaultException.Code.CORRUPT, fileWithKdf("m", new CborValue.UInt(m)));
    }

    @Test
    void rejectsKdfValueThatOverflowsInt() {
        assertCode(VaultException.Code.CORRUPT, fileWithKdf("t", new CborValue.UInt(1L << 32)));
    }

    @Test
    void rejectsKdfIterationsAboveCap() {
        long t = EnvelopeCodec.MAX_ITERATIONS + 1L;
        assertCode(VaultException.Code.CORRUPT, fileWithKdf("t", new CborValue.UInt(t)));
    }

    @Test
    void rejectsZeroSlots() {
        Map<String, CborValue> top = headerMap();
        top.put("slots", new CborValue.Array(List.of()));
        assertCode(VaultException.Code.CORRUPT, file(top));
    }

    @Test
    void rejectsTooManySlots() {
        List<CborValue> slots = new ArrayList<>();
        slots.add(slot(MASTER_ID, SlotHeader.MASTER, EnvelopeCodec.WRAPPED_KEY_LENGTH));
        for (int i = 0; i < EnvelopeCodec.MAX_SLOTS; i++) {
            slots.add(slot(new UUID(9L, i), SlotHeader.RECOVERY, EnvelopeCodec.WRAPPED_KEY_LENGTH));
        }
        assertCode(VaultException.Code.CORRUPT, fileWithSlots(slots));
    }

    @Test
    void rejectsUnknownSlotType() {
        assertCode(VaultException.Code.CORRUPT, fileWithSlots(List.of(
                slot(MASTER_ID, SlotHeader.MASTER, EnvelopeCodec.WRAPPED_KEY_LENGTH),
                slot(RECOVERY_ID, "fido2", EnvelopeCodec.WRAPPED_KEY_LENGTH))));
    }

    @Test
    void rejectsWrappedKeyOfWrongLength() {
        assertCode(VaultException.Code.CORRUPT, fileWithSlots(List.of(
                slot(MASTER_ID, SlotHeader.MASTER, EnvelopeCodec.WRAPPED_KEY_LENGTH - 1))));
    }

    @Test
    void rejectsMissingPassphraseSlot() {
        assertCode(VaultException.Code.CORRUPT, fileWithSlots(List.of(
                slot(RECOVERY_ID, SlotHeader.RECOVERY, EnvelopeCodec.WRAPPED_KEY_LENGTH))));
    }

    @Test
    void rejectsTwoPassphraseSlots() {
        assertCode(VaultException.Code.CORRUPT, fileWithSlots(List.of(
                slot(MASTER_ID, SlotHeader.MASTER, EnvelopeCodec.WRAPPED_KEY_LENGTH),
                slot(RECOVERY_ID, SlotHeader.MASTER, EnvelopeCodec.WRAPPED_KEY_LENGTH))));
    }

    @Test
    void rejectsDuplicateSlotIds() {
        assertCode(VaultException.Code.CORRUPT, fileWithSlots(List.of(
                slot(MASTER_ID, SlotHeader.MASTER, EnvelopeCodec.WRAPPED_KEY_LENGTH),
                slot(MASTER_ID, SlotHeader.RECOVERY, EnvelopeCodec.WRAPPED_KEY_LENGTH))));
    }

    // ---- encoder refuses what the decoder would reject ----------------------------------

    @Test
    void encodeHeaderRejectsInvalidHeader() {
        EnvelopeHeader noMasterSlot = new EnvelopeHeader(kdf(), List.of(
                new SlotHeader(RECOVERY_ID, SlotHeader.RECOVERY, new byte[EnvelopeCodec.WRAPPED_KEY_LENGTH])),
                1L, 1L, 1L);
        assertThrows(IllegalArgumentException.class, () -> EnvelopeCodec.encodeHeader(noMasterSlot));
    }

    @Test
    void encodeHeaderRejectsZeroSaveSeq() {
        EnvelopeHeader h = new EnvelopeHeader(kdf(), header().slots(), 1L, 1L, 0L);
        assertThrows(IllegalArgumentException.class, () -> EnvelopeCodec.encodeHeader(h));
    }

    @Test
    void encodeRejectsCiphertextShorterThanTag() {
        assertThrows(IllegalArgumentException.class,
                () -> EnvelopeCodec.encode(header(), new byte[SALT], new byte[TAG - 1]));
    }

    @Test
    void aadOfRejectsWrongSaltLength() {
        assertThrows(IllegalArgumentException.class, () -> EnvelopeCodec.aadOf(new byte[1], new byte[SALT - 1]));
    }

    // ---- value classes ------------------------------------------------------------------

    @Test
    void headerTypesCopyArraysInAndOut() {
        byte[] salt = filled(SALT, 0x07);
        KdfHeader k = new KdfHeader("argon2id", 1, 1, 1, salt);
        salt[0] = 0;
        k.salt()[1] = 0;
        assertArrayEquals(filled(SALT, 0x07), k.salt());

        byte[] wrapped = filled(EnvelopeCodec.WRAPPED_KEY_LENGTH, 0x09);
        SlotHeader s = new SlotHeader(MASTER_ID, SlotHeader.MASTER, wrapped);
        wrapped[0] = 0;
        s.wrappedKey()[1] = 0;
        assertArrayEquals(filled(EnvelopeCodec.WRAPPED_KEY_LENGTH, 0x09), s.wrappedKey());
    }

    @Test
    void nextSaveIncrementsSequenceAndKeepsCreated() {
        EnvelopeHeader next = header().nextSave(500L);
        assertEquals(2L, next.saveSeq());
        assertEquals(100L, next.created());
        assertEquals(500L, next.saved());
    }

    @Test
    void nextSaveRefusesToOverflow() {
        EnvelopeHeader h = new EnvelopeHeader(kdf(), header().slots(), 1L, 1L, Long.MAX_VALUE);
        assertThrows(ArithmeticException.class, () -> assertNotNull(h.nextSave(2L)));
    }

    @Test
    void encodeHeaderRejectsEveryFieldTheDecoderWouldReject() {
        Argon2Params f = Argon2Params.FLOOR;
        byte[] salt = filled(SALT, 0x33);
        List<SlotHeader> slots = header().slots();
        SlotHeader master = slots.get(0);
        SlotHeader recovery = slots.get(1);
        SlotHeader otherRecovery = new SlotHeader(new UUID(5L, 6L), SlotHeader.RECOVERY,
                new byte[EnvelopeCodec.WRAPPED_KEY_LENGTH]);
        List<EnvelopeHeader> bad = new ArrayList<>(List.of(
                new EnvelopeHeader(new KdfHeader("scrypt", f.memoryKiB(), f.iterations(), f.parallelism(), salt),
                        slots, 1L, 1L, 1L),
                new EnvelopeHeader(new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB() - 1, f.iterations(),
                        f.parallelism(), salt), slots, 1L, 1L, 1L),
                new EnvelopeHeader(new KdfHeader(EnvelopeCodec.KDF_ALG, EnvelopeCodec.MAX_MEMORY_KIB + 1,
                        f.iterations(), f.parallelism(), salt), slots, 1L, 1L, 1L),
                new EnvelopeHeader(new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB(), EnvelopeCodec.MAX_ITERATIONS + 1,
                        f.parallelism(), salt), slots, 1L, 1L, 1L),
                new EnvelopeHeader(new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB(), f.iterations(),
                        EnvelopeCodec.MAX_PARALLELISM + 1, salt), slots, 1L, 1L, 1L),
                new EnvelopeHeader(new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB(), f.iterations(),
                        f.parallelism(), new byte[SALT - 1]), slots, 1L, 1L, 1L),
                new EnvelopeHeader(kdf(), List.of(), 1L, 1L, 1L),
                new EnvelopeHeader(kdf(), slots, -1L, 1L, 1L),
                new EnvelopeHeader(kdf(), slots, 1L, -1L, 1L),
                new EnvelopeHeader(kdf(), List.of(new SlotHeader(MASTER_ID, SlotHeader.MASTER, new byte[39])),
                        1L, 1L, 1L),
                new EnvelopeHeader(kdf(), List.of(master, new SlotHeader(MASTER_ID, SlotHeader.RECOVERY,
                        new byte[EnvelopeCodec.WRAPPED_KEY_LENGTH])), 1L, 1L, 1L),
                new EnvelopeHeader(kdf(), List.of(master, new SlotHeader(RECOVERY_ID, "fido2",
                        new byte[EnvelopeCodec.WRAPPED_KEY_LENGTH])), 1L, 1L, 1L),
                new EnvelopeHeader(kdf(), List.of(master, recovery, otherRecovery), 1L, 1L, 1L)));
        List<SlotHeader> many = new ArrayList<>();
        for (int i = 0; i <= EnvelopeCodec.MAX_SLOTS; i++) {
            many.add(new SlotHeader(new UUID(9L, i), SlotHeader.RECOVERY, new byte[EnvelopeCodec.WRAPPED_KEY_LENGTH]));
        }
        bad.add(new EnvelopeHeader(kdf(), many, 1L, 1L, 1L));
        for (EnvelopeHeader h : bad) {
            assertThrows(IllegalArgumentException.class, () -> EnvelopeCodec.encodeHeader(h), h.toString());
        }
    }

    @Test
    void theLargestValidHeaderIsFarBelowTheLimit() {
        EnvelopeHeader largest = new EnvelopeHeader(new KdfHeader(EnvelopeCodec.KDF_ALG, EnvelopeCodec.MAX_MEMORY_KIB,
                EnvelopeCodec.MAX_ITERATIONS, EnvelopeCodec.MAX_PARALLELISM, filled(SALT, 0xFF)),
                header().slots(), Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE);
        assertEquals(true, EnvelopeCodec.encodeHeader(largest).length < EnvelopeCodec.MAX_HEADER / 64);
    }

    @Test
    void aadOfRejectsAnEmptyOrOversizedHeader() {
        byte[] dataSalt = filled(SALT, 0);
        assertThrows(IllegalArgumentException.class, () -> EnvelopeCodec.aadOf(new byte[0], dataSalt));
        assertThrows(IllegalArgumentException.class,
                () -> EnvelopeCodec.aadOf(new byte[EnvelopeCodec.MAX_HEADER + 1], dataSalt));
        assertEquals(PREFIX + EnvelopeCodec.MAX_HEADER + SALT,
                EnvelopeCodec.aadOf(new byte[EnvelopeCodec.MAX_HEADER], dataSalt).length);
    }

    @Test
    void rejectsSlotsThatAreNotAnArrayTwoRecoverySlotsAndFieldsOfTheWrongType() {
        Map<String, CborValue> top = headerMap();
        top.put("slots", new CborValue.Text("none"));
        assertCode(VaultException.Code.CORRUPT, file(top));
        assertCode(VaultException.Code.CORRUPT, fileWithSlots(List.of(
                slot(MASTER_ID, SlotHeader.MASTER, EnvelopeCodec.WRAPPED_KEY_LENGTH),
                slot(RECOVERY_ID, SlotHeader.RECOVERY, EnvelopeCodec.WRAPPED_KEY_LENGTH),
                slot(new UUID(7L, 8L), SlotHeader.RECOVERY, EnvelopeCodec.WRAPPED_KEY_LENGTH))));
        assertCode(VaultException.Code.CORRUPT, fileWithSlots(List.of(new CborValue.MapV(Map.of(
                "id", new CborValue.Bytes(uuidBytes(MASTER_ID)),
                "type", new CborValue.UInt(1),
                "wrapped_key", new CborValue.Bytes(new byte[EnvelopeCodec.WRAPPED_KEY_LENGTH]))))));
        assertCode(VaultException.Code.CORRUPT, fileWithSlots(List.of(new CborValue.MapV(Map.of(
                "id", new CborValue.Text(MASTER_ID.toString()),
                "type", new CborValue.Text(SlotHeader.MASTER),
                "wrapped_key", new CborValue.Bytes(new byte[EnvelopeCodec.WRAPPED_KEY_LENGTH]))))));
    }

    // ---- helpers ------------------------------------------------------------------------

    private static void assertCode(VaultException.Code expected, byte[] file) {
        VaultException e = assertThrows(VaultException.class, () -> EnvelopeCodec.decode(file));
        assertEquals(expected, e.code());
    }

    private static KdfHeader kdf() {
        Argon2Params f = Argon2Params.FLOOR;
        return new KdfHeader(EnvelopeCodec.KDF_ALG, f.memoryKiB(), f.iterations(), f.parallelism(), filled(SALT, 0x33));
    }

    private static EnvelopeHeader header() {
        return new EnvelopeHeader(kdf(), List.of(
                new SlotHeader(MASTER_ID, SlotHeader.MASTER, filled(EnvelopeCodec.WRAPPED_KEY_LENGTH, 0x44)),
                new SlotHeader(RECOVERY_ID, SlotHeader.RECOVERY, filled(EnvelopeCodec.WRAPPED_KEY_LENGTH, 0x55))),
                100L, 200L, 1L);
    }

    private static byte[] validFile() {
        return EnvelopeCodec.encode(header(), filled(SALT, 0x01), filled(TAG + 4, 0x02));
    }

    /** Mutable copy of the header map that {@link #header()} encodes to. */
    private static Map<String, CborValue> headerMap() {
        Argon2Params f = Argon2Params.FLOOR;
        Map<String, CborValue> top = new HashMap<>();
        top.put("schema_version", new CborValue.UInt(1));
        top.put("kdf", new CborValue.MapV(kdfMap(f)));
        top.put("slots", new CborValue.Array(List.of(
                slotWithFill(MASTER_ID, SlotHeader.MASTER, 0x44),
                slotWithFill(RECOVERY_ID, SlotHeader.RECOVERY, 0x55))));
        top.put("created", new CborValue.UInt(100));
        top.put("saved", new CborValue.UInt(200));
        top.put("save_seq", new CborValue.UInt(1));
        return top;
    }

    private static Map<String, CborValue> kdfMap(Argon2Params f) {
        Map<String, CborValue> kdf = new HashMap<>();
        kdf.put("alg", new CborValue.Text(EnvelopeCodec.KDF_ALG));
        kdf.put("m", new CborValue.UInt(f.memoryKiB()));
        kdf.put("t", new CborValue.UInt(f.iterations()));
        kdf.put("p", new CborValue.UInt(f.parallelism()));
        kdf.put("salt", new CborValue.Bytes(filled(SALT, 0x33)));
        return kdf;
    }

    private static byte[] fileWithKdf(String key, CborValue value) {
        Map<String, CborValue> kdf = kdfMap(Argon2Params.FLOOR);
        kdf.put(key, value);
        Map<String, CborValue> top = headerMap();
        top.put("kdf", new CborValue.MapV(kdf));
        return file(top);
    }

    private static byte[] fileWithSlots(List<CborValue> slots) {
        Map<String, CborValue> top = headerMap();
        top.put("slots", new CborValue.Array(slots));
        return file(top);
    }

    private static CborValue slot(UUID id, String type, int wrappedLength) {
        return new CborValue.MapV(Map.of(
                "id", new CborValue.Bytes(uuidBytes(id)),
                "type", new CborValue.Text(type),
                "wrapped_key", new CborValue.Bytes(new byte[wrappedLength])));
    }

    private static CborValue slotWithFill(UUID id, String type, int fill) {
        return new CborValue.MapV(Map.of(
                "id", new CborValue.Bytes(uuidBytes(id)),
                "type", new CborValue.Text(type),
                "wrapped_key", new CborValue.Bytes(filled(EnvelopeCodec.WRAPPED_KEY_LENGTH, fill))));
    }

    private static byte[] file(Map<String, CborValue> top) {
        return fileFromCbor(CborWriter.encode(new CborValue.MapV(top)));
    }

    /** Builds a file around arbitrary header bytes, bypassing encodeHeader's validation. */
    private static byte[] fileFromCbor(byte[] headerCbor) {
        byte[] aad = EnvelopeCodec.aadOf(headerCbor, filled(SALT, 0x01));
        return Arrays.copyOf(aad, aad.length + TAG + 4);
    }

    private static byte[] uuidBytes(UUID id) {
        return ByteBuffer.allocate(16).putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits()).array();
    }

    private static byte[] filled(int length, int value) {
        byte[] b = new byte[length];
        Arrays.fill(b, (byte) value);
        return b;
    }
}
