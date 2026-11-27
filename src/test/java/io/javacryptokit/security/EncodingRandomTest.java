package io.javacryptokit.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** ENC-01·CMP-01·RNG-01/02: RFC 4648 벡터, 엄격한 디코딩, 안전 비교의 null·빈 값 규칙, 난수 길이·형식. */
class EncodingRandomTest {
    private static final String[] PLAIN = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    private static final String[] B32 = {"", "MY", "MZXQ", "MZXW6", "MZXW6YQ", "MZXW6YTB", "MZXW6YTBOI"};
    private static final String[] B32_PADDED = {"", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======"};
    private static final String[] B64 = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};

    @Test
    void longBase32PaddingIsRejectedWithoutDecoding() {
        // 정상 Base32의 패딩은 최대 6자다. 길게 이어진 '='는 실행 시간과 관계없이 형식 오류로 거부되어야 한다.
        for (int length : new int[] {7, 8, 10_000, 300_000}) {
            StringBuilder padding = new StringBuilder();
            for (int i = 0; i < length; i++) padding.append('=');
            for (String text : new String[] {padding.toString(), "MY" + padding, "MZXW6YTB" + padding}) {
                assertThrows(IllegalArgumentException.class, () -> Encoding.BASE32.decode(text), "길이 " + text.length());
            }
        }
        // 허용되는 패딩(0·1·3·4·6자)과 소문자 입력은 그대로 복원한다.
        assertArrayEquals("f".getBytes(StandardCharsets.US_ASCII), Encoding.BASE32.decode("my======"));
        assertArrayEquals("foob".getBytes(StandardCharsets.US_ASCII), Encoding.BASE32.decode("MZXW6YQ="));
        assertThrows(IllegalArgumentException.class, () -> Encoding.BASE32.decode("MY====="));
    }

    @Test
    void rfc4648VectorsEncodeAndDecode() {
        for (int i = 0; i < PLAIN.length; i++) {
            byte[] raw = PLAIN[i].getBytes(StandardCharsets.US_ASCII);
            assertEquals(B32[i], Encoding.BASE32.encode(raw));
            assertArrayEquals(raw, Encoding.BASE32.decode(B32[i]));
            assertArrayEquals(raw, Encoding.BASE32.decode(B32_PADDED[i]));
            assertArrayEquals(raw, Encoding.BASE32.decode(B32[i].toLowerCase()));
            assertEquals(B64[i], Encoding.BASE64.encode(raw));
            assertArrayEquals(raw, Encoding.BASE64.decode(B64[i]));
            assertEquals(B64[i].replace("=", ""), Encoding.BASE64_URL.encode(raw));
            assertArrayEquals(raw, Encoding.BASE64_URL.decode(B64[i]));
            assertArrayEquals(raw, Encoding.BASE64_URL.decode(B64[i].replace("=", "")));
        }
        assertEquals("666f6f626172", Encoding.HEX.encode("foobar".getBytes(StandardCharsets.US_ASCII)));
        assertArrayEquals("foobar".getBytes(StandardCharsets.US_ASCII), Encoding.HEX.decode("666F6F626172"));
        byte[] all = new byte[256];
        for (int i = 0; i < all.length; i++) all[i] = (byte) i;
        for (Encoding encoding : Encoding.values()) assertArrayEquals(all, encoding.decode(encoding.encode(all)), encoding.name());
        assertEquals("_-8", Encoding.BASE64_URL.encode(new byte[] {(byte) 0xff, (byte) 0xef}).substring(0, 3));
    }

    @Test
    void decodingIsStrictAndDoesNotGuess() {
        String[] badHex = {"abc", "zz", "0g", "٣٣", " 00", "00\n"};
        for (String bad : badHex) assertThrows(IllegalArgumentException.class, () -> Encoding.HEX.decode(bad), bad);
        // 정규형이 아님(남는 비트), 패딩 없음(표준), 잘못된 패딩, 다른 알파벳, 공백
        String[] badB64 = {"Zh==", "Zg", "Zg=", "Zm9v\n", "Zm-v", "Zm9 v", "Zg==="};
        for (String bad : badB64) assertThrows(IllegalArgumentException.class, () -> Encoding.BASE64.decode(bad), bad);
        String[] badUrl = {"Zh", "Zg=", "Zm+v", "Zm/v", "Z", "Zg==="};
        for (String bad : badUrl) assertThrows(IllegalArgumentException.class, () -> Encoding.BASE64_URL.decode(bad), bad);
        String[] badB32 = {"MZ", "M", "MZX", "MZXW6Y", "MY=====", "MY=======", "MY0", "MY 6", "MZ=XQ===", "MYı"};
        for (String bad : badB32) assertThrows(IllegalArgumentException.class, () -> Encoding.BASE32.decode(bad), bad);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Encoding.BASE64.decode("dummy-secret-token!"));
        assertFalse(e.getMessage().contains("dummy-secret-token"), "입력값이 오류 문구에 들어가면 안 된다");
        assertThrows(IllegalArgumentException.class, () -> Encoding.HEX.decode(null));
        assertThrows(IllegalArgumentException.class, () -> Encoding.HEX.encode(null));
    }

    @Test
    void utf8ConversionIsStrict() {
        assertArrayEquals(new byte[] {(byte) 0xed, (byte) 0x95, (byte) 0x9c}, Bytes.utf8("한"));
        assertEquals("한", Bytes.utf8String(new byte[] {(byte) 0xed, (byte) 0x95, (byte) 0x9c}));
        assertThrows(IllegalArgumentException.class, () -> Bytes.utf8("a\ud800b"));
        assertThrows(IllegalArgumentException.class, () -> Bytes.utf8String(new byte[] {(byte) 0xc3, (byte) 0x28}));
        assertThrows(IllegalArgumentException.class, () -> Bytes.utf8String(new byte[] {(byte) 0xed, (byte) 0xa0, (byte) 0x80}));
    }

    @Test
    void constantTimeCompareNeverTreatsMissingValuesAsEqual() {
        assertFalse(Bytes.equalsConstantTime((byte[]) null, null), "MessageDigest.isEqual(null, null)은 true지만 여기서는 false");
        assertFalse(Bytes.equalsConstantTime(new byte[0], new byte[0]));
        assertFalse(Bytes.equalsConstantTime(new byte[] {1}, null));
        assertFalse(Bytes.equalsConstantTime(new byte[] {1, 2}, new byte[] {1}));
        assertFalse(Bytes.equalsConstantTime(new byte[] {1, 2}, new byte[] {1, 3}));
        assertTrue(Bytes.equalsConstantTime(new byte[] {1, 2}, new byte[] {1, 2}));
        assertFalse(Bytes.equalsConstantTime((String) null, null));
        assertFalse(Bytes.equalsConstantTime("", ""));
        assertFalse(Bytes.equalsConstantTime("token", ""));
        assertFalse(Bytes.equalsConstantTime("a\ud800", "a\ud800"));
        assertTrue(Bytes.equalsConstantTime("토큰-1", "토큰-1"));
        assertFalse(Bytes.equalsConstantTime("토큰-1", "토큰-2"));
    }

    @Test
    void randomStringsPreservePrefixLengthAndAlphabet() {
        SecureRandoms.Alphabet[] sets = SecureRandoms.Alphabet.values();
        String[] ranges = {"0-9", "A-Z", "a-z", "A-Za-z", "A-Z0-9", "a-z0-9", "A-Za-z0-9"};
        assertEquals(ranges.length, sets.length);
        for (int i = 0; i < sets.length; i++) {
            String result = SecureRandoms.string(1024, sets[i], "00-한-");
            assertTrue(result.matches("00-한-[" + ranges[i] + "]{1024}"), sets[i].name());
        }
        SecureRandoms.Alphabet digits = SecureRandoms.Alphabet.DIGITS;
        assertTrue(SecureRandoms.string(1, digits).matches("[0-9]"));
        String prefix = new String(new char[1024]).replace('\0', '0');
        assertTrue(SecureRandoms.string(1, digits, prefix).startsWith(prefix));
        assertThrows(IllegalArgumentException.class, () -> SecureRandoms.string(0, digits));
        assertThrows(IllegalArgumentException.class, () -> SecureRandoms.string(1025, digits));
        assertThrows(IllegalArgumentException.class, () -> SecureRandoms.string(1, digits, prefix + "0"));
        assertThrows(IllegalArgumentException.class, () -> SecureRandoms.string(1, null));
        assertThrows(IllegalArgumentException.class, () -> SecureRandoms.string(1, digits, null));
    }

    @Test
    void randomValuesHaveTheDocumentedLengthsAndFormats() {
        assertEquals(43, SecureRandoms.token().length());
        assertTrue(SecureRandoms.token().matches("[A-Za-z0-9_-]{43}"));
        assertEquals(22, SecureRandoms.nonce().length());
        assertEquals(64, SecureRandoms.token(32, Encoding.HEX).length());
        assertEquals(44, SecureRandoms.token(32, Encoding.BASE64).length());
        assertEquals(16, SecureRandoms.bytes(16).length);
        assertEquals(65536, SecureRandoms.bytes(65536).length);
        int[] badBytes = {0, -1, 65537};
        for (int bad : badBytes) assertThrows(IllegalArgumentException.class, () -> SecureRandoms.bytes(bad));
        int[] badTokens = {15, 0, -5, 1025};
        for (int bad : badTokens) assertThrows(IllegalArgumentException.class, () -> SecureRandoms.token(bad));
        assertThrows(IllegalArgumentException.class, () -> SecureRandoms.token(32, null));
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 2000; i++) assertTrue(seen.add(SecureRandoms.token()));
        assertNotEquals(SecureRandoms.nonce(), SecureRandoms.nonce());
        UUID uuid = SecureRandoms.uuidV4();
        assertEquals(4, uuid.version());
        assertEquals(2, uuid.variant(), "RFC 9562 variant 10xx");
    }
}
