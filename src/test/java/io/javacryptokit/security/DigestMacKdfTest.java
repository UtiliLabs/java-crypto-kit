package io.javacryptokit.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * DIG-01·MAC-01·KDF-01: FIPS 180 "abc", RFC 4231 HMAC, RFC 5869 HKDF 고정 벡터와 독립 구현(Python cryptography 50, OpenSSL
 * 기반)으로 만든 SHA512·PBKDF2 벡터, 파일 스트리밍, 키 길이 정책, 동시성.
 */
class DigestMacKdfTest {
    @TempDir
    Path dir;

    private static byte[] hex(String value) {
        return Encoding.HEX.decode(value);
    }

    @Test
    void digestsMatchStandardVectorsForBytesTextAndFiles() throws IOException {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Digests.sha256Hex("abc"));
        assertEquals("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
                + "454d4423643ce80e2a9ac94fa54ca49f", Digests.hash(DigestAlgorithm.SHA512, "abc", Encoding.HEX));
        // 파일: 여러 버퍼(64KiB)에 걸친 크기도 메모리 계산과 같고 파일은 바뀌지 않는다
        byte[] big = new byte[200_000 + 17];
        for (int i = 0; i < big.length; i++) big[i] = (byte) (i * 31);
        Path file = Files.write(dir.resolve("data.bin"), big);
        long modified = Files.getLastModifiedTime(file).toMillis();
        assertEquals(Digests.sha256Hex(big), Digests.sha256File(file));
        assertArrayEquals(Digests.hash(DigestAlgorithm.SHA512, big), Digests.hashFile(DigestAlgorithm.SHA512, file));
        assertTrue(Digests.verifyFile(DigestAlgorithm.SHA256, file, Digests.sha256Hex(big).toUpperCase(), Encoding.HEX));
        assertFalse(Digests.verifyFile(DigestAlgorithm.SHA256, file, Digests.sha256Hex("other"), Encoding.HEX));
        assertThrows(IllegalArgumentException.class, () -> Digests.verifyFile(DigestAlgorithm.SHA256, file, "xyz", Encoding.HEX));
        assertThrows(NoSuchFileException.class, () -> Digests.sha256File(dir.resolve("missing.bin")));
        assertArrayEquals(big, Files.readAllBytes(file));
        assertEquals(modified, Files.getLastModifiedTime(file).toMillis());
    }

    @Test
    void hmacMatchesRfc4231ForSha256AndSha512() {
        Object[][] cases = {
            {repeat(0x0b, 20), "4869205468657265", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
            {"Jefe".getBytes(StandardCharsets.US_ASCII), Encoding.HEX.encode("what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII)),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"},
            {repeat(0xaa, 20), Encoding.HEX.encode(repeat(0xdd, 50)), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"},
            {range(1, 25), Encoding.HEX.encode(repeat(0xcd, 50)), "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
                "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"},
            {repeat(0xaa, 131), Encoding.HEX.encode("Test Using Larger Than Block-Size Key - Hash Key First".getBytes(StandardCharsets.US_ASCII)),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"},
        };
        for (Object[] c : cases) {
            byte[] key = (byte[]) c[0];
            byte[] data = hex((String) c[1]);
            // 짧은 RFC 키(4~20바이트)는 외부 연동 경로로만 받는다. 32바이트 이상은 두 경로 모두 같은 값
            Hmac sha256 = Hmac.ofExternalKey(HmacAlgorithm.SHA256, key);
            Hmac sha512 = Hmac.ofExternalKey(HmacAlgorithm.SHA512, key);
            assertEquals(c[2], sha256.sign(data, Encoding.HEX));
            assertEquals(c[3], sha512.sign(data, Encoding.HEX));
            assertTrue(sha256.verify(data, (String) c[2], Encoding.HEX));
            assertTrue(sha512.verify(data, hex((String) c[3])));
            if (key.length >= Hmac.MIN_KEY_BYTES) assertEquals(c[2], Hmac.of(HmacAlgorithm.SHA256, key).sign(data, Encoding.HEX));
        }
    }

    @Test
    void hmacKeyPolicyEncodingsAndMismatch() {
        assertEquals(32, Hmac.generateKey().length);
        assertEquals(64, Hmac.generateKey(HmacAlgorithm.SHA512).length);
        assertThrows(IllegalArgumentException.class, () -> Hmac.of(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> Hmac.of(null));
        assertThrows(IllegalArgumentException.class, () -> Hmac.ofExternalKey(HmacAlgorithm.SHA256, new byte[0]));
        byte[] key = Hmac.generateKey();
        Hmac hmac = Hmac.of(key);
        String body = "{\"orderId\":\"A-1\",\"금액\":1000}";
        for (Encoding encoding : new Encoding[] {Encoding.HEX, Encoding.BASE64, Encoding.BASE64_URL}) {
            String mac = hmac.sign(body, encoding);
            assertTrue(hmac.verify(body, mac, encoding));
            assertFalse(hmac.verify(body + " ", mac, encoding), "원본을 정규화하지 않는다");
        }
        assertArrayEquals(hmac.sign(body), hmac.sign(Bytes.utf8(body)));
        Arrays.fill(key, (byte) 0);
        assertTrue(hmac.verify(body, hmac.sign(body, Encoding.HEX), Encoding.HEX), "호출자 배열을 지워도 객체는 복사본을 쓴다");
        assertFalse(hmac.verify(Bytes.utf8(body), new byte[0]));
        assertFalse(hmac.verify(Bytes.utf8(body), (byte[]) null));
        assertThrows(IllegalArgumentException.class, () -> hmac.verify(body, "zz-not-hex", Encoding.HEX), "형식 오류는 불일치와 구분");
        assertFalse(Hmac.of(Hmac.generateKey()).verify(body, hmac.sign(body, Encoding.HEX), Encoding.HEX), "다른 키");
        assertFalse(hmac.toString().contains(Encoding.HEX.encode(key)));
    }

    @Test
    void hmacObjectIsSafeAcrossThreads() throws Exception {
        Hmac hmac = Hmac.of(HmacAlgorithm.SHA512, Hmac.generateKey(HmacAlgorithm.SHA512));
        String expected = hmac.sign("동시성", Encoding.HEX);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 400; i++) {
                results.add(pool.submit(() -> expected.equals(hmac.sign("동시성", Encoding.HEX)) && hmac.verify("동시성", expected, Encoding.HEX)));
            }
            for (Future<Boolean> result : results) assertTrue(result.get());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void hkdfMatchesRfc5869AndAnIndependentSha512Vector() {
        byte[] ikm = repeat(0x0b, 22);
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                Encoding.HEX.encode(Hkdf.derive(ikm, salt, info, 42)));
        assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                Encoding.HEX.encode(Hkdf.derive(ikm, null, null, 42)), "RFC 5869 A.3: Salt·Info 없음");
        assertEquals("832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
                Encoding.HEX.encode(Hkdf.derive(HmacAlgorithm.SHA512, ikm, salt, info, 42)));
        assertEquals("f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bac",
                Encoding.HEX.encode(Hkdf.derive(HmacAlgorithm.SHA512, ikm, new byte[0], new byte[0], 42)));
        byte[] enc = Hkdf.derive(HmacAlgorithm.SHA256, ikm, salt, "app/enc/v1", 32);
        byte[] mac = Hkdf.derive(HmacAlgorithm.SHA256, ikm, salt, "app/mac/v1", 32);
        assertFalse(Arrays.equals(enc, mac), "용도(info)가 다르면 다른 키");
        assertEquals(8160, Hkdf.derive(ikm, salt, info, 255 * 32).length);
        assertThrows(IllegalArgumentException.class, () -> Hkdf.derive(ikm, salt, info, 255 * 32 + 1));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.derive(ikm, salt, info, 0));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.derive(new byte[0], salt, info, 32));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.expand(HmacAlgorithm.SHA256, new byte[31], info, 32));
    }

    @Test
    void pbkdf2MatchesIndependentVectorsAndValidatesInput() {
        byte[] salt = range(0, 15);
        char[] pass = "dummy-파생-Passphrase".toCharArray();
        assertEquals("d9d92e3bfaa79c6b6fdd617ea9d512a913e9e22bec71f33226c1ff66450a287f",
                Encoding.HEX.encode(Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, pass, salt, 100_000, 32)));
        assertEquals("dff376ccdab3ce26b18eb71fcbf8524335b0c7961f8787da069e4a1589faddc9",
                Encoding.HEX.encode(Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA512, pass, salt, 100_000, 32)));
        assertEquals("d9d92e3bfaa79c6b6fdd617ea9d512a9",
                Encoding.HEX.encode(Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, pass, salt, 100_000, 16)));
        assertEquals("dff376ccdab3ce26b18eb71fcbf8524335b0c7961f8787da069e4a1589faddc96d58f62bf8d106161e17759b4ef2edd70aa0dfd65a7a5e8a99a343e1bafe1d25",
                Encoding.HEX.encode(Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA512, pass, salt, 100_000, 64)));
        // NFD로 입력한 한글도 같은 키(NFC 정규화), 호출자 배열은 그대로
        char[] nfd = java.text.Normalizer.normalize("dummy-파생-Passphrase", java.text.Normalizer.Form.NFD).toCharArray();
        char[] copy = nfd.clone();
        assertArrayEquals(Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, pass, salt, 100_000, 32),
                Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, nfd, salt, 100_000, 32));
        assertArrayEquals(copy, nfd);
        assertEquals(16, Pbkdf2.newSalt().length);
        assertEquals(600_000, Pbkdf2Algorithm.SHA256.recommendedIterations());
        assertEquals(210_000, Pbkdf2Algorithm.SHA512.recommendedIterations());
        assertThrows(IllegalArgumentException.class, () -> Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, pass, new byte[15], 100_000, 32));
        assertThrows(IllegalArgumentException.class, () -> Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, pass, salt, 99_999, 32));
        assertThrows(IllegalArgumentException.class, () -> Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, pass, salt, 5_000_001, 32));
        assertThrows(IllegalArgumentException.class, () -> Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, pass, salt, 100_000, 15));
        assertThrows(IllegalArgumentException.class, () -> Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, "   ".toCharArray(), salt, 100_000, 32));
        assertThrows(IllegalArgumentException.class, () -> Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, "a\tb".toCharArray(), salt, 100_000, 32));
        char[] tooLong = new char[1025];
        Arrays.fill(tooLong, 'a');
        assertThrows(IllegalArgumentException.class, () -> Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, tooLong, salt, 100_000, 32));
    }

    static byte[] repeat(int value, int count) {
        byte[] out = new byte[count];
        Arrays.fill(out, (byte) value);
        return out;
    }

    static byte[] range(int from, int to) {
        byte[] out = new byte[to - from + 1];
        for (int i = 0; i < out.length; i++) out[i] = (byte) (from + i);
        return out;
    }
}
