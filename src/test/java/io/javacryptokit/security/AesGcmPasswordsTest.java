package io.javacryptokit.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.CredentialCryptoException.Reason;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * AAD-01·API-01/02(원시 AES-GCM)·PWD-01: NIST GCM 명세 벡터(Test Case 1·2·4·13·14·16)의 복호화, 독립 구현(Python cryptography)이
 * 만든 Passphrase 파생 결과의 교차 복호화, AAD·키·Passphrase 불일치, ENC/JCKF와의 구분, 비밀번호 해시 형식·검증·재해시.
 */
class AesGcmPasswordsTest {
    private static final byte[] SALT = DigestMacKdfTest.range(0, 15);

    private static byte[] hex(String value) {
        return Encoding.HEX.decode(value);
    }

    private static Reason reason(ThrowingRunnable action) {
        try {
            action.run();
        } catch (CredentialCryptoException e) {
            return e.getReason();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        throw new AssertionError("예외가 나야 한다");
    }

    interface ThrowingRunnable {
        void run() throws Exception;
    }

    @Test
    void nistGcmVectorsDecryptInTheRawFormat() throws Exception {
        String zeroIv = "000000000000000000000000";
        assertArrayEquals(new byte[0], AesGcm.of(AesKeySize.AES_128, new byte[16]).decrypt(hex(zeroIv + "58e2fccefa7e3061367f1d57a4e7455a")));
        assertArrayEquals(new byte[16], AesGcm.of(AesKeySize.AES_128, new byte[16])
                .decrypt(hex(zeroIv + "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")));
        assertArrayEquals(new byte[0], AesGcm.of(AesKeySize.AES_256, new byte[32]).decrypt(hex(zeroIv + "530f8afbc74536b9a963b4f1c4cb738b")));
        assertArrayEquals(new byte[16], AesGcm.of(AesKeySize.AES_256, new byte[32])
                .decrypt(hex(zeroIv + "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")));
        byte[] plain = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        byte[] aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        String iv = "cafebabefacedbaddecaf888";
        AesGcm tc4 = AesGcm.of(AesKeySize.AES_128, hex("feffe9928665731c6d6a8f9467308308"));
        assertArrayEquals(plain, tc4.decrypt(hex(iv + "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"), aad));
        AesGcm tc16 = AesGcm.of(AesKeySize.AES_256, hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"));
        byte[] sealed16 = hex(iv + "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b");
        assertArrayEquals(plain, tc16.decrypt(sealed16, aad));
        assertEquals(Reason.INTEGRITY, reason(() -> tc16.decrypt(sealed16)), "AAD 없이");
        assertEquals(Reason.INTEGRITY, reason(() -> tc16.decrypt(sealed16, Arrays.copyOf(aad, aad.length - 1))));
        assertEquals(Reason.INTEGRITY, reason(() -> tc4.decrypt(sealed16, aad)), "다른 키");
    }

    @Test
    void passphraseCombinationsInteroperateWithAnIndependentImplementation() throws Exception {
        char[] pass = "dummy-파생-Passphrase".toCharArray();
        AesGcm aes128 = AesGcm.fromPassphrase(AesKeySize.AES_128, Pbkdf2Algorithm.SHA256, pass, SALT, 100_000);
        AesGcm aes256 = AesGcm.fromPassphrase(AesKeySize.AES_256, Pbkdf2Algorithm.SHA512, pass, SALT, 100_000);
        byte[] fromPython128 = hex("000102030405060708090a0bf806540cf2fc2622ca9f87adc1fc61898606820190b5002be1d1defa");
        byte[] fromPython256 = hex("000102030405060708090a0b485544debfd8df8d03bc0477f4622647d4792f80f05b72936e518386");
        byte[] aad = "order:42".getBytes(StandardCharsets.UTF_8);
        assertEquals("dummy-평문", new String(aes128.decrypt(fromPython128, aad), StandardCharsets.UTF_8));
        assertEquals("dummy-평문", new String(aes256.decrypt(fromPython256, aad), StandardCharsets.UTF_8));
        // 네 조합(AES-128/256 × SHA256/512) 모두 왕복, 조합이 하나라도 다르면 INTEGRITY
        for (AesKeySize size : AesKeySize.values()) {
            for (Pbkdf2Algorithm kdf : Pbkdf2Algorithm.values()) {
                AesGcm gcm = AesGcm.fromPassphrase(size, kdf, pass, SALT, 100_000);
                String sealed = gcm.encryptText("dummy-주문-데이터", "customer:7", Encoding.BASE64_URL);
                assertEquals("dummy-주문-데이터", AesGcm.fromPassphrase(size, kdf, pass.clone(), SALT.clone(), 100_000)
                        .decryptText(sealed, "customer:7", Encoding.BASE64_URL), size + "/" + kdf);
                Pbkdf2Algorithm otherKdf = kdf == Pbkdf2Algorithm.SHA256 ? Pbkdf2Algorithm.SHA512 : Pbkdf2Algorithm.SHA256;
                assertEquals(Reason.INTEGRITY, reason(() -> AesGcm.fromPassphrase(size, otherKdf, pass, SALT, 100_000)
                        .decryptText(sealed, "customer:7", Encoding.BASE64_URL)));
                assertEquals(Reason.INTEGRITY, reason(() -> AesGcm.fromPassphrase(size, kdf, pass, Pbkdf2.newSalt(), 100_000)
                        .decryptText(sealed, "customer:7", Encoding.BASE64_URL)));
                assertEquals(Reason.INTEGRITY, reason(() -> gcm.decryptText(sealed, "customer:8", Encoding.BASE64_URL)));
                assertEquals(Reason.INTEGRITY, reason(() -> gcm.decryptText(sealed, Encoding.BASE64_URL)));
            }
        }
        assertArrayEquals("dummy-파생-Passphrase".toCharArray(), pass, "호출자 배열은 바뀌지 않는다");
    }

    @Test
    void rawFormatKeysAndFailuresAreExplicit() throws Exception {
        byte[] key = AesGcm.generateKey(AesKeySize.AES_256);
        AesGcm gcm = AesGcm.of(AesKeySize.AES_256, key);
        byte[] plain = "dummy-원문".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = gcm.encrypt(plain);
        assertEquals(AesGcm.IV_BYTES + plain.length + AesGcm.TAG_BYTES, sealed.length);
        assertFalse(Arrays.equals(sealed, gcm.encrypt(plain)), "IV는 매번 새 난수");
        Arrays.fill(key, (byte) 0);
        assertArrayEquals(plain, gcm.decrypt(sealed), "호출자 키 배열을 지워도 동작");
        byte[] tampered = sealed.clone();
        tampered[tampered.length - 1] ^= 1;
        assertEquals(Reason.INTEGRITY, reason(() -> gcm.decrypt(tampered)));
        assertEquals(Reason.INTEGRITY, reason(() -> gcm.decrypt(Arrays.copyOf(sealed, sealed.length - 1))));
        assertEquals(Reason.INVALID_TOKEN, reason(() -> gcm.decrypt(new byte[27])));
        assertEquals(Reason.INVALID_TOKEN, reason(() -> gcm.decryptText("not base64!", Encoding.BASE64)));
        assertArrayEquals(new byte[0], gcm.decrypt(gcm.encrypt(new byte[0])), "빈 평문");
        // 키 길이를 추측하거나 맞추지 않는다
        assertThrows(IllegalArgumentException.class, () -> AesGcm.of(AesKeySize.AES_128, new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> AesGcm.of(AesKeySize.AES_256, new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> AesGcm.of(AesKeySize.AES_256, null));
        assertEquals(16, AesGcm.generateKey(AesKeySize.AES_128).length);
        // 원시 결과는 ENC 토큰이 아니고, ENC 토큰은 원시 결과가 아니다(서로 해석하지 않음)
        String text = gcm.encryptText("dummy", Encoding.BASE64_URL);
        assertFalse(text.startsWith("ENC["));
        CredentialCrypto direct = CredentialCrypto.fromRawKey("raw-sep", AesGcm.generateKey(AesKeySize.AES_256));
        assertEquals(Reason.INVALID_TOKEN, reason(() -> direct.decryptText(text)));
        String enc = direct.encryptText("dummy");
        assertEquals(Reason.INVALID_TOKEN, reason(() -> gcm.decryptText(enc, Encoding.BASE64_URL)));
        assertEquals("AesGcm[AES_256]", gcm.toString());
    }

    @Test
    void credentialCryptoSha512KeepsEncV1AndNeedsTheSameKdf() throws Exception {
        char[] pass = "dummy-직접-Passphrase".toCharArray();
        CredentialCrypto sha512 = CredentialCrypto.fromPassphrase("app-pass-512", pass, SALT, 210_000, Pbkdf2Algorithm.SHA512);
        String token = sha512.encryptText("dummy-비밀");
        assertTrue(token.startsWith("ENC[v1:app-pass-512:"), token);
        assertEquals("dummy-비밀", CredentialCrypto.fromPassphrase("app-pass-512", pass, SALT, 210_000, Pbkdf2Algorithm.SHA512)
                .decryptText(token));
        assertEquals(Reason.INTEGRITY, reason(() -> CredentialCrypto.fromPassphrase("app-pass-512", pass, SALT, 210_000).decryptText(token)),
                "같은 Passphrase·Salt라도 KDF가 다르면 다른 키");
        // 기본 오버로드는 SHA256과 같다(기존 계약)
        String token256 = CredentialCrypto.fromPassphrase("app-pass-256", pass, SALT, 100_000).encryptText("x");
        assertEquals("x", CredentialCrypto.fromPassphrase("app-pass-256", pass, SALT, 100_000, Pbkdf2Algorithm.SHA256).decryptText(token256));
        // 같은 Passphrase·Salt·SHA512에서 AesGcm(AES-256)과 CredentialCrypto는 같은 32바이트 키를 쓴다(형식만 다름)
        byte[] derived = Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA512, pass, SALT, 210_000, 32);
        assertEquals("dummy-비밀", CredentialCrypto.fromRawKey("app-pass-512", derived).decryptText(token));
        assertEquals(Reason.INVALID_INPUT, reason(() -> CredentialCrypto.fromPassphrase("k", pass, SALT, 210_000, null)));
        assertEquals(Reason.INVALID_INPUT, reason(() -> CredentialCrypto.fromPassphrase("k", pass, new byte[32], 210_000, Pbkdf2Algorithm.SHA512)),
                "ENC 경로의 Salt는 기존 계약대로 16바이트");
    }

    @Test
    void passwordHashFormatVerificationAndRehash() {
        char[] password = "dummy-로그인-비밀번호".toCharArray();
        // 독립 구현(Python hashlib.pbkdf2_hmac)으로 만든 저장값을 검증한다
        String python256 = "$pbkdf2-sha256$v=1$i=100000$AAECAwQFBgcICQoLDA0ODw$ooL9PKBgWSM+mY/3xe5iUqS9U+nHjMmOiiwceY153lo";
        String python512 = "$pbkdf2-sha512$v=1$i=100000$AAECAwQFBgcICQoLDA0ODw$SQSC3ac47bPZKSidk08KJYAtW4O2FZ5ovI+A+R2YZmg1M73vC9rT24r7sZI0Iil6kKHPFkIWWbor5Wf853y0Pw";
        assertTrue(Passwords.verify(password, python256));
        assertTrue(Passwords.verify(password, python512));
        assertFalse(Passwords.verify("dummy-로그인-비밀번호!".toCharArray(), python256));
        assertTrue(Passwords.needsRehash(python256), "100,000회 < 기본 600,000회");
        assertTrue(Passwords.needsRehash(python512), "알고리즘이 기본(SHA256)과 다름");
        assertFalse(Passwords.needsRehash(python512, Pbkdf2Algorithm.SHA512, 100_000));
        String stored = Passwords.hash(password);
        assertTrue(stored.matches("\\$pbkdf2-sha256\\$v=1\\$i=600000\\$[A-Za-z0-9+/]{22}\\$[A-Za-z0-9+/]{43}"), stored);
        assertNotEquals(stored, Passwords.hash(password), "해시마다 새 Salt");
        assertTrue(Passwords.verify(password, stored));
        assertFalse(Passwords.needsRehash(stored));
        String sha512 = Passwords.hash(password, Pbkdf2Algorithm.SHA512, 210_000);
        assertTrue(sha512.startsWith("$pbkdf2-sha512$v=1$i=210000$"));
        assertTrue(Passwords.verify(password, sha512));
        assertFalse(Passwords.verify("".toCharArray(), stored), "빈 입력은 불일치");
        assertFalse(Passwords.verify("   ".toCharArray(), stored));
        assertArrayEquals("dummy-로그인-비밀번호".toCharArray(), password);
        // NFD로 입력해도 같은 비밀번호
        assertTrue(Passwords.verify(java.text.Normalizer.normalize("dummy-로그인-비밀번호", java.text.Normalizer.Form.NFD).toCharArray(), stored));
        // 형식 변조·범위 밖(서비스 거부 방지)·모르는 알고리즘은 계산하지 않고 거부
        String[] bad = {
            stored.replace("$v=1$", "$v=2$"),
            stored.replace("$i=600000$", "$i=5000001$"),
            stored.replace("$i=600000$", "$i=999$"),
            stored.replace("pbkdf2-sha256", "pbkdf2-sha1"),
            stored.replace("pbkdf2-sha256", "pbkdf2-sha512"),
            stored.substring(0, stored.length() - 1),
            stored + "=",
            "plain-text-password",
            "",
        };
        for (String value : bad) assertThrows(IllegalArgumentException.class, () -> Passwords.verify(password, value), value);
        assertThrows(IllegalArgumentException.class, () -> Passwords.hash(password, Pbkdf2Algorithm.SHA256, 99_999));
        assertThrows(IllegalArgumentException.class, () -> Passwords.hash("".toCharArray()));
        assertThrows(IllegalArgumentException.class, () -> Passwords.verify(null, stored));
    }
}
