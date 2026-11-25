package io.javacryptokit.security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.CredentialCryptoException.Reason;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * ADD-RSA-01·ADD-HYB-01(N01~N04 중 단위 범위): RSA 2048/3072 × OAEP SHA256/SHA512 왕복과 최대 평문 경계, JCA를 거치지 않는 독립
 * OAEP 디코딩으로 해시·MGF1 매개변수 확인, 실패 원인 비노출, JCKH 봉투 배치·변조·잘림·AAD·다른 키 거부, 문서의 배치대로 직접 조립한
 * 봉투의 복호화(형식 적합성). 외부 구현(Python cryptography) 교차 검증은 최종 통합 단계 스크립트에서 한다.
 */
class RsaOaepHybridTest {
    private static KeyPair rsa2048;
    private static KeyPair rsa3072;
    private static KeyPair other;

    @BeforeAll
    static void keys() {
        rsa2048 = Signatures.generateRsaKeyPair(2048);
        rsa3072 = Signatures.generateRsaKeyPair(3072);
        other = Signatures.generateRsaKeyPair(2048);
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
    void oaepRoundTripsAndPlaintextLimits() throws Exception {
        assertEquals(190, RsaOaep.maxPlaintextBytes(rsa2048.getPublic(), RsaOaepAlgorithm.SHA256));
        assertEquals(318, RsaOaep.maxPlaintextBytes(rsa3072.getPublic(), RsaOaepAlgorithm.SHA256));
        assertEquals(126, RsaOaep.maxPlaintextBytes(rsa2048.getPublic(), RsaOaepAlgorithm.SHA512));
        assertEquals(254, RsaOaep.maxPlaintextBytes(rsa3072.getPublic(), RsaOaepAlgorithm.SHA512));
        for (KeyPair pair : new KeyPair[] {rsa2048, rsa3072}) {
            for (RsaOaepAlgorithm algorithm : RsaOaepAlgorithm.values()) {
                int max = RsaOaep.maxPlaintextBytes(pair.getPublic(), algorithm);
                byte[] exact = new byte[max];
                Arrays.fill(exact, (byte) 0x5a);
                byte[] ciphertext = RsaOaep.encrypt(pair.getPublic(), exact, algorithm);
                assertEquals(((java.security.interfaces.RSAKey) pair.getPublic()).getModulus().bitLength() / 8, ciphertext.length);
                assertArrayEquals(exact, RsaOaep.decrypt(pair.getPrivate(), ciphertext, algorithm));
                assertFalse(Arrays.equals(ciphertext, RsaOaep.encrypt(pair.getPublic(), exact, algorithm)), "같은 평문도 매번 다른 암호문");
                assertThrows(IllegalArgumentException.class, () -> RsaOaep.encrypt(pair.getPublic(), new byte[max + 1], algorithm));
                assertArrayEquals(exact, independentOaepDecode((RSAPrivateKey) pair.getPrivate(), ciphertext, algorithm),
                        "독립 OAEP 디코더: 해시·MGF1 해시가 " + algorithm + "로 명시됨");
            }
        }
        // 문자열은 UTF-8 바이트로 센다: 한글 63자 = 189바이트(가능), 64자 = 192바이트(초과)
        char[] han = new char[63];
        Arrays.fill(han, '한');
        String ok = new String(han);
        for (Encoding encoding : new Encoding[] {Encoding.BASE64, Encoding.BASE64_URL, Encoding.HEX}) {
            String c = RsaOaep.encryptText(rsa2048.getPublic(), ok, encoding);
            assertEquals(ok, RsaOaep.decryptText(rsa2048.getPrivate(), c, encoding));
        }
        assertThrows(IllegalArgumentException.class, () -> RsaOaep.encryptText(rsa2048.getPublic(), ok + "한", Encoding.BASE64));
    }

    @Test
    void oaepFailuresAreUniformAndRejectWrongKeys() throws Exception {
        byte[] secret = "dummy-데이터-키".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = RsaOaep.encrypt(rsa2048.getPublic(), secret);
        assertEquals(Reason.INTEGRITY, reason(() -> RsaOaep.decrypt(other.getPrivate(), ciphertext)), "다른 개인키");
        assertEquals(Reason.INTEGRITY, reason(() -> RsaOaep.decrypt(rsa2048.getPrivate(), ciphertext, RsaOaepAlgorithm.SHA512)), "매개변수 불일치");
        byte[] tampered = ciphertext.clone();
        tampered[10] ^= 1;
        assertEquals(Reason.INTEGRITY, reason(() -> RsaOaep.decrypt(rsa2048.getPrivate(), tampered)));
        assertEquals(Reason.INVALID_TOKEN, reason(() -> RsaOaep.decrypt(rsa2048.getPrivate(), Arrays.copyOf(ciphertext, 255))));
        assertEquals(Reason.INVALID_TOKEN, reason(() -> RsaOaep.decryptText(rsa2048.getPrivate(), "not base64!", Encoding.BASE64)));
        CredentialCryptoException e = assertThrows(CredentialCryptoException.class, () -> RsaOaep.decrypt(other.getPrivate(), ciphertext));
        assertFalse(e.getMessage().contains("dummy"), "평문·키가 문구에 없음");
        KeyPairGenerator small = KeyPairGenerator.getInstance("RSA");
        small.initialize(1024);
        KeyPair weak = small.generateKeyPair();
        assertThrows(IllegalArgumentException.class, () -> RsaOaep.encrypt(weak.getPublic(), secret));
        KeyPair ec = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256);
        assertThrows(IllegalArgumentException.class, () -> RsaOaep.encrypt(ec.getPublic(), secret));
        assertThrows(IllegalArgumentException.class, () -> RsaOaep.decrypt(ec.getPrivate(), ciphertext));
    }

    @Test
    void hybridRoundTripsLargeDataWithFreshKeysAndDocumentedLayout() throws Exception {
        byte[] big = new byte[1024 * 1024 + 3];
        new java.util.Random(1).nextBytes(big);
        byte[] envelope = HybridEncryption.encrypt(rsa2048.getPublic(), big);
        assertArrayEquals(big, HybridEncryption.decrypt(rsa2048.getPrivate(), envelope));
        // 배치: JCKH | 1 | 1 | N=256 | DEK(256) | IV(12) | 암호문+태그
        assertArrayEquals(new byte[] {'J', 'C', 'K', 'H', 1, 1, 1, 0}, Arrays.copyOf(envelope, 8));
        assertEquals(8 + 256 + 12 + big.length + 16, envelope.length);
        byte[] again = HybridEncryption.encrypt(rsa2048.getPublic(), big);
        assertFalse(Arrays.equals(Arrays.copyOfRange(envelope, 8, 264), Arrays.copyOfRange(again, 8, 264)), "메시지마다 새 DEK");
        assertFalse(Arrays.equals(Arrays.copyOfRange(envelope, 264, 276), Arrays.copyOfRange(again, 264, 276)), "메시지마다 새 IV");
        byte[] envelope3072 = HybridEncryption.encrypt(rsa3072.getPublic(), new byte[0]);
        assertEquals(384 >> 8, envelope3072[6]);
        assertEquals((byte) (384 & 0xff), envelope3072[7]);
        assertArrayEquals(new byte[0], HybridEncryption.decrypt(rsa3072.getPrivate(), envelope3072));
        for (Encoding encoding : new Encoding[] {Encoding.BASE64, Encoding.BASE64_URL, Encoding.HEX}) {
            String text = HybridEncryption.encryptText(rsa2048.getPublic(), "dummy-주문-메시지", "order:7", encoding);
            assertEquals("dummy-주문-메시지", HybridEncryption.decryptText(rsa2048.getPrivate(), text, "order:7", encoding));
        }
        assertThrows(IllegalArgumentException.class, () -> HybridEncryption.encrypt(rsa2048.getPublic(), new byte[HybridEncryption.MAX_PLAINTEXT_BYTES + 1]));
    }

    @Test
    void hybridRejectsTamperingWrongKeysAadAndMalformedEnvelopes() throws Exception {
        byte[] aad = "customer:42".getBytes(StandardCharsets.UTF_8);
        byte[] envelope = HybridEncryption.encrypt(rsa2048.getPublic(), "dummy-기밀".getBytes(StandardCharsets.UTF_8), aad);
        assertEquals(Reason.INTEGRITY, reason(() -> HybridEncryption.decrypt(other.getPrivate(), envelope, aad)), "다른 개인키");
        assertEquals(Reason.INTEGRITY, reason(() -> HybridEncryption.decrypt(rsa3072.getPrivate(), envelope, aad)), "크기가 다른 개인키");
        assertEquals(Reason.INTEGRITY, reason(() -> HybridEncryption.decrypt(rsa2048.getPrivate(), envelope)), "AAD 없이");
        assertEquals(Reason.INTEGRITY, reason(() -> HybridEncryption.decrypt(rsa2048.getPrivate(), envelope, "customer:43".getBytes(StandardCharsets.UTF_8))));
        int[] integrityOffsets = {8, 100, 263, 264, 275, 276, envelope.length - 1};   // DEK·IV·본문·태그
        for (int offset : integrityOffsets) {
            byte[] t = envelope.clone();
            t[offset] ^= 1;
            assertEquals(Reason.INTEGRITY, reason(() -> HybridEncryption.decrypt(rsa2048.getPrivate(), t, aad)), "offset " + offset);
        }
        int[] formatOffsets = {0, 3, 4, 5};   // magic·버전·suite
        for (int offset : formatOffsets) {
            byte[] t = envelope.clone();
            t[offset] ^= 1;
            assertEquals(Reason.INVALID_TOKEN, reason(() -> HybridEncryption.decrypt(rsa2048.getPrivate(), t, aad)), "offset " + offset);
        }
        byte[] badLength = envelope.clone();
        badLength[6] = 0x7f;
        assertEquals(Reason.INVALID_TOKEN, reason(() -> HybridEncryption.decrypt(rsa2048.getPrivate(), badLength, aad)), "길이 범위 밖");
        byte[] shortLength = envelope.clone();
        shortLength[7] = (byte) 0xff;
        assertEquals(Reason.INVALID_TOKEN, reason(() -> HybridEncryption.decrypt(rsa2048.getPrivate(), shortLength, aad)), "길이 변조");
        assertEquals(Reason.INTEGRITY, reason(() -> HybridEncryption.decrypt(rsa2048.getPrivate(), Arrays.copyOf(envelope, envelope.length - 1), aad)), "잘림");
        assertEquals(Reason.INTEGRITY, reason(() -> HybridEncryption.decrypt(rsa2048.getPrivate(), Arrays.copyOf(envelope, envelope.length + 1), aad)), "덧붙임");
        assertEquals(Reason.INVALID_TOKEN, reason(() -> HybridEncryption.decrypt(rsa2048.getPrivate(), Arrays.copyOf(envelope, 100), aad)), "너무 짧음");
        assertEquals(Reason.INVALID_TOKEN, reason(() -> HybridEncryption.decryptText(rsa2048.getPrivate(), "AA==", Encoding.BASE64)));
    }

    @Test
    void envelopeAssembledIndependentlyFromTheDocumentedLayoutDecrypts() throws Exception {
        byte[] plain = "dummy-독립-조립".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "doc:1".getBytes(StandardCharsets.UTF_8);
        byte[] dek = new byte[32];
        new java.security.SecureRandom().nextBytes(dek);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, rsa2048.getPublic(),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] wrapped = rsa.doFinal(dek);
        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);
        byte[] header = ByteBuffer.allocate(8 + wrapped.length + 12).put(new byte[] {'J', 'C', 'K', 'H', 1, 1})
                .putShort((short) wrapped.length).put(wrapped).put(iv).array();
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, iv));
        gcm.updateAAD(ByteBuffer.allocate(header.length + 4 + aad.length).put(header).putInt(aad.length).put(aad).array());
        byte[] body = gcm.doFinal(plain);
        byte[] envelope = ByteBuffer.allocate(header.length + body.length).put(header).put(body).array();
        assertArrayEquals(plain, HybridEncryption.decrypt(rsa2048.getPrivate(), envelope, aad));
        assertTrue(HybridEncryption.decryptText(rsa2048.getPrivate(), Encoding.BASE64.encode(envelope), "doc:1", Encoding.BASE64).startsWith("dummy"));
    }

    /** JCA를 거치지 않는 OAEP 디코딩(RFC 8017 7.1.2): 원시 RSA 복호화 후 지정한 해시로 MGF1·lHash를 다시 계산한다. */
    private static byte[] independentOaepDecode(RSAPrivateKey key, byte[] ciphertext, RsaOaepAlgorithm algorithm) throws Exception {
        String hashName = algorithm == RsaOaepAlgorithm.SHA256 ? "SHA-256" : "SHA-512";
        int k = (key.getModulus().bitLength() + 7) / 8;
        int h = algorithm.hashLength();
        BigInteger m = new BigInteger(1, ciphertext).modPow(key.getPrivateExponent(), key.getModulus());
        byte[] em = new byte[k];
        byte[] raw = m.toByteArray();
        System.arraycopy(raw, Math.max(0, raw.length - k), em, k - Math.min(k, raw.length), Math.min(k, raw.length));
        assertEquals(0, em[0]);
        byte[] maskedSeed = Arrays.copyOfRange(em, 1, 1 + h);
        byte[] maskedDb = Arrays.copyOfRange(em, 1 + h, k);
        byte[] seed = xor(maskedSeed, mgf1(hashName, maskedDb, h));
        byte[] db = xor(maskedDb, mgf1(hashName, seed, k - h - 1));
        assertArrayEquals(MessageDigest.getInstance(hashName).digest(new byte[0]), Arrays.copyOf(db, h), "lHash(빈 label)");
        int i = h;
        while (db[i] == 0) i++;
        assertEquals(1, db[i]);
        return Arrays.copyOfRange(db, i + 1, db.length);
    }

    private static byte[] mgf1(String hashName, byte[] seed, int length) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(hashName);
        byte[] out = new byte[length];
        int filled = 0;
        for (int counter = 0; filled < length; counter++) {
            digest.update(seed);
            digest.update(ByteBuffer.allocate(4).putInt(counter).array());
            byte[] block = digest.digest();
            int n = Math.min(block.length, length - filled);
            System.arraycopy(block, 0, out, filled, n);
            filled += n;
        }
        return out;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }
}
