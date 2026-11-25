package example;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.TestKeytool;
import io.javacryptokit.security.AesGcm;
import io.javacryptokit.security.AesKeySize;
import io.javacryptokit.security.Digests;
import io.javacryptokit.security.Hmac;
import io.javacryptokit.security.Passwords;
import io.javacryptokit.security.Pbkdf2;
import io.javacryptokit.security.Pbkdf2Algorithm;
import io.javacryptokit.security.RequestAuth;
import io.javacryptokit.security.Signatures;
import io.javacryptokit.security.Totp;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 사용자 가이드 13장 예제({@link SecurityApiExample})가 라이브러리 패키지 밖에서 공개 API만으로 실제 동작하는지 JDK 8·21에서 확인한다.
 */
class SecurityApiExampleTest {
    @TempDir
    Path dir;

    @Test
    void encryptionExamples() throws Exception {
        assertEquals("dummy-4111-1111", SecurityApiExample.aesGcmWithAad(AesGcm.generateKey(AesKeySize.AES_256), "C-1", "dummy-4111-1111"));
        byte[] data = "dummy-바이트".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(data, SecurityApiExample.aesGcmFromPassphrase("dummy-pass".toCharArray(), Pbkdf2.newSalt(), data));
        KeyPair recipient = Signatures.generateRsaKeyPair(2048);
        byte[] dataKey = AesGcm.generateKey(AesKeySize.AES_256);
        assertArrayEquals(dataKey, SecurityApiExample.protectDataKey(recipient.getPublic(), recipient.getPrivate(), dataKey));
        StringBuilder big = new StringBuilder();
        for (int i = 0; i < 2000; i++) big.append("{\"order\":").append(i).append("},");
        assertEquals(big.toString(), SecurityApiExample.sendToPartner(recipient.getPublic(), recipient.getPrivate(), big.toString()));
    }

    @Test
    void macRandomDigestPasswordAndKeyExamples() throws Exception {
        byte[] secret = "dummy-webhook-secret".getBytes(StandardCharsets.UTF_8);
        byte[] body = "{\"event\":\"paid\"}".getBytes(StandardCharsets.UTF_8);
        String header = "sha256=" + Hmac.ofExternalKey(io.javacryptokit.security.HmacAlgorithm.SHA256, secret).sign(body, io.javacryptokit.security.Encoding.HEX);
        assertTrue(SecurityApiExample.verifyWebhook(secret, body, header));
        assertFalse(SecurityApiExample.verifyWebhook(secret, "{}".getBytes(StandardCharsets.UTF_8), header));
        assertTrue(SecurityApiExample.macRoundTrip("dummy-message"));
        assertEquals(RequestAuth.Result.VALID, SecurityApiExample.requestAuth(Hmac.generateKey(), "POST", "/orders", body));
        String[] random = SecurityApiExample.randomValues();
        assertEquals(43, random[0].length());
        assertEquals(64, random[1].length());
        assertEquals(36, random[2].length());
        assertTrue(random[3].matches("R-[0-9]{6}"));
        Path file = Files.write(dir.resolve("release.zip"), body);
        assertTrue(SecurityApiExample.fileMatches(file, Digests.sha256Hex(body)));
        String stored = SecurityApiExample.register("dummy-pw-1".toCharArray());
        assertEquals("true", SecurityApiExample.login("dummy-pw-1".toCharArray(), stored)[0]);
        assertNull(SecurityApiExample.login("dummy-pw-1".toCharArray(), stored)[1], "기본 정책이면 재해시 불필요");
        String old = Passwords.hash("dummy-pw-1".toCharArray(), Pbkdf2Algorithm.SHA256, 100_000);
        assertNotNull(SecurityApiExample.login("dummy-pw-1".toCharArray(), old)[1], "약한 저장값은 재해시");
        assertEquals("false", SecurityApiExample.login("wrong".toCharArray(), stored)[0]);
        byte[][] keys = SecurityApiExample.splitKeys(Hmac.generateKey(), Pbkdf2.newSalt());
        assertFalse(java.util.Arrays.equals(keys[0], keys[1]));
        assertTrue(SecurityApiExample.encodingAndCompare("token-a", "token-a"));
        assertFalse(SecurityApiExample.encodingAndCompare("token-a", null));
    }

    @Test
    void signatureCertificateOtpAndKeyStoreExamples() throws Exception {
        Path doc = Files.write(dir.resolve("contract.pdf"), new byte[200_000]);
        assertTrue(SecurityApiExample.signFile(doc));
        TestKeytool.caAndServer(dir, "dns:localhost");
        assertTrue(SecurityApiExample.daysLeft(dir.resolve("server.pem"), dir.resolve("ca.pem")) >= 363);
        byte[] otpSecret = Totp.generateSecret();
        String code = Totp.of(otpSecret).generate(Instant.now());
        assertTrue(SecurityApiExample.totp(otpSecret, code).isPresent());
        assertFalse(SecurityApiExample.totp(otpSecret, "000000".equals(code) ? "111111" : "000000").isPresent());
        TestKeytool.run(dir, "-genkeypair", "-alias", "signer", "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA",
                "-dname", "CN=signer", "-validity", "30", "-storetype", "PKCS12", "-storepass", TestKeytool.STORE_PASS,
                "-keypass", TestKeytool.STORE_PASS, "-keystore", "signing.p12");
        byte[] before = Files.readAllBytes(dir.resolve("signing.p12"));
        assertTrue(SecurityApiExample.signWithKeyStore(dir.resolve("signing.p12"), TestKeytool.STORE_PASS.toCharArray(),
                TestKeytool.STORE_PASS.toCharArray(), "dummy-document".getBytes(StandardCharsets.UTF_8)));
        assertArrayEquals(before, Files.readAllBytes(dir.resolve("signing.p12")));
    }
}
