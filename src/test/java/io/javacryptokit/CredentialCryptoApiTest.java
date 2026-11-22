package io.javacryptokit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 공개 API {@link CredentialCrypto}의 텍스트·바이트·검증 기능과 정제된 실패 처리를 검증한다.
 */
class CredentialCryptoApiTest {
    @TempDir
    Path dir;

    private CredentialCrypto crypto;
    private Path keyFile;
    private Path fileConfig;

    @BeforeEach
    void setUp() throws Exception {
        keyFile = TestSupport.writeRandomKeyFile(dir, "api.key");
        fileConfig = TestSupport.writeConfig(dir, "api.properties", "crypto.key.source=file", "crypto.key.id=api01",
                "crypto.key.file=" + TestSupport.propertiesPath(keyFile), "crypto.warning.enabled=false");
        crypto = CredentialCrypto.fromConfigFile(fileConfig);
    }

    @Test
    void textRoundTripPreservesUnicodeAndUsesFreshIv() throws Exception {
        String value = "비밀번호:Ω!😀";
        String first = crypto.encryptText(value);
        String second = crypto.encryptText(value.toCharArray());
        assertNotEquals(first, second, "같은 값도 매번 다른 암호문(난수 IV)");
        assertEquals(value, crypto.decryptText(first));
        assertEquals(value, crypto.decryptText(second));
        assertEquals("api01", crypto.keyId());
        assertEquals("file", crypto.keySource());
    }

    @Test
    void bytesRoundTripPreservesArbitraryBytes() throws Exception {
        byte[] data = {0, (byte) 0xFF, (byte) 0xC3, 0x28, 1, 2, 3};
        String token = crypto.encryptBytes(data);
        assertArrayEquals(data, crypto.decryptBytes(token));
        assertTrue(crypto.verify(token));
        // 올바른 UTF-8이 아닌 바이너리를 텍스트로 꺼내려 하면 '?'로 바꾸지 않고 거부한다.
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> crypto.decryptText(token));
        assertEquals(CredentialCryptoException.Reason.INVALID_INPUT, ex.getReason());
    }

    @Test
    void verifyReturnsFalseOnlyForTokenProblems() throws Exception {
        String token = crypto.encryptText("dummy");
        assertTrue(crypto.verify(token));
        assertFalse(crypto.verify("not-a-token"));
        assertFalse(crypto.verify(token.replace("ENC[v1:api01:", "ENC[v1:other:")));
        assertFalse(crypto.verify(TestSupport.jarDefaults().encryptText("dummy")));
        // 키 공급원 자체의 문제는 "검증 실패"로 숨기지 않고 예외로 알린다.
        Files.delete(keyFile);
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> crypto.verify(token));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason());
    }

    @Test
    void distinguishesKeyIdMismatchAndIntegrityFailure() throws Exception {
        String token = crypto.encryptText("dummy");
        CredentialCrypto jarDefaults = TestSupport.jarDefaults();
        assertEquals(CredentialCryptoException.Reason.KEY_ID_MISMATCH,
                assertThrows(CredentialCryptoException.class, () -> jarDefaults.decryptText(token)).getReason());
        // 같은 키ID에 다른 키를 쓰면 인증 태그 검증에서 실패한다.
        Files.write(keyFile, Files.readAllBytes(TestSupport.writeRandomKeyFile(dir, "other.key")));
        assertEquals(CredentialCryptoException.Reason.INTEGRITY,
                assertThrows(CredentialCryptoException.class, () -> crypto.decryptText(token)).getReason());
    }

    @Test
    void rejectsEmptyAndOversizedInput() throws Exception {
        assertEquals(CredentialCryptoException.Reason.INVALID_INPUT,
                assertThrows(CredentialCryptoException.class, () -> crypto.encryptText("")).getReason());
        assertEquals(CredentialCryptoException.Reason.INVALID_INPUT,
                assertThrows(CredentialCryptoException.class, () -> crypto.encryptText((String) null)).getReason());
        assertEquals(CredentialCryptoException.Reason.INVALID_INPUT,
                assertThrows(CredentialCryptoException.class, () -> crypto.encryptBytes(new byte[0])).getReason());
        // 복호화할 수 없는 크기의 암호문은 처음부터 만들지 않는다.
        assertEquals(CredentialCryptoException.Reason.INVALID_INPUT,
                assertThrows(CredentialCryptoException.class, () -> crypto.encryptBytes(new byte[13000])).getReason());
        byte[] large = new byte[12000];
        assertArrayEquals(large, crypto.decryptBytes(crypto.encryptBytes(large)));
    }

    @Test
    void failuresDoNotCarryPathsCausesOrInput() throws Exception {
        Path secretDir = Files.createDirectory(dir.resolve("secret-dir-9f3a"));
        Path config = TestSupport.writeConfig(secretDir, "c.properties", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(secretDir.resolve("missing.key")));
        CredentialCrypto broken = CredentialCrypto.fromConfigFile(config);
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> broken.encryptText("dummy-pw-xyz"));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason());
        assertEquals("NoSuchFileException", ex.getCauseType());
        assertNull(ex.getCause(), "원래 예외(경로 포함)를 원인으로 붙이지 않는다");
        assertFalse(ex.getMessage().contains("secret-dir-9f3a"));
        assertFalse(ex.getMessage().contains("dummy-pw-xyz"));

        CredentialCryptoException missingConfig = assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(secretDir.resolve("none.properties")));
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION, missingConfig.getReason());
        assertFalse(missingConfig.getMessage().contains("secret-dir-9f3a"));
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION,
                assertThrows(CredentialCryptoException.class, () -> CredentialCrypto.fromConfigFile(null)).getReason());
    }

    @Test
    void instancesAreSafeToShareAcrossThreads() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                final int thread = t;
                results.add(pool.submit((Callable<Boolean>) () -> {
                    for (int i = 0; i < 50; i++) {
                        String value = "dummy-" + thread + "-" + i;
                        if (!value.equals(crypto.decryptText(crypto.encryptText(value)))) return false;
                    }
                    return true;
                }));
            }
            for (Future<Boolean> result : results) assertTrue(result.get());
        } finally {
            pool.shutdownNow();
        }
    }
}
