package io.javacryptokit;

import io.javacryptokit.core.TokenCodec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * 서로 다른 기능을 혼동하지 않는지(AGENTS.md 품질 게이트의 경계)를 고정하는 회귀 테스트.
 */
class BoundaryRegressionTest {
    @TempDir
    Path dir;

    /** 경고 OFF는 보안 검사 OFF가 아니다: 변조·키 누락은 그대로 실패한다. */
    @Test
    void warningOffIsNotSecurityOff() throws Exception {
        Path quiet = TestSupport.writeConfig(dir, "quiet.properties", "crypto.key.source=embedded",
                "crypto.warning.enabled=false");
        CredentialCrypto crypto = CredentialCrypto.fromConfigFile(quiet);
        String token = crypto.encryptText("dummy");
        String tampered = token.substring(0, token.length() - 3)
                + (token.charAt(token.length() - 3) == 'A' ? 'B' : 'A') + token.substring(token.length() - 2);
        assertEquals(CredentialCryptoException.Reason.INTEGRITY,
                assertThrows(CredentialCryptoException.class, () -> crypto.decryptText(tampered)).getReason());
        Path missing = TestSupport.writeConfig(dir, "quiet-missing.properties", "crypto.key.type=key", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(dir.resolve("gone.key")), "crypto.warning.enabled=false");
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(missing).encryptText("dummy")).getReason());
    }

    /** 외부 Properties 사용은 외부 키 강제가 아니다: 외부 파일에서 embedded를 선택할 수 있다. */
    @Test
    void externalPropertiesDoNotForceExternalKey() throws Exception {
        Path config = TestSupport.writeConfig(dir, "embedded.properties", "crypto.key.source=embedded");
        CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
        assertEquals("embedded", crypto.keySource());
        assertEquals("dummy", crypto.decryptText(crypto.encryptText("dummy")));
    }

    /** 키를 바꿀 수 있다는 것은 자동 교체가 아니다: 다른 키·키ID로는 기존 암호문이 복호화되지 않는다. */
    @Test
    void dynamicKeyIsNotAutomaticRotation() throws Exception {
        Path key = TestSupport.writeRandomKeyFile(dir, "old.key");
        Path oldConfig = TestSupport.writeConfig(dir, "old.properties", "crypto.key.type=key", "crypto.key.source=file",
                "crypto.key.id=prod01",
                "crypto.key.file=" + TestSupport.propertiesPath(key));
        String oldToken = CredentialCrypto.fromConfigFile(oldConfig).encryptText("dummy");
        // 같은 키ID에 새 키 값 → 무결성 실패
        Files.write(key, Files.readAllBytes(TestSupport.writeRandomKeyFile(dir, "new.key")));
        assertEquals(CredentialCryptoException.Reason.INTEGRITY, assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(oldConfig).decryptText(oldToken)).getReason());
        // 새 키ID → 키ID 불일치
        Path newConfig = TestSupport.writeConfig(dir, "new.properties", "crypto.key.type=key", "crypto.key.source=file",
                "crypto.key.id=prod02",
                "crypto.key.file=" + TestSupport.propertiesPath(key));
        assertEquals(CredentialCryptoException.Reason.KEY_ID_MISMATCH, assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(newConfig).decryptText(oldToken)).getReason());
    }

    /** Base64 선택은 알고리즘 선택이 아니다: B64 포장 안은 언제나 같은 v1 AES-256-GCM 봉투다. */
    @Test
    void base64OptionIsNotAlgorithmChoice() throws Exception {
        Path config = TestSupport.writeConfig(dir, "b64.properties", "crypto.output.encoding=base64");
        CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
        String token = crypto.encryptText("dummy");
        assertTrue(TokenCodec.toEnvelope(token).startsWith("ENC[v1:"));
        assertEquals("AES/GCM/NoPadding", TestSupport.isolatedSettings(config).get("crypto.algorithm"));
    }

    /** 알고리즘 항목이 있다고 임의 알고리즘을 쓸 수 있는 것은 아니다. */
    @ParameterizedTest(name = "알고리즘 {0} 거부")
    @ValueSource(strings = {"AES/CBC/PKCS5Padding", "AES/ECB/PKCS5Padding", "DES/CBC/PKCS5Padding",
            "AES/GCM/PKCS5Padding", "aes/gcm/nopadding", ""})
    void algorithmPropertyDoesNotAllowArbitraryAlgorithms(String algorithm) throws Exception {
        Path config = TestSupport.writeConfig(dir, "alg.properties", "crypto.algorithm=" + algorithm);
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION, assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(config)).getReason());
    }
}
