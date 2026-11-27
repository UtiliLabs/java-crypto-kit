package example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCrypto;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/**
 * 사용자 가이드 6.7절 예제({@link DirectKeyExample})가 라이브러리 패키지 밖에서 공개 API만으로 실제 동작하는지 확인한다.
 */
class DirectKeyExampleTest {
    private static byte[] key() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    @Test
    void rawKeyExampleRoundTrips() throws Exception {
        assertEquals("dummy-예제-값", DirectKeyExample.rawKeyRoundTrip(key(), "dummy-예제-값"));
    }

    @Test
    void passphraseExampleDecryptsAfterRestartOnlyWithTheSameValues() throws Exception {
        byte[] salt = DirectKeyExample.newSalt();
        String token = DirectKeyExample.encryptWithPassphrase("dummy-example-pass".toCharArray(), salt, "dummy-secret");
        assertTrue(token.startsWith("ENC[v1:app-pass-01:"), token);
        assertEquals("dummy-secret", DirectKeyExample.decryptAfterRestart("dummy-example-pass".toCharArray(), salt.clone(), token));
        CredentialCrypto wrongSalt = CredentialCrypto.fromPassphrase("app-pass-01", "dummy-example-pass".toCharArray(),
                DirectKeyExample.newSalt(), DirectKeyExample.ITERATIONS);
        assertEquals("키·Passphrase·Salt·반복 횟수가 암호화할 때와 다르거나 암호문이 변조됨",
                DirectKeyExample.describeFailure(wrongSalt, token));
        assertEquals("다른 Key ID의 암호문", DirectKeyExample.describeFailure(CredentialCrypto.fromRawKey("other", key()), token));
    }

    @Test
    void separateKeysAndTheManagedKeysWorkSideBySide() throws Exception {
        assumeTrue(System.getenv("CRYPTO_CONFIG_FILE") == null && System.getProperty("crypto.config.file") == null);
        try (AutoCloseable ignored = io.javacryptokit.TestSupport.systemProperty("crypto.config.file",
                io.javacryptokit.TestSupport.managedConfig().toString())) {
            assertTrue(DirectKeyExample.separateKeys(key(), key()));
        }
    }

    @Test
    void callerMayWipeItsKeyArray() throws Exception {
        assertTrue(DirectKeyExample.wipeCallerKey(key()));
    }
}
