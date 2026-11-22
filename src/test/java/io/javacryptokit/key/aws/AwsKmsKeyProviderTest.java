package io.javacryptokit.key.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.key.KeyResolver;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.ServiceLoader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * AWS KMS Envelope Encryption 키 공급원(모의 KMS + 실제 AWS SDK 2.x 클라이언트). 실제 AWS를 호출하지 않으므로 실제 KMS 연동
 * 검증이 아니다(계약·모의 테스트).
 */
class AwsKmsKeyProviderTest {
    @TempDir
    Path dir;
    private MockKms kms;

    @BeforeEach
    void start() throws Exception {
        kms = new MockKms();
        kms.install();
    }

    @AfterEach
    void stop() {
        kms.close();
    }

    private CryptoSettings settings(String keyId, String kmsKey, Path dataKey) throws Exception {
        return TestSupport.isolatedSettings(TestSupport.writeConfig(dir, "kms-" + System.nanoTime() + ".properties",
                "crypto.key.source=aws-kms", "crypto.key.id=" + keyId, "crypto.aws.region=us-east-1",
                "crypto.aws.kms.key.id=" + kmsKey,
                "crypto.aws.kms.data-key.file=" + (dataKey == null ? "" : TestSupport.propertiesPath(dataKey))));
    }

    private Path createDataKey(String keyId) throws Exception {
        AwsKmsKeyProvider.DataKey dataKey = AwsKmsKeyProvider.generate(settings(keyId, "alias/test", null));
        assertEquals(32, dataKey.plaintext.length);
        dataKey.wipe();
        Path file = dir.resolve(keyId + ".datakey");
        Files.write(file, (Base64.getEncoder().encodeToString(dataKey.ciphertextBlob) + "\n").getBytes(StandardCharsets.US_ASCII));
        return file;
    }

    @Test
    void exactlyOneSdkHttpClientIsOnTheClasspath() {
        // 기본 자격증명 체계의 STS(웹 ID·역할 전환)처럼 SDK가 내부에서 직접 만드는 클라이언트는 HTTP 구현을 클래스패스에서 고른다.
        // 구현이 둘 이상이면 SDK가 "Multiple HTTP implementations" 오류를 내므로 url-connection-client 하나만 있어야 한다
        // (build.gradle의 apache-client·apache5-client·netty 제외가 테스트·KMS 묶음에 같이 적용됨).
        List<String> found = new ArrayList<>();
        for (software.amazon.awssdk.http.SdkHttpService service : ServiceLoader.load(software.amazon.awssdk.http.SdkHttpService.class)) {
            found.add(service.getClass().getName());
        }
        assertEquals(1, found.size(), "HTTP 클라이언트 구현: " + found);
        assertTrue(found.get(0).contains("UrlConnection"), "HTTP 클라이언트 구현: " + found);
    }

    @Test
    void dataKeyIsCreatedOnceStoredAndRestoredWithTheSameKeyEveryTime() throws Exception {
        Path dataKey = createDataKey("prod01");
        CryptoService first = CryptoService.of(settings("prod01", "alias/test", dataKey));
        String token = first.encryptText("dummy-db-pw".toCharArray());
        String fingerprint = first.keyFingerprint();
        int decryptsBefore = count("TrentService.Decrypt");
        assertEquals("dummy-db-pw", first.decryptText(token));
        assertEquals(decryptsBefore, count("TrentService.Decrypt"), "서비스 인스턴스당 한 번만 복원(연결마다 KMS 호출 안 함)");
        // WAS 재시작 = 새 서비스: 같은 데이터 키 파일에서 같은 키를 복원해 기존 암호문을 그대로 복호화한다.
        CryptoService restarted = CryptoService.of(settings("prod01", "alias/test", dataKey));
        assertEquals(fingerprint, restarted.keyFingerprint());
        assertEquals("dummy-db-pw", restarted.decryptText(token));
        assertEquals(0, count("TrentService.GenerateDataKey") - 1, "시작할 때 새 데이터 키를 만들지 않는다");
        String decrypt = last("TrentService.Decrypt");
        assertTrue(decrypt.contains("\"KeyId\":\"alias/test\""), decrypt);
        assertTrue(decrypt.contains("\"java-crypto-kit:key-id\":\"prod01\""), "Encryption Context: " + decrypt);
        String authorization = kms.authorizations.get(kms.authorizations.size() - 1);
        assertTrue(authorization.startsWith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
                && authorization.contains("/us-east-1/kms/aws4_request"), "SDK SigV4 서명: " + authorization);
    }

    @Test
    void wrappingAnExistingKeyKeepsTheFingerprintAndExistingCiphertext() throws Exception {
        byte[] existing = new byte[32];
        new java.security.SecureRandom().nextBytes(existing);
        byte[] blob = AwsKmsKeyProvider.wrap(settings("prod01", "alias/test", null), existing);
        Path file = Files.write(dir.resolve("wrapped.datakey"), Base64.getEncoder().encode(blob));
        assertEquals(KeyResolver.fingerprint(existing), CryptoService.of(settings("prod01", "alias/test", file)).keyFingerprint());
    }

    @Test
    void kmsErrorsAreClassifiedWithoutLeakingDetailsAndNeverFallBack() throws Exception {
        Path dataKey = createDataKey("prod01");
        assertTrue(failure(settings("prod01", "alias/other", dataKey)).contains("IncorrectKeyException"), "다른 KMS 키");
        assertTrue(failure(settings("prod02", "alias/test", dataKey)).contains("InvalidCiphertextException"),
                "Encryption Context(키ID) 불일치");
        assertTrue(failure(settings("prod01", "alias/unknown", dataKey)).contains("NotFoundException"));
        kms.forcedError = "AccessDeniedException";
        String denied = failure(settings("prod01", "alias/test", dataKey));
        assertTrue(denied.contains("AccessDeniedException") && denied.contains("kms:Decrypt"), denied);
        assertFalse(denied.contains("secret-detail"), "SDK 오류 메시지를 출력하지 않는다");
        kms.forcedError = "KMSInternalException";
        assertTrue(failure(settings("prod01", "alias/test", dataKey)).contains("KMSInternalException"));
        kms.forcedError = null;
        int closed;
        try (ServerSocket socket = new ServerSocket(0)) {
            closed = socket.getLocalPort();
        }
        MockKms.installUnreachable(closed);
        assertTrue(failure(settings("prod01", "alias/test", dataKey)).contains("AWS KMS"), "네트워크 장애");
    }

    @Test
    void damagedOrMissingDataKeyFileFailsClosed() throws Exception {
        Path broken = Files.write(dir.resolve("broken.datakey"), "not base64 !!".getBytes(StandardCharsets.US_ASCII));
        assertTrue(failure(settings("prod01", "alias/test", broken)).contains("crypto.aws.kms.data-key.file"));
        CredentialCryptoException missing = assertThrows(CredentialCryptoException.class,
                () -> CryptoService.of(settings("prod01", "alias/test", dir.resolve("none.datakey"))).encryptText("x".toCharArray()));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, missing.getReason());
        CredentialCryptoException noFile = assertThrows(CredentialCryptoException.class,
                () -> CryptoService.of(settings("prod01", "alias/test", null)).encryptText("x".toCharArray()));
        assertTrue(noFile.getMessage().contains("crypto.aws.kms.data-key.file"), noFile.getMessage());
    }

    private String failure(CryptoSettings settings) {
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> CryptoService.of(settings).encryptText("x".toCharArray()));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason(), ex.getMessage());
        return ex.getMessage();
    }

    private int count(String target) {
        int n = 0;
        synchronized (kms.requests) {
            for (String request : kms.requests) if (request.startsWith(target + " ")) n++;
        }
        return n;
    }

    private String last(String target) {
        String found = "";
        synchronized (kms.requests) {
            for (String request : kms.requests) if (request.startsWith(target + " ")) found = request;
        }
        return found;
    }
}
