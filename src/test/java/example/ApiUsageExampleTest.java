package example;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * README의 Java API 예제({@link ApiUsageExample})가 라이브러리 패키지 밖에서 공개 API만으로 실제 동작하는지 확인한다.
 */
class ApiUsageExampleTest {
    @TempDir
    Path dir;

    private Path fileKeyConfig() throws Exception {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        Path keyFile = dir.resolve("example.key");
        Files.write(keyFile, (Base64.getEncoder().encodeToString(key) + "\n").getBytes(StandardCharsets.US_ASCII));
        Path config = dir.resolve("example.properties");
        String path = keyFile.toAbsolutePath().toString().replace('\\', '/');
        Files.write(config, ("crypto.key.source=file\ncrypto.key.id=example01\ncrypto.key.file=" + path
                + "\ncrypto.warning.enabled=false\n").getBytes(StandardCharsets.UTF_8));
        return config;
    }

    @Test
    void textExampleWorksFromOutsideThePackage() throws Exception {
        assertEquals("dummy-api-값", ApiUsageExample.roundTrip(fileKeyConfig(), "dummy-api-값"));
    }

    @Test
    void binaryExampleKeepsBytes() throws Exception {
        byte[] data = {0, 1, (byte) 0xFE, (byte) 0xFF};
        assertArrayEquals(data, ApiUsageExample.binaryRoundTrip(fileKeyConfig(), data));
    }

    @Test
    void failureReasonsAreDistinguishable() throws Exception {
        Path config = fileKeyConfig();
        assertEquals("암호문 형식 오류", ApiUsageExample.describeFailure(config, "not-a-token"));
        assertEquals("키ID 불일치", ApiUsageExample.describeFailure(config,
                "ENC[v1:default:fiwaaeeeILgco85o:-uFGHK3H0eqZKIfj3MZhRG3cr9gLeQCjYJ7UHFdWCg4f4982fNx8]"));
    }
}
