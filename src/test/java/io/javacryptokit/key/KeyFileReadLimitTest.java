package io.javacryptokit.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 키 파일 읽기 상한(QA-07) 검증: 크기를 미리 조회하지 않고 512바이트 + 1까지만 읽어, 큰 파일·폴더·잘못된 형식을
 * 내장 키로 바꾸지 않고 거부하는지 확인한다(키 내용은 메시지에 넣지 않는다).
 */
class KeyFileReadLimitTest {
    @TempDir
    Path dir;

    private CryptoSettings fileSettings(Path key) throws IOException {
        Path config = TestSupport.writeConfig(dir, "k.properties", "crypto.key.source=file", "crypto.key.id=lim01",
                "crypto.key.file=" + TestSupport.propertiesPath(key));
        return TestSupport.isolatedSettings(config);
    }

    @Test
    void oversizedKeyFileIsRejectedWithClearMessage() throws Exception {
        Path big = dir.resolve("big.key");
        byte[] content = new byte[2 * 1024 * 1024];
        Arrays.fill(content, (byte) 'A');
        Files.write(big, content);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> KeyResolver.resolve(fileSettings(big)));
        assertTrue(ex.getMessage().contains("512바이트"), ex.getMessage());
    }

    @Test
    void keyFileOfExactlyTheLimitIsReadAndThenValidated() throws Exception {
        Path padded = dir.resolve("padded.key");
        String key = TestSupport.managedSettings()[0].split("=", 2)[1];
        StringBuilder text = new StringBuilder(key).append("\r\n");
        while (text.length() < 512) text.append(' ');
        Files.write(padded, text.toString().getBytes(StandardCharsets.US_ASCII));
        assertEquals(512, Files.size(padded));
        byte[] resolved = KeyResolver.resolve(fileSettings(padded));
        assertEquals(32, resolved.length, "앞뒤 공백·CRLF는 무시하고 읽는다");
        Arrays.fill(resolved, (byte) 0);
    }

    @Test
    void directoryInsteadOfKeyFileFailsClosed() throws Exception {
        Path folder = Files.createDirectory(dir.resolve("folder.key"));
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> KeyResolver.resolve(fileSettings(folder)));
        assertTrue(ex.getMessage().contains("일반 파일"), ex.getMessage());
    }

    @Test
    void endlessDeviceFileIsRejectedBeforeReading() throws Exception {
        // Linux·macOS에서만 의미가 있다(Windows에는 /dev/zero가 없음). 크기 상한 읽기 이전에 일반 파일 검사로 거부한다.
        Path zero = java.nio.file.Paths.get("/dev/zero");
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.exists(zero), "POSIX 장치 파일이 있는 환경에서만 실행");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> KeyResolver.resolve(fileSettings(zero)));
        assertTrue(ex.getMessage().contains("일반 파일"), ex.getMessage());
    }

    @Test
    void symbolicLinkToARegularKeyFileIsAccepted() throws Exception {
        // Kubernetes Secret·systemd credential 마운트처럼 링크로 공급되는 키 파일은 허용한다.
        Path target = TestSupport.writeRandomKeyFile(dir, "target.key");
        Path link = dir.resolve("link.key");
        try {
            Files.createSymbolicLink(link, target);
        } catch (UnsupportedOperationException | IOException | SecurityException e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "심볼릭 링크를 만들 수 없는 환경(Windows 일반 권한 등)");
        }
        byte[] resolved = KeyResolver.resolve(fileSettings(link));
        assertEquals(32, resolved.length);
        Arrays.fill(resolved, (byte) 0);
    }

    @Test
    void emptyFilePathNamesTheSettingToFix() throws Exception {
        Path config = TestSupport.writeConfig(dir, "empty.properties", "crypto.key.source=file", "crypto.key.file=");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> KeyResolver.resolve(TestSupport.isolatedSettings(config)));
        assertTrue(ex.getMessage().contains("crypto.key.file"), ex.getMessage());
    }
}
