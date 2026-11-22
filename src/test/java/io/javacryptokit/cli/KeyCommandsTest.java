package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.TestSupport;
import io.javacryptokit.key.KeyResolver;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** fingerprint·rekey: 키 원문·평문 미노출, 같은/다른 키 판별, 독립된 이전·신규 설정, 오류 처리. */
class KeyCommandsTest {
    @TempDir
    Path dir;
    private CliHarness cli;

    @BeforeEach
    void setUp() {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        cli = new CliHarness();
    }

    @AfterEach
    void tearDown() throws Exception {
        cli.close();
    }

    private Path fileConfig(String name, String keyId, Path key) throws Exception {
        return TestSupport.writeConfig(dir, name, "crypto.key.source=file", "crypto.key.id=" + keyId,
                "crypto.key.file=" + TestSupport.propertiesPath(key));
    }

    private String fingerprintOf(String... args) {
        assertEquals(0, cli.run(args), cli.err());
        for (String line : cli.out().split("\\r?\\n")) {
            if (line.contains("SHA-256")) return line.substring(line.lastIndexOf(' ') + 1);
        }
        throw new AssertionError(cli.out());
    }

    @Test
    void fingerprintIsStableDistinguishesKeysAndNeverShowsTheKey() throws Exception {
        // 고정 키의 고정 지문: OS·JDK와 무관하게 같아야 한다(Windows·Linux 교차 비교의 기준값).
        byte[] fixed = new byte[32];
        for (int i = 0; i < 32; i++) fixed[i] = (byte) i;
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        md.update("java-crypto-kit/key-fingerprint/v1\0".getBytes(StandardCharsets.US_ASCII));
        StringBuilder expected = new StringBuilder();
        for (byte value : md.digest(fixed)) expected.append(String.format("%02x", value));
        String fixedPrint = KeyResolver.fingerprint(fixed);
        assertEquals(expected.toString(), fixedPrint, "문서에 적은 계산식(SHA-256(라벨||0x00||키))과 같아야 한다");
        Path fixedFile = TestSupport.writeKeyFile(dir, "fixed.key", Base64.getEncoder().encodeToString(fixed));
        assertEquals(fixedPrint, fingerprintOf("fingerprint", "--key-file", fixedFile.toString()));

        Path a = TestSupport.writeRandomKeyFile(dir, "a.key");
        Path b = TestSupport.writeRandomKeyFile(dir, "b.key");
        String printA = fingerprintOf("fingerprint", "--key-file", a.toString());
        String printA2 = fingerprintOf("fingerprint", "--config", fileConfig("a.properties", "a01", a).toString());
        String printB = fingerprintOf("fingerprint", "--key-file", b.toString());
        assertEquals(printA, printA2, "같은 키(파일 vs 설정)는 같은 지문");
        assertNotEquals(printA, printB, "다른 키는 다른 지문");
        String keyText = new String(Files.readAllBytes(a), StandardCharsets.US_ASCII).trim();
        assertFalse(cli.out().contains(keyText));
        assertTrue(cli.out().contains("인증") , "지문은 인증 수단이 아님을 안내: " + cli.out());
        // 기본 공개 키는 경고
        assertEquals(0, cli.run("fingerprint"));
        assertTrue(cli.out().contains("[WARN]"), cli.out());
        assertEquals(1, cli.run("fingerprint", "--key-file", a.toString(), "--config", "x.properties"));
    }

    @Test
    void rekeyMovesCiphertextToTheNewKeyWithoutShowingPlaintext() throws Exception {
        Path oldKey = TestSupport.writeRandomKeyFile(dir, "old.key");
        Path newKey = TestSupport.writeRandomKeyFile(dir, "new.key");
        Path oldConfig = fileConfig("old.properties", "prod01", oldKey);
        Path newConfig = fileConfig("new.properties", "prod02", newKey);
        String oldToken = CredentialCrypto.fromConfigFile(oldConfig).encryptText("dummy-secret-pw");

        assertEquals(0, cli.run("rekey", "--from-config", oldConfig.toString(), "--to-config", newConfig.toString(),
                "--value", oldToken), cli.err());
        String newToken = cli.out().trim();
        assertTrue(newToken.startsWith("ENC[v1:prod02:"), cli.out());
        assertEquals(1, newToken.split("\\r?\\n").length, "표준 출력에는 새 암호문 한 줄만");
        assertTrue(cli.err().contains("[PASS]"), cli.err());
        assertFalse(cli.out().contains("dummy-secret-pw") || cli.err().contains("dummy-secret-pw"), "평문 미노출");
        assertEquals("dummy-secret-pw", CredentialCrypto.fromConfigFile(newConfig).decryptText(newToken));
        assertFalse(CredentialCrypto.fromConfigFile(oldConfig).verify(newToken), "이전 키로는 복호화되지 않는다");
        assertTrue(CredentialCrypto.fromConfigFile(oldConfig).verify(oldToken), "기존 암호문은 그대로 둔다");

        // 대화형 입력(화면 비표시)도 같다
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.secrets.add(oldToken);
        assertEquals(0, cli.run(terminal, "rekey", "--from-config", oldConfig.toString(), "--to-config", newConfig.toString()),
                cli.err());
        assertNotEquals(newToken, cli.out().trim(), "새 IV로 매번 다른 암호문");
    }

    @Test
    void rekeyFromOriginalJarToCompanyKeyOfTheCurrentRuntime() throws Exception {
        // 현재 실행 설정(=외부 설정 파일 없음 → 테스트 JVM의 JAR 기본값, 공개 키)에서 회사 키 설정 파일로 옮긴다.
        Path company = TestSupport.writeRandomKeyFile(dir, "company.key");
        Path companyConfig = fileConfig("company.properties", "prod01", company);
        String publicToken = TestSupport.jarDefaults().encryptText("dummy-pw");
        assertEquals(0, cli.run("rekey", "--to-config", companyConfig.toString(), "--value", publicToken), cli.err());
        assertEquals("dummy-pw", CredentialCrypto.fromConfigFile(companyConfig).decryptText(cli.out().trim()));
    }

    @Test
    void rekeyRefusesUnsafeCombinationsAndWrongInput() throws Exception {
        Path oldKey = TestSupport.writeRandomKeyFile(dir, "o.key");
        Path newKey = TestSupport.writeRandomKeyFile(dir, "n.key");
        Path oldConfig = fileConfig("o.properties", "prod01", oldKey);
        String token = CredentialCrypto.fromConfigFile(oldConfig).encryptText("dummy");
        // 같은 키ID
        assertEquals(1, cli.run("rekey", "--from-config", oldConfig.toString(),
                "--to-config", fileConfig("same-id.properties", "prod01", newKey).toString(), "--value", token));
        assertTrue(cli.err().contains("키ID가 같습니다"), cli.err());
        // 같은 키(다른 키ID)
        assertEquals(1, cli.run("rekey", "--from-config", oldConfig.toString(),
                "--to-config", fileConfig("same-key.properties", "prod09", oldKey).toString(), "--value", token));
        assertTrue(cli.err().contains("같은 키"), cli.err());
        // 양쪽 모두 현재 실행 설정
        assertEquals(1, cli.run("rekey", "--value", token));
        assertTrue(cli.err().contains("--from-config"), cli.err());
        // 이전 설정과 맞지 않는 암호문, 변조 암호문
        Path newConfig = fileConfig("n.properties", "prod02", newKey);
        String otherToken = CredentialCrypto.fromConfigFile(newConfig).encryptText("x");
        assertEquals(1, cli.run("rekey", "--from-config", oldConfig.toString(), "--to-config", newConfig.toString(),
                "--value", otherToken));
        assertTrue(cli.err().contains("[사유: KEY_ID_MISMATCH]"), cli.err());
        String tampered = token.substring(0, token.length() - 3) + (token.charAt(token.length() - 3) == 'A' ? 'B' : 'A')
                + token.substring(token.length() - 2);
        assertEquals(1, cli.run("rekey", "--from-config", oldConfig.toString(), "--to-config", newConfig.toString(),
                "--value", tampered));
        assertTrue(cli.err().contains("[사유: INTEGRITY]"), cli.err());
        assertFalse(cli.out().contains("ENC["), "실패하면 새 암호문을 출력하지 않는다");
        // 이전 쪽 두 옵션을 함께 쓰면 거부
        assertEquals(1, cli.run("rekey", "--from-config", oldConfig.toString(), "--from-jar", "x.jar", "--value", token));
    }
}
