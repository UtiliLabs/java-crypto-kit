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

    /** crypto.key.* AES 키(file) 설정. 이 설정의 새 암호화 기본도 그 AES 키다(crypto.key.type=key, 이전 형식 설정의 이전 절차). */
    private Path fileConfig(String name, String keyId, Path key) throws Exception {
        return TestSupport.writeConfig(dir, name, "crypto.key.type=key", "crypto.key.source=file", "crypto.key.id=" + keyId,
                "crypto.key.file=" + TestSupport.propertiesPath(key));
    }

    /** fingerprint를 실행해 "키 지문   : <64자>" 줄의 지문을 돌려준다(명시적 비교 명령은 전체 64자를 보여 준다). */
    private String fingerprintOf(String... args) {
        assertEquals(0, cli.run(args), cli.err());
        for (String line : cli.out().split("\\r?\\n")) {
            if (line.startsWith("키 지문   : ")) {
                String value = line.substring("키 지문   : ".length());
                assertTrue(value.matches("[0-9a-f]{64}"), "fingerprint는 전체 64자 지문: " + line);
                return value;
            }
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
        assertTrue(cli.out().contains("키 상태   : 사용자 지정"), cli.out());
        assertFalse(cli.out().contains("인증") || cli.out().contains("참고"), "결과 외 안내 문구 없음: " + cli.out());
        // 기본 공개 키는 경고 대신 키 상태로 표시(공급원·키 ID·유형 포함). 옵션이 없으면 새 암호화의 기본 키(pass).
        assertEquals(0, cli.run("fingerprint"));
        assertTrue(cli.out().contains("키 공급원 : embedded") && cli.out().contains("키 ID     : test-pass")
                && cli.out().contains("키 유형   : pass") && cli.out().contains("키 상태   : 사용자 지정"), cli.out());
        assertTrue(cli.out().matches("(?s).*키 지문   : [0-9a-f]{64}.*"), cli.out());
        assertFalse(cli.out().contains("[WARN]"), cli.out());
        // --type key: crypto.key.* AES 키, --key-id: 그 키
        String aesPrint = fingerprintOf("fingerprint", "--type", "key");
        assertTrue(cli.out().contains("키 ID     : default") && cli.out().contains("키 유형   : key"), cli.out());
        assertEquals(aesPrint, fingerprintOf("fingerprint", "--key-id", "default"));
        assertEquals(1, cli.run("fingerprint", "--type", "pass", "--key-id", "default"));
        assertTrue(cli.err().contains("[사유: CONFIGURATION]"), cli.err());
        assertEquals(1, cli.run("fingerprint", "--key-file", a.toString(), "--type", "key"));
        assertTrue(cli.err().contains("[사유: USAGE]"), cli.err());
        assertFalse(cli.out().contains(TestSupport.publicKeyBase64()), "키 원문은 출력하지 않는다");
        assertEquals(1, cli.run("fingerprint", "--key-file", a.toString(), "--config", "x.properties"));
        // 키를 읽지 못하면 실제 원인(사유 코드)으로 실패한다.
        Path missing = fileConfig("missing.properties", "m01", dir.resolve("none.key"));
        assertEquals(1, cli.run("fingerprint", "--config", missing.toString()));
        assertTrue(cli.err().startsWith("[java-crypto-kit] [사유: KEY_SOURCE] "), cli.err());
        assertFalse(cli.out().contains("키 지문"), cli.out());
        assertSingleError(cli.err(), "KEY_SOURCE");
    }

    /** 오류는 한 줄이고 태그·사유·원인·조치가 각각 한 번만 나온다(이미 정제된 오류를 다시 감싸지 않음). */
    private static void assertSingleError(String err, String reason) {
        String line = err.trim();
        assertEquals(1, line.split("\\r?\\n").length, "오류는 한 줄: " + err);
        String prefix = "[java-crypto-kit] [사유: " + reason + "] ";
        assertTrue(line.startsWith(prefix) && line.contains(" 조치: "), err);
        assertEquals(1, count(line, "[java-crypto-kit]"), err);
        assertEquals(1, count(line, "[사유: "), err);
        assertEquals(1, count(line, "조치:"), "조치가 한 번만: " + err);
        String cause = line.substring(prefix.length(), line.indexOf(" 조치: "));
        assertEquals(1, count(line, cause), "원인이 한 번만: " + err);
    }

    private static int count(String text, String part) {
        int found = 0;
        for (int at = text.indexOf(part); at >= 0; at = text.indexOf(part, at + part.length())) found++;
        return found;
    }

    /** @return 공개 기본 키 경고 기록 수 */
    private static long publicKeyWarnings(TestSupport.LogCapture log) {
        return log.warnings().stream().filter(message -> message.contains("공개된 기본 키 사용 중")).count();
    }

    @Test
    void rekeyToThePublicKeyWarnsOnlyAfterTheNewCiphertextIsVerified() throws Exception {
        // 신규 쪽 = 현재 실행 설정(JAR 기본값, 공개 기본 키). 이전 쪽 = 사용자 지정 키 설정 파일.
        Path companyKey = TestSupport.writeRandomKeyFile(dir, "c.key");
        Path companyConfig = fileConfig("c.properties", "prod01", companyKey);
        String token = CredentialCrypto.fromConfigFile(companyConfig).encryptText("dummy-pw");
        String tampered = token.substring(0, token.length() - 3) + (token.charAt(token.length() - 3) == 'A' ? 'B' : 'A')
                + token.substring(token.length() - 2);
        String newToken;
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            // 실패(변조 암호문, 이전 키 파일 없음): 오류만 남기고 경고는 0건(키 지문 조회·복호화 중에도 경고하지 않음)
            assertEquals(1, cli.run("rekey", "--from-config", companyConfig.toString(), "--value", tampered));
            assertTrue(cli.err().contains("[사유: INTEGRITY]"), cli.err());
            // 이전 키는 암호문의 키 ID(prod01)로 고르므로, 같은 키 ID의 키 파일이 없는 이전 설정이면 KEY_SOURCE다.
            Path missing = fileConfig("missing.properties", "prod01", dir.resolve("none.key"));
            assertEquals(1, cli.run("rekey", "--from-config", missing.toString(), "--value", token));
            assertSingleError(cli.err(), "KEY_SOURCE");
            assertEquals("", cli.out(), "실패하면 표준 출력에 아무것도 쓰지 않는다");
            assertEquals(0, publicKeyWarnings(log), "실패한 재암호화에는 경고가 없다: " + log.warnings());

            // 성공: 새 암호문을 모두 검증한 뒤 경고 1건, 표준 출력은 새 암호문 한 줄
            assertEquals(0, cli.run("rekey", "--from-config", companyConfig.toString(), "--value", token), cli.err());
            newToken = cli.out().trim();
            assertTrue(newToken.startsWith("ENC[v1:default:"), cli.out());
            assertEquals(1, cli.out().trim().split("\\r?\\n").length, "표준 출력에는 새 암호문 한 줄만");
            assertEquals(0, publicKeyWarnings(log), log.warnings().toString());
        }
        assertEquals("dummy-pw", TestSupport.managedCrypto().decryptText(newToken));
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
        assertEquals("", cli.err(), "성공하면 표준 오류에 요약·안내를 쓰지 않는다");
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
        // 공개 AES 키(default)로 만든 암호문 → 대상 유형을 정하지 않으면 같은 유형(key)의 기본 키(회사 AES 키 prod01)
        String publicToken = TestSupport.managedCrypto().encryptText("dummy-pw", io.javacryptokit.KeyType.KEY);
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            assertEquals(0, cli.run("rekey", "--to-config", companyConfig.toString(), "--value", publicToken), cli.err());
            assertTrue(cli.out().trim().startsWith("ENC[v1:prod01:"), cli.out());
            // 신규 키가 사용자 지정 키면 이전 쪽이 공개 키여도 경고하지 않는다(표준 오류 비어 있음).
            assertEquals("", cli.err());
            assertEquals(0, publicKeyWarnings(log), log.warnings().toString());
        }
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
        assertTrue(cli.err().contains("키 ID가 같습니다"), cli.err());
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
