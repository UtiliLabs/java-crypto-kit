package io.javacryptokit.cli;

import io.javacryptokit.CredentialCrypto;

import io.javacryptokit.TestSupport;

import io.javacryptokit.config.CryptoSettings;

import io.javacryptokit.key.DefaultKeyWarning;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * CLI 명령의 출력·종료 코드·안전 장치를 가짜 터미널로 검증한다. 실제 콘솔 입력 화면(문자 가림)은 수동 확인 대상이다.
 */
class CryptoCliTest {
    @TempDir
    Path dir;

    private final ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errBytes = new ByteArrayOutputStream();
    private AutoCloseable commonProperty;
    private AutoCloseable legacyProperty;
    private AutoCloseable jvmProperties;

    @BeforeEach
    void isolate() {
        // 설정 파일을 지정하지 않는 명령도 실제 환경의 외부 설정·JVM 개별 속성을 읽지 않도록 격리한다.
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        commonProperty = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, null);
        legacyProperty = TestSupport.clearOtherConfigProperties();
        jvmProperties = TestSupport.jvmSettings();
        DefaultKeyWarning.resetForTests();
    }

    @AfterEach
    void restore() throws Exception {
        if (jvmProperties != null) jvmProperties.close();
        if (commonProperty != null) commonProperty.close();
        if (legacyProperty != null) legacyProperty.close();
    }

    /** 입력을 미리 정해 두는 가짜 대화형 터미널. 터미널에 쓴 문구도 기록한다. */
    static final class FakeTerminal implements CryptoCli.Terminal {
        final Deque<String> lines = new ArrayDeque<>();
        final Deque<String> secrets = new ArrayDeque<>();
        final List<String> printed = new ArrayList<>();

        @Override
        public char[] readSecret(String prompt) {
            printed.add(prompt);
            String value = secrets.poll();
            return value == null ? null : value.toCharArray();
        }

        @Override
        public String readLine(String prompt) {
            printed.add(prompt);
            return lines.poll();
        }

        @Override
        public void println(String message) {
            printed.add(message);
        }
    }

    private int run(FakeTerminal terminal, String... args) {
        PrintStream out = new PrintStream(outBytes, true);
        PrintStream err = new PrintStream(errBytes, true);
        CryptoCli.TerminalProvider provider = terminal == null
                ? () -> { throw new CryptoCli.CliException("대화형 터미널이 필요합니다. 테스트에서는 터미널이 없습니다."); }
                : () -> terminal;
        return CryptoCli.execute(args, provider, out, err);
    }

    private String out() {
        return new String(outBytes.toByteArray(), StandardCharsets.UTF_8);
    }

    private String err() {
        return new String(errBytes.toByteArray(), StandardCharsets.UTF_8);
    }

    private Path fileKeyConfig(String... extra) throws Exception {
        Path key = TestSupport.writeRandomKeyFile(dir, "cli.key");
        List<String> lines = new ArrayList<>();
        lines.add("crypto.key.source=file");
        lines.add("crypto.key.id=cli01");
        lines.add("crypto.key.file=" + TestSupport.propertiesPath(key));
        for (String line : extra) lines.add(line);
        return TestSupport.writeConfig(dir, "cli.properties", lines.toArray(new String[0]));
    }

    @Test
    void helpSucceeds() {
        assertEquals(0, run(null, "help"));
        assertTrue(out().contains("java-crypto-kit CLI"));
        assertTrue(out().contains("crypto.config.file") && out().contains("CRYPTO_CONFIG_FILE"), out());
    }

    @Test
    void infoShowsDefaultModeWithoutPrintingTheKey() throws Exception {
        assertEquals(0, run(null, "info"));
        String output = out();
        assertTrue(output.contains("키 공급 방식: embedded (JAR 기본값)"), output);
        assertTrue(output.contains("경고 정책(crypto.warning.enabled): true"), output);
        assertTrue(output.contains("출력 형식(crypto.output.encoding): enc"), output);
        assertTrue(output.contains("공개 기본 키입니다"), output);
        assertFalse(output.contains(TestSupport.publicKeyBase64()), "키 값을 출력하면 안 된다");
    }

    @Test
    void infoShowsExternalFileModePolicyAndOriginWithoutFullPath() throws Exception {
        Path config = fileKeyConfig("crypto.warning.enabled=false", "crypto.output.encoding=base64");
        assertEquals(0, run(null, "info", "--config", config.toString()));
        String output = out();
        assertTrue(output.contains("키 공급 방식: file (외부 설정에서 지정)"), output);
        assertTrue(output.contains("키 위치: 파일 cli.key"), output);
        assertTrue(output.contains("외부 설정: 사용 - 출처: 직접 지정(CLI --config 또는 CredentialCrypto.fromConfigFile), 파일명: cli.properties"), output);
        assertTrue(output.contains("false - 안내 WARNING 출력 안 함"), output);
        assertTrue(output.contains("출력 형식(crypto.output.encoding): base64"), output);
        assertTrue(output.contains("키 확인: 정상(32바이트)"), output);
        assertFalse(output.contains("공개 기본 키입니다"), output);
        assertFalse(output.contains(dir.toString()), "전체 경로는 출력하지 않는다");
    }

    @Test
    void infoMakesInheritedEmbeddedSourceVisible() throws Exception {
        Path config = TestSupport.writeConfig(dir, "id-only.properties", "crypto.key.id=prod01");
        assertEquals(0, run(null, "info", "--config", config.toString()));
        assertTrue(out().contains("crypto.key.source 없음 - JAR 기본값 상속"), out());
    }

    @Test
    void infoFailsWhenKeyCannotBeLoaded() throws Exception {
        Path config = TestSupport.writeConfig(dir, "missing.properties", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(dir.resolve("gone.key")));
        assertEquals(1, run(null, "info", "--config", config.toString()));
        assertTrue(out().contains("키 확인: 실패"), out());
    }

    @Test
    void invalidConfigurationReportsReasonWithoutEchoingValue() throws Exception {
        Path config = TestSupport.writeConfig(dir, "bad.properties", "crypto.warning.enabled=maybe-xyz");
        assertEquals(1, run(null, "info", "--config", config.toString()));
        assertTrue(err().contains("[사유: CONFIGURATION]"), err());
        assertTrue(err().contains("crypto.warning.enabled"), err());
        assertFalse(err().contains("maybe-xyz"));
    }

    @Test
    void encryptPrintsOnlyTheTokenInConfiguredFormat() throws Exception {
        FakeTerminal terminal = new FakeTerminal();
        terminal.secrets.add("dummy-pw-123");
        assertEquals(0, run(terminal, "encrypt"));
        assertTrue(out().trim().startsWith("ENC[v1:default:"), out());
        assertFalse(out().contains("dummy-pw-123") || err().contains("dummy-pw-123"), "평문을 출력하면 안 된다");

        outBytes.reset();
        FakeTerminal second = new FakeTerminal();
        second.secrets.add("dummy-pw-123");
        Path config = fileKeyConfig("crypto.output.encoding=base64");
        assertEquals(0, run(second, "encrypt", "--config", config.toString()));
        assertTrue(out().trim().startsWith("B64["), out());
    }

    @Test
    void verifyNeverPrintsPlaintextAndReportsReasons() throws Exception {
        Path config = fileKeyConfig();
        String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-verify-pw");
        assertEquals(0, run(null, "verify", "--value", token, "--config", config.toString()));
        assertTrue(out().contains("검증 성공"));
        assertFalse(out().contains("dummy-verify-pw"));

        FakeTerminal terminal = new FakeTerminal();
        terminal.secrets.add(token);
        outBytes.reset();
        assertEquals(0, run(terminal, "verify", "--config", config.toString()));
        assertTrue(out().contains("검증 성공"));

        String tampered = token.substring(0, token.length() - 3)
                + (token.charAt(token.length() - 3) == 'A' ? 'B' : 'A') + token.substring(token.length() - 2);
        assertEquals(1, run(null, "verify", "--value", tampered, "--config", config.toString()));
        assertTrue(err().contains("[사유: INTEGRITY]"), err());
        assertFalse(err().contains(tampered));
    }

    @Test
    void decryptShowsPlaintextOnlyAfterShowConfirmation() throws Exception {
        String token = TestSupport.jarDefaults().encryptText("dummy-decrypt-pw");
        FakeTerminal terminal = new FakeTerminal();
        terminal.lines.add("SHOW");
        terminal.secrets.add(token);
        assertEquals(0, run(terminal, "decrypt"));
        assertTrue(out().contains("복호화 결과 (평문): dummy-decrypt-pw"));
        assertTrue(String.join("\n", terminal.printed).contains("[주의] decrypt는 복호화한 평문을 화면에 표시합니다"));
    }

    @Test
    void decryptCancelsWithoutShowEvenWhenWarningsAreDisabled() throws Exception {
        Path config = TestSupport.writeConfig(dir, "quiet.properties", "crypto.key.source=embedded",
                "crypto.warning.enabled=false");
        String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-cancel-pw");
        FakeTerminal terminal = new FakeTerminal();
        terminal.lines.add("show"); // 소문자는 확인으로 인정하지 않는다
        terminal.secrets.add(token);
        assertEquals(0, run(terminal, "decrypt", "--config", config.toString()));
        assertFalse(out().contains("dummy-cancel-pw"), "SHOW 없이 평문을 보여 주면 안 된다");
        assertTrue(String.join("\n", terminal.printed).contains("취소했습니다"));
        assertEquals(1, terminal.secrets.size(), "취소하면 암호문 입력도 받지 않는다");
    }

    @Test
    void decryptRejectsValueOptionAndCommandsRequireTerminal() {
        assertEquals(1, run(null, "decrypt", "--value", "ENC[v1:default:AAAA:AAAA]"));
        assertTrue(err().contains("decrypt에서 쓸 수 없는 옵션입니다(--value)"), err());
        errBytes.reset();
        assertEquals(1, run(null, "encrypt"));
        assertTrue(err().contains("대화형 터미널이 필요합니다"));
        errBytes.reset();
        assertEquals(1, run(null, "decrypt"));
        assertTrue(err().contains("대화형 터미널이 필요합니다"));
    }

    @Test
    void keygenCreatesKeyAndNeverOverwrites() throws Exception {
        Path key = dir.resolve("new.key");
        assertEquals(0, run(null, "keygen", "--out", key.toString()));
        byte[] content = Files.readAllBytes(key);
        assertEquals(45, content.length, "Base64 44자 + 줄바꿈");
        assertEquals(32, Base64.getDecoder().decode(new String(content, StandardCharsets.US_ASCII).trim()).length);
        assertFalse(out().contains(new String(content, StandardCharsets.US_ASCII).trim()), "키를 출력하면 안 된다");
        byte[] before = Files.readAllBytes(key);
        assertEquals(1, run(null, "keygen", "--out", key.toString()));
        assertTrue(err().contains("FileAlreadyExistsException"), err());
        assertTrue(java.util.Arrays.equals(before, Files.readAllBytes(key)), "기존 키 파일이 바뀌면 안 된다");
        assertEquals(1, run(null, "keygen", "--out", dir.resolve("no-dir").resolve("k.key").toString()));
    }

    @Test
    void unknownArgumentsAreRejectedWithoutEchoingThem() {
        assertEquals(1, run(null, "encrypt", "--password", "SuperSecret-123"));
        assertFalse(err().contains("SuperSecret-123"), "실수로 넣은 평문을 다시 출력하면 안 된다");
        assertEquals(1, run(null, "unknown-command"));
    }

    @Test
    void helpExplainsJvmPropertyPlacement() {
        assertEquals(0, run(null, "help"));
        assertTrue(out().contains("-D 옵션은 java와 -jar 사이에 둡니다"), out());
        assertTrue(out().contains("-Dcrypto.lang=en"), out());
    }

    @Test
    void jvmPropertyPlacedAfterJarIsRejectedWithPlacementHint() {
        // java -jar <jar> info -Dcrypto.key.id=... 처럼 -D를 명령 뒤에 두면 JVM 속성이 아니라 프로그램 인자가 된다.
        assertEquals(1, run(null, "info", "-Dcrypto.key.id=zz-misplaced-value"));
        assertTrue(err().contains("-D 옵션은 java와 -jar 사이에 두어야 합니다"), err());
        assertFalse(err().contains("zz-misplaced-value"), "인자 값을 그대로 출력하지 않는다");
    }

    @Test
    void infoShowsJvmPropertyOriginsAndKeepsExplicitDiagnosticsWhenWarningsAreOff() throws Exception {
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.warning.enabled=false", "crypto.key.id=cli02")) {
            assertEquals(0, run(null, "info"));
        }
        String output = out();
        assertTrue(output.contains("키 식별자: cli02 [출처: JVM 속성 -D]"), output);
        assertTrue(output.contains("false - 안내 WARNING 출력 안 함(오류·검증에는 영향 없음) [출처: JVM 속성 -D]"), output);
        assertTrue(output.contains("JVM 개별 속성(crypto.jvm.override.enabled): true - 허용, "
                + "적용: crypto.key.id, crypto.warning.enabled [출처: JAR 기본값]"), output);
        assertTrue(output.contains("crypto.key.source 없음 - JAR 기본값 상속"), output);
        assertTrue(output.contains("알고리즘: AES/GCM/NoPadding [출처: JAR 기본값]"), output);
        // 사용자가 직접 요청한 진단(info)은 자동 경고와 구분되어 경고 정책 false에서도 그대로 보여 준다.
        assertTrue(output.contains("공개 기본 키입니다"), output);
        assertFalse(output.contains(TestSupport.publicKeyBase64()), "키 값을 출력하면 안 된다");
    }

    @Test
    void infoShowsIgnoredJvmPropertiesWhenPolicyIsOff() throws Exception {
        Path config = TestSupport.writeConfig(dir, "policy.properties", "crypto.jvm.override.enabled=false");
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.warning.enabled=false")) {
            assertEquals(0, run(null, "info", "--config", config.toString()));
        }
        String output = out();
        assertTrue(output.contains("false - 개별 -D 설정 무시"), output);
        assertTrue(output.contains("무시: crypto.warning.enabled"), output);
        assertTrue(output.contains("경고 정책(crypto.warning.enabled): true - 안내 WARNING 출력 [출처: JAR 기본값]"), output);
        assertTrue(output.contains("[출처: 외부 설정 파일]"), output);
    }

    @Test
    void encryptAndVerifyWithJvmPropertiesOnly() throws Exception {
        Path key = TestSupport.writeRandomKeyFile(dir, "jvm-cli.key");
        FakeTerminal terminal = new FakeTerminal();
        terminal.secrets.add("dummy-jvm-cli-pw");
        String token;
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(key), "crypto.key.id=cli03")) {
            assertEquals(0, run(terminal, "encrypt"));
            token = out().trim();
            assertTrue(token.startsWith("ENC[v1:cli03:"), token);
            outBytes.reset();
            assertEquals(0, run(null, "verify", "--value", token));
            assertTrue(out().contains("검증 성공"), out());
        }
        // JVM 속성(키 설정)을 빼면 JAR 기본값(공개 내장 키, 키ID default)으로 돌아가므로 같은 암호문은 검증에 실패해야 한다.
        assertEquals(1, run(null, "verify", "--value", token));
        assertTrue(err().contains("[사유: KEY_ID_MISMATCH]"), err());
    }

    @Test
    void rawKeyInJvmPropertyIsRejectedByTheCli() throws Exception {
        String dummy = Base64.getEncoder().encodeToString(new byte[32]);
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.key.embedded=" + dummy)) {
            assertEquals(1, run(null, "info"));
        }
        assertTrue(err().contains("[사유: CONFIGURATION]"), err());
        assertTrue(err().contains("crypto.key.embedded"), err());
        assertFalse(err().contains(dummy), "키 값을 출력하면 안 된다");
    }

    // ===== QA-02/03/08: 빈 경로 거부, 사유 코드 + 조치 줄, 오타 진단 =====

    @Test
    void blankConfigOptionFailsClosedInsteadOfUsingTheEmbeddedKey() {
        assertEquals(1, run(null, "info", "--config", "   "));
        String error = err();
        assertTrue(error.contains("[사유: CONFIGURATION]"), error);
        assertTrue(error.contains("비어 있습니다"), error);
        assertTrue(error.contains(" 조치: "), "다음 조치를 함께 안내해야 한다: " + error);
        assertFalse(out().contains("키 공급 방식"), "설정을 읽지 않고 중단해야 한다");
    }

    @Test
    void failureOutputHasReasonCodeAndActionWithoutValues() throws Exception {
        Path config = TestSupport.writeConfig(dir, "typo.properties", "crypto.warnning.enabled=false");
        assertEquals(1, run(null, "info", "--config", config.toString()));
        String[] lines = err().trim().split("\\r?\\n");
        assertEquals(1, lines.length, err());
        assertTrue(lines[0].startsWith("[java-crypto-kit] [사유: CONFIGURATION] "), lines[0]);
        assertTrue(lines[0].contains("'crypto.warning.enabled'"), "비슷한 정식 이름을 안내해야 한다: " + lines[0]);
        assertTrue(lines[0].contains(" 조치: "), lines[0]);
        assertFalse(err().contains(dir.toString()), "경로를 출력하지 않는다");
    }

    @Test
    void misspelledLibraryJvmPropertyStopsTheCommandWithSuggestion() throws Exception {
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.key.soruce=file")) {
            assertEquals(1, run(null, "info"));
        }
        assertTrue(err().contains("[사유: CONFIGURATION]"), err());
        assertTrue(err().contains("'crypto.key.soruce'") && err().contains("'crypto.key.source'"), err());
        assertFalse(err().contains("=file"), "값은 출력하지 않는다");
        assertFalse(out().contains("키 공급 방식"), "오타를 무시하고 내장 키로 진행하면 안 된다");
    }

    @Test
    void unrelatedJvmPropertyDoesNotAffectTheCli() throws Exception {
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.policy=unlimited")) {
            assertEquals(0, run(null, "info"));
        }
    }

    @Test
    void keygenExplainsMissingFolderWithoutPrintingThePath() {
        String missing = dir.resolve("no-such-folder").resolve("crypto.key").toString();
        assertEquals(1, run(null, "keygen", "--out", missing));
        assertTrue(err().contains("키 파일을 만들 폴더가 없습니다"), err());
        assertFalse(err().contains("no-such-folder"), err());
    }
}
