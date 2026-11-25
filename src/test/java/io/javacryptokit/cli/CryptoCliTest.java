package io.javacryptokit.cli;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.i18n.Messages;

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
        return CryptoCli.execute(args, provider, out, err, new CliHarness.RecordingGate());
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

    /** 64자 키 지문(16진수) 패턴: 일반 조회 화면에는 나오면 안 된다(앞 12자 + ... + 뒤 8자만). */
    private static final java.util.regex.Pattern FULL_FINGERPRINT = java.util.regex.Pattern.compile("[0-9a-f]{64}");
    /** 짧은 키 지문 패턴. */
    private static final java.util.regex.Pattern SHORT_FINGERPRINT = java.util.regex.Pattern.compile("[0-9a-f]{12}\\.\\.\\.[0-9a-f]{8}");

    @Test
    void infoShowsDefaultModeWithoutPrintingTheKey() throws Exception {
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            assertEquals(0, run(null, "info"));
            // info는 키 상태를 직접 보여 주므로 자동 경고를 한 번 더 내지 않는다.
            assertTrue(log.warnings().isEmpty(), log.warnings().toString());
        }
        String output = out();
        // 기본 유형·유형별 기본 키, 그다음 등록된 키마다 한 덩어리(crypto.key.* AES 키가 먼저).
        assertTrue(output.contains("기본 유형 : pass [JAR 기본값]"), output);
        assertTrue(output.contains("pass 기본 : pass-default [JAR 기본값]"), output);
        assertTrue(output.contains("key 기본  : default [JAR 기본값]"), output);
        String aes = block(output, "키 default (key, 기본, crypto.key.*)");
        assertTrue(aes.contains("  공급원 : embedded [JAR 기본값]"), aes);
        assertTrue(aes.contains("  상태   : 공개 기본 키") && aes.contains("  조회   : OK"), aes);
        String pass = block(output, "키 pass-default (pass, 기본)");
        assertTrue(pass.contains("  KDF    : pbkdf2-sha256, 반복 600,000회"), pass);
        assertTrue(pass.contains("  상태   : 공개 기본 키") && pass.contains("  지문   : 3dca588c78a1...94453656"), pass);
        assertTrue(output.indexOf("키 default (") < output.indexOf("키 pass-default ("), "crypto.key.* AES 키가 먼저");
        assertTrue(output.contains("경고 출력 : true [JAR 기본값]"), output);
        assertTrue(output.contains("출력 형식 : enc [JAR 기본값]"), output);
        assertTrue(SHORT_FINGERPRINT.matcher(output).find(), "짧은 키 지문으로 식별: " + output);
        assertFalse(FULL_FINGERPRINT.matcher(output).find(), "일반 조회에는 전체 지문을 보이지 않는다: " + output);
        assertFalse(output.contains(TestSupport.publicKeyBase64()), "키 값을 출력하면 안 된다");
        assertFalse(output.contains("[WARN]") || output.contains("권장"), "조회 화면에 경고·권고 문구 없음: " + output);
    }

    @Test
    void infoShowsExternalFileModePolicyAndOriginWithoutFullPath() throws Exception {
        Path config = fileKeyConfig("crypto.warning.enabled=false", "crypto.output.encoding=base64");
        assertEquals(0, run(null, "info", "--config", config.toString()));
        String output = out();
        assertTrue(output.contains("key 기본  : cli01 [외부 설정 파일]"), output);
        String aes = block(output, "키 cli01 (key, 기본, crypto.key.*)");
        assertTrue(aes.contains("  공급원 : file [외부 설정 파일]"), aes);
        assertTrue(aes.contains("  위치   : 파일 cli.key [외부 설정 파일]"), aes);
        assertTrue(aes.contains("  상태   : 사용자 지정") && aes.contains("  조회   : OK"), aes);
        assertFalse(aes.contains("공개 기본 키"), aes);
        // crypto.key.*를 바꿔도 JAR의 공개 pass 키(pass-default)는 그대로 키 목록에 있다(유형 미지정 기본 = pass).
        assertTrue(block(output, "키 pass-default (pass, 기본)").contains("  상태   : 공개 기본 키"), output);
        assertTrue(output.contains("외부 설정 : cli.properties [직접 지정(--config, fromConfigFile)]"), output);
        assertTrue(output.contains("경고 출력 : false [외부 설정 파일]"), output);
        assertTrue(output.contains("출력 형식 : base64 [외부 설정 파일]"), output);
        assertFalse(output.contains(dir.toString()), "전체 경로는 출력하지 않는다");
    }

    @Test
    void infoMakesInheritedEmbeddedSourceVisible() throws Exception {
        Path config = TestSupport.writeConfig(dir, "id-only.properties", "crypto.key.id=prod01");
        assertEquals(0, run(null, "info", "--config", config.toString()));
        assertTrue(block(out(), "키 prod01 (key, 기본, crypto.key.*)")
                .contains("  공급원 : embedded [JAR 기본값 - 외부 설정·-D에 crypto.key.source 없음]"), out());
    }

    @Test
    void infoFailsWhenKeyCannotBeLoaded() throws Exception {
        Path config = TestSupport.writeConfig(dir, "missing.properties", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(dir.resolve("gone.key")));
        assertEquals(1, run(null, "info", "--config", config.toString()));
        String aes = block(out(), "키 default (key, 기본, crypto.key.*)");
        assertTrue(aes.contains("  조회   : FAIL"), out());
        assertFalse(aes.contains("지문"), "키를 읽지 못하면 지문을 만들어 보이지 않는다: " + out());
        assertTrue(block(out(), "키 pass-default (pass, 기본)").contains("  조회   : OK"), "다른 키 확인은 계속한다: " + out());
        assertTrue(err().startsWith("[java-crypto-kit] [사유: KEY_SOURCE] "), "실제 원인은 오류 형식 한 줄: " + err());
        assertEquals(1, err().trim().split("\\r?\\n").length, "실패한 키마다 한 줄: " + err());
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
        assertTrue(out().trim().startsWith("ENC[v1:pass-default:"), "유형 미지정 기본은 pass: " + out());
        assertEquals(1, out().trim().split("\\r?\\n").length, "표준 출력은 암호문 한 줄만: " + out());
        assertEquals(java.util.Collections.singletonList("암호화할 값(입력 숨김): "), terminal.printed,
                "입력 프롬프트 하나뿐, 다음 단계 안내 없음");
        assertFalse(out().contains("dummy-pw-123") || err().contains("dummy-pw-123"), "평문을 출력하면 안 된다");

        outBytes.reset();
        FakeTerminal second = new FakeTerminal();
        second.secrets.add("dummy-pw-123");
        Path config = fileKeyConfig("crypto.output.encoding=base64");
        assertEquals(0, run(second, "encrypt", "--config", config.toString()));
        assertTrue(out().trim().startsWith("B64["), out());

        // --type key: crypto.key.* AES 키, --key-id: 그 키(유형 자동), 둘 다: 유형 확인 후 사용
        FakeTerminal third = new FakeTerminal();
        third.secrets.add("dummy-pw-123");
        outBytes.reset();
        assertEquals(0, run(third, "encrypt", "--type", "key"));
        assertTrue(out().trim().startsWith("ENC[v1:default:"), out());
        FakeTerminal fourth = new FakeTerminal();
        fourth.secrets.add("dummy-pw-123");
        outBytes.reset();
        assertEquals(0, run(fourth, "encrypt", "--key-id", "default"));
        assertTrue(out().trim().startsWith("ENC[v1:default:"), out());
        // 유형 불일치·미등록 Key ID·잘못된 --type은 입력을 받기 전에 실패하고 평문을 묻지 않는다.
        FakeTerminal never = new FakeTerminal();
        assertEquals(1, run(never, "encrypt", "--type", "pass", "--key-id", "default"));
        assertTrue(err().contains("[사유: CONFIGURATION]"), err());
        assertTrue(never.printed.isEmpty(), "선택이 실패하면 입력을 받지 않는다");
        assertEquals(1, run(never, "encrypt", "--key-id", "no-such"));
        assertTrue(err().contains("[사유: CONFIGURATION]") && err().contains("no-such"), err());
        assertEquals(1, run(never, "encrypt", "--type", "aes"));
        assertTrue(err().contains("[사유: USAGE]") && err().contains("pass"), err());
        assertTrue(never.printed.isEmpty());
    }

    @Test
    void verifyNeverPrintsPlaintextAndReportsReasons() throws Exception {
        Path config = fileKeyConfig();
        String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-verify-pw");
        assertEquals(0, run(null, "verify", "--value", token, "--config", config.toString()));
        assertEquals("OK", out().trim());
        assertFalse(out().contains("dummy-verify-pw"));

        FakeTerminal terminal = new FakeTerminal();
        terminal.secrets.add(token);
        outBytes.reset();
        assertEquals(0, run(terminal, "verify", "--config", config.toString()));
        assertEquals("OK", out().trim());

        String tampered = token.substring(0, token.length() - 3)
                + (token.charAt(token.length() - 3) == 'A' ? 'B' : 'A') + token.substring(token.length() - 2);
        assertEquals(1, run(null, "verify", "--value", tampered, "--config", config.toString()));
        assertTrue(err().contains("[사유: INTEGRITY]"), err());
        assertFalse(err().contains(tampered));
    }

    @Test
    void decryptShowsPlaintextRightAfterTheCiphertextWithoutExtraConfirmation() throws Exception {
        String token = TestSupport.jarDefaults().encryptText("dummy decrypt\npw ");
        FakeTerminal terminal = new FakeTerminal();
        terminal.secrets.add(token);
        assertEquals(0, run(terminal, "decrypt"));
        // 암호문 한 번 입력 → 바로 평문(공백·줄바꿈 그대로). SHOW 같은 확인 입력·경고 문구는 없다.
        assertEquals("복호화 결과: dummy decrypt\npw " + System.lineSeparator(), out());
        assertEquals(java.util.Collections.singletonList("암호문(입력 숨김): "), terminal.printed, terminal.printed.toString());
        assertTrue(terminal.lines.isEmpty() && terminal.secrets.isEmpty());
    }

    @Test
    void decryptOfDamagedOrForeignCiphertextNeverPrintsPlaintext() throws Exception {
        Path config = TestSupport.writeConfig(dir, "quiet.properties", "crypto.key.source=embedded",
                "crypto.warning.enabled=false");
        String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-damaged-pw");
        String tampered = token.substring(0, token.length() - 3)
                + (token.charAt(token.length() - 3) == 'A' ? 'B' : 'A') + token.substring(token.length() - 2);
        FakeTerminal terminal = new FakeTerminal();
        terminal.secrets.add(tampered);
        assertEquals(1, run(terminal, "decrypt", "--config", config.toString()));
        assertTrue(err().contains("[사유: INTEGRITY]"), err());
        assertFalse(out().contains("dummy-damaged-pw") || err().contains("dummy-damaged-pw"), "검증 실패면 평문 없음");
        // 다른 키 ID로 만든 암호문도 평문 없이 KEY_ID_MISMATCH
        FakeTerminal second = new FakeTerminal();
        second.secrets.add(fileKeyConfigToken("dummy-other-key-pw"));
        errBytes.reset();
        assertEquals(1, run(second, "decrypt", "--config", config.toString()));
        assertTrue(err().contains("[사유: KEY_ID_MISMATCH]"), err());
        assertFalse(out().contains("dummy-other-key-pw"));
    }

    /** 다른 키·키ID(cli01, crypto.key.* AES 키)로 만든 암호문. */
    private String fileKeyConfigToken(String plain) throws Exception {
        return CredentialCrypto.fromConfigFile(fileKeyConfig()).encryptText(plain, io.javacryptokit.KeyType.KEY);
    }

    /** info 출력에서 머리줄부터 다음 빈 줄까지(키 한 덩어리). 없으면 빈 문자열. */
    private static String block(String output, String header) {
        int start = output.indexOf(header);
        if (start < 0) return "";
        int end = output.indexOf(System.lineSeparator() + System.lineSeparator(), start);
        return end < 0 ? output.substring(start) : output.substring(start, end);
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
        assertEquals(0, run(null, "keygen", "--out", key.toString(), "--reason", "시험 키 준비"));
        byte[] content = Files.readAllBytes(key);
        assertEquals(45, content.length, "Base64 44자 + 줄바꿈");
        assertEquals(32, Base64.getDecoder().decode(new String(content, StandardCharsets.US_ASCII).trim()).length);
        // 비대화형 실행(터미널 없음)에서는 생성값을 어디에도 출력하지 않는다(키 파일이 원본).
        assertFalse(out().contains(new String(content, StandardCharsets.US_ASCII).trim()), "키를 출력하면 안 된다");
        assertFalse(err().contains(new String(content, StandardCharsets.US_ASCII).trim()), "표준 오류에도 키가 없다");
        // 결과: 파일 경로, 전체 키 지문, 사유, 이력에 남지 않는다는 사실(다음 단계 안내 없음)
        String[] lines = out().trim().split("\\r?\\n");
        assertEquals(4, lines.length, out());
        assertTrue(lines[0].startsWith("키 파일   : ") && lines[0].endsWith("new.key"), lines[0]);
        assertTrue(lines[1].matches("키 지문   : [0-9a-f]{64}"), lines[1]);
        assertEquals("사유      : 시험 키 준비", lines[2]);
        assertEquals("이력      : 저장 안 함(JAR를 바꾸지 않는 명령이라 config history에 없음)", lines[3]);
        byte[] before = Files.readAllBytes(key);
        assertEquals(1, run(null, "keygen", "--out", key.toString(), "--reason", "다시"));
        assertTrue(err().contains("키 파일이 이미 있어 덮어쓰지 않습니다"), err());
        assertTrue(java.util.Arrays.equals(before, Files.readAllBytes(key)), "기존 키 파일이 바뀌면 안 된다");
        assertEquals(1, run(null, "keygen", "--out", dir.resolve("no-dir").resolve("k.key").toString(), "--reason", "x"));
    }

    @Test
    void keygenNeedsAReasonBeforeCreatingAnythingAndShowsTheKeyLineOnlyInATerminal() throws Exception {
        // 사유가 없으면 비대화형 실행은 키를 만들기 전에 멈춘다(파일 없음).
        Path none = dir.resolve("none.key");
        assertEquals(1, run(null, "keygen", "--out", none.toString()));
        assertTrue(err().contains("[사유: USAGE]") && err().contains("--reason"), err());
        assertFalse(Files.exists(none), "사유 없이 키 파일을 만들면 안 된다");
        // 대화형: 사유를 묻고(빈 입력이면 중단, 파일 없음), 받은 뒤 만든다.
        FakeTerminal empty = new FakeTerminal();
        empty.lines.add("   ");
        assertEquals(1, run(empty, "keygen", "--out", none.toString()));
        assertTrue(err().contains("사유를 입력하지 않아 중단했습니다"), err());
        assertFalse(Files.exists(none));
        FakeTerminal terminal = new FakeTerminal();
        terminal.lines.add("운영 키 준비");
        Path key = dir.resolve("shown.key");
        assertEquals(0, run(terminal, "keygen", "--out", key.toString(), "--operator", "example-admin"), err());
        String fileLine = new String(Files.readAllBytes(key), StandardCharsets.US_ASCII).trim();
        assertTrue(out().contains("사유      : 운영 키 준비") && out().contains("작업자    : example-admin"), out());
        assertFalse(out().contains(fileLine) || err().contains(fileLine), "생성값은 표준 출력·표준 오류에 쓰지 않는다");
        // 터미널: 사유 질문, 유형, 키 ID 미등록, 형식, 값 한 줄(= 키 파일 한 줄, 라벨·공백 없음), 안내
        assertEquals(java.util.Arrays.asList("사유(비밀값 제외): ", "", "유형      : key", "키 ID     : 미등록(키 파일만 만듦)",
                "생성값    : AES 키(표준 Base64, 32바이트) - 다음 줄 전체가 값", fileLine,
                "안내      : 키 파일 내용과 같은 값입니다. 키 파일을 안전하게 보관하세요."), terminal.printed);
        for (String line : terminal.printed) assertTrue(CliHelp.width(line) <= 80, "80열: " + line);
        // 화면에서 복사한 값은 keygen 키 파일과 같은 형식으로 다시 쓸 수 있다(같은 지문).
        Path copied = Files.write(dir.resolve("copied.key"), (fileLine + "\r\n").getBytes(StandardCharsets.US_ASCII));
        assertEquals(0, run(null, "fingerprint", "--key-file", copied.toString()));
        String copiedPrint = out().replaceAll("(?s).*키 지문   : ([0-9a-f]{64}).*", "$1");
        assertEquals(0, run(null, "fingerprint", "--key-file", key.toString()));
        assertEquals(copiedPrint, out().replaceAll("(?s).*키 지문   : ([0-9a-f]{64}).*", "$1"), "복사한 값 = 키 파일");
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
        assertTrue(out().contains("-D<설정>=<값>은 java와 -jar 사이에 둡니다"), out());
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
        assertTrue(output.contains("key 기본  : cli02 [JVM 속성 -D]"), output);
        assertTrue(output.contains("경고 출력 : false [JVM 속성 -D]"), output);
        // 정책 줄 다음에 적용한 -D를 한 줄에 하나씩(값 열에 맞춤) 보여 준다.
        String ls = System.lineSeparator();
        assertTrue(output.contains("JVM -D    : 허용 [JAR 기본값]" + ls + "적용 -D   : crypto.key.id" + ls
                + "            crypto.warning.enabled" + ls), output);
        assertFalse(output.contains("무시 -D"), "무시한 -D가 없으면 그 줄을 만들지 않는다: " + output);
        assertTrue(output.contains("외부 설정·-D에 crypto.key.source 없음"), output);
        assertTrue(output.contains("알고리즘  : AES/GCM/NoPadding [JAR 기본값]"), output);
        // 사용자가 직접 요청한 조회(info)의 키 상태는 경고 정책 false에서도 그대로 보여 준다.
        assertTrue(block(output, "키 cli02 (key, 기본, crypto.key.*)").contains("  상태   : 공개 기본 키"), output);
        assertFalse(output.contains(TestSupport.publicKeyBase64()), "키 값을 출력하면 안 된다");
    }

    @Test
    void infoShowsIgnoredJvmPropertiesWhenPolicyIsOff() throws Exception {
        Path config = TestSupport.writeConfig(dir, "policy.properties", "crypto.jvm.override.enabled=false");
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.warning.enabled=false")) {
            assertEquals(0, run(null, "info", "--config", config.toString()));
        }
        String output = out();
        assertTrue(output.contains("JVM -D    : 차단(crypto.jvm.override.enabled=false)"), output);
        assertTrue(output.contains("적용 -D   : 없음" + System.lineSeparator() + "무시 -D   : crypto.warning.enabled"),
                output);
        assertTrue(output.contains("경고 출력 : true [JAR 기본값]"), output);
        assertTrue(output.contains("[외부 설정 파일]"), output);
    }

    @Test
    void encryptAndVerifyWithJvmPropertiesOnly() throws Exception {
        Path key = TestSupport.writeRandomKeyFile(dir, "jvm-cli.key");
        FakeTerminal terminal = new FakeTerminal();
        terminal.secrets.add("dummy-jvm-cli-pw");
        String token;
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.key.type=key", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(key), "crypto.key.id=cli03")) {
            assertEquals(0, run(terminal, "encrypt"));
            token = out().trim();
            assertTrue(token.startsWith("ENC[v1:cli03:"), token);
            outBytes.reset();
            assertEquals(0, run(null, "verify", "--value", token));
            assertEquals("OK", out().trim());
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
    void cleanupNoteFollowsThePrimaryCodeAndRawCloseExceptionsAreOmitted() {
        for (Messages.Language lang : new Messages.Language[] {Messages.Language.KO, Messages.Language.EN}) {
            try (Messages.Scope ignored = Messages.use(lang)) {
                String cause = Messages.get("file.err.integrity");
                String notice = Messages.get("file.err.tempLeft", ".sample.jck-tmp");
                CredentialCryptoException primary = new CredentialCryptoException(CredentialCryptoException.Reason.INTEGRITY, cause);
                primary.addSuppressed(new java.io.IOException("private close diagnostic"));
                primary.addSuppressed(new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, notice));
                assertEquals(Messages.error("INTEGRITY", cause + " " + notice), CryptoCli.errorLine(primary));
            }
        }
    }

    @Test
    void displayedFileNamesStayOnOneLineWithoutChangingPaths() throws Exception {
        // zipfs 경로는 Windows에서도 CR, LF, TAB 및 C1 문자를 파일명에 담을 수 있다.
        Path archive = dir.resolve("names.zip");
        try (java.nio.file.FileSystem zip = java.nio.file.FileSystems.newFileSystem(
                java.net.URI.create("jar:" + archive.toUri()), java.util.Collections.singletonMap("create", "true"))) {
            Path raw = zip.getPath("/folder/한글🙂\r\n\t\u0085\u007F\u2028\u2029.txt");
            assertEquals("한글🙂\\u000D\\u000A\\u0009\\u0085\\u007F\\u2028\\u2029.txt",
                    io.javacryptokit.key.SecretFiles.fileName(raw));
            assertEquals(io.javacryptokit.key.SecretFiles.fileName(raw), JarConfigEditor.name(raw));
        }
        Path input = Files.write(dir.resolve("원본🙂\u2028.txt"), new byte[] {1, 2});
        Path output = dir.resolve("결과\u2029.jck");
        assertEquals(0, run(null, "file", "encrypt", "--in", input.toString(), "--out", output.toString()));
        assertTrue(Files.isRegularFile(output));
        assertTrue(out().contains("원본🙂\\u2028.txt") && out().contains("결과\\u2029.jck"), out());
        for (String lang : new String[] {"ko", "en"}) {
            errBytes.reset();
            assertEquals(1, run(null, "file", "encrypt", "--in", input.toString(), "--out", output.toString(), "--lang", lang));
            String message = err().trim();
            assertTrue(message.contains("INVALID_INPUT") && message.contains("결과\\u2029.jck"), message);
            assertTrue(message.contains(lang.equals("ko") ? "새 출력 이름" : "unused output name"), message);
            assertFalse(message.contains(dir.toString()) || message.contains("\u2029") || message.contains("12KB"));
        }
        Path originalJar = dir.resolve("한글\u2028.jar");
        assertEquals(dir.resolve("한글\u2028-configured.jar"), ConfigCommand.defaultOutputJar(originalJar));
    }

    @Test
    void blankConfigOptionFailsClosedInsteadOfUsingTheEmbeddedKey() {
        assertEquals(1, run(null, "info", "--config", "   "));
        String error = err();
        assertTrue(error.contains("[사유: CONFIGURATION]"), error);
        assertTrue(error.contains("비어 있습니다"), error);
        assertTrue(error.contains(" 조치: "), "다음 조치를 함께 안내해야 한다: " + error);
        assertFalse(out().contains("키 공급원"), "설정을 읽지 않고 중단해야 한다");
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
        assertFalse(out().contains("키 공급원"), "오타를 무시하고 내장 키로 진행하면 안 된다");
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
        assertEquals(1, run(null, "keygen", "--out", missing, "--reason", "x"));
        assertTrue(err().contains("키 파일을 만들 폴더가 없습니다"), err());
        assertFalse(err().contains("no-such-folder"), err());
    }
}
