package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.TestJars;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.i18n.Messages;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * doctor 진단과 CLI 도움말: 상태 코드·종료 코드, 모든 설정·명령·옵션이 영어·한국어 도움말에 있는지, 도움말 예제가 실제 명령
 * 정의와 맞는지, 도움말이 설정·키 없이 동작하고 비밀값을 보이지 않는지.
 */
class DoctorAndHelpTest {
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

    // ===================================================================================================
    // doctor
    // ===================================================================================================

    @Test
    void doctorPassesAndShowsThePublicKeyAsAStatusWithoutPolicyWarnings() throws Exception {
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            assertEquals(0, cli.run("doctor"), cli.out());
            assertTrue(log.warnings().isEmpty(), "doctor는 자동 경고를 한 번 더 내지 않는다: " + log.warnings());
        }
        String out = cli.out();
        assertTrue(out.contains("[PASS] 설정 로딩 정상"), out);
        // 등록된 키마다 따로 점검하고 키 상태는 사실로만 표시한다(공개 기본 키 두 개 모두 PASS).
        assertTrue(out.contains("[INFO] 기본 유형 pass, pass 기본 pass-default, key 기본 default"), out);
        assertTrue(out.contains("[PASS] 키 로딩 정상: default, 공개 기본 키, 지문 "), "키 상태는 사실로만 표시: " + out);
        assertTrue(out.contains("[PASS] 키 로딩 정상: pass-default, 공개 기본 키, 지문 3dca588c78a1...94453656"), out);
        for (String line : out.split("\\r?\\n")) assertTrue(CliHelp.width(line) <= 80, "doctor 80열 초과: " + line);
        assertTrue(out.contains("[PASS] 암호화·복호화·변조 거부 검사 정상"), out);
        assertFalse(out.contains("[WARN]"), "정책성 WARN 없음: " + out);
        assertTrue(out.trim().endsWith("결과: PASS"), out);
        // 점검하지 않은 Tomcat 기동·DB 연결은 PASS로 보이지 않는다.
        for (String line : out.split("\\r?\\n")) {
            if (line.startsWith("[PASS]")) assertFalse(line.contains("DB") || line.contains("Tomcat"), line);
        }
    }

    @Test
    void doctorFailsForMissingKeyFileEnvAndBadSettingsWithExitCodeOne() throws Exception {
        Path config = TestSupport.writeConfig(dir, "file.properties", "crypto.key.source=file", "crypto.key.id=prod01",
                "crypto.key.file=" + TestSupport.propertiesPath(dir.resolve("missing.key")));
        assertEquals(1, cli.run("doctor", "--config", config.toString()));
        assertTrue(cli.out().contains("[FAIL]") && cli.out().contains("조치:"), cli.out());
        assertFalse(cli.out().contains(dir.toString()), "전체 경로를 출력하지 않는다");
        Path env = TestSupport.writeConfig(dir, "env.properties", "crypto.key.source=env", "crypto.key.env=JCK_TEST_NOT_SET_42");
        assertEquals(1, cli.run("doctor", "--config", env.toString()));
        assertTrue(cli.out().contains("JCK_TEST_NOT_SET_42"), cli.out());
        Path bad = TestSupport.writeConfig(dir, "bad.properties", "crypto.warnning.enabled=false");
        assertEquals(1, cli.run("doctor", "--config", bad.toString()));
        assertTrue(cli.out().contains("'crypto.warning.enabled'"), cli.out());
    }

    @Test
    void rawKeyInAnExternalPropertiesFileIsNeverPrintedAndALostKeyNeverFallsBack() throws Exception {
        // 외부 Properties의 키 원문(crypto.key.embedded)은 동작은 유지하되(정책 결정 전) 어떤 진단 출력에도 나오면 안 된다.
        String rawKey = new String(Files.readAllBytes(TestSupport.writeRandomKeyFile(dir, "raw.key")), StandardCharsets.US_ASCII).trim();
        Path config = TestSupport.writeConfig(dir, "raw-key.properties", "crypto.key.source=embedded", "crypto.key.id=raw01",
                "crypto.key.embedded=" + rawKey);
        assertEquals(0, cli.run("doctor", "--config", config.toString()), cli.out());
        assertFalse(cli.out().contains("[WARN] 공개 기본 키"), cli.out());
        assertTrue(cli.out().contains("외부 설정 파일"), "키 위치를 실제 출처대로 안내: " + cli.out());
        assertFalse(cli.out().contains(rawKey) || cli.err().contains(rawKey), "doctor가 키 원문을 출력하면 안 된다");
        assertEquals(0, cli.run("info", "--config", config.toString()), cli.err());
        assertFalse(cli.out().contains(rawKey) || cli.err().contains(rawKey), "info가 키 원문을 출력하면 안 된다");
        // 키 원문이 잘못되면 공개 내장 키로 바꾸지 않고 FAIL(종료 코드 1)
        Path broken = TestSupport.writeConfig(dir, "broken-key.properties", "crypto.key.source=embedded", "crypto.key.id=raw01",
                "crypto.key.embedded=" + rawKey.substring(0, 20));
        assertEquals(1, cli.run("doctor", "--config", broken.toString()));
        assertTrue(cli.out().contains("[FAIL]"), cli.out());
        assertFalse(cli.out().contains(rawKey.substring(0, 20)), "잘못된 키 값도 출력하지 않는다");
    }

    @Test
    void doctorOfflineSkipsRemoteSourcesAndChecksTheirSettings() throws Exception {
        Path token = TestSupport.writeKeyFile(dir, "token", "s.dummytoken");
        Path config = TestSupport.writeConfig(dir, "vault.properties", "crypto.key.source=vault", "crypto.key.id=prod01",
                "crypto.vault.url=https://127.0.0.1:1", "crypto.vault.path=app/prod",
                "crypto.vault.token.file=" + TestSupport.propertiesPath(token));
        assertEquals(0, cli.run("doctor", "--offline", "--config", config.toString()), cli.out());
        assertTrue(cli.out().contains("[SKIP]") && cli.out().contains("SKIP 1"), cli.out());
        // 읽을 Secret 버전은 키 위치의 사실로만 보여 주고(버전 고정 권고 WARN 없음), 토큰 파일 권한도 정책 점검하지 않는다.
        assertTrue(cli.out().contains("버전 최신"), cli.out());
        assertFalse(cli.out().contains("[WARN]"), cli.out());
        assertFalse(cli.out().contains("s.dummytoken"), "토큰을 출력하면 안 된다");
    }

    @Test
    void doctorListsAppliedAndIgnoredJvmPropertiesOnePerLine() throws Exception {
        String ls = System.lineSeparator();
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.key.id=dr01")) {
            assertEquals(0, cli.run("doctor"), cli.out());
        }
        assertTrue(cli.out().contains("[INFO] 적용된 -D: crypto.key.id" + ls), "하나면 한 줄: " + cli.out());
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.key.id=dr01", "crypto.warning.enabled=false")) {
            assertEquals(0, cli.run("doctor"), cli.out());
        }
        String out = cli.out();
        assertTrue(out.contains("[INFO] 적용된 -D:" + ls + "       crypto.") && out.contains(ls + "       crypto.key.id" + ls)
                && out.contains(ls + "       crypto.warning.enabled" + ls), "여러 개면 한 줄에 하나씩: " + out);
        // 정책 때문에 적용되지 않은 -D는 WARN으로, 이름을 한 줄에 하나씩 쓰고 조치 한 줄을 붙인다.
        Path policy = TestSupport.writeConfig(dir, "policy.properties", "crypto.jvm.override.enabled=false");
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.lang=ko", "crypto.warning.enabled=false")) {
            assertEquals(0, cli.run("doctor", "--config", policy.toString()), cli.out());
        }
        out = cli.out();
        assertTrue(out.contains("[WARN] crypto.jvm.override.enabled=false라서 무시된 -D:" + ls + "       crypto."), out);
        assertTrue(out.contains(ls + "       crypto.lang" + ls) && out.contains(ls + "       crypto.warning.enabled" + ls), out);
        assertTrue(out.contains(ls + "       조치: "), out);
        assertTrue(out.trim().endsWith("결과: PASS (WARN 1)"), out);
        for (String line : out.split("\\r?\\n")) {
            assertTrue(CliHelp.width(line) <= 80, "doctor 80열 초과: " + line);
        }
    }

    @Test
    void doctorStatusCodesStayEnglishInEnglishMode() {
        assertEquals(0, cli.run("doctor", "--lang", "en"));
        assertTrue(cli.out().contains("[PASS] Settings loaded"), cli.out());
        assertTrue(cli.out().contains("Result: PASS"), cli.out());
    }

    // ===================================================================================================
    // 도움말
    // ===================================================================================================

    @Test
    void everyHelpTopicExistsInBothLanguagesAndPrints() {
        for (String topic : CliCommands.topics()) {
            for (Messages.Language language : Messages.Language.values()) {
                assertNotNull(Messages.text(language, topic), language + " " + topic);
            }
        }
        assertEquals(0, cli.run("help"));
        assertTrue(cli.out().contains("java-crypto-kit CLI"), cli.out());
        for (CliCommands.Spec spec : CliCommands.ALL) {
            List<String> args = new ArrayList<>();
            for (String word : spec.name.split(" ")) args.add(word);
            args.add("--help");
            assertEquals(0, cli.run(args.toArray(new String[0])), spec.name + ": " + cli.err());
            assertTrue(cli.out().startsWith(spec.name.replace("config help", "config")), spec.name + " -> " + cli.out());
            args.add("--lang");
            args.add("en");
            assertEquals(0, cli.run(args.toArray(new String[0])), spec.name);
        }
        assertEquals(0, cli.run("help", "vault"));
        assertEquals(0, cli.run("help", "aws-kms"));
        assertEquals(0, cli.run("config", "help"));
        assertEquals(0, cli.run("help", "config", "set"));
        assertTrue(cli.out().startsWith("config set"), cli.out());
        assertEquals(0, cli.run("file"));
        assertTrue(cli.out().contains("file encrypt"), cli.out());
    }

    @Test
    void configHelpListsEverySettingWithDefaultsInBothLanguages() throws Exception {
        for (String lang : new String[]{"ko", "en"}) {
            assertEquals(0, cli.run("config", "help", "--lang", lang));
            String out = cli.out();
            for (SettingCatalog.Setting setting : SettingCatalog.ALL) {
                // 표의 한 행(이름 뒤 공백) 또는 이름이 길어 줄바꿈한 행
                assertTrue(out.contains("  " + setting.key + " ") || out.contains("  " + setting.key + "\n")
                        || out.contains("  " + setting.key + "\r\n"), lang + " 도움말에 설정 누락: " + setting.key);
            }
            // 허용값·기본값은 SettingCatalog·JAR 기본값에서 만든다(예: crypto.lang 행).
            assertTrue(out.matches("(?s).*  crypto\\.lang +ko\\|en\\|auto +ko\\R.*"), out);
            assertTrue(out.contains("org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory"), out);
            assertTrue(out.contains(CryptoSettings.CONFIG_FILE_PROPERTY) && out.contains(CryptoSettings.CONFIG_FILE_ENV), out);
            assertFalse(out.contains("!setting."), "설명 누락: " + lang);
            assertFalse(out.contains("{settings}"));
            assertFalse(out.contains(TestSupport.publicKeyBase64()), "내장 키 값을 보이면 안 된다");
            // 80열 콘솔에서 가로 스크롤 없이 보인다(한글 2칸). 명령 예제 줄은 실행 위치에 따라 {jar} 이름 길이가 달라지므로
            // 배포 JAR 이름 기준 시험(everyHelpLineFitsIn80ColumnsWithTheReleaseJarName)에서 따로 검사한다.
            for (String line : out.split("\\r?\\n")) {
                if (line.trim().startsWith("java ")) continue;
                assertTrue(CliHelp.width(line) <= 80, lang + " 80열 초과(" + CliHelp.width(line) + "): " + line);
            }
        }
    }

    /** 배포 JAR 이름(도움말의 {jar} 자리에 실제로 들어가는 이름). */
    private static final String RELEASE_JAR = "java-crypto-kit-" + TestJars.VERSION + ".jar";

    @Test
    void everyHelpLineFitsIn80ColumnsWithTheReleaseJarName() {
        // 실제 JAR 이름을 넣은 최종 출력 기준(한글 2칸). 예외는 필수 옵션을 모두 쓴 복사용 예제 한 줄씩뿐이다(config embed-key,
        // config key remove, 비대화형 admin setup: 정확히 복사해 실행할 수 있는 명령을 우선). 설정 표({settings})는 config help
        // 시험이 따로 검사한다.
        for (Messages.Language language : Messages.Language.values()) {
            List<String> exceptions = new ArrayList<>();
            for (String topic : CliCommands.topics()) {
                String text = Messages.text(language, topic).replace("{jar}", RELEASE_JAR)
                        .replace("{version}", TestJars.VERSION).replace("{settings}", "")
                        .replace("{configured}", ConfigCommand.defaultOutputName(RELEASE_JAR));
                for (String line : text.split("\\r?\\n")) {
                    if (CliHelp.width(line) <= 80) continue;
                    // 예외: 필수 옵션을 모두 쓴 복사용 예제 한 줄씩(config embed-key, config key remove, 비대화형 admin setup)
                    boolean embed = topic.equals("config-embed-key")
                            && line.startsWith("  java -jar " + RELEASE_JAR + " config embed-key ");
                    boolean remove = topic.equals("config-key-remove")
                            && line.equals("  java -jar " + RELEASE_JAR + " config key remove --key-id p1 --operator ops");
                    boolean setup = topic.equals("admin-setup")
                            && line.equals("  java -jar " + RELEASE_JAR + " admin setup --operator ci --admin-pass-file admin.pw");
                    assertTrue(embed || remove || setup, language + " " + topic + " 80열 초과(" + CliHelp.width(line) + "): " + line);
                    exceptions.add(line);
                }
            }
            assertEquals(3, exceptions.size(), language + ": 80열 예외는 필수 옵션 예제 세 줄뿐: " + exceptions);
        }
    }

    @Test
    void helpNeverShowsSecretsAndWorksWithBrokenExternalConfig() throws Exception {
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY,
                dir.resolve("missing.properties").toString())) {
            assertEquals(0, cli.run("help"), cli.err());
            assertEquals(0, cli.run("config", "help"), cli.err());
            assertFalse(cli.out().contains(TestSupport.publicKeyBase64()), "내장 키 값을 보이면 안 된다");
            assertEquals(1, cli.run("info"), "실제 명령은 잘못된 설정을 알려야 한다");
        }
    }

    @Test
    void wrongCommandsAndOptionsPointToValidOnesAndHelp() {
        assertEquals(1, cli.run("encrpyt"));
        assertTrue(cli.err().contains("'encrypt'") && cli.err().contains("help"), cli.err());
        assertEquals(1, cli.run("config", "shwo"));
        assertTrue(cli.err().contains("show, history, set, embed-key"), cli.err());
        assertEquals(1, cli.run("file", "encrypt", "--inn", "a"));
        assertTrue(cli.err().contains("--in") && cli.err().contains("file encrypt --help"), cli.err());
        assertEquals(1, cli.run("help", "nothing"));
        assertTrue(cli.err().contains("config-set"), cli.err());
        assertEquals(1, cli.run("info", "--lang", "jp"));
        assertTrue(cli.err().contains("--lang"), cli.err());
    }

    /** 문서에 나온 옵션 이름(--xxx)과 설정 이름(crypto.xxx). */
    private static final Pattern OPTION = Pattern.compile("(?<![A-Za-z0-9-])--[a-z][a-z-]*[a-z]");
    private static final Pattern SETTING = Pattern.compile("crypto\\.[a-z0-9.-]*[a-z0-9]");

    @Test
    void helpDocumentsMatchCommandDefinitionsAndSettingsInBothLanguages() {
        Set<String> knownSettings = new LinkedHashSet<>(SettingCatalog.keys());
        knownSettings.add(CryptoSettings.CONFIG_FILE_PROPERTY);
        for (String topic : CliCommands.topics()) {
            String en = Messages.text(Messages.Language.EN, topic);
            String ko = Messages.text(Messages.Language.KO, topic);
            assertEquals(tokens(OPTION, en), tokens(OPTION, ko), "옵션 이름이 언어마다 다름: " + topic);
            assertEquals(tokens(SETTING, en), tokens(SETTING, ko), "설정 이름이 언어마다 다름: " + topic);
            for (String setting : tokens(SETTING, en)) {
                // 오타 예시로 일부러 적은 이름은 제외
                if (setting.equals("crypto.key.soruce") || setting.equals("crypto.policy")) continue;
                // 키 목록 항목: crypto.keys.<키 ID>.<항목>(틀 이름) 또는 실제 프로필 설정 이름
                if (setting.equals("crypto.keys") || SettingCatalog.isProfileSetting(setting)) continue;
                // crypto.key.*: crypto.key.로 시작하는 AES 키 설정 묶음 표기
                if (setting.equals("crypto.key") && en.contains("crypto.key.*")) continue;
                assertTrue(knownSettings.contains(setting), topic + " 도움말의 없는 설정 이름: " + setting);
            }
        }
        for (CliCommands.Spec spec : CliCommands.ALL) {
            String en = Messages.text(Messages.Language.EN, spec.topic);
            String ko = Messages.text(Messages.Language.KO, spec.topic);
            for (String option : spec.options()) {
                assertTrue(en.contains(option) && ko.contains(option), spec.name + " 도움말에 옵션 누락: " + option);
            }
            assertTrue(en.contains("--lang") && ko.contains("--lang"), spec.name);
        }
    }

    @Test
    void everyExampleCommandLineInTheHelpUsesARealCommandAndValidOptions() {
        // 예제 줄만 고른다: "-jar <jar 파일>" 또는 "-cp ... io.javacryptokit.cli.CryptoCli" 다음의 명령(설명 문장은 제외).
        Pattern example = Pattern.compile(
                "(?:-jar \\S*(?:\\.jar|\\{jar\\})\\S*|io\\.javacryptokit\\.cli\\.CryptoCli) ((?:config key|config|file|kms|admin password|admin) \\S+|\\S+)(.*)");
        int checked = 0;
        for (String topic : CliCommands.topics()) {
            for (Messages.Language language : Messages.Language.values()) {
                for (String line : Messages.text(language, topic).split("\n")) {
                    if (!line.trim().startsWith("java ") && !line.trim().startsWith("$new = java ")) continue;
                    Matcher m = example.matcher(line);
                    if (!m.find()) continue;
                    String name = m.group(1).trim();
                    if (name.startsWith("<") || name.equals("help")) continue;
                    CliCommands.Spec spec = CliCommands.find(name);
                    assertNotNull(spec, topic + "(" + language + ") 예제의 없는 명령: " + line);
                    for (String option : tokens(OPTION, m.group(2))) {
                        if (option.equals("--help") || option.equals("--lang")) continue;
                        assertTrue(spec.options().contains(option), topic + "(" + language + ") 예제의 잘못된 옵션 " + option + ": " + line);
                    }
                    checked++;
                }
            }
        }
        assertTrue(checked > 100, "검사한 예제 수: " + checked);
    }

    private static Set<String> tokens(Pattern pattern, String text) {
        Set<String> found = new LinkedHashSet<>();
        Matcher m = pattern.matcher(text);
        while (m.find()) found.add(m.group());
        return found;
    }
}
