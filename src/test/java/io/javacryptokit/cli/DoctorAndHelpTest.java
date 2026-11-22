package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

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
    void doctorPassesWithWarningForThePublicKey() {
        assertEquals(0, cli.run("doctor"), cli.out());
        String out = cli.out();
        assertTrue(out.contains("[PASS] 설정 로딩 정상"), out);
        assertTrue(out.contains("[PASS] 암복호화 자체 검증 정상"), out);
        assertTrue(out.contains("[WARN] 공개 기본 키"), out);
        assertTrue(out.contains("FAIL 0"), out);
        assertTrue(out.contains("DB 연결"), "doctor PASS가 DB 연결 PASS가 아님을 안내: " + out);
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
        assertTrue(cli.out().contains("[SKIP]"), cli.out());
        assertTrue(cli.out().contains("crypto.vault.ver"), "버전 미고정 경고: " + cli.out());
        assertFalse(cli.out().contains("s.dummytoken"), "토큰을 출력하면 안 된다");
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
    void configHelpListsEverySettingWithDefaultsInBothLanguages() {
        for (String lang : new String[]{"ko", "en"}) {
            assertEquals(0, cli.run("config", "help", "--lang", lang));
            String out = cli.out();
            for (SettingCatalog.Setting setting : SettingCatalog.ALL) {
                assertTrue(out.contains("  " + setting.key + "\n") || out.contains("  " + setting.key + "\r\n"),
                        lang + " 도움말에 설정 누락: " + setting.key);
            }
            assertTrue(out.contains(CryptoSettings.CONFIG_FILE_PROPERTY) && out.contains(CryptoSettings.CONFIG_FILE_ENV), out);
            assertFalse(out.contains("!setting."), "설명 누락: " + lang);
            assertFalse(out.contains("{settings}"));
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
                "(?:-jar \\S*(?:\\.jar|\\{jar\\})\\S*|io\\.javacryptokit\\.cli\\.CryptoCli) ((?:config|file|kms) \\S+|\\S+)(.*)");
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
