package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.KeyType;
import io.javacryptokit.TestJars;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.key.KeyResolver;
import io.javacryptokit.key.PassKdf;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code config key add / use / remove}: 재료(생성·파일·입력·다른 JAR·pass 백업)와 공급(embedded·file·env)의 조합, 외부 키 지문 고정,
 * 키 ID 규칙(공개 기본 키 전용·이미 등록·이력 사용 = 같은 키 복원만), 기본 키 변경 분리, 사유 필수, 모든 키 변경의 CHANGE 확인,
 * 자동 생성값의 대화형 1회 표시·비대화형 보호, 생성값의 재등록·과거 암호문 복구, 이력의 키 기록, 이전 버전 JAR.
 */
class ConfigKeyTest {
    private static final String REASON_PROMPT = "사유(비밀값 제외): ";
    private static final String CHANGE_PROMPT = "계속하려면 CHANGE를 입력하세요(그 외 입력은 취소): ";

    @TempDir
    Path dir;
    private CliHarness cli;
    private Path jar;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        cli = new CliHarness();
        jar = CliHarness.configure(TestJars.build(dir.resolve("java-crypto-kit-0.1.0.jar")), CliHarness.ADMIN_PASSWORD);
    }

    @AfterEach
    void tearDown() throws Exception {
        cli.close();
    }

    @Test
    void addPassFromHiddenInputTwiceKeepsTheDefaultUntilUseOrActive() throws Exception {
        Path out = dir.resolve("p1.jar");
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.lines.add("앱 Passphrase 키 추가");
        terminal.secrets.add("dummy-app-passphrase");
        terminal.secrets.add("dummy-app-passphrase");
        terminal.lines.add("CHANGE");
        assertEquals(0, cli.run(terminal, "config", "key", "add", "--key-id", "app-pass", "--operator", "123456",
                "--jar", Files.copy(jar, out).toString()), cli.err());
        // 사유 → 재료(숨김 입력 2회) → 바꿀 내용 → CHANGE 확인 순서
        assertEquals(Arrays.asList(REASON_PROMPT, "Passphrase(입력 숨김): ", "Passphrase 확인(입력 숨김): ", CHANGE_PROMPT),
                terminal.prompts, "사유 다음 입력은 숨김 2회 후 CHANGE 확인");
        String screen = String.join("\n", terminal.printed);
        assertTrue(screen.startsWith("키를 추가합니다(기존 암호문은 그대로):\n  현재 JAR p1.jar 갱신"), screen);
        assertTrue(screen.contains("  crypto.keys.app-pass.embedded (비공개)"), screen);
        assertTrue(screen.contains("\n  사유: 앱 Passphrase 키 추가\n"), "확인 화면에 사유를 보여 준다: " + screen);
        assertFalse(screen.contains("dummy-app-passphrase"), "직접 입력한 Passphrase는 다시 보여 주지 않는다(자동 생성값만 표시)");
        String result = cli.out();
        assertTrue(result.contains("crypto.keys.app-pass.type ((없음) -> pass)"), result);
        assertTrue(result.contains("crypto.keys.app-pass.kdf.iterations ((없음) -> 600000)"), result);
        assertTrue(result.matches("(?s).*추가 키   : app-pass \\(pass, embedded, 지문 [0-9a-f]{12}\\.\\.\\.[0-9a-f]{8}\\).*"), result);
        assertFalse(result.contains("dummy-app-passphrase") || cli.err().contains("dummy-app-passphrase"), "Passphrase 미출력");

        CryptoSettings settings = jarSettings(out);
        KeyProfile profile = settings.profile("app-pass");
        assertEquals(KeyType.PASS, profile.type());
        assertEquals(jarSettings(jar).activeProfile(KeyType.PASS).id(), settings.activeProfile(KeyType.PASS).id(), "추가만으로 기본 키는 바뀌지 않는다");
        // JAR에는 파생 키만 들어 있다: 같은 Salt·반복으로 다시 파생하면 같은 지문.
        byte[] derived = PassKdf.derive(PassKdf.normalize("dummy-app-passphrase".toCharArray()), profile.salt(), 600_000);
        assertEquals(KeyResolver.fingerprint(derived), CryptoService.of(settings).keyFingerprint(profile));
        assertFalse(new String(Files.readAllBytes(out), StandardCharsets.ISO_8859_1).contains("dummy-app-passphrase"),
                "Passphrase 원문은 JAR에 없다");

        // 기본 키는 config key use로만 바꾼다(새 JAR 생성도 CHANGE 확인, 사유 필수).
        Path used = dir.resolve("p2.jar");
        assertEquals(1, cli.run("config", "key", "use", "--key-id", "app-pass", "--operator", "123456", "--yes",
                "--jar", out.toString()));
        assertTrue(cli.err().contains("--reason"), "사유 없으면 비대화형 실행은 멈춘다: " + cli.err());
        assertEquals(1, cli.run("config", "key", "use", "--key-id", "app-pass", "--operator", "123456", "--reason", "전환",
                "--jar", out.toString()));
        assertTrue(cli.err().contains("CHANGE") && cli.err().contains("--yes"), cli.err());
        assertFalse(Files.exists(used));
        assertEquals(0, cli.run("config", "key", "use", "--key-id", "app-pass", "--operator", "123456", "--reason", "전환",
                "--yes", "--jar", Files.copy(out, used).toString()), cli.err());
        assertTrue(cli.out().contains("crypto.key.active.pass (" + jarSettings(jar).activeProfile(KeyType.PASS).id())
                && cli.out().contains("기본 키   : pass=app-pass"), cli.out());
        assertEquals("app-pass", jarSettings(used).activeProfile(KeyType.PASS).id());
        assertEquals(jarSettings(jar).activeProfile(KeyType.KEY).id(), jarSettings(used).activeProfile(KeyType.KEY).id(), "다른 유형의 기본 키는 그대로");
        assertEquals(1, cli.run("config", "key", "use", "--key-id", "app-pass", "--operator", "123456", "--reason", "x", "--yes",
                "--jar", used.toString()));
        assertTrue(cli.err().contains("이미 pass 유형의 기본 키"), cli.err());
        assertEquals(1, cli.run("config", "key", "use", "--key-id", "app-pass", "--type", "key", "--operator", "123456",
                "--reason", "x", "--yes", "--jar", used.toString()));
        assertTrue(cli.err().contains("[사유: CONFIGURATION]"), cli.err());
    }

    @Test
    void passphraseInputErrorsAndThePublicPassphraseAreRejectedWithoutChangingTheJar() throws Exception {
        Object[][] cases = {
                {"dummy-one", "dummy-two", "두 번 입력한 Passphrase가 다릅니다"},
                {"   ", "   ", "[사유: INVALID_INPUT]"},
                {"java-crypto-kit-public-passphrase-v1", "java-crypto-kit-public-passphrase-v1", "공개된 기본 키 또는 공개된 기본 Passphrase"},
        };
        for (Object[] item : cases) {
            CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
            terminal.secrets.add((String) item[0]);
            terminal.secrets.add((String) item[1]);
            Path out = dir.resolve("bad.jar");
            assertEquals(1, cli.run(terminal, "config", "key", "add", "--key-id", "p9", "--operator", "123456", "--reason", "x",
                    "--yes", "--jar", jar.toString()));
            assertTrue(cli.err().contains((String) item[2]), cli.err());
            assertFalse(Files.exists(out), "실패하면 결과 JAR를 만들지 않는다");
        }
        // 짧은 Passphrase도 실제 오류가 아니므로 받는다(길이 정책 없음).
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.secrets.add("a");
        terminal.secrets.add("a");
        assertEquals(0, cli.run(terminal, "config", "key", "add", "--key-id", "p9", "--operator", "123456", "--reason", "x",
                "--yes", "--jar", Files.copy(jar, dir.resolve("short.jar")).toString()), cli.err());
        // 사유를 묻는 질문에 빈 값을 넣으면 Passphrase를 묻기 전에 멈춘다(아무것도 바뀌지 않음).
        CliHarness.FakeTerminal empty = new CliHarness.FakeTerminal();
        empty.lines.add(" ");
        assertEquals(1, cli.run(empty, "config", "key", "add", "--key-id", "p10", "--operator", "123456", "--yes",
                "--jar", jar.toString()));
        assertTrue(cli.err().contains("사유를 입력하지 않아 중단했습니다"), cli.err());
        assertEquals(Arrays.asList(REASON_PROMPT), empty.prompts, "재료를 묻기 전에 멈춘다");
        assertFalse(Files.exists(dir.resolve("noreason.jar")));
    }

    @Test
    void nonInteractiveGenerationNeedsAnExportFileAndNeverPrintsTheValue() throws Exception {
        // 대화형 터미널이 없으면 생성값을 보여 줄 곳이 없으므로 --export 없이는 만들기 전에 멈춘다.
        Path noExport = dir.resolve("no-export.jar");
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "gen-x", "--generate", "--operator", "123456",
                "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("--export") && cli.err().contains("생성 전에 중단했습니다"), cli.err());
        assertFalse(Files.exists(noExport));

        Path passOut = dir.resolve("gen-pass.jar");
        Path exported = dir.resolve("gen-pass.backup");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "gen-pass", "--generate", "--export", exported.toString(),
                "--operator", "123456", "--reason", "생성", "--yes", "--jar", Files.copy(jar, passOut).toString()),
                cli.err());
        // pass 내보내기 = 복원 백업: 머리줄, 키 ID, KDF, 반복 횟수, Salt, 전체 지문, Passphrase
        List<String> lines = Arrays.asList(new String(Files.readAllBytes(exported), StandardCharsets.UTF_8).split("\n"));
        assertEquals(KeyringCommand.PassBackup.HEADER, lines.get(0));
        KeyProfile profile = jarSettings(passOut).profile("gen-pass");
        String fingerprint = CryptoService.of(jarSettings(passOut)).keyFingerprint(profile);
        assertTrue(lines.contains("key-id=gen-pass") && lines.contains("kdf=pbkdf2-sha256") && lines.contains("kdf.iterations=600000"),
                lines.toString());
        assertTrue(lines.contains("salt=" + Base64.getEncoder().encodeToString(profile.salt())), lines.toString());
        assertTrue(lines.contains("fingerprint=" + fingerprint), lines.toString());
        String passphrase = lines.get(lines.size() - 1).substring("passphrase=".length());
        assertTrue(passphrase.matches("[A-Za-z0-9]{32}"), "생성한 Passphrase(32자)");
        assertEquals(fingerprint, KeyResolver.fingerprint(PassKdf.derive(PassKdf.normalize(passphrase.toCharArray()),
                profile.salt(), 600_000)), "백업의 Passphrase·Salt = 등록한 키");
        assertFalse(cli.out().contains(passphrase) || cli.err().contains(passphrase), "비대화형 실행은 생성값을 출력하지 않는다");
        assertTrue(cli.out().contains("내보내기  : " + exported.toAbsolutePath().normalize()), cli.out());
        // 내보낼 파일이 이미 있으면 덮어쓰지 않고 아무것도 바꾸지 않는다.
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "gen-2", "--generate", "--export", exported.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("덮어쓰지 않으니"), cli.err());
        assertFalse(Files.exists(dir.resolve("x.jar")));

        // key 내보내기 = keygen 키 파일과 같은 표준 Base64 한 줄(32바이트)
        Path keyOut = dir.resolve("gen-key.jar");
        Path keyFile = dir.resolve("gen-aes.key");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "gen-aes", "--type", "key", "--generate", "--export",
                keyFile.toString(), "--active", "--operator", "123456", "--reason", "생성", "--yes", "--jar", Files.copy(jar, keyOut).toString()), cli.err());
        byte[] keyLine = Files.readAllBytes(keyFile);
        assertEquals(45, keyLine.length, "Base64 44자 + 줄바꿈(keygen과 같음)");
        assertTrue(cli.out().contains("crypto.key.active.key ((비어 있음) -> gen-aes)"), cli.out());
        assertEquals(0, cli.run("fingerprint", "--key-file", keyFile.toString()), cli.err());
        String filePrint = cli.out().replaceAll("(?s).*키 지문   : ([0-9a-f]{64}).*", "$1");
        assertEquals(filePrint, CryptoService.of(jarSettings(keyOut)).keyFingerprint(jarSettings(keyOut).profile("gen-aes")),
                "내보낸 AES 키 = 등록한 키");
        assertEquals("gen-aes", jarSettings(keyOut).activeProfile(KeyType.KEY).id());
    }

    @Test
    void interactiveGenerationShowsTheValueOnceAndThatValueCanBeRegisteredAgain() throws Exception {
        // pass: 대화형 터미널에만 한 번 보여 준다(표준 출력·표준 오류에는 없음). 값 한 줄에는 라벨·공백이 없다.
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        Path a = dir.resolve("a.jar");
        assertEquals(0, cli.run(terminal, "config", "key", "add", "--key-id", "gen1", "--generate", "--operator", "123456",
                "--reason", "신규 키", "--yes", "--jar", Files.copy(jar, a).toString()), cli.err());
        List<String> shown = terminal.printed;
        assertEquals(9, shown.size(), shown.toString());
        assertEquals("", shown.get(0), "결과 줄과 생성값 묶음 사이의 빈 줄");
        assertEquals("유형      : pass", shown.get(1));
        assertEquals("키 ID     : gen1", shown.get(2));
        assertEquals("생성값    : Passphrase(32자) - 다음 줄 전체가 값", shown.get(3));
        String passphrase = shown.get(4);
        assertTrue(passphrase.matches("[A-Za-z0-9]{32}"), "값 한 줄만: " + passphrase);
        KeyProfile profile = jarSettings(a).profile("gen1");
        String salt = Base64.getEncoder().encodeToString(profile.salt());
        String fingerprint = CryptoService.of(jarSettings(a)).keyFingerprint(profile);
        assertEquals("복원 정보 : pbkdf2-sha256, 600000회, Salt " + salt, shown.get(5));
        assertEquals("키 지문   : " + fingerprint, shown.get(6));
        assertEquals("안내      : 값과 복원 정보를 지금 따로 안전하게 보관하세요.", shown.get(7));
        assertEquals("            조회·이력에서 다시 볼 수 없습니다.", shown.get(8));
        for (String line : shown) assertTrue(CliHelp.width(line) <= 80, "80열: " + line);
        assertFalse(cli.out().contains(passphrase) || cli.err().contains(passphrase), "표준 출력·오류에는 생성값이 없다");
        assertEquals(0, cli.run("config", "history", "--jar", a.toString()), cli.err());
        // 이력: 원문(Passphrase)은 없고, 관리정보(Salt·KDF·반복 횟수·전체 지문·Salt SHA-256)는 마스킹 없이 보인다.
        assertFalse(cli.out().contains(passphrase), "이력에 원문이 없다: " + cli.out());
        String ls = System.lineSeparator();
        assertTrue(cli.out().contains("    crypto.keys.gen1.salt: (없음) -> " + salt), cli.out());
        assertTrue(cli.out().contains("    키 gen1: (없음) -> pass, embedded, 생성" + ls + "      키 지문: " + fingerprint + ls
                + "      KDF: pbkdf2-sha256, 600,000회" + ls + "      Salt SHA-256:" + ls + "        "
                + KeyringView.saltSha256(salt)), cli.out());
        assertTrue(cli.out().contains("    crypto.keys.gen1.kdf.iterations: (없음) -> 600000"), cli.out());
        String oldToken = CryptoService.of(jarSettings(a)).encryptText("dummy-old".toCharArray(), null, "gen1");

        // 화면의 값만 한 줄 파일로 다시 등록하면(새 JAR) 새 Salt로 새 키가 된다: 지문이 달라 예전 암호문은 복호화되지 않는다.
        Path plainFile = Files.write(dir.resolve("copied.pass"), (passphrase + "\r\n").getBytes(StandardCharsets.UTF_8));
        Path b = dir.resolve("b.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "gen1", "--from-file", plainFile.toString(), "--operator",
                "123456", "--reason", "재등록", "--yes", "--jar", Files.copy(jar, b).toString()), cli.err());
        assertTrue(cli.out().contains("Salt      : 새로 만듦(같은 Passphrase라도 이전에 등록한 키와 다른 키)"), cli.out());
        assertNotEquals(fingerprint, CryptoService.of(jarSettings(b)).keyFingerprint(jarSettings(b).profile("gen1")));
        CredentialCryptoException failure = assertThrows(CredentialCryptoException.class,
                () -> CryptoService.of(jarSettings(b)).decryptText(oldToken));
        assertEquals(CredentialCryptoException.Reason.INTEGRITY, failure.getReason(), "다른 Salt = 다른 키");

        // 화면의 값 + 복원 정보로 백업 파일을 만들면(원본 JAR 없이) 같은 키로 되살려 예전 암호문이 복호화된다.
        String backup = KeyringCommand.PassBackup.HEADER + "\nkey-id=gen1\nkdf=pbkdf2-sha256\nkdf.iterations=600000\nsalt=" + salt
                + "\nfingerprint=" + fingerprint + "\npassphrase=" + passphrase + "\n";
        Path backupFile = Files.write(dir.resolve("gen1.backup"), backup.getBytes(StandardCharsets.UTF_8));
        Path c = dir.resolve("c.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "gen1", "--from-file", backupFile.toString(), "--operator",
                "123456", "--reason", "복구", "--yes", "--jar", Files.copy(jar, c).toString()), cli.err());
        assertTrue(cli.out().contains("복원      : 백업과 같은 키(키 ID·KDF·반복 횟수·Salt·지문 일치)"), cli.out());
        assertEquals("dummy-old", CryptoService.of(jarSettings(c)).decryptText(oldToken), "과거 암호문 복호화");

        // key: 화면의 값 = 표준 Base64 한 줄(32바이트). 그 줄을 키 파일로 저장하면 지문이 같고, 같은 키 ID로 다시 등록하면 복호화된다.
        CliHarness.FakeTerminal keyTerminal = new CliHarness.FakeTerminal();
        Path k = dir.resolve("k.jar");
        assertEquals(0, cli.run(keyTerminal, "config", "key", "add", "--key-id", "gen-k1", "--type", "key", "--generate",
                "--operator", "123456", "--reason", "신규 AES 키", "--yes", "--jar", Files.copy(jar, k).toString()), cli.err());
        assertEquals(Arrays.asList("", "유형      : key", "키 ID     : gen-k1", "생성값    : AES 키(표준 Base64, 32바이트) - 다음 줄 전체가 값"),
                keyTerminal.printed.subList(0, 4));
        String keyLine = keyTerminal.printed.get(4);
        assertEquals(32, Base64.getDecoder().decode(keyLine).length);
        assertEquals("안내      : 지금 따로 안전하게 보관하세요. 조회·이력에서 다시 볼 수 없습니다.", keyTerminal.printed.get(5));
        assertFalse(cli.out().contains(keyLine) || cli.err().contains(keyLine));
        String keyToken = CryptoService.of(jarSettings(k)).encryptText("dummy-key".toCharArray(), null, "gen-k1");
        Path copiedKey = Files.write(dir.resolve("copied.key"), (keyLine + "\n").getBytes(StandardCharsets.US_ASCII));
        assertEquals(KeyResolver.fingerprint(KeyResolver.readKeyFile(copiedKey, "k")),
                CryptoService.of(jarSettings(k)).keyFingerprint(jarSettings(k).profile("gen-k1")), "화면 값 = 등록한 키");
        Path k2 = dir.resolve("k2.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "gen-k1", "--type", "key", "--from-file", copiedKey.toString(),
                "--operator", "123456", "--reason", "복구", "--yes", "--jar", Files.copy(jar, k2).toString()), cli.err());
        assertEquals("dummy-key", CryptoService.of(jarSettings(k2)).decryptText(keyToken));
    }

    @Test
    void passBackupRestoresTheSameKeyAndReusedKeyIdsNeedTheSameRecordedKey() throws Exception {
        // 원본 JAR A1: pass 키를 생성해 백업으로 내보내고, 그 키로 암호문을 만든다.
        Path a1 = dir.resolve("a1.jar");
        Path backup = dir.resolve("app-pass.backup");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "app-pass", "--generate", "--export", backup.toString(),
                "--operator", "123456", "--reason", "생성", "--yes", "--jar", Files.copy(jar, a1).toString()), cli.err());
        String fingerprint = CryptoService.of(jarSettings(a1)).keyFingerprint(jarSettings(a1).profile("app-pass"));
        String token = CryptoService.of(jarSettings(a1)).encryptText("dummy-db-password".toCharArray(), null, "app-pass");
        // 원본 JAR가 없어도 백업만으로 새 JAR에 같은 키를 되살린다(같은 지문, 과거 암호문 복호화).
        Path fresh = dir.resolve("fresh.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "app-pass", "--from-file", backup.toString(), "--operator",
                "123456", "--reason", "복구", "--yes", "--jar", Files.copy(jar, fresh).toString()), cli.err());
        assertTrue(cli.out().contains("복원      : 백업과 같은 키"), cli.out());
        assertEquals(fingerprint, CryptoService.of(jarSettings(fresh)).keyFingerprint(jarSettings(fresh).profile("app-pass")));
        assertEquals("dummy-db-password", CryptoService.of(jarSettings(fresh)).decryptText(token));
        // --from-jar: 원본 JAR가 있으면 원문 없이 프로필(파생 키·Salt·KDF)을 옮긴다.
        Path copied = dir.resolve("copied.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "app-pass", "--from-jar", a1.toString(), "--operator",
                "123456", "--reason", "이관", "--yes", "--jar", Files.copy(jar, copied).toString()), cli.err());
        assertEquals("dummy-db-password", CryptoService.of(jarSettings(copied)).decryptText(token));

        // 백업 오류는 구분해 알리고 JAR를 만들지 않는다: 다른 키 ID, 고친 Salt(지문 불일치), 빠진 항목, key 유형으로 등록.
        String text = new String(Files.readAllBytes(backup), StandardCharsets.UTF_8);
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "other", "--from-file", backup.toString(), "--operator",
                "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("백업 파일의 키 ID(app-pass)와 --key-id(other)가 다릅니다"), cli.err());
        String otherSalt = Base64.getEncoder().encodeToString(PassKdf.newSalt());
        Path editedSalt = Files.write(dir.resolve("edited.backup"),
                text.replaceAll("salt=[A-Za-z0-9+/=]+", "salt=" + otherSalt).getBytes(StandardCharsets.UTF_8));
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "app-pass", "--from-file", editedSalt.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("[사유: KEY_SOURCE]") && cli.err().contains("백업의 키 지문과 다릅니다"), cli.err());
        Path missing = Files.write(dir.resolve("missing.backup"),
                text.replaceAll("fingerprint=[0-9a-f]{64}\n", "").getBytes(StandardCharsets.UTF_8));
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "app-pass", "--from-file", missing.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("백업 파일 형식이 올바르지 않습니다(항목: fingerprint)"), cli.err());
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "app-pass", "--type", "key", "--from-file", backup.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("pass 키 백업 파일입니다"), cli.err());
        for (String name : new String[] {"e1.jar", "e2.jar", "e3.jar", "e4.jar"}) assertFalse(Files.exists(dir.resolve(name)), name);
        // 앞의 BOM·Windows 줄바꿈(CRLF)이 붙은 백업도 같은 키로 복원한다(PowerShell 저장).
        Path crlf = Files.write(dir.resolve("crlf.backup"),
                ("﻿" + text.replace("\n", "\r\n")).getBytes(StandardCharsets.UTF_8));
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "app-pass", "--from-file", crlf.toString(), "--operator",
                "123456", "--reason", "복구", "--yes", "--jar", Files.copy(jar, dir.resolve("crlf.jar")).toString()), cli.err());
        assertEquals("dummy-db-password", CryptoService.of(jarSettings(dir.resolve("crlf.jar"))).decryptText(token));

        // 이력에서 쓰인 키 ID: 제거한 뒤 다시 등록하려면 이력의 기록(유형·전체 지문·KDF·반복 횟수·Salt 지문)과 같은 키여야 한다.
        Path a2 = dir.resolve("a2.jar");
        assertEquals(0, cli.run("config", "key", "remove", "--key-id", "app-pass", "--operator", "123456", "--reason", "회수",
                "--yes", "--jar", Files.copy(a1, a2).toString()), cli.err());
        // 같은 Passphrase라도 한 줄 파일(새 Salt)이면 다른 키라 거부한다(다른 항목: Salt, 키 지문).
        String passphrase = text.replaceAll("(?s).*\npassphrase=([^\n]*)\n.*", "$1");
        Path samePlain = Files.write(dir.resolve("same.pass"), passphrase.getBytes(StandardCharsets.UTF_8));
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "app-pass", "--from-file", samePlain.toString(), "--operator",
                "123456", "--reason", "x", "--yes", "--jar", a2.toString()));
        assertTrue(cli.err().contains("다른 키에 쓰였습니다") && cli.err().contains("키 지문") && cli.err().contains("Salt"),
                cli.err());
        // 새로 생성하는 재료는 같은 키일 수 없으므로 입력·생성 전에 거부한다.
        assertEquals(1, cli.run(new CliHarness.FakeTerminal(), "config", "key", "add", "--key-id", "app-pass", "--generate",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", a2.toString()));
        assertTrue(cli.err().contains("config history"), cli.err());
        // 백업으로는 같은 키라 되살릴 수 있다(이력 확인 + 백업 지문 확인).
        Path a3 = dir.resolve("a3.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "app-pass", "--from-file", backup.toString(), "--operator",
                "123456", "--reason", "복구", "--yes", "--jar", Files.copy(a2, a3).toString()), cli.err());
        assertEquals("dummy-db-password", CryptoService.of(jarSettings(a3)).decryptText(token));
        assertEquals(0, cli.run("config", "history", "--jar", a3.toString()), cli.err());
        assertTrue(cli.out().contains("표시 범위 : pass 관련 3건(전체 4건)"), cli.out());
        assertTrue(cli.out().contains("pass, embedded, 복원" + System.lineSeparator() + "      키 지문: " + fingerprint),
                cli.out());
    }

    @Test
    void aesKeyRestoreNeedsTheSameKeyBytesAndKeyIdAndKeyFilesToleratePowerShellSaving() throws Exception {
        Path k1 = TestSupport.writeRandomKeyFile(dir, "k1.key");
        Path k2 = TestSupport.writeRandomKeyFile(dir, "k2.key");
        Path a = dir.resolve("a.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "app-key", "--type", "key", "--from-file", k1.toString(),
                "--operator", "123456", "--reason", "등록", "--yes", "--jar", Files.copy(jar, a).toString()), cli.err());
        String token = CryptoService.of(jarSettings(a)).encryptText("dummy-old".toCharArray(), null, "app-key");
        // 같은 키 ID + 같은 키 바이트를 새 JAR에 등록하면 과거 암호문이 복호화된다. 키 ID가 다르면 그 암호문의 키를 찾지 못한다.
        Path b = dir.resolve("b.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "app-key", "--type", "key", "--from-file", k1.toString(),
                "--operator", "123456", "--reason", "복구", "--yes", "--jar", Files.copy(jar, b).toString()), cli.err());
        assertEquals("dummy-old", CryptoService.of(jarSettings(b)).decryptText(token));
        Path c = dir.resolve("c.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "app-key2", "--type", "key", "--from-file", k1.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", Files.copy(jar, c).toString()), cli.err());
        CredentialCryptoException mismatch = assertThrows(CredentialCryptoException.class,
                () -> CryptoService.of(jarSettings(c)).decryptText(token));
        assertEquals(CredentialCryptoException.Reason.KEY_ID_MISMATCH, mismatch.getReason());
        // 이력에서 쓰인 키 ID: 다른 키는 거부, 같은 키는 복원으로 허용(결과에 표시).
        Path removed = dir.resolve("removed.jar");
        assertEquals(0, cli.run("config", "key", "remove", "--key-id", "app-key", "--operator", "123456", "--reason", "회수",
                "--yes", "--jar", Files.copy(a, removed).toString()), cli.err());
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "app-key", "--type", "key", "--from-file", k2.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", removed.toString()));
        assertTrue(cli.err().contains("다른 키에 쓰였습니다(다른 항목: 키 지문)") && cli.err().contains("--key-id"), cli.err());
        assertFalse(Files.exists(dir.resolve("x.jar")));
        // 유형이 다르면 유형·지문 차이만 알린다(KDF·반복 횟수·Salt는 둘 다 pass일 때만 비교).
        Path otherPass = Files.write(dir.resolve("other.pass"), "dummy-other-passphrase".getBytes(StandardCharsets.UTF_8));
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "app-key", "--from-file", otherPass.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", removed.toString()));
        assertTrue(cli.err().contains("다른 키에 쓰였습니다(다른 항목: 유형, 키 지문).") && cli.err().contains("--key-id"), cli.err());
        assertFalse(Files.exists(dir.resolve("y.jar")));
        Path restored = dir.resolve("restored.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "app-key", "--type", "key", "--from-file", k1.toString(),
                "--operator", "123456", "--reason", "복구", "--yes", "--jar", Files.copy(removed, restored).toString()),
                cli.err());
        assertTrue(cli.out().contains("복원      : 이력에 기록된 이 키 ID의 키와 같음(유형·전체 지문 일치)"), cli.out());
        assertEquals("dummy-old", CryptoService.of(jarSettings(restored)).decryptText(token));
        // PowerShell 5.1 저장(앞 BOM + CRLF)한 키 파일도 같은 키다. 라벨까지 복사한 줄은 다른 키가 되지 않고 형식 오류로 거부된다.
        String keyText = new String(Files.readAllBytes(k1), StandardCharsets.US_ASCII).trim();
        Path bom = Files.write(dir.resolve("bom.key"), ("﻿" + keyText + "\r\n").getBytes(StandardCharsets.UTF_8));
        assertEquals(KeyResolver.fingerprint(KeyResolver.readKeyFile(k1, "k")), KeyResolver.fingerprint(KeyResolver.readKeyFile(bom, "k")));
        Path labeled = Files.write(dir.resolve("labeled.key"), ("생성값    : " + keyText + "\n").getBytes(StandardCharsets.UTF_8));
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "lab", "--type", "key", "--from-file", labeled.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("[사유: KEY_SOURCE]") && cli.err().contains("표준 Base64"), cli.err());
        // 외부 공급원(키 파일)은 keygen 표준 Base64만 받는다: JAR 내부 저장 표현(obf1)은 키 파일 형식이 아니다.
        Path obf = Files.write(dir.resolve("obf.key"), (KeyResolver.encodeEmbedded(KeyResolver.readKeyFile(k1, "k")) + "\n")
                .getBytes(StandardCharsets.US_ASCII));
        assertThrows(IllegalArgumentException.class, () -> KeyResolver.readKeyFile(obf, "k"));
    }

    @Test
    void externalSourcesArePinnedAndKeyFilesCanBeRegisteredOnce() throws Exception {
        // file 공급원 pass 키: 등록할 때 한 번 읽어 지문을 고정한다(실행 중 값이 바뀌면 실패).
        Path passFile = Files.write(dir.resolve("svc.pass"), "dummy-service-pass\n".getBytes(StandardCharsets.UTF_8));
        Path out = dir.resolve("ext.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "svc-pass", "--source", "file", "--location",
                TestSupport.propertiesPath(passFile), "--operator", "123456", "--reason", "x", "--yes", "--jar", Files.copy(jar, out).toString()), cli.err());
        KeyProfile profile = jarSettings(out).profile("svc-pass");
        assertNotNull(profile.pinnedFingerprint());
        assertEquals(KeyResolver.fingerprint(PassKdf.derive(PassKdf.normalize("dummy-service-pass".toCharArray()),
                profile.salt(), 600_000)), profile.pinnedFingerprint());
        assertEquals(0, cli.run("config", "show", "--jar", out.toString()), cli.err());
        // 고정 지문 줄은 80열을 넘으므로 이름 다음 줄에 값을 쓴다(값은 자르지 않음).
        String ls = System.lineSeparator();
        assertTrue(cli.out().contains("  svc-pass: pass, file, 외부 키" + ls + "    키 지문:" + ls + "      "
                + profile.pinnedFingerprint() + " (고정 지문)"), cli.out());
        // AES 키 파일을 embedded로 등록하면 같은 키는 다른 키 ID로 다시 등록할 수 없다.
        Path aes = TestSupport.writeRandomKeyFile(dir, "biz.key");
        Path out2 = dir.resolve("ext2.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "biz-aes", "--type", "key", "--from-file", aes.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", Files.copy(out, out2).toString()), cli.err());
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "biz-aes2", "--type", "key", "--from-file", aes.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", out2.toString()));
        assertTrue(cli.err().contains("같은 키가 이미 키 ID biz-aes"), cli.err());
        // env 공급원 key 키: 지금 환경변수를 한 번 읽어 고정(테스트 환경변수는 Gradle이 넣는 더미 AES 키)
        String env = System.getenv(TestSupport.ENV_TEST_KEY);
        if (env != null) {
            Path out3 = dir.resolve("ext3.jar");
            assertEquals(0, cli.run("config", "key", "add", "--key-id", "env-aes", "--type", "key", "--source", "env",
                    "--location", TestSupport.ENV_TEST_KEY, "--operator", "123456", "--reason", "x", "--yes", "--jar", Files.copy(out2, out3).toString()), cli.err());
            byte[] key = Base64.getDecoder().decode(env.trim());
            assertEquals(KeyResolver.fingerprint(key), jarSettings(out3).profile("env-aes").pinnedFingerprint());
        }
        // 지금 읽을 수 없는 외부 위치는 등록하지 않는다(지문을 고정할 수 없음).
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "gone", "--source", "file", "--location",
                TestSupport.propertiesPath(dir.resolve("gone.pass")), "--operator", "123456", "--reason", "x", "--yes",
                "--jar", jar.toString()));
        assertTrue(cli.err().contains("[사유: KEY_SOURCE]"), cli.err());
        assertFalse(Files.exists(dir.resolve("gone.jar")));
    }

    @Test
    void fromJarCopiesTheDefinitionSoBothJarsShareTheKey() throws Exception {
        Path a = dir.resolve("a.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "shared", "--type", "key", "--generate", "--export",
                dir.resolve("shared.key").toString(), "--operator", "123456", "--reason", "x", "--yes", "--jar", Files.copy(jar, a).toString()), cli.err());
        Path b = dir.resolve("b.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "shared", "--from-jar", a.toString(), "--operator",
                "123456", "--reason", "x", "--yes", "--jar", Files.copy(jar, b).toString()), cli.err());
        CryptoService serviceA = CryptoService.of(jarSettings(a));
        CryptoService serviceB = CryptoService.of(jarSettings(b));
        assertEquals(serviceA.keyFingerprint(jarSettings(a).profile("shared")),
                serviceB.keyFingerprint(jarSettings(b).profile("shared")));
        String token = serviceA.encryptText("dummy".toCharArray(), null, "shared");
        assertEquals("dummy", serviceB.decryptText(token), "두 JAR가 같은 키를 쓴다");
        // 그 JAR에 없는 키 ID, 유형 불일치, 공급 옵션과 함께 쓰기는 거부한다.
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "other", "--from-jar", a.toString(), "--operator",
                "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("키 ID other"), cli.err());
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "shared", "--type", "pass", "--from-jar", a.toString(),
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("[사유: CONFIGURATION]"), cli.err());
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "shared", "--from-jar", a.toString(), "--source", "file",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("--from-jar"), cli.err());
    }

    @Test
    void keyIdRulesAndOptionCombinationsAreCheckedBeforeAnyInput() throws Exception {
        String[][] bad = {
                {"--key-id", "default", "--type", "key", "--generate"},             // 공개 기본 키 전용
                {"--key-id", "pass-default", "--generate"},                         // 공개 기본 키 전용
                {"--key-id", "bad id!", "--generate"},                              // 형식
                {"--key-id", "k1", "--generate", "--from-file", "x.key"},           // 재료 둘
                {"--key-id", "k1", "--export", "x.txt"},                            // --export는 --generate와만
                {"--key-id", "k1", "--source", "file"},                             // 위치 없음
                {"--key-id", "k1", "--location", "x"},                              // embedded에는 위치 없음
                {"--key-id", "k1", "--source", "env", "--location", "1BAD"},        // 환경변수 이름 형식
                {"--key-id", "k1", "--source", "file", "--location", "x", "--generate"}, // file은 생성 불가
                {"--key-id", "k1", "--type", "key"},                                // key embedded는 재료 필요
                {"--key-id", "k1", "--source", "hsm", "--location", "x"},           // 공급원 값
        };
        for (String[] options : bad) {
            CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
            String[] args = new String[options.length + 8];
            System.arraycopy(new String[] {"config", "key", "add"}, 0, args, 0, 3);
            System.arraycopy(options, 0, args, 3, options.length);
            System.arraycopy(new String[] {"--operator", "123456", "--yes", "--jar", jar.toString()}, 0, args,
                    3 + options.length, 5);
            assertEquals(1, cli.run(terminal, args), String.join(" ", options));
            assertTrue(terminal.prompts.isEmpty(), "사유·입력을 받기 전에 거부: " + String.join(" ", options));
            assertTrue(cli.err().startsWith("[java-crypto-kit] [사유: "), cli.err());
        }
        assertFalse(Files.exists(dir.resolve("java-crypto-kit-0.1.0-cfg.jar")), "거부하면 아무것도 만들지 않는다");
        // 그룹 안내·모르는 하위 명령
        assertEquals(0, cli.run("config", "key"));
        assertTrue(cli.out().contains("config key add") && cli.out().contains("config key remove"), cli.out());
        assertEquals(1, cli.run("config", "key", "rotate"));
        assertTrue(cli.err().contains("add, use, remove"), cli.err());
    }

    @Test
    void removeRefusesDefaultAndAesSlotKeysAndRemovedIdsCannotBeReusedForAnotherKey() throws Exception {
        Path aes = TestSupport.writeRandomKeyFile(dir, "old-aes.key");
        Path added = dir.resolve("r1.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "old-aes", "--type", "key", "--from-file", aes.toString(),
                "--active", "--operator", "123456", "--reason", "x", "--yes", "--jar", Files.copy(jar, added).toString()),
                cli.err());
        assertEquals(1, cli.run("config", "key", "remove", "--key-id", "old-aes", "--operator", "123456", "--reason", "x",
                "--yes", "--jar", added.toString()));
        assertTrue(cli.err().contains("key 유형의 기본 키라 제거할 수 없습니다"), cli.err());
        assertEquals(1, cli.run("config", "key", "remove", "--key-id", JarConfigEditor.read(jar).validated().legacyProfile().id(), "--operator", "123456", "--reason", "x",
                "--yes", "--jar", added.toString()));
        assertTrue(cli.err().contains("crypto.key.* AES 키라 제거할 수 없습니다"), cli.err());
        // 기본 AES 키를 crypto.key.*로 되돌린 뒤 제거한다(빈 값 = crypto.key.*를 따른다).
        Path back = dir.resolve("r2.jar");
        assertEquals(0, cli.run("config", "key", "use", "--key-id", JarConfigEditor.read(jar).validated().legacyProfile().id(), "--operator", "123456", "--reason", "x",
                "--yes", "--jar", Files.copy(added, back).toString()), cli.err());
        assertTrue(cli.out().contains("crypto.key.active.key (old-aes -> (비어 있음))"), cli.out());
        Path removed = dir.resolve("r3.jar");
        assertEquals(0, cli.run("config", "key", "remove", "--key-id", "old-aes", "--operator", "123456", "--yes",
                "--reason", "회전 완료", "--jar", Files.copy(back, removed).toString()), cli.err());
        assertTrue(cli.out().contains("제거 키   : old-aes"), cli.out());
        assertEquals(null, jarSettings(removed).profile("old-aes"));
        // 이력(key 유형): 명령·사유·항목별 이전 -> 이후(비밀 값은 표시만)·키 기록, 해시 체인 검증 정상
        assertEquals(0, cli.run("config", "history", "--type", "key", "--jar", removed.toString()), cli.err());
        String history = cli.out();
        assertTrue(history.contains("config key add  [key]") && history.contains("config key use  [key]")
                && history.contains("config key remove  [key]"), history);
        assertTrue(history.contains("    crypto.keys.old-aes.embedded: (없음) -> (비공개)"), history);
        assertTrue(history.contains("    crypto.keys.old-aes.embedded: (비공개) -> (없음)"), history);
        // 키 기록: 요약 줄(유형·공급원·출처) 아래에 같은 키 복원 확인용 64자 전체 지문(추가·제거 기록 모두 같은 키)
        String oldFingerprint = KeyResolver.fingerprint(Base64.getDecoder().decode(
                new String(Files.readAllBytes(aes), StandardCharsets.UTF_8).trim()));
        String ls = System.lineSeparator();
        assertTrue(history.contains("    키 old-aes: (없음) -> key, embedded, 파일" + ls + "      키 지문: " + oldFingerprint + ls),
                history);
        assertTrue(history.contains("    키 old-aes: key, embedded, 파일 -> (없음)" + ls + "      키 지문: " + oldFingerprint + ls),
                history);
        assertTrue(history.contains("    사유: 회전 완료") && history.contains("이력 검증 : 정상(4건"), history);
        for (String line : history.split("\\r?\\n")) assertTrue(CliHelp.width(line) <= 80, "80열: " + line);
        // 제거한 키 ID는 다른 키에 다시 쓸 수 없다(같은 키 ID가 다른 키를 가리키지 않게). 생성은 입력 전에 거부한다.
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        assertEquals(1, cli.run(terminal, "config", "key", "add", "--key-id", "old-aes", "--type", "key", "--generate",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", removed.toString()));
        assertTrue(cli.err().contains("config history"), cli.err());
        assertTrue(terminal.printed.isEmpty(), "생성값을 만들거나 보여 주지 않는다");
    }

    @Test
    void cancellingTheConfirmationChangesNothing() throws Exception {
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.lines.add("no");
        Path out = dir.resolve("cancel.jar");
        assertEquals(0, cli.run(terminal, "config", "key", "add", "--key-id", "k5", "--type", "key", "--generate",
                "--export", dir.resolve("k5.key").toString(), "--operator", "123456", "--reason", "x", "--jar", Files.copy(jar, out).toString()));
        assertTrue(cli.out().contains("취소했습니다"), cli.out());
        org.junit.jupiter.api.Assertions.assertArrayEquals(Files.readAllBytes(jar), Files.readAllBytes(out));
        assertFalse(Files.exists(dir.resolve("k5.key")), "취소하면 내보낼 파일도 만들지 않는다");
        assertEquals(Arrays.asList(CHANGE_PROMPT), terminal.prompts);
        assertFalse(String.join("\n", terminal.printed).contains("생성값"), "취소하면 생성값을 보여 주지 않는다");
    }

    @Test
    void olderJarsWithoutKeyListSupportAreNotGivenTheNewFormat() throws Exception {
        Path legacy = TestJars.buildLegacy(dir.resolve("java-crypto-kit-legacy.jar"));
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "k1", "--type", "key", "--generate", "--export",
                dir.resolve("k1.key").toString(), "--operator", "123456", "--reason", "x", "--yes", "--jar", legacy.toString()));
        assertTrue(cli.err().contains("예약된 설정 영역이 없습니다"), cli.err());
        assertFalse(Files.exists(dir.resolve("k1.key")), "거부하면 내보낼 파일도 만들지 않는다");
        Path keyFile = dir.resolve("k.key");
        assertEquals(0, cli.run("keygen", "--out", keyFile.toString(), "--reason", "x"), cli.err());
        byte[] before = Files.readAllBytes(legacy);
        assertEquals(1, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "prod01",
                "--operator", "123456", "--reason", "x", "--yes", "--jar", legacy.toString()));
        assertTrue(cli.err().contains("예약된 설정 영역이 없습니다"), cli.err());
        org.junit.jupiter.api.Assertions.assertArrayEquals(before, Files.readAllBytes(legacy));
        assertEquals(0, cli.run("config", "history", "--type", "key", "--jar", legacy.toString()), cli.err());
    }

    @Test
    void aRegisteredProfileLocationCanBeSetFirstAndChangedOnlyWithReasonAndConfirmation() throws Exception {
        // 등록된 Vault 프로필(제품의 key add와 같은 저장 경로로 기록, vault.ver 미지정). 실제 Vault에는 접속하지 않는다.
        String pin = KeyResolver.fingerprint(new byte[32]);
        java.util.Map<String, String> profile = new java.util.LinkedHashMap<>();
        profile.put("crypto.keys.qa-vault.type", "key");
        profile.put("crypto.keys.qa-vault.source", "vault");
        profile.put("crypto.keys.qa-vault.vault.path", "qa/key");
        profile.put("crypto.keys.qa-vault.vault.field", "key");
        profile.put("crypto.keys.qa-vault.fingerprint", pin);
        JarConfigEditor.apply(JarConfigEditor.read(jar), new JarConfigEditor.Change("key add", profile,
                java.util.Collections.<String>emptySet(), java.util.Collections.<ConfigHistory.Change>emptyList(), "qa", "등록"),
                java.time.Instant.now());
        String ver = "crypto.keys.qa-vault.vault.ver";
        byte[] registered = Files.readAllBytes(jar);
        // 사유 없음(비대화형), 확인 거절, 관리자 인증 실패: 모두 JAR 그대로
        assertEquals(1, cli.run("config", "set", ver + "=1", "--operator", "qa", "--yes", "--jar", jar.toString()));
        CliHarness.FakeTerminal no = new CliHarness.FakeTerminal();
        no.lines.add("no");
        assertEquals(0, cli.run(no, "config", "set", ver + "=1", "--operator", "qa", "--reason", "버전 고정",
                "--jar", jar.toString()));
        assertEquals(Arrays.asList(CHANGE_PROMPT), no.prompts);
        assertTrue((cli.out() + String.join("\n", no.printed)).contains(ver + " ((없음) -> 1)"), cli.out());
        org.junit.jupiter.api.Assertions.assertArrayEquals(registered, Files.readAllBytes(jar));
        cli.withCliJar(jar);
        assertEquals(1, cli.run("config", "set", ver + "=1", "--operator", "qa", "--reason", "버전 고정", "--yes",
                "--admin-pass-file", CliHarness.passFile(dir, "Wrong-admin-9")));
        assertTrue(cli.err().contains("[사유: ADMIN_AUTH]"), cli.err());
        cli.recordingGate();
        org.junit.jupiter.api.Assertions.assertArrayEquals(registered, Files.readAllBytes(jar));
        // 미등록 Key ID, 그 공급원에 없는 위치 항목, 프로필 정체 항목은 거부(JAR 그대로)
        assertEquals(1, cli.run("config", "set", "crypto.keys.no-such.vault.ver=1", "--operator", "qa", "--reason", "x",
                "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("[사유: CONFIGURATION]") && cli.err().contains("프로필이 없습니다"), cli.err());
        assertEquals(1, cli.run("config", "set", "crypto.keys.qa-vault.file=/tmp/qa.key", "--operator", "qa", "--reason", "x",
                "--yes", "--jar", jar.toString()));
        assertTrue(cli.err().contains("vault 공급원에서 쓰지 않는 항목"), cli.err());
        for (String identity : new String[]{"crypto.keys.qa-vault.type=pass", "crypto.keys.qa-vault.source=file",
                "crypto.keys.qa-vault.fingerprint=" + KeyResolver.fingerprint(new byte[]{1, 2, 3})}) {
            assertNotEquals(0, cli.run("config", "set", identity, "--operator", "qa", "--reason", "x", "--yes",
                    "--jar", jar.toString()), identity);
            assertTrue(cli.err().contains("config set으로 바꿀 수 없습니다"), cli.err());
        }
        org.junit.jupiter.api.Assertions.assertArrayEquals(registered, Files.readAllBytes(jar));
        // 처음 지정과 변경: 사유·확인(--yes) 뒤 같은 JAR에 기록, 이력에 남고 고정 지문은 그대로
        assertEquals(0, cli.run("config", "set", ver + "=1", "--operator", "qa", "--reason", "버전 고정", "--yes",
                "--jar", jar.toString()), cli.err());
        assertEquals("1", JarConfigEditor.read(jar).settings.getProperty(ver));
        assertEquals(0, cli.run("config", "set", ver + "=2", "--operator", "qa", "--reason", "버전 변경", "--yes",
                "--jar", jar.toString()), cli.err());
        assertEquals("2", JarConfigEditor.read(jar).settings.getProperty(ver));
        assertEquals(pin, jarSettings(jar).profile("qa-vault").pinnedFingerprint());
        assertEquals(0, cli.run("config", "history", "--type", "key", "--jar", jar.toString()), cli.err());
        assertTrue(cli.out().contains(ver + ": (없음) -> 1") && cli.out().contains(ver + ": 1 -> 2"), cli.out());
    }

    @Test
    void sixtyFourCharacterKeyIdsWorkForEveryStepAndLongerIdsAreRejected() throws Exception {
        char[] fill = new char[63];
        Arrays.fill(fill, 'a');
        String keyId = "k" + new String(fill);
        String passId = "p" + new String(fill);
        String fileId = "f" + new String(fill);
        Path aes = TestSupport.writeRandomKeyFile(dir, "long.key");
        Path passFile = Files.write(dir.resolve("long.pass"), "dummy-long-id-pass\n".getBytes(StandardCharsets.UTF_8));
        Path extFile = TestSupport.writeRandomKeyFile(dir, "long-ext.key");
        // 등록(KEY·PASS·외부 파일 공급원)과 활성화: 프로필 설정 이름이 80자를 넘어도 이력 검증을 통과해야 한다.
        assertEquals(0, cli.run("config", "key", "add", "--key-id", keyId, "--type", "key", "--from-file", aes.toString(), "--active",
                "--operator", "qa", "--reason", "x", "--yes", "--jar", jar.toString()), cli.err());
        assertEquals(0, cli.run("config", "key", "add", "--key-id", passId, "--from-file", passFile.toString(), "--active",
                "--operator", "qa", "--reason", "x", "--yes", "--jar", jar.toString()), cli.err());
        assertEquals(0, cli.run("config", "key", "add", "--key-id", fileId, "--type", "key", "--source", "file", "--location",
                TestSupport.propertiesPath(extFile), "--operator", "qa", "--reason", "x", "--yes", "--jar", jar.toString()), cli.err());
        assertEquals(0, cli.run("config", "history", "--all", "--jar", jar.toString()), cli.err());
        assertEquals(0, cli.run("config", "show", "--jar", jar.toString()), cli.err());
        // 암복호화: 키 ID로 선택
        CryptoService crypto = CryptoService.of(jarSettings(jar));
        for (String id : new String[]{keyId, passId, fileId}) {
            String token = crypto.encryptText("long-id".toCharArray(), null, id);
            assertTrue(token.startsWith("ENC[v1:" + id + ":"), id);
            assertEquals("long-id", crypto.decryptText(token));
        }
        // 제거 후 같은 키로 재등록(이력의 같은 키 복원), 이력 전체 검증
        assertEquals(0, cli.run("config", "key", "remove", "--key-id", fileId, "--operator", "qa", "--reason", "x", "--yes",
                "--jar", jar.toString()), cli.err());
        assertEquals(0, cli.run("config", "key", "add", "--key-id", fileId, "--type", "key", "--source", "file", "--location",
                TestSupport.propertiesPath(extFile), "--operator", "qa", "--reason", "x", "--yes", "--jar", jar.toString()), cli.err());
        assertEquals(0, cli.run("config", "history", "--all", "--jar", jar.toString()), cli.err());
        // 65자 Key ID는 JAR를 바꾸지 않고 거부
        byte[] before = Files.readAllBytes(jar);
        assertNotEquals(0, cli.run("config", "key", "add", "--key-id", keyId + "x", "--type", "key", "--generate",
                "--export", dir.resolve("too-long.key").toString(), "--operator", "qa", "--reason", "x", "--yes", "--jar", jar.toString()));
        org.junit.jupiter.api.Assertions.assertArrayEquals(before, Files.readAllBytes(jar));
        assertFalse(Files.exists(dir.resolve("too-long.key")));
    }

    /** 결과 JAR의 내부 설정(외부 설정·-D 없이 검증). */
    private static CryptoSettings jarSettings(Path jar) throws Exception {
        CryptoSettings settings = JarConfigEditor.read(jar).validated();
        assertNotNull(settings, "결과 JAR 설정은 검증을 통과해야 한다");
        return settings;
    }
}
