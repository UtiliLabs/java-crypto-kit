package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.TestJars;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.config.KeyProfile;
import io.javacryptokit.config.SettingCatalog;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.key.KeyResolver;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * CLI 관리자 비밀번호를 실제 확인 경로({@link AdminAccess})로 시험한다: 미설정 JAR의 차단과 최초 설정, 민감 명령의 인증(대화형·비밀번호
 * 파일·실패·취소), 비밀번호 변경, 다른 JAR 인증(--jar·--from-jar·--to-jar), 손상 Fail Closed, 키 관리정보 전체 표시와 SHOW 확인 뒤
 * 원문 표시·내보내기·재등록 복구, 이력 분류. Java API는 관리자 비밀번호와 무관하게 동작해야 한다.
 */
class AdminCliTest {
    private static final String PW = CliHarness.ADMIN_PASSWORD;
    private static final String ADMIN_PROMPT = "관리자 비밀번호(입력 숨김): ";

    @TempDir
    Path dir;
    private CliHarness cli;
    /** 미설정 새 버전 JAR(배포 JAR). */
    private Path fresh;
    /** 관리자 비밀번호(PW)를 설정한 JAR. */
    private Path app;
    private String pwFile;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        cli = new CliHarness();
        fresh = TestJars.build(dir.resolve("java-crypto-kit-0.1.0.jar"));
        app = CliHarness.configure(TestJars.build(dir.resolve("app.jar")), PW);
        pwFile = CliHarness.passFile(dir, PW);
    }

    @AfterEach
    void tearDown() throws Exception {
        cli.close();
    }

    private static CliHarness.FakeTerminal terminal(String... secrets) {
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.secrets.addAll(Arrays.asList(secrets));
        return terminal;
    }

    private List<String> files() throws Exception {
        try (Stream<Path> list = Files.list(dir)) {
            return list.map(p -> p.getFileName().toString()).sorted().collect(Collectors.toList());
        }
    }

    // ===================================================================================================
    // 미설정 JAR와 최초 설정
    // ===================================================================================================

    @Test
    void uninitializedJarRunsNoCommandAndHelpShowsOnlyTheSetupGuide() throws Exception {
        cli.withCliJar(fresh);
        Path plain = Files.write(dir.resolve("plain.txt"), "dummy".getBytes(StandardCharsets.UTF_8));
        List<String> before = files();
        String token = TestSupport.jarDefaults().encryptText("dummy-x");
        String[][] commands = {{"encrypt"}, {"decrypt"}, {"verify", "--value", token}, {"info"}, {"doctor"}, {"fingerprint"},
                {"file", "encrypt", "--in", plain.toString(), "--out", dir.resolve("plain.jck").toString()}, {"config", "history"}, {"config", "show"},
                {"config", "key", "show", "--key-id", "default"}, {"keygen", "--out", dir.resolve("k.key").toString(), "--reason", "r"},
                {"admin", "password", "change"}};
        for (String[] args : commands) {
            assertEquals(1, cli.run(args), String.join(" ", args));
            assertTrue(cli.err().contains("[사유: ADMIN_SETUP]") && cli.err().contains("admin setup --operator <ID>"),
                    String.join(" ", args) + ": " + cli.err());
            assertEquals("", cli.out(), "기능을 실행하지 않는다: " + String.join(" ", args));
        }
        assertEquals(before, files(), "아무 파일도 만들지 않는다");
        // 도움말은 초기 설정 안내만(다른 기능 안내·실행 없음). admin setup 도움말은 볼 수 있다.
        for (String[] args : new String[][]{{}, {"help"}, {"help", "config", "set"}, {"encrypt", "--help"}, {"config"},
                {"config", "key"}, {"admin"}}) {
            assertEquals(0, cli.run(args), String.join(" ", args));
            assertTrue(cli.out().contains("관리자 비밀번호 최초 설정 필요") && cli.out().contains("admin setup --operator <작업자ID>")
                    && cli.out().contains("java-crypto-kit-0.1.0-configured.jar"), cli.out());
            assertFalse(cli.out().contains("config key add"), "다른 명령 안내 없음: " + cli.out());
        }
        assertEquals(0, cli.run("admin", "setup", "--help"));
        assertTrue(cli.out().startsWith("admin setup - CLI 관리자 비밀번호 최초 설정"), cli.out());
        // 클래스 폴더(JAR가 아님)에서 실행하면 관리자 상태를 확인할 수 없어 거부한다.
        cli.withCliJar(null);
        assertEquals(1, cli.run("info"));
        assertTrue(cli.err().contains("[사유: ADMIN_SETUP]") && cli.err().contains("JAR로 실행할 때만"), cli.err());
    }

    @Test
    void firstRunOfAnyCommandSetsUpInteractivelyAndDoesNotRunTheCommand() throws Exception {
        cli.withCliJar(fresh);
        CliHarness.FakeTerminal t = terminal("admin@12345", "admin@12345");
        t.lines.add("ops01");
        assertEquals(1, cli.run(t, "encrypt"));
        Path created = dir.resolve("java-crypto-kit-0.1.0-configured.jar");
        assertTrue(Files.exists(created), cli.out() + cli.err());
        assertEquals(Arrays.asList("작업자 ID: ", "새 관리자 비밀번호(입력 숨김): ", "비밀번호 확인(입력 숨김): "), t.prompts);
        assertEquals("[CLI 초기 설정 필요]", t.printed.get(0), t.printed.toString());
        assertTrue(t.printed.contains("지금 설정하면 새 JAR(java-crypto-kit-0.1.0-configured.jar)을 만들고 원본은 그대로 둡니다."));
        assertTrue(t.printed.contains("비밀번호 규칙: 10~128자, 영문자·숫자·특수문자 각 1자 이상(공백·한글 불가)"), t.printed.toString());
        String ls = System.lineSeparator();
        assertEquals("관리자    : 비밀번호 설정 완료" + ls
                + "생성 JAR  : " + created.toAbsolutePath() + ls + CliHarness.permissionLine()
                + "원본 JAR  : java-crypto-kit-0.1.0.jar (그대로, 관리자 비밀번호 미설정)" + ls
                + "작업자    : ops01" + ls
                + "안내      : 이후에는 생성 JAR로 CLI를 실행하세요." + ls, cli.out());
        assertTrue(cli.err().contains("[사유: ADMIN_SETUP] 요청한 명령(encrypt)은 실행하지 않았습니다. 생성 JAR로 다시 실행하세요: "
                + "java -jar java-crypto-kit-0.1.0-configured.jar encrypt"), cli.err());
        assertFalse(cli.out().contains("ENC[") || t.prompts.contains("암호화할 값(입력 숨김): "), "요청한 명령은 실행하지 않는다");
        String all = cli.out() + cli.err() + String.join("\n", t.printed) + new String(Files.readAllBytes(created), StandardCharsets.ISO_8859_1);
        assertFalse(all.contains("admin@12345"), "비밀번호 원문은 화면·JAR 어디에도 없다");

        // 설정된 JAR: 키·설정은 그대로, 이력에는 관리자 기록 1건(--all에서만, 비밀번호·해시 없음)
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(created);
        assertArrayEquals(JarConfigEditor.read(fresh).settingsBytes, snap.settingsBytes, "키·설정은 바뀌지 않는다");
        assertEquals(AdminPassword.State.INITIALIZED, AdminPassword.statusOf(snap).state);
        String newPw = CliHarness.passFile(dir, "admin@12345");
        cli.withCliJar(created);
        assertEquals(0, cli.run("config", "history", "--all", "--admin-pass-file", newPw), cli.err());
        assertTrue(cli.out().contains("수정자 ops01  admin setup  [관리자]") && cli.out().contains("    사유: 최초 설정")
                && cli.out().contains("    관리자 비밀번호: (없음) -> (설정됨)"), cli.out());
        assertEquals(0, cli.run("config", "history", "--admin-pass-file", newPw), cli.err());
        assertTrue(cli.out().contains("표시 범위 : pass 관련 0건(전체 1건)"), "관리자 기록은 pass·key로 분류하지 않는다: " + cli.out());
        assertEquals(0, cli.run("config", "history", "--type", "key", "--admin-pass-file", newPw), cli.err());
        assertTrue(cli.out().contains("표시 범위 : key 관련 0건(전체 1건)"), cli.out());
        // 이미 설정된 JAR는 최초 설정을 다시 할 수 없다(인증 없는 덮어쓰기 없음).
        assertEquals(1, cli.run("admin", "setup", "--operator", "x", "--admin-pass-file", newPw));
        assertTrue(cli.err().contains("이미 설정되어 있습니다"), cli.err());
        // 원본 JAR는 여전히 미설정(실행할 때마다 다시 설정을 요구)
        cli.withCliJar(fresh);
        assertEquals(1, cli.run("info"));
        assertTrue(cli.err().contains("[사유: ADMIN_SETUP]"), cli.err());
        // 기본 결과 이름이 이미 있으면(이미 설정한 JAR일 수 있음) 입력을 받기 전에 그 JAR를 안내한다.
        CliHarness.FakeTerminal again = terminal("admin@12345", "admin@12345");
        again.lines.add("ops01");
        assertEquals(1, cli.run(again, "info"));
        assertTrue(again.prompts.isEmpty(), again.prompts.toString());
        assertTrue(cli.err().contains("java -jar java-crypto-kit-0.1.0-configured.jar info"), cli.err());
    }

    @Test
    void setupFailuresChangeNothing() throws Exception {
        cli.withCliJar(fresh);
        Path created = dir.resolve("java-crypto-kit-0.1.0-configured.jar");
        // 두 입력 불일치 3번
        CliHarness.FakeTerminal mismatch = terminal("admin@12345", "admin@12346", "admin@12345", "x", "admin@12345", "y");
        mismatch.lines.add("ops");
        assertEquals(1, cli.run(mismatch, "admin", "setup"));
        assertTrue(cli.err().contains("[사유: ADMIN_PASSWORD]") && cli.err().contains("3번 실패") && cli.err().contains("두 입력이 다릅니다"),
                cli.err());
        assertTrue(mismatch.printed.contains("두 입력이 다릅니다. 다시 입력하세요(남은 기회 2번)."), mismatch.printed.toString());
        assertFalse(Files.exists(created));
        // 규칙 위반: 구체적인 사유를 알리고 다시 받는다(확인 입력은 묻지 않음)
        CliHarness.FakeTerminal rules = terminal("Admin12345", "admin@123", "admin@12345", "admin@12345");
        rules.lines.add("ops");
        assertEquals(0, cli.run(rules, "admin", "setup"), cli.err());
        assertTrue(rules.printed.contains("규칙에 맞지 않습니다: 특수문자 없음. 다시 입력하세요(남은 기회 2번)."), rules.printed.toString());
        assertTrue(rules.printed.contains("규칙에 맞지 않습니다: 10자 미만. 다시 입력하세요(남은 기회 1번)."), rules.printed.toString());
        assertEquals(Arrays.asList("작업자 ID: ", "새 관리자 비밀번호(입력 숨김): ", "새 관리자 비밀번호(입력 숨김): ",
                "새 관리자 비밀번호(입력 숨김): ", "비밀번호 확인(입력 숨김): "), rules.prompts);
        assertTrue(Files.exists(created));
        Files.delete(created);
        // 빈 입력(취소)·빈 작업자 ID·비대화형 필수 항목 누락
        CliHarness.FakeTerminal cancel = terminal("");
        cancel.lines.add("ops");
        assertEquals(1, cli.run(cancel, "admin", "setup"));
        assertTrue(cli.err().contains("취소했습니다"), cli.err());
        CliHarness.FakeTerminal noOperator = terminal("admin@12345", "admin@12345");
        noOperator.lines.add("   ");
        assertEquals(1, cli.run(noOperator, "admin", "setup"));
        assertTrue(cli.err().contains("작업자 ID가 비어 있어"), cli.err());
        assertEquals(1, cli.run("admin", "setup", "--admin-pass-file", pwFile));
        assertTrue(cli.err().contains("--operator <작업자 ID>가 필요합니다"), cli.err());
        assertEquals(1, cli.run("admin", "setup", "--operator", "ci"));
        assertTrue(cli.err().contains("--admin-pass-file <파일>로 새 비밀번호를 주어야"), cli.err());
        String weak = CliHarness.passFile(dir, "Admin12345");
        assertEquals(1, cli.run("admin", "setup", "--operator", "ci", "--admin-pass-file", weak));
        assertTrue(cli.err().contains("[사유: ADMIN_PASSWORD]") && cli.err().contains("특수문자 없음"), cli.err());
        assertFalse(Files.exists(created), "실패하면 JAR를 만들지 않는다");
        // 비대화형 최초 설정(CI): 파일 1회로 같은 규칙을 검사해 설정한다.
        Path ci = dir.resolve("ci.jar");
        assertEquals(0, cli.run("admin", "setup", "--operator", "ci", "--admin-pass-file", pwFile, "--out", ci.toString()), cli.err());
        assertEquals(AdminPassword.State.INITIALIZED, AdminPassword.statusOf(JarConfigEditor.read(ci)).state);
        assertFalse(cli.out().contains(PW) || cli.err().contains(PW));
    }

    // ===================================================================================================
    // 민감 명령의 인증
    // ===================================================================================================

    @Test
    void nonSensitiveCommandsNeedOnlyTheSetupAndDecryptAsksTheAdminPasswordFirst() throws Exception {
        cli.withCliJar(app);
        CliHarness.FakeTerminal enc = terminal("dummy-db-password");
        assertEquals(0, cli.run(enc, "encrypt"), cli.err());
        assertEquals(Arrays.asList("암호화할 값(입력 숨김): "), enc.prompts, "encrypt는 관리자 비밀번호를 묻지 않는다");
        String token = cli.out().trim();
        assertEquals(0, cli.run("verify", "--value", token), cli.err());
        assertEquals(0, cli.run("fingerprint"), cli.err());
        assertEquals(0, cli.run("info"), cli.err());
        assertEquals(0, cli.run("help"), cli.err());
        assertTrue(cli.out().contains("admin password change") && cli.out().contains("config key show *"), cli.out());
        // decrypt: 관리자 인증 → 암호문 입력 → 평문
        CliHarness.FakeTerminal dec = terminal(PW, token);
        assertEquals(0, cli.run(dec, "decrypt"), cli.err());
        assertEquals(Arrays.asList(ADMIN_PROMPT, "암호문(입력 숨김): "), dec.prompts);
        assertTrue(cli.out().contains("복호화 결과: dummy-db-password"), cli.out());
        // 3번 틀리면 암호문을 받지 않고 끝난다(영구 잠금은 없음)
        CliHarness.FakeTerminal wrong = terminal("wrong-1", "wrong-2", "wrong-3", token);
        assertEquals(1, cli.run(wrong, "decrypt"));
        assertEquals(Arrays.asList(ADMIN_PROMPT, ADMIN_PROMPT, ADMIN_PROMPT), wrong.prompts);
        assertTrue(wrong.printed.contains("관리자 비밀번호가 맞지 않습니다. 다시 입력하세요(남은 기회 2번)."), wrong.printed.toString());
        assertTrue(cli.err().contains("[사유: ADMIN_AUTH]") && cli.err().contains("3번 실패"), cli.err());
        assertEquals("", cli.out(), "평문 없음");
        // 취소(빈 입력)
        assertEquals(1, cli.run(terminal(""), "decrypt"));
        assertTrue(cli.err().contains("관리자 비밀번호 입력을 취소했습니다"), cli.err());
        // 비밀번호 파일(대화형에서도 쓸 수 있음): 관리자 비밀번호를 묻지 않는다
        CliHarness.FakeTerminal withFile = terminal(token);
        assertEquals(0, cli.run(withFile, "decrypt", "--admin-pass-file", pwFile), cli.err());
        assertEquals(Arrays.asList("암호문(입력 숨김): "), withFile.prompts);
        // 새로 실행하면 다시 묻는다(인증 상태를 다음 실행에 넘기지 않음)
        CliHarness.FakeTerminal next = terminal(PW, token);
        assertEquals(0, cli.run(next, "decrypt"), cli.err());
        assertEquals(ADMIN_PROMPT, next.prompts.get(0));
    }

    @Test
    void everySensitiveCommandFailsBeforeAnySideEffectWithoutValidAuthentication() throws Exception {
        // 등록된 다른 키(k2)와 암호화 파일을 미리 준비한다(인증 호출만 기록하는 창구로).
        Path keyFile = TestSupport.writeRandomKeyFile(dir, "k2.key");
        Path withKey = dir.resolve("with-key.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "k2", "--type", "key", "--from-file", keyFile.toString(),
                "--operator", "ops", "--reason", "prep", "--yes", "--jar", app.toString(), "--out", withKey.toString()), cli.err());
        Path plain = Files.write(dir.resolve("plain.csv"), "a,b".getBytes(StandardCharsets.UTF_8));
        Path enc = dir.resolve("plain.csv.jck");
        CryptoService.of(JarConfigEditor.read(withKey).validated()).encryptFile(plain, enc);
        String token = TestSupport.jarDefaults().encryptText("dummy-rekey");
        String wrongFile = CliHarness.passFile(dir, "Wrong-pass-9");
        String missingFile = dir.resolve("no-such.pw").toString();
        cli.withCliJar(withKey);
        List<String[]> commands = new ArrayList<>();
        commands.add(new String[]{"keygen", "--out", dir.resolve("new.key").toString(), "--reason", "r"});
        commands.add(new String[]{"kms", "datakey", "--out", dir.resolve("new.datakey").toString(), "--reason", "r"});
        commands.add(new String[]{"config", "set", "crypto.lang=en", "--operator", "ops", "--out", dir.resolve("set.jar").toString()});
        commands.add(new String[]{"config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "e9", "--operator", "ops",
                "--reason", "r", "--yes", "--out", dir.resolve("embed.jar").toString()});
        commands.add(new String[]{"config", "key", "add", "--key-id", "n1", "--generate", "--export", dir.resolve("n1.backup").toString(),
                "--operator", "ops", "--reason", "r", "--yes", "--out", dir.resolve("add.jar").toString()});
        commands.add(new String[]{"config", "key", "use", "--key-id", "k2", "--operator", "ops", "--reason", "r", "--yes",
                "--out", dir.resolve("use.jar").toString()});
        commands.add(new String[]{"config", "key", "remove", "--key-id", "k2", "--operator", "ops", "--reason", "r", "--yes",
                "--out", dir.resolve("remove.jar").toString()});
        commands.add(new String[]{"config", "key", "show", "--key-id", "k2", "--export", dir.resolve("k2.export").toString()});
        commands.add(new String[]{"config", "show"});
        commands.add(new String[]{"config", "history", "--all"});
        commands.add(new String[]{"rekey", "--key-id", "default", "--value", token});
        commands.add(new String[]{"file", "decrypt", "--in", enc.toString(), "--out", dir.resolve("out.csv").toString()});
        List<String> before = files();
        for (String[] args : commands) {
            String name = String.join(" ", args);
            // 1) 비대화형 + 비밀번호 파일 없음, 2) 틀린 파일, 3) 없는 파일: 모두 실행 전에 ADMIN_AUTH, 결과·파일 없음
            assertEquals(1, cli.run(args), name);
            assertTrue(cli.err().contains("[사유: ADMIN_AUTH]") && cli.err().contains("--admin-pass-file"), name + ": " + cli.err());
            assertEquals("", cli.out(), name);
            for (String file : new String[]{wrongFile, missingFile}) {
                String[] withFile = Arrays.copyOf(args, args.length + 2);
                withFile[args.length] = "--admin-pass-file";
                withFile[args.length + 1] = file;
                assertEquals(1, cli.run(withFile), name);
                assertTrue(cli.err().contains("[사유: ADMIN_AUTH]"), name + ": " + cli.err());
                assertEquals("", cli.out(), name);
            }
            // --yes는 관리자 인증을 대신하지 못한다(위 명령 중 --yes를 쓴 것도 실패). 대화형 취소도 같다.
            assertEquals(1, cli.run(terminal(""), args), name);
            assertEquals(before, files(), "인증 실패 후 만든 파일이 없어야 한다: " + name);
        }
        // 정책(명령 정의)의 민감 명령이 모두 이 시험 또는 대화형 전용 시험(decrypt·admin password change: 위·아래 시험)에 들어 있는지.
        // 민감 명령을 새로 정의하면 여기에도 넣어야 시험이 통과한다(인증 누락 방지).
        java.util.Set<String> covered = new java.util.TreeSet<>(Arrays.asList("decrypt", "admin password change"));
        for (String[] args : commands) {
            for (int words = Math.min(3, args.length); words > 0; words--) {
                CliCommands.Spec spec = CliCommands.find(String.join(" ", Arrays.copyOf(args, words)));
                if (spec != null) {
                    covered.add(spec.name);
                    break;
                }
            }
        }
        java.util.Set<String> sensitive = new java.util.TreeSet<>();
        for (CliCommands.Spec spec : CliCommands.ALL) if (CliCommands.needsAdmin(spec)) sensitive.add(spec.name);
        assertEquals(sensitive, covered, "모든 민감 명령의 인증 실패·부작용 0건을 확인해야 한다");
        // JVM -D로 관리자 비밀번호를 줄 수 없다(설정 항목이 아님).
        try (CliHarness withProperty = new CliHarness("crypto.admin.password=" + PW)) {
            withProperty.withCliJar(withKey);
            assertEquals(1, withProperty.run("config", "show"));
            assertTrue(withProperty.err().contains("[사유: ADMIN_AUTH]") || withProperty.err().contains("crypto.admin.password"),
                    withProperty.err());
            assertEquals("", withProperty.out());
        }
        // 맞는 비밀번호 파일이면 실행된다(대표: keygen, config set).
        assertEquals(0, cli.run("keygen", "--out", dir.resolve("ok.key").toString(), "--reason", "r", "--admin-pass-file", pwFile),
                cli.err());
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "ops", "--out", dir.resolve("ok.jar").toString(),
                "--admin-pass-file", pwFile), cli.err());
        // 관리자 인증 → 사유 → CHANGE 순서(대화형)
        CliHarness.FakeTerminal order = terminal(PW);
        order.lines.add("정기 회전");
        order.lines.add("CHANGE");
        assertEquals(0, cli.run(order, "config", "key", "use", "--key-id", "k2", "--operator", "ops", "--out",
                dir.resolve("use-ok.jar").toString()), cli.err());
        assertEquals(Arrays.asList(ADMIN_PROMPT, "사유(비밀값 제외): ", "계속하려면 CHANGE를 입력하세요(그 외 입력은 취소): "),
                order.prompts);
    }

    @Test
    void passwordChangeNeedsTheCurrentPasswordAndTwoMatchingNewEntries() throws Exception {
        cli.withCliJar(app);
        assertEquals(1, cli.run("admin", "password", "change", "--reason", "r"));
        assertTrue(cli.err().contains("대화형 터미널에서만"), cli.err());
        Path next = dir.resolve("app-configured.jar");
        // 현재 비밀번호가 틀리면 바꾸지 않는다
        assertEquals(1, cli.run(terminal("bad-1", "bad-2", "bad-3"), "admin", "password", "change", "--operator", "ops",
                "--reason", "r"));
        assertTrue(cli.err().contains("[사유: ADMIN_AUTH]"), cli.err());
        assertFalse(Files.exists(next));
        // 새 비밀번호가 현재와 같거나 두 입력이 다르면 다시 받고, 3번이면 바꾸지 않는다
        CliHarness.FakeTerminal same = terminal(PW, PW, "Other-pass-7", "Other-pass-8", "admin@", "admin@");
        assertEquals(1, cli.run(same, "admin", "password", "change", "--operator", "ops", "--reason", "r"));
        assertTrue(same.printed.contains("현재 비밀번호와 같습니다. 다시 입력하세요(남은 기회 2번)."), same.printed.toString());
        assertTrue(same.printed.contains("두 입력이 다릅니다. 다시 입력하세요(남은 기회 1번)."), same.printed.toString());
        assertTrue(cli.err().contains("[사유: ADMIN_PASSWORD]") && cli.err().contains("10자 미만"), cli.err());
        assertFalse(Files.exists(next));
        // 성공: 현재 → 작업자 ID → 사유 → 새 비밀번호 2회
        CliHarness.FakeTerminal ok = terminal(PW, "New-admin-22", "New-admin-22");
        ok.lines.add("sec01");
        ok.lines.add("분기 변경");
        assertEquals(0, cli.run(ok, "admin", "password", "change"), cli.err());
        assertEquals(Arrays.asList("현재 관리자 비밀번호(입력 숨김): ", "작업자 ID: ", "사유(비밀값 제외): ",
                "새 관리자 비밀번호(입력 숨김): ", "비밀번호 확인(입력 숨김): "), ok.prompts);
        assertEquals("[CLI 관리자 비밀번호 변경]", ok.printed.get(0));
        String ls = System.lineSeparator();
        assertEquals("관리자    : 비밀번호 변경 완료" + ls + "생성 JAR  : " + next.toAbsolutePath() + ls + CliHarness.permissionLine()
                + "원본 JAR  : app.jar (그대로, 이전 비밀번호 유지)" + ls + "작업자    : sec01" + ls + "사유      : 분기 변경" + ls
                + "안내      : 생성 JAR을 쓰고, 필요 없는 원본 JAR은 직접 폐기하세요." + ls, cli.out());
        // 새 JAR: 새 비밀번호만 통한다. 키·설정은 그대로, 이력에 변경 기록(사유 포함). 원본 JAR는 이전 비밀번호 그대로.
        assertArrayEquals(JarConfigEditor.read(app).settingsBytes, JarConfigEditor.read(next).settingsBytes);
        String newFile = CliHarness.passFile(dir, "New-admin-22");
        cli.withCliJar(next);
        assertEquals(1, cli.run("config", "show", "--admin-pass-file", pwFile));
        assertTrue(cli.err().contains("[사유: ADMIN_AUTH]"), "변경 뒤 이전 비밀번호는 통하지 않는다: " + cli.err());
        assertEquals(0, cli.run("config", "history", "--all", "--admin-pass-file", newFile), cli.err());
        assertTrue(cli.out().contains("수정자 sec01  admin password change  [관리자]") && cli.out().contains("    사유: 분기 변경")
                && cli.out().contains("    관리자 비밀번호: (설정됨) -> (변경됨)"), cli.out());
        assertFalse(cli.out().contains("New-admin-22") || cli.out().contains(PW), "이력에 비밀번호가 없다");
        cli.withCliJar(app);
        assertEquals(0, cli.run("config", "show", "--admin-pass-file", pwFile), "원본 JAR는 이전 비밀번호로 계속 열린다");
    }

    // ===================================================================================================
    // 다른 JAR의 관리자 인증
    // ===================================================================================================

    @Test
    void otherJarsAreAuthenticatedWithTheirOwnPasswords() throws Exception {
        Path other = CliHarness.configure(TestJars.build(dir.resolve("other.jar")), "Other-admin-2");
        Path keyFile = TestSupport.writeRandomKeyFile(dir, "shared.key");
        Path otherWithKey = dir.resolve("other-key.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "shared", "--type", "key", "--from-file", keyFile.toString(),
                "--operator", "ops", "--reason", "prep", "--yes", "--jar", other.toString(), "--out", otherWithKey.toString()),
                cli.err());
        cli.withCliJar(app);
        // --jar: 비대화형은 비밀번호 파일 하나가 모든 JAR와 맞아야 한다(실행 중인 JAR 인증으로 대신하지 않음)
        Path out1 = dir.resolve("o1.jar");
        assertEquals(1, cli.run("config", "set", "crypto.lang=en", "--operator", "ops", "--jar", other.toString(), "--out",
                out1.toString(), "--admin-pass-file", pwFile));
        assertTrue(cli.err().contains("[사유: ADMIN_AUTH]") && cli.err().contains("대상 JAR(other.jar)의 관리자 비밀번호가 다릅니다"),
                cli.err());
        assertFalse(Files.exists(out1));
        // 대화형은 그 JAR의 비밀번호를 따로 묻는다
        CliHarness.FakeTerminal two = terminal(PW, "Other-admin-2");
        assertEquals(0, cli.run(two, "config", "set", "crypto.lang=en", "--operator", "ops", "--jar", other.toString(), "--out",
                out1.toString()), cli.err());
        assertEquals(Arrays.asList(ADMIN_PROMPT, "대상 JAR(other.jar) 관리자 비밀번호(입력 숨김): "), two.prompts);
        // 같은 비밀번호면 한 번만 묻는다
        Path same = CliHarness.configure(TestJars.build(dir.resolve("same.jar")), PW);
        CliHarness.FakeTerminal one = terminal(PW);
        assertEquals(0, cli.run(one, "config", "show", "--jar", same.toString()), cli.err());
        assertEquals(Arrays.asList(ADMIN_PROMPT), one.prompts);
        // 미설정 새 버전 JAR는 대상이 될 수 없다(그 JAR에서 먼저 설정)
        assertEquals(1, cli.run("config", "show", "--jar", fresh.toString(), "--admin-pass-file", pwFile));
        assertTrue(cli.err().contains("[사유: ADMIN_SETUP]") && cli.err().contains("admin setup"), cli.err());
        assertEquals("", cli.out());
        // --from-jar(키 복사 원본)도 그 JAR의 비밀번호를 확인한다
        Path copied = dir.resolve("copied.jar");
        assertEquals(1, cli.run("config", "key", "add", "--key-id", "shared", "--from-jar", otherWithKey.toString(), "--operator",
                "ops", "--reason", "r", "--yes", "--out", copied.toString(), "--admin-pass-file", pwFile));
        assertTrue(cli.err().contains("원본 JAR(other-key.jar)의 관리자 비밀번호가 다릅니다"), cli.err());
        CliHarness.FakeTerminal source = terminal(PW, "Other-admin-2");
        assertEquals(0, cli.run(source, "config", "key", "add", "--key-id", "shared", "--from-jar", otherWithKey.toString(),
                "--operator", "ops", "--reason", "r", "--yes", "--out", copied.toString()), cli.err());
        assertEquals(Arrays.asList(ADMIN_PROMPT, "원본 JAR(other-key.jar) 관리자 비밀번호(입력 숨김): "), source.prompts);
        // rekey: --from-jar(복호화에 쓰는 원본)는 인증, --to-jar(암호화만, 바뀌지 않음)는 인증하지 않는다
        String publicToken = TestSupport.jarDefaults().encryptText("dummy-rk");
        assertEquals(0, cli.run("rekey", "--to-jar", otherWithKey.toString(), "--key-id", "shared", "--value", publicToken,
                "--admin-pass-file", pwFile), cli.err());
        String moved = cli.out().trim();
        assertTrue(moved.startsWith("ENC[v1:shared:"), cli.out());
        byte[] otherBefore = Files.readAllBytes(otherWithKey);
        assertEquals(1, cli.run("rekey", "--from-jar", otherWithKey.toString(), "--key-id", "default", "--value", moved,
                "--admin-pass-file", pwFile));
        assertTrue(cli.err().contains("원본 JAR(other-key.jar)의 관리자 비밀번호가 다릅니다"), cli.err());
        assertArrayEquals(otherBefore, Files.readAllBytes(otherWithKey), "--to-jar·--from-jar 대상 JAR는 바뀌지 않는다");
        // 관리자 비밀번호를 모르는 이전 형식 JAR는 실행 중인 CLI JAR의 인증만으로 편집하고 관리자 정보를 쓰지 않는다
        Path legacy = TestJars.buildLegacy(dir.resolve("java-crypto-kit-legacy.jar"));
        Path legacyOut = dir.resolve("legacy-out.jar");
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "ops", "--jar", legacy.toString(), "--out",
                legacyOut.toString(), "--admin-pass-file", pwFile), cli.err());
        JarConfigEditor.Snapshot legacySnap = JarConfigEditor.read(legacyOut);
        assertNull(legacySnap.adminBytes, "이전 버전 JAR에는 관리자 검증값을 쓰지 않는다");
        assertEquals(AdminPassword.State.LEGACY, AdminPassword.statusOf(legacySnap).state);
    }

    // ===================================================================================================
    // 손상·삭제와 Java API
    // ===================================================================================================

    @Test
    void damagedOrDeletedVerifierFailsClosedButTheJavaApiStillWorks() throws Exception {
        Path broken = dir.resolve("broken.jar");
        Files.copy(app, broken);
        String entry = new String(JarConfigEditor.read(app).adminBytes, StandardCharsets.US_ASCII);
        CliHarness.replaceEntry(broken, AdminPassword.ENTRY, entry.replace("format.version=1", "format.version=9")
                .getBytes(StandardCharsets.US_ASCII));
        cli.withCliJar(broken);
        for (String[] args : new String[][]{{"info"}, {"help"}, {"config", "show", "--admin-pass-file", pwFile}}) {
            assertEquals(1, cli.run(args), String.join(" ", args));
            assertTrue(cli.err().contains("[사유: INTEGRITY]") && cli.err().contains("형식 버전을 알 수 없습니다")
                    && cli.err().contains("Java API·Tomcat은 영향을 받지 않습니다"), cli.err());
        }
        // 설정 기록이 있는 JAR에서 검증값만 지우면 "미설정"이 아니라 손상(삭제 의심)이다(최초 설정으로 되돌릴 수 없음).
        cli.withCliJar(fresh);
        Path set = dir.resolve("set.jar");
        assertEquals(0, cli.run("admin", "setup", "--operator", "ci", "--admin-pass-file", pwFile, "--out", set.toString()), cli.err());
        Path deleted = dir.resolve("deleted.jar");
        Files.copy(set, deleted);
        CliHarness.replaceEntry(deleted, AdminPassword.ENTRY, null);
        cli.withCliJar(deleted);
        assertEquals(1, cli.run("info"));
        assertTrue(cli.err().contains("[사유: INTEGRITY]") && cli.err().contains("삭제 의심"), cli.err());
        assertEquals(1, cli.run("admin", "setup", "--operator", "x", "--admin-pass-file", pwFile));
        assertTrue(cli.err().contains("[사유: INTEGRITY]"), "손상 JAR는 다시 설정할 수도 없다: " + cli.err());
        // Java API는 관리자 비밀번호 항목을 읽지 않는다: 손상·삭제·미설정 JAR 모두 그대로 암복호화한다.
        for (Path jar : new Path[]{broken, deleted, fresh, set}) {
            assertEquals("dummy-api", javaApiRoundTrip(jar, "dummy-api"), jar.getFileName().toString());
        }
    }

    /** JAR 하나만 클래스패스로 둔 별도 클래스로더에서 공개 API로 암호화·복호화한다(관리자 비밀번호 입력 없음). */
    private static String javaApiRoundTrip(Path jar, String value) throws Exception {
        try (URLClassLoader loader = new URLClassLoader(new URL[]{jar.toUri().toURL()}, ClassLoader.getSystemClassLoader().getParent())) {
            Class<?> api = loader.loadClass("io.javacryptokit.CredentialCrypto");
            assertTrue(api.getProtectionDomain().getCodeSource().getLocation().toString().endsWith(jar.getFileName().toString()));
            Object crypto = api.getMethod("fromDefaultConfiguration").invoke(null);
            String token = (String) api.getMethod("encryptText", String.class).invoke(crypto, value);
            return (String) api.getMethod("decryptText", String.class).invoke(crypto, token);
        }
    }

    // ===================================================================================================
    // config key show: 관리정보, SHOW 확인, 원문 표시·내보내기와 재등록 복구
    // ===================================================================================================

    @Test
    void keyShowRevealsOnlyAfterAuthenticationAndAnExactShowAndRecoversOldCiphertext() throws Exception {
        Path keyFile = TestSupport.writeRandomKeyFile(dir, "k1.key");
        String keyText = new String(Files.readAllBytes(keyFile), StandardCharsets.US_ASCII).trim();
        Path passFile = Files.write(dir.resolve("svc.pass"), "dummy-service-pass\n".getBytes(StandardCharsets.UTF_8));
        Path step1 = dir.resolve("step1.jar");
        Path step2 = dir.resolve("step2.jar");
        Path keys = dir.resolve("keys.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "k1", "--type", "key", "--from-file", keyFile.toString(),
                "--operator", "ops", "--reason", "prep", "--yes", "--jar", app.toString(), "--out", step1.toString()), cli.err());
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "fp", "--source", "file", "--location",
                TestSupport.propertiesPath(passFile), "--operator", "ops", "--reason", "prep", "--yes", "--jar", step1.toString(),
                "--out", step2.toString()), cli.err());
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "gp", "--generate", "--export",
                dir.resolve("gp.backup").toString(), "--operator", "ops", "--reason", "prep", "--yes", "--jar", step2.toString(),
                "--out", keys.toString()), cli.err());
        CryptoSettings settings = JarConfigEditor.read(keys).validated();
        CryptoService service = CryptoService.of(settings);
        String k1Token = service.encryptText("dummy-k1".toCharArray(), null, "k1");
        String fpToken = service.encryptText("dummy-fp".toCharArray(), null, "fp");
        String k1Fingerprint = KeyResolver.fingerprint(KeyResolver.readKeyFile(keyFile, "k"));
        byte[] historyBefore = JarConfigEditor.read(keys).history.entries.isEmpty() ? null
                : rawHistory(keys);
        cli.withCliJar(keys);

        // 관리정보(인증 뒤, 마스킹 없음, 원문 없음)
        assertEquals(0, cli.run("config", "key", "show", "--key-id", "k1", "--admin-pass-file", pwFile), cli.err());
        String ls = System.lineSeparator();
        assertEquals("키 ID     : k1" + ls + "유형      : key" + ls + "공급원    : embedded" + ls + "상태      : 사용자 지정" + ls
                + "키 지문   : " + k1Fingerprint + ls + "원문      : JAR 내장 AES 키(--show 화면 표시, --export 파일)" + ls, cli.out());
        assertEquals(0, cli.run("config", "key", "show", "--key-id", "gp", "--admin-pass-file", pwFile), cli.err());
        KeyProfile gp = settings.profile("gp");
        String gpSalt = gp.value(KeyProfile.SALT);
        assertTrue(cli.out().contains("KDF       : pbkdf2-sha256, 600,000회" + ls + "Salt      : " + gpSalt + ls
                + "Salt 해시 : " + KeyringView.saltSha256(gpSalt) + ls
                + "원문      : 없음 - PBKDF2 파생 키만 있어 원문 복원 불가(생성 때 만든 백업 사용)"), cli.out());

        // --show: 비대화형 거부, 인증 실패면 SHOW를 묻지 않음, SHOW가 아니면 취소(소문자도 취소)
        assertEquals(1, cli.run("config", "key", "show", "--key-id", "k1", "--show", "--admin-pass-file", pwFile));
        assertTrue(cli.err().contains("--show는 대화형 터미널에서만"), cli.err());
        CliHarness.FakeTerminal failed = terminal("bad-1", "bad-2", "bad-3");
        assertEquals(1, cli.run(failed, "config", "key", "show", "--key-id", "k1", "--show"));
        assertFalse(failed.prompts.contains("계속하려면 SHOW를 입력하세요(그 외 입력은 취소): "));
        assertFalse(String.join("\n", failed.printed).contains(keyText) || cli.out().contains(keyText));
        for (String answer : new String[]{"show", "SHOW please", "", "CHANGE"}) {
            CliHarness.FakeTerminal cancel = terminal(PW);
            cancel.lines.add(answer);
            assertEquals(0, cli.run(cancel, "config", "key", "show", "--key-id", "k1", "--show"), cli.err());
            assertTrue(cli.out().contains("취소했습니다. 원문을 표시하거나 내보내지 않았습니다."), cli.out());
            assertFalse(String.join("\n", cancel.printed).contains(keyText) || cli.out().contains(keyText), answer);
        }
        // SHOW를 정확히 입력하면 대화형 터미널에만 원문(키 파일 한 줄과 같은 표준 Base64)을 보여 준다
        CliHarness.FakeTerminal show = terminal(PW);
        show.lines.add("SHOW");
        assertEquals(0, cli.run(show, "config", "key", "show", "--key-id", "k1", "--show"), cli.err());
        assertEquals(Arrays.asList(ADMIN_PROMPT, "계속하려면 SHOW를 입력하세요(그 외 입력은 취소): "), show.prompts,
                "관리자 인증과 SHOW 확인은 별도 단계");
        assertTrue(show.printed.contains("[비밀값 표시 경고]"), show.printed.toString());
        int at = show.printed.indexOf("원문      : AES 키(표준 Base64, 32바이트) - 다음 줄 전체가 값");
        assertTrue(at > 0, show.printed.toString());
        assertEquals(keyText, show.printed.get(at + 1), "값 한 줄 = 키 파일 한 줄");
        assertEquals("키 지문   : " + k1Fingerprint, show.printed.get(at + 2));
        assertFalse(cli.out().contains(keyText) || cli.err().contains(keyText), "표준 출력·오류에는 원문이 없다");
        assertTrue(cli.out().contains("이력      : 저장 안 함(JAR를 바꾸지 않는 조회)"), cli.out());

        // pass: 공급원(file)에 보관된 원문만 보인다. 파생 키만 있는 pass(embedded)는 원문 복원 불가를 알리고 아무것도 보이지 않는다.
        CliHarness.FakeTerminal passShow = terminal(PW);
        passShow.lines.add("SHOW");
        assertEquals(0, cli.run(passShow, "config", "key", "show", "--key-id", "fp", "--show"), cli.err());
        assertTrue(passShow.printed.contains("dummy-service-pass"), passShow.printed.toString());
        assertTrue(passShow.printed.contains("원문      : Passphrase(18자) - 다음 줄 전체가 값"), passShow.printed.toString());
        CliHarness.FakeTerminal derived = terminal(PW);
        derived.lines.add("SHOW");
        assertEquals(1, cli.run(derived, "config", "key", "show", "--key-id", "gp", "--show"));
        assertTrue(cli.err().contains("PBKDF2 파생 키만 있어 Passphrase 원문을 복원할 수 없습니다") && cli.err().contains("--from-file"),
                cli.err());
        assertFalse(derived.prompts.contains("계속하려면 SHOW를 입력하세요(그 외 입력은 취소): "), "보일 원문이 없으면 확인도 묻지 않는다");
        assertEquals(1, cli.run("config", "key", "show", "--key-id", "gp", "--export", dir.resolve("gp.export").toString(),
                "--admin-pass-file", pwFile));
        assertFalse(Files.exists(dir.resolve("gp.export")));

        // --export(비대화형, 비밀번호 파일): key는 keygen 형식 한 줄 → 새 JAR에 같은 Key ID로 재등록하면 예전 암호문이 복호화된다
        Path k1Export = dir.resolve("k1.export");
        assertEquals(0, cli.run("config", "key", "show", "--key-id", "k1", "--export", k1Export.toString(), "--admin-pass-file",
                pwFile), cli.err());
        assertEquals(keyText + "\n", new String(Files.readAllBytes(k1Export), StandardCharsets.US_ASCII));
        assertTrue(cli.out().contains("내보내기  : " + k1Export.toAbsolutePath().normalize()) && !cli.out().contains(keyText), cli.out());
        assertEquals(1, cli.run("config", "key", "show", "--key-id", "k1", "--export", k1Export.toString(), "--admin-pass-file",
                pwFile), "기존 파일은 덮어쓰지 않는다");
        // pass(file 공급원)는 복원 백업(키 ID·KDF·반복 횟수·Salt·지문·Passphrase)
        Path fpExport = dir.resolve("fp.backup");
        assertEquals(0, cli.run("config", "key", "show", "--key-id", "fp", "--export", fpExport.toString(), "--admin-pass-file",
                pwFile), cli.err());
        String backup = new String(Files.readAllBytes(fpExport), StandardCharsets.UTF_8);
        assertTrue(backup.startsWith(KeyringCommand.PassBackup.HEADER) && backup.contains("\nkey-id=fp\n")
                && backup.contains("\nsalt=" + settings.profile("fp").value(KeyProfile.SALT) + "\n")
                && backup.contains("\npassphrase=dummy-service-pass\n"), backup);
        // 원본 JAR 없이 새 JAR(새 관리자 비밀번호)에 재등록 → 같은 Key ID·전체 지문, 예전 암호문 복호화
        Path rebuilt = CliHarness.configure(TestJars.build(dir.resolve("rebuilt.jar")), "Rebuilt-pass-5");
        Path r1 = dir.resolve("r1.jar");
        Path r2 = dir.resolve("r2.jar");
        cli.recordingGate();
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "k1", "--type", "key", "--from-file", k1Export.toString(),
                "--operator", "ops", "--reason", "복구", "--yes", "--jar", rebuilt.toString(), "--out", r1.toString()), cli.err());
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "fp", "--from-file", fpExport.toString(), "--operator", "ops",
                "--reason", "복구", "--yes", "--jar", r1.toString(), "--out", r2.toString()), cli.err());
        CryptoService restored = CryptoService.of(JarConfigEditor.read(r2).validated());
        assertEquals("dummy-k1", restored.decryptText(k1Token));
        assertEquals("dummy-fp", restored.decryptText(fpToken));
        assertEquals(k1Fingerprint, restored.keyFingerprint(restored.settings().profile("k1")));
        // 조회·내보내기는 JAR를 바꾸지 않으므로 이력도 그대로다
        assertArrayEquals(historyBefore, rawHistory(keys));
    }

    private static byte[] rawHistory(Path jar) throws Exception {
        try (java.util.jar.JarFile file = new java.util.jar.JarFile(jar.toFile())) {
            java.util.jar.JarEntry entry = file.getJarEntry(ConfigHistory.ENTRY);
            if (entry == null) return null;
            try (java.io.InputStream in = file.getInputStream(entry)) {
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
                return out.toByteArray();
            }
        }
    }

    // ===================================================================================================
    // 이력: 관리정보 전체 표시와 이전 형식 구분
    // ===================================================================================================

    @Test
    void historyShowsRecordedSaltsAndMarksValuesAnOlderFormatDidNotRecord() throws Exception {
        Path added = dir.resolve("added.jar");
        assertEquals(0, cli.run("config", "key", "add", "--key-id", "old", "--generate", "--export",
                dir.resolve("old.backup").toString(), "--operator", "ops", "--reason", "r", "--yes", "--jar", app.toString(),
                "--out", added.toString()), cli.err());
        JarConfigEditor.Snapshot snap = JarConfigEditor.read(added);
        String salt = snap.settings.getProperty("crypto.keys.old.salt").trim();
        // 새 기록: Salt 값을 그대로 남기고 보여 준다
        cli.withCliJar(added);
        assertEquals(0, cli.run("config", "history", "--admin-pass-file", pwFile), cli.err());
        assertTrue(cli.out().contains("    crypto.keys.old.salt: (없음) -> " + salt), cli.out());
        // 이전 형식의 기록(Salt 줄이 고정 표시)은 값을 지어내지 않고 "기록 없음"으로 구분한다. 최초 설정 기록은 그대로 두고 키 추가
        // 기록만 이전 형식으로 바꿔 체인을 다시 만든다(관리자 기록 규칙·해시 체인은 정상).
        List<ConfigHistory.Entry> entries = snap.history.entries;
        ConfigHistory.Entry keyEntry = entries.get(entries.size() - 1);
        List<ConfigHistory.Change> changes = new ArrayList<>();
        for (ConfigHistory.Change change : keyEntry.changes) {
            changes.add(SettingCatalog.isSaltSetting(change.key)
                    ? new ConfigHistory.Change(change.key, change.before, ConfigHistory.SECRET_BEFORE) : change);
        }
        byte[] appSettings = JarConfigEditor.read(app).settingsBytes;
        ConfigHistory.Log log = ConfigHistory.read(null, appSettings, null, null, TestJars.VERSION);
        byte[] oldStyle = null;
        for (ConfigHistory.Entry entry : entries) {
            boolean last = entry == keyEntry;
            byte[] settings = last ? snap.settingsBytes : appSettings;
            oldStyle = ConfigHistory.append(log, TestJars.VERSION, Instant.parse(entry.time), entry.operator, entry.command,
                    entry.reason, last ? changes : entry.changes, settings);
            log = ConfigHistory.read(ConfigHistory.load(oldStyle), settings, null, null, TestJars.VERSION);
        }
        Path older = dir.resolve("older.jar");
        Files.copy(added, older);
        CliHarness.replaceEntry(older, ConfigHistory.ENTRY, ConfigHistory.store(oldStyle));
        cli.withCliJar(older);
        assertEquals(0, cli.run("config", "history", "--admin-pass-file", pwFile), cli.err());
        assertTrue(cli.out().contains("이력 검증 : 정상(2건") && cli.out().contains("    crypto.keys.old.salt: (없음) -> (기록 없음)"),
                cli.out());
        assertFalse(cli.out().contains(salt), cli.out());
        // 이전 형식으로 추가된 키를 지우면 제거 기록은 체인을 잇도록 고정 표시로 남는다(이력 검증 정상)
        Path removed = dir.resolve("removed.jar");
        cli.recordingGate();
        assertEquals(0, cli.run("config", "key", "remove", "--key-id", "old", "--operator", "ops", "--reason", "r", "--yes",
                "--jar", older.toString(), "--out", removed.toString()), cli.err());
        assertNotNull(JarConfigEditor.read(removed).history);
        assertEquals(null, JarConfigEditor.read(removed).history.problem);
    }
}
