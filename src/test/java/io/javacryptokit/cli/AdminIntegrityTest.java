package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.TestJars;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.LightObfuscation;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.i18n.Messages;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * CLI의 상태·무결성 판단과 인증 경계(실제 확인 경로 {@link AdminAccess}, 실제 JAR):
 * <ul>
 *   <li>관리자 검증값이 있는 JAR의 변경 이력 삭제·빈 파일·잘림·해시 변조·관리자 기록 누락/중복/순서 오류·설정 지문 변조는 모두 손상이며,
 *       그 JAR로는(실행 중인 JAR든 --jar·--from-jar·--to-jar든) 비밀 노출·파일·JAR 변경이 없다(원본 그대로, Java API는 영향 없음).</li>
 *   <li>명령 정책은 명령 정의 한 곳에서만 정하고, 민감 명령은 대상 JAR의 키·설정을 읽기 전에 인증한다(인증 전 응답으로 키 등록
 *       여부를 알 수 없음).</li>
 *   <li>새 결과 JAR·백업 권한(POSIX).</li>
 * </ul>
 */
class AdminIntegrityTest {
    private static final String PW = CliHarness.ADMIN_PASSWORD;

    @TempDir
    Path dir;
    private CliHarness cli;
    /** 관리자 비밀번호(PW)를 설정한 JAR(이력: 최초 설정 1건). */
    private Path app;
    private String pwFile;

    @BeforeEach
    void setUp() throws Exception {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        cli = new CliHarness();
        app = CliHarness.configure(TestJars.build(dir.resolve("app.jar")), PW);
        pwFile = CliHarness.passFile(dir, PW);
    }

    @AfterEach
    void tearDown() throws Exception {
        cli.close();
    }

    // ===================================================================================================
    // 상태 판단: 정상 상태와 손상 사례
    // ===================================================================================================

    @Test
    void normalStatesStayUsable() throws Exception {
        assertEquals(AdminPassword.State.UNINITIALIZED, state(TestJars.build(dir.resolve("fresh.jar"))));
        assertEquals(AdminPassword.State.INITIALIZED, state(app));
        assertEquals(AdminPassword.State.LEGACY, state(TestJars.buildLegacy(dir.resolve("legacy.jar"))));
        // 최초 설정 뒤 비밀번호를 바꾼 이력(설정 → 변경)도 정상
        assertEquals(AdminPassword.State.INITIALIZED, state(withAdminRecords("set-change.jar",
                ConfigHistory.ADMIN_SETUP, ConfigHistory.ADMIN_CHANGE)));
    }

    @Test
    void damagedHistoryOrAdminRecordsMakeTheJarDamagedAndNothingRunsOrIsWritten() throws Exception {
        Map<String, Path> damaged = damagedJars();
        String token = CryptoService.of(JarConfigEditor.read(app).validated()).encryptText("dummy-token".toCharArray());
        for (Map.Entry<String, Path> item : damaged.entrySet()) {
            String name = item.getKey();
            Path jar = item.getValue();
            byte[] before = sha256(jar);
            assertEquals(AdminPassword.State.DAMAGED, state(jar), name);
            List<String> filesBefore = files();

            // 1) 그 JAR로 실행한 CLI: 민감·일반 명령 모두 인증·실행 전에 INTEGRITY(원인 안내, 관리정보·원문 없음)
            cli.withCliJar(jar);
            for (String[] args : new String[][]{
                    {"config", "key", "show", "--key-id", "default", "--export", dir.resolve("x.export").toString(), "--admin-pass-file", pwFile},
                    {"config", "history", "--all", "--admin-pass-file", pwFile},
                    {"config", "show", "--admin-pass-file", pwFile},
                    {"config", "set", "crypto.lang=en", "--operator", "ops", "--admin-pass-file", pwFile},
                    {"keygen", "--out", dir.resolve("x.key").toString(), "--reason", "r", "--admin-pass-file", pwFile},
                    {"encrypt"}, {"doctor"}}) {
                assertEquals(1, cli.run(args), name + " " + String.join(" ", args));
                assertTrue(cli.err().contains("[사유: INTEGRITY]") && cli.err().contains("Java API·Tomcat은 영향을 받지 않습니다"),
                        name + ": " + cli.err());
                assertEquals("", cli.out(), name);
            }
            assertEquals(1, cli.run(terminal(PW, "New-admin-9!", "New-admin-9!"), "admin", "password", "change", "--operator", "ops",
                    "--reason", "r"), name);
            assertTrue(cli.err().contains("[사유: INTEGRITY]"), name + ": " + cli.err());

            // 2) 정상 CLI JAR에서 다른 JAR로 지정: 대상(--jar)·원본(--from-jar)·새 암호문(--to-jar) 모두 거부
            cli.withCliJar(app);
            for (String[] args : new String[][]{
                    {"config", "key", "show", "--jar", jar.toString(), "--key-id", "default", "--export", dir.resolve("y.export").toString(),
                            "--admin-pass-file", pwFile},
                    {"config", "history", "--jar", jar.toString(), "--admin-pass-file", pwFile},
                    {"config", "set", "crypto.lang=en", "--operator", "ops", "--jar", jar.toString(),
                            "--admin-pass-file", pwFile},
                    {"config", "key", "add", "--key-id", "copied", "--from-jar", jar.toString(), "--operator", "ops", "--reason", "r", "--yes", "--admin-pass-file", pwFile},
                    {"rekey", "--to-jar", jar.toString(), "--value", token, "--admin-pass-file", pwFile}}) {
                assertEquals(1, cli.run(args), name + " " + String.join(" ", args));
                assertTrue(cli.err().contains("[사유: INTEGRITY]"), name + ": " + cli.err());
                assertEquals("", cli.out(), name);
            }

            // 3) 변경 경로의 공통 관문: 손상된 원본으로는 새 이력·결과 JAR를 만들지 않는다
            CryptoCli.CliException e = assertThrows(CryptoCli.CliException.class, () -> JarConfigEditor.apply(JarConfigEditor.read(jar), new JarConfigEditor.Change("set",
                            Collections.singletonMap("crypto.lang", "en"), "ops", "r"), Instant.now()));
            assertEquals("INTEGRITY", e.code, name);
            assertThrows(CryptoCli.CliException.class, () -> JarConfigEditor.applyAdmin(JarConfigEditor.read(jar),
                    AdminPassword.create("New-admin-9!".toCharArray(), AdminPassword.MIN_ITERATIONS), "ops",
                    ConfigHistory.ADMIN_CHANGE, "r", Instant.now(), null));

            assertEquals(filesBefore, files(), name + ": 출력·임시 파일이 생기면 안 된다");
            assertArrayEquals(before, sha256(jar), name + ": 원본 JAR는 그대로");
            // 4) Java API·Tomcat은 관리자 검증값·CLI 이력을 읽지 않는다(손상과 무관하게 같은 키로 동작)
            CryptoService service = CryptoService.of(JarConfigEditor.read(jar).validated());
            assertEquals("dummy-token", service.decryptText(token), name);
        }
    }

    /** 손상 사례: 이름 → 손상된 JAR(모두 관리자 검증값이 있는 JAR에서 만든다). */
    private Map<String, Path> damagedJars() throws Exception {
        Map<String, Path> jars = new LinkedHashMap<>();
        // 이력 삭제(검증값은 그대로): 새 이력을 시작하면 안 된다
        jars.put("history-deleted", CliHarness.replaceEntry(copy("deleted.jar"), ConfigHistory.ENTRY, null));
        // 빈 이력 파일, 잘린 이력
        jars.put("history-empty", CliHarness.replaceEntry(copy("empty.jar"), ConfigHistory.ENTRY, new byte[0]));
        String plain = new String(historyPlain(app), StandardCharsets.UTF_8);
        jars.put("history-truncated", CliHarness.replaceEntry(copy("truncated.jar"), ConfigHistory.ENTRY,
                ConfigHistory.store(plain.substring(0, plain.length() / 2).getBytes(StandardCharsets.UTF_8))));
        // 해시 변조(한 글자)
        int at = plain.indexOf("entry.1.hash=") + "entry.1.hash=".length();
        char flipped = plain.charAt(at) == 'a' ? 'b' : 'a';
        jars.put("hash-tampered", CliHarness.replaceEntry(copy("hash.jar"), ConfigHistory.ENTRY,
                ConfigHistory.store((plain.substring(0, at) + flipped + plain.substring(at + 1)).getBytes(StandardCharsets.UTF_8))));
        // 관리자 기록 규칙 위반(해시 체인은 정상): 최초 설정 없음, 설정 전 변경, 최초 설정 중복
        jars.put("setup-missing", withAdminRecords("no-setup.jar", ConfigHistory.ADMIN_CHANGE));
        jars.put("change-before-setup", withAdminRecords("order.jar", ConfigHistory.ADMIN_CHANGE, ConfigHistory.ADMIN_SETUP));
        jars.put("setup-twice", withAdminRecords("twice.jar", ConfigHistory.ADMIN_SETUP, ConfigHistory.ADMIN_SETUP));
        // 설정 지문 변조: CLI 밖에서 JAR 안의 설정을 바꿈(이력은 그대로)
        String settings = new String(entry(app, "java-crypto-kit.properties"), StandardCharsets.UTF_8);
        assertTrue(settings.contains("crypto.lang=ko"), settings);
        jars.put("settings-tampered", CliHarness.replaceEntry(copy("settings.jar"), "java-crypto-kit.properties",
                settings.replace("crypto.lang=ko", "crypto.lang=en").getBytes(StandardCharsets.UTF_8)));
        return jars;
    }

    /** 관리자 검증값이 있는 JAR에 해시 체인이 맞는 관리자 기록만 담은 이력을 넣는다(설정은 그대로). */
    private Path withAdminRecords(String name, String... commands) throws Exception {
        Path jar = copy(name);
        byte[] settings = JarConfigEditor.read(jar).settingsBytes;
        ConfigHistory.Log log = ConfigHistory.read(null, JarConfigEditor.read(TestJars.build(dir.resolve("baseline.jar"))).settingsBytes,
                null, null, TestJars.VERSION);
        byte[] plain = null;
        Instant time = Instant.parse("2026-11-24T00:00:00Z");
        for (String command : commands) {
            ConfigHistory.Change change = ConfigHistory.ADMIN_SETUP.equals(command)
                    ? new ConfigHistory.Change(ConfigHistory.ADMIN_SUMMARY, ConfigHistory.ABSENT, ConfigHistory.SECRET_BEFORE)
                    : new ConfigHistory.Change(ConfigHistory.ADMIN_SUMMARY, ConfigHistory.SECRET_BEFORE, ConfigHistory.SECRET_AFTER);
            plain = ConfigHistory.append(log, TestJars.VERSION, time, "ops", command, "r", Collections.singletonList(change), settings);
            log = ConfigHistory.read(ConfigHistory.load(plain), settings, null, null, TestJars.VERSION);
            time = time.plusSeconds(1);
        }
        return CliHarness.replaceEntry(jar, ConfigHistory.ENTRY, ConfigHistory.store(plain));
    }

    @Test
    void adminRecordRulesCatchWhatTheHashChainAloneAccepts() throws Exception {
        // 최초 설정 없이 변경 기록만 있는 이력: 해시 체인·값 연결은 정상이지만 관리자 기록 규칙으로 손상
        Path noSetup = withAdminRecords("rule-no-setup.jar", ConfigHistory.ADMIN_CHANGE);
        assertEquals(null, JarConfigEditor.read(noSetup).history.problem, "체인은 정상(관리자 기록 규칙만으로 잡는 경우)");
        assertEquals(AdminPassword.State.DAMAGED, state(noSetup));
        assertEquals(Messages.get("admin.damaged.records"), AdminPassword.statusOf(JarConfigEditor.read(noSetup)).detail);
        // 설정 전 변경·최초 설정 중복은 이전 기록과 값이 이어지지 않아 이력 검증에서 먼저 손상으로 잡힌다
        for (String[] commands : new String[][]{{ConfigHistory.ADMIN_CHANGE, ConfigHistory.ADMIN_SETUP},
                {ConfigHistory.ADMIN_SETUP, ConfigHistory.ADMIN_SETUP}}) {
            Path jar = withAdminRecords("rule-" + commands[0].replace(' ', '-') + "-" + commands[1].replace(' ', '-') + ".jar", commands);
            assertTrue(JarConfigEditor.read(jar).history.problem != null, Arrays.toString(commands));
            assertEquals(AdminPassword.State.DAMAGED, state(jar), Arrays.toString(commands));
        }
        // 검증값은 있는데 이력이 없음(이력 삭제)
        Path deleted = CliHarness.replaceEntry(copy("rule-deleted.jar"), ConfigHistory.ENTRY, null);
        assertEquals(Messages.get("admin.damaged.noHistory"), AdminPassword.statusOf(JarConfigEditor.read(deleted)).detail);
    }

    // ===================================================================================================
    // 인증 경계: 정책 한 곳, 인증 전에는 JAR 내용을 평가하지 않음
    // ===================================================================================================

    @Test
    void everyCommandHasOnePolicyAndOnlyCommandsWithoutSecretsAreOpen() {
        Set<String> open = new TreeSet<>();
        Set<String> setup = new TreeSet<>();
        Set<String> admin = new TreeSet<>();
        for (CliCommands.Spec spec : CliCommands.ALL) {
            switch (spec.access) {
                case OPEN:
                    open.add(spec.name);
                    break;
                case SETUP:
                    setup.add(spec.name);
                    break;
                default:
                    admin.add(spec.name);
            }
            assertEquals(spec.access == CliCommands.Access.ADMIN, CliCommands.needsAdmin(spec), spec.name);
        }
        // 새 명령을 OPEN으로 두려면 이 목록을 함께 바꿔야 한다(평문·키 원문을 보여 주지 않는 명령만).
        assertEquals(new TreeSet<>(Arrays.asList("doctor", "encrypt", "file encrypt", "fingerprint", "info", "verify")), open);
        assertEquals(Collections.singleton("admin setup"), setup);
        assertEquals(CliCommands.ALL.size() - 7, admin.size(), admin.toString());
        assertThrows(IllegalArgumentException.class, () -> new CliCommands.Spec("x", "x", Collections.<String>emptyList(),
                Collections.<String>emptyList(), false, null), "정책 없는 명령 정의는 만들 수 없다");
    }

    @Test
    void keyRegistrationIsNotRevealedBeforeAuthentication() throws Exception {
        cli.withCliJar(app);
        String token = CryptoService.of(JarConfigEditor.read(app).validated()).encryptText("dummy-token".toCharArray());
        // 같은 명령에서 등록된 Key ID와 없는 Key ID가 인증 전에는 같은 응답(ADMIN_AUTH)이다.
        String[][] pairs = {
            {"config key show --key-id default", "config key show --key-id notthere"},
            {"config key use --key-id default --operator ops --reason r --yes",
                "config key use --key-id notthere --operator ops --reason r --yes"},
            {"config key remove --key-id default --operator ops --reason r --yes",
                "config key remove --key-id notthere --operator ops --reason r --yes"},
            {"rekey --key-id default --value " + token, "rekey --key-id notthere --value " + token},
            {"config key add --key-id pass-default --generate --export " + dir.resolve("g.backup") + " --operator ops --reason r --yes"
                + "", "config key add --key-id free01 --generate --export " + dir.resolve("g.backup") + " --operator ops"
                + " --reason r --yes"}};
        for (String[] pair : pairs) {
            String first = null;
            for (String line : pair) {
                String[] args = line.split(" ");
                for (int i = 0; i < args.length; i++) if (args[i].endsWith(".jar")) args[i] = dir.resolve(args[i]).toString();
                assertEquals(1, cli.run(args), line);
                assertTrue(cli.err().contains("[사유: ADMIN_AUTH]") && !cli.err().contains("CONFIGURATION"), line + ": " + cli.err());
                if (first == null) {
                    first = cli.err();
                } else {
                    assertEquals(first, cli.err(), "Key ID 등록 여부에 따라 인증 전 응답이 달라지면 안 된다: " + line);
                }
            }
        }
        // embed-key: 현재 Key ID와 같은 ID(충돌)도 인증 전에는 알리지 않는다
        Path keyFile = TestSupport.writeRandomKeyFile(dir, "e.key");
        assertEquals(1, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "default", "--operator", "ops",
                "--reason", "r", "--yes"));
        assertTrue(cli.err().contains("[사유: ADMIN_AUTH]"), cli.err());
        // 인자 형식 오류는 인증 전에 바로 알린다(비밀 자료와 무관): 비밀번호를 묻기 전에 끝남
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        assertEquals(1, cli.run(terminal, "config", "history", "--all", "--type", "key"));
        assertTrue(cli.err().contains("--type과 --all은 함께 쓸 수 없습니다") && terminal.prompts.isEmpty(), cli.err());
        assertEquals(1, cli.run(terminal, "config", "key", "show", "--key-id", "bad id!"));
        assertTrue(terminal.prompts.isEmpty(), "형식 오류에서 비밀번호를 묻지 않는다");
    }

    // ===================================================================================================
    // 결과 JAR·백업 권한(POSIX)
    // ===================================================================================================

    @Test
    void setupProtectsJarAndLaterUpdatesKeepDeployedPermissions() throws Exception {
        assumeTrue(JarConfigEditor.posix(), "POSIX filesystem required");
        Path fresh = TestJars.build(dir.resolve("fresh-permissions.jar"));
        Files.setPosixFilePermissions(fresh, PosixFilePermissions.fromString("rw-r--r--"));
        cli.withCliJar(fresh);
        assertEquals(0, cli.run("admin", "setup", "--admin-pass-file", pwFile), cli.err());
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(fresh)));
        Files.setPosixFilePermissions(fresh, PosixFilePermissions.fromString("rw-r-----"));
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "ops", "--replace",
                "--admin-pass-file", pwFile), cli.err());
        assertEquals("rw-r-----", PosixFilePermissions.toString(Files.getPosixFilePermissions(fresh)));
    }

    // ===================================================================================================
    // 도우미
    // ===================================================================================================

    private static AdminPassword.State state(Path jar) throws Exception {
        return AdminPassword.statusOf(JarConfigEditor.read(jar)).state;
    }

    private Path copy(String name) throws Exception {
        return Files.copy(app, dir.resolve(name));
    }

    private static byte[] entry(Path jar, String name) throws Exception {
        return CliHarness.effectiveEntry(jar, name);
    }

    private static byte[] historyPlain(Path jar) throws Exception {
        return LightObfuscation.decodeFile(entry(jar, ConfigHistory.ENTRY));
    }

    private static byte[] sha256(Path file) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file));
    }

    private List<String> files() throws Exception {
        try (Stream<Path> list = Files.list(dir)) {
            return list.map(p -> p.getFileName().toString()).sorted().collect(Collectors.toList());
        }
    }

    private static CliHarness.FakeTerminal terminal(String... secrets) {
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.secrets.addAll(Arrays.asList(secrets));
        return terminal;
    }
}
