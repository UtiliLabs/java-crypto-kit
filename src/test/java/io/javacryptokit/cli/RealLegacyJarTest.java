package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.KeyType;
import io.javacryptokit.TestJars;
import io.javacryptokit.TestSupport;
import io.javacryptokit.core.CryptoService;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 실제 이전 형식 바이너리와의 호환(선택 시험). 환경변수 {@code JCK_LEGACY_JAR}에 실제로 배포·빌드한 이전 버전 JAR 경로를 주면
 * 실행하고, 없으면 건너뛴다(저장소에는 JAR를 두지 않는다). 모의 이전 버전 JAR({@link TestJars#buildLegacy})로 하는 시험을 실제 바이너리로
 * 다시 확인한다:
 * <ul>
 *   <li>새 CLI는 이전 JAR를 이전 버전(관리자 비밀번호 기능 없음)으로 읽고, 편집 결과를 이전 형식(표준 Base64 내장 키·평문 이력,
 *       관리자 항목 없음)으로 쓴다(실행 중인 CLI JAR의 관리자 인증으로 편집).</li>
 *   <li>이전 바이너리가 편집된 JAR를 자기 코드로 그대로 실행한다(CLI info·config history·file, Java API 암복호화).</li>
 *   <li>이전 바이너리의 암호문·JCKF 파일을 새 코드가, 새 코드의 것을 이전 바이너리가 복호화한다.</li>
 * </ul>
 * 실행 예: {@code JCK_LEGACY_JAR=/path/legacy/java-crypto-kit.jar ./gradlew test --tests io.javacryptokit.cli.RealLegacyJarTest}
 */
class RealLegacyJarTest {
    private static final String PW = CliHarness.ADMIN_PASSWORD;

    @TempDir
    Path dir;
    private CliHarness cli;
    private Path legacy;
    private String pwFile;

    @BeforeEach
    void setUp() throws Exception {
        String value = System.getenv("JCK_LEGACY_JAR");
        assumeTrue(value != null && !value.trim().isEmpty() && Files.isRegularFile(Paths.get(value.trim())),
                "JCK_LEGACY_JAR(실제 이전 버전 JAR 경로)가 없어 건너뜀");
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        legacy = Files.copy(Paths.get(value.trim()), dir.resolve("java-crypto-kit-legacy.jar"));
        cli = new CliHarness();
        cli.withCliJar(CliHarness.configure(TestJars.build(dir.resolve("cli.jar")), PW));
        pwFile = CliHarness.passFile(dir, PW);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (cli != null) cli.close();
    }

    @Test
    void newCliReadsTheRealOldJarAndWritesEditsInTheOldFormat() throws Exception {
        assertEquals(AdminPassword.State.LEGACY, AdminPassword.statusOf(JarConfigEditor.read(legacy)).state);
        assertEquals(0, cli.run("config", "show", "--jar", legacy.toString(), "--admin-pass-file", pwFile), cli.err());
        assertTrue(cli.out().contains("관리자    : 지원 안 함(이전 버전 JAR, CLI 인증 없음)"), cli.out());
        Path edited = edit();
        String settings = text(edited, "java-crypto-kit.properties");
        String key = new String(Files.readAllBytes(dir.resolve("old.key")), StandardCharsets.US_ASCII).trim();
        assertTrue(settings.contains("crypto.key.embedded=" + key) && !settings.contains("obf1:"),
                "이전 버전은 obf1을 모르므로 표준 Base64로 둔다: " + settings);
        String history = text(edited, ConfigHistory.ENTRY);
        assertTrue(history.contains("entry.1.command=embed-key") && history.contains("entry.2.command=set") && !history.startsWith("obf1:"),
                history);
        assertEquals(null, entry(edited, AdminPassword.ENTRY), "이전 버전 JAR에는 관리자 정보를 쓰지 않는다");
        assertEquals(AdminPassword.State.LEGACY, AdminPassword.statusOf(JarConfigEditor.read(edited)).state);
        assertEquals(0, cli.run("config", "history", "--all", "--jar", edited.toString(), "--admin-pass-file", pwFile), cli.err());
        assertTrue(cli.out().contains("이력 검증 : 정상(2건") && cli.out().contains("crypto.key.id: default -> old01"), cli.out());
    }

    @Test
    void theOldBinaryRunsTheEditedJarAndTokensAndFilesWorkBothWays() throws Exception {
        Path edited = edit();
        // 이전 바이너리 자신의 CLI(별도 JVM): 새 CLI가 쓴 설정·이력을 읽는다
        TestJars.Run history = TestJars.run(edited, Collections.<String>emptyList(), "config", "history");
        assertEquals(0, history.exit, history.toString());
        assertTrue(history.out.contains("old01"), history.toString());
        TestJars.Run info = TestJars.run(edited, Collections.<String>emptyList(), "info");
        assertEquals(0, info.exit, info.toString());
        assertTrue(info.out.contains("old01"), info.toString());

        // 이전 바이너리의 Java API ↔ 새 코드: 같은 JAR 설정(키 old01)으로 서로의 암호문을 복호화한다
        CryptoService current = CryptoService.of(JarConfigEditor.read(edited).validated());
        try (URLClassLoader loader = new URLClassLoader(new URL[]{edited.toUri().toURL()}, null)) {
            Class<?> api = loader.loadClass("io.javacryptokit.CredentialCrypto");
            Object old = api.getMethod("fromDefaultConfiguration").invoke(null);
            Method encrypt = api.getMethod("encryptText", String.class);
            Method decrypt = api.getMethod("decryptText", String.class);
            String oldToken = (String) encrypt.invoke(old, "dummy-old");
            assertTrue(oldToken.startsWith("ENC[v1:old01:"), oldToken);
            assertEquals("dummy-old", current.decryptText(oldToken));
            String newToken = current.encryptText("dummy-new".toCharArray(), KeyType.KEY, "old01");
            assertEquals("dummy-new", decrypt.invoke(old, newToken));
            // 편집 전 공개 기본 키(default) 암호문은 새 버전의 공개 키와 같다(기존 암호문 호환)
            String publicToken = TestSupport.jarDefaults().encryptText("dummy-public", KeyType.KEY);
            try (URLClassLoader original = new URLClassLoader(new URL[]{legacy.toUri().toURL()}, null)) {
                Class<?> originalApi = original.loadClass("io.javacryptokit.CredentialCrypto");
                Object originalCrypto = originalApi.getMethod("fromDefaultConfiguration").invoke(null);
                assertEquals("dummy-public", originalApi.getMethod("decryptText", String.class).invoke(originalCrypto, publicToken));
            }
        }

        // JCKF 파일: 이전 바이너리 CLI로 암호화 → 새 코드로 복호화, 새 코드로 암호화 → 이전 바이너리 CLI로 복호화
        Path plain = Files.write(dir.resolve("report.csv"), "id,name\n1,example\n".getBytes(StandardCharsets.UTF_8));
        TestJars.Run fileEnc = TestJars.run(edited, Collections.<String>emptyList(), "file", "encrypt", "--in", plain.toString(),
                "--out", dir.resolve("old.jck").toString());
        assertEquals(0, fileEnc.exit, fileEnc.toString());
        current.decryptFile(dir.resolve("old.jck"), dir.resolve("old-back.csv"));
        assertEquals("id,name\n1,example\n", new String(Files.readAllBytes(dir.resolve("old-back.csv")), StandardCharsets.UTF_8));
        current.encryptFile(plain, dir.resolve("new.jck"), KeyType.KEY, "old01");
        TestJars.Run fileDec = TestJars.run(edited, Collections.<String>emptyList(), "file", "decrypt", "--in",
                dir.resolve("new.jck").toString(), "--out", dir.resolve("new-back.csv").toString());
        assertEquals(0, fileDec.exit, fileDec.toString());
        assertEquals("id,name\n1,example\n", new String(Files.readAllBytes(dir.resolve("new-back.csv")), StandardCharsets.UTF_8));
        assertFalse(fileDec.out.contains("example") || fileDec.err.contains("example"), "평문을 출력하지 않는다");
    }

    /** 새 CLI(실행 중인 JAR의 관리자 인증)로 실제 이전 JAR에 AES 키를 넣고 설정 하나를 바꾼다. */
    private Path edit() throws Exception {
        Path keyFile = TestSupport.writeKeyFile(dir, "old.key", java.util.Base64.getEncoder().encodeToString(randomKey()));
        Path embedded = dir.resolve("old-embedded.jar");
        assertEquals(0, cli.run("config", "embed-key", "--from-file", keyFile.toString(), "--key-id", "old01", "--operator", "ops",
                "--reason", "이전 JAR 키 교체", "--yes", "--jar", legacy.toString(), "--out", embedded.toString(),
                "--admin-pass-file", pwFile), cli.err());
        Path edited = dir.resolve("old-edited.jar");
        assertEquals(0, cli.run("config", "set", "crypto.lang=en", "--operator", "ops", "--jar", embedded.toString(),
                "--out", edited.toString(), "--admin-pass-file", pwFile), cli.err());
        return edited;
    }

    private static byte[] randomKey() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        return key;
    }

    private static String text(Path jar, String name) throws Exception {
        byte[] bytes = entry(jar, name);
        return bytes == null ? null : new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] entry(Path jar, String name) throws Exception {
        try (JarFile file = new JarFile(jar.toFile())) {
            JarEntry entry = file.getJarEntry(name);
            if (entry == null) return null;
            try (InputStream in = file.getInputStream(entry)) {
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int read;
                while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
                return out.toByteArray();
            }
        }
    }
}
