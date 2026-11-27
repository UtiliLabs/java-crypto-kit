package io.javacryptokit.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.TestJars;
import io.javacryptokit.TestSupport;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Optional binary compatibility check. JCK_LEGACY_JAR selects a real older release.
 * Fixtures keep the original JAR unchanged and share a test-only external key between versions.
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
    void olderJarStaysReadableAndRejectsInPlaceMutation() throws Exception {
        JarConfigEditor.Snapshot before = JarConfigEditor.read(legacy);
        assertEquals(null, before.stateFormat);
        assertEquals(1, cli.run("config", "set", "crypto.lang=en", "--operator", "ops",
                "--jar", legacy.toString(), "--admin-pass-file", pwFile));
        assertTrue(cli.err().contains("예약된 설정 영역이 없습니다"), cli.err());
        assertEquals(before.fileSha256, JarConfigEditor.sha256(legacy));
        assertEquals(null, JarConfigEditor.read(legacy).history.problem);
    }

    @Test
    void sharesUserKeyWithOlderBinaryAndReadsItsJckfFiles() throws Exception {
        Path key = TestSupport.writeRandomKeyFile(dir, "compat.key");
        String slot = "crypto.key.file=" + key.toString().replace('\\', '/');
        boolean keyType = JarConfigEditor.read(legacy).settings.containsKey("crypto.key.type");
        String[] legacySettings = keyType
                ? new String[]{"crypto.key.id=compat01", "crypto.key.source=file", slot, "crypto.key.type=key"}
                : new String[]{"crypto.key.id=compat01", "crypto.key.source=file", slot};
        Path legacyConfig = TestSupport.writeConfig(dir, "legacy.properties", legacySettings);
        Path currentConfig = TestSupport.writeConfig(dir, "current.properties",
                "crypto.key.id=compat01", "crypto.key.source=file", slot, "crypto.key.type=key");
        io.javacryptokit.CredentialCrypto current = io.javacryptokit.CredentialCrypto.fromConfigFile(currentConfig);
        try (URLClassLoader loader = new URLClassLoader(new URL[]{legacy.toUri().toURL()}, null)) {
            Class<?> api = loader.loadClass("io.javacryptokit.CredentialCrypto");
            Object old = api.getMethod("fromConfigFile", Path.class).invoke(null, legacyConfig);
            String token = (String) api.getMethod("encryptText", String.class).invoke(old, "legacy sample");
            assertEquals("legacy sample", current.decryptText(token));
            assertEquals("current sample", api.getMethod("decryptText", String.class)
                    .invoke(old, current.encryptText("current sample")));
            Path plain = Files.write(dir.resolve("report.csv"), "qa,test\n".getBytes(StandardCharsets.UTF_8));
            Path sealed = dir.resolve("old.jck");
            api.getMethod("encryptFile", Path.class, Path.class).invoke(old, plain, sealed);
            Path restored = dir.resolve("restored.csv");
            current.decryptFile(sealed, restored);
            org.junit.jupiter.api.Assertions.assertArrayEquals(Files.readAllBytes(plain), Files.readAllBytes(restored));
        }
    }
}
