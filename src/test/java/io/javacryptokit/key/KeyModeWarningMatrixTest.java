package io.javacryptokit.key;

import io.javacryptokit.CredentialCrypto;

import io.javacryptokit.CredentialCryptoException;

import io.javacryptokit.TestSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.config.CryptoSettings;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * 키 공급 방식 3종(embedded/file/env) × 경고 정책(crypto.warning.enabled=true/false) 시나리오 검증.
 * 경고 표시 여부만 바뀌고 암복호화 동작·Fail Closed는 그대로인지 확인한다.
 */
class KeyModeWarningMatrixTest {
    @TempDir
    Path dir;

    /** 개발자 PC·IDE 실행 옵션에 남은 -Dcrypto.* 값이 시험 결과에 섞이지 않도록 비우고, 끝나면 되돌린다. */
    private AutoCloseable jvmIsolation;

    @BeforeEach
    void resetWarningState() {
        // "이미 경고함" 표시를 비워 테스트 실행 순서와 관계없이 결과가 같게 한다.
        DefaultKeyWarning.resetForTests();
        jvmIsolation = TestSupport.jvmSettings();
    }

    @AfterEach
    void restoreJvmProperties() throws Exception {
        if (jvmIsolation != null) jvmIsolation.close();
    }

    @ParameterizedTest(name = "{0} 모드, crypto.warning.enabled={1}")
    @CsvSource({"embedded,true", "embedded,false", "file,true", "file,false", "env,true", "env,false"})
    void everyKeyModeRoundTripsAndFollowsWarningPolicy(String source, boolean warningEnabled) throws Exception {
        Path config = configFor(source, warningEnabled, false);
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
            String token = crypto.encryptText("dummy-값-" + source);
            assertEquals("dummy-값-" + source, crypto.decryptText(token));
            assertTrue(crypto.verify(token));
            assertEquals(source, crypto.keySource());
            // embedded 기본 키는 공개 키이므로 경고 대상이고, file/env의 난수 키는 경고 대상이 아니다.
            int expected = warningEnabled && "embedded".equals(source) ? 1 : 0;
            assertEquals(expected, log.warnings().size(), log.warnings().toString());
        }
    }

    @ParameterizedTest(name = "공개 기본 키를 {0}로 공급, crypto.warning.enabled={1}")
    @CsvSource({"file,true", "file,false", "env,true", "env,false"})
    void publicDefaultKeyIsDetectedRegardlessOfSource(String source, boolean warningEnabled) throws Exception {
        Path config = configFor(source, warningEnabled, true);
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
            assertEquals("dummy", crypto.decryptText(crypto.encryptText("dummy")));
            List<String> warnings = log.warnings();
            if (warningEnabled) {
                assertEquals(1, warnings.size(), warnings.toString());
                assertTrue(warnings.get(0).contains("공개 기본 키"));
                assertTrue(warnings.get(0).contains("키 공급 방식: " + source));
                assertFalse(warnings.get(0).contains(TestSupport.publicKeyBase64()), "키 값이 로그에 나오면 안 된다");
            } else {
                assertTrue(warnings.isEmpty(), warnings.toString());
            }
        }
    }

    @ParameterizedTest(name = "교체한 내장 키, crypto.warning.enabled={0}")
    @ValueSource(booleans = {true, false})
    void replacedEmbeddedKeyWarnsAboutExtractionOnlyWhenEnabled(boolean warningEnabled) throws Exception {
        String randomKey = new String(java.nio.file.Files.readAllBytes(TestSupport.writeRandomKeyFile(dir, "r.key")),
                java.nio.charset.StandardCharsets.US_ASCII).trim();
        Path config = TestSupport.writeConfig(dir, "embedded-custom.properties",
                "crypto.key.source=embedded", "crypto.key.embedded=" + randomKey,
                "crypto.warning.enabled=" + warningEnabled);
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
            crypto.decryptText(crypto.encryptText("dummy"));
            List<String> warnings = log.warnings();
            assertEquals(warningEnabled ? 1 : 0, warnings.size(), warnings.toString());
            if (warningEnabled) {
                assertTrue(warnings.get(0).contains("JAR 내장 키"));
                assertFalse(warnings.get(0).contains(randomKey));
            }
        }
    }

    @Test
    void embeddedKeyFromAnExternalFileIsDescribedWithItsRealOrigin() throws Exception {
        // 외부 Properties에 적은 내장 키를 info·doctor가 "JAR 내장"으로 잘못 안내하지 않아야 한다(키 값은 표시하지 않음).
        String randomKey = new String(java.nio.file.Files.readAllBytes(TestSupport.writeRandomKeyFile(dir, "o.key")),
                java.nio.charset.StandardCharsets.US_ASCII).trim();
        Path config = TestSupport.writeConfig(dir, "embedded-origin.properties",
                "crypto.key.source=embedded", "crypto.key.embedded=" + randomKey);
        String external = io.javacryptokit.core.CryptoService.of(CryptoSettings.load(config.toString(), name -> null, name -> null))
                .describeKeyLocation();
        assertTrue(external.contains("외부 설정 파일") && !external.contains("JAR 내장"), external);
        assertFalse(external.contains(randomKey), "키 값은 표시하지 않는다");
        String builtIn = io.javacryptokit.core.CryptoService.of(CryptoSettings.load(null, name -> null, name -> null))
                .describeKeyLocation();
        assertTrue(builtIn.contains("JAR 내장"), builtIn);
    }

    @Test
    void warningIsNotRepeatedAcrossManyOperationsAndInstances() throws Exception {
        Path config = configFor("embedded", true, false);
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            for (int instance = 0; instance < 3; instance++) {
                CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
                for (int i = 0; i < 5; i++) crypto.decryptText(crypto.encryptText("dummy-" + i));
            }
            assertEquals(1, log.warnings().size(), "같은 JVM에서 같은 경고는 한 번만 나와야 한다");
        }
    }

    @Test
    void disabledPolicyDoesNotConsumeTheOneTimeWarning() throws Exception {
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            // 경고를 끈 설정이 먼저 실행돼도
            CredentialCrypto quiet = CredentialCrypto.fromConfigFile(configFor("embedded", false, false));
            quiet.decryptText(quiet.encryptText("dummy"));
            assertTrue(log.warnings().isEmpty());
            // 이후 경고를 켠 설정에서는 경고가 정상적으로 나와야 한다.
            CredentialCrypto loud = CredentialCrypto.fromConfigFile(configFor("embedded", true, false));
            loud.decryptText(loud.encryptText("dummy"));
            assertEquals(1, log.warnings().size());
        }
    }

    @Test
    void missingWarningPropertyKeepsDefaultTrue() throws Exception {
        // 이 항목이 없는 이전 외부 설정 파일은 JAR 기본값(true)을 그대로 쓴다.
        Path config = TestSupport.writeConfig(dir, "old.properties", "crypto.key.source=embedded");
        assertTrue(TestSupport.isolatedSettings(config).warningEnabled());
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
            crypto.decryptText(crypto.encryptText("dummy"));
            assertEquals(1, log.warnings().size());
        }
    }

    @ParameterizedTest(name = "잘못된 경고 정책 값 \"{0}\"은 거부")
    @ValueSource(strings = {"", " ", "TRUE", "False", "yes", "1", "off"})
    void invalidWarningPolicyValueIsRejected(String value) throws Exception {
        Path config = TestSupport.writeConfig(dir, "bad-warning.properties", "crypto.warning.enabled=" + value);
        assertThrows(IllegalArgumentException.class, () -> TestSupport.isolatedSettings(config));
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(config));
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION, ex.getReason());
        assertTrue(ex.getMessage().contains("crypto.warning.enabled"));
    }

    @Test
    void disabledWarningsStillFailClosedWhenFileKeyIsMissing() throws Exception {
        Path missingKey = dir.resolve("missing.key");
        Path config = TestSupport.writeConfig(dir, "missing-file.properties", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(missingKey), "crypto.warning.enabled=false");
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
            CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> crypto.encryptText("dummy"));
            assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason());
            assertTrue(log.warnings().isEmpty());
        }
    }

    @Test
    void disabledWarningsStillFailClosedWhenEnvKeyIsMissing() throws Exception {
        Path config = TestSupport.writeConfig(dir, "missing-env.properties", "crypto.key.source=env",
                "crypto.key.env=JAVA_CRYPTO_KIT_UNSET_" + Long.toHexString(System.nanoTime() & 0xffffffffL),
                "crypto.warning.enabled=false");
        CredentialCrypto crypto = CredentialCrypto.fromConfigFile(config);
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class, () -> crypto.encryptText("dummy"));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason());
    }

    // ===== JVM 속성(-Dcrypto.warning.enabled)과 외부 Properties의 경고 정책 우선순위(실제 System 속성 사용) =====

    @ParameterizedTest(name = "외부 경고={0}, -Dcrypto.warning.enabled={1}, 외부 정책={2} → WARNING {3}건")
    @CsvSource({
            "-,-,-,1",            // 1. 아무 설정 없음: 기본값 true → 출력
            "false,-,-,0",        // 2. Properties false → 미출력
            "-,false,-,0",        // 3. 외부 파일 없이 -D false 하나만 → 미출력
            "-,true,-,1",         // 4. -D true → 출력
            "false,true,-,1",     // 4. 외부 false보다 -D true가 우선 → 출력
            "true,false,true,0",  // 5. 외부 true + 정책 true + -D false → -D 우선 → 미출력
            "true,false,false,1"  // 6. 외부 정책 false → -D 무시 → 외부 true 적용 → 출력
    })
    void warningPolicyFollowsPropertiesAndJvmPrecedence(String fileValue, String jvmValue, String policy, int expected)
            throws Exception {
        List<String> lines = new ArrayList<>();
        if (!"-".equals(fileValue)) lines.add("crypto.warning.enabled=" + fileValue);
        if (!"-".equals(policy)) lines.add("crypto.jvm.override.enabled=" + policy);
        Path config = lines.isEmpty() ? null : TestSupport.writeConfig(dir, "w.properties", lines.toArray(new String[0]));
        String[] jvm = "-".equals(jvmValue) ? new String[0] : new String[]{"crypto.warning.enabled=" + jvmValue};
        try (AutoCloseable paths = isolateConfigPaths();
             AutoCloseable props = TestSupport.jvmSettings(jvm);
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            CredentialCrypto crypto = config == null
                    ? CredentialCrypto.fromDefaultConfiguration() : CredentialCrypto.fromConfigFile(config);
            String token = crypto.encryptText("dummy-경고-값");
            // 8. 경고 정책은 표시 여부만 바꾸고 암복호화 결과에는 영향을 주지 않는다.
            assertEquals("dummy-경고-값", crypto.decryptText(token));
            assertTrue(crypto.verify(token));
            assertEquals(expected, log.warnings().size(), log.warnings().toString());
        }
    }

    @ParameterizedTest(name = "공개 기본 키를 -D로 지정한 {0} 공급원으로 사용, -Dcrypto.warning.enabled={1}")
    @CsvSource({"file,true", "file,false", "env,true", "env,false"})
    void publicKeyFromJvmConfiguredSourceFollowsJvmWarningPolicy(String source, boolean warningEnabled) throws Exception {
        String[] jvm;
        if ("file".equals(source)) {
            Path key = TestSupport.writeKeyFile(dir, "jvm-public.key", TestSupport.publicKeyBase64());
            jvm = new String[]{"crypto.key.source=file", "crypto.key.file=" + TestSupport.propertiesPath(key),
                    "crypto.warning.enabled=" + warningEnabled};
        } else {
            assumeTrue(System.getenv(TestSupport.ENV_PUBLIC_KEY) != null, "Gradle test 태스크의 테스트용 환경변수가 필요하다");
            jvm = new String[]{"crypto.key.source=env", "crypto.key.env=" + TestSupport.ENV_PUBLIC_KEY,
                    "crypto.warning.enabled=" + warningEnabled};
        }
        try (AutoCloseable paths = isolateConfigPaths();
             AutoCloseable props = TestSupport.jvmSettings(jvm);
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration();
            assertEquals(source, crypto.keySource());
            assertEquals("dummy", crypto.decryptText(crypto.encryptText("dummy")));
            List<String> warnings = log.warnings();
            if (warningEnabled) {
                assertEquals(1, warnings.size(), warnings.toString());
                assertTrue(warnings.get(0).contains("키 공급 방식: " + source));
                assertFalse(warnings.get(0).contains(TestSupport.publicKeyBase64()), "키 값이 로그에 나오면 안 된다");
            } else {
                assertTrue(warnings.isEmpty(), "false이면 우회 안내문도 남기지 않는다: " + warnings);
            }
        }
    }

    @Test
    void warningsOffFromJvmNeverDisableSecurityChecks() throws Exception {
        // 7. -Dcrypto.warning.enabled=false여도 변조 검증 실패·외부 키 누락은 그대로 오류다.
        try (AutoCloseable paths = isolateConfigPaths();
             AutoCloseable props = TestSupport.jvmSettings("crypto.warning.enabled=false");
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            CredentialCrypto crypto = CredentialCrypto.fromDefaultConfiguration();
            String token = crypto.encryptText("dummy");
            String tampered = token.substring(0, token.length() - 3)
                    + (token.charAt(token.length() - 3) == 'A' ? 'B' : 'A') + token.substring(token.length() - 2);
            CredentialCryptoException integrity = assertThrows(CredentialCryptoException.class,
                    () -> crypto.decryptText(tampered));
            assertEquals(CredentialCryptoException.Reason.INTEGRITY, integrity.getReason());
            assertFalse(crypto.verify(tampered));
            try (AutoCloseable fileKey = TestSupport.jvmSettings("crypto.warning.enabled=false", "crypto.key.source=file",
                    "crypto.key.file=" + TestSupport.propertiesPath(dir.resolve("none.key")))) {
                CredentialCryptoException keyError = assertThrows(CredentialCryptoException.class,
                        () -> CredentialCrypto.fromDefaultConfiguration().encryptText("dummy"));
                assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, keyError.getReason(), "내장 키로 대체하지 않는다");
            }
            assertTrue(log.warnings().isEmpty(), log.warnings().toString());
        }
    }

    @ParameterizedTest(name = "잘못된 -Dcrypto.warning.enabled=\"{0}\"은 거부")
    @ValueSource(strings = {"", " ", "TRUE", "False", "yes", "1", "off"})
    void invalidWarningValueFromJvmIsRejected(String value) throws Exception {
        // 9. 잘못된 boolean 값은 조용히 기본값으로 바꾸지 않고 설정 오류로 중단한다.
        try (AutoCloseable paths = isolateConfigPaths();
             AutoCloseable props = TestSupport.jvmSettings("crypto.warning.enabled=" + value)) {
            CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                    CredentialCrypto::fromDefaultConfiguration);
            assertEquals(CredentialCryptoException.Reason.CONFIGURATION, ex.getReason());
            assertTrue(ex.getMessage().contains("crypto.warning.enabled"));
        }
    }

    @Test
    void misspelledJvmWarningPropertyFailsInsteadOfBeingIgnored() throws Exception {
        // -Dcrypto.warning.enable=false(마지막 d 누락)를 무시하면 운영자는 경고를 껐다고 착각한다 → 설정 오류로 중단.
        try (AutoCloseable paths = isolateConfigPaths();
             AutoCloseable props = TestSupport.jvmSettings("crypto.warning.enable=false")) {
            CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                    CredentialCrypto::fromDefaultConfiguration);
            assertEquals(CredentialCryptoException.Reason.CONFIGURATION, ex.getReason());
            assertTrue(ex.getMessage().contains("'crypto.warning.enabled'"), ex.getMessage());
        }
    }

    @Test
    void typoValidationStillWorksWhenWarningsAreOff() throws Exception {
        // WARN OFF는 안내 로그만 끈다. 설정 오류 검증(키 공급 이름 오타)은 그대로 동작해야 한다.
        try (AutoCloseable paths = isolateConfigPaths();
             AutoCloseable props = TestSupport.jvmSettings("crypto.warning.enabled=false", "crypto.key.soruce=file");
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                    CredentialCrypto::fromDefaultConfiguration);
            assertEquals(CredentialCryptoException.Reason.CONFIGURATION, ex.getReason());
            assertTrue(log.warnings().isEmpty(), log.warnings().toString());
        }
    }

    /** 실제 환경의 설정 경로(JVM 속성)를 잠시 비운다. 설정 경로 환경변수가 있으면 결과가 달라지므로 시험을 건너뛴다. */
    private static AutoCloseable isolateConfigPaths() {
        assumeTrue(TestSupport.noConfigEnvironmentVariables(), "설정 경로 환경변수가 있으면 기본 탐색 시험을 할 수 없다");
        AutoCloseable common = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, null);
        AutoCloseable others = TestSupport.clearOtherConfigProperties();
        return () -> {
            others.close();
            common.close();
        };
    }

    /** 키 공급 방식별 외부 설정 파일을 만든다(공개 키 사용 여부 선택). */
    private Path configFor(String source, boolean warningEnabled, boolean usePublicKey) throws Exception {
        switch (source) {
            case "embedded":
                return TestSupport.writeConfig(dir, "embedded-" + warningEnabled + ".properties",
                        "crypto.key.source=embedded", "crypto.warning.enabled=" + warningEnabled);
            case "file":
                Path key = usePublicKey
                        ? TestSupport.writeKeyFile(dir, "public-" + warningEnabled + ".key", TestSupport.publicKeyBase64())
                        : TestSupport.writeRandomKeyFile(dir, "random-" + warningEnabled + ".key");
                return TestSupport.writeConfig(dir, "file-" + warningEnabled + "-" + usePublicKey + ".properties",
                        "crypto.key.source=file", "crypto.key.id=file01",
                        "crypto.key.file=" + TestSupport.propertiesPath(key), "crypto.warning.enabled=" + warningEnabled);
            default:
                String envName = usePublicKey ? TestSupport.ENV_PUBLIC_KEY : TestSupport.ENV_TEST_KEY;
                assumeTrue(System.getenv(envName) != null, "Gradle test 태스크가 넣는 테스트용 환경변수가 필요하다");
                return TestSupport.writeConfig(dir, "env-" + warningEnabled + "-" + usePublicKey + ".properties",
                        "crypto.key.source=env", "crypto.key.id=env01",
                        "crypto.key.env=" + envName, "crypto.warning.enabled=" + warningEnabled);
        }
    }
}
