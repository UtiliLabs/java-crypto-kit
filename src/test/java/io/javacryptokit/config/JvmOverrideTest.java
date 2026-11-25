package io.javacryptokit.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings.ValueOrigin;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.key.KeyResolver;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * JVM 개별 속성(-Dcrypto.*) 덮어쓰기 규칙을 설정 로더 수준에서 검증한다.
 *
 * <p>실제 System 속성은 바꾸지 않고 조회 함수({@code Map::get})를 주입하므로 다른 테스트와 섞이지 않는다.
 * 실제 {@code System.getProperty} 경로는 CLI·Factory·경고 시험에서 따로 확인한다.</p>
 *
 * <ul>
 *   <li>A: 외부 파일·JVM 속성 없음 → JAR 기본값</li>
 *   <li>B: JVM 속성만(외부 파일 없음)으로 file 키 구성</li>
 *   <li>C: 외부 Properties만</li>
 *   <li>D: 혼합 - 키는 외부 파일, 경고만 JVM 속성</li>
 *   <li>E: JVM 속성으로 env 키 구성</li>
 *   <li>F: 외부 파일의 crypto.jvm.override.enabled=false → JVM 속성 무시(정책은 -D로 우회 불가)</li>
 * </ul>
 */
class JvmOverrideTest {
    @TempDir
    Path dir;

    /** "이름=값" 목록으로 가짜 JVM 속성 조회 함수를 만든다. */
    private static Map<String, String> jvm(String... pairs) {
        Map<String, String> map = new LinkedHashMap<>();
        for (String pair : pairs) {
            int separator = pair.indexOf('=');
            map.put(pair.substring(0, separator), pair.substring(separator + 1));
        }
        return map;
    }

    /** 실제 환경변수·System 속성과 무관하게 지정한 외부 파일과 가짜 JVM 속성만으로 설정을 읽는다. */
    private static CryptoSettings load(Path config, Map<String, String> jvm) throws IOException {
        return CryptoSettings.load(config == null ? null : config.toString(), jvm::get, name -> null);
    }

    private Path keyFile(String name) throws IOException {
        return TestSupport.writeRandomKeyFile(dir, name);
    }

    @Test
    void scenarioA_noExternalFileAndNoJvmPropertiesUsesJarDefaults() throws Exception {
        CryptoSettings settings = load(null, jvm());
        assertEquals("embedded", settings.keySource());
        assertEquals("default", settings.keyId(), "기존 암호문 호환을 위해 기본 키ID는 default");
        assertTrue(settings.warningEnabled());
        assertTrue(settings.jvmOverrideEnabled(), "기본 정책은 true");
        assertTrue(settings.jvmOverriddenKeys().isEmpty());
        assertFalse(settings.externalConfigUsed());
        assertEquals(ValueOrigin.JAR_DEFAULT, settings.valueOrigin(CryptoSettings.JVM_OVERRIDE_ENABLED));
        assertEquals(ValueOrigin.JAR_DEFAULT, settings.valueOrigin(CryptoSettings.KEY_SOURCE));
    }

    @Test
    void scenarioB_jvmPropertiesAloneConfigureFileKeyWithoutExternalFile() throws Exception {
        Path key = keyFile("b.key");
        CryptoSettings settings = load(null, jvm(
                "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(key),
                "crypto.key.id=prod01",
                "crypto.algorithm=AES/GCM/NoPadding",
                "crypto.warning.enabled=false"));
        assertFalse(settings.externalConfigUsed(), "외부 Properties 파일 없이 동작해야 한다");
        assertEquals("file", settings.keySource());
        assertEquals("prod01", settings.keyId());
        assertFalse(settings.warningEnabled());
        assertTrue(settings.keySourceExplicit());
        for (String name : new String[]{"crypto.key.source", "crypto.key.file", "crypto.key.id",
                "crypto.algorithm", "crypto.warning.enabled"}) {
            assertEquals(ValueOrigin.JVM_PROPERTY, settings.valueOrigin(name), name);
        }
        assertEquals(Arrays.asList("crypto.key.source", "crypto.key.id", "crypto.key.file", "crypto.algorithm",
                "crypto.warning.enabled"), Arrays.asList(settings.jvmOverriddenKeys().toArray()), "허용 목록(설정 카탈로그) 순서로 기록");
        byte[] resolved = KeyResolver.resolve(settings);
        assertEquals(32, resolved.length);
        Arrays.fill(resolved, (byte) 0);
        CryptoService service = CryptoService.of(settings);
        // -D로만 설정한 crypto.key.* AES 키로 암호화한다(유형 미지정 기본은 pass이므로 key를 지정).
        String token = service.encryptText("dummy-b-값".toCharArray(), io.javacryptokit.KeyType.KEY, null);
        assertTrue(token.startsWith("ENC[v1:prod01:"));
        assertEquals("dummy-b-값", service.decryptText(token));
    }

    @Test
    void scenarioC_externalPropertiesAloneAreApplied() throws Exception {
        Path key = keyFile("c.key");
        Path config = TestSupport.writeConfig(dir, "c.properties", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(key), "crypto.key.id=prod01",
                "crypto.warning.enabled=false");
        CryptoSettings settings = load(config, jvm());
        assertTrue(settings.externalConfigUsed());
        assertEquals("file", settings.keySource());
        assertEquals("prod01", settings.keyId());
        assertFalse(settings.warningEnabled());
        assertEquals(ValueOrigin.EXTERNAL_FILE, settings.valueOrigin(CryptoSettings.WARNING_ENABLED));
        assertTrue(settings.jvmOverriddenKeys().isEmpty());
    }

    @Test
    void scenarioD_mixedKeyFromExternalFileAndWarningFromJvm() throws Exception {
        Path key = keyFile("d.key");
        Path config = TestSupport.writeConfig(dir, "d.properties", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(key), "crypto.key.id=prod01",
                "crypto.warning.enabled=true", "crypto.jvm.override.enabled=true");
        CryptoSettings settings = load(config, jvm("crypto.warning.enabled=false"));
        assertEquals("file", settings.keySource(), "키는 외부 Properties를 따른다");
        assertEquals(ValueOrigin.EXTERNAL_FILE, settings.valueOrigin(CryptoSettings.KEY_SOURCE));
        assertEquals("prod01", settings.keyId());
        assertFalse(settings.warningEnabled(), "경고만 JVM 속성을 따른다");
        assertEquals(ValueOrigin.JVM_PROPERTY, settings.valueOrigin(CryptoSettings.WARNING_ENABLED));
    }

    @Test
    void scenarioE_envKeyConfiguredByJvmProperties() throws Exception {
        assumeTrue(System.getenv(TestSupport.ENV_TEST_KEY) != null, "Gradle test 태스크의 테스트용 환경변수가 필요하다");
        CryptoSettings settings = load(null, jvm("crypto.key.source=env",
                "crypto.key.env=" + TestSupport.ENV_TEST_KEY, "crypto.key.id=prod01"));
        assertEquals("env", settings.keySource());
        assertEquals(TestSupport.ENV_TEST_KEY, settings.get(CryptoSettings.KEY_ENV));
        CryptoService service = CryptoService.of(settings);
        assertEquals("dummy-e", service.decryptText(service.encryptText("dummy-e".toCharArray())));
    }

    @Test
    void scenarioF_overrideDisabledInExternalFileIgnoresJvmValues() throws Exception {
        Path config = TestSupport.writeConfig(dir, "f.properties", "crypto.jvm.override.enabled=false",
                "crypto.warning.enabled=true");
        CryptoSettings settings = load(config, jvm("crypto.warning.enabled=false", "crypto.key.id=ignored01"));
        assertTrue(settings.warningEnabled(), "정책 false이면 -Dcrypto.warning.enabled=false는 무시되어 true");
        assertEquals("default", settings.keyId());
        assertFalse(settings.jvmOverrideEnabled());
        assertTrue(settings.jvmOverriddenKeys().isEmpty());
        assertEquals(Arrays.asList("crypto.key.id", "crypto.warning.enabled"),
                Arrays.asList(settings.ignoredJvmKeys().toArray()), "무시한 항목 이름은 진단용으로 남긴다");
    }

    @Test
    void policyCannotBeReEnabledByJvmProperty() throws Exception {
        Path config = TestSupport.writeConfig(dir, "f2.properties", "crypto.jvm.override.enabled=false",
                "crypto.warning.enabled=true");
        CryptoSettings settings = load(config, jvm("crypto.jvm.override.enabled=true", "crypto.warning.enabled=false"));
        assertFalse(settings.jvmOverrideEnabled(), "-D 하나로 운영 정책을 다시 켤 수 없다");
        assertTrue(settings.warningEnabled());
        assertTrue(settings.ignoredJvmKeys().contains(CryptoSettings.JVM_OVERRIDE_ENABLED));
    }

    @Test
    void policyIsNotChangedByJvmPropertyInEitherDirection() throws Exception {
        CryptoSettings settings = load(null, jvm("crypto.jvm.override.enabled=false", "crypto.warning.enabled=false"));
        assertTrue(settings.jvmOverrideEnabled(), "정책은 Properties에서만 정한다");
        assertFalse(settings.warningEnabled(), "기본 정책 true이므로 경고 설정은 적용된다");
        assertEquals(ValueOrigin.JAR_DEFAULT, settings.valueOrigin(CryptoSettings.JVM_OVERRIDE_ENABLED));
        assertTrue(settings.ignoredJvmKeys().contains(CryptoSettings.JVM_OVERRIDE_ENABLED));
    }

    @Test
    void jvmTrueTurnsWarningBackOnOverExternalFalse() throws Exception {
        Path config = TestSupport.writeConfig(dir, "on.properties", "crypto.warning.enabled=false");
        CryptoSettings settings = load(config, jvm("crypto.warning.enabled=true"));
        assertTrue(settings.warningEnabled());
        assertEquals(ValueOrigin.JVM_PROPERTY, settings.valueOrigin(CryptoSettings.WARNING_ENABLED));
    }

    @Test
    void singleWarningPropertyKeepsEmbeddedKey() throws Exception {
        CryptoSettings settings = load(null, jvm("crypto.warning.enabled=false"));
        assertEquals("embedded", settings.keySource(), "경고만 바꾼 경우 기존 embedded 키를 그대로 쓴다");
        assertFalse(settings.keySourceExplicit());
        assertFalse(settings.warningEnabled());
        CryptoService service = CryptoService.of(settings);
        assertEquals("dummy", service.decryptText(service.encryptText("dummy".toCharArray())));
    }

    @ParameterizedTest(name = "잘못된 JVM 값 거부: {0}")
    @ValueSource(strings = {
            "crypto.algorithm=AES/CBC/PKCS5Padding",
            "crypto.algorithm=",
            "crypto.key.source=http-zz",
            "crypto.key.source=",
            "crypto.key.id=bad id!zz",
            "crypto.key.id=",
            "crypto.warning.enabled=TRUE",
            "crypto.warning.enabled=yes-zz",
            "crypto.warning.enabled=",
            "crypto.output.encoding=hex-zz",
            "crypto.require.encrypted.password=false",
            "crypto.pool.factory=com.example.EvilFactoryZz"})
    void invalidJvmValuesFailClosedWithoutEchoingTheValue(String pair) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(null, jvm(pair)));
        String value = pair.substring(pair.indexOf('=') + 1);
        if (value.length() > 4) assertFalse(ex.getMessage().contains(value), "설정값을 메시지에 그대로 넣지 않는다");
    }

    @Test
    void invalidPolicyValueInExternalFileIsRejected() throws Exception {
        Path config = TestSupport.writeConfig(dir, "bad-policy.properties", "crypto.jvm.override.enabled=maybe-zz");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(config, jvm()));
        assertTrue(ex.getMessage().contains(CryptoSettings.JVM_OVERRIDE_ENABLED));
        assertFalse(ex.getMessage().contains("maybe-zz"));
    }

    @Test
    void rawEmbeddedKeyFromJvmIsRejectedEvenWhenPolicyIsFalse() throws Exception {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String dummyKey = Base64.getEncoder().encodeToString(raw);
        IllegalArgumentException withDefaultPolicy = assertThrows(IllegalArgumentException.class,
                () -> load(null, jvm("crypto.key.embedded=" + dummyKey)));
        assertTrue(withDefaultPolicy.getMessage().contains(CryptoSettings.KEY_EMBEDDED));
        assertFalse(withDefaultPolicy.getMessage().contains(dummyKey), "키 값은 메시지에 넣지 않는다");

        Path policyOff = TestSupport.writeConfig(dir, "off.properties", "crypto.jvm.override.enabled=false");
        IllegalArgumentException withPolicyOff = assertThrows(IllegalArgumentException.class,
                () -> load(policyOff, jvm("crypto.key.embedded=" + dummyKey)));
        assertFalse(withPolicyOff.getMessage().contains(dummyKey));
    }

    @Test
    void jvmKeyFilePathWithoutSourceIsAmbiguousAndRejected() throws Exception {
        Path key = keyFile("amb.key");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> load(null, jvm("crypto.key.file=" + TestSupport.propertiesPath(key))));
        assertTrue(ex.getMessage().contains("crypto.key.source"));
    }

    @Test
    void jvmKeyEnvNameWithoutSourceIsAmbiguousAndRejected() {
        assertThrows(IllegalArgumentException.class, () -> load(null, jvm("crypto.key.env=MY_KEY_ZZ")));
    }

    @Test
    void jvmSourceSatisfiesKeyPathWrittenInExternalFile() throws Exception {
        Path key = keyFile("intent.key");
        Path config = TestSupport.writeConfig(dir, "intent.properties", "crypto.key.id=prod01",
                "crypto.key.file=" + TestSupport.propertiesPath(key));
        // 외부 파일만으로는 모호하지만(키 경로는 있고 공급 방식이 없음) JVM 속성이 공급 방식을 채우면 정상이다.
        assertThrows(IllegalArgumentException.class, () -> load(config, jvm()));
        CryptoSettings settings = load(config, jvm("crypto.key.source=file"));
        assertEquals("file", settings.keySource());
        assertEquals(ValueOrigin.JVM_PROPERTY, settings.valueOrigin(CryptoSettings.KEY_SOURCE));
        assertEquals(ValueOrigin.EXTERNAL_FILE, settings.valueOrigin(CryptoSettings.KEY_FILE));
    }

    @Test
    void jvmValueWinsOverExternalValueForTheSameKey() throws Exception {
        Path key = keyFile("win.key");
        Path config = TestSupport.writeConfig(dir, "win.properties", "crypto.key.source=env",
                "crypto.key.env=SOME_KEY_ZZ", "crypto.key.id=env01");
        CryptoSettings settings = load(config, jvm("crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(key), "crypto.key.id=file01"));
        assertEquals("file", settings.keySource());
        assertEquals("file01", settings.keyId());
        assertEquals(ValueOrigin.EXTERNAL_FILE, settings.valueOrigin(CryptoSettings.KEY_ENV), "덮어쓰지 않은 항목은 외부 값 유지");
    }

    @Test
    void jvmKeyIdAloneKeepsEmbeddedForCompatibilityButIsVisibleAsInherited() throws Exception {
        CryptoSettings settings = load(null, jvm("crypto.key.id=dev01"));
        assertEquals("embedded", settings.keySource());
        assertFalse(settings.keySourceExplicit(), "info에서 '기본값 상속'으로 보여야 한다");
        assertEquals("dev01", settings.keyId());
    }

    @Test
    void bootstrapConfigPathWorksEvenWhenOverrideIsDisabled() throws Exception {
        Path config = TestSupport.writeConfig(dir, "boot.properties", "crypto.jvm.override.enabled=false",
                "crypto.key.source=embedded", "crypto.key.id=boot01");
        Map<String, String> props = jvm(CryptoSettings.CONFIG_FILE_PROPERTY + "=" + config, "crypto.key.id=ignored01");
        CryptoSettings settings = CryptoSettings.load(null, props::get, name -> null);
        assertTrue(settings.externalConfigUsed(), "-Dcrypto.config.file는 정책과 관계없이 동작한다");
        assertEquals("boot01", settings.keyId(), "개별 -D 값은 정책 false로 무시된다");
    }

    @Test
    void unrelatedJvmPropertiesHaveNoEffect() throws Exception {
        CryptoSettings settings = load(null, jvm("crypto.unknown.option=1", "user.name=someone"));
        assertTrue(settings.jvmOverriddenKeys().isEmpty());
        assertTrue(settings.ignoredJvmKeys().isEmpty());
    }

    @Test
    void explicitFileKeyFromJvmNeverFallsBackToEmbedded() throws Exception {
        CryptoSettings settings = load(null, jvm("crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(dir.resolve("missing.key"))));
        assertThrows(NoSuchFileException.class, () -> KeyResolver.resolve(settings));
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> CryptoService.of(settings).encryptText("dummy".toCharArray(), io.javacryptokit.KeyType.KEY, null));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason());
    }

    @Test
    void explicitEnvKeyFromJvmNeverFallsBackToEmbedded() throws Exception {
        String unset = "JAVA_CRYPTO_KIT_UNSET_" + Integer.toHexString(new SecureRandom().nextInt() & 0x7fffffff);
        CryptoSettings settings = load(null, jvm("crypto.key.source=env", "crypto.key.env=" + unset));
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> CryptoService.of(settings).encryptText("dummy".toCharArray(), io.javacryptokit.KeyType.KEY, null));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason());
    }

    @Test
    void everyJarPropertyIsClassifiedForJvmOverride() throws Exception {
        // 새 설정 항목을 추가할 때 -D 허용 여부를 의식적으로 정하도록, JAR 기본 설정의 모든 항목이 분류되어 있는지 확인한다.
        Properties defaults = new Properties();
        try (InputStream in = CryptoSettings.class.getResourceAsStream(CryptoSettings.DEFAULT_CONFIG_RESOURCE);
             Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            defaults.load(reader);
        }
        assertFalse(CryptoSettings.JVM_OVERRIDABLE_KEYS.contains(CryptoSettings.KEY_EMBEDDED), "키 원문은 -D 금지");
        assertFalse(CryptoSettings.JVM_OVERRIDABLE_KEYS.contains(CryptoSettings.JVM_OVERRIDE_ENABLED), "정책 항목은 -D 금지");
        int fixed = 0;
        for (String name : defaults.stringPropertyNames()) {
            if (SettingCatalog.isProfileSetting(name)) {
                // 키 프로필 항목은 항목 정의로 분류한다: 위치 항목만 같은 이름의 -D 허용, 정체 항목(유형·공급원·내장 값·KDF 등)은 -D 거부.
                SettingCatalog.ProfileItem item = SettingCatalog.profileItem(SettingCatalog.parseProfileName(name)[1]);
                assertTrue(item != null, "정의되지 않은 키 프로필 항목: " + name);
                assertFalse(CryptoSettings.JVM_OVERRIDABLE_KEYS.contains(name), "키 프로필 항목은 고정 목록에 넣지 않는다: " + name);
                continue;
            }
            fixed++;
            boolean classified = CryptoSettings.JVM_OVERRIDABLE_KEYS.contains(name)
                    || CryptoSettings.KEY_EMBEDDED.equals(name) || CryptoSettings.JVM_OVERRIDE_ENABLED.equals(name);
            assertTrue(classified, "분류되지 않은 설정 항목: " + name);
        }
        assertEquals(fixed, CryptoSettings.JVM_OVERRIDABLE_KEYS.size() + 2);
    }

    // ===== QA-03: 이 라이브러리 설정의 오타로 보이는 -Dcrypto.* 이름은 실패, 무관한 이름은 영향 없음 =====

    /** 이름 목록까지 주입해 JVM 속성 오타 검사를 포함한 설정을 읽는다. */
    private static CryptoSettings loadWithNames(Path config, Map<String, String> props) throws IOException {
        return CryptoSettings.load(config == null ? null : config.toString(), props::get, name -> null, props.keySet());
    }

    @ParameterizedTest(name = "라이브러리 설정 오타 -D{0}는 실패")
    @ValueSource(strings = {"crypto.key.soruce=file", "crypto.key.sourc=file", "crypto.keys.source=file",
            "crypto.warning.enable=false", "crypto.jvm.override.enable=true", "crypto.pool.factor=x",
            "crypto.key.unknownthing=1"})
    void misspelledLibraryJvmPropertyFailsClosedWithoutEchoingTheValue(String pair) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> loadWithNames(null, jvm(pair)));
        String name = pair.substring(0, pair.indexOf('='));
        assertTrue(ex.getMessage().contains("'" + name + "'"), ex.getMessage());
        assertFalse(ex.getMessage().contains(pair), "값은 출력하지 않는다: " + ex.getMessage());
    }

    @Test
    void keySourceTypoCannotSilentlyFallBackToTheEmbeddedKey() {
        // -Dcrypto.key.soruce=file 만 지정한 경우: 무시하면 공개 내장 키로 동작하므로 반드시 중단해야 한다.
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> loadWithNames(null, jvm("crypto.key.soruce=file")));
        assertTrue(ex.getMessage().contains("'crypto.key.source'"), "정식 이름을 안내해야 한다: " + ex.getMessage());
    }

    @Test
    void typoCheckWorksEvenWhenWarningsAndOverridesAreDisabled() throws Exception {
        Path policyOff = TestSupport.writeConfig(dir, "off2.properties", "crypto.jvm.override.enabled=false",
                "crypto.warning.enabled=false");
        assertThrows(IllegalArgumentException.class,
                () -> loadWithNames(policyOff, jvm("crypto.warning.enabled=false", "crypto.key.idd=x")));
    }

    @Test
    void unrelatedJvmPropertiesHaveNoEffectEvenWithCryptoPrefix() throws Exception {
        CryptoSettings settings = loadWithNames(null, jvm("crypto.policy=unlimited", "crypto.custom.flag=1",
                "user.home=/x", "java.crypto.kit.custom=1"));
        assertEquals("embedded", settings.keySource());
        assertTrue(settings.jvmOverriddenKeys().isEmpty());
    }

    @Test
    void suggestionIsGivenOnlyWhenConfident() throws Exception {
        CryptoSettings settings = load(null, jvm());
        assertEquals("crypto.key.source", settings.suggestKnownKey("crypto.key.sourc"));
        assertEquals(null, settings.suggestKnownKey("crypto.something.else"), "확신할 수 없으면 추측하지 않는다");
    }

    @Test
    void unsafeLibraryJvmNameIsRejectedWithoutEchoingIt() {
        java.util.Set<String> names = new java.util.HashSet<>(Arrays.asList("crypto.key.so urce/s3cr3t", "crypto.policy"));
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> CryptoSettings.load(null, name -> null, name -> null, names));
        assertFalse(ex.getMessage().contains("s3cr3t"), ex.getMessage());
        assertTrue(ex.getMessage().contains("이름 표시 생략"), ex.getMessage());
    }
}
