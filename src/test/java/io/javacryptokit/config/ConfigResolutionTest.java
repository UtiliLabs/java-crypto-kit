package io.javacryptokit.config;

import io.javacryptokit.CredentialCrypto;

import io.javacryptokit.CredentialCryptoException;

import io.javacryptokit.TestSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * 외부 설정 경로의 우선순위·공통/기존 이름 별칭·충돌, Fail Closed, 모호한 키 설정(S3), 출력 형식 설정을 검증한다.
 * 실제 JVM 속성·환경변수를 바꾸지 않도록 조회 함수를 주입한다.
 */
class ConfigResolutionTest {
    @TempDir
    Path dir;

    private final Map<String, String> jvm = new HashMap<>();
    private final Map<String, String> env = new HashMap<>();
    private Path configA;
    private Path configB;

    @BeforeEach
    void createConfigs() throws IOException {
        configA = TestSupport.writeConfig(dir, "a.properties", "crypto.key.source=embedded", "crypto.key.id=keyA");
        configB = TestSupport.writeConfig(dir, "b.properties", "crypto.key.source=embedded", "crypto.key.id=keyB");
    }

    private CryptoSettings load(String cliPath) throws IOException {
        return CryptoSettings.load(cliPath, jvm::get, env::get);
    }

    @Test
    void noExternalConfigUsesJarDefaults() throws IOException {
        CryptoSettings settings = load(null);
        assertEquals(CryptoSettings.ConfigOrigin.NONE, settings.configOrigin());
        assertEquals("embedded", settings.keySource());
        assertEquals("default", settings.keyId());
        assertFalse(settings.keySourceExplicit());
        assertTrue(settings.warningEnabled());
        assertEquals(CryptoSettings.OutputFormat.ENC, settings.outputFormat());
    }

    @Test
    void cliOptionWinsOverJvmPropertyAndEnvironment() throws IOException {
        jvm.put(CryptoSettings.CONFIG_FILE_PROPERTY, configA.toString());
        env.put(CryptoSettings.CONFIG_FILE_ENV, configA.toString());
        CryptoSettings settings = load(configB.toString());
        assertEquals(CryptoSettings.ConfigOrigin.EXPLICIT_PATH, settings.configOrigin());
        assertEquals("keyB", settings.keyId());
    }

    @Test
    void commonJvmPropertyIsUsed() throws IOException {
        jvm.put(CryptoSettings.CONFIG_FILE_PROPERTY, configA.toString());
        CryptoSettings settings = load(null);
        assertEquals(CryptoSettings.ConfigOrigin.JVM_PROPERTY, settings.configOrigin());
        assertEquals("keyA", settings.keyId());
        assertEquals("a.properties", settings.configFileName());
    }





    @Test
    void jvmPropertyHasPriorityOverEnvironment() throws IOException {
        jvm.put(CryptoSettings.CONFIG_FILE_PROPERTY, configA.toString());
        env.put(CryptoSettings.CONFIG_FILE_ENV, configB.toString());
        CryptoSettings settings = load(null);
        assertEquals("keyA", settings.keyId());
        assertEquals(CryptoSettings.ConfigOrigin.JVM_PROPERTY, settings.configOrigin());
    }

    @Test
    void environmentIsUsedWhenNoJvmProperty() throws IOException {
        env.put(CryptoSettings.CONFIG_FILE_ENV, configB.toString());
        CryptoSettings settings = load(null);
        assertEquals(CryptoSettings.ConfigOrigin.ENVIRONMENT, settings.configOrigin());
        assertEquals("keyB", settings.keyId());
    }

    @Test
    void removedAliasNamesAreNotConfigPaths() throws IOException {
        // 최초 공개 전에 정리한 이전 이름은 설정 경로로 쓰이지 않는다(조용히 쓰이지도, 섞이지도 않음).
        jvm.put("java.crypto.kit.config", configA.toString());
        env.put("JAVA_CRYPTO_KIT_CONFIG", configA.toString());
        assertEquals(CryptoSettings.ConfigOrigin.NONE, load(null).configOrigin());
    }

    @Test
    void configFileEntryInsideExternalFileIsRejectedWithGuidance() throws IOException {
        Path config = TestSupport.writeConfig(dir, "self.properties", "crypto.config.file=/tmp/other.properties");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(config.toString()));
        assertTrue(ex.getMessage().contains(CryptoSettings.CONFIG_FILE_ENV), ex.getMessage());
    }

    @Test
    void pathsWithSpacesAndUnicodeWorkOnEveryOs() throws IOException {
        java.nio.file.Path spaced = java.nio.file.Files.createDirectories(dir.resolve("설정 폴더 with space"));
        java.nio.file.Path key = TestSupport.writeRandomKeyFile(spaced, "키 파일.key");
        java.nio.file.Path config = TestSupport.writeConfig(spaced, "java crypto kit.properties", "crypto.key.source=file",
                "crypto.key.id=space01", "crypto.key.file=" + TestSupport.propertiesPath(key));
        CryptoSettings settings = load(config.toString());
        assertEquals("file", settings.keySource());
        assertTrue(io.javacryptokit.core.CryptoService.of(settings).checkKey().available(), "공백·한글 경로의 키 파일을 읽어야 한다");
    }







    @Test
    void missingExternalFileFailsClosed() {
        jvm.put(CryptoSettings.CONFIG_FILE_PROPERTY, dir.resolve("none.properties").toString());
        assertThrows(NoSuchFileException.class, () -> load(null));
    }

    @Test
    void nonUtf8ExternalFileFailsClosed() throws IOException {
        Path ansi = dir.resolve("ansi.properties");
        // "# 한글"을 UTF-8이 아닌 바이트로 기록한다(ANSI 저장 사고 재현).
        Files.write(ansi, new byte[]{'#', ' ', (byte) 0xC7, (byte) 0xD1, '\n', 'a', '=', 'b', '\n'});
        assertThrows(IOException.class, () -> load(ansi.toString()));
    }

    @Test
    void keyFilePathWithoutSourceIsRejected() throws IOException {
        Path config = TestSupport.writeConfig(dir, "s3-file.properties", "crypto.key.id=prod01",
                "crypto.key.file=C:/secure/java-crypto-kit.key");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(config.toString()));
        assertTrue(ex.getMessage().contains("crypto.key.source"));
    }

    @Test
    void keyEnvNameWithoutSourceIsRejected() throws IOException {
        Path config = TestSupport.writeConfig(dir, "s3-env.properties", "crypto.key.env=MY_KEY");
        assertThrows(IllegalArgumentException.class, () -> load(config.toString()));
    }

    @Test
    void keyIdOnlyKeepsEmbeddedForCompatibilityButIsVisibleAsInherited() throws IOException {
        Path config = TestSupport.writeConfig(dir, "s3-id.properties", "crypto.key.id=prod01");
        CryptoSettings settings = load(config.toString());
        assertEquals("embedded", settings.keySource());
        assertFalse(settings.keySourceExplicit(), "info에서 '기본값 상속'으로 보여야 한다");
        assertEquals("prod01", settings.keyId());
    }

    @Test
    void explicitEmbeddedInExternalConfigIsAccepted() throws IOException {
        Path config = TestSupport.writeConfig(dir, "explicit.properties", "crypto.key.source=embedded",
                "crypto.warning.enabled=false");
        CryptoSettings settings = load(config.toString());
        assertTrue(settings.keySourceExplicit());
        assertFalse(settings.warningEnabled());
    }

    @Test
    void nonKeySettingsOnlyKeepEmbedded() throws IOException {
        Path config = TestSupport.writeConfig(dir, "pool-only.properties",
                "crypto.pool.factory=" + CryptoSettings.TOMCAT_JDBC_FACTORY, "crypto.key.file=");
        CryptoSettings settings = load(config.toString());
        assertEquals("embedded", settings.keySource());
        assertEquals(CryptoSettings.TOMCAT_JDBC_FACTORY, settings.poolFactory());
    }

    @Test
    void outputEncodingAcceptsOnlyEncAndBase64() throws IOException {
        assertEquals(CryptoSettings.OutputFormat.ENC,
                load(TestSupport.writeConfig(dir, "enc.properties", "crypto.output.encoding=enc").toString()).outputFormat());
        assertEquals(CryptoSettings.OutputFormat.BASE64,
                load(TestSupport.writeConfig(dir, "b64.properties", "crypto.output.encoding=base64").toString()).outputFormat());
    }

    @ParameterizedTest(name = "잘못된 출력 형식 \"{0}\"은 거부")
    @ValueSource(strings = {"", "BASE64", "b64", "raw", "none"})
    void invalidOutputEncodingIsRejected(String value) throws IOException {
        Path config = TestSupport.writeConfig(dir, "bad-output.properties", "crypto.output.encoding=" + value);
        assertThrows(IllegalArgumentException.class, () -> load(config.toString()));
    }

    @Test
    void facadeReportsConfigurationReasonWithSafeMessage() throws IOException {
        Path config = TestSupport.writeConfig(dir, "s3-facade.properties",
                "crypto.key.file=" + TestSupport.propertiesPath(dir.resolve("k.key")));
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(config));
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION, ex.getReason());
        assertTrue(ex.getMessage().contains("crypto.key.source"));
        assertFalse(ex.getMessage().contains(dir.toString()));
    }

    // ===== QA-02: 지정했지만 비어 있는 설정 경로는 내장 키로 바꾸지 않고 실패 =====

    @ParameterizedTest(name = "직접 지정 경로 \"{0}\"는 거부")
    @ValueSource(strings = {"", " ", "\t "})
    void blankExplicitConfigPathFailsClosed(String blank) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(blank));
        assertTrue(ex.getMessage().contains("비어 있습니다"), ex.getMessage());
    }

    @ParameterizedTest(name = "JVM 속성 {0}의 빈 값은 거부")
    @ValueSource(strings = {CryptoSettings.CONFIG_FILE_PROPERTY})
    void blankJvmConfigPathFailsClosedEvenWhenEnvironmentHasAPath(String name) {
        jvm.put(name, "  ");
        env.put(CryptoSettings.CONFIG_FILE_ENV, configA.toString());
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(null));
        assertTrue(ex.getMessage().contains(name), "어느 설정이 비었는지 이름으로 알려야 한다: " + ex.getMessage());
    }

    @ParameterizedTest(name = "환경변수 {0}의 빈 값은 거부")
    @ValueSource(strings = {CryptoSettings.CONFIG_FILE_ENV})
    void blankEnvironmentConfigPathFailsClosed(String name) {
        env.put(name, "");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(null));
        assertTrue(ex.getMessage().contains(name), ex.getMessage());
    }

    @Test
    void blankPathIsRejectedAlsoThroughThePublicApi() {
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> CredentialCrypto.fromConfigFile(java.nio.file.Paths.get("")));
        assertEquals(CredentialCryptoException.Reason.CONFIGURATION, ex.getReason());
    }

    // ===== QA-03: 외부 설정 파일의 모르는 항목(오타)은 조용히 무시하지 않고 거부 =====

    @Test
    void misspelledExternalKeyIsRejectedWithSuggestionAndWithoutValue() throws IOException {
        Path config = TestSupport.writeConfig(dir, "typo.properties", "crypto.warnning.enabled=false-zz-value");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(config.toString()));
        assertTrue(ex.getMessage().contains("'crypto.warnning.enabled'"), ex.getMessage());
        assertTrue(ex.getMessage().contains("'crypto.warning.enabled'"), "비슷한 정식 이름을 안내해야 한다: " + ex.getMessage());
        assertFalse(ex.getMessage().contains("false-zz-value"), "값은 출력하지 않는다");
    }

    @Test
    void misspelledPolicyKeyIsRejected() throws IOException {
        // 운영 정책 항목 오타가 무시되면 개별 -D 설정이 계속 적용되므로 반드시 거부해야 한다.
        Path config = TestSupport.writeConfig(dir, "policy-typo.properties", "crypto.jvm.overide.enabled=false");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(config.toString()));
        assertTrue(ex.getMessage().contains("crypto.jvm.override.enabled"), ex.getMessage());
    }

    @Test
    void unknownKeysOutsideTheCryptoPrefixAreRejectedToo() throws IOException {
        Path config = TestSupport.writeConfig(dir, "prefix-typo.properties", "crpyto.key.source=file", "other.option=1");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(config.toString()));
        assertTrue(ex.getMessage().contains("외 1개"), "여러 개면 개수를 알려야 한다: " + ex.getMessage());
    }

    @Test
    void malformedLineDoesNotEchoItsContent() throws IOException {
        // '=' 없이 값까지 붙은 줄은 이름에 값이 섞였을 수 있으므로 이름도 출력하지 않는다.
        Path config = TestSupport.writeConfig(dir, "malformed.properties", "crypto.key.file/etc/secret!dir/k");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> load(config.toString()));
        assertFalse(ex.getMessage().contains("secret"), ex.getMessage());
        assertTrue(ex.getMessage().contains("이름 표시 생략"), ex.getMessage());
    }

    @Test
    void everyKnownKeyIsAcceptedInExternalFile() throws IOException {
        Path config = TestSupport.writeConfig(dir, "all.properties", "crypto.algorithm=AES/GCM/NoPadding",
                "crypto.key.source=embedded", "crypto.key.id=all01", "crypto.key.env=SOME_KEY",
                "crypto.key.file=", "crypto.pool.factory=" + CryptoSettings.DBCP2_FACTORY,
                "crypto.require.encrypted.password=true", "crypto.warning.enabled=true", "crypto.output.encoding=enc",
                "crypto.jvm.override.enabled=true");
        assertEquals("all01", load(config.toString()).keyId());
    }
}
