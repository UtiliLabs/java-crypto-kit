package io.javacryptokit.jdbc.tomcat;

import io.javacryptokit.CredentialCrypto;

import io.javacryptokit.TestSupport;

import io.javacryptokit.config.CryptoSettings;

import io.javacryptokit.key.DefaultKeyWarning;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.UUID;
import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.sql.DataSource;
import org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tomcat JNDI 연동 시나리오 A~F와 보안 회귀(S2)를 모의 Pool Factory로 검증한다(실제 Tomcat·DB 아님).
 *
 * <ul>
 *   <li>A: 기본 DBCP2 + embedded(외부 설정 없음)</li>
 *   <li>B: 기본 DBCP2 + 외부 file 키</li>
 *   <li>C: 기본 DBCP2 + env 키</li>
 *   <li>D: 선택형 Tomcat JDBC Pool + embedded/file/env</li>
 *   <li>E: crypto.warning.enabled=false에서 라이브러리 WARN 없음, true에서 여러 DataSource에도 한 번</li>
 *   <li>F: 암호문 오류·키 누락·키ID 불일치 시 실패, 민감정보 누출 없음</li>
 * </ul>
 */
class DataSourceFactoryScenarioTest {
    @TempDir
    Path dir;

    private AutoCloseable commonProperty;
    private AutoCloseable legacyProperty;
    private AutoCloseable jvmProperties;

    @BeforeEach
    void isolate() {
        assumeTrue(TestSupport.noConfigEnvironmentVariables(), "설정 경로 환경변수가 있으면 Factory 시험 결과가 달라진다");
        commonProperty = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, null);
        legacyProperty = TestSupport.clearOtherConfigProperties();
        // 개발자 PC·IDE 실행 옵션에 남은 -Dcrypto.* 값이 시험 결과에 섞이지 않게 비운다.
        jvmProperties = TestSupport.jvmSettings();
        BasicDataSourceFactory.reset();
        org.apache.tomcat.jdbc.pool.DataSourceFactory.reset();
        DefaultKeyWarning.resetForTests();
    }

    @AfterEach
    void restore() throws Exception {
        if (jvmProperties != null) jvmProperties.close();
        if (commonProperty != null) commonProperty.close();
        if (legacyProperty != null) legacyProperty.close();
    }

    @Test
    void scenarioA_defaultDbcp2WithEmbeddedKeyAndNoExternalConfig() throws Exception {
        String token = TestSupport.jarDefaults().encryptText("dummy-db-pw");
        Reference resource = resource("app_user", token);
        Object dataSource = new EncryptedDataSourceFactory().getObjectInstance(resource, null, null, null);
        assertTrue(dataSource instanceof DataSource);
        assertEquals("dummy-db-pw", BasicDataSourceFactory.lastPassword);
        assertEquals("app_user", BasicDataSourceFactory.lastUsername, "평문 사용자명은 그대로 전달");
        assertEquals("jdbc:fake:memory", BasicDataSourceFactory.lastUrl);
        assertFalse(BasicDataSourceFactory.lastHadFactoryAttribute, "factory 속성은 하위 Pool에 넘기지 않는다");
        assertEquals(token, ((StringRefAddr) resource.get("password")).getContent(), "원본 Reference는 바뀌지 않는다");
    }

    @Test
    void scenarioB_defaultDbcp2WithExternalFileKey() throws Exception {
        Path config = fileKeyConfig("b.properties", "crypto.warning.enabled=true");
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString())) {
            String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-file-pw");
            new EncryptedDataSourceFactory().getObjectInstance(resource("app_user", token), null, null, null);
            assertEquals("dummy-file-pw", BasicDataSourceFactory.lastPassword);
        }
    }

    @Test
    void scenarioB_externalFileKeyWithWarningSettingOmitted() throws Exception {
        // 경고 설정을 생략한 외부 설정(기본값 true)도 -Dcrypto.config.file로 Factory에 그대로 적용된다.
        Path config = fileKeyConfig("b-default-warning.properties");
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString())) {
            String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-file-default-pw");
            new EncryptedDataSourceFactory().getObjectInstance(resource("app_user", token), null, null, null);
            assertEquals("dummy-file-default-pw", BasicDataSourceFactory.lastPassword);
        }
    }

    @Test
    void scenarioC_defaultDbcp2WithEnvKey() throws Exception {
        assumeTrue(System.getenv(TestSupport.ENV_TEST_KEY) != null, "Gradle test 태스크의 테스트용 환경변수가 필요하다");
        Path config = TestSupport.writeConfig(dir, "c.properties", "crypto.key.source=env", "crypto.key.id=env01",
                "crypto.key.env=" + TestSupport.ENV_TEST_KEY);
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString())) {
            String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-env-pw");
            new EncryptedDataSourceFactory().getObjectInstance(resource("app_user", token), null, null, null);
            assertEquals("dummy-env-pw", BasicDataSourceFactory.lastPassword);
        }
    }

    @ParameterizedTest(name = "D: 선택형 Tomcat JDBC Pool + {0}")
    @ValueSource(strings = {"embedded", "file", "env"})
    void scenarioD_optionalTomcatJdbcPoolWithEveryKeyMode(String source) throws Exception {
        String pool = "crypto.pool.factory=" + CryptoSettings.TOMCAT_JDBC_FACTORY;
        Path config;
        if ("embedded".equals(source)) {
            config = TestSupport.writeConfig(dir, "d-embedded.properties", "crypto.key.source=embedded", pool);
        } else if ("file".equals(source)) {
            config = fileKeyConfig("d-file.properties", pool);
        } else {
            assumeTrue(System.getenv(TestSupport.ENV_TEST_KEY) != null);
            config = TestSupport.writeConfig(dir, "d-env.properties", "crypto.key.source=env", "crypto.key.id=env01",
                    "crypto.key.env=" + TestSupport.ENV_TEST_KEY, pool);
        }
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString())) {
            String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-pool-pw");
            Reference resource = resource("app_user", token);
            resource.add(new StringRefAddr("maxActive", "20"));
            new EncryptedDataSourceFactory().getObjectInstance(resource, null, null, null);
            assertEquals(1, org.apache.tomcat.jdbc.pool.DataSourceFactory.invocations);
            assertEquals(0, BasicDataSourceFactory.invocations, "DBCP2로 가면 안 된다");
            assertEquals("dummy-pool-pw", org.apache.tomcat.jdbc.pool.DataSourceFactory.lastPassword);
            assertEquals("20", org.apache.tomcat.jdbc.pool.DataSourceFactory.lastMaxActive, "Pool 고유 속성 보존");
        }
    }

    @Test
    void scenarioE_warningDisabledProducesNoLibraryWarningsAcrossDataSources() throws Exception {
        Path config = TestSupport.writeConfig(dir, "e-off.properties", "crypto.key.source=embedded",
                "crypto.warning.enabled=false");
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString());
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy");
            for (int i = 0; i < 3; i++) {
                new EncryptedDataSourceFactory().getObjectInstance(resource("u", token), null, null, null);
            }
            assertTrue(log.warnings().isEmpty(), log.warnings().toString());
        }
    }

    @Test
    void scenarioE_warningEnabledWarnsOnceAcrossDataSources() throws Exception {
        Path config = TestSupport.writeConfig(dir, "e-on.properties", "crypto.key.source=embedded",
                "crypto.warning.enabled=true");
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString());
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy");
            for (int i = 0; i < 3; i++) {
                new EncryptedDataSourceFactory().getObjectInstance(resource("u", token), null, null, null);
            }
            assertEquals(1, log.warnings().size());
        }
    }

    @Test
    void scenarioF_wrongTokenMissingKeyAndKeyIdMismatchFailWithoutLeaks() throws Exception {
        // 공개 AES 키(default)로 만든 암호문: 아래 file 키 설정에는 이 Key ID가 없다(crypto.key.*가 다른 키로 바뀜).
        String goodToken = TestSupport.jarDefaults().encryptText("dummy-f-pw", io.javacryptokit.KeyType.KEY);
        String tampered = goodToken.substring(0, goodToken.length() - 3)
                + (goodToken.charAt(goodToken.length() - 3) == 'A' ? 'B' : 'A') + goodToken.substring(goodToken.length() - 2);
        assertFactoryFailsWithoutLeak(resource("u", tampered), tampered, "dummy-f-pw");
        assertFactoryFailsWithoutLeak(resource("u", "dummy-plain-pw"), "dummy-plain-pw", null);

        // 키ID 불일치: 외부 file 키 설정에서 기본 키 암호문을 쓰면 실패해야 한다(내장 키로 대체하지 않음).
        Path config = fileKeyConfig("f.properties");
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString())) {
            NamingException ex = assertFactoryFailsWithoutLeak(resource("u", goodToken), goodToken, "dummy-f-pw");
            assertTrue(ex.getMessage().contains("키 식별자"));
        }
        // 키 파일 누락
        Path missing = TestSupport.writeConfig(dir, "f-missing.properties", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(dir.resolve("gone.key")));
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, missing.toString())) {
            assertFactoryFailsWithoutLeak(resource("u", goodToken), goodToken, "dummy-f-pw");
        }
        // 외부 설정 파일 누락
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY,
                dir.resolve("no-config.properties").toString())) {
            NamingException ex = assertFactoryFailsWithoutLeak(resource("u", goodToken), goodToken, "dummy-f-pw");
            assertTrue(ex.getMessage().contains("설정"));
        }
        assertEquals(0, BasicDataSourceFactory.invocations, "실패 시 하위 Pool을 호출하지 않는다");
    }

    @Test
    void s2_delegateNamingExceptionDoesNotLeakSecrets() throws Exception {
        String secret = "dummy-secret-" + UUID.randomUUID();
        NamingException fromPool = new NamingException("pool failed with password=" + secret);
        fromPool.setRootCause(new IllegalStateException("root " + secret));
        fromPool.addSuppressed(new RuntimeException("suppressed " + secret));
        BasicDataSourceFactory.nextFailure = fromPool;
        String token = TestSupport.jarDefaults().encryptText(secret);
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            NamingException thrown = assertThrows(NamingException.class,
                    () -> new EncryptedDataSourceFactory().getObjectInstance(resource("u", token), null, null, null));
            assertNoLeak(thrown, secret);
            assertFalse(log.allText().contains(secret));
            assertTrue(thrown.getMessage().contains("원인 유형: NamingException > IllegalStateException"),
                    "비밀값 없이 원인 유형으로 진단할 수 있어야 한다: " + thrown.getMessage());
        }
    }

    @Test
    void s2_delegateSqlExceptionKeepsOnlySqlState() throws Exception {
        String secret = "dummy-secret-" + UUID.randomUUID();
        BasicDataSourceFactory.nextFailure = new SQLException("Access denied, password " + secret, "28000", 1045);
        String token = TestSupport.jarDefaults().encryptText(secret);
        NamingException thrown = assertThrows(NamingException.class,
                () -> new EncryptedDataSourceFactory().getObjectInstance(resource("u", token), null, null, null));
        assertNoLeak(thrown, secret);
        assertTrue(thrown.getMessage().contains("SQLException(SQLState=28000)"), thrown.getMessage());
    }

    @Test
    void b64PasswordAndEncryptedUsernameAreDecryptedForThePool() throws Exception {
        Path b64Config = TestSupport.writeConfig(dir, "b64.properties", "crypto.output.encoding=base64");
        CredentialCrypto b64 = CredentialCrypto.fromConfigFile(b64Config);
        String password = b64.encryptText("dummy-b64-pw");
        String username = b64.encryptText("dummy-user");
        assertTrue(password.startsWith("B64["));
        new EncryptedDataSourceFactory().getObjectInstance(resource(username, password), null, null, null);
        assertEquals("dummy-b64-pw", BasicDataSourceFactory.lastPassword);
        assertEquals("dummy-user", BasicDataSourceFactory.lastUsername);
    }

    @Test
    void missingPasswordAndNonDataSourceTypesAreRejected() {
        Reference noPassword = new Reference("javax.sql.DataSource");
        noPassword.add(new StringRefAddr("username", "u"));
        assertThrows(NamingException.class, () -> new EncryptedDataSourceFactory().getObjectInstance(noPassword, null, null, null));
        Reference xa = new Reference("javax.sql.XADataSource");
        assertThrows(NamingException.class, () -> new EncryptedDataSourceFactory().getObjectInstance(xa, null, null, null));
        assertThrows(NamingException.class, () -> new EncryptedDataSourceFactory().getObjectInstance("x", null, null, null));
    }

    /** 실패 예외에 원인·suppressed·입력값·평문이 없는지 확인하고 예외를 돌려준다. */
    private NamingException assertFactoryFailsWithoutLeak(Reference resource, String input, String plain) {
        try (TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            NamingException thrown = assertThrows(NamingException.class,
                    () -> new EncryptedDataSourceFactory().getObjectInstance(resource, null, null, null));
            assertTrue(thrown.getMessage().startsWith("[java-crypto-kit]"));
            assertNoLeak(thrown, input);
            if (plain != null) assertNoLeak(thrown, plain);
            assertFalse(log.allText().contains(input));
            return thrown;
        }
    }

    /** 예외 메시지·원인·suppressed·스택 트레이스 전체에 비밀 문자열이 없는지 확인한다. */
    private static void assertNoLeak(NamingException thrown, String secret) {
        assertFalse(thrown.getMessage().contains(secret), "메시지에 비밀값이 있으면 안 된다");
        assertNull(thrown.getCause());
        assertNull(thrown.getRootCause());
        assertEquals(0, thrown.getSuppressed().length);
        StringWriter trace = new StringWriter();
        thrown.printStackTrace(new PrintWriter(trace));
        assertFalse(trace.toString().contains(secret), "스택 트레이스에 비밀값이 있으면 안 된다");
    }

    private Path fileKeyConfig(String name, String... extra) throws Exception {
        Path key = TestSupport.writeRandomKeyFile(dir, name + ".key");
        String[] lines = new String[3 + extra.length];
        lines[0] = "crypto.key.source=file";
        lines[1] = "crypto.key.id=file01";
        lines[2] = "crypto.key.file=" + TestSupport.propertiesPath(key);
        System.arraycopy(extra, 0, lines, 3, extra.length);
        return TestSupport.writeConfig(dir, name, lines);
    }

    private static Reference resource(String username, String password) {
        Reference reference = new Reference("javax.sql.DataSource");
        reference.add(new StringRefAddr("factory", EncryptedDataSourceFactory.class.getName()));
        if (username != null) reference.add(new StringRefAddr("username", username));
        if (password != null) reference.add(new StringRefAddr("password", password));
        reference.add(new StringRefAddr("url", "jdbc:fake:memory"));
        return reference;
    }
}
