package io.javacryptokit.jdbc.tomcat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.key.DefaultKeyWarning;
import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.naming.spi.ObjectFactory;
import javax.sql.DataSource;
import org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tomcat이 Resource의 {@code factory} 값(클래스 이름)으로 Factory를 만드는 방식 그대로 검증한다(모의 Pool Factory 사용,
 * 실제 Tomcat 아님). Tomcat은 컨텍스트 클래스로더에서 클래스를 이름으로 찾고 public 기본 생성자로 만든 뒤
 * {@link ObjectFactory}로 호출한다.
 *
 * <p>함께 확인하는 설정 경로: JVM 개별 속성만 쓰는 경우, 외부 Properties와 혼합하는 경우, 외부 Properties의
 * {@code crypto.jvm.override.enabled=false}로 JVM 속성을 막는 경우, 설정 파일 경로 JVM 속성({@code crypto.config.file})과 파일 키.
 * 실제 System 속성을 잠시 바꾸므로 각 시험이 끝나면 원래 값으로 되돌린다.</p>
 */
class FactoryEntryPointTest {
    static final String FACTORY = "io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory";

    @TempDir
    Path dir;

    private AutoCloseable isolation;

    @BeforeEach
    void isolate() {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        AutoCloseable common = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, null);
        AutoCloseable others = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, TestSupport.managedConfig().toString());
        AutoCloseable jvm = TestSupport.jvmSettings();
        isolation = () -> {
            jvm.close();
            others.close();
            common.close();
        };
        BasicDataSourceFactory.reset();
        org.apache.tomcat.jdbc.pool.DataSourceFactory.reset();
        DefaultKeyWarning.resetForTests();
    }

    @AfterEach
    void restore() throws Exception {
        if (isolation != null) isolation.close();
    }

    /** Tomcat과 같은 방식(컨텍스트 클래스로더 + 이름 + public 기본 생성자)으로 Factory를 만든다. */
    private static ObjectFactory load() throws Exception {
        Class<?> type = Class.forName(FACTORY, true, Thread.currentThread().getContextClassLoader());
        assertTrue(Modifier.isPublic(type.getModifiers()), "Tomcat이 생성할 수 있도록 public이어야 한다");
        return (ObjectFactory) type.getConstructor().newInstance();
    }

    @Test
    void loadsByClassNameAndDelegatesToDbcp2() throws Exception {
        String token = TestSupport.managedCrypto().encryptText("dummy-entry-pw");
        String user = TestSupport.managedCrypto().encryptText("dummy-entry-user");
        Reference resource = resource(user, token);
        Object dataSource = load().getObjectInstance(resource, null, null, null);
        assertTrue(dataSource instanceof DataSource);
        assertEquals("dummy-entry-pw", BasicDataSourceFactory.lastPassword);
        assertEquals("dummy-entry-user", BasicDataSourceFactory.lastUsername);
        assertFalse(BasicDataSourceFactory.lastHadFactoryAttribute);
        assertEquals(token, ((StringRefAddr) resource.get("password")).getContent(), "원본 Reference 불변");
    }

    @Test
    void delegatesToOptionalTomcatJdbcPool() throws Exception {
        Path config = TestSupport.writeManagedConfig(dir, "pool.properties", "crypto.key.source=embedded",
                "crypto.pool.factory=" + CryptoSettings.TOMCAT_JDBC_FACTORY);
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString())) {
            String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-pool-pw");
            load().getObjectInstance(resource("u", token), null, null, null);
            assertEquals("dummy-pool-pw", org.apache.tomcat.jdbc.pool.DataSourceFactory.lastPassword);
            assertEquals(0, BasicDataSourceFactory.invocations);
        }
    }

    @Test
    void usesConfigFileJvmPropertyWithFileKey() throws Exception {
        Path key = TestSupport.writeRandomKeyFile(dir, "external.key");
        Path config = TestSupport.writeManagedConfig(dir, "external.properties", "crypto.key.type=key", "crypto.key.source=file", "crypto.key.id=ext01",
                "crypto.key.file=" + TestSupport.propertiesPath(key));
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString())) {
            String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-external-pw");
            load().getObjectInstance(resource("u", token), null, null, null);
            assertEquals("dummy-external-pw", BasicDataSourceFactory.lastPassword);
        }
    }

    @Test
    void jvmPropertiesAloneConfigureFileKeyAndSilenceWarnings() throws Exception {
        // 시나리오 B: 외부 Properties 없이 CATALINA_OPTS의 -D 옵션만으로 file 키·키ID·경고 정책을 지정한 상황.
        Path key = TestSupport.writeRandomKeyFile(dir, "jvm.key");
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.key.type=key", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(key), "crypto.key.id=prod01",
                "crypto.algorithm=AES/GCM/NoPadding", "crypto.warning.enabled=false");
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            String token = CredentialCrypto.fromDefaultConfiguration().encryptText("dummy-jvm-pw", io.javacryptokit.KeyType.KEY);
            assertTrue(token.startsWith("ENC[v1:prod01:"));
            load().getObjectInstance(resource("u", token), null, null, null);
            assertEquals("dummy-jvm-pw", BasicDataSourceFactory.lastPassword);
            assertTrue(log.warnings().isEmpty(), log.warnings().toString());
        }
    }

    @Test
    void mixedExternalKeyAndJvmWarningPolicy() throws Exception {
        // 시나리오 D: 키는 외부 Properties(공개 기본 키를 file로 공급해 경고 대상이 되게 함), 경고만 JVM 속성이 정한다.
        Path publicKey = TestSupport.writeRandomKeyFile(dir, "external.key");
        Path config = TestSupport.writeManagedConfig(dir, "mixed.properties", "crypto.key.type=key", "crypto.key.source=file",
                "crypto.key.file=" + TestSupport.propertiesPath(publicKey), "crypto.warning.enabled=true");
        String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-mixed-pw", io.javacryptokit.KeyType.KEY);
        DefaultKeyWarning.resetForTests();
        try (AutoCloseable path = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString());
             AutoCloseable jvm = TestSupport.jvmSettings("crypto.warning.enabled=false");
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            load().getObjectInstance(resource("u", token), null, null, null);
            assertEquals("dummy-mixed-pw", BasicDataSourceFactory.lastPassword, "키는 외부 Properties를 따른다");
            assertTrue(log.warnings().isEmpty(), "경고는 JVM 속성(false)을 따른다: " + log.warnings());
        }
    }

    @Test
    void overrideDisabledInExternalFileKeepsWarningPolicyFromFile() throws Exception {
        // 시나리오 F: 외부 Properties가 JVM 덮어쓰기를 막으면 -Dcrypto.warning.enabled=false는 무시되고 경고가 나온다.
        Path config = TestSupport.writeManagedConfig(dir, "policy.properties", "crypto.key.source=embedded",
                "crypto.warning.enabled=true", "crypto.jvm.override.enabled=false");
        String token = CredentialCrypto.fromConfigFile(config).encryptText("dummy-policy-pw");
        DefaultKeyWarning.resetForTests();
        try (AutoCloseable path = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString());
             AutoCloseable jvm = TestSupport.jvmSettings("crypto.warning.enabled=false", "crypto.jvm.override.enabled=true");
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            load().getObjectInstance(resource("u", token), null, null, null);
            assertEquals("dummy-policy-pw", BasicDataSourceFactory.lastPassword);
            assertTrue(CryptoSettings.load(null).warningEnabled());
            assertTrue(log.warnings().isEmpty());
        }
    }

    @Test
    void rawKeyInJvmPropertyFailsClosedWithoutEchoingIt() throws Exception {
        byte[] raw = new byte[32];
        new SecureRandom().nextBytes(raw);
        String dummyKey = Base64.getEncoder().encodeToString(raw);
        String token = TestSupport.managedCrypto().encryptText("dummy-raw-pw");
        try (AutoCloseable jvm = TestSupport.jvmSettings("crypto.key.embedded=" + dummyKey);
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            NamingException thrown = assertThrows(NamingException.class,
                    () -> load().getObjectInstance(resource("u", token), null, null, null));
            assertTrue(thrown.getMessage().contains(CryptoSettings.KEY_EMBEDDED), thrown.getMessage());
            assertFalse(thrown.getMessage().contains(dummyKey));
            assertNull(thrown.getCause());
            assertFalse(log.allText().contains(dummyKey));
            assertEquals(0, BasicDataSourceFactory.invocations, "설정 오류면 하위 Pool을 호출하지 않는다");
        }
    }

    @Test
    void warningOffStillFailsOnTamperedCiphertext() throws Exception {
        String token = TestSupport.managedCrypto().encryptText("dummy-tamper-pw");
        String tampered = token.substring(0, token.length() - 3)
                + (token.charAt(token.length() - 3) == 'A' ? 'B' : 'A') + token.substring(token.length() - 2);
        try (AutoCloseable jvm = TestSupport.jvmSettings("crypto.warning.enabled=false")) {
            NamingException thrown = assertThrows(NamingException.class,
                    () -> load().getObjectInstance(resource("u", tampered), null, null, null));
            assertTrue(thrown.getMessage().contains("무결성"), "WARN OFF여도 보안 검증 실패는 그대로 드러나야 한다");
            assertEquals(0, BasicDataSourceFactory.invocations);
        }
    }

    private static Reference resource(String username, String password) {
        Reference reference = new Reference("javax.sql.DataSource");
        reference.add(new StringRefAddr("factory", FACTORY));
        reference.add(new StringRefAddr("username", username));
        reference.add(new StringRefAddr("password", password));
        reference.add(new StringRefAddr("url", "jdbc:fake:memory"));
        return reference;
    }

    @Test
    void factoryErrorsCarryFixedEnglishReasonCodes() throws Exception {
        // 콘솔 인코딩 문제로 한글이 깨져도 원인을 구분할 수 있도록 메시지 끝에 고정 사유 코드를 붙인다.
        String token = TestSupport.managedCrypto().encryptText("dummy-code-pw");
        String tampered = token.substring(0, token.length() - 3)
                + (token.charAt(token.length() - 3) == 'A' ? 'B' : 'A') + token.substring(token.length() - 2);
        assertCodeCauseAndAction(failure(resource("u", tampered)), "INTEGRITY");
        assertCodeCauseAndAction(failure(resource("u", "dummy-plain-pw")), "PLAINTEXT_PASSWORD");
        Reference noPassword = new Reference("javax.sql.DataSource");
        noPassword.add(new StringRefAddr("username", "u"));
        assertCodeCauseAndAction(failure(noPassword), "MISSING_PASSWORD");
        BasicDataSourceFactory.nextFailure = new IllegalStateException("x");
        assertCodeCauseAndAction(failure(resource("u", token)), "POOL_FAILURE");
        try (AutoCloseable jvm = TestSupport.jvmSettings("crypto.warning.enabled=maybe")) {
            assertCodeCauseAndAction(failure(resource("u", token)), "CONFIGURATION");
        }
    }

    /** "[java-crypto-kit] [사유: 코드] 원인 ... 조치: ..." 형식인지 확인한다(CLI·Java API와 같은 형식). */
    private static void assertCodeCauseAndAction(String message, String code) {
        assertTrue(message.startsWith("[java-crypto-kit] [사유: " + code + "] "), message);
        assertTrue(message.contains(" 조치: "), "확인할 설정·조치를 함께 알려야 한다: " + message);
    }

    private static String failure(Reference resource) throws Exception {
        NamingException thrown = assertThrows(NamingException.class,
                () -> load().getObjectInstance(resource, null, null, null));
        return thrown.getMessage();
    }
}
