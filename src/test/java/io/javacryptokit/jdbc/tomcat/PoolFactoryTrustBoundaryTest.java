package io.javacryptokit.jdbc.tomcat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.key.DefaultKeyWarning;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.UUID;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * 보안 회귀 시험(QA-01): 공식 Pool Factory 클래스를 "이름"이 아니라 "신뢰할 수 있는 출처"에서 로딩하는지 검증한다.
 *
 * <p>Tomcat 웹 애플리케이션 클래스로더는 자식 우선으로 로딩하므로, 웹 애플리케이션이 공식 Pool과 같은 이름의 가짜 Factory를
 * 넣고 스레드 컨텍스트 클래스로더로 지정된 상태에서 DataSource가 만들어질 수 있다. 이 시험은 그 상황을 재현하기 위해,
 * 부모를 거치지 않고 테스트 클래스 폴더에서 같은 이름의 클래스를 따로 정의하는 클래스로더를 컨텍스트 로더로 둔다.
 * 복호화된 비밀번호는 라이브러리와 같은(신뢰) 로더의 Factory에만 전달되고, 가짜 쪽에는 전달되지 않아야 한다.</p>
 */
class PoolFactoryTrustBoundaryTest {
    @TempDir
    Path dir;

    private AutoCloseable isolation;

    @BeforeEach
    void isolate() {
        assumeTrue(TestSupport.noConfigEnvironmentVariables());
        AutoCloseable common = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, null);
        AutoCloseable others = TestSupport.clearOtherConfigProperties();
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

    /** 테스트 클래스 폴더를 부모 위임 없이(플랫폼 로더만 부모로) 읽는 "웹 애플리케이션 흉내" 클래스로더. */
    private static URLClassLoader lookalikeLoader() {
        URL testClasses = BasicDataSourceFactory.class.getProtectionDomain().getCodeSource().getLocation();
        // Java 8은 확장 로더, Java 9 이상은 플랫폼 로더: javax.naming·javax.sql은 보이지만 테스트 클래스는 보이지 않는다.
        ClassLoader platform = ClassLoader.getSystemClassLoader().getParent();
        return new URLClassLoader(new URL[]{testClasses}, platform);
    }

    @ParameterizedTest(name = "{0}: 컨텍스트 로더의 같은 이름 가짜 Factory는 평문 비밀번호를 받지 못함")
    @ValueSource(strings = {"dbcp2", "tomcat-jdbc"})
    void lookalikePoolFactoryInContextClassLoaderNeverReceivesThePassword(String pool) throws Exception {
        String factoryName = "dbcp2".equals(pool) ? CryptoSettings.DBCP2_FACTORY : CryptoSettings.TOMCAT_JDBC_FACTORY;
        Class<?> trusted = "dbcp2".equals(pool) ? BasicDataSourceFactory.class : org.apache.tomcat.jdbc.pool.DataSourceFactory.class;
        Path config = TestSupport.writeConfig(dir, "trust.properties", "crypto.key.source=embedded",
                "crypto.pool.factory=" + factoryName);
        String secret = "dummy-trust-" + UUID.randomUUID();
        String token = CredentialCrypto.fromConfigFile(config).encryptText(secret);

        try (URLClassLoader lookalike = lookalikeLoader();
             AutoCloseable path = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString())) {
            Class<?> fake = lookalike.loadClass(factoryName);
            assertNotSame(trusted, fake, "같은 이름이지만 다른 출처의 클래스여야 시험이 의미가 있다");
            assertFalse(EncryptedDataSourceFactory.definedByTrustedLoader(fake,
                    EncryptedDataSourceFactory.class.getClassLoader()), "다른 출처 클래스는 신뢰 대상이 아니다");

            Thread thread = Thread.currentThread();
            ClassLoader previous = thread.getContextClassLoader();
            thread.setContextClassLoader(lookalike);
            try {
                new EncryptedDataSourceFactory().getObjectInstance(resource(token), null, null, null);
            } finally {
                thread.setContextClassLoader(previous);
            }

            assertEquals(secret, trusted.getField("lastPassword").get(null), "신뢰 로더의 공식 Factory에 위임해야 한다");
            assertNull(fake.getField("lastPassword").get(null), "가짜 Factory에는 평문 비밀번호가 전달되면 안 된다");
            assertEquals(0, fake.getField("invocations").get(null));
        }
    }

    @Test
    void jdkAndAncestorClassesAreTrusted() {
        ClassLoader own = EncryptedDataSourceFactory.class.getClassLoader();
        assertTrue(EncryptedDataSourceFactory.definedByTrustedLoader(String.class, own), "부트스트랩 클래스");
        assertTrue(EncryptedDataSourceFactory.definedByTrustedLoader(BasicDataSourceFactory.class, own), "같은 로더");
    }

    private static Reference resource(String password) {
        Reference reference = new Reference("javax.sql.DataSource");
        reference.add(new StringRefAddr("factory", EncryptedDataSourceFactory.class.getName()));
        reference.add(new StringRefAddr("username", "app_user"));
        reference.add(new StringRefAddr("password", password));
        reference.add(new StringRefAddr("url", "jdbc:fake:memory"));
        return reference;
    }
}
