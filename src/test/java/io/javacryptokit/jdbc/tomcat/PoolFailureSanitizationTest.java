package io.javacryptokit.jdbc.tomcat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.key.DefaultKeyWarning;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.UUID;
import javax.naming.NamingException;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * 보안 회귀 시험: 하위 JDBC Pool Factory가 "복호화된 평문 비밀번호가 들어 있는 예외"를 던져도, 그 내용이
 * 이 라이브러리 밖(Tomcat·애플리케이션·로그)으로 그대로 전달되지 않는지 검증한다(모의 Pool Factory 사용).
 *
 * <p>검사 범위: Pool 2종(DBCP2 기본, 선택형 Tomcat JDBC Pool) × 예외 6종(메시지·원인·suppressed에 평문을 넣은
 * NamingException, 원인 체인이 있는 SQLException, 실행 예외, 클래스 로딩 오류(LinkageError), 일반 Error(AssertionError),
 * 원인 체인이 순환하는 예외). 밖으로 나가는 예외는 원인·suppressed가 없어야 하고, 메시지·스택 트레이스·로그 어디에도 평문이
 * 없어야 한다. 대신 비밀값이 아닌 "원인 유형"(클래스 이름·SQLState)은 남아 진단할 수 있어야 한다.</p>
 */
class PoolFailureSanitizationTest {
    @TempDir
    Path dir;

    private AutoCloseable isolation;

    @BeforeEach
    void isolate() {
        assumeTrue(TestSupport.noConfigEnvironmentVariables(), "설정 경로 환경변수가 있으면 Factory 시험 결과가 달라진다");
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
        BasicDataSourceFactory.reset();
        org.apache.tomcat.jdbc.pool.DataSourceFactory.reset();
        if (isolation != null) isolation.close();
    }

    /** 평문 비밀번호를 여러 위치(메시지·원인·suppressed)에 넣은 하위 Pool 예외를 만든다. */
    private static Throwable failure(String kind, String secret) {
        switch (kind) {
            case "naming":
                NamingException naming = new NamingException("pool failed, password=" + secret);
                naming.setRootCause(new IllegalStateException("root cause " + secret));
                naming.addSuppressed(new RuntimeException("suppressed " + secret));
                return naming;
            case "sql":
                SQLException sql = new SQLException("Access denied for user, password " + secret, "28000", 1045);
                sql.initCause(new IllegalArgumentException("driver detail " + secret));
                sql.setNextException(new SQLException("next " + secret));
                return sql;
            case "runtime":
                return new IllegalStateException("invalid pool config url=jdbc:x://h?password=" + secret);
            case "linkage":
                return new NoClassDefFoundError("could not init pool with " + secret);
            case "error":
                return new AssertionError("unexpected state, password=" + secret);
            case "cycle":
                RuntimeException first = new RuntimeException("cycle-a " + secret);
                RuntimeException second = new RuntimeException("cycle-b " + secret, first);
                first.initCause(second);
                return first;
            default:
                throw new IllegalArgumentException(kind);
        }
    }

    @ParameterizedTest(name = "{0} Pool이 {1} 예외를 던져도 평문이 새지 않음")
    @CsvSource({
            "dbcp2,naming", "dbcp2,sql", "dbcp2,runtime", "dbcp2,linkage", "dbcp2,error", "dbcp2,cycle",
            "tomcat-jdbc,naming", "tomcat-jdbc,sql", "tomcat-jdbc,runtime", "tomcat-jdbc,linkage", "tomcat-jdbc,error",
            "tomcat-jdbc,cycle"})
    void downstreamPoolFailureNeverLeaksThePlainPassword(String pool, String kind) throws Exception {
        String secret = "dummy-plain-" + UUID.randomUUID();
        Path config = TestSupport.writeConfig(dir, "pool.properties", "crypto.key.source=embedded",
                "crypto.pool.factory=" + ("dbcp2".equals(pool) ? CryptoSettings.DBCP2_FACTORY : CryptoSettings.TOMCAT_JDBC_FACTORY));
        try (AutoCloseable ignored = TestSupport.systemProperty(CryptoSettings.CONFIG_FILE_PROPERTY, config.toString());
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            String token = CredentialCrypto.fromConfigFile(config).encryptText(secret);
            Throwable fromPool = failure(kind, secret);
            if ("dbcp2".equals(pool)) {
                BasicDataSourceFactory.nextFailure = fromPool;
            } else {
                org.apache.tomcat.jdbc.pool.DataSourceFactory.nextFailure = fromPool;
            }
            NamingException thrown = assertThrows(NamingException.class,
                    () -> new EncryptedDataSourceFactory().getObjectInstance(resource(token), null, null, null));

            // 하위 Pool에는 복호화된 평문이 실제로 전달되었다(즉 예외 안에 평문이 있던 상황을 재현했다).
            String delivered = "dbcp2".equals(pool) ? BasicDataSourceFactory.lastPassword
                    : org.apache.tomcat.jdbc.pool.DataSourceFactory.lastPassword;
            assertEquals(secret, delivered);

            // 어느 Pool이 실패했는지(설정한 Pool 이름과 그 라이브러리 JAR)를 알려 준다.
            String poolName = "dbcp2".equals(pool) ? "DBCP2" : "Tomcat JDBC Pool";
            String poolJar = "dbcp2".equals(pool) ? "tomcat-dbcp.jar" : "tomcat-jdbc.jar";
            assertTrue(thrown.getMessage().startsWith("[java-crypto-kit] [사유: POOL_FAILURE] Connection Pool(" + poolName
                    + ") 생성에 실패했습니다"), thrown.getMessage());
            assertTrue(thrown.getMessage().contains("Pool 라이브러리(" + poolJar + ")"), thrown.getMessage());
            assertTrue(thrown.getMessage().contains("원인 유형: " + fromPool.getClass().getSimpleName()),
                    "비밀값 없이 원인 유형으로 진단할 수 있어야 한다: " + thrown.getMessage());
            assertNull(thrown.getCause(), "원인 예외를 붙이지 않는다");
            assertNull(thrown.getRootCause());
            assertEquals(0, thrown.getSuppressed().length);
            assertFalse(thrown.getMessage().contains(secret));
            assertFalse(thrown.getMessage().contains(token), "암호문도 넣지 않는다");
            StringWriter trace = new StringWriter();
            thrown.printStackTrace(new PrintWriter(trace));
            assertFalse(trace.toString().contains(secret), "스택 트레이스 전체에 평문이 없어야 한다");
            assertFalse(log.allText().contains(secret), "로그에 평문이 없어야 한다");
        }
    }

    @Test
    void sqlStateIsKeptForDiagnosisButMessageIsDropped() throws Exception {
        String secret = "dummy-plain-" + UUID.randomUUID();
        String token = TestSupport.jarDefaults().encryptText(secret);
        BasicDataSourceFactory.nextFailure = new SQLException("Access denied, password " + secret, "28000", 1045);
        NamingException thrown = assertThrows(NamingException.class,
                () -> new EncryptedDataSourceFactory().getObjectInstance(resource(token), null, null, null));
        assertTrue(thrown.getMessage().contains("SQLException(SQLState=28000)"), thrown.getMessage());
        assertFalse(thrown.getMessage().contains(secret));
    }

    @Test
    void nonStandardSqlStateIsNotCopiedIntoTheMessage() throws Exception {
        String secret = "pw" + UUID.randomUUID().toString().substring(0, 3);
        String token = TestSupport.jarDefaults().encryptText("dummy-pw");
        // 드라이버가 SQLState 자리에 임의 문자열(여기서는 비밀값 흉내)을 넣어도 표준 5자리 형식이 아니면 버린다.
        BasicDataSourceFactory.nextFailure = new SQLException("x", "state:" + secret);
        NamingException thrown = assertThrows(NamingException.class,
                () -> new EncryptedDataSourceFactory().getObjectInstance(resource(token), null, null, null));
        assertFalse(thrown.getMessage().contains(secret), thrown.getMessage());
        assertTrue(thrown.getMessage().contains("원인 유형: SQLException"));
    }

    @Test
    void jvmFatalErrorsArePropagatedUnchanged() throws Exception {
        // 메모리 부족 같은 JVM 장애는 JVM이 만든 고정 메시지라 사용자 데이터가 없고, 장애 처리를 위해 그대로 전달한다.
        String token = TestSupport.jarDefaults().encryptText("dummy-pw");
        OutOfMemoryError oom = new OutOfMemoryError("Java heap space");
        BasicDataSourceFactory.nextFailure = oom;
        OutOfMemoryError thrown = assertThrows(OutOfMemoryError.class,
                () -> new EncryptedDataSourceFactory().getObjectInstance(resource(token), null, null, null));
        assertSame(oom, thrown);
    }

    @Test
    void warningPolicyOffDoesNotHideOrAlterPoolFailures() throws Exception {
        String secret = "dummy-plain-" + UUID.randomUUID();
        try (AutoCloseable ignored = TestSupport.jvmSettings("crypto.warning.enabled=false");
             TestSupport.LogCapture log = new TestSupport.LogCapture()) {
            String token = CredentialCrypto.fromDefaultConfiguration().encryptText(secret);
            BasicDataSourceFactory.nextFailure = new SQLException("denied " + secret, "28000");
            NamingException thrown = assertThrows(NamingException.class,
                    () -> new EncryptedDataSourceFactory().getObjectInstance(resource(token), null, null, null));
            assertTrue(thrown.getMessage().contains("SQLState=28000"), "경고를 꺼도 오류는 그대로 드러나야 한다");
            assertFalse(thrown.getMessage().contains(secret));
            assertTrue(log.warnings().isEmpty(), "경고 정책 false: 안내 WARNING 없음");
        }
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
