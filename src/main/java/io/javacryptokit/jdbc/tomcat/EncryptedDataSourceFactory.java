package io.javacryptokit.jdbc.tomcat;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.core.TokenCodec;
import io.javacryptokit.i18n.Messages;
import java.sql.SQLException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NamingException;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.naming.spi.ObjectFactory;

/**
 * <b>Tomcat 연동 어댑터(핵심 기능)</b>: Tomcat JNDI DataSource 설정의 암호문 비밀번호(필수)와 사용자명(선택)을 복호화한 뒤,
 * Tomcat이 제공하는 공식 Connection Pool Factory에 생성을 위임한다. 자체 Connection Pool은 구현하지 않는다.
 *
 * <p><b>적용 방법(애플리케이션 코드 수정 없음)</b>: JAR와 JDBC 드라이버를 {@code CATALINA_BASE/lib}에 두고, JNDI Resource에
 * {@code factory="io.javacryptokit.jdbc.tomcat.EncryptedDataSourceFactory"}를 추가한 뒤 {@code password}를 CLI가
 * 만든 암호문({@code ENC[v1:...]} 또는 {@code B64[...]})으로 바꾼다. 애플리케이션은 기존처럼 JNDI로 DataSource를 조회한다.
 * 키·경고 정책 등 설정을 바꿀 때도 JAR를 다시 빌드하지 않는다(WAS 실행 옵션·외부 파일만 변경).</p>
 *
 * <p><b>동작 흐름</b></p>
 * <ol>
 *   <li>Tomcat이 Resource를 만들 때 이 클래스를 기본 생성자로 만들고 {@link #getObjectInstance}를 호출한다.
 *       Resource의 모든 속성은 {@link Reference} 안에 문자열 속성({@link StringRefAddr})으로 들어 있다.</li>
 *   <li>공통 서비스({@link CryptoService#load})로 설정을 읽는다(CLI·공개 API와 같은 규칙). 최종값은 JVM 개별 속성
 *       ({@code -Dcrypto.key.source=file} 등, {@code crypto.jvm.override.enabled=true}일 때) &gt; 외부 설정 파일
 *       ({@code -Dcrypto.config.file=<경로>} 또는 같은 의미의 별칭·이전 이름·환경변수) &gt; JAR 기본값 순서로 정해진다.</li>
 *   <li>새 Reference를 만들어 속성을 복사하면서 접속정보만 복호화한 값으로 바꾸고, 이 클래스를 가리키는 {@code factory}
 *       속성은 뺀다. 원본 Reference는 건드리지 않는다.</li>
 *   <li>허용 목록의 Tomcat Pool Factory(DBCP2 기본, Tomcat JDBC Pool 선택)를 만들어 새 Reference를 넘기고, 돌려받은
 *       {@link javax.sql.DataSource}를 Tomcat에 반환한다.</li>
 * </ol>
 *
 * <p><b>시점 주의</b>: DataSource는 Tomcat이 Resource를 처음 만들 때(기동 중 또는 첫 JNDI 조회) 복호화되고, 실제 DB 연결은
 * Pool 설정에 따라 생성 시(initialSize &gt; 0) 또는 첫 {@code getConnection()}에서 일어난다. 따라서 기동 로그만으로 성공을
 * 판단하지 말고 {@code getConnection()}과 간단한 SQL까지 확인해야 한다.</p>
 *
 * <p><b>설계 판단</b></p>
 * <ul>
 *   <li>Tomcat 소스를 복사·상속하지 않고 컴파일 시점에도 Tomcat 라이브러리를 참조하지 않는다(Java 표준 JNDI API +
 *       리플렉션). 그래서 Tomcat 8.5/9/10.1/11에 같은 JAR를 적용할 수 있다. Tomcat 10 이후에도 JDBC API는 {@code javax.sql}이다.</li>
 *   <li>모든 실패는 원인(cause)·suppressed를 붙이지 않은 고정 문구의 {@link NamingException}으로 바꾼다. 하위 Pool Factory의
 *       예외(NamingException 포함)에는 평문 비밀번호·접속 URL이 들어 있을 수 있기 때문이다. 대신 비밀값이 아닌 "원인 유형"
 *       (예외 클래스 이름, SQLState)만 붙여 진단할 수 있게 한다.</li>
 *   <li>정제 범위는 이 Factory 안(설정 로딩·복호화·Pool 생성)에서 생긴 실패다. DataSource를 돌려준 뒤 애플리케이션이
 *       {@code getConnection()}을 호출할 때 Pool·JDBC 드라이버가 내는 예외와 로그는 이 클래스를 거치지 않으므로 정제하지
 *       않는다(드라이버 디버그 로그 등은 운영 설정으로 관리해야 한다).</li>
 *   <li>공식 Pool Factory는 이 라이브러리를 로딩한 클래스로더에서만 찾는다(웹 애플리케이션이 넣은 같은 이름의 가짜 Factory가
 *       평문 비밀번호를 받지 못하게 하기 위함). 그래서 Pool 라이브러리는 {@code CATALINA_BASE/lib}에 있어야 한다.</li>
 * </ul>
 */
public final class EncryptedDataSourceFactory implements ObjectFactory {
    /** Tomcat에서는 JULI 설정(conf/logging.properties)에 따라 기록된다. 민감정보는 기록하지 않는다. */
    private static final Logger LOG = Logger.getLogger(EncryptedDataSourceFactory.class.getName());
    /** 원인 유형을 몇 단계까지 붙일지. 너무 긴 메시지를 막는다. */
    private static final int MAX_CAUSE_DEPTH = 5;

    /**
     * Tomcat이 JNDI Resource(DataSource)를 실제로 생성할 때 호출하는 진입점이다.
     *
     * @param object      Tomcat이 넘겨주는 Resource 정의({@code javax.sql.DataSource} 타입의 {@link Reference})
     * @param name        JNDI 이름(위임 대상 Factory에 그대로 전달)
     * @param nameContext JNDI 컨텍스트(위임 대상 Factory에 그대로 전달)
     * @param environment JNDI 환경 정보(위임 대상 Factory에 그대로 전달)
     * @return Tomcat 공식 Pool Factory가 만든 {@link javax.sql.DataSource}
     * @throws NamingException 다음 경우 모두 정제된 메시지로 실패한다(평문 fallback 없음): Reference가 아니거나 DataSource가 아님,
     *                         설정 로딩·검증 실패, 접속정보가 문자열이 아님, 비밀번호가 암호문이 아님, 비밀번호 누락,
     *                         복호화 실패(위조·손상·키ID 불일치·키 오류), Pool Factory 로딩·생성 실패, DataSource 미반환
     */
    @Override
    public Object getObjectInstance(Object object, Name name, Context nameContext,
                                    Hashtable<?, ?> environment) throws Exception {
        // [1] 입력 형식 확인: DataSource Resource만 처리하고 다른 타입은 추측해 처리하지 않는다.
        if (!(object instanceof Reference)) {
            throw sanitized(Messages.get("factory.err.unsupportedRef"), "UNSUPPORTED_RESOURCE");
        }
        Reference original = (Reference) object;
        if (!"javax.sql.DataSource".equals(original.getClassName())) {
            throw sanitized(Messages.get("factory.err.notDataSource"), "UNSUPPORTED_RESOURCE");
        }

        // [2] 공통 설정 로딩. 외부 설정이 지정됐는데 읽지 못하면 내장 기본값으로 진행하지 않고 여기서 중단한다.
        final CryptoService crypto;
        try {
            crypto = CryptoService.load(null);
        } catch (CredentialCryptoException ex) {
            // 정제된 사유 문구만 붙인다(경로·설정값·키 없음).
            throw sanitized(Messages.get("factory.err.config", ex.getMessage()), ex.getReason().name());
        }
        // 설정을 읽은 뒤에는 이 Resource의 설정 언어(crypto.lang)로 메시지를 만든다(CLI 초기화에 의존하지 않음).
        try (Messages.Scope ignored = Messages.use(crypto.settings().language())) {
            return createDataSource(original, crypto, name, nameContext, environment);
        }
    }

    /**
     * 설정을 읽은 뒤의 처리: 접속정보 복호화와 공식 Pool Factory 위임.
     */
    private static Object createDataSource(Reference original, CryptoService crypto, Name name, Context nameContext,
                                           Hashtable<?, ?> environment) throws NamingException {

        // [3] 새 Reference에 속성을 복사하면서 접속정보만 복호화한다. 원본 Reference는 건드리지 않는다.
        Reference clear = new Reference(original.getClassName());
        boolean passwordFound = false;
        Enumeration<RefAddr> addresses = original.getAll();
        while (addresses.hasMoreElements()) {
            RefAddr address = addresses.nextElement();
            String property = address.getType();
            if ("factory".equals(property)) {
                // 이 Factory 자신을 가리키는 속성이므로 하위 Pool에 다시 전달하지 않는다.
                continue;
            }
            if ("password".equals(property) || "username".equals(property)) {
                // Tomcat은 Resource 속성을 문자열로 넘긴다. 다른 형식이면 예상하지 못한 경로이므로 거부한다.
                if (!(address.getContent() instanceof String)) {
                    throw sanitized(Messages.get("factory.err.notString"), "UNSUPPORTED_RESOURCE");
                }
                String value = (String) address.getContent();
                if ("password".equals(property)) {
                    passwordFound = true;
                    // 암호화되지 않은 비밀번호는 허용하지 않는다(crypto.require.encrypted.password=true 정책).
                    if (!TokenCodec.looksLikeToken(value)) {
                        throw sanitized(Messages.get("factory.err.plaintext"), "PLAINTEXT_PASSWORD");
                    }
                }
                // 비밀번호는 위에서 암호문임을 확인했고, 사용자명은 암호문일 때만 복호화한다(선택 기능).
                if (TokenCodec.looksLikeToken(value)) {
                    try {
                        value = crypto.decryptText(value);
                    } catch (CredentialCryptoException ex) {
                        // 사유 문구만 붙이고 암호문·평문·키는 넣지 않는다. 복호화 실패 시 대체 동작 없이 중단한다.
                        throw sanitized(Messages.get("factory.err.decrypt", property, ex.getMessage()),
                                ex.getReason().name());
                    }
                }
                clear.add(new StringRefAddr(property, value));
            } else {
                // Pool의 URL, maxTotal 등 기존 속성은 변경 없이 전달한다.
                clear.add(address);
            }
        }
        // 비밀번호 속성이 아예 없으면 "암호문 필수" 정책을 우회한 설정이므로 거부한다.
        if (!passwordFound) {
            throw sanitized(Messages.get("factory.err.missingPassword"), "MISSING_PASSWORD");
        }

        // [4] 허용 목록의 Tomcat 공식 Pool Factory에 생성을 위임한다.
        Object datasource;
        String[] pool = poolLabel(crypto.settings().poolFactory());
        try {
            ObjectFactory delegate = createOfficialPoolFactory(crypto.settings().poolFactory());
            datasource = delegate.getObjectInstance(clear, name, nameContext, environment);
        } catch (Exception | Error ex) {
            // JVM 자체 장애(메모리 부족·스택 넘침 등 VirtualMachineError)와 스레드 종료 신호(ThreadDeath)는 그대로 전달한다.
            // JVM이 만든 고정 메시지라 사용자 데이터가 없고, 바꿔 버리면 장애 처리(덤프·종료)를 방해할 수 있다.
            if (ex instanceof VirtualMachineError || ex instanceof ThreadDeath) throw (Error) ex;
            // 그 밖의 예외·오류는 하위 Factory가 던진 것이 NamingException이든 Error(예: AssertionError, 클래스 로딩 오류)든
            // 그대로 전달하지 않는다. 메시지·원인·suppressed에 복호화한 비밀번호나 접속 URL이 들어 있을 수 있기 때문이다.
            // 비밀값이 아닌 원인 유형(클래스 이름, SQLState)만 남긴다.
            // (initialSize > 0이면 생성 시점에 DB에 접속하므로 DB 로그인 실패도 여기서 드러난다)
            throw sanitized(Messages.get("factory.err.pool", pool[0], describe(ex), pool[1]), "POOL_FAILURE");
        }
        // Tomcat Pool Factory는 처리할 수 없는 Reference에 null을 돌려줄 수 있으므로 결과 타입을 확인한다.
        if (!(datasource instanceof javax.sql.DataSource)) {
            throw sanitized(Messages.get("factory.err.noDataSource"), "POOL_FAILURE");
        }
        LOG.fine(Messages.TAG + " " + Messages.get("factory.log.delegated"));
        return datasource;
    }

    /**
     * 오류 메시지에 쓸 Pool 이름과 라이브러리 JAR 이름. 허용 목록은 두 가지뿐이므로 운영자가 어느 Pool이 실패했는지 바로 알 수 있게 한다.
     *
     * @param factoryClass 설정된 공식 Pool Factory 클래스 이름
     * @return {Pool 이름, JAR 이름}
     */
    private static String[] poolLabel(String factoryClass) {
        return CryptoSettings.TOMCAT_JDBC_FACTORY.equals(factoryClass)
                ? new String[] {"Tomcat JDBC Pool", "tomcat-jdbc.jar"}
                : new String[] {"DBCP2", "tomcat-dbcp.jar"};
    }

    /**
     * Tomcat 설치본에 실제 포함된 공식 Pool Factory를 동적으로 생성한다.
     *
     * <p>클래스 이름은 설정 검증에서 허용 목록(DBCP2, Tomcat JDBC Pool)으로 이미 확인되었으므로 임의 클래스를 만들지 않는다.</p>
     *
     * <p><b>신뢰 경계</b>: 이름이 허용 목록에 있다는 것만으로는 그 구현을 믿을 수 없다. 웹 애플리케이션 클래스로더(스레드
     * 컨텍스트 로더)는 자식 우선으로 로딩하므로, 웹 애플리케이션이 같은 이름의 가짜 Factory를 넣으면 복호화된 비밀번호를
     * 받게 된다. 그래서 컨텍스트 로더는 쓰지 않고, <b>이 라이브러리를 로딩한 클래스로더</b>(보통 {@code CATALINA_BASE/lib}의
     * 공통 로더이며 Tomcat 공식 {@code tomcat-dbcp.jar}·{@code tomcat-jdbc.jar}도 여기 있다)에서만 찾는다. 찾은 클래스를 실제로
     * 정의한 로더가 그 로더 자신이거나 상위(부모 체인)인지도 확인한다. 따라서 Pool 라이브러리는 이 JAR와 같은 곳
     * ({@code CATALINA_BASE/lib})에 있어야 하며, 웹 애플리케이션의 {@code WEB-INF/lib}에만 있는 Pool은 사용하지 않는다.</p>
     *
     * @param className 허용 목록에 있는 Pool Factory 클래스 이름
     * @return 새 Pool Factory 인스턴스
     * @throws Exception 클래스를 찾지 못했거나(예: tomcat-dbcp.jar 없음) 신뢰 로더가 정의한 클래스가 아니거나 생성에 실패했거나
     *                   ObjectFactory가 아닌 경우
     */
    private static ObjectFactory createOfficialPoolFactory(String className) throws Exception {
        ClassLoader trustedLoader = EncryptedDataSourceFactory.class.getClassLoader();
        Class<?> type = Class.forName(className, false, trustedLoader);
        if (!definedByTrustedLoader(type, trustedLoader)) {
            throw new SecurityException("untrusted pool factory loader");
        }
        Object instance = type.getDeclaredConstructor().newInstance();
        // 허용 목록 검증이 있더라도, 실제로 JNDI ObjectFactory인지 한 번 더 확인한다.
        if (!(instance instanceof ObjectFactory)) {
            throw new IllegalStateException("not a JNDI ObjectFactory");
        }
        return (ObjectFactory) instance;
    }

    /**
     * 클래스를 정의한 로더가 신뢰 로더 자신이거나 그 부모 체인(부트스트랩 포함)에 있는지 확인한다. 표준 부모 우선 위임을
     * 따르는 로더라면 항상 참이고, 이름이 같은 다른 출처의 클래스(형제·자식 로더가 정의한 클래스)는 거짓이 된다.
     *
     * @param type          확인할 클래스
     * @param trustedLoader 신뢰 로더(이 라이브러리를 로딩한 로더)
     * @return 신뢰할 수 있는 출처면 true
     */
    static boolean definedByTrustedLoader(Class<?> type, ClassLoader trustedLoader) {
        ClassLoader defining = type.getClassLoader();
        if (defining == null) return true; // 부트스트랩 로더(JDK 자체)
        for (ClassLoader loader = trustedLoader; loader != null; loader = loader.getParent()) {
            if (loader == defining) return true;
        }
        return false;
    }

    /**
     * 진단용 원인 유형을 만든다. 예외 메시지는 쓰지 않고 클래스 이름과 SQLState(표준 5자리 상태 코드)만 이어 붙인다.
     *
     * @param failure 하위 단계에서 발생한 예외
     * @return 예: {@code SQLException(SQLState=28000) > SQLInvalidAuthorizationSpecException}
     */
    static String describe(Throwable failure) {
        StringBuilder text = new StringBuilder();
        Throwable current = failure;
        for (int depth = 0; current != null && depth < MAX_CAUSE_DEPTH; depth++) {
            if (depth > 0) text.append(" > ");
            text.append(current.getClass().getSimpleName());
            if (current instanceof SQLException) {
                String state = ((SQLException) current).getSQLState();
                // 드라이버가 임의 문자열을 넣는 경우를 막기 위해 표준 형식(영숫자 5자리)일 때만 붙인다.
                if (state != null && state.matches("[0-9A-Za-z]{5}")) {
                    text.append("(SQLState=").append(state).append(')');
                }
            }
            Throwable next = current.getCause();
            if (next == current) break;
            current = next;
        }
        return text.toString();
    }

    /**
     * 민감한 내용을 메시지와 원인(cause)에 싣지 않는 표준 예외를 만든다. 형식은 {@link Messages#error}가 정한다
     * ({@code [java-crypto-kit] [사유: 코드] ...}, 영어는 {@code [reason: 코드]}).
     *
     * <p>메시지 앞에는 고정 영문 사유 코드를 붙인다({@code [사유: INTEGRITY]} 등). 형식은 "사유 코드 + 원인 + 조치"이며
     * CLI·Java API와 같다. 암복호화 실패는 공개 API
     * {@code CredentialCryptoException.Reason}과 같은 이름을 쓰고, Factory 전용 실패는 {@code PLAINTEXT_PASSWORD}·
     * {@code MISSING_PASSWORD}·{@code POOL_FAILURE}·{@code UNSUPPORTED_RESOURCE}를 쓴다. 코드는 번역하지 않으므로 로그 인코딩
     * 문제로 문장이 깨지거나 언어가 달라도 원인을 구분할 수 있다.</p>
     *
     * @param message 비밀값·입력값이 들어 있지 않은 고정 문구
     * @param code    고정 영문 사유 코드
     * @return 태그·사유 코드가 붙은 NamingException(원인 없음)
     */
    private static NamingException sanitized(String message, String code) {
        return new NamingException(Messages.error(code, message));
    }
}
