package org.apache.tomcat.dbcp.dbcp2;

import java.lang.reflect.Proxy;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.spi.ObjectFactory;
import javax.sql.DataSource;

/**
 * <b>테스트 전용 모의 클래스</b>: Tomcat 내장 DBCP2 Factory와 같은 패키지·클래스 이름을 쓰지만 실제 Tomcat 코드가 아니다.
 *
 * <p>{@code EncryptedDataSourceFactory}는 기본 설정에서 이 이름의 클래스를 리플렉션으로 찾아 위임한다. 테스트 클래스패스에
 * 이 모의 클래스를 두면 Tomcat·DB 없이도 "복호화된 값이 Pool Factory에 정확히 전달되는지"를 확인할 수 있다. 테스트 소스에만
 * 있으므로 배포 JAR에는 포함되지 않는다(빌드 후 {@code jar tf}로 확인).</p>
 *
 * <p>전달받은 값은 정적 필드에 기록해 테스트가 읽는다. {@link #nextFailure}를 지정하면 다음 호출에서 그 예외를 던져
 * "하위 Pool Factory 예외에 들어 있는 비밀값이 밖으로 새지 않는지"(S2)를 재현할 수 있다.</p>
 */
public final class BasicDataSourceFactory implements ObjectFactory {
    // 테스트 외부에 노출되거나 배포되는 클래스가 아니다.
    /** 마지막으로 전달받은 password 값(복호화 결과 확인용, 더미 값만 사용). */
    public static volatile String lastPassword;
    /** 마지막으로 전달받은 username 값. */
    public static volatile String lastUsername;
    /** 마지막으로 전달받은 url 값(일반 속성 보존 확인용). */
    public static volatile String lastUrl;
    /** 마지막으로 전달받은 Reference에 factory 속성이 남아 있었는지. */
    public static volatile boolean lastHadFactoryAttribute;
    public static volatile Reference lastReference;
    /** 호출 횟수. */
    public static volatile int invocations;
    /** 지정하면 다음 호출에서 이 예외(Exception 또는 Error)를 던지고 비운다(실패 재현용). */
    public static volatile Throwable nextFailure;

    /** 기록을 초기화한다. */
    public static void reset() {
        lastPassword = null;
        lastUsername = null;
        lastUrl = null;
        lastHadFactoryAttribute = false;
        lastReference = null;
        invocations = 0;
        nextFailure = null;
    }

    /**
     * Tomcat DBCP2 Factory 대신 호출되어 전달받은 속성을 기록하고 모의 DataSource를 돌려준다.
     *
     * @return DB에 접속하지 않는 모의 {@link DataSource} 프록시
     * @throws Exception {@link #nextFailure}가 지정된 경우 그 예외
     */
    @Override
    public Object getObjectInstance(Object object, Name name, Context context,
                                    Hashtable<?, ?> environment) throws Exception {
        invocations++;
        Reference ref = (Reference) object;
        lastReference = ref;
        lastPassword = content(ref, "password");
        lastUsername = content(ref, "username");
        lastUrl = content(ref, "url");
        lastHadFactoryAttribute = ref.get("factory") != null;
        Throwable failure = nextFailure;
        if (failure != null) {
            nextFailure = null;
            // 실제 Pool 라이브러리처럼 검사 예외·실행 예외·Error를 모두 던질 수 있게 한다(테스트는 Exception·Error만 지정).
            if (failure instanceof Error) throw (Error) failure;
            throw (Exception) failure;
        }
        // 핵심은 공식 Factory에 전달한 속성값 확인이다. 실제 DB에는 접속하지 않는다.
        return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{DataSource.class},
                (proxy, method, args) -> {
                    if ("toString".equals(method.getName())) return "FakeDbcp2DataSource";
                    throw new UnsupportedOperationException("모의 객체에서는 DB 접속을 수행하지 않습니다.");
                });
    }

    /** Reference에서 지정한 속성 값을 문자열로 꺼낸다. 없으면 null. */
    private static String content(Reference ref, String field) {
        RefAddr value = ref.get(field);
        return value == null ? null : String.valueOf(value.getContent());
    }
}
