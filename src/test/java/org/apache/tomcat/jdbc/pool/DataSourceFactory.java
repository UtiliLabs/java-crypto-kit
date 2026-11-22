package org.apache.tomcat.jdbc.pool;

import java.lang.reflect.Proxy;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.spi.ObjectFactory;
import javax.sql.DataSource;

/**
 * <b>테스트 전용 모의 클래스</b>: 선택형 공식 Tomcat JDBC Pool Factory와 같은 이름의 가짜 Factory다.
 * {@code crypto.pool.factory=org.apache.tomcat.jdbc.pool.DataSourceFactory}를 선택했을 때 위임 경로가 올바른지 검증한다.
 * 테스트 소스에만 있으며 배포 JAR에는 포함되지 않는다.
 */
public final class DataSourceFactory implements ObjectFactory {
    /** 마지막으로 전달받은 password 값(더미). */
    public static volatile String lastPassword;
    /** 마지막으로 전달받은 username 값. */
    public static volatile String lastUsername;
    /** 마지막으로 전달받은 maxActive 값(Tomcat JDBC Pool 고유 속성 보존 확인용). */
    public static volatile String lastMaxActive;
    /** 호출 횟수. */
    public static volatile int invocations;
    /** 지정하면 다음 호출에서 이 예외(Exception 또는 Error)를 던지고 비운다(하위 Pool 예외 정제 검증용). */
    public static volatile Throwable nextFailure;

    /** 기록을 초기화한다. */
    public static void reset() {
        lastPassword = null;
        lastUsername = null;
        lastMaxActive = null;
        invocations = 0;
        nextFailure = null;
    }

    /**
     * 전달받은 속성을 기록하고 DB에 접속하지 않는 모의 DataSource를 돌려준다.
     *
     * @throws Exception {@link #nextFailure}가 지정된 경우 그 예외
     */
    @Override
    public Object getObjectInstance(Object object, Name name, Context context,
                                    Hashtable<?, ?> environment) throws Exception {
        invocations++;
        Reference ref = (Reference) object;
        lastPassword = content(ref, "password");
        lastUsername = content(ref, "username");
        lastMaxActive = content(ref, "maxActive");
        Throwable failure = nextFailure;
        if (failure != null) {
            nextFailure = null;
            if (failure instanceof Error) throw (Error) failure;
            throw (Exception) failure;
        }
        return Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{DataSource.class},
                (proxy, method, args) -> {
                    if ("toString".equals(method.getName())) return "FakeTomcatJdbcDataSource";
                    throw new UnsupportedOperationException("모의 객체에서는 DB 접속을 수행하지 않습니다.");
                });
    }

    /** Reference에서 지정한 속성 값을 문자열로 꺼낸다. 없으면 null. */
    private static String content(Reference ref, String field) {
        RefAddr value = ref.get(field);
        return value == null ? null : String.valueOf(value.getContent());
    }
}
