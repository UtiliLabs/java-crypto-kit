package io.javacryptokit.key;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: {@code doctor} 점검 결과 한 줄(상태 코드 + 설명 + 조치). 키·토큰·평문은 담지 않는다.
 * 상태 코드({@code PASS/WARN/FAIL/INFO/SKIP})는 언어와 관계없이 같아 스크립트가 판별할 수 있다.
 */
public final class Diagnostic {
    /** 점검 상태(번역하지 않는 고정 코드). */
    public enum Status {
        /** 정상. */
        PASS,
        /** 동작은 하지만 주의가 필요함. */
        WARN,
        /** 실패(이대로는 WAS 기동·복호화가 실패함). 종료 코드가 0이 아니다. */
        FAIL,
        /** 참고 정보. */
        INFO,
        /** 점검하지 않음(예: --offline이라 네트워크 점검 생략, 앞 단계 실패). */
        SKIP
    }

    /** 상태. */
    public final Status status;
    /** 설명(현재 메시지 언어). */
    public final String message;
    /** 조치 안내(없으면 null). */
    public final String action;

    private Diagnostic(Status status, String message, String action) {
        this.status = status;
        this.message = message;
        this.action = action;
    }

    /**
     * @param status  상태
     * @param message 설명
     * @param action  조치(없으면 null)
     * @return 점검 결과
     */
    public static Diagnostic of(Status status, String message, String action) {
        return new Diagnostic(status, message, action);
    }

    /** @return 정상 결과 */
    public static Diagnostic pass(String message) {
        return new Diagnostic(Status.PASS, message, null);
    }

    /** @return 참고 정보 */
    public static Diagnostic info(String message) {
        return new Diagnostic(Status.INFO, message, null);
    }

    /** @return 경고 결과 */
    public static Diagnostic warn(String message, String action) {
        return new Diagnostic(Status.WARN, message, action);
    }

    /** @return 실패 결과 */
    public static Diagnostic fail(String message, String action) {
        return new Diagnostic(Status.FAIL, message, action);
    }

    /** @return 생략 결과 */
    public static Diagnostic skip(String message) {
        return new Diagnostic(Status.SKIP, message, null);
    }
}
