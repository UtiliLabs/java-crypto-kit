package io.javacryptokit.config;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 이 라이브러리가 직접 만든 고정 문구만 메시지로 가지는 설정·키 검증 예외다.
 * 패키지 사이에서 쓰기 위해 public이지만 다음 버전에서 바뀔 수 있으므로 애플리케이션에서 직접 쓰지 않는다.
 *
 * <p>JDK의 {@link IllegalArgumentException}(예: 경로 형식 오류 {@code InvalidPathException})은 메시지에 입력 경로가
 * 들어갈 수 있어 화면·로그에 그대로 내보낼 수 없다. 반면 이 클래스의 메시지는 고정 문구라서 CLI·Tomcat 오류 메시지에
 * 그대로 포함해도 안전하다. 덕분에 운영자는 "키 파일 경로가 지정되지 않았습니다" 같은 구체적인 원인을 볼 수 있다.</p>
 *
 * <p>기존 호출부와의 호환을 위해 {@link IllegalArgumentException}의 하위 클래스로 둔다.</p>
 */
public final class SafeMessageException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    /**
     * @param fixedMessage 비밀값·입력값·경로가 들어 있지 않은 고정 문구
     */
    public SafeMessageException(String fixedMessage) {
        super(fixedMessage);
    }
}
