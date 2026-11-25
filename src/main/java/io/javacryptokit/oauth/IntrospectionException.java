package io.javacryptokit.oauth;

/**
 * <b>공개 API</b>: Introspection 조회 자체가 실패함(인증 서버 통신·응답 문제). <b>토큰이 비활성이라는 뜻이 아니다</b>(비활성은
 * {@link IntrospectionResult#active()}가 false). 이 예외가 나면 토큰을 유효하다고 보지 말고, 일반 JWT 검증으로 대신하지도 않는다.
 * 사유는 {@link #getReason()}({@link OAuthClientException.Reason})이며 문구에는 토큰·클라이언트 비밀·응답 본문을 넣지 않는다.
 */
public final class IntrospectionException extends OAuthClientException {
    private static final long serialVersionUID = 1L;

    IntrospectionException(Reason reason, String message, int statusCode) {
        super(reason, message, statusCode, null);
    }
}
