package io.javacryptokit.oauth;

/**
 * <b>공개 API</b>: Client Credentials 토큰 발급 요청 실패. 인증 서버의 OAuth 오류(사유 {@link OAuthClientException.Reason#OAUTH_ERROR},
 * 표준 코드는 {@link #getOAuthError()}), HTTP 오류, 시간 초과, TLS·호스트명 실패, 응답 형식·크기 오류를 구분한다. 이 예외가 나면
 * 토큰이 발급되지 않은 것이다. 문구에는 클라이언트 비밀·토큰·{@code error_description}을 넣지 않는다.
 */
public final class TokenRequestException extends OAuthClientException {
    private static final long serialVersionUID = 1L;

    TokenRequestException(Reason reason, String message, int statusCode, String oauthError) {
        super(reason, message, statusCode, oauthError);
    }
}
