package io.javacryptokit.oauth;

import java.io.IOException;

/**
 * <b>공개 API</b>: 인증 서버 HTTPS 호출({@link TokenIntrospector}·{@link ClientCredentials})이 실패함. 공통 상위 예외이며 실제로는
 * {@link IntrospectionException}·{@link TokenRequestException}이 던져진다. 문구에는 토큰·클라이언트 비밀·응답 본문
 * ({@code error_description} 포함)을 넣지 않는다.
 */
public abstract class OAuthClientException extends IOException {
    private static final long serialVersionUID = 1L;

    /** 실패 사유. 이름은 공개 계약이다. */
    public enum Reason {
        /** 인증 서버가 OAuth 오류 응답을 돌려줌(RFC 6749 5.2, {@link #getOAuthError()}의 표준 오류 코드). */
        OAUTH_ERROR,
        /** 인증 서버가 200이 아닌 상태를 돌려줌(4xx·5xx). */
        HTTP_STATUS,
        /** 클라이언트 인증 실패(401·403). */
        CLIENT_AUTH,
        /** 리다이렉트 응답(따라가지 않음). */
        REDIRECT,
        /** 연결·읽기 시간 초과. */
        TIMEOUT,
        /** TLS 실패(인증서 신뢰·호스트명 불일치 등). */
        TLS,
        /** 그 밖의 네트워크 오류. */
        NETWORK,
        /** 응답이 JSON 객체가 아니거나 필수 값·형식이 맞지 않음. */
        INVALID_RESPONSE,
        /** 응답이 크기 상한을 넘음. */
        RESPONSE_TOO_LARGE
    }

    private final Reason reason;
    private final int statusCode;
    private final String oauthError;

    OAuthClientException(Reason reason, String message, int statusCode, String oauthError) {
        super(message);
        this.reason = reason;
        this.statusCode = statusCode;
        this.oauthError = oauthError;
    }

    /** @return 실패 사유 */
    public Reason getReason() {
        return reason;
    }

    /** @return HTTP 상태 코드(응답을 받지 못했으면 -1) */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * @return 인증 서버의 표준 오류 코드({@code invalid_client}·{@code invalid_scope}·{@code unauthorized_client}·
     *         {@code invalid_request}·{@code invalid_grant}·{@code unsupported_grant_type}), 없거나 표준이 아니면 null
     */
    public String getOAuthError() {
        return oauthError;
    }
}
