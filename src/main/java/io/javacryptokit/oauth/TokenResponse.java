package io.javacryptokit.oauth;

import java.time.Instant;
import java.util.OptionalLong;
import java.util.Set;

/**
 * <b>공개 API</b>: Client Credentials로 발급받은 Access Token(RFC 6749 5.1 성공 응답). 토큰 문자열은 그대로 돌려주며 JWT라고 가정하지
 * 않는다. 발급 성공은 리소스 접근 승인이나 JWT 검증 성공과 같지 않다(리소스 서버가 검증한다). 응답의 {@code refresh_token}은 읽지
 * 않는다. 토큰을 저장·공유·갱신하는 일(캐시, 만료 전 재발급)은 호출 애플리케이션 몫이며, {@code toString}에는 토큰을 넣지 않는다.
 */
public final class TokenResponse {
    private final String accessToken;
    private final Long expiresIn;
    private final Instant receivedAt;
    private final Set<String> requestedScopes;
    private final Set<String> grantedScopes;
    private final boolean scopeInResponse;

    TokenResponse(String accessToken, Long expiresIn, Instant receivedAt, Set<String> requestedScopes, Set<String> grantedScopes,
                  boolean scopeInResponse) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.receivedAt = receivedAt;
        this.requestedScopes = requestedScopes;
        this.grantedScopes = grantedScopes;
        this.scopeInResponse = scopeInResponse;
    }

    /** @return {@code access_token} 원문(로그에 남기지 않는다) */
    public String accessToken() {
        return accessToken;
    }

    /** @return {@code token_type}: 지원하는 {@code Bearer}만 받으며 대소문자 구분 없이 받아 {@code Bearer}로 돌려준다 */
    public String tokenType() {
        return "Bearer";
    }

    /** @return HTTP Authorization 헤더 값({@code Bearer <토큰>}) */
    public String authorizationHeader() {
        return "Bearer " + accessToken;
    }

    /** @return {@code expires_in}(초). 인증 서버가 주지 않았으면 빈 값(만료 시각을 지어내지 않음) */
    public OptionalLong expiresIn() {
        return expiresIn == null ? OptionalLong.empty() : OptionalLong.of(expiresIn);
    }

    /** @return 응답을 받은 시각 + expires_in, 서버가 주지 않았으면 null */
    public Instant expiresAt() {
        return expiresIn == null ? null : receivedAt.plusSeconds(expiresIn);
    }

    /** @return 응답을 받은 시각(주입한 시계 기준) */
    public Instant receivedAt() {
        return receivedAt;
    }

    /** @return 요청한 scope(공백으로 나눈 값, 요청하지 않았으면 빈 집합) */
    public Set<String> requestedScopes() {
        return requestedScopes;
    }

    /** @return 응답의 scope(공백으로 나눈 값). 응답에 없으면 빈 집합({@link #scopeInResponse()}로 구분) */
    public Set<String> grantedScopes() {
        return grantedScopes;
    }

    /** @return 응답에 {@code scope}가 있었으면 true(없으면 RFC 6749상 요청과 같다는 뜻이지만 이 객체는 추측하지 않는다) */
    public boolean scopeInResponse() {
        return scopeInResponse;
    }

    @Override
    public String toString() {
        return "TokenResponse[Bearer" + (expiresIn == null ? "" : ", expiresIn=" + expiresIn + "s") + "]";
    }
}
