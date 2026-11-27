package io.javacryptokit.oauth;

import io.javacryptokit.jwt.JwtClaims;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * <b>공개 API</b>: RFC 7662 Introspection 응답. {@link #active()}가 false이면 토큰을 쓰면 안 되며 다른 값은 의미가 없다(빈 값).
 * true이면 인증 서버가 알려 준 선택 정보(scope·client_id·exp 등)를 형식 검사 후 돌려준다. 명시된 scope는 RFC 6749 구문을 따른다. 이 API의 대상·업무 권한 확인
 * ({@link #audience()}·{@link #scopes()})은 호출자가 한다.
 */
public final class IntrospectionResult {
    private final boolean active;
    private final JwtClaims claims;
    private final Set<String> scopes;

    IntrospectionResult(boolean active, JwtClaims claims) {
        this.active = active;
        this.claims = claims;
        this.scopes = active ? OAuthText.responseScopes(claims) : Collections.emptySet();
    }

    /** @return 인증 서버가 활성이라고 답했으면 true */
    public boolean active() {
        return active;
    }

    /** @return 권한(scope를 공백으로 나눈 값, 비활성이거나 없으면 빈 집합) */
    public Set<String> scopes() {
        return scopes;
    }

    /** @return {@code client_id}(비활성·없으면 null) */
    public String clientId() {
        return active ? claims.getString("client_id") : null;
    }

    /** @return {@code username}(비활성·없으면 null) */
    public String username() {
        return active ? claims.getString("username") : null;
    }

    /** @return {@code token_type}(비활성·없으면 null) */
    public String tokenType() {
        return active ? claims.getString("token_type") : null;
    }

    /** @return {@code sub}(비활성·없으면 null) */
    public String subject() {
        return active ? claims.subject() : null;
    }

    /** @return {@code iss}(비활성·없으면 null) */
    public String issuer() {
        return active ? claims.issuer() : null;
    }

    /** @return {@code aud}(비활성·없으면 빈 목록) */
    public List<String> audience() {
        return active ? claims.audience() : Collections.<String>emptyList();
    }

    /** @return {@code jti}(비활성·없으면 null) */
    public String jwtId() {
        return active ? claims.jwtId() : null;
    }

    /** @return {@code exp}(비활성·없으면 null) */
    public Instant expiresAt() {
        return active ? claims.expiresAt() : null;
    }

    /** @return {@code iat}(비활성·없으면 null) */
    public Instant issuedAt() {
        return active ? claims.issuedAt() : null;
    }

    /** @return {@code nbf}(비활성·없으면 null) */
    public Instant notBefore() {
        return active ? claims.notBefore() : null;
    }

    /** @return 응답의 최상위 멤버 전체(비활성이면 {@code active}만) */
    public JwtClaims claims() {
        return claims;
    }

    @Override
    public String toString() {
        return "IntrospectionResult[active=" + active + "]";
    }
}
