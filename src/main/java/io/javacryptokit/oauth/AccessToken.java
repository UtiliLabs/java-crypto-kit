package io.javacryptokit.oauth;

import io.javacryptokit.jwt.JwtClaims;
import io.javacryptokit.jwt.VerifiedJwt;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * <b>공개 API</b>: {@link AccessTokenVerifier}가 서명·프로파일·권한 정책을 모두 확인한 JWT Access Token. 라이브러리 밖에서는 만들 수
 * 없다. 검증 성공은 "믿는 발급자가 이 서비스용으로 발급했고 아직 유효하며 요구한 권한 클레임이 있다"는 뜻일 뿐, 최종 업무 접근
 * 승인·토큰 폐기·세션 상태 확인은 애플리케이션 몫이다.
 */
public final class AccessToken {
    private final VerifiedJwt jwt;
    private final String clientId;
    private final Set<String> scopes;
    private final List<String> roles;

    AccessToken(VerifiedJwt jwt, String clientId, Set<String> scopes, List<String> roles) {
        this.jwt = jwt;
        this.clientId = clientId;
        this.scopes = scopes;
        this.roles = roles;
    }

    /** @return 발급자({@code iss}) */
    public String issuer() {
        return jwt.claims().issuer();
    }

    /** @return 주체({@code sub}, 사용자 또는 클라이언트) */
    public String subject() {
        return jwt.claims().subject();
    }

    /** @return 클라이언트 ID(프로파일에서 정한 클레임, RFC 9068은 {@code client_id}; 정하지 않았으면 null) */
    public String clientId() {
        return clientId;
    }

    /** @return 대상({@code aud}) */
    public List<String> audience() {
        return jwt.claims().audience();
    }

    /** @return 위임 권한(scope 클레임을 공백으로 나눈 값, 없으면 빈 집합) */
    public Set<String> scopes() {
        return scopes;
    }

    /** @return 역할(roles 클레임, 없으면 빈 목록) */
    public List<String> roles() {
        return roles;
    }

    /**
     * @param scope 권한 이름(정확히 일치, 부분 문자열 아님)
     * @return 있으면 true
     */
    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    /**
     * @param role 역할 이름(정확히 일치)
     * @return 있으면 true
     */
    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    /** @return 만료 시각 */
    public Instant expiresAt() {
        return jwt.claims().expiresAt();
    }

    /** @return 토큰 ID({@code jti}, 없으면 null) */
    public String jwtId() {
        return jwt.claims().jwtId();
    }

    /** @return 검증된 전체 클레임 */
    public JwtClaims claims() {
        return jwt.claims();
    }

    /** @return 검증된 JWT(알고리즘·kid·헤더) */
    public VerifiedJwt jwt() {
        return jwt;
    }

    @Override
    public String toString() {
        return "AccessToken[" + jwt.algorithm() + ", scopes=" + scopes.size() + ", roles=" + roles.size() + "]";
    }
}
