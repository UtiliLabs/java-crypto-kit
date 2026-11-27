package io.javacryptokit.oauth;

import io.javacryptokit.jwt.JwtClaims;
import io.javacryptokit.jwt.JwtException;
import io.javacryptokit.jwt.JwtKey;
import io.javacryptokit.jwt.JwtVerifier;
import io.javacryptokit.jwt.VerifiedJwt;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * <b>공개 API</b>: OAuth 2.0 JWT Access Token 검증기(리소스 서버용). 일반 JWT 검증({@link JwtVerifier})과 목적이 다르다: "이 API를
 * 호출해도 되는 접근 토큰인가"를 확인하며, ID Token·다른 서비스용 토큰·일반 JWT를 Access Token으로 받아들이지 않도록 토큰 종류
 * 조건을 반드시 둔다. OAuth 인증 서버 기능(발급 엔드포인트·Refresh Token·폐기)은 없다.
 *
 * <p><b>두 가지 프로파일</b></p>
 * <ul>
 *   <li>{@link #rfc9068()}: RFC 9068 표준. 헤더 {@code typ}가 {@code at+jwt}(또는 {@code application/at+jwt}, 대소문자 무시)인
 *       토큰만, 필수 클레임 iss·exp·aud·sub·client_id·iat·jti, 권한은 {@code scope}(공백 구분)·{@code roles}.</li>
 *   <li>{@link #profile()}: RFC 9068을 따르지 않는 인증 서버(예: 헤더 typ가 {@code JWT}인 Microsoft Entra ID·Keycloak 기본 설정)를
 *       위한 설정형 프로파일. 발급자·대상은 필수이고, 토큰 종류({@code types})·필수 클레임·클레임 값·금지 클레임·권한 클레임 이름과
 *       필수 여부를 조합한다. ID Token과 구분할 조건이 <b>최종 설정 기준으로</b> 하나 이상 없으면 만들지 않는다: {@code JWT}가 아닌
 *       typ만 허용, 등록 클레임(iss·sub·aud·exp·nbf·iat·jti)이 아닌 필수 클레임·클레임 값·금지 클레임, 권한 클레임 필수(true),
 *       비어 있지 않은 필수 scope·roles. 빈 목록, 나중에 해제한 조건, typ {@code JWT} 허용은 구분 조건이 아니다(ID Token도 typ JWT).
 *       조건은 인증 서버의 실제 토큰 구조를 전제로 하므로, 클레임 하나만 지정했다고 모든 ID Token이 막힌다고 보장하지 않는다.
 *       인증 서버를 추가할 때 소스를 고치지 않고 이 설정만 바꾼다.</li>
 * </ul>
 *
 * <pre>{@code
 * // Microsoft Entra ID(v2) 예: typ JWT, 권한 scp(위임)·roles(앱), 클라이언트 azp
 * AccessTokenVerifier entra = AccessTokenVerifier.profile()
 *         .issuer("https://login.microsoftonline.com/" + tenantId + "/v2.0")
 *         .audience(apiClientId)
 *         .keys(Jwks.parse(jwksJson, "https://login.microsoftonline.com/" + tenantId + "/v2.0"))
 *         .types("JWT").scopeClaim("scp").rolesClaim("roles").clientIdClaim("azp")
 *         .requireClaimValue("ver", "2.0").requirePermissionClaim(true)
 *         .requireScopes("Orders.Read")
 *         .clockSkew(Duration.ofSeconds(60))
 *         .build();
 * AccessToken token = entra.verify(bearer);
 * }</pre>
 *
 * <p>시간·키·서명 규칙은 {@link JwtVerifier}와 같다(기본 오차 0초, exp 필수, 미래 iat 거부). 권한 확인은 정확한 이름 비교다
 * (부분 문자열로 승인하지 않음). 실패는 {@link JwtException}(권한 부족은 SCOPE). 객체는 불변이며 스레드 안전하다.</p>
 */
public final class AccessTokenVerifier {
    private static final String[] RFC9068_REQUIRED = {"iss", "exp", "aud", "sub", "client_id", "iat", "jti"};
    /** 모든 JWT(ID Token 포함)가 가질 수 있는 등록 클레임: 이 이름만으로는 토큰 종류를 구분하지 못한다. */
    private static final Set<String> REGISTERED_CLAIMS = new HashSet<>(Arrays.asList("iss", "sub", "aud", "exp", "nbf", "iat", "jti"));

    private final JwtVerifier jwt;
    private final String clientIdClaim;
    private final String scopeClaim;
    private final String rolesClaim;
    private final boolean requirePermission;
    private final boolean rfc9068;
    private final Set<String> requiredScopes;
    private final Set<String> requiredRoles;
    private final List<String> forbiddenClaims;

    private AccessTokenVerifier(Builder b, JwtVerifier jwt) {
        this.jwt = jwt;
        this.clientIdClaim = b.clientIdClaim;
        this.rfc9068 = b.rfc9068;
        this.scopeClaim = b.scopeClaim;
        this.rolesClaim = b.rolesClaim;
        this.requirePermission = b.requirePermission;
        this.requiredScopes = Collections.unmodifiableSet(new LinkedHashSet<>(b.requiredScopes));
        this.requiredRoles = Collections.unmodifiableSet(new LinkedHashSet<>(b.requiredRoles));
        this.forbiddenClaims = Collections.unmodifiableList(new ArrayList<>(b.forbiddenClaims));
    }

    /** @return RFC 9068 표준 프로파일 생성기 */
    public static Builder rfc9068() {
        return new Builder(true);
    }

    /** @return 설정형(공급자별) 프로파일 생성기 */
    public static Builder profile() {
        return new Builder(false);
    }

    /**
     * @param token Bearer 토큰(compact JWS)
     * @return 검증된 Access Token
     * @throws JwtException 서명·프로파일·시간·권한 중 하나라도 맞지 않음
     */
    public AccessToken verify(String token) throws JwtException {
        VerifiedJwt verified = jwt.verify(token);
        JwtClaims claims = verified.claims();
        for (String name : forbiddenClaims) {
            if (claims.has(name)) throw OAuthText.fail(JwtException.Reason.INVALID_CLAIM, "oauth.err.forbidden", name);
        }
        for (String name : new String[] {clientIdClaim, scopeClaim, rolesClaim}) {
            if (name != null) rejectExplicitNull(claims, name);
        }
        String clientId = null;
        if (clientIdClaim != null) {
            clientId = string(claims, clientIdClaim);
            if (clientId == null || clientId.isEmpty()) throw OAuthText.fail(JwtException.Reason.MISSING_CLAIM, "oauth.err.missing", clientIdClaim);
        }
        if (clientId != null) requireIdentifier(clientId, clientIdClaim);
        if (rfc9068) {
            requireIdentifier(string(claims, "sub"), "sub");
            requireIdentifier(string(claims, "jti"), "jti");
        }
        Set<String> scopes = scopes(claims);
        List<String> roles = roles(claims);
        if (requirePermission && scopes.isEmpty() && roles.isEmpty()) {
            throw OAuthText.fail(JwtException.Reason.SCOPE, "oauth.err.noPermission", scopeClaim + "/" + rolesClaim);
        }
        for (String scope : requiredScopes) {
            if (!scopes.contains(scope)) throw OAuthText.fail(JwtException.Reason.SCOPE, "oauth.err.scope", scopeClaim);
        }
        for (String role : requiredRoles) {
            if (!roles.contains(role)) throw OAuthText.fail(JwtException.Reason.SCOPE, "oauth.err.role", rolesClaim);
        }
        return new AccessToken(verified, clientId, scopes, roles);
    }

    private static void requireIdentifier(String value, String claim) throws JwtException {
        if (!OAuthText.validIdentifier(value)) {
            throw OAuthText.fail(JwtException.Reason.INVALID_CLAIM, "oauth.err.claimType", claim);
        }
    }

    private Set<String> scopes(JwtClaims claims) throws JwtException {
        String value = string(claims, scopeClaim);
        Set<String> out = new LinkedHashSet<>();
        if (value != null) {
            for (String part : value.split(" ")) {
                if (part.isEmpty()) continue;
                // 공백으로 나눈 각 이름은 scope 규칙을 따라야 한다(탭·제어문자 등이 섞인 값을 권한으로 인정하지 않음).
                if (!OAuthText.validScope(part)) throw OAuthText.fail(JwtException.Reason.INVALID_CLAIM, "oauth.err.claimType", scopeClaim);
                out.add(part);
            }
        }
        return Collections.unmodifiableSet(out);
    }

    private List<String> roles(JwtClaims claims) throws JwtException {
        List<String> roles;
        try {
            roles = claims.getStringList(rolesClaim);
        } catch (IllegalArgumentException e) {
            throw OAuthText.fail(JwtException.Reason.INVALID_CLAIM, "oauth.err.claimType", rolesClaim);
        }
        // 빈 문자열·공백만 있는 이름·제어문자가 든 이름은 역할로 인정하지 않는다(목록에 값이 있다는 것만으로 권한이 아님).
        for (String role : roles) {
            if (!OAuthText.validIdentifier(role)) throw OAuthText.fail(JwtException.Reason.INVALID_CLAIM, "oauth.err.claimType", rolesClaim);
        }
        return roles;
    }

    /** 클라이언트 ID·권한 클레임이 명시적 JSON null이면 "없음"과 구분해 형식 오류로 거부한다. */
    private static void rejectExplicitNull(JwtClaims claims, String name) throws JwtException {
        if (!claims.has(name)) return;
        boolean explicitNull;
        try {
            explicitNull = claims.getString(name) == null;
        } catch (IllegalArgumentException e) {
            explicitNull = false;   // 문자열이 아닌 값(배열 등)은 각 읽기에서 형식을 검사한다
        }
        if (explicitNull) throw OAuthText.fail(JwtException.Reason.INVALID_CLAIM, "oauth.err.claimType", name);
    }

    private static String string(JwtClaims claims, String name) throws JwtException {
        try {
            return claims.getString(name);
        } catch (IllegalArgumentException e) {
            throw OAuthText.fail(JwtException.Reason.INVALID_CLAIM, "oauth.err.claimType", name);
        }
    }

    /** 검증기 생성기. */
    public static final class Builder {
        private final boolean rfc9068;
        private final JwtVerifier.Builder jwt = JwtVerifier.builder();
        private boolean issuerSet;
        private boolean audienceSet;
        /** 마지막 types 호출의 값(정규화). null이면 기본(없음 또는 JWT). */
        private Set<String> typeRule;
        private final Set<String> requiredClaimNames = new LinkedHashSet<>();
        private final Map<String, String> requiredClaimValues = new LinkedHashMap<>();
        private String clientIdClaim;
        private String scopeClaim = "scope";
        private String rolesClaim = "roles";
        private boolean requirePermission;
        private final List<String> requiredScopes = new ArrayList<>();
        private final List<String> requiredRoles = new ArrayList<>();
        private final List<String> forbiddenClaims = new ArrayList<>();

        Builder(boolean rfc9068) {
            this.rfc9068 = rfc9068;
            if (rfc9068) {
                jwt.types("at+jwt").requireClaims(RFC9068_REQUIRED).requireIssuedAt(true);
                clientIdClaim = "client_id";
            }
        }

        /** @param issuer 신뢰하는 발급자(정확히 일치, 필수) @return this */
        public Builder issuer(String issuer) {
            jwt.issuer(OAuthText.require(issuer, "issuer"));
            issuerSet = true;
            return this;
        }

        /** @param audience 이 API의 식별자(토큰 aud에 포함, 필수) @return this */
        public Builder audience(String audience) {
            jwt.audience(OAuthText.require(audience, "audience"));
            audienceSet = true;
            return this;
        }

        /** @param key 발급자의 검증 키 @return this */
        public Builder key(JwtKey key) {
            jwt.key(key);
            return this;
        }

        /** @param keys 발급자의 검증 키 목록(예: Jwks.parse) @return this */
        public Builder keys(Collection<JwtKey> keys) {
            jwt.keys(keys);
            return this;
        }

        /**
         * 설정형 프로파일에서 허용할 헤더 typ(예: {@code JWT}). RFC 9068 프로파일은 {@code at+jwt}로 고정이라 바꿀 수 없다.
         *
         * @param allowed 값
         * @return this
         */
        public Builder types(String... allowed) {
            if (rfc9068) throw OAuthText.invalid("oauth.err.rfc9068Fixed", "types");
            jwt.types(allowed);
            Set<String> normalized = new LinkedHashSet<>();
            for (String value : allowed) {
                String lower = value.toLowerCase(Locale.ROOT);
                normalized.add(lower.startsWith("application/") ? lower.substring("application/".length()) : lower);
            }
            typeRule = normalized;   // JwtVerifier와 같이 마지막 호출이 앞선 값을 바꾼다
            return this;
        }

        /** @param names 있어야 하는 클레임(등록 클레임이 아닌 이름이면 토큰 종류 구분 조건, 누적) @return this */
        public Builder requireClaims(String... names) {
            jwt.requireClaims(names);
            requiredClaimNames.addAll(Arrays.asList(names));
            return this;
        }

        /** @param name 클레임 @param value 기대 문자열(예: Keycloak {@code typ}={@code Bearer}, Entra {@code ver}={@code 2.0}) @return this */
        public Builder requireClaimValue(String name, String value) {
            jwt.requireClaimValue(name, value);
            requiredClaimValues.put(name, value);
            return this;
        }

        /** @param names 있으면 거부할 클레임(예: ID Token 표지 {@code nonce}·{@code at_hash}, 누적) @return this */
        public Builder forbidClaims(String... names) {
            if (names == null) throw OAuthText.invalid("oauth.err.required", "names");
            for (String name : names) forbiddenClaims.add(OAuthText.require(name, "name"));
            return this;
        }

        /** @param name 클라이언트 ID 클레임(설정형만, 예: {@code azp}·{@code appid}; 지정하면 필수) @return this */
        public Builder clientIdClaim(String name) {
            if (rfc9068) throw OAuthText.invalid("oauth.err.rfc9068Fixed", "client_id");
            clientIdClaim = OAuthText.require(name, "clientIdClaim");
            return this;
        }

        /** @param name 공백 구분 위임 권한 클레임(기본 {@code scope}, Entra {@code scp}) @return this */
        public Builder scopeClaim(String name) {
            scopeClaim = OAuthText.require(name, "scopeClaim");
            return this;
        }

        /** @param name 문자열 배열 역할 클레임(기본 {@code roles}) @return this */
        public Builder rolesClaim(String name) {
            rolesClaim = OAuthText.require(name, "rolesClaim");
            return this;
        }

        /** @param required true면 권한 클레임(scope 또는 roles)이 비어 있는 토큰 거부(마지막 값이 적용) @return this */
        public Builder requirePermissionClaim(boolean required) {
            requirePermission = required;
            return this;
        }

        /** @param scopes 모두 있어야 하는 위임 권한(누적) @return this */
        public Builder requireScopes(String... scopes) {
            if (scopes == null) throw OAuthText.invalid("oauth.err.required", "scopes");
            for (String scope : scopes) {
                if (!OAuthText.validScope(OAuthText.require(scope, "scope"))) throw OAuthText.invalid("oauth.err.scopeFormat");
                requiredScopes.add(scope);
            }
            return this;
        }

        /** @param roles 모두 있어야 하는 역할(누적) @return this */
        public Builder requireRoles(String... roles) {
            if (roles == null) throw OAuthText.invalid("oauth.err.required", "roles");
            for (String role : roles) {
                if (!OAuthText.validIdentifier(OAuthText.require(role, "role"))) throw OAuthText.invalid("oauth.err.roleFormat");
                requiredRoles.add(role);
            }
            return this;
        }

        /** @param skew 시계 차 허용(0~300초) @return this */
        public Builder clockSkew(Duration skew) {
            jwt.clockSkew(skew);
            return this;
        }

        /** @param maxAge iat 기준 최대 나이 @return this */
        public Builder maxAge(Duration maxAge) {
            jwt.maxAge(maxAge);
            return this;
        }

        /** @param required 설정형 프로파일의 iat 필수 여부(RFC 9068은 항상 필수) @return this */
        public Builder requireIssuedAt(boolean required) {
            if (rfc9068 && !required) throw OAuthText.invalid("oauth.err.rfc9068Fixed", "iat");
            jwt.requireIssuedAt(required);
            return this;
        }

        /** @param reject 미래 iat 거부(기본 true) @return this */
        public Builder rejectFutureIssuedAt(boolean reject) {
            jwt.rejectFutureIssuedAt(reject);
            return this;
        }

        /** @param allow 소수 초 시간 허용(기본 false) @return this */
        public Builder allowFractionalTimes(boolean allow) {
            jwt.allowFractionalTimes(allow);
            return this;
        }

        /** @param clock 시계 @return this */
        public Builder clock(Clock clock) {
            jwt.clock(clock);
            return this;
        }

        /**
         * @return 검증기
         * @throws IllegalArgumentException 발급자·대상·키가 없거나, 설정형 프로파일에 ID Token 구분 조건이 없음
         */
        public AccessTokenVerifier build() {
            if (!issuerSet) throw OAuthText.invalid("oauth.err.required", "issuer");
            if (!audienceSet) throw OAuthText.invalid("oauth.err.required", "audience");
            if (!rfc9068 && !distinguishesTokenType()) throw OAuthText.invalid("oauth.err.discriminator");
            return new AccessTokenVerifier(this, jwt.build());
        }

        /**
         * 최종 설정에 ID Token 등과 구분할 조건이 있는지(호출 이력이 아니라 남은 값으로 판단). typ {@code JWT} 허용, 빈 목록, 해제한
         * 조건, 모든 JWT가 가질 수 있는 등록 클레임만 지정한 조건은 구분 조건이 아니다.
         */
        private boolean distinguishesTokenType() {
            if (typeRule != null && !typeRule.contains("jwt") && typeRule.stream().anyMatch(Builder::hasText)) return true;
            if (requiredClaimNames.stream().anyMatch(Builder::customClaim)) return true;
            for (Map.Entry<String, String> expected : requiredClaimValues.entrySet()) {
                if (customClaim(expected.getKey()) && hasText(expected.getValue())) return true;
            }
            return forbiddenClaims.stream().anyMatch(Builder::customClaim) || requirePermission
                    || requiredScopes.stream().anyMatch(Builder::hasText) || requiredRoles.stream().anyMatch(Builder::hasText);
        }

        private static boolean customClaim(String name) {
            return hasText(name) && !REGISTERED_CLAIMS.contains(name);
        }

        private static boolean hasText(String value) {
            return !value.trim().isEmpty();
        }
    }
}
