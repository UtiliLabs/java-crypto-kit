package io.javacryptokit.oauth;

import io.javacryptokit.jwt.Jwt;
import io.javacryptokit.jwt.JwtKey;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

/**
 * <b>공개 API</b>: RFC 9068 JWT Access Token 생성(자체 인증 서버·시험·서버 간 발급용). 헤더 {@code typ: at+jwt}와 필수 클레임
 * iss·exp·aud·sub·client_id·iat·jti를 항상 넣는다({@code jti}는 기본 256비트 난수, {@code iat}는 현재 시각). 비대칭 서명(RS256·
 * ES256)을 권장하며, RFC 9068을 지원하는 검증기는 RS256을 반드시 지원한다. 토큰 엔드포인트·Refresh Token·폐기 기능은 없다.
 *
 * <pre>{@code
 * String accessToken = AccessTokens.builder()
 *         .issuer("https://auth.example.com").subject("user-1").audience("orders-api")
 *         .clientId("web-portal").scopes("orders.read", "orders.write")
 *         .expiresIn(Duration.ofMinutes(5))
 *         .sign(JwtKey.rs256(privateKey).withKeyId("2026-11"));
 * }</pre>
 */
public final class AccessTokens {
    private AccessTokens() { }

    /** @return 시스템 UTC 시계 생성기 */
    public static Builder builder() {
        return new Builder(Clock.systemUTC());
    }

    /**
     * @param clock 발급 시각 시계
     * @return 생성기
     */
    public static Builder builder(Clock clock) {
        if (clock == null) throw OAuthText.invalid("oauth.err.required", "clock");
        return new Builder(clock);
    }

    /** Access Token 생성기(한 번 쓰고 버린다). */
    public static final class Builder {
        private final Jwt.Builder jwt;
        private boolean issuer;
        private boolean subject;
        private boolean audience;
        private boolean clientId;
        private boolean lifetime;
        private boolean jwtId;

        Builder(Clock clock) {
            this.jwt = Jwt.builder(clock).type("at+jwt");
        }

        /** @param value 발급자 @return this */
        public Builder issuer(String value) {
            jwt.issuer(OAuthText.require(value, "iss"));
            issuer = true;
            return this;
        }

        /** @param value 주체(사용자 ID, 클라이언트 자격 흐름이면 클라이언트 ID) @return this */
        public Builder subject(String value) {
            jwt.subject(OAuthText.require(value, "sub"));
            subject = true;
            return this;
        }

        /** @param values 대상 API 식별자 @return this */
        public Builder audience(String... values) {
            jwt.audience(values);
            audience = true;
            return this;
        }

        /** @param value 요청한 클라이언트 ID @return this */
        public Builder clientId(String value) {
            jwt.claim("client_id", OAuthText.require(value, "client_id"));
            clientId = true;
            return this;
        }

        /** @param scopes 허용 권한(공백으로 이어 {@code scope} 클레임에 넣는다; 이름에 공백 불가) @return this */
        public Builder scopes(String... scopes) {
            if (scopes == null || scopes.length == 0) throw OAuthText.invalid("oauth.err.required", "scope");
            StringBuilder joined = new StringBuilder();
            for (String scope : scopes) {
                if (OAuthText.require(scope, "scope").indexOf(' ') >= 0) throw OAuthText.invalid("oauth.err.scopeFormat");
                if (joined.length() > 0) joined.append(' ');
                joined.append(scope);
            }
            jwt.claim("scope", joined.toString());
            return this;
        }

        /** @param values 역할({@code roles} 문자열 배열) @return this */
        public Builder roles(List<String> values) {
            jwt.claim("roles", values);
            return this;
        }

        /** @param value 유효 기간(1초 이상, 짧게 권장) @return this */
        public Builder expiresIn(Duration value) {
            jwt.expiresIn(value);
            lifetime = true;
            return this;
        }

        /** @param value 토큰 ID(지정하지 않으면 256비트 보안 난수) @return this */
        public Builder jwtId(String value) {
            jwt.jwtId(OAuthText.require(value, "jti"));
            jwtId = true;
            return this;
        }

        /** @param name 업무 클레임 @param value 문자열 @return this */
        public Builder claim(String name, String value) {
            jwt.claim(checkName(name), value);
            return this;
        }

        /** @param name 업무 클레임 @param value 정수 @return this */
        public Builder claim(String name, long value) {
            jwt.claim(checkName(name), value);
            return this;
        }

        /** @param name 업무 클레임 @param value 논리 값 @return this */
        public Builder claim(String name, boolean value) {
            jwt.claim(checkName(name), value);
            return this;
        }

        /**
         * @param key 발급자의 서명 키
         * @return {@code typ: at+jwt} compact JWS
         * @throws IllegalArgumentException 필수 값(iss·sub·aud·client_id·만료) 누락
         */
        public String sign(JwtKey key) {
            if (!issuer || !subject || !audience || !clientId || !lifetime) throw OAuthText.invalid("oauth.err.atRequired");
            if (!jwtId) jwt.randomJwtId();
            return jwt.sign(key);
        }

        private static String checkName(String name) {
            if ("client_id".equals(name) || "scope".equals(name) || "roles".equals(name)) throw OAuthText.invalid("oauth.err.reserved", name);
            return name;
        }
    }
}
