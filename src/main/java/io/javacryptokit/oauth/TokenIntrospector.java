package io.javacryptokit.oauth;

import io.javacryptokit.jwt.JwtClaims;
import io.javacryptokit.security.Bytes;
import java.net.URI;
import java.time.Duration;
import javax.net.ssl.SSLContext;

/**
 * <b>공개 API</b>: RFC 7662 OAuth 2.0 Token Introspection 클라이언트. 내용을 해석할 수 없는(Opaque) 접근 토큰의 상태를 호출자가 정한
 * 인증 서버 엔드포인트에 묻는다. 토큰을 JWT로 해석하지 않으며, 조회 실패 때 JWT 검증으로 대신하지 않는다.
 *
 * <pre>{@code
 * TokenIntrospector introspector = TokenIntrospector.builder(URI.create("https://auth.example.com/oauth2/introspect"))
 *         .clientSecretBasic("orders-api", clientSecret)   // char[]; 객체가 Authorization 헤더 값으로 보관
 *         .build();                                         // 한 번 만들어 재사용(스레드 안전)
 * IntrospectionResult result = introspector.introspect(opaqueToken);   // 통신 실패는 IntrospectionException
 * if (!result.active() || !result.scopes().contains("orders.read")) { ... 거부 ... }
 * }</pre>
 *
 * <ul>
 *   <li>요청: HTTPS {@code POST}, {@code application/x-www-form-urlencoded} 본문 {@code token}(+{@code token_type_hint}). 토큰·비밀을
 *       URL에 넣지 않는다. 클라이언트 인증은 {@code client_secret_basic}(RFC 6749 2.3.1: ID·비밀을 form-urlencoding 후 Basic).</li>
 *   <li>TLS: JVM 기본 신뢰 저장소 또는 주입한 {@link SSLContext}로 인증서를 검증하고, <b>호스트명 검증은 항상 JDK 기본</b>을 쓴다
 *       (끄는 기능 없음). {@code http://}·사용자 정보가 든 URI는 거부, 리다이렉트는 따라가지 않는다.</li>
 *   <li>제한: 연결 기본 5초(최대 60초)·읽기 10초(최대 120초)·응답 64KiB(최대 1MiB). 응답은 {@code application/json}이어야 하며
 *       엄격한 UTF-8·JSON(중복 멤버 거부)으로 읽고 {@code active}는 boolean이어야 한다.</li>
 *   <li>결과 구분: 비활성 = {@link IntrospectionResult#active()} false, 통신·응답 문제 = {@link IntrospectionException}(사유 구분).
 *       토큰 캐시·공유 DB·로그를 두지 않는다(토큰·비밀·응답을 기록하지 않음). HTTPS 처리는 {@link ClientCredentials}와 같은 구현이다.</li>
 * </ul>
 */
public final class TokenIntrospector {
    /** 응답 최대 크기 상한. */
    public static final int MAX_RESPONSE_LIMIT = OAuthHttp.MAX_RESPONSE_LIMIT;
    private static final int MAX_TOKEN_LENGTH = 16 * 1024;

    private final OAuthHttp.Settings settings;
    private final String authorization;

    private TokenIntrospector(Builder b) {
        this.settings = b.settings.copy();
        this.authorization = b.authorization;
    }

    /**
     * @param endpoint 신뢰하는 HTTPS Introspection 엔드포인트(설정에서만 받는다. 토큰·클레임의 URL을 쓰지 않는다)
     * @return 생성기
     */
    public static Builder builder(URI endpoint) {
        return new Builder(endpoint);
    }

    /**
     * @param token 조회할 토큰
     * @return 결과(활성/비활성)
     * @throws IntrospectionException 통신·응답 문제(비활성과 구분)
     */
    public IntrospectionResult introspect(String token) throws IntrospectionException {
        return introspect(token, null);
    }

    /**
     * @param token         조회할 토큰
     * @param tokenTypeHint 토큰 종류 힌트(예: {@code access_token}, 없으면 null)
     * @return 결과(활성/비활성)
     * @throws IntrospectionException 통신·응답 문제(비활성과 구분)
     */
    public IntrospectionResult introspect(String token, String tokenTypeHint) throws IntrospectionException {
        if (token == null || token.isEmpty() || token.length() > MAX_TOKEN_LENGTH) throw OAuthText.invalid("oauth.err.token", MAX_TOKEN_LENGTH);
        if (tokenTypeHint != null && !tokenTypeHint.matches("[A-Za-z0-9_]{1,64}")) throw OAuthText.invalid("oauth.err.hint");
        byte[] form = Bytes.utf8("token=" + OAuthHttp.form(token)
                + (tokenTypeHint == null ? "" : "&token_type_hint=" + OAuthHttp.form(tokenTypeHint)));
        OAuthHttp.Response response;
        try {
            response = OAuthHttp.post(settings, form, authorization);
        } catch (OAuthHttp.Failure f) {
            throw failure(f.reason, f.messageKey(), f.status);
        }
        int status = response.status;
        if (status >= 300 && status < 400) throw failure(OAuthClientException.Reason.REDIRECT, "oauth.err.redirect", status);
        if (status == 401 || status == 403) throw failure(OAuthClientException.Reason.CLIENT_AUTH, "oauth.err.clientAuth", status);
        if (status != 200) throw failure(OAuthClientException.Reason.HTTP_STATUS, "oauth.err.status", status);
        if (!response.isJson()) throw failure(OAuthClientException.Reason.INVALID_RESPONSE, "oauth.err.response", status);
        JwtClaims claims;
        try {
            claims = response.json();
        } catch (IllegalArgumentException e) {
            throw failure(OAuthClientException.Reason.INVALID_RESPONSE, "oauth.err.response", status);
        }
        Boolean active;
        try {
            active = claims.getBoolean("active");
        } catch (IllegalArgumentException e) {
            active = null;
        }
        if (active == null) throw failure(OAuthClientException.Reason.INVALID_RESPONSE, "oauth.err.active", status);
        if (!active) return new IntrospectionResult(false, JwtClaims.parse("{\"active\":false}"));
        try {
            for (String name : new String[] {"scope", "client_id", "username", "token_type", "sub", "iss", "jti"}) claims.getString(name);
            for (String name : new String[] {"exp", "iat", "nbf"}) claims.getInstant(name);
            claims.audience();
        } catch (IllegalArgumentException e) {
            throw failure(OAuthClientException.Reason.INVALID_RESPONSE, "oauth.err.response", status);
        }
        return new IntrospectionResult(true, claims);
    }

    private static IntrospectionException failure(OAuthClientException.Reason reason, String key, int status) {
        return new IntrospectionException(reason, OAuthText.get(key, status), status);
    }

    @Override
    public String toString() {
        return "TokenIntrospector[" + settings.endpoint.getHost() + "]";
    }

    /** Introspector 생성기. */
    public static final class Builder {
        private final OAuthHttp.Settings settings;
        private String authorization;

        Builder(URI endpoint) {
            this.settings = new OAuthHttp.Settings(endpoint);
        }

        /**
         * @param clientId     이 리소스 서버의 클라이언트 ID
         * @param clientSecret 클라이언트 비밀(Authorization 헤더 값으로만 보관, 호출자 배열은 호출자가 지운다)
         * @return this
         */
        public Builder clientSecretBasic(String clientId, char[] clientSecret) {
            OAuthText.require(clientId, "clientId");
            if (clientSecret == null || clientSecret.length == 0) throw OAuthText.invalid("oauth.err.required", "clientSecret");
            this.authorization = OAuthHttp.basic(clientId, clientSecret);
            return this;
        }

        /** @param timeout 연결 시간 제한(1밀리초~60초) @return this */
        public Builder connectTimeout(Duration timeout) {
            settings.connectTimeout(timeout);
            return this;
        }

        /** @param timeout 읽기 시간 제한(1밀리초~120초) @return this */
        public Builder readTimeout(Duration timeout) {
            settings.readTimeout(timeout);
            return this;
        }

        /** @param bytes 응답 최대 크기(1KiB~1MiB) @return this */
        public Builder maxResponseBytes(int bytes) {
            settings.maxResponseBytes(bytes);
            return this;
        }

        /**
         * 사설 CA 등 신뢰할 인증서를 정한 TLS 설정(신뢰 관리자를 끄는 설정을 넣지 않는다). 호스트명 검증은 계속 JDK 기본이다.
         *
         * @param context TLS 설정
         * @return this
         */
        public Builder sslContext(SSLContext context) {
            settings.sslContext(context);
            return this;
        }

        /**
         * @return Introspector
         * @throws IllegalArgumentException 클라이언트 인증이 없음
         */
        public TokenIntrospector build() {
            if (authorization == null) throw OAuthText.invalid("oauth.err.required", "clientSecretBasic");
            return new TokenIntrospector(this);
        }
    }
}
