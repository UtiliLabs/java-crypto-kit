package io.javacryptokit.oauth;

import io.javacryptokit.jwt.JwtClaims;
import io.javacryptokit.security.Bytes;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import javax.net.ssl.SSLContext;

/**
 * <b>공개 API</b>: OAuth 2.0 Client Credentials Grant(RFC 6749 4.4) 토큰 발급 요청 클라이언트. 서버 간 API를 호출하기 전에, 호출
 * 애플리케이션이 신뢰하는 기존 인증 서버의 token endpoint에서 서비스 계정(기밀 클라이언트)용 Access Token을 받는다. 인증 서버
 * 기능·로그인·Authorization Code·Refresh Token 관리는 없다.
 *
 * <pre>{@code
 * ClientCredentials client = ClientCredentials.builder(URI.create("https://auth.example.com/oauth2/token"))
 *         .clientSecretBasic("orders-batch", clientSecret)   // char[]; 또는 clientSecretPost(명시 선택)
 *         .build();                                           // 한 번 만들어 재사용(스레드 안전)
 * TokenResponse token = client.requestToken("orders.read");  // 실패는 TokenRequestException
 * connection.setRequestProperty("Authorization", token.authorizationHeader());
 * }</pre>
 *
 * <ul>
 *   <li>요청: HTTPS {@code POST}, UTF-8 {@code application/x-www-form-urlencoded}, {@code grant_type=client_credentials}, 선택
 *       {@code scope}(공백 구분). 클라이언트 인증은 정확히 한 가지: {@code client_secret_basic}(ID·비밀을 각각 form-urlencoding 후
 *       Basic, 기본) 또는 {@code client_secret_post}(본문에 {@code client_id}·{@code client_secret}). 둘을 함께 쓰거나 실패 시 다른
 *       방식으로 바꿔 시도하지 않는다. 비밀을 URL에 넣지 않는다.</li>
 *   <li>응답: {@code access_token}(비어 있지 않은 문자열)·{@code token_type}({@code Bearer}만, 대소문자 무시) 필수,
 *       {@code expires_in}(0 이상 정수 초, 10년 이하)·{@code scope} 선택. 형식이 맞지 않으면 INVALID_RESPONSE.</li>
 *   <li>오류: 인증 서버의 OAuth 오류 응답(400 등)은 OAUTH_ERROR + 표준 코드({@code invalid_client}·{@code invalid_scope}·
 *       {@code unauthorized_client} 등, {@code error_description}은 전달하지 않음). 401·403은 CLIENT_AUTH다(요청을 고정 길이 스트리밍으로
 *       보내 JVM 전역 {@code Authenticator}가 다른 자격 증명을 자동으로 보내지 않게 하며, 이때 JDK는 401 본문을 주지 않으므로 오류 코드를
 *       추측하지 않는다). 그 밖에 HTTP_STATUS·REDIRECT·TIMEOUT·TLS·NETWORK·RESPONSE_TOO_LARGE({@link TokenRequestException}).</li>
 *   <li>HTTPS 처리(신뢰·호스트명 검증 유지, 리다이렉트 안 따라감, 연결 5초·읽기 10초·응답 64KiB 기본)는 {@link TokenIntrospector}와 같다.
 *       자동 재시도·토큰 캐시·갱신을 하지 않는다. 토큰 공유·재발급 시점·인증 서버 장애 처리는 애플리케이션 몫이다.</li>
 * </ul>
 */
public final class ClientCredentials {
    private static final long MAX_EXPIRES_IN = 10L * 366 * 24 * 3600;
    private static final Set<String> OAUTH_ERRORS = new HashSet<>(Arrays.asList("invalid_request", "invalid_client", "invalid_grant",
            "unauthorized_client", "unsupported_grant_type", "invalid_scope"));

    private final OAuthHttp.Settings settings;
    private final String authorization;
    private final String postCredentials;
    private final Clock clock;

    private ClientCredentials(Builder b) {
        this.settings = b.settings.copy();
        this.authorization = b.authorization;
        this.postCredentials = b.postCredentials;
        this.clock = b.clock;
    }

    /**
     * @param tokenEndpoint 신뢰하는 HTTPS token endpoint(설정에서만 받는다. 응답·토큰 안의 URL을 따라가지 않는다)
     * @return 생성기
     */
    public static Builder builder(URI tokenEndpoint) {
        return new Builder(tokenEndpoint);
    }

    /**
     * scope 없이 요청한다(인증 서버의 기본 scope).
     *
     * @return 발급받은 토큰
     * @throws TokenRequestException 발급 실패(사유 구분)
     */
    public TokenResponse requestToken() throws TokenRequestException {
        return requestToken(new String[0]);
    }

    /**
     * @param scopes 요청할 scope(각각 공백·{@code "}·{@code \} 없는 출력 가능 ASCII)
     * @return 발급받은 토큰
     * @throws TokenRequestException 발급 실패(사유 구분)
     */
    public TokenResponse requestToken(String... scopes) throws TokenRequestException {
        Set<String> requested = new LinkedHashSet<>();
        for (String scope : scopes == null ? new String[0] : scopes) requested.add(checkScope(scope));
        StringBuilder form = new StringBuilder("grant_type=client_credentials");
        if (!requested.isEmpty()) form.append("&scope=").append(OAuthHttp.form(String.join(" ", requested)));
        if (postCredentials != null) form.append('&').append(postCredentials);
        OAuthHttp.Response response;
        try {
            response = OAuthHttp.post(settings, Bytes.utf8(form.toString()), authorization);
        } catch (OAuthHttp.Failure f) {
            throw failure(f.reason, f.messageKey(), f.status, null);
        }
        Instant receivedAt = clock.instant();
        int status = response.status;
        if (status >= 300 && status < 400) throw failure(OAuthClientException.Reason.REDIRECT, "oauth.err.redirect", status, null);
        if (status != 200) throw errorResponse(response);
        if (!response.isJson()) throw failure(OAuthClientException.Reason.INVALID_RESPONSE, "oauth.err.response", status, null);
        try {
            JwtClaims claims = response.json();
            String accessToken = claims.getString("access_token");
            String tokenType = claims.getString("token_type");
            if (accessToken == null || accessToken.isEmpty()) throw failure(OAuthClientException.Reason.INVALID_RESPONSE, "oauth.err.accessToken", status, null);
            if (tokenType == null || !"bearer".equalsIgnoreCase(tokenType)) {
                throw failure(OAuthClientException.Reason.INVALID_RESPONSE, "oauth.err.tokenType", status, null);
            }
            Long expiresIn = claims.getLong("expires_in");
            if (expiresIn != null && (expiresIn < 0 || expiresIn > MAX_EXPIRES_IN)) {
                throw failure(OAuthClientException.Reason.INVALID_RESPONSE, "oauth.err.expiresIn", status, null);
            }
            String scope = claims.getString("scope");
            return new TokenResponse(accessToken, expiresIn, receivedAt, Collections.unmodifiableSet(requested), split(scope), scope != null);
        } catch (IllegalArgumentException e) {
            throw failure(OAuthClientException.Reason.INVALID_RESPONSE, "oauth.err.response", status, null);
        }
    }

    /** 200이 아닌 응답: 표준 OAuth 오류 코드만 꺼내고(설명 문구는 버림) 나머지는 상태로 구분한다. */
    private static TokenRequestException errorResponse(OAuthHttp.Response response) {
        int status = response.status;
        if (response.isJson()) {
            try {
                String error = response.json().getString("error");
                if (error != null && OAUTH_ERRORS.contains(error)) return failure(OAuthClientException.Reason.OAUTH_ERROR, "oauth.err.oauthError", status, error);
            } catch (IllegalArgumentException ignored) {
                // 형식이 깨진 오류 응답은 아래 상태 코드로 구분한다.
            }
        }
        if (status == 401 || status == 403) return failure(OAuthClientException.Reason.CLIENT_AUTH, "oauth.err.clientAuth", status, null);
        return failure(OAuthClientException.Reason.HTTP_STATUS, "oauth.err.status", status, null);
    }

    private static Set<String> split(String scope) {
        Set<String> out = new LinkedHashSet<>();
        if (scope != null) {
            for (String part : scope.split(" ")) {
                if (!part.isEmpty()) out.add(part);
            }
        }
        return Collections.unmodifiableSet(out);
    }

    private static String checkScope(String scope) {
        if (scope == null || scope.isEmpty()) throw OAuthText.invalid("oauth.err.scopeFormat");
        for (int i = 0; i < scope.length(); i++) {
            char c = scope.charAt(i);
            if (c < 0x21 || c > 0x7e || c == '"' || c == '\\') throw OAuthText.invalid("oauth.err.scopeFormat");
        }
        return scope;
    }

    private static TokenRequestException failure(OAuthClientException.Reason reason, String key, int status, String oauthError) {
        return new TokenRequestException(reason, OAuthText.get(key, oauthError != null ? oauthError : String.valueOf(status)), status, oauthError);
    }

    @Override
    public String toString() {
        return "ClientCredentials[" + settings.endpoint.getHost() + ", " + (postCredentials != null ? "client_secret_post" : "client_secret_basic") + "]";
    }

    /** 클라이언트 생성기. 클라이언트 인증 방식을 정확히 하나 정해야 한다. */
    public static final class Builder {
        private final OAuthHttp.Settings settings;
        private String authorization;
        private String postCredentials;
        private Clock clock = Clock.systemUTC();

        Builder(URI endpoint) {
            this.settings = new OAuthHttp.Settings(endpoint);
        }

        /**
         * {@code client_secret_basic}(기본 권장).
         *
         * @param clientId     클라이언트 ID
         * @param clientSecret 클라이언트 비밀(헤더 값으로만 보관, 호출자 배열은 호출자가 지운다)
         * @return this
         */
        public Builder clientSecretBasic(String clientId, char[] clientSecret) {
            checkOne(clientId, clientSecret);
            this.authorization = OAuthHttp.basic(clientId, clientSecret);
            return this;
        }

        /**
         * {@code client_secret_post}(인증 서버가 본문 방식만 받을 때 명시적으로 선택).
         *
         * @param clientId     클라이언트 ID
         * @param clientSecret 클라이언트 비밀
         * @return this
         */
        public Builder clientSecretPost(String clientId, char[] clientSecret) {
            checkOne(clientId, clientSecret);
            this.postCredentials = "client_id=" + OAuthHttp.form(clientId) + "&client_secret=" + OAuthHttp.form(new String(clientSecret));
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

        /** @param context 사설 CA 등 신뢰 설정(호스트명 검증은 JDK 기본 유지) @return this */
        public Builder sslContext(SSLContext context) {
            settings.sslContext(context);
            return this;
        }

        /** @param clock 응답 수신 시각·만료 계산 시계(기본 시스템 UTC) @return this */
        public Builder clock(Clock clock) {
            if (clock == null) throw OAuthText.invalid("oauth.err.required", "clock");
            this.clock = clock;
            return this;
        }

        /**
         * @return 클라이언트
         * @throws IllegalArgumentException 클라이언트 인증 방식이 없음
         */
        public ClientCredentials build() {
            if (authorization == null && postCredentials == null) throw OAuthText.invalid("oauth.err.required", "clientSecretBasic/clientSecretPost");
            return new ClientCredentials(this);
        }

        private void checkOne(String clientId, char[] clientSecret) {
            if (authorization != null || postCredentials != null) throw OAuthText.invalid("oauth.err.oneAuth");
            OAuthText.require(clientId, "clientId");
            if (clientSecret == null || clientSecret.length == 0) throw OAuthText.invalid("oauth.err.required", "clientSecret");
        }
    }
}
