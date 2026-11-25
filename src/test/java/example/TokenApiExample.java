package example;

import io.javacryptokit.jwt.Jwks;
import io.javacryptokit.jwt.Jwt;
import io.javacryptokit.jwt.JwtException;
import io.javacryptokit.jwt.JwtKey;
import io.javacryptokit.jwt.JwtVerifier;
import io.javacryptokit.jwt.UnverifiedJwt;
import io.javacryptokit.jwt.VerifiedJwt;
import io.javacryptokit.oauth.AccessToken;
import io.javacryptokit.oauth.AccessTokenVerifier;
import io.javacryptokit.oauth.AccessTokens;
import io.javacryptokit.oauth.ClientCredentials;
import io.javacryptokit.oauth.IntrospectionException;
import io.javacryptokit.oauth.IntrospectionResult;
import io.javacryptokit.oauth.TokenIntrospector;
import io.javacryptokit.oauth.TokenRequestException;
import io.javacryptokit.oauth.TokenResponse;
import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.List;

/**
 * 사용자 가이드 13장(JWT·OAuth Access Token·Introspection·Client Credentials)의 예제와 같은 코드다. 공개 API만 쓰며
 * {@code TokenApiExampleTest}가 실행해 확인한다(Introspection은 네트워크가 필요하므로 객체 구성까지만 시험).
 */
public final class TokenApiExample {
    private TokenApiExample() { }

    /** 서버 A: 배포받은 개인키로 JWT를 발급한다. */
    public static String issue(PrivateKey signingKey) {
        // 예제: TokenApiExample.issue
        JwtKey key = JwtKey.rs256(signingKey).withKeyId("2026-11");       // 각 서버가 키를 새로 만들지 않는다
        return Jwt.builder()
                .issuer("https://auth.example.com").subject("user-1").audience("orders-api")
                .expiresIn(Duration.ofMinutes(10)).randomJwtId()
                .claim("role", "manager")
                .sign(key);                                               // header.payload.signature
    }

    /** 서버 B·C: 공개키로 검증한다(키 교체 기간에는 이전·새 kid를 함께 등록). */
    public static String verify(PublicKey current, PublicKey previous, String token) throws JwtException {
        // 예제: TokenApiExample.verify
        JwtVerifier verifier = JwtVerifier.builder()
                .key(JwtKey.rs256(current).withKeyId("2026-11"))
                .key(JwtKey.rs256(previous).withKeyId("2026-05"))
                .issuer("https://auth.example.com").audience("orders-api")
                .clockSkew(Duration.ofSeconds(30))                        // 서버 간 시계 차(기본 0초, 최대 300초)
                .build();                                                 // 한 번 만들어 재사용(스레드 안전)
        VerifiedJwt jwt = verifier.verify(token);                         // 실패하면 JwtException(getReason)
        return jwt.claims().getString("role");
    }

    /** 미검증 분석: 어떤 검증기를 쓸지 고를 때만(인증에 쓰지 않는다). */
    public static String peekIssuer(String token) throws JwtException {
        // 예제: TokenApiExample.peekIssuer
        UnverifiedJwt peek = Jwt.parseUnverified(token);                  // 서명을 확인하지 않음
        return peek.claims().issuer();                                    // 이 값으로 인증하지 말고 검증기 선택에만 쓴다
    }

    /** RFC 9068 Access Token 발급(자체 인증 서버·시험용). */
    public static String issueAccessToken(PrivateKey signingKey) {
        // 예제: TokenApiExample.issueAccessToken
        return AccessTokens.builder()
                .issuer("https://auth.example.com").subject("user-1").audience("orders-api")
                .clientId("web-portal").scopes("orders.read", "orders.write")
                .expiresIn(Duration.ofMinutes(5))
                .sign(JwtKey.rs256(signingKey).withKeyId("2026-11"));     // typ: at+jwt, jti·iat 자동
    }

    /** 리소스 서버: RFC 9068 Access Token을 검증하고 권한을 확인한다. */
    public static boolean canReadOrders(PublicKey issuerKey, String bearer) {
        // 예제: TokenApiExample.canReadOrders
        AccessTokenVerifier verifier = AccessTokenVerifier.rfc9068()
                .issuer("https://auth.example.com").audience("orders-api")
                .key(JwtKey.rs256(issuerKey).withKeyId("2026-11"))
                .requireScopes("orders.read")                             // 정확한 이름(부분 문자열 아님)
                .build();
        try {
            AccessToken token = verifier.verify(bearer);
            return token.hasScope("orders.read");                         // 업무 권한·폐기 여부는 앱이 추가로 판단
        } catch (JwtException e) {
            return false;                                                 // e.getReason(): TYPE·AUDIENCE·EXPIRED·SCOPE ...
        }
    }

    /** typ=JWT를 쓰는 인증 서버(예: Keycloak 기본 설정)용 설정형 프로파일. JWKS는 앱이 신뢰 경로로 받은 문자열. */
    public static AccessTokenVerifier keycloakStyle(String issuer, String jwksJson) {
        // 예제: TokenApiExample.keycloakStyle
        List<JwtKey> keys = Jwks.parse(jwksJson, issuer);                 // 네트워크 조회 없음, 발급자에 키를 묶음
        return AccessTokenVerifier.profile()
                .issuer(issuer).audience("orders-api").keys(keys)
                .requireClaimValue("typ", "Bearer")                       // Access Token(Bearer)과 ID Token(ID) 구분
                .clientIdClaim("azp")
                .clockSkew(Duration.ofSeconds(60))
                .build();
    }

    /** Introspection(Opaque Token): 활성·비활성과 통신 실패를 구분한다. */
    public static boolean introspect(URI endpoint, char[] clientSecret, String opaqueToken) {
        // 예제: TokenApiExample.introspect
        TokenIntrospector introspector = TokenIntrospector.builder(endpoint)   // https만, 리다이렉트 안 따라감
                .clientSecretBasic("orders-api", clientSecret)
                .build();                                                  // 한 번 만들어 재사용
        try {
            IntrospectionResult result = introspector.introspect(opaqueToken, "access_token");
            return result.active() && result.scopes().contains("orders.read");
        } catch (IntrospectionException e) {
            // 인증 서버 통신·응답 문제(e.getReason()): 토큰을 유효하다고 보지 않고 일시 오류(예: 503)로 처리한다.
            return false;
        }
    }

    /** Client Credentials: 서비스 계정 토큰을 받아 다른 API 호출에 Bearer로 쓴다. */
    public static String partnerAuthorization(URI tokenEndpoint, char[] clientSecret) throws TokenRequestException {
        // 예제: TokenApiExample.partnerAuthorization
        ClientCredentials client = ClientCredentials.builder(tokenEndpoint)
                .clientSecretBasic("orders-batch", clientSecret)          // 또는 clientSecretPost(인증 서버가 요구할 때)
                .build();                                                  // 한 번 만들어 재사용
        TokenResponse token = client.requestToken("orders.read");         // 실패: TokenRequestException(getReason·getOAuthError)
        // 토큰 재사용·만료 전 재발급 시점은 애플리케이션이 정한다(token.expiresAt()이 null이면 서버가 만료를 알려 주지 않은 것).
        return token.authorizationHeader();                               // "Bearer ..." → 호출할 API의 Authorization 헤더
    }
}
