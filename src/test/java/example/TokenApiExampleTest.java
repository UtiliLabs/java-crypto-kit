package example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.jwt.JwtException;
import io.javacryptokit.oauth.OAuthClientException;
import io.javacryptokit.oauth.TokenRequestException;
import io.javacryptokit.security.Encoding;
import io.javacryptokit.security.Signatures;
import java.net.URI;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

/**
 * 사용자 가이드 13장 JWT·OAuth 예제({@link TokenApiExample})를 실제로 실행한다. 네트워크가 필요한 Introspection·Client Credentials
 * 예제는 닿지 않는 로컬 주소로 실패 처리 경로를 확인하고(실제 인증 서버 연동은 Docker 하니스의 Keycloak 시험), 로컬 HTTPS 모의 시험은
 * {@code OAuthTest}가 맡는다.
 */
class TokenApiExampleTest {
    @Test
    void jwtIssueVerifyAndRotation() throws Exception {
        KeyPair current = Signatures.generateRsaKeyPair(2048);
        KeyPair previous = Signatures.generateRsaKeyPair(2048);
        String token = TokenApiExample.issue(current.getPrivate());
        assertEquals("manager", TokenApiExample.verify(current.getPublic(), previous.getPublic(), token));
        assertEquals("https://auth.example.com", TokenApiExample.peekIssuer(token));
        KeyPair stranger = Signatures.generateRsaKeyPair(2048);
        assertThrows(JwtException.class, () -> TokenApiExample.verify(stranger.getPublic(), previous.getPublic(), token));
    }

    @Test
    void accessTokenExamples() throws Exception {
        KeyPair issuer = Signatures.generateRsaKeyPair(2048);
        String accessToken = TokenApiExample.issueAccessToken(issuer.getPrivate());
        assertTrue(TokenApiExample.canReadOrders(issuer.getPublic(), accessToken));
        assertFalse(TokenApiExample.canReadOrders(issuer.getPublic(), TokenApiExample.issue(issuer.getPrivate())), "일반 JWT는 Access Token이 아님");
        String jwks = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"2026-11\",\"use\":\"sig\",\"n\":\""
                + Encoding.BASE64_URL.encode(unsigned(((java.security.interfaces.RSAPublicKey) issuer.getPublic()).getModulus().toByteArray()))
                + "\",\"e\":\"AQAB\"}]}";
        assertEquals("AccessTokenVerifier", TokenApiExample.keycloakStyle("https://idp.example.com/realms/x", jwks).getClass().getSimpleName());
    }

    @Test
    void networkExamplesFailClosedWithoutAServer() {
        assertFalse(TokenApiExample.introspect(URI.create("https://127.0.0.1:9/introspect"), "dummy-secret".toCharArray(), "dummy-token"),
                "통신 실패를 활성으로 보지 않는다");
        TokenRequestException e = assertThrows(TokenRequestException.class,
                () -> TokenApiExample.partnerAuthorization(URI.create("https://127.0.0.1:9/token"), "dummy-secret".toCharArray()));
        assertEquals(OAuthClientException.Reason.NETWORK, e.getReason());
    }

    private static byte[] unsigned(byte[] value) {
        return value[0] == 0 ? java.util.Arrays.copyOfRange(value, 1, value.length) : value;
    }
}
