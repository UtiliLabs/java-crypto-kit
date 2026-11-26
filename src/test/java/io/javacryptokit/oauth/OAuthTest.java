package io.javacryptokit.oauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.javacryptokit.TestKeytool;
import io.javacryptokit.jwt.Jwt;
import io.javacryptokit.jwt.JwtException;
import io.javacryptokit.jwt.JwtKey;
import io.javacryptokit.security.Certificates;
import io.javacryptokit.security.Encoding;
import io.javacryptokit.security.SignatureAlgorithm;
import io.javacryptokit.security.Signatures;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * OAUTH-01: RFC 9068 생성·검증과 설정형 프로파일(ID Token·일반 JWT·다른 서비스 토큰 거부, 권한 정확 일치), RFC 7662 Introspection을
 * 로컬 HTTPS 시험 서버(keytool로 만든 시험용 CA·인증서)로 확인: 활성/비활성/클라이언트 인증 실패/HTTP 오류/리다이렉트/시간 초과/
 * 잘못된 JSON/크기 상한/신뢰하지 않는 인증서/호스트명 불일치, 요청 형식(POST·form·Basic, URL에 토큰 없음)과 문구의 비밀 비노출.
 * 실제 인증 서버(Keycloak) 연동은 최종 통합 시험 하니스에서 따로 확인한다.
 */
class OAuthTest {
    private static final Instant NOW = Instant.parse("2026-11-24T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String ISSUER = "https://auth.example.com";
    private static final String TOKEN = "dummy-opaque-token+/=한글";
    private static final char[] SECRET = "dummy-client-secret:&=".toCharArray();

    @TempDir
    static Path dir;
    private static HttpsServer server;
    private static HttpsServer wrongHostServer;
    private static ExecutorService executor;
    private static SSLContext clientTls;
    private static final Map<String, String> lastRequest = new ConcurrentHashMap<>();
    private static KeyPair signer;

    @BeforeAll
    static void startServers() throws Exception {
        signer = Signatures.generateRsaKeyPair(2048);
        Path good = Files.createDirectory(dir.resolve("good"));
        TestKeytool.caAndServer(good, "dns:localhost,ip:127.0.0.1");
        Path wrong = Files.createDirectory(dir.resolve("wrong"));
        TestKeytool.caAndServer(wrong, "dns:other.example");
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("good", Certificates.readFile(good.resolve("ca.pem")));
        trust.setCertificateEntry("wrong", Certificates.readFile(wrong.resolve("ca.pem")));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        clientTls = SSLContext.getInstance("TLS");
        clientTls.init(null, tmf.getTrustManagers(), null);
        executor = Executors.newCachedThreadPool();
        server = start(good.resolve("server.p12"));
        wrongHostServer = start(wrong.resolve("server.p12"));
    }

    @AfterAll
    static void stopServers() {
        if (server != null) server.stop(0);
        if (wrongHostServer != null) wrongHostServer.stop(0);
        if (executor != null) executor.shutdownNow();
    }

    private static HttpsServer start(Path keystore) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystore)) {
            ks.load(in, TestKeytool.STORE_PASS.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, TestKeytool.STORE_PASS.toCharArray());
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(kmf.getKeyManagers(), null, null);
        HttpsServer https = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        https.setHttpsConfigurator(new HttpsConfigurator(tls));
        https.setExecutor(executor);
        https.createContext("/active", json(200, "application/json", "{\"active\":true,\"scope\":\"orders.read orders.write\",\"client_id\":\"web\","
                + "\"sub\":\"u1\",\"exp\":4102444800,\"aud\":[\"orders-api\"],\"iss\":\"" + ISSUER + "\",\"username\":\"kim\"}"));
        https.createContext("/inactive", json(200, "application/json; charset=utf-8", "{\"active\":false,\"scope\":\"leak\"}"));
        https.createContext("/unauthorized", exchange -> {
            record(exchange);
            exchange.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"introspect\"");
            send(exchange, 401, "application/json", "{\"error\":\"invalid_client\"}");
        });
        https.createContext("/forbidden", json(403, "application/json", "{}"));
        https.createContext("/error", json(500, "text/plain", "boom " + TOKEN));
        https.createContext("/redirect", exchange -> {
            record(exchange);
            exchange.getResponseHeaders().add("Location", "https://attacker.example/introspect");
            send(exchange, 302, "text/plain", "");
        });
        https.createContext("/slow", exchange -> {
            record(exchange);
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            send(exchange, 200, "application/json", "{\"active\":true}");
        });
        https.createContext("/badjson", json(200, "application/json", "{\"active\":true,"));
        https.createContext("/activestring", json(200, "application/json", "{\"active\":\"true\"}"));
        https.createContext("/duplicate", json(200, "application/json", "{\"active\":false,\"active\":true}"));
        https.createContext("/badtype", json(200, "application/json", "{\"active\":true,\"exp\":\"tomorrow\"}"));
        https.createContext("/html", json(200, "text/html", "{\"active\":true}"));
        char[] big = new char[4000];
        Arrays.fill(big, 'x');
        https.createContext("/big", json(200, "application/json", "{\"active\":true,\"pad\":\"" + new String(big) + "\"}"));
        // Client Credentials token endpoint 모의 응답
        https.createContext("/token-ok", json(200, "application/json;charset=UTF-8",
                "{\"access_token\":\"dummy-at-123\",\"token_type\":\"bearer\",\"expires_in\":300,\"scope\":\"orders.read\",\"refresh_token\":\"dummy-rt\"}"));
        char[] tokenLimit = new char[16 * 1024];
        Arrays.fill(tokenLimit, 'x');
        String boundaryToken = new String(tokenLimit);
        https.createContext("/token-limit", json(200, "application/json",
                "{\"access_token\":\"" + boundaryToken + "\",\"token_type\":\"Bearer\"}"));
        https.createContext("/token-over-limit", json(200, "application/json",
                "{\"access_token\":\"" + boundaryToken + "x\",\"token_type\":\"Bearer\"}"));
        https.createContext("/token-noexpiry", json(200, "application/json", "{\"access_token\":\"dummy-at-456\",\"token_type\":\"Bearer\"}"));
        https.createContext("/token-invalid-client", json(401, "application/json",
                "{\"error\":\"invalid_client\",\"error_description\":\"dummy-description-with-" + TOKEN + "\"}"));
        https.createContext("/token-invalid-client-400", json(400, "application/json", "{\"error\":\"invalid_client\"}"));
        https.createContext("/token-invalid-scope", json(400, "application/json", "{\"error\":\"invalid_scope\"}"));
        https.createContext("/token-custom-error", json(400, "application/json", "{\"error\":\"custom_thing\"}"));
        https.createContext("/token-mac", json(200, "application/json", "{\"access_token\":\"a\",\"token_type\":\"mac\"}"));
        https.createContext("/token-negative", json(200, "application/json", "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":-1}"));
        https.createContext("/token-string-expiry", json(200, "application/json", "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":\"300\"}"));
        https.createContext("/token-empty", json(200, "application/json", "{\"access_token\":\"\",\"token_type\":\"Bearer\"}"));
        https.createContext("/token-duplicate", json(200, "application/json", "{\"access_token\":\"a\",\"access_token\":\"b\",\"token_type\":\"Bearer\"}"));
        https.start();
        return https;
    }

    private static HttpHandler json(int status, String type, String body) {
        return exchange -> {
            record(exchange);
            send(exchange, status, type, body);
        };
    }

    private static void record(HttpExchange exchange) throws IOException {
        lastRequest.put("method", exchange.getRequestMethod());
        lastRequest.put("query", String.valueOf(exchange.getRequestURI().getRawQuery()));
        lastRequest.put("contentType", String.valueOf(exchange.getRequestHeaders().getFirst("Content-Type")));
        lastRequest.put("authorization", String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        try (InputStream in = exchange.getRequestBody()) {
            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer)) != -1) body.write(buffer, 0, read);
        }
        lastRequest.put("body", new String(body.toByteArray(), StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange exchange, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", type);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
        exchange.close();
    }

    private static TokenIntrospector introspector(HttpsServer target, String path) {
        return TokenIntrospector.builder(URI.create("https://127.0.0.1:" + target.getAddress().getPort() + path))
                .clientSecretBasic("orders-api", SECRET).sslContext(clientTls)
                .readTimeout(Duration.ofMillis(800)).maxResponseBytes(2048).build();
    }

    private static IntrospectionException.Reason failure(TokenIntrospector introspector) {
        try {
            introspector.introspect(TOKEN);
        } catch (IntrospectionException e) {
            assertFalse(e.getMessage().contains(TOKEN) || e.getMessage().contains("dummy-client-secret"), "토큰·비밀 비노출");
            return e.getReason();
        }
        throw new AssertionError("실패해야 한다");
    }

    @Test
    void introspectionDistinguishesActiveInactiveAndFailures() throws Exception {
        IntrospectionResult active = introspector(server, "/active").introspect(TOKEN, "access_token");
        assertTrue(active.active());
        assertEquals(Arrays.asList("orders.read", "orders.write"), Arrays.asList(active.scopes().toArray()));
        assertEquals("web", active.clientId());
        assertEquals("kim", active.username());
        assertEquals(Arrays.asList("orders-api"), active.audience());
        assertEquals(Instant.ofEpochSecond(4102444800L), active.expiresAt());
        assertEquals("POST", lastRequest.get("method"));
        assertEquals("null", lastRequest.get("query"), "URL에 토큰을 넣지 않는다");
        assertEquals("application/x-www-form-urlencoded", lastRequest.get("contentType"));
        assertEquals("token=" + URLEncoder.encode(TOKEN, "UTF-8") + "&token_type_hint=access_token", lastRequest.get("body"));
        String expectedAuth = "Basic " + Encoding.BASE64.encode(("orders-api:" + URLEncoder.encode(new String(SECRET), "UTF-8")).getBytes(StandardCharsets.UTF_8));
        assertEquals(expectedAuth, lastRequest.get("authorization"), "client_secret_basic(form-urlencoding 후 Basic)");
        IntrospectionResult inactive = introspector(server, "/inactive").introspect(TOKEN);
        assertFalse(inactive.active());
        assertTrue(inactive.scopes().isEmpty(), "비활성이면 다른 값을 쓰지 않는다");
        assertNull(inactive.clientId());
        assertEquals(IntrospectionException.Reason.CLIENT_AUTH, failure(introspector(server, "/unauthorized")));
        assertEquals(IntrospectionException.Reason.CLIENT_AUTH, failure(introspector(server, "/forbidden")));
        assertEquals(IntrospectionException.Reason.HTTP_STATUS, failure(introspector(server, "/error")));
        assertEquals(IntrospectionException.Reason.REDIRECT, failure(introspector(server, "/redirect")));
        assertEquals(IntrospectionException.Reason.TIMEOUT, failure(introspector(server, "/slow")));
        for (String path : new String[] {"/badjson", "/activestring", "/duplicate", "/badtype", "/html"}) {
            assertEquals(IntrospectionException.Reason.INVALID_RESPONSE, failure(introspector(server, path)), path);
        }
        assertEquals(IntrospectionException.Reason.RESPONSE_TOO_LARGE, failure(introspector(server, "/big")));
    }

    @Test
    void introspectionKeepsCertificateTrustAndHostnameVerification() {
        TokenIntrospector untrusted = TokenIntrospector.builder(URI.create("https://127.0.0.1:" + server.getAddress().getPort() + "/active"))
                .clientSecretBasic("orders-api", SECRET).build();
        assertEquals(IntrospectionException.Reason.TLS, failure(untrusted), "JVM 기본 신뢰 저장소에 없는 시험용 CA");
        assertEquals(IntrospectionException.Reason.TLS, failure(introspector(wrongHostServer, "/active")), "신뢰하는 CA지만 호스트명 불일치");
        assertThrows(IllegalArgumentException.class, () -> TokenIntrospector.builder(URI.create("http://127.0.0.1/introspect")));
        assertThrows(IllegalArgumentException.class, () -> TokenIntrospector.builder(URI.create("https://user:pw@127.0.0.1/introspect")));
        assertThrows(IllegalArgumentException.class, () -> TokenIntrospector.builder(URI.create("https://127.0.0.1/i")).build(), "클라이언트 인증 필수");
        assertThrows(IllegalArgumentException.class, () -> introspector(server, "/active").introspect(""));
    }

    @Test
    void rfc9068TokensVerifyAndOtherTokenKindsAreRejected() throws Exception {
        JwtKey signing = JwtKey.rs256(signer.getPrivate()).withKeyId("as-1");
        AccessTokenVerifier verifier = AccessTokenVerifier.rfc9068().issuer(ISSUER).audience("orders-api")
                .key(JwtKey.rs256(signer.getPublic()).withKeyId("as-1")).requireScopes("orders.read").clock(CLOCK).build();
        String at = AccessTokens.builder(CLOCK).issuer(ISSUER).subject("user-1").audience("orders-api").clientId("web")
                .scopes("orders.read", "orders.write").expiresIn(Duration.ofMinutes(5)).sign(signing);
        AccessToken token = verifier.verify(at);
        assertEquals("user-1", token.subject());
        assertEquals("web", token.clientId());
        assertTrue(token.hasScope("orders.write"));
        assertFalse(token.hasScope("orders"), "부분 문자열로 승인하지 않음");
        assertEquals("at+jwt", token.jwt().header().getString("typ"));
        // typ: application/at+jwt(대소문자 무시)도 규격대로 허용
        String appType = Jwt.builder(CLOCK).type("Application/AT+JWT").issuer(ISSUER).subject("s").audience("orders-api").claim("client_id", "web")
                .claim("scope", "orders.read").randomJwtId().expiresIn(Duration.ofMinutes(1)).sign(signing);
        assertEquals("s", verifier.verify(appType).subject());
        // 일반 JWT(typ JWT)·ID Token은 Access Token이 아니다
        String plainJwt = Jwt.builder(CLOCK).issuer(ISSUER).subject("s").audience("orders-api").claim("client_id", "web").claim("scope", "orders.read")
                .randomJwtId().expiresIn(Duration.ofMinutes(1)).sign(signing);
        assertEquals(JwtException.Reason.TYPE, reason(verifier, plainJwt));
        String idToken = idToken(signing, "orders-api");
        assertEquals(JwtException.Reason.TYPE, reason(verifier, idToken));
        // 필수 클레임(jti) 누락, 권한 부족, 다른 서비스 대상
        String noJti = Jwt.builder(CLOCK).type("at+jwt").issuer(ISSUER).subject("s").audience("orders-api").claim("client_id", "web")
                .claim("scope", "orders.read").expiresIn(Duration.ofMinutes(1)).sign(signing);
        assertEquals(JwtException.Reason.MISSING_CLAIM, reason(verifier, noJti));
        String readonly = AccessTokens.builder(CLOCK).issuer(ISSUER).subject("s").audience("orders-api").clientId("web").scopes("orders.readonly")
                .expiresIn(Duration.ofMinutes(1)).sign(signing);
        assertEquals(JwtException.Reason.SCOPE, reason(verifier, readonly));
        String otherApi = AccessTokens.builder(CLOCK).issuer(ISSUER).subject("s").audience("billing-api").clientId("web").scopes("orders.read")
                .expiresIn(Duration.ofMinutes(1)).sign(signing);
        assertEquals(JwtException.Reason.AUDIENCE, reason(verifier, otherApi));
        assertThrows(IllegalArgumentException.class, () -> AccessTokenVerifier.rfc9068().types("JWT"));
        assertThrows(IllegalArgumentException.class, () -> AccessTokenVerifier.rfc9068().requireIssuedAt(false));
        assertThrows(IllegalArgumentException.class, () -> AccessTokens.builder().issuer(ISSUER).subject("s").audience("a").sign(signing), "필수 값");
        assertThrows(IllegalArgumentException.class, () -> AccessTokenVerifier.rfc9068().issuer(ISSUER).key(JwtKey.rs256(signer.getPublic())).build(),
                "대상 필수");
    }

    @Test
    void configurableProfilesNeedAnEffectiveFinalRule() {
        JwtKey key = JwtKey.rs256(signer.getPublic());
        AccessTokenVerifier.Builder profile = AccessTokenVerifier.profile().issuer(ISSUER).audience("orders-api").key(key);
        assertThrows(IllegalArgumentException.class, () -> profile.requireClaims().build());
        assertThrows(IllegalArgumentException.class, () -> profile.forbidClaims().build());
        assertThrows(IllegalArgumentException.class, () -> profile.requireScopes().build());
        assertThrows(IllegalArgumentException.class, () -> profile.requireRoles().build());
        assertThrows(IllegalArgumentException.class, () -> profile.requirePermissionClaim(true).requirePermissionClaim(false).build());
        profile.types("at+jwt").build();
        assertThrows(IllegalArgumentException.class, () -> profile.types("JWT").build());
        assertThrows(IllegalArgumentException.class, () -> profile.types("at+jwt", "application/JWT").build());
        assertThrows(IllegalArgumentException.class, () -> profile.forbidClaims(" ").build());
        assertThrows(IllegalArgumentException.class, () -> profile.requireClaims("iss", "sub").build());
        profile.requireClaimValue("kind", "access").build();
        assertThrows(IllegalArgumentException.class, () -> profile.requireClaimValue("kind", "").build());
        profile.requireScopes("orders.read").build();
    }

    @Test
    void bothClientsEnforceMillisecondTimeoutBounds() {
        URI endpoint = URI.create("https://localhost/");
        ClientCredentials.Builder client = ClientCredentials.builder(endpoint).clientSecretBasic("svc", SECRET);
        TokenIntrospector.Builder introspector = TokenIntrospector.builder(endpoint).clientSecretBasic("svc", SECRET);
        Duration min = Duration.ofMillis(1);
        client.connectTimeout(min).readTimeout(min).build();
        introspector.connectTimeout(min).readTimeout(min).build();
        Duration connectMax = Duration.ofSeconds(60);
        Duration readMax = Duration.ofSeconds(120);
        client.connectTimeout(connectMax).readTimeout(readMax).build();
        introspector.connectTimeout(connectMax).readTimeout(readMax).build();
        for (Duration bad : new Duration[] {Duration.ofMillis(-1), Duration.ZERO, Duration.ofNanos(1), min.minusNanos(1)}) {
            assertThrows(IllegalArgumentException.class, () -> client.connectTimeout(bad));
            assertThrows(IllegalArgumentException.class, () -> client.readTimeout(bad));
            assertThrows(IllegalArgumentException.class, () -> introspector.connectTimeout(bad));
            assertThrows(IllegalArgumentException.class, () -> introspector.readTimeout(bad));
        }
        assertThrows(IllegalArgumentException.class, () -> client.connectTimeout(connectMax.plusNanos(1)));
        assertThrows(IllegalArgumentException.class, () -> client.readTimeout(readMax.plusNanos(1)));
        assertThrows(IllegalArgumentException.class, () -> introspector.connectTimeout(connectMax.plusNanos(1)));
        assertThrows(IllegalArgumentException.class, () -> introspector.readTimeout(readMax.plusNanos(1)));
    }

    @Test
    void configurableProfilesCombineRulesAndRejectIdTokens() throws Exception {
        JwtKey signing = JwtKey.rs256(signer.getPrivate()).withKeyId("idp-1");
        JwtKey verifying = JwtKey.rs256(signer.getPublic()).withKeyId("idp-1");
        assertThrows(IllegalArgumentException.class, () -> AccessTokenVerifier.profile().issuer(ISSUER).audience("orders-api").key(verifying).build(),
                "ID Token 구분 조건이 없으면 만들지 않는다");
        // Entra 형태: typ JWT, scp(공백 구분)·roles, azp, ver 2.0
        AccessTokenVerifier entra = AccessTokenVerifier.profile().issuer(ISSUER).audience("orders-api").key(verifying)
                .types("JWT").scopeClaim("scp").clientIdClaim("azp").requireClaimValue("ver", "2.0").requirePermissionClaim(true)
                .clockSkew(Duration.ofSeconds(60)).clock(CLOCK).build();
        String delegated = Jwt.builder(CLOCK).issuer(ISSUER).subject("u").audience("orders-api").claim("azp", "web").claim("ver", "2.0")
                .claim("scp", "Orders.Read").expiresIn(Duration.ofMinutes(5)).sign(signing);
        AccessToken token = entra.verify(delegated);
        assertEquals("web", token.clientId());
        assertTrue(token.hasScope("Orders.Read"));
        String appOnly = Jwt.builder(CLOCK).issuer(ISSUER).subject("app").audience("orders-api").claim("azp", "batch").claim("ver", "2.0")
                .claim("roles", Arrays.asList("Orders.ReadAll")).expiresIn(Duration.ofMinutes(5)).sign(signing);
        assertTrue(entra.verify(appOnly).hasRole("Orders.ReadAll"));
        // 같은 키로 서명한 ID Token: 대상이 다르면 AUDIENCE, 대상이 같아도(같은 앱 등록) 권한 클레임이 없어 SCOPE, ver 없으면 MISSING
        assertEquals(JwtException.Reason.AUDIENCE, reason(entra, idToken(signing, "web-client")));
        String sameAudience = Jwt.builder(CLOCK).issuer(ISSUER).subject("u").audience("orders-api").claim("azp", "web").claim("ver", "2.0")
                .claim("nonce", "n-1").expiresIn(Duration.ofMinutes(5)).sign(signing);
        assertEquals(JwtException.Reason.SCOPE, reason(entra, sameAudience));
        // Keycloak 형태: typ 클레임 Bearer(액세스)/ID(ID Token), 금지 클레임
        AccessTokenVerifier keycloak = AccessTokenVerifier.profile().issuer(ISSUER).audience("orders-api").key(verifying)
                .requireClaimValue("typ", "Bearer").forbidClaims("at_hash").clientIdClaim("azp").clock(CLOCK).build();
        String kcAccess = Jwt.builder(CLOCK).issuer(ISSUER).subject("u").audience("orders-api").claim("typ", "Bearer").claim("azp", "web")
                .claim("scope", "openid profile").expiresIn(Duration.ofMinutes(5)).sign(signing);
        assertEquals("web", keycloak.verify(kcAccess).clientId());
        String kcId = Jwt.builder(CLOCK).issuer(ISSUER).subject("u").audience("orders-api").claim("typ", "ID").claim("azp", "web")
                .expiresIn(Duration.ofMinutes(5)).sign(signing);
        assertEquals(JwtException.Reason.INVALID_CLAIM, reason(keycloak, kcId));
        String withAtHash = Jwt.builder(CLOCK).issuer(ISSUER).subject("u").audience("orders-api").claim("typ", "Bearer").claim("azp", "web")
                .claim("at_hash", "x").expiresIn(Duration.ofMinutes(5)).sign(signing);
        assertEquals(JwtException.Reason.INVALID_CLAIM, reason(keycloak, withAtHash));
        String noAzp = Jwt.builder(CLOCK).issuer(ISSUER).subject("u").audience("orders-api").claim("typ", "Bearer")
                .expiresIn(Duration.ofMinutes(5)).sign(signing);
        assertEquals(JwtException.Reason.MISSING_CLAIM, reason(keycloak, noAzp));
        // 역할은 대소문자까지 정확히 일치
        AccessTokenVerifier admin = AccessTokenVerifier.profile().issuer(ISSUER).audience("orders-api").key(verifying).requireRoles("Admin").clock(CLOCK).build();
        String lower = Jwt.builder(CLOCK).issuer(ISSUER).subject("u").audience("orders-api").claim("roles", Arrays.asList("admin"))
                .expiresIn(Duration.ofMinutes(5)).sign(signing);
        assertEquals(JwtException.Reason.SCOPE, reason(admin, lower));
        // 다른 키(다른 발급 서버)로 서명한 토큰
        KeyPair other = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256);
        String foreign = Jwt.builder(CLOCK).issuer(ISSUER).subject("u").audience("orders-api").claim("typ", "Bearer").claim("azp", "web")
                .expiresIn(Duration.ofMinutes(5)).sign(JwtKey.es256(other.getPrivate()).withKeyId("idp-1"));
        assertEquals(JwtException.Reason.KEY_NOT_FOUND, reason(keycloak, foreign));
    }

    private static ClientCredentials client(HttpsServer target, String path, boolean post) {
        ClientCredentials.Builder builder = ClientCredentials.builder(URI.create("https://127.0.0.1:" + target.getAddress().getPort() + path))
                .sslContext(clientTls).readTimeout(Duration.ofMillis(800)).maxResponseBytes(2048).clock(CLOCK);
        return (post ? builder.clientSecretPost("svc a&b", SECRET) : builder.clientSecretBasic("svc a&b", SECRET)).build();
    }

    private static OAuthClientException.Reason tokenFailure(ClientCredentials client, String expectedOAuthError) {
        try {
            client.requestToken("orders.read");
        } catch (TokenRequestException e) {
            assertFalse(e.getMessage().contains(TOKEN) || e.getMessage().contains("dummy-client-secret") || e.getMessage().contains("description"),
                    "비밀·토큰·error_description 비노출");
            assertEquals(expectedOAuthError, e.getOAuthError());
            return e.getReason();
        }
        throw new AssertionError("실패해야 한다");
    }

    @Test
    void clientCredentialsRequestsTokensWithBasicOrPostAuthentication() throws Exception {
        TokenResponse token = client(server, "/token-ok", false).requestToken("orders.read", "orders.write");
        assertEquals("dummy-at-123", token.accessToken());
        assertEquals("Bearer", token.tokenType(), "token_type은 대소문자 구분 없이 Bearer");
        assertEquals("Bearer dummy-at-123", token.authorizationHeader());
        assertEquals(300, token.expiresIn().getAsLong());
        assertEquals(NOW.plusSeconds(300), token.expiresAt());
        assertEquals(new java.util.LinkedHashSet<>(Arrays.asList("orders.read", "orders.write")), token.requestedScopes());
        assertEquals(java.util.Collections.singleton("orders.read"), token.grantedScopes(), "요청과 응답 scope 차이를 숨기지 않음");
        assertTrue(token.scopeInResponse());
        assertFalse(token.toString().contains("dummy-at-123"));
        assertEquals("POST", lastRequest.get("method"));
        assertEquals("null", lastRequest.get("query"), "비밀을 URL에 넣지 않는다");
        assertEquals("grant_type=client_credentials&scope=orders.read+orders.write", lastRequest.get("body"));
        String expectedAuth = "Basic " + Encoding.BASE64.encode((URLEncoder.encode("svc a&b", "UTF-8") + ":"
                + URLEncoder.encode(new String(SECRET), "UTF-8")).getBytes(StandardCharsets.UTF_8));
        assertEquals(expectedAuth, lastRequest.get("authorization"), "client_secret_basic: 각각 form-urlencoding 후 Basic");
        TokenResponse posted = client(server, "/token-noexpiry", true).requestToken();
        assertEquals("grant_type=client_credentials&client_id=" + URLEncoder.encode("svc a&b", "UTF-8")
                + "&client_secret=" + URLEncoder.encode(new String(SECRET), "UTF-8"), lastRequest.get("body"));
        assertEquals("null", lastRequest.get("authorization"), "client_secret_post는 Authorization 헤더를 쓰지 않는다");
        assertFalse(posted.expiresIn().isPresent(), "expires_in이 없으면 만료를 지어내지 않음");
        assertEquals(null, posted.expiresAt());
        assertFalse(posted.scopeInResponse());
        assertThrows(IllegalArgumentException.class, () -> ClientCredentials.builder(URI.create("https://127.0.0.1/t"))
                .clientSecretBasic("a", SECRET).clientSecretPost("a", SECRET), "두 방식을 함께 쓰지 않음");
        assertThrows(IllegalArgumentException.class, () -> ClientCredentials.builder(URI.create("https://127.0.0.1/t")).build());
        assertThrows(IllegalArgumentException.class, () -> ClientCredentials.builder(URI.create("http://127.0.0.1/t")));
        assertThrows(IllegalArgumentException.class, () -> client(server, "/token-ok", false).requestToken("bad scope"));
    }

    @Test
    void clientCredentialsDistinguishesOAuthErrorsTransportAndBadResponses() {
        // 401은 JDK가 스트리밍 요청의 본문을 주지 않으므로 오류 코드를 추측하지 않고 CLIENT_AUTH(전역 Authenticator 자동 전송 방지)
        assertEquals(OAuthClientException.Reason.CLIENT_AUTH, tokenFailure(client(server, "/token-invalid-client", false), null));
        assertEquals(OAuthClientException.Reason.OAUTH_ERROR, tokenFailure(client(server, "/token-invalid-client-400", true), "invalid_client"));
        assertEquals(OAuthClientException.Reason.OAUTH_ERROR, tokenFailure(client(server, "/token-invalid-scope", true), "invalid_scope"));
        assertEquals(OAuthClientException.Reason.HTTP_STATUS, tokenFailure(client(server, "/token-custom-error", false), null), "표준이 아닌 오류 코드");
        assertEquals(OAuthClientException.Reason.HTTP_STATUS, tokenFailure(client(server, "/error", false), null));
        assertEquals(OAuthClientException.Reason.CLIENT_AUTH, tokenFailure(client(server, "/forbidden", false), null));
        assertEquals(OAuthClientException.Reason.REDIRECT, tokenFailure(client(server, "/redirect", false), null));
        assertEquals(OAuthClientException.Reason.TIMEOUT, tokenFailure(client(server, "/slow", false), null));
        assertEquals(OAuthClientException.Reason.RESPONSE_TOO_LARGE, tokenFailure(client(server, "/big", false), null));
        for (String path : new String[] {"/token-mac", "/token-negative", "/token-string-expiry", "/token-empty", "/token-duplicate", "/html", "/badjson"}) {
            assertEquals(OAuthClientException.Reason.INVALID_RESPONSE, tokenFailure(client(server, path, false), null), path);
        }
        assertEquals(OAuthClientException.Reason.TLS, tokenFailure(client(wrongHostServer, "/token-ok", false), null), "호스트명 불일치");
        ClientCredentials untrusted = ClientCredentials.builder(URI.create("https://127.0.0.1:" + server.getAddress().getPort() + "/token-ok"))
                .clientSecretBasic("svc", SECRET).build();
        assertEquals(OAuthClientException.Reason.TLS, tokenFailure(untrusted, null), "신뢰하지 않는 인증서");
    }

    private static String idToken(JwtKey key, String audience) {
        return Jwt.builder(CLOCK).issuer(ISSUER).subject("u").audience(audience).claim("nonce", "n-123").claim("at_hash", "abc")
                .claim("auth_time", NOW.getEpochSecond()).expiresIn(Duration.ofMinutes(5)).sign(key);
    }

    private static JwtException.Reason reason(AccessTokenVerifier verifier, String token) {
        try {
            verifier.verify(token);
        } catch (JwtException e) {
            return e.getReason();
        }
        throw new AssertionError("거부해야 한다");
    }
    @Test
    void independentCliUsesTheExistingHttpsBoundaryAndProtectsTokenOutput() throws Exception {
        Path fixture = Files.createTempDirectory(dir, "cli-");
        Path jar = io.javacryptokit.cli.CliHarness.configure(
                io.javacryptokit.TestJars.build(fixture.resolve("configured.jar")),
                io.javacryptokit.cli.CliHarness.ADMIN_PASSWORD);
        String adminFile = io.javacryptokit.cli.CliHarness.passFile(fixture, io.javacryptokit.cli.CliHarness.ADMIN_PASSWORD);
        Path secret = Files.write(fixture.resolve("client.pw"), new String(SECRET).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        if (secret.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(secret, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        }
        Path trustFile = fixture.resolve("trust.jks");
        KeyStore trust = KeyStore.getInstance("JKS");
        trust.load(null, null);
        trust.setCertificateEntry("root", Certificates.readFile(dir.resolve("good").resolve("ca.pem")));
        try (java.io.OutputStream out = Files.newOutputStream(trustFile)) {
            trust.store(out, TestKeytool.STORE_PASS.toCharArray());
        }
        java.util.List<String> tls = Arrays.asList("-Djavax.net.ssl.trustStore=" + trustFile,
                "-Djavax.net.ssl.trustStorePassword=" + TestKeytool.STORE_PASS, "-Djavax.net.ssl.trustStoreType=JKS");
        Path token = fixture.resolve("access.txt");
        io.javacryptokit.TestJars.Run issued = apiHttps(jar, tls, "token", "/token-ok", secret, adminFile,
                "--scope", "orders.read", "--out", token.toString());
        assertEquals(0, issued.exit, issued.err);
        assertEquals("dummy-at-123", new String(Files.readAllBytes(token), java.nio.charset.StandardCharsets.UTF_8).trim());
        assertTrue(issued.err.contains("expires_in"));
        assertFalse((issued.out + issued.err).contains("dummy-at-123"));
        Path postToken = fixture.resolve("post.txt");
        io.javacryptokit.TestJars.Run post = apiHttps(jar, tls, "token", "/token-ok", secret, adminFile,
                "--auth-method", "post", "--out", postToken.toString());
        assertEquals(0, post.exit, post.err);
        assertEquals("null", lastRequest.get("authorization"));
        assertTrue(lastRequest.get("body").contains("&client_secret="));
        assertFalse((post.out + post.err).contains("dummy-at-123"));
        Map<String, String> beforeRejectedOptions = new java.util.HashMap<>(lastRequest);
        Path invalidIntrospection = fixture.resolve("invalid-introspection.json");
        io.javacryptokit.TestJars.Run invalidOptions = apiHttps(jar, tls, "introspect", "/active", secret, adminFile,
                "--auth-method", "post", "--in", token.toString(), "--out", invalidIntrospection.toString());
        assertEquals(1, invalidOptions.exit, invalidOptions.err);
        assertTrue(invalidOptions.err.contains("USAGE"), invalidOptions.err);
        assertEquals(beforeRejectedOptions, lastRequest);
        assertFalse(Files.exists(invalidIntrospection));
        Path active = fixture.resolve("active.json");
        io.javacryptokit.TestJars.Run viewed = apiHttps(jar, tls, "introspect", "/active", secret, adminFile,
                "--in", token.toString(), "--token-type-hint", "access_token", "--out", active.toString());
        assertEquals(0, viewed.exit, viewed.err);
        assertTrue(new String(Files.readAllBytes(active), java.nio.charset.StandardCharsets.UTF_8).contains("\"active\":true"));
        Path inactive = fixture.resolve("inactive.json");
        assertEquals(0, apiHttps(jar, tls, "introspect", "/inactive", secret, adminFile,
                "--in", token.toString(), "--out", inactive.toString()).exit);
        assertEquals("{\"active\":false}", new String(Files.readAllBytes(inactive), java.nio.charset.StandardCharsets.UTF_8).trim());
        Path boundary = fixture.resolve("boundary-token.txt");
        io.javacryptokit.TestJars.Run atLimit = apiHttps(jar, tls, "token", "/token-limit", secret, adminFile,
                "--out", boundary.toString());
        assertEquals(0, atLimit.exit, atLimit.err);
        assertFalse(atLimit.err.contains("16 KiB"), atLimit.err);
        assertEquals(0, apiHttps(jar, tls, "introspect", "/active", secret, adminFile, "--in", boundary.toString(),
                "--out", fixture.resolve("boundary-status.json").toString()).exit);
        assertEquals("token=".length() + 16 * 1024, lastRequest.get("body").length());

        Path oversized = fixture.resolve("oversized-token.txt");
        io.javacryptokit.TestJars.Run issuedLarge = apiHttps(jar, tls, "token", "/token-over-limit", secret, adminFile,
                "--out", oversized.toString());
        assertEquals(0, issuedLarge.exit, issuedLarge.err);
        assertTrue(issuedLarge.err.contains("16 KiB") && issuedLarge.out.isEmpty(), issuedLarge.err);
        assertFalse(issuedLarge.err.contains("xxxxxxxx"));
        assertEquals(16 * 1024 + 2, Files.size(oversized));
        Map<String, String> beforeSizeCheck = new java.util.HashMap<>(lastRequest);
        Path oversizedResult = fixture.resolve("oversized-status.json");
        io.javacryptokit.TestJars.Run rejectedLarge = apiHttps(jar, tls, "introspect", "/active", secret, adminFile,
                "--in", oversized.toString(), "--out", oversizedResult.toString());
        assertEquals(1, rejectedLarge.exit);
        assertTrue(rejectedLarge.err.contains("16 KiB") && rejectedLarge.err.contains("64 KiB"), rejectedLarge.err);
        assertTrue(rejectedLarge.out.isEmpty());
        assertEquals(beforeSizeCheck, lastRequest);
        assertFalse(Files.exists(oversizedResult));
        Path rejected = fixture.resolve("rejected");
        io.javacryptokit.TestJars.Run denied = apiHttps(jar, tls, "token", "/token-invalid-client", secret, adminFile, "--out", rejected.toString());
        assertEquals(1, denied.exit);
        assertTrue(denied.err.contains("CLIENT_AUTH") && denied.err.contains("401"), denied.err);
        assertFalse(denied.err.contains(new String(SECRET)));
        assertFalse(Files.exists(rejected));
        assertTrue(apiHttps(jar, tls, "token", "/token-duplicate", secret, adminFile, "--out", rejected.toString()).err
                .contains("INVALID_RESPONSE"));
        assertTrue(apiHttps(jar, java.util.Collections.<String>emptyList(), "token", "/token-ok", secret, adminFile,
                "--out", rejected.toString()).err.contains("TLS"));
        assertTrue(apiHttps(jar, tls, "introspect", "/slow", secret, adminFile, "--read-timeout", "1",
                "--in", token.toString(), "--out", rejected.toString()).err.contains("TIMEOUT"));
        assertFalse(Files.exists(rejected));
    }

    private static io.javacryptokit.TestJars.Run apiHttps(Path jar, java.util.List<String> tls, String action, String endpoint,
                                                        Path secret, String adminFile, String... extra) throws Exception {
        java.util.List<String> cli = new java.util.ArrayList<>(Arrays.asList("api", "oauth", action,
                "--endpoint", "https://localhost:" + server.getAddress().getPort() + endpoint, "--client-id", "cli-test",
                "--client-secret-file", secret.toString(), "--admin-pass-file", adminFile, "--lang", "en"));
        cli.addAll(Arrays.asList(extra));
        return io.javacryptokit.TestJars.run(jar, tls, cli.toArray(new String[0]));
    }

}
