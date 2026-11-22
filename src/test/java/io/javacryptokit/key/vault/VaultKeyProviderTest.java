package io.javacryptokit.key.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.TestSupport;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.core.CryptoService;
import io.javacryptokit.key.KeyResolver;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Vault KV v2 키 공급원: 실제 TLS(HTTPS) 통신으로 정상·인증 실패·권한 부족·Secret 없음·삭제·필드·키 형식·TLS 오류·호스트 이름
 * 불일치·네트워크 장애·시간 초과·일시 장애 재시도·리다이렉트·캐시·토큰 미노출·내장 키 자동 전환 없음을 검증한다(모의 Vault 서버).
 */
class VaultKeyProviderTest {
    @TempDir
    static Path dir;
    private static TlsTestServer server;
    private static TlsTestServer wrongName;
    private static TlsTestServer.Certificate good;
    private static TlsTestServer.Certificate other;
    private static final byte[] KEY = new byte[32];
    private static final Map<String, AtomicInteger> HITS = new ConcurrentHashMap<>();

    @BeforeAll
    static void start() throws Exception {
        new SecureRandom().nextBytes(KEY);
        good = TlsTestServer.generate(dir, "vault", "localhost", "dns:localhost,ip:127.0.0.1");
        other = TlsTestServer.generate(dir, "wrong", "wrong.example", "dns:wrong.example");
        server = new TlsTestServer(good, exchange -> {
            String path = exchange.getRequestURI().getPath();
            String query = exchange.getRequestURI().getQuery();
            String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");
            HITS.computeIfAbsent(path + (query == null ? "" : "?" + query), k -> new AtomicInteger()).incrementAndGet();
            if (path.equals("/v1/auth/token/lookup-self")) {
                TlsTestServer.respond(exchange, "s.good".equals(token) || "s.limited".equals(token) ? 200 : 403, "{}");
                return;
            }
            if (!"s.good".equals(token)) {
                TlsTestServer.respond(exchange, 403, "{\"errors\":[\"permission denied\"]}");
                return;
            }
            String key = Base64.getEncoder().encodeToString(KEY);
            switch (path) {
                case "/v1/secret/data/app/prod":
                    if ("version=9".equals(query)) {
                        TlsTestServer.respond(exchange, 404, "{\"errors\":[]}");
                    } else {
                        TlsTestServer.respond(exchange, 200, "{\"data\":{\"data\":{\"key\":\"" + key + "\"},"
                                + "\"metadata\":{\"version\":3,\"deletion_time\":\"\",\"destroyed\":false}}}");
                    }
                    return;
                case "/v1/secret/data/app/deleted":
                    TlsTestServer.respond(exchange, 200, "{\"data\":{\"data\":null,\"metadata\":{\"version\":2,"
                            + "\"deletion_time\":\"2026-11-01T00:00:00Z\",\"destroyed\":false}}}");
                    return;
                case "/v1/secret/data/app/badkey":
                    TlsTestServer.respond(exchange, 200, "{\"data\":{\"data\":{\"key\":\"not-base64!\"},\"metadata\":{}}}");
                    return;
                case "/v1/secret/data/app/flaky":
                    if (HITS.get(path).get() == 1) {
                        TlsTestServer.respond(exchange, 503, "{\"errors\":[\"Vault is sealed\"]}");
                    } else {
                        TlsTestServer.respond(exchange, 200, "{\"data\":{\"data\":{\"key\":\"" + key + "\"},\"metadata\":{}}}");
                    }
                    return;
                case "/v1/secret/data/app/redirect":
                    exchange.getResponseHeaders().add("Location", "https://evil.example/v1/secret/data/app/prod");
                    TlsTestServer.respond(exchange, 307, "");
                    return;
                case "/v1/secret/data/app/slow":
                    try {
                        Thread.sleep(1500);
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                    TlsTestServer.respond(exchange, 200, "{}");
                    return;
                default:
                    TlsTestServer.respond(exchange, 404, "{\"errors\":[]}");
            }
        });
        wrongName = new TlsTestServer(other, exchange -> TlsTestServer.respond(exchange, 200, "{}"));
    }

    @AfterAll
    static void stop() {
        server.close();
        wrongName.close();
    }

    private static CryptoSettings settings(String token, String... extra) throws Exception {
        Path tokenFile = TestSupport.writeKeyFile(dir, "token-" + token, token);
        List<String> lines = new ArrayList<>(Arrays.asList("crypto.key.source=vault", "crypto.key.id=v01",
                "crypto.vault.url=https://localhost:" + server.port(), "crypto.vault.path=app/prod",
                "crypto.vault.token.file=" + TestSupport.propertiesPath(tokenFile),
                "crypto.vault.ca.file=" + TestSupport.propertiesPath(good.pem), "crypto.vault.timeout.ms=2000"));
        lines.addAll(Arrays.asList(extra));
        Path config = TestSupport.writeConfig(dir, "vault-" + System.nanoTime() + ".properties", lines.toArray(new String[0]));
        return TestSupport.isolatedSettings(config);
    }

    private static String failure(CryptoSettings settings) {
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> CryptoService.of(settings).encryptText("x".toCharArray()));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason(), ex.getMessage());
        assertFalse(ex.getMessage().contains("s.good") || ex.getMessage().contains("s.bad") || ex.getMessage().contains("s.limited"),
                "토큰을 메시지에 넣으면 안 된다");
        return ex.getMessage();
    }

    @Test
    void readsTheKeyOnceAndEncryptsWithIt() throws Exception {
        CryptoService service = CryptoService.of(settings("s.good"));
        int before = HITS.getOrDefault("/v1/secret/data/app/prod", new AtomicInteger()).get();
        String token = service.encryptText("dummy-db-pw".toCharArray());
        assertEquals("dummy-db-pw", service.decryptText(token));
        assertTrue(service.verify(token));
        assertEquals(KeyResolver.fingerprint(KEY), service.keyFingerprint());
        assertEquals(before + 1, HITS.get("/v1/secret/data/app/prod").get(), "서비스 인스턴스당 한 번만 조회(연결마다 조회하지 않음)");
        CryptoService.of(settings("s.good", "crypto.vault.ver=3")).encryptText("y".toCharArray());
        assertTrue(HITS.containsKey("/v1/secret/data/app/prod?version=3"), "버전 고정 요청");
    }

    @Test
    void authenticationPermissionAndMissingSecretAreToldApart() throws Exception {
        assertTrue(failure(settings("s.bad")).contains("인증을 거부"), "만료·폐기 토큰");
        assertTrue(failure(settings("s.limited")).contains("권한이 없습니다"), "유효 토큰 + 정책 부족");
        assertTrue(failure(settings("s.good", "crypto.vault.path=app/none")).contains("찾지 못했습니다"));
        assertTrue(failure(settings("s.good", "crypto.vault.ver=9")).contains("찾지 못했습니다"));
        assertTrue(failure(settings("s.good", "crypto.vault.path=app/deleted")).contains("삭제"));
        assertTrue(failure(settings("s.good", "crypto.vault.field=password")).contains("crypto.vault.field"));
        assertTrue(failure(settings("s.good", "crypto.vault.path=app/badkey")).contains("Base64"));
    }

    @Test
    void tlsIsAlwaysVerifiedAndRedirectsAreNotFollowed() throws Exception {
        // CA를 지정하지 않으면 JVM 기본 신뢰 저장소로 검증하므로 자체 서명 인증서는 거부된다(검증을 끌 수 없음).
        CryptoSettings untrusted = settings("s.good", "crypto.vault.ca.file=");
        assertTrue(failure(untrusted).contains("TLS"), "신뢰할 수 없는 인증서");
        CryptoSettings mismatch = settings("s.good", "crypto.vault.url=https://localhost:" + wrongName.port(),
                "crypto.vault.ca.file=" + TestSupport.propertiesPath(other.pem));
        assertTrue(failure(mismatch).contains("TLS"), "인증서 이름 불일치");
        assertTrue(failure(settings("s.good", "crypto.vault.path=app/redirect")).contains("리다이렉트"));
    }

    @Test
    void temporaryFailuresAreRetriedButNetworkAndTimeoutFailClosed() throws Exception {
        String token = CryptoService.of(settings("s.good", "crypto.vault.path=app/flaky")).encryptText("z".toCharArray());
        assertTrue(token.startsWith("ENC[v1:v01:"));
        assertEquals(2, HITS.get("/v1/secret/data/app/flaky").get(), "503 다음 재시도 1회로 성공");
        int closed;
        try (ServerSocket socket = new ServerSocket(0)) {
            closed = socket.getLocalPort();
        }
        assertTrue(failure(settings("s.good", "crypto.vault.url=https://localhost:" + closed)).contains("3회"), "연결 실패 3회 시도");
        long start = System.nanoTime();
        assertTrue(failure(settings("s.good", "crypto.vault.path=app/slow", "crypto.vault.timeout.ms=300")).contains("제한 시간"));
        assertTrue((System.nanoTime() - start) / 1_000_000 < 15000, "무한 대기 없음");
    }

    @Test
    void vaultFailureNeverFallsBackToTheBuiltInKey() throws Exception {
        // 같은 키ID로 JAR 내장(공개) 키 암호문을 만든 뒤, Vault가 실패하면 그 암호문이 복호화되면 안 된다.
        Path embedded = TestSupport.writeConfig(dir, "embedded-v01.properties", "crypto.key.source=embedded", "crypto.key.id=v01");
        String tokenWithBuiltInKey = CryptoService.of(TestSupport.isolatedSettings(embedded)).encryptText("x".toCharArray());
        CryptoSettings broken = settings("s.bad");
        CredentialCryptoException ex = assertThrows(CredentialCryptoException.class,
                () -> CryptoService.of(broken).decryptText(tokenWithBuiltInKey));
        assertEquals(CredentialCryptoException.Reason.KEY_SOURCE, ex.getReason());
    }

    @Test
    void tokenMustComeFromAFileOrEnvironmentVariable() throws Exception {
        Path config = TestSupport.writeConfig(dir, "env-token.properties", "crypto.key.source=vault", "crypto.key.id=v01",
                "crypto.vault.url=https://localhost:" + server.port(), "crypto.vault.path=app/prod",
                "crypto.vault.token.env=JCK_TEST_TOKEN_NOT_SET_7");
        assertTrue(failure(TestSupport.isolatedSettings(config)).contains("JCK_TEST_TOKEN_NOT_SET_7"));
        assertTrue(failure(settings("s.good with space")).contains("토큰 형식"), "헤더 주입 방지");
    }

    @Test
    void miniJsonIsStrict() {
        assertEquals("v", MiniJson.path(MiniJson.parse("{\"a\":{\"b\":\"v\"}}"), "a", "b"));
        assertEquals(3L, MiniJson.path(MiniJson.parse("{\"n\":3}"), "n"));
        assertEquals("\u00e9", MiniJson.parse("\"\\u00e9\""));
        for (String bad : new String[]{"{", "{\"a\":}", "[1,]", "{\"a\":1}x", "\"\u0001\"", "tru"}) {
            assertThrows(IllegalArgumentException.class, () -> MiniJson.parse(bad), bad);
        }
        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < 50; i++) deep.append('[');
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse(deep.toString()), "깊이 제한");
    }
}
