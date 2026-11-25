package io.javacryptokit.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.security.Encoding;
import io.javacryptokit.security.Hmac;
import io.javacryptokit.security.PemKeys;
import io.javacryptokit.security.SignatureAlgorithm;
import io.javacryptokit.security.Signatures;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;

/**
 * JWT-01: RFC 7515 A.1(HS256)·A.3(ES256) 벡터와 독립 구현(Python cryptography)이 만든 HS256·RS256·ES256 토큰·JWKS 검증, 생성 →
 * 검증, 그리고 알고리즘 혼동·none·kid·중복 JSON·crit·typ·시간·대상·발급자·크기·Base64URL 정규형·키 교체·발급자 결합 부정 시험.
 */
class JwtTest {
    private static final Instant NOW = Instant.parse("2026-11-24T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String RFC_PAYLOAD = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

    static Properties vectors() throws IOException {
        Properties properties = new Properties();
        try (Reader reader = new InputStreamReader(JwtTest.class.getResourceAsStream("independent-vectors.properties"), StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    private static JwtException.Reason reason(JwtVerifier verifier, String token) {
        try {
            verifier.verify(token);
        } catch (JwtException e) {
            assertFalse(e.getMessage().contains(token), "토큰 원문을 문구에 넣지 않는다");
            return e.getReason();
        }
        throw new AssertionError("검증이 실패해야 한다");
    }

    @Test
    void rfc7515AppendixVectorsVerify() throws Exception {
        Clock at2011 = Clock.fixed(Instant.ofEpochSecond(1300819380L - 60), ZoneOffset.UTC);
        byte[] a1Key = Encoding.BASE64_URL.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        String a1 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." + RFC_PAYLOAD + ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        VerifiedJwt jwt = JwtVerifier.builder().key(JwtKey.hs256(a1Key)).clock(at2011).build().verify(a1);
        assertEquals("joe", jwt.claims().issuer());
        assertEquals(Boolean.TRUE, jwt.claims().getBoolean("http://example.com/is_root"));
        assertEquals(JwtException.Reason.EXPIRED, reason(JwtVerifier.builder().key(JwtKey.hs256(a1Key)).clock(CLOCK).build(), a1));
        String a3 = "eyJhbGciOiJFUzI1NiJ9." + RFC_PAYLOAD
                + ".DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
        JwtKey a3Key = JwtKey.es256(PemKeys.readPublicKey(vectors().getProperty("rfc7515.a3.spki").replace('|', '\n')));
        assertEquals(JwtAlgorithm.ES256, JwtVerifier.builder().key(a3Key).clock(at2011).build().verify(a3).algorithm());
    }

    @Test
    void tokensFromAnIndependentImplementationAndItsJwksVerify() throws Exception {
        Properties p = vectors();
        List<JwtKey> keys = Jwks.parse(p.getProperty("py.jwks"), "https://py.example");
        assertEquals(2, keys.size(), "암호화용(use=enc) 키는 건너뛴다");
        JwtVerifier verifier = JwtVerifier.builder().keys(keys).issuer("https://py.example").audience("orders-api").clock(CLOCK).build();
        assertEquals("user-py", verifier.verify(p.getProperty("py.rs256.token")).claims().subject());
        assertEquals("py-ec", verifier.verify(p.getProperty("py.es256.token")).keyId());
        byte[] hsKey = new byte[32];
        for (int i = 0; i < 32; i++) hsKey[i] = (byte) i;
        JwtVerifier hs = JwtVerifier.builder().key(JwtKey.hs256(hsKey)).audience("orders-api").clock(CLOCK).build();
        assertEquals("orders.read", hs.verify(p.getProperty("py.hs256.token")).claims().getString("scope"));
        // PEM 공개키로도 같은 토큰 검증
        JwtVerifier pem = JwtVerifier.builder().key(JwtKey.rs256(PemKeys.readPublicKey(p.getProperty("py.rsa.spki").replace('|', '\n'))).withKeyId("py-rsa"))
                .audience("orders-api").clock(CLOCK).build();
        assertEquals(JwtAlgorithm.RS256, pem.verify(p.getProperty("py.rs256.token")).algorithm());
    }

    @Test
    void createThenVerifyForEveryAlgorithmWithKeyRotation() throws Exception {
        KeyPair rsaOld = Signatures.generateRsaKeyPair(2048);
        KeyPair rsaNew = Signatures.generateRsaKeyPair(2048);
        KeyPair ec = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256);
        byte[] secret = Hmac.generateKey();
        JwtKey[] signing = {JwtKey.rs256(rsaOld.getPrivate()).withKeyId("rsa-2026-05"), JwtKey.rs256(rsaNew.getPrivate()).withKeyId("rsa-2026-11"),
            JwtKey.es256(ec.getPrivate()).withKeyId("ec-1"), JwtKey.hs256(secret).withKeyId("hs-1")};
        JwtVerifier verifier = JwtVerifier.builder()
                .key(JwtKey.rs256(rsaOld.getPublic()).withKeyId("rsa-2026-05"))
                .key(JwtKey.rs256(rsaNew.getPublic()).withKeyId("rsa-2026-11"))
                .key(JwtKey.es256(ec.getPublic()).withKeyId("ec-1"))
                .key(JwtKey.hs256(secret).withKeyId("hs-1"))
                .issuer("https://auth.example.com").audience("orders-api").requireClaims("sub").clock(CLOCK).build();
        for (JwtKey key : signing) {
            String token = Jwt.builder(CLOCK).issuer("https://auth.example.com").subject("user-1").audience("orders-api", "billing-api")
                    .expiresIn(Duration.ofMinutes(10)).randomJwtId().claim("roles", Arrays.asList("admin", "user"))
                    .claim("tenant", "t-1").claim("level", 3).claim("active", true).sign(key);
            VerifiedJwt jwt = verifier.verify(token);
            assertEquals(key.keyId(), jwt.keyId());
            assertEquals(Arrays.asList("orders-api", "billing-api"), jwt.claims().audience());
            assertEquals(NOW.plusSeconds(600), jwt.claims().expiresAt());
            assertEquals(NOW, jwt.claims().issuedAt());
            assertEquals(Arrays.asList("admin", "user"), jwt.claims().getStringList("roles"));
            assertEquals(Long.valueOf(3), jwt.claims().getLong("level"));
            assertThrows(IllegalArgumentException.class, () -> jwt.claims().getLong("tenant"), "형식 변환 없음");
            assertEquals("JWT", jwt.header().getString("typ"));
        }
        // 이전 키를 검증기에서 빼면 그 키로 만든 토큰은 거부(키 교체 완료)
        JwtVerifier rotated = JwtVerifier.builder().key(JwtKey.rs256(rsaNew.getPublic()).withKeyId("rsa-2026-11"))
                .issuer("https://auth.example.com").audience("orders-api").clock(CLOCK).build();
        String old = Jwt.builder(CLOCK).issuer("https://auth.example.com").audience("orders-api").expiresIn(Duration.ofMinutes(1)).sign(signing[0]);
        assertEquals(JwtException.Reason.KEY_NOT_FOUND, reason(rotated, old));
    }

    @Test
    void algorithmConfusionNoneKidAndHeaderAttacksAreRejected() throws Exception {
        KeyPair rsa = Signatures.generateRsaKeyPair(2048);
        JwtVerifier rsOnly = JwtVerifier.builder().key(JwtKey.rs256(rsa.getPublic()).withKeyId("k1")).anyAudience().requireExpiration(false).clock(CLOCK).build();
        String payload = b64("{\"sub\":\"attacker\"}");
        // none
        assertEquals(JwtException.Reason.UNSUPPORTED, reason(rsOnly, b64("{\"alg\":\"none\"}") + "." + payload + ".AA"));
        assertEquals(JwtException.Reason.MALFORMED, reason(rsOnly, b64("{\"alg\":\"none\"}") + "." + payload + "."), "빈 서명 구간");
        // RS256 공개키(SPKI 바이트)를 HMAC 비밀로 쓴 HS256 위조: 검증기는 HS256 키가 없으므로 거부
        String forgedInput = b64("{\"alg\":\"HS256\",\"kid\":\"k1\"}") + "." + payload;
        String forged = forgedInput + "." + Encoding.BASE64_URL.encode(Hmac.of(rsa.getPublic().getEncoded()).sign(forgedInput.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(JwtException.Reason.KEY_NOT_FOUND, reason(rsOnly, forged));
        // 모르는 kid, 헤더 crit·b64·enc·zip, 중첩 JWT, alg 형식
        String sig = ".c2ln";
        assertEquals(JwtException.Reason.KEY_NOT_FOUND, reason(rsOnly, b64("{\"alg\":\"RS256\",\"kid\":\"other\"}") + "." + payload + sig));
        for (String header : new String[] {"{\"alg\":\"RS256\",\"crit\":[\"exp\"]}", "{\"alg\":\"RS256\",\"b64\":false}",
            "{\"alg\":\"RS256\",\"enc\":\"A256GCM\"}", "{\"alg\":\"RS256\",\"zip\":\"DEF\"}", "{\"alg\":\"RS256\",\"cty\":\"JWT\"}",
            "{\"alg\":\"RS512\"}", "{\"alg\":\"rs256\"}", "{\"alg\":\"PS256\"}"}) {
            assertEquals(JwtException.Reason.UNSUPPORTED, reason(rsOnly, b64(header) + "." + payload + sig), header);
        }
        assertEquals(JwtException.Reason.MALFORMED, reason(rsOnly, b64("{\"alg\":1}") + "." + payload + sig));
        // 중복 멤버(마지막 값 채택 금지)
        assertEquals(JwtException.Reason.MALFORMED, reason(rsOnly, b64("{\"alg\":\"RS256\",\"alg\":\"none\"}") + "." + payload + sig));
        // 구간 수·패딩·정규형·크기
        assertEquals(JwtException.Reason.MALFORMED, reason(rsOnly, "a.b"));
        assertEquals(JwtException.Reason.UNSUPPORTED, reason(rsOnly, "a.b.c.d.e"), "JWE");
        assertEquals(JwtException.Reason.MALFORMED, reason(rsOnly, b64("{\"alg\":\"RS256\"}") + "=." + payload + sig));
        char[] huge = new char[Jose.MAX_TOKEN_LENGTH + 1];
        Arrays.fill(huge, 'a');
        assertEquals(JwtException.Reason.MALFORMED, reason(rsOnly, new String(huge)));
        // jku·x5u·jwk 헤더는 무시(신뢰·조회하지 않음): 서명이 맞지 않으면 그대로 실패
        String withJku = b64("{\"alg\":\"RS256\",\"kid\":\"k1\",\"jku\":\"https://attacker.example/jwks\"}") + "." + payload + sig;
        assertEquals(JwtException.Reason.SIGNATURE, reason(rsOnly, withJku));
    }

    @Test
    void signatureCanonicalFormAndEs256DerAreRejected() throws Exception {
        KeyPair ec = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256);
        JwtVerifier verifier = JwtVerifier.builder().key(JwtKey.es256(ec.getPublic())).anyAudience().clock(CLOCK).build();
        String token = Jwt.builder(CLOCK).expiresIn(Duration.ofMinutes(1)).sign(JwtKey.es256(ec.getPrivate()));
        verifier.verify(token);
        String[] parts = token.split("\\.");
        String input = parts[0] + "." + parts[1];
        byte[] der = Signatures.sign(SignatureAlgorithm.ECDSA_P256_SHA256, ec.getPrivate(), input.getBytes(StandardCharsets.US_ASCII));
        assertEquals(JwtException.Reason.SIGNATURE, reason(verifier, input + "." + Encoding.BASE64_URL.encode(der)), "ES256에 DER 서명은 거부");
        assertEquals(JwtException.Reason.SIGNATURE, reason(verifier, input + "." + Encoding.BASE64_URL.encode(new byte[64])), "r=s=0");
        // 서명 구간의 비정규 Base64URL(마지막 문자 남는 비트 변경)
        String last = parts[2];
        char c = last.charAt(last.length() - 1);
        String mutated = last.substring(0, last.length() - 1) + (char) (c == 'A' ? 'B' : c - 1);
        JwtException.Reason r = reason(verifier, input + "." + mutated);
        assertTrue(r == JwtException.Reason.MALFORMED || r == JwtException.Reason.SIGNATURE, r.name());
    }

    @Test
    void timeAudienceIssuerAndClaimPolicies() throws Exception {
        byte[] secret = Hmac.generateKey();
        JwtKey key = JwtKey.hs256(secret);
        JwtVerifier strict = JwtVerifier.builder().key(key).issuer("iss-A").audience("api").clock(CLOCK).build();
        assertEquals(JwtException.Reason.MISSING_CLAIM, reason(strict, Jwt.builder(CLOCK).issuer("iss-A").audience("api").sign(key)), "exp 기본 필수");
        assertEquals(JwtException.Reason.EXPIRED, reason(strict, Jwt.builder(CLOCK).issuer("iss-A").audience("api").expiresAt(NOW).sign(key)), "exp = 현재");
        assertEquals("iss-A", strict.verify(Jwt.builder(CLOCK).issuer("iss-A").audience("api").expiresAt(NOW.plusSeconds(1)).sign(key)).claims().issuer());
        assertEquals(JwtException.Reason.NOT_YET_VALID, reason(strict, Jwt.builder(CLOCK).issuer("iss-A").audience("api").expiresIn(Duration.ofHours(1))
                .notBefore(NOW.plusSeconds(1)).sign(key)));
        assertEquals(JwtException.Reason.ISSUED_IN_FUTURE, reason(strict, Jwt.builder(CLOCK).issuer("iss-A").audience("api")
                .issuedAt(NOW.plusSeconds(1)).expiresAt(NOW.plusSeconds(600)).sign(key)), "미래 iat 기본 거부(오차 0)");
        JwtVerifier skewed = JwtVerifier.builder().key(key).issuer("iss-A").audience("api").clockSkew(Duration.ofSeconds(30)).clock(CLOCK).build();
        skewed.verify(Jwt.builder(CLOCK).issuer("iss-A").audience("api").issuedAt(NOW.plusSeconds(20)).expiresAt(NOW.plusSeconds(600)).sign(key));
        assertEquals(JwtException.Reason.ISSUED_IN_FUTURE, reason(skewed, Jwt.builder(CLOCK).issuer("iss-A").audience("api")
                .issuedAt(NOW.plusSeconds(31)).expiresAt(NOW.plusSeconds(600)).sign(key)));
        JwtVerifier lenientIat = JwtVerifier.builder().key(key).issuer("iss-A").audience("api").rejectFutureIssuedAt(false).clock(CLOCK).build();
        lenientIat.verify(Jwt.builder(CLOCK).issuer("iss-A").audience("api").issuedAt(NOW.plusSeconds(100)).expiresAt(NOW.plusSeconds(600)).sign(key));
        JwtVerifier aged = JwtVerifier.builder().key(key).issuer("iss-A").audience("api").maxAge(Duration.ofMinutes(5)).clock(CLOCK).build();
        assertEquals(JwtException.Reason.TOO_OLD, reason(aged, Jwt.builder(CLOCK).issuer("iss-A").audience("api")
                .issuedAt(NOW.minusSeconds(301)).expiresAt(NOW.plusSeconds(600)).sign(key)));
        assertEquals(JwtException.Reason.MISSING_CLAIM, reason(aged, Jwt.builder(CLOCK).issuer("iss-A").audience("api").issuedAt(null)
                .expiresAt(NOW.plusSeconds(600)).sign(key)), "maxAge는 iat 필수");
        assertEquals(JwtException.Reason.ISSUER, reason(strict, Jwt.builder(CLOCK).issuer("iss-B").audience("api").expiresIn(Duration.ofMinutes(1)).sign(key)));
        assertEquals(JwtException.Reason.AUDIENCE, reason(strict, Jwt.builder(CLOCK).issuer("iss-A").audience("other").expiresIn(Duration.ofMinutes(1)).sign(key)));
        JwtVerifier noAudience = JwtVerifier.builder().key(key).clock(CLOCK).build();
        assertEquals(JwtException.Reason.AUDIENCE, reason(noAudience, Jwt.builder(CLOCK).audience("api").expiresIn(Duration.ofMinutes(1)).sign(key)),
                "대상 정책 없이 aud 있는 토큰은 거부");
        noAudience.verify(Jwt.builder(CLOCK).expiresIn(Duration.ofMinutes(1)).sign(key));
        // 시간 클레임 형식: 소수 초는 기본 거부, 옵션으로 허용
        String fractional = hs(secret, "{\"alg\":\"HS256\"}", "{\"exp\":" + (NOW.getEpochSecond() + 60) + ".5}");
        assertEquals(JwtException.Reason.INVALID_CLAIM, reason(noAudience, fractional));
        JwtVerifier.builder().key(key).allowFractionalTimes(true).clock(CLOCK).build().verify(fractional);
        assertEquals(JwtException.Reason.INVALID_CLAIM, reason(noAudience, hs(secret, "{\"alg\":\"HS256\"}", "{\"exp\":\"" + NOW.getEpochSecond() + "\"}")));
        assertEquals(JwtException.Reason.MALFORMED, reason(noAudience, hs(secret, "{\"alg\":\"HS256\"}", "{\"exp\":1e400}")), "무한대가 되는 수");
        assertEquals(JwtException.Reason.INVALID_CLAIM, reason(noAudience, hs(secret, "{\"alg\":\"HS256\"}", "{\"exp\":-5}")), "음수 시각");
        assertEquals(JwtException.Reason.MALFORMED, reason(noAudience, hs(secret, "{\"alg\":\"HS256\"}", "{\"exp\":1,\"exp\":2}")), "중복 클레임");
        // typ 정책
        JwtVerifier typed = JwtVerifier.builder().key(key).types("at+jwt").anyAudience().clock(CLOCK).build();
        assertEquals(JwtException.Reason.TYPE, reason(typed, Jwt.builder(CLOCK).expiresIn(Duration.ofMinutes(1)).sign(key)));
        typed.verify(Jwt.builder(CLOCK).type("application/AT+JWT").expiresIn(Duration.ofMinutes(1)).sign(key));
        assertEquals(JwtException.Reason.TYPE, reason(noAudience, Jwt.builder(CLOCK).type("at+jwt").expiresIn(Duration.ofMinutes(1)).sign(key)),
                "일반 검증기는 Access Token(at+jwt)을 받지 않는다");
        // 클레임 값
        JwtVerifier valued = JwtVerifier.builder().key(key).requireClaimValue("typ", "Bearer").clock(CLOCK).build();
        assertEquals(JwtException.Reason.INVALID_CLAIM, reason(valued, Jwt.builder(CLOCK).claim("typ", "ID").expiresIn(Duration.ofMinutes(1)).sign(key)));
        assertEquals(JwtException.Reason.MISSING_CLAIM, reason(valued, Jwt.builder(CLOCK).expiresIn(Duration.ofMinutes(1)).sign(key)));
        // 다른 키 서명
        assertEquals(JwtException.Reason.SIGNATURE, reason(noAudience, Jwt.builder(CLOCK).expiresIn(Duration.ofMinutes(1)).sign(JwtKey.hs256(Hmac.generateKey()))));
    }

    @Test
    void keyRulesIssuerBindingAndUnverifiedParsing() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> JwtKey.hs256(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> JwtVerifier.builder().build());
        byte[] secret = Hmac.generateKey();
        assertThrows(IllegalArgumentException.class, () -> JwtVerifier.builder().key(JwtKey.hs256(secret).withKeyId("a")).key(JwtKey.hs256(secret).withKeyId("a")).build());
        assertThrows(IllegalArgumentException.class, () -> JwtVerifier.builder().key(JwtKey.hs256(secret)).key(JwtKey.hs256(Hmac.generateKey())).build());
        assertThrows(IllegalArgumentException.class, () -> JwtVerifier.builder().key(JwtKey.hs256(secret).withIssuer("iss-B")).issuer("iss-A").build(),
                "다른 발급자에 묶인 키 혼용 거부");
        KeyPair rsa = Signatures.generateRsaKeyPair(2048);
        assertThrows(IllegalArgumentException.class, () -> JwtVerifier.builder().key(JwtKey.rs256(rsa.getPrivate())), "개인키는 검증 키가 아님");
        assertThrows(IllegalArgumentException.class, () -> Jwt.builder().sign(JwtKey.rs256(rsa.getPublic())), "공개키로 서명 불가");
        assertThrows(IllegalArgumentException.class, () -> Jwt.builder().claim("exp", "x"), "표준 클레임은 전용 메서드로");
        assertThrows(IllegalArgumentException.class, () -> JwtKey.hs256(secret).withKeyId("has space"));
        // 발급자에 묶인 키: 서명이 맞아도 다른 iss 토큰은 거부
        JwtKey bound = JwtKey.hs256(secret).withIssuer("iss-A");
        JwtVerifier any = JwtVerifier.builder().key(bound).clock(CLOCK).build();
        assertEquals(JwtException.Reason.ISSUER, reason(any, Jwt.builder(CLOCK).issuer("iss-B").expiresIn(Duration.ofMinutes(1)).sign(JwtKey.hs256(secret))));
        any.verify(Jwt.builder(CLOCK).issuer("iss-A").expiresIn(Duration.ofMinutes(1)).sign(JwtKey.hs256(secret)));
        // 미검증 분석: 서명을 확인하지 않고 내용만, 타입으로 구분
        String token = Jwt.builder(CLOCK).issuer("iss-A").subject("s").expiresIn(Duration.ofMinutes(1)).sign(JwtKey.hs256(secret).withKeyId("k9"));
        String tampered = token.substring(0, token.lastIndexOf('.') + 1) + "AAAA";
        UnverifiedJwt peek = Jwt.parseUnverified(tampered);
        assertEquals("iss-A", peek.claims().issuer());
        assertEquals("k9", peek.keyId());
        assertEquals("HS256", peek.algorithm());
        assertTrue(peek.toString().contains("NOT VERIFIED"));
        assertEquals(JwtException.Reason.SIGNATURE, reason(JwtVerifier.builder().key(JwtKey.hs256(secret).withKeyId("k9")).clock(CLOCK).build(), tampered));
        assertThrows(JwtException.class, () -> Jwt.parseUnverified("x.y"));
        assertEquals("JWT", peek.type());
        assertFalse(JwtKey.hs256(secret).toString().contains(Encoding.HEX.encode(secret)));
    }

    @Test
    void optionalRegisteredFieldsAcceptOmissionAndRejectExplicitNull() throws Exception {
        byte[] secret = Hmac.generateKey();
        JwtVerifier verifier = JwtVerifier.builder().key(JwtKey.hs256(secret)).requireExpiration(false).clock(CLOCK).build();
        String header = "{\"alg\":\"HS256\"}";
        assertTrue(verifier.verify(hs(secret, header, "{\"custom\":null}")).claims().has("custom"));
        for (String name : new String[] {"typ", "kid", "cty"}) {
            String withNull = "{\"alg\":\"HS256\",\"" + name + "\":null}";
            assertEquals(JwtException.Reason.MALFORMED, reason(verifier, hs(secret, withNull, "{}")), name);
        }
        for (String name : new String[] {"aud", "exp", "nbf", "iat", "iss", "sub", "jti"}) {
            assertEquals(JwtException.Reason.INVALID_CLAIM, reason(verifier, hs(secret, header, "{\"" + name + "\":null}")), name);
        }
    }

    @Test
    void optionalJwkMembersAcceptOmissionAndRejectExplicitNull() throws Exception {
        String n = (String) firstKey(vectors().getProperty("py.jwks")).get("n");
        String rsa = "{\"kty\":\"RSA\",\"n\":\"" + n + "\",\"e\":\"AQAB\"";
        assertEquals(1, Jwks.parse("{\"keys\":[" + rsa + "}]}").size());
        for (String name : new String[] {"use", "kid", "key_ops", "issuer", "alg"}) {
            String keys = "{\"keys\":[" + rsa + ",\"" + name + "\":null}]}";
            assertThrows(IllegalArgumentException.class, () -> Jwks.parse(keys), name);
        }
    }

    @Test
    void jwksValidationRejectsUnsafeSets() throws Exception {
        Properties p = vectors();
        String jwks = p.getProperty("py.jwks");
        Map<String, Object> rsaJwk = firstKey(jwks);
        String n = (String) rsaJwk.get("n");
        String[] bad = {
            "{\"keys\":[{\"kty\":\"oct\",\"k\":\"AAAA\"}]}",
            "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"" + n + "\",\"e\":\"AQAB\",\"d\":\"AAAA\"}]}",
            "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"ES256\",\"n\":\"" + n + "\",\"e\":\"AQAB\"}]}",
            "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"x\",\"n\":\"" + n + "\",\"e\":\"AQAB\"},{\"kty\":\"RSA\",\"kid\":\"x\",\"n\":\"" + n + "\",\"e\":\"AQAB\"}]}",
            "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}",
            "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AAAA\",\"y\":\"AAAA\"}]}",
            "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"enc\",\"n\":\"" + n + "\",\"e\":\"AQAB\"}]}",
            "{\"keys\":[{\"kty\":\"RSA\",\"key_ops\":[\"encrypt\"],\"n\":\"" + n + "\",\"e\":\"AQAB\"}]}",
            "{\"keys\":[{\"kty\":\"RSA\",\"issuer\":\"https://other.example\",\"n\":\"" + n + "\",\"e\":\"AQAB\"}]}",
            "{\"keys\":[]}", "{\"keys\":{}}", "[]", "{\"keys\":[{\"kty\":\"RSA\",\"kty\":\"EC\"}]}",
        };
        for (String value : bad) assertThrows(IllegalArgumentException.class, () -> Jwks.parse(value, "https://py.example"), value.substring(0, Math.min(60, value.length())));
        List<JwtKey> ops = Jwks.parse("{\"keys\":[{\"kty\":\"RSA\",\"key_ops\":[\"verify\"],\"kid\":\"ok\",\"n\":\"" + n + "\",\"e\":\"AQAB\"}]}");
        assertEquals("ok", ops.get(0).keyId());
        assertNull(ops.get(0).issuer());
        List<JwtKey> skipped = Jwks.parse("{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS384\",\"n\":\"" + n + "\",\"e\":\"AQAB\"},"
                + "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"AAAA\"},{\"kty\":\"RSA\",\"kid\":\"use\",\"n\":\"" + n + "\",\"e\":\"AQAB\"}]}");
        assertEquals(1, skipped.size(), "지원하지 않는 알고리즘·키 종류는 건너뜀");
        assertEquals("use", skipped.get(0).keyId());
        List<JwtKey> entraStyle = Jwks.parse("{\"keys\":[{\"kty\":\"RSA\",\"issuer\":\"https://login.example/{tenantid}/v2.0\",\"n\":\"" + n + "\",\"e\":\"AQAB\"}]}");
        assertNull(entraStyle.get(0).issuer(), "템플릿 issuer는 묶지 않는다");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> firstKey(String jwks) {
        Object root = io.javacryptokit.json.StrictJson.parse(jwks);
        return (Map<String, Object>) ((List<Object>) ((Map<String, Object>) root).get("keys")).get(0);
    }

    private static String b64(String json) {
        return Encoding.BASE64_URL.encode(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String hs(byte[] secret, String header, String payload) {
        String input = b64(header) + "." + b64(payload);
        return input + "." + Encoding.BASE64_URL.encode(Hmac.of(secret).sign(input.getBytes(StandardCharsets.US_ASCII)));
    }
}
