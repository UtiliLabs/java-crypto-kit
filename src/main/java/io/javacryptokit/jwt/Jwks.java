package io.javacryptokit.jwt;

import io.javacryptokit.json.StrictJson;
import io.javacryptokit.security.Encoding;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>공개 API</b>: 호출자가 신뢰할 수 있는 경로(설정 파일, 인증 서버의 {@code jwks_uri}를 애플리케이션이 HTTPS로 받은 값 등)로 확보한
 * JWKS(JSON Web Key Set, RFC 7517) 문자열을 검증용 {@link JwtKey} 목록으로 바꾼다. <b>네트워크 조회·캐시를 하지 않으며</b>, 토큰
 * 헤더의 {@code jku}·{@code jwk}·{@code x5u}로 키를 가져오지 않는다. 인증 서버가 키를 교체하면 호출자가 새 JWKS로 검증기를 다시 만든다.
 *
 * <p><b>받는 키</b>: 서명 검증용 공개키만 — {@code kty} RSA(2048비트 이상, {@code alg} 없거나 RS256)·EC({@code crv} P-256,
 * {@code alg} 없거나 ES256). {@code use}가 있으면 {@code sig}, {@code key_ops}가 있으면 {@code verify}를 포함해야 한다.</p>
 * <p><b>건너뛰는 키</b>: 암호화용({@code use: enc} 또는 {@code key_ops}에 verify 없음), 지원하지 않지만 형식이 맞는 키(다른 곡선·
 * RS384 등·다른 {@code kty}).</p>
 * <p><b>전체를 거부하는 경우</b>({@link IllegalArgumentException}): JSON·형식 오류, 개인키 성분({@code d} 등) 포함, 대칭 키
 * ({@code kty: oct}), 키 종류와 맞지 않는 {@code alg}(예: RSA 키에 ES256), 잘못된 키 값(길이·곡선 밖의 점), 서명용 키 사이의 중복
 * {@code kid}, 지정한 발급자와 다른 {@code issuer} 멤버, 쓸 수 있는 키 없음. {@code x5c}·{@code x5t}는 쓰지 않는다.</p>
 */
public final class Jwks {
    private static final int MAX_KEYS = 100;
    private static final Set<String> PRIVATE_MEMBERS = new HashSet<>(Arrays.asList("d", "p", "q", "dp", "dq", "qi", "oth", "k"));

    private Jwks() { }

    /**
     * 발급자를 묶어 읽는다(권장). 모든 키가 이 발급자의 토큰만 검증하게 되며, JWK에 다른 {@code issuer} 멤버가 있으면 거부한다.
     *
     * @param json   JWKS 문자열
     * @param issuer 이 JWKS를 쓰는 발급자({@code iss} 값)
     * @return 검증용 키 목록
     */
    public static List<JwtKey> parse(String json, String issuer) {
        if (issuer == null || issuer.isEmpty()) throw Jose.invalid("jwt.err.issuerEmpty");
        return read(json, issuer);
    }

    /**
     * 발급자를 묶지 않고 읽는다(JWK에 구체적인 {@code issuer} 멤버가 있으면 그 발급자에 묶는다).
     *
     * @param json JWKS 문자열
     * @return 검증용 키 목록
     */
    public static List<JwtKey> parse(String json) {
        return read(json, null);
    }

    @SuppressWarnings("unchecked")
    private static List<JwtKey> read(String json, String expectedIssuer) {
        Object root;
        try {
            root = StrictJson.parse(json == null ? "" : json, Jose.LIMITS);
        } catch (IllegalArgumentException e) {
            throw Jose.invalid("jwt.err.jwks", "json");
        }
        Object keys = StrictJson.path(root, "keys");
        if (!(keys instanceof List) || ((List<?>) keys).size() > MAX_KEYS) throw Jose.invalid("jwt.err.jwks", "keys");
        List<JwtKey> out = new ArrayList<>();
        Set<String> kids = new HashSet<>();
        for (Object item : (List<?>) keys) {
            if (!(item instanceof Map)) throw Jose.invalid("jwt.err.jwks", "keys");
            JwtKey key = toKey((Map<String, Object>) item, expectedIssuer);
            if (key == null) continue;
            if (key.keyId() != null && !kids.add(key.keyId())) throw Jose.invalid("jwt.err.jwks", "kid");
            out.add(key);
        }
        if (out.isEmpty()) throw Jose.invalid("jwt.err.jwksEmpty");
        return Collections.unmodifiableList(out);
    }

    private static JwtKey toKey(Map<String, Object> jwk, String expectedIssuer) {
        String kty = string(jwk, "kty", true);
        for (String member : PRIVATE_MEMBERS) {
            if (jwk.containsKey(member)) throw Jose.invalid("jwt.err.jwks", member);
        }
        if ("oct".equals(kty)) throw Jose.invalid("jwt.err.jwks", "oct");
        String use = string(jwk, "use", false);
        String alg = string(jwk, "alg", false);
        String kid = string(jwk, "kid", false);
        if (kid != null) Jose.checkKeyId(kid);
        if (use != null && !"sig".equals(use)) return null;
        if (jwk.containsKey("key_ops")) {
            Object ops = jwk.get("key_ops");
            if (!(ops instanceof List)) throw Jose.invalid("jwt.err.jwks", "key_ops");   // 명시적 null 포함
            for (Object op : (List<?>) ops) {
                if (!(op instanceof String)) throw Jose.invalid("jwt.err.jwks", "key_ops");
            }
            if (!((List<?>) ops).contains("verify")) return null;
        }
        String jwkIssuer = string(jwk, "issuer", false);
        if (jwkIssuer != null && jwkIssuer.indexOf('{') >= 0) jwkIssuer = null; // 템플릿(예: {tenantid})은 묶지 않는다
        if (expectedIssuer != null && jwkIssuer != null && !expectedIssuer.equals(jwkIssuer)) throw Jose.invalid("jwt.err.jwks", "issuer");
        String bind = expectedIssuer != null ? expectedIssuer : jwkIssuer;
        JwtKey key;
        if ("RSA".equals(kty)) {
            if (alg != null && !alg.startsWith("RS") && !alg.startsWith("PS")) throw Jose.invalid("jwt.err.jwks", "alg");
            if (alg != null && !"RS256".equals(alg)) return null;
            key = JwtKey.rs256(rsa(jwk));
        } else if ("EC".equals(kty)) {
            String crv = string(jwk, "crv", true);
            if (alg != null && !alg.startsWith("ES")) throw Jose.invalid("jwt.err.jwks", "alg");
            if (!"P-256".equals(crv)) {
                if ("ES256".equals(alg)) throw Jose.invalid("jwt.err.jwks", "crv");
                return null;
            }
            if (alg != null && !"ES256".equals(alg)) throw Jose.invalid("jwt.err.jwks", "alg");
            key = JwtKey.es256(ec(jwk));
        } else {
            return null;
        }
        if (kid != null) key = key.withKeyId(kid);
        return bind == null ? key : key.withIssuer(bind);
    }

    private static PublicKey rsa(Map<String, Object> jwk) {
        BigInteger n = new BigInteger(1, bytes(jwk, "n"));
        BigInteger e = new BigInteger(1, bytes(jwk, "e"));
        if (!e.testBit(0) || e.compareTo(BigInteger.valueOf(3)) < 0 || n.bitLength() < 2048) throw Jose.invalid("jwt.err.jwks", "n");
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        } catch (GeneralSecurityException ex) {
            throw Jose.invalid("jwt.err.jwks", "n");
        }
    }

    private static PublicKey ec(Map<String, Object> jwk) {
        byte[] x = bytes(jwk, "x");
        byte[] y = bytes(jwk, "y");
        if (x.length != 32 || y.length != 32) throw Jose.invalid("jwt.err.jwks", "x");
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
        } catch (GeneralSecurityException ex) {
            throw Jose.invalid("jwt.err.jwks", "x");
        }
    }

    private static byte[] bytes(Map<String, Object> jwk, String name) {
        String value = string(jwk, name, true);
        if (value.isEmpty() || value.indexOf('=') >= 0) throw Jose.invalid("jwt.err.jwks", name);
        try {
            return Encoding.BASE64_URL.decode(value);
        } catch (IllegalArgumentException e) {
            throw Jose.invalid("jwt.err.jwks", name);
        }
    }

    /** 멤버 문자열: 없으면(선택 멤버) null, 있으면 문자열이어야 한다(명시적 null은 생략으로 보지 않고 형식 오류). */
    private static String string(Map<String, Object> jwk, String name, boolean required) {
        if (!jwk.containsKey(name)) {
            if (required) throw Jose.invalid("jwt.err.jwks", name);
            return null;
        }
        Object value = jwk.get(name);
        if (!(value instanceof String)) throw Jose.invalid("jwt.err.jwks", name);
        return (String) value;
    }
}
