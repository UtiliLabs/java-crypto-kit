package io.javacryptokit.jwt;

import io.javacryptokit.security.Hmac;
import io.javacryptokit.security.HmacAlgorithm;
import io.javacryptokit.security.Signatures;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * <b>공개 API</b>: JWT 서명·검증 키와 그 알고리즘·kid·(선택) 발급자를 묶은 불변 값. 알고리즘은 키를 만들 때 정하며, 토큰의
 * {@code alg} 헤더로 바뀌지 않는다(RSA 공개키를 HMAC 비밀로 쓰는 혼동이 생길 수 없다).
 *
 * <ul>
 *   <li>{@link #hs256(byte[])}: 공유 비밀키 32바이트 이상(RFC 7518). 사람이 기억하는 비밀번호를 쓰지 말고
 *       {@code Hmac.generateKey()} 같은 보안 난수로 만든다. 서명·검증 모두 가능.</li>
 *   <li>{@link #rs256(PrivateKey)}·{@link #es256(PrivateKey)}: 발급 서버의 서명 키. {@link #rs256(PublicKey)}·
 *       {@link #es256(PublicKey)}: 검증 서버의 공개키(RSA 2048비트 이상, EC P-256).</li>
 *   <li>{@link #withKeyId(String)}: 키 교체 때 이전·새 키를 함께 등록하고 토큰 {@code kid}로 고르게 한다. kid는 조회 이름일 뿐
 *       신뢰 근거가 아니다(검증기에 등록한 키만 쓴다).</li>
 *   <li>{@link #withIssuer(String)}: 이 키를 한 발급자에 묶는다. 묶인 키로 검증한 토큰은 {@code iss}가 그 발급자여야 하며, 다른
 *       발급자를 기대하는 검증기에는 등록할 수 없다(발급자 간 키 혼용 방지).</li>
 * </ul>
 * <p>{@code toString}에 키 값을 넣지 않는다. JAR 관리형 키·Passphrase·CLI 관리자 비밀번호를 서명 키로 쓰지 않는다.</p>
 */
public final class JwtKey {
    /** HS256 비밀키 최소 길이(바이트). */
    public static final int MIN_HS256_BYTES = 32;

    private final JwtAlgorithm algorithm;
    private final String keyId;
    private final String issuer;
    private final byte[] secret;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private JwtKey(JwtAlgorithm algorithm, String keyId, String issuer, byte[] secret, PrivateKey privateKey, PublicKey publicKey) {
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.issuer = issuer;
        this.secret = secret;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * @param secret 공유 비밀키(32바이트 이상, 복사해 보관)
     * @return HS256 키(서명·검증)
     */
    public static JwtKey hs256(byte[] secret) {
        if (secret == null || secret.length < MIN_HS256_BYTES) throw Jose.invalid("jwt.err.hsKey", MIN_HS256_BYTES);
        return new JwtKey(JwtAlgorithm.HS256, null, null, secret.clone(), null, null);
    }

    /**
     * @param key RSA 개인키(2048비트 이상)
     * @return RS256 서명 키
     */
    public static JwtKey rs256(PrivateKey key) {
        Signatures.checkKey(JwtAlgorithm.RS256.signature(), key);
        return new JwtKey(JwtAlgorithm.RS256, null, null, null, key, null);
    }

    /**
     * @param key RSA 공개키(2048비트 이상)
     * @return RS256 검증 키
     */
    public static JwtKey rs256(PublicKey key) {
        Signatures.checkKey(JwtAlgorithm.RS256.signature(), key);
        return new JwtKey(JwtAlgorithm.RS256, null, null, null, null, key);
    }

    /**
     * @param key EC P-256 개인키
     * @return ES256 서명 키
     */
    public static JwtKey es256(PrivateKey key) {
        Signatures.checkKey(JwtAlgorithm.ES256.signature(), key);
        return new JwtKey(JwtAlgorithm.ES256, null, null, null, key, null);
    }

    /**
     * @param key EC P-256 공개키
     * @return ES256 검증 키
     */
    public static JwtKey es256(PublicKey key) {
        Signatures.checkKey(JwtAlgorithm.ES256.signature(), key);
        return new JwtKey(JwtAlgorithm.ES256, null, null, null, null, key);
    }

    /**
     * @param keyId kid(출력 가능한 ASCII 1~256자, 공백 불가)
     * @return kid를 붙인 새 키(원래 키는 그대로)
     */
    public JwtKey withKeyId(String keyId) {
        Jose.checkKeyId(keyId);
        return new JwtKey(algorithm, keyId, issuer, secret, privateKey, publicKey);
    }

    /**
     * @param issuer 이 키를 쓰는 발급자({@code iss} 값 그대로)
     * @return 발급자에 묶은 새 키
     */
    public JwtKey withIssuer(String issuer) {
        if (issuer == null || issuer.isEmpty()) throw Jose.invalid("jwt.err.issuerEmpty");
        return new JwtKey(algorithm, keyId, issuer, secret, privateKey, publicKey);
    }

    /** @return 알고리즘 */
    public JwtAlgorithm algorithm() {
        return algorithm;
    }

    /** @return kid(없으면 null) */
    public String keyId() {
        return keyId;
    }

    /** @return 묶인 발급자(없으면 null) */
    public String issuer() {
        return issuer;
    }

    /** @return 서명할 수 있으면 true(HS256·개인키) */
    public boolean canSign() {
        return secret != null || privateKey != null;
    }

    /** @return 검증할 수 있으면 true(HS256·공개키) */
    public boolean canVerify() {
        return secret != null || publicKey != null;
    }

    /** 서명 원본(ASCII {@code header.payload})에 서명한다. */
    byte[] sign(byte[] signingInput) {
        if (algorithm == JwtAlgorithm.HS256) return Hmac.of(HmacAlgorithm.SHA256, secret).sign(signingInput);
        if (privateKey == null) throw Jose.invalid("jwt.err.notSigningKey");
        return Signatures.sign(algorithm.signature(), privateKey, signingInput);
    }

    /** 서명을 확인한다(길이·형식이 맞지 않는 서명은 false). */
    boolean verify(byte[] signingInput, byte[] signature) {
        if (algorithm == JwtAlgorithm.HS256) return Hmac.of(HmacAlgorithm.SHA256, secret).verify(signingInput, signature);
        return publicKey != null && Signatures.verify(algorithm.signature(), publicKey, signingInput, signature);
    }

    @Override
    public String toString() {
        return "JwtKey[" + algorithm + (keyId == null ? "" : ", kid=" + keyId) + (issuer == null ? "" : ", iss=" + issuer)
                + (canSign() ? ", sign" : "") + (canVerify() ? ", verify" : "") + "]";
    }
}
