package io.javacryptokit.jwt;

import io.javacryptokit.security.SignatureAlgorithm;

/**
 * <b>공개 API</b>: 지원하는 JWS 서명 알고리즘(RFC 7518). 토큰 헤더의 {@code alg}로 검증 방법을 정하지 않고, 검증기에 등록한 키의
 * 알고리즘과 같은지 확인할 때만 쓴다. {@code none}·RS384·PS256 등 그 밖의 값은 지원하지 않는다.
 */
public enum JwtAlgorithm {
    /** HMAC-SHA256(공유 비밀키 32바이트 이상). */
    HS256(null),
    /** RSASSA-PKCS1-v1_5 + SHA-256(RSA 2048비트 이상). RFC 9068 필수 지원 알고리즘. */
    RS256(SignatureAlgorithm.RSA_SHA256),
    /** ECDSA P-256 + SHA-256(서명은 64바이트 R‖S). */
    ES256(SignatureAlgorithm.ECDSA_P256_SHA256_P1363);

    private final SignatureAlgorithm signature;

    JwtAlgorithm(SignatureAlgorithm signature) {
        this.signature = signature;
    }

    SignatureAlgorithm signature() {
        return signature;
    }

    static JwtAlgorithm fromHeader(String value) {
        for (JwtAlgorithm algorithm : values()) {
            if (algorithm.name().equals(value)) return algorithm;
        }
        return null;
    }
}
