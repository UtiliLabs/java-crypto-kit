package io.javacryptokit.security;

/**
 * <b>공개 API</b>: {@link Hmac}·{@link Hkdf}가 지원하는 HMAC 알고리즘. 지원 목록은 이 열거형이 정본이다.
 */
public enum HmacAlgorithm {
    /** HMAC-SHA256(결과 32바이트, 새 키 32바이트). 기본값. */
    SHA256("HmacSHA256", 32),
    /** HMAC-SHA512(결과 64바이트, 새 키 64바이트). */
    SHA512("HmacSHA512", 64);

    private final String jcaName;
    private final int length;

    HmacAlgorithm(String jcaName, int length) {
        this.jcaName = jcaName;
        this.length = length;
    }

    /** @return MAC 결과 길이(바이트) = {@link Hmac#generateKey(HmacAlgorithm)}가 만드는 키 길이 */
    public int length() {
        return length;
    }

    String jcaName() {
        return jcaName;
    }
}
