package io.javacryptokit.security;

/**
 * <b>공개 API</b>: {@link Digests}가 지원하는 해시 알고리즘. 지원 목록은 이 열거형이 정본이며 임의 알고리즘 문자열을 받지 않는다
 * (MD5·SHA-1 같은 약한 일반 해시는 없다).
 */
public enum DigestAlgorithm {
    /** SHA-256(결과 32바이트). 기본값. */
    SHA256("SHA-256", 32),
    /** SHA-512(결과 64바이트). */
    SHA512("SHA-512", 64);

    private final String jcaName;
    private final int length;

    DigestAlgorithm(String jcaName, int length) {
        this.jcaName = jcaName;
        this.length = length;
    }

    /** @return 결과 길이(바이트) */
    public int length() {
        return length;
    }

    String jcaName() {
        return jcaName;
    }
}
