package io.javacryptokit.security;

/**
 * <b>공개 API</b>: Passphrase·비밀번호에서 키를 파생하는 PBKDF2의 HMAC 해시 선택({@link Pbkdf2}, {@link Passwords},
 * {@link AesGcm#fromPassphrase}, {@code CredentialCrypto.fromPassphrase}). 권장 반복 횟수는 OWASP Password Storage Cheat
 * Sheet 기준이다.
 */
public enum Pbkdf2Algorithm {
    /** PBKDF2-HMAC-SHA256(권장 반복 600,000회). 기본값이며 관리형 pass 키와 같은 방식이다. */
    SHA256("PBKDF2WithHmacSHA256", "pbkdf2-sha256", 600_000, 32),
    /** PBKDF2-HMAC-SHA512(권장 반복 210,000회). */
    SHA512("PBKDF2WithHmacSHA512", "pbkdf2-sha512", 210_000, 64);

    private final String jcaName;
    private final String id;
    private final int recommendedIterations;
    private final int hashLength;

    Pbkdf2Algorithm(String jcaName, String id, int recommendedIterations, int hashLength) {
        this.jcaName = jcaName;
        this.id = id;
        this.recommendedIterations = recommendedIterations;
        this.hashLength = hashLength;
    }

    /** @return 권장 반복 횟수(SHA256 600,000, SHA512 210,000) */
    public int recommendedIterations() {
        return recommendedIterations;
    }

    /** @return 저장 형식에 쓰는 이름({@code pbkdf2-sha256}·{@code pbkdf2-sha512}) */
    public String id() {
        return id;
    }

    /** @return JCA 알고리즘 이름({@code PBKDF2WithHmacSHA256}·{@code PBKDF2WithHmacSHA512}, 다른 시스템과 맞출 때 참고) */
    public String jcaName() {
        return jcaName;
    }

    int hashLength() {
        return hashLength;
    }

    static Pbkdf2Algorithm fromId(String id) {
        for (Pbkdf2Algorithm algorithm : values()) {
            if (algorithm.id.equals(id)) return algorithm;
        }
        return null;
    }
}
