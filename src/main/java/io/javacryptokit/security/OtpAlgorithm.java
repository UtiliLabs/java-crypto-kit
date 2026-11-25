package io.javacryptokit.security;

/**
 * <b>공개 API</b>: HOTP·TOTP의 HMAC 해시. HOTP(RFC 4226)는 SHA1만 정의하며, TOTP(RFC 6238)는 SHA1·SHA256·SHA512를 쓸 수 있다.
 * SHA1은 이 OTP 표준 연동에만 쓴다(HMAC-SHA1은 OTP 용도에서 여전히 안전하다). 인증 앱 호환성은 SHA1이 가장 넓다.
 */
public enum OtpAlgorithm {
    /** HMAC-SHA1(새 비밀키 20바이트). HOTP·TOTP 기본값. */
    SHA1("HmacSHA1", 20),
    /** HMAC-SHA256(새 비밀키 32바이트). TOTP 전용. */
    SHA256("HmacSHA256", 32),
    /** HMAC-SHA512(새 비밀키 64바이트). TOTP 전용. */
    SHA512("HmacSHA512", 64);

    private final String jcaName;
    private final int secretBytes;

    OtpAlgorithm(String jcaName, int secretBytes) {
        this.jcaName = jcaName;
        this.secretBytes = secretBytes;
    }

    /** @return 새 비밀키 길이(바이트) */
    public int secretBytes() {
        return secretBytes;
    }

    String jcaName() {
        return jcaName;
    }
}
