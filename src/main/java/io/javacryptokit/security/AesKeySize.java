package io.javacryptokit.security;

/**
 * <b>공개 API</b>: {@link AesGcm}의 AES 키 길이. 키 길이를 자동으로 추측하지 않으며, 선택한 길이와 정확히 같은 키만 받는다.
 */
public enum AesKeySize {
    /** AES-128(키 16바이트). 외부 시스템 연동 등 꼭 필요할 때 명시적으로 선택한다. */
    AES_128(16),
    /** AES-256(키 32바이트). 기본 권장. */
    AES_256(32);

    private final int keyBytes;

    AesKeySize(int keyBytes) {
        this.keyBytes = keyBytes;
    }

    /** @return 키 길이(바이트) */
    public int keyBytes() {
        return keyBytes;
    }
}
