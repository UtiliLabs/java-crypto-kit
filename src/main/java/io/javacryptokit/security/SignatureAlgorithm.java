package io.javacryptokit.security;

/**
 * <b>공개 API</b>: {@link Signatures}가 지원하는 전자서명 알고리즘. 서명 바이트 형식까지 명시하며 자동으로 바꿔 시도하지 않는다.
 * RSA-PSS·SHA-1 서명·다른 곡선은 지원하지 않는다.
 */
public enum SignatureAlgorithm {
    /** RSASSA-PKCS1-v1_5 + SHA-256({@code SHA256withRSA}). RSA 2048비트 이상. JWT RS256과 같은 서명. */
    RSA_SHA256("SHA256withRSA", "RSA"),
    /** ECDSA P-256 + SHA-256, 서명은 ASN.1 DER(JCA·OpenSSL 기본 형식, 길이 가변). */
    ECDSA_P256_SHA256("SHA256withECDSA", "EC"),
    /** ECDSA P-256 + SHA-256, 서명은 고정 64바이트 R‖S(IEEE P1363, WebCrypto·JWT ES256 형식). */
    ECDSA_P256_SHA256_P1363("SHA256withECDSA", "EC");

    private final String jcaName;
    private final String keyAlgorithm;

    SignatureAlgorithm(String jcaName, String keyAlgorithm) {
        this.jcaName = jcaName;
        this.keyAlgorithm = keyAlgorithm;
    }

    /** @return 키 알고리즘({@code RSA} 또는 {@code EC}) */
    public String keyAlgorithm() {
        return keyAlgorithm;
    }

    String jcaName() {
        return jcaName;
    }
}
