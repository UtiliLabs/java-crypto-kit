package io.javacryptokit.security;

import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * <b>공개 API</b>: {@link RsaOaep}의 OAEP 매개변수. 해시와 MGF1 해시를 <b>같은 값으로 둘 다 명시</b>하고 label은 빈 값이다
 * (RFC 8017 7.1). JCA 변환 이름만으로 MGF1 해시를 정하지 않는다. SHA-1 OAEP·PKCS#1 v1.5 암호화는 지원하지 않는다.
 */
public enum RsaOaepAlgorithm {
    /** RSAES-OAEP, SHA-256 + MGF1-SHA256(기본). 최대 평문 = 모듈러스 바이트 - 66(RSA 2048: 190, 3072: 318바이트). */
    SHA256("SHA-256", MGF1ParameterSpec.SHA256, 32),
    /** RSAES-OAEP, SHA-512 + MGF1-SHA512. 최대 평문 = 모듈러스 바이트 - 130(RSA 2048: 126, 3072: 254바이트). */
    SHA512("SHA-512", MGF1ParameterSpec.SHA512, 64);

    private final String digest;
    private final MGF1ParameterSpec mgf1;
    private final int hashLength;

    RsaOaepAlgorithm(String digest, MGF1ParameterSpec mgf1, int hashLength) {
        this.digest = digest;
        this.mgf1 = mgf1;
        this.hashLength = hashLength;
    }

    /** @return 해시 출력 길이(바이트, 최대 평문 계산의 hLen) */
    public int hashLength() {
        return hashLength;
    }

    OAEPParameterSpec spec() {
        return new OAEPParameterSpec(digest, "MGF1", mgf1, PSource.PSpecified.DEFAULT);
    }
}
