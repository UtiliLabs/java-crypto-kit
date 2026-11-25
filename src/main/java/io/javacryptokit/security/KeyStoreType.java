package io.javacryptokit.security;

/**
 * <b>공개 API</b>: {@link KeyStoreReader}가 읽는 Java 키 저장소 형식. 파일 확장자로 추측하지 않으므로 호출자가 형식을 지정한다.
 */
public enum KeyStoreType {
    /** PKCS#12({@code .p12}·{@code .pfx}). */
    PKCS12("PKCS12"),
    /** Java KeyStore({@code .jks}). */
    JKS("JKS");

    private final String jcaName;

    KeyStoreType(String jcaName) {
        this.jcaName = jcaName;
    }

    String jcaName() {
        return jcaName;
    }
}
