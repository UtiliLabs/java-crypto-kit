package io.javacryptokit;

/**
 * <b>공개 API</b>: 등록된 키 하나의 읽기 전용 정보다({@link CredentialCrypto#keys()}). 키 원문·Passphrase·내장 값은 들어 있지 않다.
 * 지문은 일반 조회용 짧은 형태(앞 12자 + {@code ...} + 뒤 8자)이며 키를 비교하는 식별값일 뿐 비밀이나 인증 수단이 아니다.
 */
public final class KeyInfo {
    private final String keyId;
    private final KeyType type;
    private final String source;
    private final boolean typeDefault;
    private final boolean encryptionDefault;
    private final boolean publicDefault;
    private final boolean available;
    private final CredentialCryptoException.Reason failureReason;
    private final String failureMessage;
    private final String fingerprint;

    KeyInfo(String keyId, KeyType type, String source, boolean typeDefault, boolean encryptionDefault, boolean publicDefault,
            boolean available, CredentialCryptoException.Reason failureReason, String failureMessage, String fingerprint) {
        this.keyId = keyId;
        this.type = type;
        this.source = source;
        this.typeDefault = typeDefault;
        this.encryptionDefault = encryptionDefault;
        this.publicDefault = publicDefault;
        this.available = available;
        this.failureReason = failureReason;
        this.failureMessage = failureMessage;
        this.fingerprint = fingerprint;
    }

    /** @return Key ID(암호문·파일 헤더에 기록되는 식별자) */
    public String keyId() { return keyId; }

    /** @return 유형({@link KeyType#PASS} 또는 {@link KeyType#KEY}) */
    public KeyType type() { return type; }

    /** @return 공급원 이름: embedded, file, env, vault, aws-kms */
    public String source() { return source; }

    /** @return 이 유형의 기본 키이면 true(그 유형을 지정한 새 암호화가 쓰는 키) */
    public boolean isTypeDefault() { return typeDefault; }

    /** @return 유형·Key ID를 정하지 않은 새 암호화({@code encryptText(value)})가 쓰는 키이면 true */
    public boolean isEncryptionDefault() { return encryptionDefault; }

    /** @return 공개 기본 키(공개 예제 키)이면 true. 키를 읽지 못했으면 false */
    public boolean isPublicDefault() { return publicDefault; }

    /** @return 키를 실제로 읽을 수 있었으면 true */
    public boolean isAvailable() { return available; }

    /** @return 키를 읽지 못한 사유 코드(읽었으면 null) */
    public CredentialCryptoException.Reason failureReason() { return failureReason; }

    /**
     * @return 키를 읽지 못한 원인과 조치({@link CredentialCryptoException#getMessage()}와 같은 정제된 문구, 읽었으면 null).
     *         키·경로·설정값은 들어 있지 않다.
     */
    public String failureMessage() { return failureMessage; }

    /** @return 짧은 키 지문(앞 12자 + ... + 뒤 8자). 키를 읽지 못했으면 null */
    public String fingerprint() { return fingerprint; }

    /** @return 비밀값 없는 한 줄 요약(로그에 남겨도 된다) */
    @Override
    public String toString() {
        return "KeyInfo[" + keyId + ", " + type.code() + ", " + source + (encryptionDefault ? ", default" : "")
                + (typeDefault ? ", type-default" : "") + (publicDefault ? ", public" : "")
                + (available ? ", " + fingerprint : ", unavailable " + failureReason) + "]";
    }
}
