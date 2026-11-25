package io.javacryptokit;

/**
 * <b>공개 API</b>: 암호화 키를 준비하는 방식(유형)이다. 두 유형 모두 같은 AES-256-GCM 엔진과 같은 암호문 형식
 * ({@code ENC[v1:...]}, 파일은 JCKF v1)을 쓰며, 유형은 "AES 키를 어떻게 준비하느냐"만 다르다.
 *
 * <ul>
 *   <li>{@link #PASS} (설정·CLI 이름 {@code pass}): Passphrase(문자열)를 PBKDF2-HMAC-SHA256과 키마다 다른 Salt로 32바이트
 *       AES 키로 파생한다. 유형을 정하지 않은 새 암호화의 기본값이다.</li>
 *   <li>{@link #KEY} (설정·CLI 이름 {@code key}): 32바이트 AES-256 키를 그대로 쓴다(기존 방식).</li>
 * </ul>
 *
 * <p>복호화에는 유형이 필요 없다. 암호문(또는 암호화 파일 헤더)에 들어 있는 Key ID로 등록된 키를 찾는다.</p>
 */
public enum KeyType {
    /** Passphrase에서 파생한 AES-256 키(기본). */
    PASS("pass"),
    /** 32바이트 AES-256 키. */
    KEY("key");

    private final String code;

    KeyType(String code) {
        this.code = code;
    }

    /** @return 설정({@code crypto.key.type})과 CLI({@code --type})에서 쓰는 이름: {@code pass} 또는 {@code key} */
    public String code() {
        return code;
    }

    /**
     * 설정·CLI 이름으로 유형을 찾는다. 대소문자·공백 변형을 추측하지 않는다.
     *
     * @param code {@code pass} 또는 {@code key}
     * @return 해당 유형, 허용 이름이 아니면 null
     */
    public static KeyType fromCode(String code) {
        for (KeyType type : values()) {
            if (type.code.equals(code)) return type;
        }
        return null;
    }
}
