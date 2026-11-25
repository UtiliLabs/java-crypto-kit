package io.javacryptokit.security;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.core.Gcm;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;

/**
 * <b>공개 API</b>: 원시 AES-GCM 암복호화(AES-128·AES-256 선택, 업무용 AAD 지원). 애플리케이션이 직접 가진 키나 Passphrase로
 * 데이터를 암호화하고, 결과는 표준 AES-GCM 바이트 배치로 돌려준다.
 *
 * <p><b>결과 형식(원시 AES-GCM)</b>: {@code IV(12바이트) ‖ 암호문 ‖ 인증 태그(16바이트)}. 헤더·버전·Key ID·Salt가 없으므로
 * 어떤 키(와 Passphrase면 Salt·알고리즘·반복 횟수)로 풀지는 호출자가 보관·선택한다. Go·Python 등에서 흔히 쓰는 nonce ‖ 암호문 ‖
 * 태그 배치와 같다. 이 결과는 {@code ENC[v1:...]} 토큰·JCKF 파일이 <b>아니며</b> {@code CredentialCrypto}로 풀 수 없다(반대도
 * 마찬가지). Key ID로 키를 고르는 토큰·파일 암호화가 필요하면 {@code CredentialCrypto.fromRawKey}·{@code fromPassphrase}
 * (AES-256 고정)를 쓴다. 파일 스트리밍은 지원하지 않는다(메모리의 바이트·문자열만).</p>
 *
 * <p><b>AAD(추가 인증 데이터)</b>: 암호화하지 않지만 함께 인증할 업무 값(예: 고객 ID·레코드 ID). 복호화할 때 같은 AAD를 줘야
 * 하며, 다르면 실패한다(다른 레코드로 옮겨 붙인 암호문 탐지). AAD는 결과에 들어 있지 않으므로 호출자가 다시 만들어 준다.</p>
 *
 * <p><b>IV와 키 사용량</b>: 암호화마다 12바이트 보안 난수 IV를 새로 만든다. 같은 <b>실제 키</b>로는 이 API·다른 서버·다른
 * 프로세스를 모두 합쳐 2^32회 이하로 암호화하고 그 전에 새 키로 바꾼다(NIST SP 800-38D). Key ID나 객체만 바꾸는 것은 키 교체가
 * 아니다. IV를 직접 지정하는 기능은 없다(IV 재사용 사고 방지).</p>
 *
 * <p><b>실패</b>: 복호화는 다른 키·AAD·Passphrase·Salt이거나 변조·잘림이면
 * {@link CredentialCryptoException.Reason#INTEGRITY}, 형식이 아니면 {@link CredentialCryptoException.Reason#INVALID_TOKEN}이며
 * 평문을 일부라도 돌려주지 않는다. 입력 null·키 길이 오류는 {@link IllegalArgumentException}이다. 객체는 불변이고(키는 복사해
 * 보관) 호출마다 새 {@code Cipher}를 쓰므로 여러 스레드에서 함께 써도 된다. 설정·키링·History·CLI 관리자 인증과 무관하다.</p>
 */
public final class AesGcm {
    /** IV 길이(바이트). */
    public static final int IV_BYTES = Gcm.IV_BYTES;
    /** 인증 태그 길이(바이트). */
    public static final int TAG_BYTES = Gcm.TAG_BYTES;

    private final AesKeySize keySize;
    private final byte[] key;

    private AesGcm(AesKeySize keySize, byte[] key) {
        this.keySize = keySize;
        this.key = key.clone();
    }

    /**
     * @param keySize 키 길이
     * @return 새 AES 키(보안 난수)
     */
    public static byte[] generateKey(AesKeySize keySize) {
        return SecureRandoms.fill(Text.require(keySize, "keySize").keyBytes());
    }

    /**
     * 키를 직접 준다.
     *
     * @param keySize 키 길이
     * @param key     키(정확히 16 또는 32바이트, 복사해 보관한다. 호출자 배열은 호출자가 지운다)
     * @return 객체
     * @throws IllegalArgumentException 키가 null이거나 길이가 다름
     */
    public static AesGcm of(AesKeySize keySize, byte[] key) {
        Text.require(keySize, "keySize");
        Text.require(key, "key");
        if (key.length != keySize.keyBytes()) throw Text.invalid("sec.err.aesKeyLength", keySize.name(), keySize.keyBytes());
        return new AesGcm(keySize, key);
    }

    /**
     * Passphrase에서 키를 파생해 객체를 만든다(PBKDF2, 파생은 한 번만 하고 객체가 키를 보관한다).
     *
     * @param keySize    키 길이
     * @param algorithm  PBKDF2 알고리즘
     * @param passphrase Passphrase(바꾸지 않는다)
     * @param salt       Salt(16~64바이트, 처음 한 번 {@link Pbkdf2#newSalt()}로 만들어 보관)
     * @param iterations 반복 횟수(100,000~5,000,000)
     * @return 객체
     * @throws IllegalArgumentException 입력이 규칙에 맞지 않음
     */
    public static AesGcm fromPassphrase(AesKeySize keySize, Pbkdf2Algorithm algorithm, char[] passphrase, byte[] salt,
                                        int iterations) {
        Text.require(keySize, "keySize");
        byte[] derived = Pbkdf2.deriveKey(algorithm, passphrase, salt, iterations, keySize.keyBytes());
        try {
            return new AesGcm(keySize, derived);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    /** @return 키 길이 */
    public AesKeySize keySize() {
        return keySize;
    }

    /**
     * @param plaintext 평문(바꾸지 않는다)
     * @return IV ‖ 암호문 ‖ 태그
     */
    public byte[] encrypt(byte[] plaintext) {
        return encrypt(plaintext, null);
    }

    /**
     * @param plaintext 평문(바꾸지 않는다)
     * @param aad       함께 인증할 업무 값(없으면 null)
     * @return IV ‖ 암호문 ‖ 태그
     */
    public byte[] encrypt(byte[] plaintext, byte[] aad) {
        Text.require(plaintext, "plaintext");
        byte[] iv = Gcm.newIv();
        byte[] sealed;
        try {
            sealed = Gcm.seal(key, iv, aad, plaintext, 0, plaintext.length);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", "AES/GCM/NoPadding"));
        }
        byte[] out = new byte[IV_BYTES + sealed.length];
        System.arraycopy(iv, 0, out, 0, IV_BYTES);
        System.arraycopy(sealed, 0, out, IV_BYTES, sealed.length);
        return out;
    }

    /**
     * @param sealed IV ‖ 암호문 ‖ 태그
     * @return 평문
     * @throws CredentialCryptoException INTEGRITY(다른 키·AAD, 변조), INVALID_TOKEN(28바이트 미만)
     */
    public byte[] decrypt(byte[] sealed) throws CredentialCryptoException {
        return decrypt(sealed, null);
    }

    /**
     * @param sealed IV ‖ 암호문 ‖ 태그
     * @param aad    암호화할 때 준 업무 값(없었으면 null)
     * @return 평문
     * @throws CredentialCryptoException INTEGRITY(다른 키·AAD, 변조), INVALID_TOKEN(28바이트 미만)
     */
    public byte[] decrypt(byte[] sealed, byte[] aad) throws CredentialCryptoException {
        Text.require(sealed, "sealed");
        if (sealed.length < IV_BYTES + TAG_BYTES) throw Text.failure(CredentialCryptoException.Reason.INVALID_TOKEN, "sec.err.gcmShort");
        byte[] iv = Arrays.copyOfRange(sealed, 0, IV_BYTES);
        try {
            return Gcm.open(key, iv, aad, sealed, IV_BYTES, sealed.length - IV_BYTES);
        } catch (AEADBadTagException e) {
            throw Text.failure(CredentialCryptoException.Reason.INTEGRITY, "sec.err.gcmIntegrity");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", "AES/GCM/NoPadding"));
        }
    }

    /**
     * 문자열을 암호화해 지정한 형식으로 돌려준다.
     *
     * @param text     평문 문자열(UTF-8)
     * @param encoding 결과 형식(예: {@link Encoding#BASE64_URL})
     * @return 인코딩한 IV ‖ 암호문 ‖ 태그
     */
    public String encryptText(String text, Encoding encoding) {
        return encryptText(text, null, encoding);
    }

    /**
     * @param text     평문 문자열(UTF-8)
     * @param aad      함께 인증할 업무 값(UTF-8, 없으면 null)
     * @param encoding 결과 형식
     * @return 인코딩한 IV ‖ 암호문 ‖ 태그
     */
    public String encryptText(String text, String aad, Encoding encoding) {
        Text.require(encoding, "encoding");
        byte[] plain = Bytes.utf8(text);
        try {
            return encoding.encode(encrypt(plain, aad == null ? null : Bytes.utf8(aad)));
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    /**
     * @param sealedText {@link #encryptText}의 결과
     * @param encoding   그 형식
     * @return 평문 문자열
     * @throws CredentialCryptoException INTEGRITY, INVALID_TOKEN(형식 오류), INVALID_INPUT(평문이 UTF-8이 아님)
     */
    public String decryptText(String sealedText, Encoding encoding) throws CredentialCryptoException {
        return decryptText(sealedText, null, encoding);
    }

    /**
     * @param sealedText {@link #encryptText}의 결과
     * @param aad        암호화할 때 준 업무 값(없었으면 null)
     * @param encoding   그 형식
     * @return 평문 문자열
     * @throws CredentialCryptoException INTEGRITY, INVALID_TOKEN(형식 오류), INVALID_INPUT(평문이 UTF-8이 아님)
     */
    public String decryptText(String sealedText, String aad, Encoding encoding) throws CredentialCryptoException {
        Text.require(encoding, "encoding");
        Text.require(sealedText, "sealedText");
        byte[] sealed;
        try {
            sealed = encoding.decode(sealedText);
        } catch (IllegalArgumentException e) {
            throw Text.failure(CredentialCryptoException.Reason.INVALID_TOKEN, "sec.err.gcmEncoding");
        }
        byte[] plain = decrypt(sealed, aad == null ? null : Bytes.utf8(aad));
        try {
            return Bytes.utf8String(plain);
        } catch (IllegalArgumentException e) {
            throw Text.failure(CredentialCryptoException.Reason.INVALID_INPUT, "sec.err.utf8Decode");
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    @Override
    public String toString() {
        return "AesGcm[" + keySize + "]";
    }

}
