package io.javacryptokit.security;

import io.javacryptokit.CredentialCryptoException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import javax.crypto.Cipher;

/**
 * <b>공개 API</b>: RSA-OAEP 공개키 암호화(RFC 8017 7.1). 상대방 <b>공개키</b>로 짧은 비밀값(데이터 키·임시 토큰 등)을 암호화하고,
 * 대응하는 <b>개인키</b>를 가진 쪽만 복호화한다.
 *
 * <ul>
 *   <li>매개변수: {@link RsaOaepAlgorithm#SHA256}(기본, SHA-256 + MGF1-SHA256, 빈 label) 또는 {@link RsaOaepAlgorithm#SHA512}.
 *       해시와 MGF1 해시를 {@code OAEPParameterSpec}으로 둘 다 명시한다. 지원하지 않는 Java에서 SHA-1 등으로 바꾸지 않는다.</li>
 *   <li>키: RSA 2048비트 이상(새 키는 {@link Signatures#generateKeyPair}·{@link Signatures#generateRsaKeyPair}, 파일은
 *       {@link PemKeys}·{@link KeyStoreReader}).</li>
 *   <li><b>짧은 데이터 전용</b>: 최대 평문 = 모듈러스 바이트 - 2 × 해시 바이트 - 2({@link #maxPlaintextBytes}). RSA 2048 +
 *       SHA256 = 190바이트, 3072 = 318바이트. 문자열은 UTF-8 바이트 수로 센다. 더 큰 데이터는 {@link HybridEncryption}을 쓴다
 *       (RSA를 여러 블록으로 나눠 쓰지 않는다).</li>
 *   <li>같은 평문도 매번 다른 암호문이 된다. 공개키 암호화는 <b>보낸 쪽 인증·전자서명이 아니다</b>(필요하면 {@link Signatures}).</li>
 *   <li>복호화 실패(다른 키·변조·매개변수 불일치·패딩 오류)는 원인을 나누지 않고 모두
 *       {@link CredentialCryptoException.Reason#INTEGRITY}로 알린다(공격자가 실패 원인을 구별하지 못하게). 암호문 길이가 키와
 *       맞지 않는 형식 오류는 {@link CredentialCryptoException.Reason#INVALID_TOKEN}, 키 종류·길이·평문 크기 오류는
 *       {@link IllegalArgumentException}.</li>
 * </ul>
 * <p>상태가 없고 호출마다 새 {@link Cipher}를 쓰므로 스레드 안전하다. 키·평문을 오류·로그에 넣지 않는다.</p>
 */
public final class RsaOaep {
    private RsaOaep() { }

    /**
     * @param key       RSA 공개키 또는 개인키
     * @param algorithm OAEP 매개변수
     * @return 이 키·매개변수로 암호화할 수 있는 최대 평문 바이트 수
     */
    public static int maxPlaintextBytes(Key key, RsaOaepAlgorithm algorithm) {
        Text.require(algorithm, "algorithm");
        return modulusBytes(key) - 2 * algorithm.hashLength() - 2;
    }

    /**
     * SHA-256 OAEP로 암호화한다.
     *
     * @param key  상대방 RSA 공개키
     * @param data 평문(최대 {@link #maxPlaintextBytes}, 바꾸지 않는다)
     * @return 암호문(모듈러스와 같은 길이)
     */
    public static byte[] encrypt(PublicKey key, byte[] data) {
        return encrypt(key, data, RsaOaepAlgorithm.SHA256);
    }

    /**
     * @param key       상대방 RSA 공개키
     * @param data      평문(최대 {@link #maxPlaintextBytes})
     * @param algorithm OAEP 매개변수
     * @return 암호문
     * @throws IllegalArgumentException 키가 RSA 2048비트 미만이거나 평문이 너무 김
     */
    public static byte[] encrypt(PublicKey key, byte[] data, RsaOaepAlgorithm algorithm) {
        Text.require(data, "data");
        int max = maxPlaintextBytes(key, algorithm);
        if (data.length > max) throw Text.invalid("sec.err.oaepTooLong", max);
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, algorithm.spec());
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", "RSA-OAEP " + algorithm));
        }
    }

    /**
     * 문자열(UTF-8)을 암호화해 지정한 형식으로 돌려준다(SHA-256 OAEP).
     *
     * @param key      상대방 RSA 공개키
     * @param text     평문(UTF-8 바이트 수가 최대 길이 이하)
     * @param encoding 결과 형식
     * @return 인코딩한 암호문
     */
    public static String encryptText(PublicKey key, String text, Encoding encoding) {
        return encryptText(key, text, RsaOaepAlgorithm.SHA256, encoding);
    }

    /**
     * @param key       상대방 RSA 공개키
     * @param text      평문(UTF-8)
     * @param algorithm OAEP 매개변수
     * @param encoding  결과 형식
     * @return 인코딩한 암호문
     */
    public static String encryptText(PublicKey key, String text, RsaOaepAlgorithm algorithm, Encoding encoding) {
        Text.require(encoding, "encoding");
        byte[] data = Bytes.utf8(text);
        try {
            return encoding.encode(encrypt(key, data, algorithm));
        } finally {
            Arrays.fill(data, (byte) 0);
        }
    }

    /**
     * SHA-256 OAEP로 복호화한다.
     *
     * @param key        RSA 개인키
     * @param ciphertext 암호문
     * @return 평문
     * @throws CredentialCryptoException INTEGRITY(다른 키·변조·매개변수 불일치), INVALID_TOKEN(길이가 키와 다름)
     */
    public static byte[] decrypt(PrivateKey key, byte[] ciphertext) throws CredentialCryptoException {
        return decrypt(key, ciphertext, RsaOaepAlgorithm.SHA256);
    }

    /**
     * @param key        RSA 개인키
     * @param ciphertext 암호문
     * @param algorithm  암호화할 때 쓴 OAEP 매개변수
     * @return 평문
     * @throws CredentialCryptoException INTEGRITY(다른 키·변조·매개변수 불일치), INVALID_TOKEN(길이가 키와 다름)
     */
    public static byte[] decrypt(PrivateKey key, byte[] ciphertext, RsaOaepAlgorithm algorithm) throws CredentialCryptoException {
        Text.require(ciphertext, "ciphertext");
        Text.require(algorithm, "algorithm");
        if (ciphertext.length != modulusBytes(key)) throw Text.failure(CredentialCryptoException.Reason.INVALID_TOKEN, "sec.err.oaepLength");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, algorithm.spec());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", "RSA-OAEP " + algorithm));
        }
        try {
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw Text.failure(CredentialCryptoException.Reason.INTEGRITY, "sec.err.oaepIntegrity");
        }
    }

    /**
     * @param key        RSA 개인키
     * @param ciphertext {@link #encryptText} 결과
     * @param encoding   그 형식
     * @return 평문 문자열
     * @throws CredentialCryptoException INTEGRITY, INVALID_TOKEN(형식·길이), INVALID_INPUT(평문이 UTF-8이 아님)
     */
    public static String decryptText(PrivateKey key, String ciphertext, Encoding encoding) throws CredentialCryptoException {
        return decryptText(key, ciphertext, RsaOaepAlgorithm.SHA256, encoding);
    }

    /**
     * @param key        RSA 개인키
     * @param ciphertext {@link #encryptText} 결과
     * @param algorithm  암호화할 때 쓴 OAEP 매개변수
     * @param encoding   그 형식
     * @return 평문 문자열
     * @throws CredentialCryptoException INTEGRITY, INVALID_TOKEN(형식·길이), INVALID_INPUT(평문이 UTF-8이 아님)
     */
    public static String decryptText(PrivateKey key, String ciphertext, RsaOaepAlgorithm algorithm, Encoding encoding)
            throws CredentialCryptoException {
        Text.require(encoding, "encoding");
        byte[] raw;
        try {
            raw = encoding.decode(Text.require(ciphertext, "ciphertext"));
        } catch (IllegalArgumentException e) {
            throw Text.failure(CredentialCryptoException.Reason.INVALID_TOKEN, "sec.err.gcmEncoding");
        }
        byte[] plain = decrypt(key, raw, algorithm);
        try {
            return Bytes.utf8String(plain);
        } catch (IllegalArgumentException e) {
            throw Text.failure(CredentialCryptoException.Reason.INVALID_INPUT, "sec.err.utf8Decode");
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    /** 패키지 내부: RSA 2048비트 이상인지 확인하고 모듈러스 바이트 수를 돌려준다. */
    static int modulusBytes(Key key) {
        Text.require(key, "key");
        if (!(key instanceof RSAKey)) throw Text.invalid("sec.err.keyType", "RSA-OAEP", "RSA");
        int bits = ((RSAKey) key).getModulus().bitLength();
        if (bits < Signatures.MIN_RSA_BITS) throw Text.invalid("sec.err.rsaShort", Signatures.MIN_RSA_BITS);
        return (bits + 7) / 8;
    }

}
