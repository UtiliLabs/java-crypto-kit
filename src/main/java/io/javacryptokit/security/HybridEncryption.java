package io.javacryptokit.security;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.core.Gcm;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * <b>공개 API</b>: 수신자 RSA 공개키로 업무 메시지를 암호화하는 하이브리드 암호화(RSA-OAEP + AES-256-GCM). RSA-OAEP의 짧은 데이터
 * 한계를 넘는 메시지를 수신자의 <b>개인키를 가진 쪽만</b> 복호화할 수 있게 한다. 암호화마다 새 32바이트 데이터 키(DEK)를 보안 난수로
 * 만들고, DEK는 {@link RsaOaep}(SHA-256 + MGF1-SHA256)로, 데이터는 공용 AES-GCM 엔진(IV 12바이트 난수, 태그 16바이트)으로 보호한다.
 *
 * <p><b>결과 형식(JCKH 봉투 버전 1, 이 KIT의 독립 형식)</b>: 모든 정수는 big-endian.</p>
 * <pre>
 * 0      4  magic "JCKH"(0x4A 0x43 0x4B 0x48)
 * 4      1  버전 = 1
 * 5      1  suite = 1 (RSA-OAEP-SHA256/MGF1-SHA256 + AES-256-GCM)
 * 6      2  N = 보호된 DEK 길이(= 수신자 RSA 모듈러스 바이트, 256~1024)
 * 8      N  보호된 DEK(RSA-OAEP 암호문)
 * 8+N   12  IV
 * 20+N   L  AES-GCM 암호문 ‖ 태그(16), L ≥ 16
 * GCM AAD = 봉투의 0 ~ 20+N 바이트(헤더 전체) ‖ 업무 AAD 길이(4바이트) ‖ 업무 AAD
 * </pre>
 * <p>헤더(버전·suite·길이·보호된 DEK·IV)를 GCM AAD에 넣으므로 한 바이트라도 바뀌거나 잘리거나 덧붙으면 복호화가 실패한다. 업무 AAD는
 * 길이와 함께 넣으므로 암호화할 때와 같은 값을 줘야 하며(빈 값 = 없음), 봉투에는 들어 있지 않다. 이 형식은 {@code ENC[v1:...]}·
 * JCKF·{@link AesGcm}의 원시 결과와 다르며 JWE가 아니다(JOSE 상호운용을 약속하지 않는다).</p>
 *
 * <p><b>범위</b>: 메모리의 바이트·문자열만, 평문 최대 64MiB(봉투 전체를 메모리에 둔다). 파일 스트리밍은 지원하지 않는다. 수신자만
 * 읽게 하는 <b>기밀성</b> 기능이며 보낸 쪽을 인증하지 않는다(필요하면 {@link Signatures}로 따로 서명하고 공개키를 신뢰 경로로
 * 배포한다). 수신자 공개키가 정말 수신자의 것인지는 호출자가 확인한다.</p>
 *
 * <p><b>실패</b>: 다른 개인키·변조·AAD 불일치는 모두 {@link CredentialCryptoException.Reason#INTEGRITY}(원인 구분 없음, DEK 복원
 * 실패도 같은 경로로 처리), 형식 오류(magic·버전·suite·길이·크기)는 {@link CredentialCryptoException.Reason#INVALID_TOKEN}이다. 태그
 * 확인 전에는 평문을 돌려주지 않는다. 임시 DEK는 쓰고 나서 지운다. 상태가 없어 스레드 안전하다.</p>
 */
public final class HybridEncryption {
    /** 평문 최대 크기(64MiB). */
    public static final int MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024;
    /** 업무 AAD 최대 크기(64KiB). */
    public static final int MAX_AAD_BYTES = 64 * 1024;
    private static final byte[] MAGIC = {0x4A, 0x43, 0x4B, 0x48};
    private static final int VERSION = 1;
    private static final int SUITE = 1;
    private static final int DEK_BYTES = 32;
    private static final int MIN_WRAPPED = 256;
    private static final int MAX_WRAPPED = 1024;

    private HybridEncryption() { }

    /**
     * @param recipient 수신자 RSA 공개키(2048비트 이상)
     * @param plaintext 평문(최대 64MiB, 바꾸지 않는다)
     * @return JCKH 봉투
     */
    public static byte[] encrypt(PublicKey recipient, byte[] plaintext) {
        return encrypt(recipient, plaintext, null);
    }

    /**
     * @param recipient 수신자 RSA 공개키(2048비트 이상)
     * @param plaintext 평문(최대 64MiB)
     * @param aad       함께 인증할 업무 값(없으면 null, 최대 64KiB)
     * @return JCKH 봉투
     */
    public static byte[] encrypt(PublicKey recipient, byte[] plaintext, byte[] aad) {
        Text.require(plaintext, "plaintext");
        if (plaintext.length > MAX_PLAINTEXT_BYTES) throw Text.invalid("sec.err.hybridTooLarge", MAX_PLAINTEXT_BYTES);
        checkAad(aad);
        int wrappedLength = RsaOaep.modulusBytes(recipient);
        if (wrappedLength > MAX_WRAPPED) throw Text.invalid("sec.err.hybridKey");
        byte[] dek = SecureRandoms.fill(DEK_BYTES);
        try {
            byte[] wrapped = RsaOaep.encrypt(recipient, dek, RsaOaepAlgorithm.SHA256);
            byte[] iv = Gcm.newIv();
            byte[] header = header(wrapped, iv);
            byte[] sealed;
            try {
                sealed = Gcm.seal(dek, iv, gcmAad(header, aad), plaintext, 0, plaintext.length);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(Text.get("sec.err.provider", "AES/GCM/NoPadding"));
            }
            byte[] envelope = Arrays.copyOf(header, header.length + sealed.length);
            System.arraycopy(sealed, 0, envelope, header.length, sealed.length);
            return envelope;
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    /**
     * @param recipientKey 수신자 RSA 개인키
     * @param envelope     JCKH 봉투
     * @return 평문
     * @throws CredentialCryptoException INTEGRITY(다른 키·변조), INVALID_TOKEN(형식)
     */
    public static byte[] decrypt(PrivateKey recipientKey, byte[] envelope) throws CredentialCryptoException {
        return decrypt(recipientKey, envelope, null);
    }

    /**
     * @param recipientKey 수신자 RSA 개인키
     * @param envelope     JCKH 봉투
     * @param aad          암호화할 때 준 업무 값(없었으면 null)
     * @return 평문
     * @throws CredentialCryptoException INTEGRITY(다른 키·변조·AAD 불일치), INVALID_TOKEN(형식)
     */
    public static byte[] decrypt(PrivateKey recipientKey, byte[] envelope, byte[] aad) throws CredentialCryptoException {
        Text.require(envelope, "envelope");
        checkAad(aad);
        int modulus = RsaOaep.modulusBytes(recipientKey);
        if (envelope.length < 8 + MIN_WRAPPED + Gcm.IV_BYTES + Gcm.TAG_BYTES
                || envelope.length > 8 + MAX_WRAPPED + Gcm.IV_BYTES + MAX_PLAINTEXT_BYTES + Gcm.TAG_BYTES
                || !Arrays.equals(Arrays.copyOf(envelope, 4), MAGIC)) {
            throw Text.failure(CredentialCryptoException.Reason.INVALID_TOKEN, "sec.err.hybridFormat");
        }
        if ((envelope[4] & 0xff) != VERSION || (envelope[5] & 0xff) != SUITE) {
            throw Text.failure(CredentialCryptoException.Reason.INVALID_TOKEN, "sec.err.hybridVersion");
        }
        int wrappedLength = ((envelope[6] & 0xff) << 8) | (envelope[7] & 0xff);
        int headerLength = 8 + wrappedLength + Gcm.IV_BYTES;
        if (wrappedLength < MIN_WRAPPED || wrappedLength > MAX_WRAPPED || envelope.length < headerLength + Gcm.TAG_BYTES) {
            throw Text.failure(CredentialCryptoException.Reason.INVALID_TOKEN, "sec.err.hybridFormat");
        }
        byte[] header = Arrays.copyOf(envelope, headerLength);
        byte[] wrapped = Arrays.copyOfRange(envelope, 8, 8 + wrappedLength);
        byte[] iv = Arrays.copyOfRange(envelope, 8 + wrappedLength, headerLength);
        byte[] dek = null;
        try {
            if (wrappedLength == modulus) {
                try {
                    byte[] unwrapped = RsaOaep.decrypt(recipientKey, wrapped, RsaOaepAlgorithm.SHA256);
                    if (unwrapped.length == DEK_BYTES) dek = unwrapped;
                    else Arrays.fill(unwrapped, (byte) 0);
                } catch (CredentialCryptoException e) {
                    dek = null;
                }
            }
            // DEK를 복원하지 못해도(다른 키·변조) 임의 키로 같은 AES-GCM 검증 경로를 지나 같은 실패를 돌려준다.
            byte[] key = dek != null ? dek : SecureRandoms.fill(DEK_BYTES);
            try {
                byte[] plain = Gcm.open(key, iv, gcmAad(header, aad), envelope, headerLength, envelope.length - headerLength);
                if (dek == null) {
                    Arrays.fill(plain, (byte) 0);
                    throw Text.failure(CredentialCryptoException.Reason.INTEGRITY, "sec.err.hybridIntegrity");
                }
                return plain;
            } catch (GeneralSecurityException e) {
                throw Text.failure(CredentialCryptoException.Reason.INTEGRITY, "sec.err.hybridIntegrity");
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        } finally {
            if (dek != null) Arrays.fill(dek, (byte) 0);
        }
    }

    /**
     * 문자열(UTF-8)을 암호화해 지정한 형식으로 돌려준다.
     *
     * @param recipient 수신자 RSA 공개키
     * @param text      평문
     * @param encoding  결과 형식(예: {@link Encoding#BASE64_URL})
     * @return 인코딩한 JCKH 봉투
     */
    public static String encryptText(PublicKey recipient, String text, Encoding encoding) {
        return encryptText(recipient, text, null, encoding);
    }

    /**
     * @param recipient 수신자 RSA 공개키
     * @param text      평문(UTF-8)
     * @param aad       함께 인증할 업무 값(UTF-8, 없으면 null)
     * @param encoding  결과 형식
     * @return 인코딩한 JCKH 봉투
     */
    public static String encryptText(PublicKey recipient, String text, String aad, Encoding encoding) {
        Text.require(encoding, "encoding");
        byte[] plain = Bytes.utf8(text);
        try {
            return encoding.encode(encrypt(recipient, plain, aad == null ? null : Bytes.utf8(aad)));
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    /**
     * @param recipientKey 수신자 RSA 개인키
     * @param envelope     {@link #encryptText} 결과
     * @param encoding     그 형식
     * @return 평문 문자열
     * @throws CredentialCryptoException INTEGRITY, INVALID_TOKEN, INVALID_INPUT(평문이 UTF-8이 아님)
     */
    public static String decryptText(PrivateKey recipientKey, String envelope, Encoding encoding) throws CredentialCryptoException {
        return decryptText(recipientKey, envelope, null, encoding);
    }

    /**
     * @param recipientKey 수신자 RSA 개인키
     * @param envelope     {@link #encryptText} 결과
     * @param aad          암호화할 때 준 업무 값(없었으면 null)
     * @param encoding     그 형식
     * @return 평문 문자열
     * @throws CredentialCryptoException INTEGRITY, INVALID_TOKEN, INVALID_INPUT(평문이 UTF-8이 아님)
     */
    public static String decryptText(PrivateKey recipientKey, String envelope, String aad, Encoding encoding)
            throws CredentialCryptoException {
        Text.require(encoding, "encoding");
        byte[] raw;
        try {
            raw = encoding.decode(Text.require(envelope, "envelope"));
        } catch (IllegalArgumentException e) {
            throw Text.failure(CredentialCryptoException.Reason.INVALID_TOKEN, "sec.err.gcmEncoding");
        }
        byte[] plain = decrypt(recipientKey, raw, aad == null ? null : Bytes.utf8(aad));
        try {
            return Bytes.utf8String(plain);
        } catch (IllegalArgumentException e) {
            throw Text.failure(CredentialCryptoException.Reason.INVALID_INPUT, "sec.err.utf8Decode");
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    private static byte[] header(byte[] wrapped, byte[] iv) {
        ByteBuffer buffer = ByteBuffer.allocate(8 + wrapped.length + iv.length);
        buffer.put(MAGIC).put((byte) VERSION).put((byte) SUITE).putShort((short) wrapped.length).put(wrapped).put(iv);
        return buffer.array();
    }

    private static byte[] gcmAad(byte[] header, byte[] aad) {
        byte[] business = aad == null ? new byte[0] : aad;
        return ByteBuffer.allocate(header.length + 4 + business.length).put(header).putInt(business.length).put(business).array();
    }

    private static void checkAad(byte[] aad) {
        if (aad != null && aad.length > MAX_AAD_BYTES) throw Text.invalid("sec.err.hybridAad", MAX_AAD_BYTES);
    }
}
