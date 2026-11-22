package io.javacryptokit.core;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.i18n.Messages;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 문자열 토큰({@code ENC[v1:...]})용 v1 암호 엔진이다. 공개 API·CLI·Tomcat 어댑터가
 * 모두 {@link CryptoService}를 거쳐 이 클래스를 쓴다. 파일 암호화는 별도 바이너리 형식({@code file.FileCipher})이 맡는다.
 *
 * <p><b>키 출처를 모른다</b>: 이 클래스는 설정·키 공급원을 알지 못하고, 호출자가 넘긴 키ID와 32바이트 키만 쓴다. 그래서 키
 * 공급원(파일·환경변수·Vault·AWS KMS 등)을 추가해도 이 클래스는 바뀌지 않는다. 키를 언제 읽고 지우는지는 {@link CryptoService}가
 * 정한다.</p>
 *
 * <p><b>암호화 방식(v1, 변경 금지)</b></p>
 * <ul>
 *   <li>알고리즘: AES-256-GCM({@code AES/GCM/NoPadding}). 암호문이 한 비트라도 바뀌면 복호화 자체가 실패한다(AEAD).</li>
 *   <li>키: 정확히 32바이트(256비트).</li>
 *   <li>IV(nonce): 암호화할 때마다 {@link SecureRandom}으로 새로 만드는 12바이트 난수. 같은 키로 같은 IV를 재사용하면 GCM의
 *       기밀성과 무결성이 모두 무너지므로 고정값·카운터를 쓰지 않는다. 그래서 같은 값도 매번 다른 암호문이 된다.</li>
 *   <li>인증 태그: 128비트(16바이트). JCE는 태그를 암호문 뒤에 붙여 한 배열로 돌려준다.</li>
 *   <li>AAD(추가 인증 데이터): {@code "v1:" + 키ID}. 봉투에 평문으로 적히는 버전·키ID를 태그 계산에 포함해, 키ID만 바꿔치기한
 *       값은 태그 검증에서 실패하게 한다.</li>
 * </ul>
 *
 * <p><b>봉투 형식</b>: {@code ENC[v1:키ID:IV(Base64URL):암호문+태그(Base64URL)]}(Base64URL은 패딩 없음, 최대 16,384자).
 * 바꿔야 한다면 v2 같은 새 버전과 마이그레이션 안내·테스트를 함께 만든다(AGENTS.md 참고).</p>
 *
 * <p><b>Fail Closed</b>: 형식 오류, 키ID 불일치, 길이 오류, 인증 태그 실패는 모두 {@link CredentialCryptoException}으로 끝나며
 * 평문을 일부라도 반환하지 않는다. 예외 메시지에는 입력값·키·평문을 넣지 않는다.</p>
 *
 * <p><b>스레드 안전성</b>: 공유 상태는 스레드 안전한 {@link SecureRandom} 하나뿐이고 {@link Cipher}는 호출마다 새로 만든다.</p>
 */
public final class CredentialCipher {
    /** 봉투 시작 표식. */
    private static final String PREFIX = TokenCodec.ENC_PREFIX;
    /** 현재 지원하는 유일한 봉투 버전. AAD에도 들어가므로 버전 바꿔치기도 태그 검증에서 걸린다. */
    private static final String VERSION = "v1";
    /** GCM 권장 IV 길이 12바이트(96비트). */
    static final int IV_LENGTH = 12;
    /** GCM 인증 태그 길이 128비트. 짧은 태그는 위조 성공 확률을 높이므로 최대 길이로 고정한다. */
    static final int TAG_BITS = 128;
    /** IV 생성용 보안 난수 생성기. 운영체제 엔트로피로 시드되며 스레드 안전하므로 하나를 공유한다. */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** 정적 메서드만 제공하는 유틸리티 클래스이므로 인스턴스 생성을 막는다. */
    private CredentialCipher() { }

    /**
     * 평문 텍스트(char[])를 String 없이 UTF-8 바이트로 바꿔 암호화한다. 중간 바이트는 반환 전에 지운다.
     *
     * @param clearChars 평문(이 메서드는 배열 자체를 지우지 않는다)
     * @param keyId      검증된 키ID(AAD와 봉투에 기록)
     * @param key        32바이트 키(호출자가 지운다)
     * @return {@code ENC[v1:...]} 봉투
     * @throws CredentialCryptoException INVALID_INPUT(UTF-8로 표현할 수 없는 문자, 너무 긴 값), CRYPTO_PROVIDER
     */
    public static String encryptChars(char[] clearChars, String keyId, byte[] key) throws CredentialCryptoException {
        byte[] clearBytes = null;
        try {
            clearBytes = utf8Bytes(clearChars);
            return seal(clearBytes, keyId, key);
        } catch (CharacterCodingException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, Messages.get("cipher.err.notEncodable"));
        } finally {
            if (clearBytes != null) Arrays.fill(clearBytes, (byte) 0);
        }
    }

    /**
     * 임의 바이트를 그대로(문자 변환 없이) 암호화한다. 봉투 형식·AAD·AES-GCM 규칙은 텍스트와 같다.
     *
     * @param data  암호화할 원본 바이트(바꾸지 않는다)
     * @param keyId 검증된 키ID
     * @param key   32바이트 키(호출자가 지운다)
     * @return {@code ENC[v1:...]} 봉투
     * @throws CredentialCryptoException INVALID_INPUT(너무 긴 값), CRYPTO_PROVIDER
     */
    public static String encryptBytes(byte[] data, String keyId, byte[] key) throws CredentialCryptoException {
        return seal(data, keyId, key);
    }

    /**
     * 실제 AES-256-GCM 암호화와 봉투 조립을 수행한다.
     */
    private static String seal(byte[] plain, String keyId, byte[] key) throws CredentialCryptoException {
        // [IV 생성] 호출마다 새 난수 IV. 같은 키·IV 조합을 재사용하지 않는 것이 GCM 안전성의 핵심이다.
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);
        byte[] encrypted;
        try {
            // Cipher는 스레드 안전하지 않고, 같은 객체를 같은 키·IV로 다시 초기화하는 실수를 막기 위해 매번 새로 만든다.
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            // [AAD] 봉투에 평문으로 남는 "v1:키ID"를 태그 계산에 포함한다.
            cipher.updateAAD(aad(keyId));
            encrypted = cipher.doFinal(plain);
        } catch (GeneralSecurityException e) {
            // 예: 오래된 Java 8의 AES-256 정책 제한(InvalidKeyException). 원인 종류만 남긴다.
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CRYPTO_PROVIDER, null, e);
        }
        // [봉투 조립] Base64URL(패딩 없음)은 구분자 ':'와 XML 특수문자를 쓰지 않는다. IV는 비밀이 아니므로 함께 저장한다.
        String envelope = PREFIX + VERSION + ":" + keyId + ":" + base64Url(iv) + ":" + base64Url(encrypted) + "]";
        if (envelope.length() > TokenCodec.MAX_ENC_LENGTH) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, Messages.get("cipher.err.tooLong"));
        }
        return envelope;
    }

    /**
     * 키를 읽기 "전" 단계의 검사: 봉투 형식·키ID 일치·IV·암호문 길이. 잘못된 입력에는 키를 꺼내지도 않도록
     * {@link CryptoService}가 키 조회 전에 호출한다.
     *
     * @param envelope 봉투
     * @param keyId    현재 설정의 키ID
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH
     */
    public static void checkEnvelope(String envelope, String keyId) throws CredentialCryptoException {
        String[] pieces = parse(envelope);
        // [키ID 확인] 설정과 다른 키ID의 암호문은 다른 키로 만든 것이므로 시도하지 않고 거부한다.
        // 이 버전은 다중 키(Keyring)를 지원하지 않으므로 하나의 설정은 하나의 키ID만 복호화할 수 있다.
        if (!keyId.equals(pieces[1])) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.KEY_ID_MISMATCH);
        }
        byte[] iv = decode(pieces[2]);
        byte[] encrypted = decode(pieces[3]);
        if (iv.length != IV_LENGTH || encrypted.length < TAG_BITS / 8) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_TOKEN, Messages.get("cipher.err.length"));
        }
    }

    /**
     * 봉투에 기록된 키ID를 돌려준다(형식만 검사, 복호화하지 않음). {@code rekey}가 이전 키ID를 안내할 때 쓴다.
     *
     * @param envelope 봉투
     * @return 키ID
     * @throws CredentialCryptoException INVALID_TOKEN
     */
    public static String keyIdOf(String envelope) throws CredentialCryptoException {
        return parse(envelope)[1];
    }

    /**
     * 봉투를 검증·복호화해 원본 바이트를 돌려준다. 태그 검증에 성공해야만 평문이 반환된다.
     *
     * @param envelope {@code ENC[v1:...]} 봉투
     * @param keyId    현재 설정의 키ID
     * @param key      32바이트 키(호출자가 지운다)
     * @return 원본 바이트(호출자가 사용 후 지운다)
     * @throws CredentialCryptoException INVALID_TOKEN, KEY_ID_MISMATCH, INTEGRITY, CRYPTO_PROVIDER
     */
    public static byte[] decryptToBytes(String envelope, String keyId, byte[] key) throws CredentialCryptoException {
        checkEnvelope(envelope, keyId);
        String[] pieces = parse(envelope);
        byte[] iv = decode(pieces[2]);
        byte[] encrypted = decode(pieces[3]);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            // 암호화 때와 같은 AAD여야 태그가 맞는다.
            cipher.updateAAD(aad(pieces[1]));
            // [인증 태그 검증] 전체를 doFinal 한 번으로 처리하므로 태그 검증에 성공해야만 평문이 반환된다.
            return cipher.doFinal(encrypted);
        } catch (AEADBadTagException e) {
            // 다른 키로 만든 암호문이거나 IV·암호문·태그·키ID가 변조·손상된 경우다.
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INTEGRITY);
        } catch (GeneralSecurityException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.CRYPTO_PROVIDER, null, e);
        }
    }

    /**
     * 봉투를 복호화해 UTF-8 텍스트로 돌려준다. 결과가 올바른 UTF-8이 아니면 '?'로 바꾸지 않고 거부한다.
     *
     * @param envelope 봉투
     * @param keyId    현재 설정의 키ID
     * @param key      32바이트 키(호출자가 지운다)
     * @return 텍스트(JNDI·JDBC API가 String을 요구하므로 String이며, String은 지울 수 없다)
     * @throws CredentialCryptoException {@link #decryptToBytes}와 같고, 텍스트가 아니면 INVALID_INPUT
     */
    public static String decryptText(String envelope, String keyId, byte[] key) throws CredentialCryptoException {
        byte[] plain = decryptToBytes(envelope, keyId, key);
        CharBuffer chars = null;
        try {
            chars = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(plain));
            return chars.toString();
        } catch (CharacterCodingException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_INPUT, Messages.get("cipher.err.notUtf8"));
        } finally {
            Arrays.fill(plain, (byte) 0);
            if (chars != null && chars.hasArray()) Arrays.fill(chars.array(), '\0');
        }
    }

    /**
     * char[]를 String을 거치지 않고 UTF-8 바이트로 바꾼다. 변환할 수 없는 문자는 '?'로 바꾸지 않고 예외로 알린다.
     */
    private static byte[] utf8Bytes(char[] chars) throws CharacterCodingException {
        ByteBuffer buffer = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(chars));
        byte[] raw = new byte[buffer.remaining()];
        buffer.get(raw);
        if (buffer.hasArray()) Arrays.fill(buffer.array(), (byte) 0);
        return raw;
    }

    /** GCM AAD {@code "v1:" + 키ID}. 키ID는 ASCII 문자만 허용되므로 US-ASCII로 손실 없이 인코딩된다(비밀값 아님). */
    private static byte[] aad(String keyId) {
        return (VERSION + ":" + keyId).getBytes(StandardCharsets.US_ASCII);
    }

    /** 패딩 없는 Base64URL 인코딩. */
    private static String base64Url(byte[] raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    /**
     * 봉투를 [버전, 키ID, IV, 암호문] 네 부분으로 엄격하게 나눈다(16,384자 초과 거부, {@code ENC[}로 시작·{@code ]}로 끝,
     * 정확히 4부분, 버전 v1, 키ID 영문·숫자·밑줄·하이픈 1~64자).
     */
    private static String[] parse(String value) throws CredentialCryptoException {
        if (value == null || value.length() > TokenCodec.MAX_ENC_LENGTH || !value.startsWith(PREFIX) || !value.endsWith("]")) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_TOKEN, Messages.get("cipher.err.format"));
        }
        String[] parts = value.substring(PREFIX.length(), value.length() - 1).split(":", -1);
        if (parts.length != 4 || !VERSION.equals(parts[0]) || !parts[1].matches("[A-Za-z0-9_-]{1,64}")) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_TOKEN, Messages.get("cipher.err.version"));
        }
        return parts;
    }

    /** Base64URL 문자열을 바이트로 바꾼다. 디코더 메시지에는 문제 문자의 코드값이 들어가므로 그대로 전달하지 않는다. */
    private static byte[] decode(String value) throws CredentialCryptoException {
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_TOKEN, Messages.get("cipher.err.base64"));
        }
    }
}
