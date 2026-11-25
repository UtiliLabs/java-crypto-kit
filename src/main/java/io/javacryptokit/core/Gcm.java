package io.javacryptokit.core;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: AES-GCM 한 번 처리를 맡는 공용 엔진이다. 문자열 토큰(ENC v1,
 * {@link CredentialCipher}), 암호화 파일(JCKF v1, {@code file.FileCipher})과 원시 AES-GCM 공개 API
 * ({@code security.AesGcm})가 모두 이 클래스를 쓴다. 형식(봉투·청크·결과 배치)과 AAD 구성은 각 호출자가 정하고, 이 클래스는
 * 알고리즘·IV·태그 규칙만 한 곳에 둔다.
 *
 * <ul>
 *   <li>{@code AES/GCM/NoPadding}, IV 12바이트, 인증 태그 128비트(16바이트, 암호문 뒤에 붙는다).</li>
 *   <li>IV는 {@link #newIv()}로 호출마다 보안 난수로 만든다. 같은 실제 키로 같은 IV를 다시 쓰면 GCM의 기밀성과 위조 방지가 함께
 *       깨지므로 고정값·카운터를 쓰지 않는다. 난수 IV는 같은 실제 키로 모든 서버·프로세스를 합쳐 2^32회 이하로 쓴다(NIST SP 800-38D).</li>
 *   <li>키 길이는 호출자가 검사한다(ENC·JCKF는 32바이트, {@code AesGcm}은 선택한 16·32바이트).</li>
 *   <li>{@link Cipher}는 스레드 안전하지 않으므로 호출마다 새로 만든다. 공유 상태는 스레드 안전한 {@link SecureRandom} 하나다.</li>
 * </ul>
 */
public final class Gcm {
    /** IV 길이(바이트). */
    public static final int IV_BYTES = 12;
    /** 인증 태그 길이(바이트). */
    public static final int TAG_BYTES = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Gcm() { }

    /** @return 새 12바이트 난수 IV */
    public static byte[] newIv() {
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        return iv;
    }

    /**
     * 암호화한다.
     *
     * @param key    AES 키(바꾸지 않는다)
     * @param iv     12바이트 IV
     * @param aad    추가 인증 데이터(없으면 null 또는 빈 배열)
     * @param data   평문
     * @param offset 평문 시작 위치
     * @param length 평문 길이
     * @return 암호문 + 태그(16바이트)
     * @throws GeneralSecurityException 공급자·키 문제
     */
    public static byte[] seal(byte[] key, byte[] iv, byte[] aad, byte[] data, int offset, int length)
            throws GeneralSecurityException {
        return run(Cipher.ENCRYPT_MODE, key, iv, aad, data, offset, length);
    }

    /**
     * 태그를 검증하고 복호화한다. 태그 검증에 성공해야만 평문을 돌려준다.
     *
     * @param key    AES 키(바꾸지 않는다)
     * @param iv     12바이트 IV
     * @param aad    암호화할 때와 같은 추가 인증 데이터(없으면 null 또는 빈 배열)
     * @param data   암호문 + 태그
     * @param offset 시작 위치
     * @param length 길이(태그 포함)
     * @return 평문
     * @throws javax.crypto.AEADBadTagException 다른 키·AAD·IV이거나 변조·손상됨
     * @throws GeneralSecurityException         공급자·키 문제
     */
    public static byte[] open(byte[] key, byte[] iv, byte[] aad, byte[] data, int offset, int length)
            throws GeneralSecurityException {
        return run(Cipher.DECRYPT_MODE, key, iv, aad, data, offset, length);
    }

    private static byte[] run(int mode, byte[] key, byte[] iv, byte[] aad, byte[] data, int offset, int length)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BYTES * 8, iv));
        if (aad != null && aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(data, offset, length);
    }
}
