package io.javacryptokit.security;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * <b>공개 API</b>: HKDF(RFC 5869, HMAC 기반 키 파생). 이미 충분히 무작위인 키 재료(IKM: 난수 키, 키 합의 결과 등) 하나에서
 * 용도가 다른 키를 여러 개 나눠 만든다(예: 같은 원본 키에서 암호화용·HMAC용 키를 {@code info}만 바꿔 파생).
 *
 * <p><b>쓰지 않는 경우</b>: 사람이 입력한 비밀번호·Passphrase에서 키를 만들 때는 느린 KDF인 {@link Pbkdf2}를 쓴다(HKDF는 대입
 * 공격을 늦추지 않는다). 비밀번호 저장은 {@link Passwords}.</p>
 *
 * <ul>
 *   <li>Salt: 선택. null·빈 값이면 RFC 5869 규칙대로 해시 길이만큼의 0바이트를 쓴다(일반 HMAC의 32바이트 키 정책과 별개).</li>
 *   <li>Info: 용도 구분 문자열/바이트(예: {@code "myapp/orders/enc/v1"}). null이면 빈 값.</li>
 *   <li>출력 길이: 1 ~ 255 × 해시 길이(SHA256 8,160바이트, SHA512 16,320바이트).</li>
 *   <li>IKM은 비어 있으면 안 된다. 같은 입력은 어디서나 같은 결과다(상태·전역 키 저장소 없음, 스레드 안전).</li>
 * </ul>
 */
public final class Hkdf {
    private Hkdf() { }

    /**
     * HKDF-SHA256 Extract + Expand.
     *
     * @param ikm    입력 키 재료(바꾸지 않는다)
     * @param salt   Salt(없으면 null)
     * @param info   용도 구분 값(없으면 null)
     * @param length 출력 길이(바이트)
     * @return 파생 키
     */
    public static byte[] derive(byte[] ikm, byte[] salt, byte[] info, int length) {
        return derive(HmacAlgorithm.SHA256, ikm, salt, info, length);
    }

    /**
     * HKDF Extract + Expand.
     *
     * @param algorithm 알고리즘
     * @param ikm       입력 키 재료
     * @param salt      Salt(없으면 null)
     * @param info      용도 구분 값(없으면 null)
     * @param length    출력 길이(바이트)
     * @return 파생 키
     * @throws IllegalArgumentException IKM이 비었거나 길이가 범위 밖
     */
    public static byte[] derive(HmacAlgorithm algorithm, byte[] ikm, byte[] salt, byte[] info, int length) {
        return expand(algorithm, extract(algorithm, salt, ikm), info, length);
    }

    /**
     * 용도 구분 값을 UTF-8 문자열로 주는 편의 메서드.
     *
     * @param algorithm 알고리즘
     * @param ikm       입력 키 재료
     * @param salt      Salt(없으면 null)
     * @param info      용도 구분 문자열(UTF-8)
     * @param length    출력 길이(바이트)
     * @return 파생 키
     */
    public static byte[] derive(HmacAlgorithm algorithm, byte[] ikm, byte[] salt, String info, int length) {
        return derive(algorithm, ikm, salt, Bytes.utf8(info), length);
    }

    /**
     * HKDF-Extract: PRK = HMAC(salt, IKM).
     *
     * @param algorithm 알고리즘
     * @param salt      Salt(없으면 null → 해시 길이의 0바이트)
     * @param ikm       입력 키 재료(비어 있으면 안 된다)
     * @return PRK(해시 길이)
     */
    public static byte[] extract(HmacAlgorithm algorithm, byte[] salt, byte[] ikm) {
        Text.require(algorithm, "algorithm");
        Text.require(ikm, "ikm");
        if (ikm.length == 0) throw Text.invalid("sec.err.keyEmpty");
        byte[] realSalt = salt == null || salt.length == 0 ? new byte[algorithm.length()] : salt;
        return Hmac.compute(algorithm.jcaName(), realSalt, ikm);
    }

    /**
     * HKDF-Expand: T(1) | T(2) | ... 의 앞 {@code length}바이트.
     *
     * @param algorithm 알고리즘
     * @param prk       PRK(해시 길이 이상)
     * @param info      용도 구분 값(없으면 null)
     * @param length    출력 길이(1 ~ 255 × 해시 길이)
     * @return 파생 키
     */
    public static byte[] expand(HmacAlgorithm algorithm, byte[] prk, byte[] info, int length) {
        Text.require(algorithm, "algorithm");
        Text.require(prk, "prk");
        int hashLength = algorithm.length();
        if (prk.length < hashLength) throw Text.invalid("sec.err.hkdfPrk", hashLength);
        if (length < 1 || length > 255 * hashLength) throw Text.invalid("sec.err.hkdfLength", 255 * hashLength);
        byte[] realInfo = info == null ? new byte[0] : info;
        ByteArrayOutputStream out = new ByteArrayOutputStream(length + hashLength);
        byte[] previous = new byte[0];
        for (int counter = 1; out.size() < length; counter++) {
            previous = Hmac.compute(algorithm.jcaName(), prk, previous, realInfo, new byte[] {(byte) counter});
            out.write(previous, 0, previous.length);
        }
        byte[] all = out.toByteArray();
        byte[] result = new byte[length];
        System.arraycopy(all, 0, result, 0, length);
        Arrays.fill(all, (byte) 0);
        return result;
    }
}
