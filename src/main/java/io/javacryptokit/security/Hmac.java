package io.javacryptokit.security;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * <b>공개 API</b>: HMAC(공유 비밀키로 만드는 메시지 인증 코드) 생성·검증.
 *
 * <p><b>언제 쓰는가</b>: 두 시스템이 같은 비밀키를 나눠 갖고, 메시지가 바뀌지 않았고 키를 가진 쪽이 보냈는지 확인할 때(서버 간
 * API 요청 서명, 웹훅 검증, 전문 위변조 확인). <b>암호화가 아니다</b>(메시지 내용은 그대로 보인다). 재전송 방지는 하지 않는다
 * ({@link RequestAuth}와 공유 저장소의 Nonce 소비를 함께 쓴다). 서명한 쪽만 키를 가져야 하면 {@link Signatures}를 쓴다.</p>
 *
 * <p><b>두 가지 생성 경로</b></p>
 * <ul>
 *   <li>{@link #of(HmacAlgorithm, byte[])}: 일반·신규 키 경로. 키는 32바이트 이상이어야 한다. 새 키는
 *       {@link #generateKey(HmacAlgorithm)}(SHA256 32바이트, SHA512 64바이트 보안 난수)로 만든다.</li>
 *   <li>{@link #ofExternalKey(HmacAlgorithm, byte[])}: 외부 시스템이 이미 정한 짧은 비밀(예: 웹훅 비밀 문자열)과 연동할 때만
 *       쓰는 호환 경로. 1바이트 이상이면 받는다. 새 키를 만들 때 쓰지 않는다. JWT HS256은 이 경로를 쓰지 않으며 항상 32바이트
 *       이상을 요구한다.</li>
 * </ul>
 * <p>키를 조용히 늘이거나 자르지 않는다. 문자열은 UTF-8 바이트로 MAC을 만들며 원본을 다시 직렬화·정규화하지 않는다.
 * {@code verify}는 계산한 MAC과 안전 비교({@link Bytes#equalsConstantTime})하며, 값이 다르면 {@code false}, MAC 문자열이 지정한
 * 형식이 아니면 {@link IllegalArgumentException}이다. 객체는 불변이고(키는 복사해 보관) 호출마다 새 {@link Mac}을 만들므로 여러
 * 스레드에서 함께 써도 된다. {@code toString}에 키를 넣지 않는다.</p>
 */
public final class Hmac {
    /** 일반 경로의 최소 키 길이(바이트, 256비트). */
    public static final int MIN_KEY_BYTES = 32;

    private final HmacAlgorithm algorithm;
    private final byte[] key;

    private Hmac(HmacAlgorithm algorithm, byte[] key) {
        this.algorithm = algorithm;
        this.key = key.clone();
    }

    /** @return 새 HMAC-SHA256 키(32바이트 보안 난수) */
    public static byte[] generateKey() {
        return generateKey(HmacAlgorithm.SHA256);
    }

    /**
     * @param algorithm 알고리즘
     * @return 새 키(SHA256 32바이트, SHA512 64바이트 보안 난수)
     */
    public static byte[] generateKey(HmacAlgorithm algorithm) {
        Text.require(algorithm, "algorithm");
        return SecureRandoms.fill(algorithm.length());
    }

    /**
     * HMAC-SHA256 객체(일반 경로).
     *
     * @param key 32바이트 이상 키(복사해 보관한다)
     * @return 객체
     * @throws IllegalArgumentException 키가 null이거나 32바이트 미만
     */
    public static Hmac of(byte[] key) {
        return of(HmacAlgorithm.SHA256, key);
    }

    /**
     * 일반 경로.
     *
     * @param algorithm 알고리즘
     * @param key       32바이트 이상 키(복사해 보관한다)
     * @return 객체
     * @throws IllegalArgumentException 키가 null이거나 32바이트 미만
     */
    public static Hmac of(HmacAlgorithm algorithm, byte[] key) {
        Text.require(algorithm, "algorithm");
        Text.require(key, "key");
        if (key.length < MIN_KEY_BYTES) throw Text.invalid("sec.err.hmacKeyShort", MIN_KEY_BYTES);
        return new Hmac(algorithm, key);
    }

    /**
     * 외부 시스템이 정한 기존 비밀과 연동하는 호환 경로(1바이트 이상). 새 키에는 {@link #of}를 쓴다.
     *
     * @param algorithm 알고리즘
     * @param key       외부 시스템의 비밀(복사해 보관한다)
     * @return 객체
     * @throws IllegalArgumentException 키가 null이거나 비어 있음
     */
    public static Hmac ofExternalKey(HmacAlgorithm algorithm, byte[] key) {
        Text.require(algorithm, "algorithm");
        Text.require(key, "key");
        if (key.length == 0) throw Text.invalid("sec.err.keyEmpty");
        return new Hmac(algorithm, key);
    }

    /** @return 알고리즘 */
    public HmacAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * @param data 원본(바꾸지 않는다)
     * @return MAC
     */
    public byte[] sign(byte[] data) {
        return compute(algorithm.jcaName(), key, Text.require(data, "data"));
    }

    /**
     * @param text 원본 문자열(UTF-8)
     * @return MAC
     */
    public byte[] sign(String text) {
        return sign(Bytes.utf8(text));
    }

    /**
     * @param data     원본
     * @param encoding 출력 형식
     * @return 인코딩한 MAC
     */
    public String sign(byte[] data, Encoding encoding) {
        return Text.require(encoding, "encoding").encode(sign(data));
    }

    /**
     * @param text     원본 문자열(UTF-8)
     * @param encoding 출력 형식
     * @return 인코딩한 MAC
     */
    public String sign(String text, Encoding encoding) {
        return Text.require(encoding, "encoding").encode(sign(text));
    }

    /**
     * @param data 원본
     * @param mac  받은 MAC
     * @return MAC이 맞으면 true(null·빈 값·길이가 다른 값은 false)
     */
    public boolean verify(byte[] data, byte[] mac) {
        return Bytes.equalsConstantTime(sign(data), mac);
    }

    /**
     * @param data     원본
     * @param mac      받은 MAC 문자열
     * @param encoding MAC 문자열의 형식
     * @return MAC이 맞으면 true
     * @throws IllegalArgumentException MAC 문자열이 그 형식이 아님
     */
    public boolean verify(byte[] data, String mac, Encoding encoding) {
        Text.require(encoding, "encoding");
        return verify(data, encoding.decode(Text.require(mac, "mac")));
    }

    /**
     * @param text     원본 문자열(UTF-8)
     * @param mac      받은 MAC 문자열
     * @param encoding MAC 문자열의 형식
     * @return MAC이 맞으면 true
     * @throws IllegalArgumentException MAC 문자열이 그 형식이 아님
     */
    public boolean verify(String text, String mac, Encoding encoding) {
        return verify(Bytes.utf8(text), mac, encoding);
    }

    @Override
    public String toString() {
        return "Hmac[" + algorithm + "]";
    }

    /** 패키지 내부: HMAC 한 번(키 길이 정책은 호출자가 정한다). 입력 조각을 순서대로 넣는다. */
    static byte[] compute(String jcaName, byte[] key, byte[]... parts) {
        try {
            Mac mac = Mac.getInstance(jcaName);
            mac.init(new SecretKeySpec(key, jcaName));
            for (byte[] part : parts) mac.update(part);
            return mac.doFinal();
        } catch (InvalidKeyException e) {
            throw Text.invalid("sec.err.keyEmpty");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(Text.get("sec.err.provider", jcaName));
        }
    }
}
