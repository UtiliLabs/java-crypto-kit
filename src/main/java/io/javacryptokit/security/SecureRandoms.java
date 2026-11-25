package io.javacryptokit.security;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * <b>공개 API</b>: 보안 난수·토큰·Nonce·UUID. 모두 JDK {@link SecureRandom}(운영체제 엔트로피로 시드, 차단형
 * {@code getInstanceStrong} 아님)으로 만들며 시간·PID·서버 번호·고정 Seed·{@code java.util.Random}을 쓰지 않는다.
 *
 * <ul>
 *   <li>{@link #token()}: 32바이트(256비트) 난수를 Base64URL(패딩 없음, 43자)로. 비밀번호 재설정 링크·세션 식별자·API 키 등.</li>
 *   <li>{@link #nonce()}: 16바이트(128비트) 난수를 Base64URL(22자)로. 요청 재전송 방지용 일회 값 등.</li>
 *   <li>{@link #bytes(int)}: 원시 바이트(키·Salt 재료 등).</li>
 *   <li>{@link #uuidV4()}: RFC 9562 UUID 버전 4({@link UUID#randomUUID()}). 추적 ID용이며 비밀 토큰이 아니다.</li>
 * </ul>
 *
 * <p><b>보장 범위</b>: 충돌·추측 가능성은 문자 집합과 길이에 따라 달라지며, <b>절대 유일성이나 일회 사용을 보장하지 않는다</b>. 절대 중복을
 * 막아야 하는 값이나 일회 사용(재전송 방지) 판단이 필요하면 애플리케이션이 자기 저장소(DB UNIQUE 제약 등)에서 처리한다. 실행 중인
 * VM·컨테이너를 스냅샷으로 복제한 직후에는 난수 생성기 상태가 같을 수 있으므로 JVM을 다시 시작한다(특히 Windows Java 8 기본
 * {@code SHA1PRNG}는 스스로 재시드하지 않는다). 스레드 안전하다.</p>
 */
public final class SecureRandoms {
    /** {@link #token()}의 기본 길이(바이트, 256비트). */
    public static final int DEFAULT_TOKEN_BYTES = 32;
    /** {@link #nonce()}의 기본 길이(바이트, 128비트). */
    public static final int DEFAULT_NONCE_BYTES = 16;
    /** 토큰·Nonce 최소 길이(바이트, 128비트). */
    public static final int MIN_TOKEN_BYTES = 16;
    /** 토큰·Nonce 최대 길이(바이트). */
    public static final int MAX_TOKEN_BYTES = 1024;
    /** {@link #bytes(int)} 최대 길이(바이트). */
    public static final int MAX_BYTES = 65536;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int MAX_STRING_LENGTH = 1024;
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";

    /** {@link #string(int, Alphabet)}에서 뽑을 ASCII 문자 집합. */
    public enum Alphabet {
        DIGITS(SecureRandoms.DIGITS),
        UPPER(SecureRandoms.UPPER),
        LOWER(SecureRandoms.LOWER),
        LETTERS(SecureRandoms.UPPER + SecureRandoms.LOWER),
        UPPER_DIGITS(SecureRandoms.UPPER + SecureRandoms.DIGITS),
        LOWER_DIGITS(SecureRandoms.LOWER + SecureRandoms.DIGITS),
        ALPHANUMERIC(SecureRandoms.UPPER + SecureRandoms.LOWER + SecureRandoms.DIGITS);

        private final String characters;

        Alphabet(String characters) {
            this.characters = characters;
        }
    }

    private SecureRandoms() { }

    /**
     * @param length 생성할 문자 수(1~1,024)
     * @param alphabet 사용할 문자 집합
     * @return 접두어 없는 고정 길이 난수 문자열
     */
    public static String string(int length, Alphabet alphabet) {
        return string(length, alphabet, "");
    }

    /**
     * 선택한 집합에서 매 자리를 독립적으로 뽑는다. 짧은 코드는 추측되거나 중복될 수 있다.
     * @param length 접두어를 제외한 난수 문자 수(1~1,024)
     * @param alphabet 사용할 문자 집합
     * @param prefix 결과 앞에 그대로 붙일 문자열(빈 문자열 허용, UTF-16 단위 최대 1,024)
     * @return 접두어와 난수 문자. 첫 자리의 0도 유지한다
     * @throws IllegalArgumentException 인수가 null이거나 길이가 범위 밖
     */
    public static String string(int length, Alphabet alphabet, String prefix) {
        Text.require(alphabet, "alphabet");
        Text.require(prefix, "prefix");
        if (length < 1 || length > MAX_STRING_LENGTH || prefix.length() > MAX_STRING_LENGTH) {
            throw Text.invalid("sec.err.randomStringLength", MAX_STRING_LENGTH);
        }
        String characters = alphabet.characters;
        StringBuilder result = new StringBuilder(prefix.length() + length).append(prefix);
        for (int i = 0; i < length; i++) {
            result.append(characters.charAt(RANDOM.nextInt(characters.length())));
        }
        return result.toString();
    }

    /**
     * @param length 바이트 수(1~65,536)
     * @return 새 난수 바이트
     * @throws IllegalArgumentException 범위 밖
     */
    public static byte[] bytes(int length) {
        if (length < 1 || length > MAX_BYTES) throw Text.invalid("sec.err.randomLength", 1, MAX_BYTES);
        return fill(length);
    }

    /** @return 32바이트 난수의 Base64URL(패딩 없음, 43자) */
    public static String token() {
        return token(DEFAULT_TOKEN_BYTES, Encoding.BASE64_URL);
    }

    /**
     * @param byteLength 난수 바이트 수(16~1,024). 문자 수가 아니다
     * @return Base64URL(패딩 없음) 토큰
     * @throws IllegalArgumentException 범위 밖
     */
    public static String token(int byteLength) {
        return token(byteLength, Encoding.BASE64_URL);
    }

    /**
     * @param byteLength 난수 바이트 수(16~1,024)
     * @param encoding   출력 형식(예: {@link Encoding#HEX})
     * @return 토큰 문자열
     * @throws IllegalArgumentException 범위 밖이거나 형식이 null
     */
    public static String token(int byteLength, Encoding encoding) {
        Text.require(encoding, "encoding");
        if (byteLength < MIN_TOKEN_BYTES || byteLength > MAX_TOKEN_BYTES) {
            throw Text.invalid("sec.err.randomLength", MIN_TOKEN_BYTES, MAX_TOKEN_BYTES);
        }
        return encoding.encode(fill(byteLength));
    }

    /** @return 16바이트 난수의 Base64URL(패딩 없음, 22자) */
    public static String nonce() {
        return token(DEFAULT_NONCE_BYTES, Encoding.BASE64_URL);
    }

    /** @return 새 UUID 버전 4(122비트 난수, version·variant 비트는 RFC 9562 규격) */
    public static UUID uuidV4() {
        return UUID.randomUUID();
    }

    /** 패키지 내부: 검사 없이 난수를 채운다. */
    static byte[] fill(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }
}
