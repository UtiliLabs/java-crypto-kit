package io.javacryptokit.security;

import java.util.OptionalLong;

/**
 * <b>공개 API</b>: HOTP(RFC 4226, 카운터 기반 일회용 비밀번호, HMAC-SHA1).
 *
 * <ul>
 *   <li>비밀키: 16바이트 이상(새 키는 {@link #generateSecret()} 20바이트). 사람에게 보여 줄 때는 {@link Encoding#BASE32}.</li>
 *   <li>자릿수: 6~8(앞자리 0 유지, 문자열로 다룬다).</li>
 *   <li>검증: 주어진 카운터부터 {@code lookAhead}(0~100)까지 확인하고 일치한 카운터를 돌려준다. 카운터 보관과 같은 코드의
 *       재사용 방지는 하지 않는다.</li>
 * </ul>
 * <p>6자리 코드는 우연히 겹칠 수 있으며(유일하지 않음), 시도 횟수 제한·계정 잠금·비밀키 보관은 호출자 책임이다. 비밀키를 로그에
 * 남기지 않는다. 객체는 불변이며 스레드 안전하다.</p>
 */
public final class Hotp {
    /** 비밀키 최소 길이(바이트, RFC 4226: 128비트 이상). */
    public static final int MIN_SECRET_BYTES = 16;
    /** 기본 자릿수. */
    public static final int DEFAULT_DIGITS = 6;
    /** 최대 lookAhead. */
    public static final int MAX_LOOK_AHEAD = 100;
    private static final int[] POWERS = {1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000};

    private final byte[] secret;
    private final int digits;

    private Hotp(byte[] secret, int digits) {
        this.secret = secret.clone();
        this.digits = digits;
    }

    /** @return 새 비밀키(20바이트 보안 난수) */
    public static byte[] generateSecret() {
        return SecureRandoms.fill(OtpAlgorithm.SHA1.secretBytes());
    }

    /**
     * @param secret 비밀키(16바이트 이상, 복사해 보관)
     * @return 6자리 HOTP
     */
    public static Hotp of(byte[] secret) {
        return of(secret, DEFAULT_DIGITS);
    }

    /**
     * @param secret 비밀키(16바이트 이상)
     * @param digits 자릿수(6~8)
     * @return HOTP
     */
    public static Hotp of(byte[] secret, int digits) {
        checkSecret(secret);
        checkDigits(digits);
        return new Hotp(secret, digits);
    }

    /**
     * @param counter 카운터(0 이상)
     * @return 코드(앞자리 0 포함)
     */
    public String generate(long counter) {
        if (counter < 0) throw Text.invalid("sec.err.otpCounter");
        return compute(OtpAlgorithm.SHA1, secret, counter, digits);
    }

    /**
     * @param code      입력 코드
     * @param counter   확인을 시작할 카운터(0 이상)
     * @param lookAhead 앞으로 더 확인할 개수(0~100)
     * @return 일치한 카운터(없거나 코드 형식이 아니면 빈 값)
     */
    public OptionalLong verify(String code, long counter, int lookAhead) {
        if (counter < 0) throw Text.invalid("sec.err.otpCounter");
        if (lookAhead < 0 || lookAhead > MAX_LOOK_AHEAD) throw Text.invalid("sec.err.otpWindow", MAX_LOOK_AHEAD);
        if (!wellFormed(code, digits)) return OptionalLong.empty();
        long last = counter > Long.MAX_VALUE - lookAhead ? Long.MAX_VALUE : counter + lookAhead;
        OptionalLong match = OptionalLong.empty();
        for (long c = counter; c <= last; c++) {
            if (Bytes.equalsConstantTime(compute(OtpAlgorithm.SHA1, secret, c, digits), code) && !match.isPresent()) match = OptionalLong.of(c);
            if (c == Long.MAX_VALUE) break;
        }
        return match;
    }

    @Override
    public String toString() {
        return "Hotp[digits=" + digits + "]";
    }

    // ---------------------------------------------------------------- 공통 계산(TOTP도 사용)

    static String compute(OtpAlgorithm algorithm, byte[] secret, long counter, int digits) {
        byte[] message = new byte[8];
        for (int i = 7; i >= 0; i--) {
            message[i] = (byte) (counter & 0xff);
            counter >>>= 8;
        }
        byte[] hash = Hmac.compute(algorithm.jcaName(), secret, message);
        int offset = hash[hash.length - 1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
        StringBuilder code = new StringBuilder(Integer.toString(binary % POWERS[digits]));
        while (code.length() < digits) code.insert(0, '0');
        return code.toString();
    }

    static void checkSecret(byte[] secret) {
        Text.require(secret, "secret");
        if (secret.length < MIN_SECRET_BYTES) throw Text.invalid("sec.err.otpSecret", MIN_SECRET_BYTES);
    }

    static void checkDigits(int digits) {
        if (digits < 6 || digits > 8) throw Text.invalid("sec.err.otpDigits");
    }

    static boolean wellFormed(String code, int digits) {
        if (code == null || code.length() != digits) return false;
        for (int i = 0; i < code.length(); i++) {
            if (code.charAt(i) < '0' || code.charAt(i) > '9') return false;
        }
        return true;
    }
}
