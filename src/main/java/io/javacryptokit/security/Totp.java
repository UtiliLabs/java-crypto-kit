package io.javacryptokit.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalLong;

/**
 * <b>공개 API</b>: TOTP(RFC 6238, 시간 기반 일회용 비밀번호). 기본은 인증 앱과 가장 잘 맞는 SHA1·6자리·30초다.
 *
 * <ul>
 *   <li>시간 구간(step) = floor(Unix 초 / 주기). {@link #generate(Instant)}·{@link #verify(String, Instant, int)}는 시각을
 *       명시로 받고, {@link Clock} 판도 있다(시험·서버 시계 주입).</li>
 *   <li>검증 허용창 {@code window}(0~10): 현재 구간 앞뒤로 몇 구간까지 받을지(보통 1 = ±30초). 일치한 구간 번호를 돌려준다
 *       (같은 코드의 재사용 방지는 하지 않는다).</li>
 *   <li>{@link #otpauthUri}: 인증 앱 등록용 {@code otpauth://totp/...} URI(QR 코드로 만든다). <b>비밀키가 들어 있으므로</b>
 *       로그·URL 접근 기록·오류 메시지에 남기지 않는다.</li>
 * </ul>
 * <p>6자리 코드는 우연히 겹칠 수 있으며(유일하지 않음), 계정별 시도 제한·비밀키 보관·사용 기록은 호출자 책임이다. 일부 인증 앱은
 * SHA1이 아닌 알고리즘·6이 아닌 자릿수·30초가 아닌 주기를 무시할 수 있으므로 앱으로 실제 확인한다. 객체는 불변이며 스레드 안전하다.</p>
 */
public final class Totp {
    /** 기본 주기. */
    public static final Duration DEFAULT_PERIOD = Duration.ofSeconds(30);
    /** 최대 허용창(앞뒤 구간 수). */
    public static final int MAX_WINDOW = 10;

    private final byte[] secret;
    private final OtpAlgorithm algorithm;
    private final int digits;
    private final long periodSeconds;

    private Totp(byte[] secret, OtpAlgorithm algorithm, int digits, long periodSeconds) {
        this.secret = secret.clone();
        this.algorithm = algorithm;
        this.digits = digits;
        this.periodSeconds = periodSeconds;
    }

    /** @return 새 SHA1용 비밀키(20바이트 보안 난수) */
    public static byte[] generateSecret() {
        return generateSecret(OtpAlgorithm.SHA1);
    }

    /**
     * @param algorithm 알고리즘
     * @return 새 비밀키(SHA1 20, SHA256 32, SHA512 64바이트)
     */
    public static byte[] generateSecret(OtpAlgorithm algorithm) {
        return SecureRandoms.fill(Text.require(algorithm, "algorithm").secretBytes());
    }

    /**
     * @param secret 비밀키(16바이트 이상, 복사해 보관)
     * @return SHA1·6자리·30초 TOTP
     */
    public static Totp of(byte[] secret) {
        return of(secret, OtpAlgorithm.SHA1, Hotp.DEFAULT_DIGITS, DEFAULT_PERIOD);
    }

    /**
     * @param secret    비밀키(16바이트 이상)
     * @param algorithm 알고리즘
     * @param digits    자릿수(6~8)
     * @param period    주기(15~300초, 초 단위)
     * @return TOTP
     */
    public static Totp of(byte[] secret, OtpAlgorithm algorithm, int digits, Duration period) {
        Hotp.checkSecret(secret);
        Text.require(algorithm, "algorithm");
        Hotp.checkDigits(digits);
        Text.require(period, "period");
        if (period.getNano() != 0 || period.getSeconds() < 15 || period.getSeconds() > 300) throw Text.invalid("sec.err.otpPeriod");
        return new Totp(secret, algorithm, digits, period.getSeconds());
    }

    /**
     * @param time 시각(1970년 이후)
     * @return 그 시각의 시간 구간 번호
     */
    public long timeStep(Instant time) {
        Text.require(time, "time");
        if (time.getEpochSecond() < 0) throw Text.invalid("sec.err.otpCounter");
        return time.getEpochSecond() / periodSeconds;
    }

    /**
     * @param time 시각
     * @return 그 시각의 코드(앞자리 0 포함)
     */
    public String generate(Instant time) {
        return Hotp.compute(algorithm, secret, timeStep(time), digits);
    }

    /**
     * @param clock 시계
     * @return 현재 코드
     */
    public String generate(Clock clock) {
        return generate(Text.require(clock, "clock").instant());
    }

    /**
     * @param code   입력 코드
     * @param time   기준 시각
     * @param window 앞뒤로 받을 구간 수(0~10)
     * @return 일치한 시간 구간 번호(없거나 형식이 아니면 빈 값)
     */
    public OptionalLong verify(String code, Instant time, int window) {
        if (window < 0 || window > MAX_WINDOW) throw Text.invalid("sec.err.otpWindow", MAX_WINDOW);
        long current = timeStep(time);
        if (!Hotp.wellFormed(code, digits)) return OptionalLong.empty();
        OptionalLong match = OptionalLong.empty();
        for (long step = Math.max(0, current - window); step <= current + window; step++) {
            if (Bytes.equalsConstantTime(Hotp.compute(algorithm, secret, step, digits), code) && !match.isPresent()) match = OptionalLong.of(step);
        }
        return match;
    }

    /**
     * @param code   입력 코드
     * @param clock  시계
     * @param window 앞뒤로 받을 구간 수(0~10)
     * @return 일치한 시간 구간 번호
     */
    public OptionalLong verify(String code, Clock clock, int window) {
        return verify(code, Text.require(clock, "clock").instant(), window);
    }

    /**
     * 인증 앱 등록용 URI({@code otpauth://totp/발급자:계정?secret=...&issuer=...&algorithm=...&digits=...&period=...}).
     * <b>비밀키가 들어 있다</b>: 화면의 QR 코드로만 보여 주고 로그·URL 기록·오류 메시지에 남기지 않는다.
     *
     * @param issuer      서비스 이름(1~100자, {@code :} 불가)
     * @param accountName 사용자 계정(1~100자, {@code :} 불가)
     * @return otpauth URI
     */
    public String otpauthUri(String issuer, String accountName) {
        checkLabel(issuer);
        checkLabel(accountName);
        return "otpauth://totp/" + percent(issuer) + ":" + percent(accountName)
                + "?secret=" + Encoding.BASE32.encode(secret)
                + "&issuer=" + percent(issuer)
                + "&algorithm=" + algorithm.name()
                + "&digits=" + digits
                + "&period=" + periodSeconds;
    }

    @Override
    public String toString() {
        return "Totp[" + algorithm + ", digits=" + digits + ", period=" + periodSeconds + "s]";
    }

    private static void checkLabel(String value) {
        Text.require(value, "label");
        if (value.isEmpty() || value.length() > 100 || value.indexOf(':') >= 0) throw Text.invalid("sec.err.otpLabel");
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) throw Text.invalid("sec.err.otpLabel");
        }
    }

    /** RFC 3986 퍼센트 인코딩(예약되지 않은 문자 외 전부, 공백은 %20). */
    private static String percent(String value) {
        StringBuilder out = new StringBuilder();
        for (byte b : Bytes.utf8(value)) {
            int c = b & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {
                out.append((char) c);
            } else {
                out.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16))).append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return out.toString();
    }
}
