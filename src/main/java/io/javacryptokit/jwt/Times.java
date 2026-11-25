package io.javacryptokit.jwt;

import java.time.Instant;

/** 패키지 내부: NumericDate 범위(0 ~ 9999-12-31T23:59:59Z)와 소수 초 변환. 범위 밖은 산술 넘침 없이 거부한다. */
final class Times {
    /** 9999-12-31T23:59:59Z. */
    static final long MAX_SECONDS = 253_402_300_799L;

    private Times() { }

    static boolean validFraction(double value) {
        return !Double.isNaN(value) && !Double.isInfinite(value) && value >= 0 && value <= MAX_SECONDS;
    }

    static Instant fractional(double value) {
        long seconds = (long) Math.floor(value);
        long nanos = (long) Math.floor((value - seconds) * 1_000_000_000L);
        return Instant.ofEpochSecond(seconds, Math.min(nanos, 999_999_999L));
    }
}
