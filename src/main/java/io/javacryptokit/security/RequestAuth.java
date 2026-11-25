package io.javacryptokit.security;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;

/**
 * <b>공개 API</b>: 서버 간 API 요청 인증 보조(HMAC + 시각 + Nonce). 보내는 쪽은 {@link #sign(byte[])}로 시각·Nonce·MAC을 만들어
 * 요청 헤더 등에 담고, 받는 쪽은 {@link #verify}로 MAC과 허용 시간 범위를 확인한다. MAC 계산·비교는 {@link Hmac}, Nonce는
 * {@link SecureRandoms#nonce()}를 그대로 쓴다.
 *
 * <p><b>서명 원본(버전 1, 양쪽이 같아야 함)</b>: {@code "JCK-REQ-AUTH-v1\n" + 시각 + "\n" + nonce + "\n"} 뒤에 호출자가 준 요청
 * 바이트를 그대로 붙여 HMAC을 계산한다. 시각은 Unix 초(10진수), Nonce는 Base64URL 16~128자, MAC은 Base64URL(패딩 없음)이다.
 * 메서드·경로·쿼리·본문 중 무엇을 어떤 바이트로 넣을지는 연계 당사자가 정한다(이 클래스는 JSON 직렬화·헤더 정렬을 강제하지 않는다).
 * 예: {@code (method + "\n" + pathAndQuery + "\n" + Digests.sha256Hex(body)).getBytes(UTF_8)}.</p>
 *
 * <p><b>재전송 방지는 하지 않는다</b>: {@link Result#VALID}는 "키를 가진 쪽이 허용 시간 안에 만든 요청"이라는 뜻일 뿐이며, 같은
 * 요청을 허용 시간 안에 다시 보내도 VALID다. Nonce를 한 번만 받아들여야 하면 애플리케이션이 자기 저장소에서 판단한다.</p>
 *
 * <p>네트워크에서 받은 값의 형식 오류는 예외가 아니라 {@link Result#MALFORMED}로 돌려준다. 객체는 불변이며 스레드 안전하다.</p>
 */
public final class RequestAuth {
    /** 기본 허용 시각 오차(5분). */
    public static final Duration DEFAULT_MAX_SKEW = Duration.ofMinutes(5);
    /** 지정할 수 있는 최대 허용 오차(15분). */
    public static final Duration MAX_ALLOWED_SKEW = Duration.ofMinutes(15);

    private final Hmac hmac;
    private final long maxSkewSeconds;
    private final Clock clock;

    private RequestAuth(Hmac hmac, Duration maxSkew, Clock clock) {
        this.hmac = hmac;
        this.maxSkewSeconds = maxSkew.getSeconds();
        this.clock = clock;
    }

    /**
     * 기본 허용 오차(5분)·시스템 UTC 시계.
     *
     * @param hmac 양쪽이 공유하는 키의 {@link Hmac}
     * @return 객체
     */
    public static RequestAuth of(Hmac hmac) {
        return of(hmac, DEFAULT_MAX_SKEW, Clock.systemUTC());
    }

    /**
     * @param hmac    양쪽이 공유하는 키의 {@link Hmac}
     * @param maxSkew 허용 시각 오차(1초~15분)
     * @param clock   시계(시험·고정 시각용)
     * @return 객체
     */
    public static RequestAuth of(Hmac hmac, Duration maxSkew, Clock clock) {
        Text.require(hmac, "hmac");
        Text.require(maxSkew, "maxSkew");
        Text.require(clock, "clock");
        if (maxSkew.getSeconds() < 1 || maxSkew.compareTo(MAX_ALLOWED_SKEW) > 0) throw Text.invalid("sec.err.skew", MAX_ALLOWED_SKEW.getSeconds());
        return new RequestAuth(hmac, maxSkew, clock);
    }

    /**
     * 현재 시각·새 Nonce로 요청을 서명한다.
     *
     * @param request 서명할 요청 바이트(바꾸지 않는다)
     * @return 시각·Nonce·MAC
     */
    public Signed sign(byte[] request) {
        Text.require(request, "request");
        String timestamp = Long.toString(clock.instant().getEpochSecond());
        String nonce = SecureRandoms.nonce();
        return new Signed(timestamp, nonce, hmac.sign(input(timestamp, nonce, request), Encoding.BASE64_URL));
    }

    /**
     * 받은 요청을 확인한다.
     *
     * @param request   받은 요청 바이트(보낸 쪽과 같은 규칙으로 만든 값)
     * @param timestamp 받은 시각 문자열
     * @param nonce     받은 Nonce
     * @param mac       받은 MAC(Base64URL)
     * @return 판정
     */
    public Result verify(byte[] request, String timestamp, String nonce, String mac) {
        Text.require(request, "request");
        if (timestamp == null || nonce == null || mac == null || !timestamp.matches("[0-9]{1,12}")
                || !nonce.matches("[A-Za-z0-9_-]{16,128}") || !mac.matches("[A-Za-z0-9_-]{1,128}")) {
            return Result.MALFORMED;
        }
        byte[] given;
        try {
            given = Encoding.BASE64_URL.decode(mac);
        } catch (IllegalArgumentException e) {
            return Result.MALFORMED;
        }
        if (given.length != hmac.algorithm().length()) return Result.MALFORMED;
        long now = clock.instant().getEpochSecond();
        if (Math.abs(now - Long.parseLong(timestamp)) > maxSkewSeconds) return Result.TIMESTAMP_OUT_OF_RANGE;
        return hmac.verify(input(timestamp, nonce, request), given) ? Result.VALID : Result.BAD_MAC;
    }

    /** 서명 원본: 버전 표지 + 시각 + Nonce + 요청 바이트. */
    private static byte[] input(String timestamp, String nonce, byte[] request) {
        byte[] header = ("JCK-REQ-AUTH-v1\n" + timestamp + "\n" + nonce + "\n").getBytes(StandardCharsets.US_ASCII);
        byte[] all = Arrays.copyOf(header, header.length + request.length);
        System.arraycopy(request, 0, all, header.length, request.length);
        return all;
    }

    /** 확인 결과. */
    public enum Result {
        /** MAC이 맞고 시각이 허용 범위 안. */
        VALID,
        /** 시각·Nonce·MAC 형식 오류. */
        MALFORMED,
        /** 시각이 허용 오차를 벗어남(오래된 요청·시계 차이). */
        TIMESTAMP_OUT_OF_RANGE,
        /** MAC 불일치(다른 키·변조). */
        BAD_MAC;

        /** @return VALID이면 true */
        public boolean isValid() {
            return this == VALID;
        }
    }

    /** 보내는 쪽 결과(헤더에 담을 값). */
    public static final class Signed {
        private final String timestamp;
        private final String nonce;
        private final String mac;

        Signed(String timestamp, String nonce, String mac) {
            this.timestamp = timestamp;
            this.nonce = nonce;
            this.mac = mac;
        }

        /** @return Unix 초(10진수) */
        public String timestamp() {
            return timestamp;
        }

        /** @return Nonce(Base64URL 22자) */
        public String nonce() {
            return nonce;
        }

        /** @return MAC(Base64URL) */
        public String mac() {
            return mac;
        }

        @Override
        public String toString() {
            return "Signed[timestamp=" + timestamp + "]";
        }
    }
}
