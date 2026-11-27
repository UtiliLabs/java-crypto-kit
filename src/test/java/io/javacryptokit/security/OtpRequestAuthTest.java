package io.javacryptokit.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

/** OTP-01(RFC 4226·6238 표, otpauth URI)·AUTH-01(요청 서명·시각·형식). */
class OtpRequestAuthTest {
    private static final byte[] SEED20 = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SEED32 = "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SEED64 = "1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.US_ASCII);

    @Test
    void hotpMatchesRfc4226AppendixD() {
        String[] expected = {"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"};
        Hotp hotp = Hotp.of(SEED20);
        for (int i = 0; i < expected.length; i++) assertEquals(expected[i], hotp.generate(i));
        assertEquals(OptionalLong.of(5), hotp.verify("254676", 3, 3), "일치한 카운터를 돌려준다");
        assertFalse(hotp.verify("254676", 6, 3).isPresent(), "이미 지난 카운터는 받지 않는다");
        assertFalse(hotp.verify("25467", 0, 10).isPresent());
        assertFalse(hotp.verify("2546７6", 0, 10).isPresent(), "전각 숫자");
        assertFalse(hotp.verify(null, 0, 10).isPresent());
        assertThrows(IllegalArgumentException.class, () -> hotp.verify("254676", 0, 101));
        assertThrows(IllegalArgumentException.class, () -> Hotp.of(new byte[15]));
        assertThrows(IllegalArgumentException.class, () -> Hotp.of(SEED20, 9));
        assertEquals(20, Hotp.generateSecret().length);
    }

    @Test
    void totpMatchesRfc6238AppendixBForAllAlgorithms() {
        long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[][] codes = {
            {"94287082", "46119246", "90693936"}, {"07081804", "68084774", "25091201"}, {"14050471", "67062674", "99943326"},
            {"89005924", "91819424", "93441116"}, {"69279037", "90698825", "38618901"}, {"65353130", "77737706", "47863826"}};
        Totp sha1 = Totp.of(SEED20, OtpAlgorithm.SHA1, 8, Duration.ofSeconds(30));
        Totp sha256 = Totp.of(SEED32, OtpAlgorithm.SHA256, 8, Duration.ofSeconds(30));
        Totp sha512 = Totp.of(SEED64, OtpAlgorithm.SHA512, 8, Duration.ofSeconds(30));
        for (int i = 0; i < times.length; i++) {
            Instant time = Instant.ofEpochSecond(times[i]);
            assertEquals(codes[i][0], sha1.generate(time));
            assertEquals(codes[i][1], sha256.generate(time));
            assertEquals(codes[i][2], sha512.generate(Clock.fixed(time, ZoneOffset.UTC)));
        }
        Instant t = Instant.ofEpochSecond(1111111109L);
        assertEquals(OptionalLong.of(1111111109L / 30), sha1.verify("07081804", t, 0));
        assertEquals(OptionalLong.of(1111111109L / 30), sha1.verify("07081804", t.plusSeconds(30), 1), "허용창 1이면 이전 구간 허용");
        assertFalse(sha1.verify("07081804", t.plusSeconds(60), 1).isPresent(), "허용창 밖");
        assertFalse(sha1.verify("7081804", t, 1).isPresent(), "앞자리 0을 지우면 불일치");
        assertThrows(IllegalArgumentException.class, () -> sha1.verify("07081804", t, 11));
        assertThrows(IllegalArgumentException.class, () -> Totp.of(SEED20, OtpAlgorithm.SHA1, 6, Duration.ofMillis(30_500)));
        assertThrows(IllegalArgumentException.class, () -> sha1.generate(Instant.ofEpochSecond(-1)));
        assertEquals(6, Totp.of(Totp.generateSecret()).generate(Instant.now()).length());
        assertEquals(64, Totp.generateSecret(OtpAlgorithm.SHA512).length);
    }

    @Test
    void otpauthUriIsEncodedAndHidesNothingButMustNotBeLogged() {
        Totp totp = Totp.of(SEED20);
        String uri = totp.otpauthUri("JCK 예제", "user@example.com");
        assertEquals("otpauth://totp/JCK%20%EC%98%88%EC%A0%9C:user%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                + "&issuer=JCK%20%EC%98%88%EC%A0%9C&algorithm=SHA1&digits=6&period=30", uri);
        assertThrows(IllegalArgumentException.class, () -> totp.otpauthUri("a:b", "user"));
        assertThrows(IllegalArgumentException.class, () -> totp.otpauthUri("issuer", ""));
        assertFalse(totp.toString().contains("GEZDGNBV"), "toString에 비밀키 없음");
    }

    @Test
    void requestSigningUsesTheVerifierTimestampRange() {
        Hmac shared = Hmac.of(Hmac.generateKey());
        byte[] request = "request".getBytes(StandardCharsets.UTF_8);
        for (long seconds : new long[] {0, 999_999_999_999L}) {
            RequestAuth auth = RequestAuth.of(shared, Duration.ofMinutes(5), Clock.fixed(Instant.ofEpochSecond(seconds), ZoneOffset.UTC));
            RequestAuth.Signed signed = auth.sign(request);
            assertEquals(Long.toString(seconds), signed.timestamp());
            assertEquals(RequestAuth.Result.VALID, auth.verify(request, signed.timestamp(), signed.nonce(), signed.mac()));
        }
        for (long seconds : new long[] {-1, 1_000_000_000_000L}) {
            RequestAuth auth = RequestAuth.of(shared, Duration.ofMinutes(5), Clock.fixed(Instant.ofEpochSecond(seconds), ZoneOffset.UTC));
            assertThrows(IllegalArgumentException.class, () -> auth.sign(request));
        }
    }

    @Test
    void requestAuthenticationChecksMacTimeAndFormat() {
        Instant now = Instant.parse("2026-11-24T00:00:00Z");
        Hmac shared = Hmac.of(Hmac.generateKey());
        RequestAuth sender = RequestAuth.of(shared, Duration.ofMinutes(5), Clock.fixed(now, ZoneOffset.UTC));
        byte[] request = ("POST\n/orders?id=1\n" + Digests.sha256Hex("{\"금액\":1000}")).getBytes(StandardCharsets.UTF_8);
        RequestAuth.Signed signed = sender.sign(request);
        assertEquals(Long.toString(now.getEpochSecond()), signed.timestamp());
        assertEquals(22, signed.nonce().length());
        assertEquals(RequestAuth.Result.VALID, sender.verify(request, signed.timestamp(), signed.nonce(), signed.mac()));
        RequestAuth late = RequestAuth.of(shared, Duration.ofMinutes(5), Clock.fixed(now.plusSeconds(301), ZoneOffset.UTC));
        assertEquals(RequestAuth.Result.TIMESTAMP_OUT_OF_RANGE, late.verify(request, signed.timestamp(), signed.nonce(), signed.mac()));
        RequestAuth early = RequestAuth.of(shared, Duration.ofMinutes(5), Clock.fixed(now.minusSeconds(301), ZoneOffset.UTC));
        assertEquals(RequestAuth.Result.TIMESTAMP_OUT_OF_RANGE, early.verify(request, signed.timestamp(), signed.nonce(), signed.mac()));
        byte[] changed = request.clone();
        changed[0] = 'G';
        assertEquals(RequestAuth.Result.BAD_MAC, sender.verify(changed, signed.timestamp(), signed.nonce(), signed.mac()));
        assertEquals(RequestAuth.Result.BAD_MAC, sender.verify(request, signed.timestamp(), SecureRandoms.nonce(), signed.mac()), "Nonce도 MAC에 묶임");
        assertEquals(RequestAuth.Result.BAD_MAC, sender.verify(request, Long.toString(now.getEpochSecond() - 1), signed.nonce(), signed.mac()));
        RequestAuth otherKey = RequestAuth.of(Hmac.of(Hmac.generateKey()), Duration.ofMinutes(5), Clock.fixed(now, ZoneOffset.UTC));
        assertEquals(RequestAuth.Result.BAD_MAC, otherKey.verify(request, signed.timestamp(), signed.nonce(), signed.mac()));
        String[][] malformed = {{null, signed.nonce(), signed.mac()}, {"-1", signed.nonce(), signed.mac()}, {"12a", signed.nonce(), signed.mac()},
            {signed.timestamp(), "short", signed.mac()}, {signed.timestamp(), signed.nonce(), "not base64url!"},
            {signed.timestamp(), signed.nonce(), signed.mac() + "A"}};
        for (String[] m : malformed) assertEquals(RequestAuth.Result.MALFORMED, sender.verify(request, m[0], m[1], m[2]));
        assertThrows(IllegalArgumentException.class, () -> RequestAuth.of(shared, Duration.ofMinutes(16), Clock.systemUTC()));
        assertTrue(RequestAuth.Result.VALID.isValid());
    }
}
