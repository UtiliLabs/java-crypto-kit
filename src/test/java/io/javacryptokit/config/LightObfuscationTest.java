package io.javacryptokit.config;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javacryptokit.key.KeyResolver;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import org.junit.jupiter.api.Test;

/**
 * JAR 안 저장 값의 경량 난독화(obf1): 가역·결정적 표현, 버전 표시, 손상·모르는 버전 거부(Fail Closed), 구형 평문 그대로 읽기.
 * 단순 열람 방지일 뿐 암호화가 아니며(되돌리는 방법이 공개되어 있음) 키 바이트·지문은 바뀌지 않는다.
 */
class LightObfuscationTest {
    @Test
    void valuesRoundTripDeterministicallyAndDoNotShowThePlainText() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        String encoded = LightObfuscation.encode(key);
        assertTrue(encoded.startsWith("obf1:") && encoded.substring(5).matches("[A-Za-z0-9_-]+"), encoded);
        assertTrue(LightObfuscation.isEncoded(encoded));
        assertFalse(encoded.contains(Base64.getEncoder().encodeToString(key)), "표준 Base64 원문이 보이면 안 된다");
        assertArrayEquals(key, LightObfuscation.decode(encoded));
        assertEquals(encoded, LightObfuscation.encode(key), "같은 값은 같은 표현(재편집해도 바뀌지 않음)");
        // 긴 본문(이력 파일)도 같은 규칙: 키 스트림 블록 경계를 넘는 길이
        byte[] text = "#1 사유: 고유한 사유 문구 / reason: unique text\n".getBytes(StandardCharsets.UTF_8);
        byte[] file = LightObfuscation.encodeFile(text);
        assertFalse(new String(file, StandardCharsets.US_ASCII).contains("reason"), "이력 본문이 글자 그대로 보이면 안 된다");
        assertArrayEquals(text, LightObfuscation.decodeFile(file));
    }

    @Test
    void theFormatMatchesAnIndependentlyComputedVectorAcrossThePrecomputedPadBoundary() {
        // 형식 고정: 사양(확인값 = SHA-256("java-crypto-kit/obf1/check"||0x00||데이터) 앞 4바이트, 키 스트림 블록 i =
        // SHA-256("java-crypto-kit/obf1/pad"||0x00||i 4바이트 big-endian))대로 별도 계산한 값과 같아야 한다.
        // 204바이트 본문은 미리 계산한 앞 128바이트와 그 뒤 계산 구간을 모두 지난다.
        byte[] data = new byte[200];
        for (int i = 0; i < data.length; i++) data[i] = (byte) i;
        String expected = "obf1:Nb3n6wYeXjenxK5AkyR7moMjohx0H5zKp-GL0C8mdPX9Zdv-FRv2HK30C5dKdg6IcXzPiRJCZ1WU-HEqRVdR5bY-feFJ-nkk9SDb9aEf4Er12qLMrf4l"
                + "noakDNtSv7XxetEJazgaj5V2VoIEdrH2aFIQhv56ljhBkNwCXnSNrmQpJH8KZO79h8DJIWgvJuE-PRXdjFkSnuHne4wQt0xIdUnycQkO8rhioypJF0tK_OgPhIAw69KZ_eLh"
                + "7OLk5QTXUlPBQm50FBC5G5KP";
        assertEquals(expected, LightObfuscation.encode(data));
        assertArrayEquals(data, LightObfuscation.decode(expected));
        // 짧은 값(내장 키 32바이트)도 같은 규칙: 왕복과 결정성
        byte[] key = Arrays.copyOf(data, 32);
        assertArrayEquals(key, LightObfuscation.decode(LightObfuscation.encode(key)));
    }

    @Test
    void damagedOrUnknownVersionsAreRejectedAndPlainLegacyValuesPassThrough() {
        String encoded = LightObfuscation.encode(new byte[32]);
        int at = encoded.length() - 4;
        String damaged = encoded.substring(0, at) + (encoded.charAt(at) == 'A' ? 'B' : 'A') + encoded.substring(at + 1);
        assertThrows(SafeMessageException.class, () -> LightObfuscation.decode(damaged), "확인값 불일치");
        assertThrows(SafeMessageException.class, () -> LightObfuscation.decode("obf1:!!"), "Base64url 아님");
        assertThrows(SafeMessageException.class, () -> LightObfuscation.decode("obf1:AA"), "확인값보다 짧음");
        assertTrue(LightObfuscation.isEncoded("obf2:AAAA"), "버전 표시가 있으면 난독화 값으로 본다");
        assertThrows(SafeMessageException.class, () -> LightObfuscation.decode("obf2:AAAA"), "모르는 버전");
        assertThrows(SafeMessageException.class, () -> LightObfuscation.decodeFile("obf9:AAAA\n".getBytes(StandardCharsets.US_ASCII)));
        // 표준 Base64에는 ':'가 없으므로 구형 평문 키와 겹치지 않는다. 표시 없는 구형 평문 이력은 그대로 읽는다.
        assertFalse(LightObfuscation.isEncoded("obfA2xQ9VbVd8P2m0r0p+Yc1rQh6HqY3c5m3q5k7a4w="));
        byte[] legacy = "# history\nformat.version=1\n".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(legacy, LightObfuscation.decodeFile(legacy));
        // 손상 메시지에는 값이 들어가지 않는다.
        SafeMessageException e = assertThrows(SafeMessageException.class, () -> LightObfuscation.decode(damaged));
        assertFalse(e.getMessage().contains(damaged.substring(5, 15)), e.getMessage());
    }

    @Test
    void publicDefaultKeysInTheJarUseObf1AndKeepTheirPublishedKeys() throws Exception {
        Properties jar = new Properties();
        try (InputStream in = LightObfuscationTest.class.getResourceAsStream("/java-crypto-kit.properties");
             Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            jar.load(reader);
        }
        String slot = jar.getProperty("crypto.key.embedded");
        String pass = jar.getProperty("crypto.keys.pass-default.embedded");
        assertTrue(slot.startsWith("obf1:") && pass.startsWith("obf1:"), "공개 기본 키도 같은 obf1 표현");
        // 키 바이트는 이전 형식와 같다: 공개된 지문(default·pass-default)이 그대로다.
        assertEquals("aac695cbd2498e97131ae49579a219c5e7f41e87e2738ba49199847c00e41a49",
                KeyResolver.fingerprint(KeyResolver.decodeEmbedded(slot)));
        assertEquals("3dca588c78a17aad886e9403e8743990d79d479bbe610664adc3ff7e94453656",
                KeyResolver.fingerprint(KeyResolver.decodeEmbedded(pass)));
        // 외부 공급원(키 파일·환경변수)은 keygen 표준 Base64만 받는다(obf1은 JAR 내부 표현).
        assertThrows(IllegalArgumentException.class, () -> KeyResolver.decodeKey(slot));
        assertArrayEquals(KeyResolver.decodeEmbedded(slot),
                KeyResolver.decodeKey(Base64.getEncoder().encodeToString(KeyResolver.decodeEmbedded(slot))));
    }
}
