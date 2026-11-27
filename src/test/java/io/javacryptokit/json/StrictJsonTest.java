package io.javacryptokit.json;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 공용 엄격 JSON(Vault 응답·JWT·OAuth Introspection): 기존 Vault 파서 시험(문법·제어문자·깊이)을 그대로 옮기고, 중복 키·이스케이프·
 * 서로게이트·숫자 범위·상한·작성기 규칙을 추가로 확인한다.
 */
class StrictJsonTest {
    @Test
    void parsesValidJsonAsBeforeAndRejectsBrokenInput() {
        assertEquals("v", StrictJson.path(StrictJson.parse("{\"a\":{\"b\":\"v\"}}"), "a", "b"));
        assertEquals(3L, StrictJson.path(StrictJson.parse("{\"n\":3}"), "n"));
        assertEquals("\u00e9", StrictJson.parse("\"\\u00e9\""));
        assertEquals("\ud83d\ude00", StrictJson.parse("\"\\ud83d\\ude00\""), "서로게이트 쌍 이스케이프");
        assertEquals(Arrays.asList(1L, -0L, 2.5, 1.0E10, true, false, null), StrictJson.parse(" [1, -0, 2.5, 1e10, true, false, null] "));
        assertEquals(Long.MAX_VALUE, StrictJson.parse("9223372036854775807"));
        String[] bad = {"{", "{\"a\":}", "[1,]", "{\"a\":1}x", "\"\u0001\"", "tru",
            "{\"a\":1,\"a\":2}", "{\"a\":{\"x\":1,\"x\":1}}",           // 중복 키(마지막 값 채택 금지)
            "\"\\u12\"", "\"\\u+123\"", "\"\\u-123\"", "\"\\x41\"",       // 잘못된 이스케이프
            "\"\\ud83d\"", "\"\\ude00\"", "\"\\ud83d\\u0041\"",           // 짝 없는 서로게이트
            "9223372036854775808", "-9223372036854775809", "1e400",       // 범위 밖
            "01", "1.", ".5", "+1", "1e", "-", "NaN", "Infinity", "0x10", // 문법
            "'a'", "{a:1}", "[1 2]", "\"a\"\"b\"", ""};
        for (String value : bad) assertThrows(IllegalArgumentException.class, () -> StrictJson.parse(value), value);
        StringBuilder deep = new StringBuilder();
        for (int i = 0; i < 50; i++) deep.append('[');
        assertThrows(IllegalArgumentException.class, () -> StrictJson.parse(deep.toString()), "깊이 제한");
    }

    @Test
    void directUnicodeSurrogatesAreCheckedInNamesAndValues() {
        for (char unpaired : new char[] {'\ud800', '\udfff'}) {
            String badValue = "{\"키\":\"" + unpaired + "\"}";
            String badName = "{\"" + unpaired + "\":\"값\"}";
            assertThrows(IllegalArgumentException.class, () -> StrictJson.parse(badValue));
            assertThrows(IllegalArgumentException.class, () -> StrictJson.parse(badName));
            assertThrows(IllegalArgumentException.class, () -> io.javacryptokit.jwt.JwtClaims.parse(badValue));
            assertThrows(IllegalArgumentException.class, () -> io.javacryptokit.jwt.JwtClaims.parse(badName));
        }
        String json = "{\"한글😀\":\"Grüße 世界 \ud83d\ude03\"}";
        io.javacryptokit.jwt.JwtClaims claims = io.javacryptokit.jwt.JwtClaims.parse(json);
        assertEquals("Grüße 世界 😃", claims.getString("한글😀"));
        assertEquals(json, claims.toJson());
        assertEquals(StrictJson.parse(json), StrictJson.parse(StrictJson.write(StrictJson.parse(json))));
    }

    @Test
    void limitsAreEnforced() {
        StrictJson.Limits small = StrictJson.Limits.of(2, 2, 2, 5);
        assertEquals(2, ((Map<?, ?>) StrictJson.parse("{\"a\":1,\"b\":[1,2]}", small)).size());
        assertThrows(IllegalArgumentException.class, () -> StrictJson.parse("{\"a\":1,\"b\":2,\"c\":3}", small), "멤버 수");
        assertThrows(IllegalArgumentException.class, () -> StrictJson.parse("[1,2,3]", small), "배열 길이");
        assertThrows(IllegalArgumentException.class, () -> StrictJson.parse("[[[1]]]", small), "깊이");
        assertThrows(IllegalArgumentException.class, () -> StrictJson.parse("\"abcdef\"", small), "문자열 길이");
        StringBuilder longNumber = new StringBuilder("0.");
        for (int i = 0; i < 70; i++) longNumber.append('1');
        assertThrows(IllegalArgumentException.class, () -> StrictJson.parse(longNumber.toString()), "숫자 길이");
    }

    @Test
    void writerEscapesAndRoundTrips() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("s", "따옴표\" 역슬래시\\ 줄\n탭\t제어\u0001 이모지\ud83d\ude00");
        value.put("n", 42L);
        value.put("d", 2.5);
        value.put("b", true);
        value.put("z", null);
        value.put("l", Arrays.asList("a", 1L));
        String json = StrictJson.write(value);
        assertEquals("{\"s\":\"따옴표\\\" 역슬래시\\\\ 줄\\n탭\\t제어\\u0001 이모지\ud83d\ude00\",\"n\":42,\"d\":2.5,\"b\":true,\"z\":null,\"l\":[\"a\",1]}", json);
        assertEquals(value, StrictJson.parse(json));
        assertThrows(IllegalArgumentException.class, () -> StrictJson.write("a\ud800"));
        assertThrows(IllegalArgumentException.class, () -> StrictJson.write(Double.POSITIVE_INFINITY));
        assertThrows(IllegalArgumentException.class, () -> StrictJson.write(new Object()));
    }
}
