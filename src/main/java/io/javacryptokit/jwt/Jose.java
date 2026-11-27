package io.javacryptokit.jwt;

import io.javacryptokit.i18n.Messages;
import io.javacryptokit.json.StrictJson;
import io.javacryptokit.security.Bytes;
import io.javacryptokit.security.Encoding;
import java.util.Locale;
import java.util.Map;

/**
 * 패키지 내부: JOSE 공통 규칙(엄격한 Base64URL, 세 구간, 엄격한 UTF-8·JSON, typ 비교, 크기 상한, 고정 문구). 문구는 한국어 고정이며
 * 토큰·키·클레임 값을 넣지 않는다.
 */
final class Jose {
    /** compact JWS 최대 길이(문자). */
    static final int MAX_TOKEN_LENGTH = 64 * 1024;
    /** 헤더·클레임 JSON 상한: 깊이 16, 객체 멤버 1,000, 배열 원소 10,000, 문자열 64KiB. */
    static final StrictJson.Limits LIMITS = StrictJson.Limits.of(16, 1_000, 10_000, MAX_TOKEN_LENGTH);
    /** kid 최대 길이. */
    static final int MAX_KID_LENGTH = 256;

    private Jose() { }

    static String text(String key, Object... args) {
        return Messages.get(Messages.Language.KO, key, args);
    }

    static JwtException fail(JwtException.Reason reason, String key, String claim) {
        return new JwtException(reason, text(key, claim == null ? "-" : claim), claim);
    }

    static IllegalArgumentException invalid(String key, Object... args) {
        return new IllegalArgumentException(text(key, args));
    }

    /** compact JWS를 세 구간으로 나눈다(정확히 점 두 개, 빈 구간 없음). */
    static String[] split(String token) throws JwtException {
        if (token == null || token.isEmpty() || token.length() > MAX_TOKEN_LENGTH) throw fail(JwtException.Reason.MALFORMED, "jwt.err.size", null);
        int first = token.indexOf('.');
        int second = first < 0 ? -1 : token.indexOf('.', first + 1);
        if (first <= 0 || second < 0 || second == first + 1 || second == token.length() - 1) {
            throw fail(JwtException.Reason.MALFORMED, "jwt.err.segments", null);
        }
        if (token.indexOf('.', second + 1) >= 0) throw fail(JwtException.Reason.UNSUPPORTED, "jwt.err.jwe", null);
        return new String[] {token.substring(0, first), token.substring(first + 1, second), token.substring(second + 1)};
    }

    /** 엄격한 Base64URL(패딩 없음, 정규형). */
    static byte[] decode(String segment) throws JwtException {
        if (segment.indexOf('=') >= 0) throw fail(JwtException.Reason.MALFORMED, "jwt.err.base64", null);
        try {
            return Encoding.BASE64_URL.decode(segment);
        } catch (IllegalArgumentException e) {
            throw fail(JwtException.Reason.MALFORMED, "jwt.err.base64", null);
        }
    }

    static String encode(byte[] data) {
        return Encoding.BASE64_URL.encode(data);
    }

    /** 엄격한 UTF-8 + JSON 객체(중복 멤버 거부). */
    @SuppressWarnings("unchecked")
    static Map<String, Object> object(byte[] json) throws JwtException {
        Object value;
        try {
            value = StrictJson.parse(Bytes.utf8String(json), LIMITS);
        } catch (IllegalArgumentException e) {
            throw fail(JwtException.Reason.MALFORMED, "jwt.err.json", null);
        }
        if (!(value instanceof Map)) throw fail(JwtException.Reason.MALFORMED, "jwt.err.json", null);
        return (Map<String, Object>) value;
    }

    /** 서명할 JSON도 검증기와 같은 UTF-8·JOSE 상한으로 검사한다. */
    static String encodeObject(Map<String, Object> object) {
        byte[] json;
        try {
            json = Bytes.utf8(StrictJson.write(object));
            object(json);
        } catch (IllegalArgumentException | JwtException e) {
            throw invalid("jwt.err.json");
        }
        return encode(json);
    }

    /** typ 비교용 정규화(RFC 7515 4.1.9: 대소문자 무시, "application/" 생략 가능). */
    static String normalizeType(String type) {
        String lower = type.toLowerCase(Locale.ROOT);
        return lower.startsWith("application/") ? lower.substring("application/".length()) : lower;
    }

    static void checkKeyId(String keyId) {
        if (keyId == null || keyId.isEmpty() || keyId.length() > MAX_KID_LENGTH) throw invalid("jwt.err.kidFormat", MAX_KID_LENGTH);
        for (int i = 0; i < keyId.length(); i++) {
            char c = keyId.charAt(i);
            if (c < 0x21 || c > 0x7e) throw invalid("jwt.err.kidFormat", MAX_KID_LENGTH);
        }
    }
}
