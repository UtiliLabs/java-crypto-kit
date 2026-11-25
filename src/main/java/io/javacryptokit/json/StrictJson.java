package io.javacryptokit.json;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 엄격한 JSON(RFC 8259) 해석·작성기. Vault 응답, JWT 헤더·클레임, OAuth Introspection
 * 응답이 같은 구현을 쓴다(외부 라이브러리 의존 없음).
 *
 * <p><b>해석 결과</b>: 객체 {@code Map<String,Object>}(입력 순서 유지), 배열 {@code List<Object>}, 문자열 {@code String}, 정수
 * {@code Long}(long 범위), 소수·지수 {@code Double}(유한값), {@code Boolean}, {@code null}.</p>
 *
 * <p><b>거부(묵시적 변환·추측 없음)</b>: 문법 오류·남는 문자, <b>중복 키</b>(마지막 값 채택 금지), 문자열 안의 제어문자, 4자리
 * 16진수가 아닌 {@code \\u} 이스케이프, 짝이 맞지 않는 서로게이트 이스케이프, long 범위를 넘는 정수, 무한대가 되는 수, 깊이·멤버 수·
 * 배열 길이·문자열 길이·숫자 길이 상한 초과. 오류는 {@link IllegalArgumentException}("json")이며 입력 내용을 담지 않는다. UTF-8
 * 해석은 호출자가 한다(JWT·OAuth는 엄격한 UTF-8, Vault는 기존 방식 유지).</p>
 */
public final class StrictJson {
    private static final int MAX_NUMBER_LENGTH = 64;

    /** 입력 상한. */
    public static final class Limits {
        /** Vault 응답 등 기존 용도의 기본 상한(깊이 32, 객체 멤버·배열 원소 각 10,000개). */
        public static final Limits DEFAULT = new Limits(32, 10_000, 10_000, Integer.MAX_VALUE);

        final int maxDepth;
        final int maxMembers;
        final int maxElements;
        final int maxStringLength;

        private Limits(int maxDepth, int maxMembers, int maxElements, int maxStringLength) {
            this.maxDepth = maxDepth;
            this.maxMembers = maxMembers;
            this.maxElements = maxElements;
            this.maxStringLength = maxStringLength;
        }

        /**
         * @param maxDepth        최대 중첩 깊이
         * @param maxMembers      객체 하나의 최대 멤버 수
         * @param maxElements     배열 하나의 최대 원소 수
         * @param maxStringLength 문자열 하나의 최대 길이(문자 수)
         * @return 상한
         */
        public static Limits of(int maxDepth, int maxMembers, int maxElements, int maxStringLength) {
            return new Limits(maxDepth, maxMembers, maxElements, maxStringLength);
        }
    }

    private final String text;
    private final Limits limits;
    private int pos;

    private StrictJson(String text, Limits limits) {
        this.text = text;
        this.limits = limits;
    }

    /**
     * @param text JSON 문자열
     * @return 해석 결과
     * @throws IllegalArgumentException 형식 오류·상한 초과
     */
    public static Object parse(String text) {
        return parse(text, Limits.DEFAULT);
    }

    /**
     * @param text   JSON 문자열
     * @param limits 상한
     * @return 해석 결과
     * @throws IllegalArgumentException 형식 오류·상한 초과
     */
    public static Object parse(String text, Limits limits) {
        if (text == null || limits == null) throw error();
        StrictJson parser = new StrictJson(text, limits);
        parser.skipSpace();
        Object value = parser.value(0);
        parser.skipSpace();
        if (parser.pos != text.length()) throw error();
        return value;
    }

    /** 객체에서 경로를 따라 값을 찾는다(없거나 객체가 아니면 null). */
    @SuppressWarnings("unchecked")
    public static Object path(Object root, String... keys) {
        Object current = root;
        for (String key : keys) {
            if (!(current instanceof Map)) return null;
            current = ((Map<String, Object>) current).get(key);
        }
        return current;
    }

    /**
     * 값을 압축 JSON으로 쓴다(공백 없음, 객체는 넣은 순서).
     *
     * @param value Map(문자열 키)·List·String·정수/소수(유한)·Boolean·null
     * @return JSON
     * @throws IllegalArgumentException 지원하지 않는 형식·짝 없는 서로게이트·무한대
     */
    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(value, out, 0);
        return out.toString();
    }

    // ------------------------------------------------------------------ 해석

    private Object value(int depth) {
        if (depth > limits.maxDepth || pos >= text.length()) throw error();
        char c = text.charAt(pos);
        switch (c) {
            case '{':
                return object(depth + 1);
            case '[':
                return array(depth + 1);
            case '"':
                return string();
            case 't':
                return literal("true", Boolean.TRUE);
            case 'f':
                return literal("false", Boolean.FALSE);
            case 'n':
                return literal("null", null);
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return number();
                throw error();
        }
    }

    private Map<String, Object> object(int depth) {
        if (depth > limits.maxDepth) throw error();
        Map<String, Object> map = new LinkedHashMap<>();
        pos++; // {
        skipSpace();
        if (peek() == '}') {
            pos++;
            return map;
        }
        while (true) {
            skipSpace();
            if (peek() != '"') throw error();
            String key = string();
            skipSpace();
            if (peek() != ':') throw error();
            pos++;
            skipSpace();
            if (map.containsKey(key) || map.size() >= limits.maxMembers) throw error();
            map.put(key, value(depth));
            skipSpace();
            char c = peek();
            pos++;
            if (c == '}') return map;
            if (c != ',') throw error();
        }
    }

    private List<Object> array(int depth) {
        if (depth > limits.maxDepth) throw error();
        List<Object> list = new ArrayList<>();
        pos++; // [
        skipSpace();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            skipSpace();
            if (list.size() >= limits.maxElements) throw error();
            list.add(value(depth));
            skipSpace();
            char c = peek();
            pos++;
            if (c == ']') return list;
            if (c != ',') throw error();
        }
    }

    private String string() {
        pos++; // "
        StringBuilder out = new StringBuilder();
        while (true) {
            if (pos >= text.length() || out.length() > limits.maxStringLength) throw error();
            char c = text.charAt(pos++);
            if (c == '"') {
                if (out.length() > limits.maxStringLength) throw error();
                return out.toString();
            }
            if (c < 0x20) throw error();
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (pos >= text.length()) throw error();
            char e = text.charAt(pos++);
            switch (e) {
                case '"': out.append('"'); break;
                case '\\': out.append('\\'); break;
                case '/': out.append('/'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case 'n': out.append('\n'); break;
                case 'r': out.append('\r'); break;
                case 't': out.append('\t'); break;
                case 'u': {
                    char unit = hex4();
                    if (Character.isHighSurrogate(unit)) {
                        if (pos + 1 >= text.length() || text.charAt(pos) != '\\' || text.charAt(pos + 1) != 'u') throw error();
                        pos += 2;
                        char low = hex4();
                        if (!Character.isLowSurrogate(low)) throw error();
                        out.append(unit).append(low);
                    } else if (Character.isLowSurrogate(unit)) {
                        throw error();
                    } else {
                        out.append(unit);
                    }
                    break;
                }
                default:
                    throw error();
            }
        }
    }

    private char hex4() {
        if (pos + 4 > text.length()) throw error();
        int value = 0;
        for (int i = 0; i < 4; i++) {
            char h = text.charAt(pos + i);
            int digit = h >= '0' && h <= '9' ? h - '0' : h >= 'a' && h <= 'f' ? h - 'a' + 10 : h >= 'A' && h <= 'F' ? h - 'A' + 10 : -1;
            if (digit < 0) throw error();
            value = (value << 4) | digit;
        }
        pos += 4;
        return (char) value;
    }

    private Object number() {
        int start = pos;
        if (peek() == '-') pos++;
        if (pos >= text.length()) throw error();
        if (text.charAt(pos) == '0') {
            pos++;
        } else if (text.charAt(pos) >= '1' && text.charAt(pos) <= '9') {
            while (pos < text.length() && Character.isDigit(text.charAt(pos)) && text.charAt(pos) <= '9') pos++;
        } else {
            throw error();
        }
        boolean integer = true;
        if (pos < text.length() && text.charAt(pos) == '.') {
            integer = false;
            pos++;
            digits();
        }
        if (pos < text.length() && (text.charAt(pos) == 'e' || text.charAt(pos) == 'E')) {
            integer = false;
            pos++;
            if (pos < text.length() && (text.charAt(pos) == '+' || text.charAt(pos) == '-')) pos++;
            digits();
        }
        String raw = text.substring(start, pos);
        if (raw.length() > MAX_NUMBER_LENGTH) throw error();
        if (integer) {
            try {
                return Long.parseLong(raw);
            } catch (NumberFormatException e) {
                throw error(); // long 범위를 넘는 정수
            }
        }
        double value = Double.parseDouble(raw);
        if (Double.isInfinite(value) || Double.isNaN(value)) throw error();
        return value;
    }

    private void digits() {
        int start = pos;
        while (pos < text.length() && text.charAt(pos) >= '0' && text.charAt(pos) <= '9') pos++;
        if (pos == start) throw error();
    }

    private Object literal(String word, Object value) {
        if (!text.startsWith(word, pos)) throw error();
        pos += word.length();
        return value;
    }

    private char peek() {
        if (pos >= text.length()) throw error();
        return text.charAt(pos);
    }

    private void skipSpace() {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return;
            pos++;
        }
    }

    // ------------------------------------------------------------------ 작성

    private static void write(Object value, StringBuilder out, int depth) {
        if (depth > Limits.DEFAULT.maxDepth) throw error();
        if (value == null) {
            out.append("null");
        } else if (value instanceof String) {
            quote((String) value, out);
        } else if (value instanceof Boolean) {
            out.append(value.toString());
        } else if (value instanceof Long || value instanceof Integer || value instanceof Short || value instanceof Byte
                || value instanceof BigInteger) {
            out.append(value.toString());
        } else if (value instanceof Double || value instanceof Float) {
            double d = ((Number) value).doubleValue();
            if (Double.isInfinite(d) || Double.isNaN(d)) throw error();
            out.append(Double.toString(d));
        } else if (value instanceof BigDecimal) {
            out.append(((BigDecimal) value).toString());
        } else if (value instanceof Map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!(entry.getKey() instanceof String)) throw error();
                if (!first) out.append(',');
                first = false;
                quote((String) entry.getKey(), out);
                out.append(':');
                write(entry.getValue(), out, depth + 1);
            }
            out.append('}');
        } else if (value instanceof List) {
            out.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) out.append(',');
                first = false;
                write(item, out, depth + 1);
            }
            out.append(']');
        } else {
            throw error();
        }
    }

    private static void quote(String value, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) throw error();
                out.append(c).append(value.charAt(++i));
                continue;
            }
            if (Character.isLowSurrogate(c)) throw error();
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
    }

    private static IllegalArgumentException error() {
        return new IllegalArgumentException("json");
    }
}
