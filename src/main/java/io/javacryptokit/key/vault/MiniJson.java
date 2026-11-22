package io.javacryptokit.key.vault;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>내부 구현 클래스</b>: Vault 응답(JSON)을 읽기 위한 최소한의 엄격한 JSON 파서다. 외부 라이브러리 의존을 피하려고 직접 둔다.
 *
 * <p>지원: 객체·배열·문자열(이스케이프·\\u 포함)·숫자·true·false·null. 결과는 {@code Map<String,Object>}, {@code List<Object>},
 * {@code String}, {@code Long}/{@code Double}, {@code Boolean}, {@code null}이다. 깊이 32단계·문자 수 상한을 넘거나 형식이
 * 깨지면 {@link IllegalArgumentException}을 던진다(메시지에 입력 내용을 넣지 않는다).</p>
 */
final class MiniJson {
    private static final int MAX_DEPTH = 32;
    private final String text;
    private int pos;

    private MiniJson(String text) {
        this.text = text;
    }

    /**
     * @param text JSON 문자열
     * @return 해석 결과
     * @throws IllegalArgumentException 형식 오류
     */
    static Object parse(String text) {
        MiniJson parser = new MiniJson(text);
        parser.skipSpace();
        Object value = parser.value(0);
        parser.skipSpace();
        if (parser.pos != text.length()) throw error();
        return value;
    }

    /** 객체에서 경로를 따라 값을 찾는다(없거나 객체가 아니면 null). */
    @SuppressWarnings("unchecked")
    static Object path(Object root, String... keys) {
        Object current = root;
        for (String key : keys) {
            if (!(current instanceof Map)) return null;
            current = ((Map<String, Object>) current).get(key);
        }
        return current;
    }

    private Object value(int depth) {
        if (depth > MAX_DEPTH || pos >= text.length()) throw error();
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
            map.put(key, value(depth));
            skipSpace();
            char c = peek();
            pos++;
            if (c == '}') return map;
            if (c != ',') throw error();
        }
    }

    private List<Object> array(int depth) {
        List<Object> list = new ArrayList<>();
        pos++; // [
        skipSpace();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            skipSpace();
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
            if (pos >= text.length()) throw error();
            char c = text.charAt(pos++);
            if (c == '"') return out.toString();
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
                case 'u':
                    if (pos + 4 > text.length()) throw error();
                    try {
                        out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                    } catch (NumberFormatException ex) {
                        throw error();
                    }
                    pos += 4;
                    break;
                default:
                    throw error();
            }
        }
    }

    private Object number() {
        int start = pos;
        if (peek() == '-') pos++;
        while (pos < text.length() && "0123456789.eE+-".indexOf(text.charAt(pos)) >= 0) pos++;
        String raw = text.substring(start, pos);
        try {
            if (raw.matches("-?(0|[1-9][0-9]{0,17})")) return Long.parseLong(raw);
            if (raw.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")) return Double.parseDouble(raw);
        } catch (NumberFormatException ignored) {
            // 아래에서 형식 오류로 처리한다.
        }
        throw error();
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

    private static IllegalArgumentException error() {
        return new IllegalArgumentException("json");
    }
}
