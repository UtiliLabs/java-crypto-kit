package io.javacryptokit.jwt;

import io.javacryptokit.json.StrictJson;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>공개 API</b>: JSON 객체(JWT 헤더·클레임, Introspection 응답의 최상위 멤버)의 읽기 전용 보기. 값의 형식을 바꿔 주지 않는다:
 * 요청한 형식이 아니면 {@link IllegalArgumentException}, 없으면 {@code null}(목록은 빈 목록)이다.
 *
 * <p>표준 클레임 접근자({@link #issuer()} 등)는 이름 그대로의 값을 돌려준다. 시간 클레임은 NumericDate(1970-01-01T00:00:00Z부터의
 * 초)를 {@link Instant}로 바꾼다. <b>이 객체가 검증된 값인지는 얻은 경로로 결정된다</b>: {@link VerifiedJwt#claims()}만 서명·정책
 * 검증을 거친 값이고, {@link UnverifiedJwt#claims()}는 검증되지 않은 값이다. {@code toString}에는 클레임 이름만 넣는다.</p>
 */
public final class JwtClaims {
    private final Map<String, Object> values;

    JwtClaims(Map<String, Object> values) {
        this.values = Collections.unmodifiableMap(new LinkedHashMap<>(values));
    }

    /**
     * JSON 객체 문자열을 엄격하게 읽어 보기 객체를 만든다(중복 멤버·짝 없는 서로게이트·형식 오류 거부, JWT와 같은 상한). 서명 검증이 아니다.
     *
     * @param json JSON 객체 문자열
     * @return 보기 객체
     * @throws IllegalArgumentException JSON 객체 형식 오류 또는 상한 초과
     */
    @SuppressWarnings("unchecked")
    public static JwtClaims parse(String json) {
        if (json == null) throw Jose.invalid("jwt.err.jsonInput");
        Object value;
        try {
            value = StrictJson.parse(json, Jose.LIMITS);
        } catch (IllegalArgumentException e) {
            throw Jose.invalid("jwt.err.jsonInput");
        }
        if (!(value instanceof Map)) throw Jose.invalid("jwt.err.jsonInput");
        return new JwtClaims((Map<String, Object>) value);
    }

    /** @return {@code iss} */
    public String issuer() {
        return getString("iss");
    }

    /** @return {@code sub} */
    public String subject() {
        return getString("sub");
    }

    /** @return {@code jti} */
    public String jwtId() {
        return getString("jti");
    }

    /** @return {@code aud}(문자열 하나 또는 문자열 배열을 목록으로, 없으면 빈 목록) */
    public List<String> audience() {
        Object value = values.get("aud");
        if (value == null) return Collections.emptyList();
        if (value instanceof String) return Collections.singletonList((String) value);
        return getStringList("aud");
    }

    /** @return {@code exp}(없으면 null) */
    public Instant expiresAt() {
        return getInstant("exp");
    }

    /** @return {@code nbf}(없으면 null) */
    public Instant notBefore() {
        return getInstant("nbf");
    }

    /** @return {@code iat}(없으면 null) */
    public Instant issuedAt() {
        return getInstant("iat");
    }

    /** @return 클레임 이름(입력 순서) */
    public Set<String> names() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(values.keySet()));
    }

    /**
     * @param name 이름
     * @return 있으면(값이 JSON null이어도) true
     */
    public boolean has(String name) {
        return values.containsKey(name);
    }

    /**
     * @param name 이름
     * @return 문자열 값(없거나 null이면 null)
     * @throws IllegalArgumentException 문자열이 아님
     */
    public String getString(String name) {
        Object value = values.get(name);
        if (value == null || value instanceof String) return (String) value;
        throw type(name, "string");
    }

    /**
     * @param name 이름
     * @return 정수 값(없으면 null)
     * @throws IllegalArgumentException 정수가 아님(소수·문자열 변환 없음)
     */
    public Long getLong(String name) {
        Object value = values.get(name);
        if (value == null || value instanceof Long) return (Long) value;
        throw type(name, "integer");
    }

    /**
     * @param name 이름
     * @return 논리 값(없으면 null)
     * @throws IllegalArgumentException true/false가 아님
     */
    public Boolean getBoolean(String name) {
        Object value = values.get(name);
        if (value == null || value instanceof Boolean) return (Boolean) value;
        throw type(name, "boolean");
    }

    /**
     * @param name 이름
     * @return 문자열 배열(없으면 빈 목록)
     * @throws IllegalArgumentException 문자열 배열이 아님(문자열 하나를 목록으로 바꾸지 않음)
     */
    public List<String> getStringList(String name) {
        Object value = values.get(name);
        if (value == null) return Collections.emptyList();
        if (!(value instanceof List)) throw type(name, "string array");
        List<String> out = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (!(item instanceof String)) throw type(name, "string array");
            out.add((String) item);
        }
        return Collections.unmodifiableList(out);
    }

    /**
     * @param name 이름
     * @return 중첩 객체(없으면 null)
     * @throws IllegalArgumentException 객체가 아님
     */
    @SuppressWarnings("unchecked")
    public JwtClaims getObject(String name) {
        Object value = values.get(name);
        if (value == null) return null;
        if (!(value instanceof Map)) throw type(name, "object");
        return new JwtClaims((Map<String, Object>) value);
    }

    /**
     * @param name 이름
     * @return 0~253402300799 범위의 NumericDate(정수 또는 유한 소수 초)를 Instant로 변환. 없거나 JSON null이면 null.
     *         소수 부분은 나노초로 변환한다.
     * @throws IllegalArgumentException 숫자 타입이 아니거나 범위를 벗어남
     */
    public Instant getInstant(String name) {
        Object value = values.get(name);
        if (value == null) return null;
        if (value instanceof Long && (Long) value >= 0 && (Long) value <= Times.MAX_SECONDS) return Instant.ofEpochSecond((Long) value);
        if (value instanceof Double && Times.validFraction((Double) value)) return Times.fractional((Double) value);
        throw type(name, "NumericDate");
    }

    /** @return 이 객체의 압축 JSON(민감한 클레임이 있을 수 있으니 로그에 남기지 않는다) */
    public String toJson() {
        return StrictJson.write(values);
    }

    Map<String, Object> raw() {
        return values;
    }

    @Override
    public String toString() {
        return "JwtClaims" + values.keySet();
    }

    private static IllegalArgumentException type(String name, String expected) {
        return Jose.invalid("jwt.err.claimType", name, expected);
    }
}
