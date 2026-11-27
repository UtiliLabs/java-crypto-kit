package io.javacryptokit.jwt;

import io.javacryptokit.security.Bytes;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>공개 API</b>: 일반 JWT 검증기. 호출자가 등록한 키와 정책으로 서명·헤더·클레임을 확인하고, 모두 통과한 경우에만
 * {@link VerifiedJwt}를 돌려준다. OAuth Access Token(RFC 9068·공급자 프로파일)은 목적이 다르므로
 * {@code io.javacryptokit.oauth.AccessTokenVerifier}를 쓴다.
 *
 * <pre>{@code
 * JwtVerifier verifier = JwtVerifier.builder()
 *         .key(JwtKey.rs256(publicKey).withKeyId("2026-11"))
 *         .key(JwtKey.rs256(previousPublicKey).withKeyId("2026-05"))   // 키 교체 기간: 이전·새 키 함께
 *         .issuer("https://auth.example.com")
 *         .audience("orders-api")
 *         .build();                                                       // 한 번 만들어 재사용(스레드 안전)
 * VerifiedJwt jwt = verifier.verify(token);                               // 실패하면 JwtException
 * }</pre>
 *
 * <p><b>확인 순서와 기본 정책(약화하지 않는 한 엄격)</b></p>
 * <ol>
 *   <li>형식: 64KiB 이하, 세 구간, 엄격한 Base64URL·UTF-8·JSON(중복 멤버 거부).</li>
 *   <li>헤더: {@code alg}는 HS256·RS256·ES256만({@code none} 거부). {@code crit}·{@code b64}·{@code enc}·{@code zip}, 중첩 JWT
 *       ({@code cty: JWT})는 거부. {@code jku}·{@code x5u}·{@code jwk}·{@code x5c}·{@code x5t}는 무시하고 절대 쓰지 않는다.
 *       {@code typ}는 기본으로 없거나 {@code JWT}만 허용({@link Builder#types}로 지정, 대소문자·{@code application/} 무시).</li>
 *   <li>키: 토큰 {@code alg}와 같은 알고리즘의 등록 키 중 {@code kid}가 같은 키 하나. kid가 없으면 그 알고리즘 키가 하나일 때만.
 *       여러 키를 차례로 시도하지 않는다. 발급자에 묶인 키({@link JwtKey#withIssuer})는 그 발급자의 토큰만 검증한다.</li>
 *   <li>서명: 받은 문자열의 {@code header.payload} 그대로(다시 직렬화하지 않음). 서명 확인 뒤에야 클레임을 해석한다.</li>
 *   <li>시간: 기본 허용 오차 0초(최대 300초). {@code exp} 필수(끌 수 있음) — 현재 ≥ exp + 오차면 만료. {@code nbf}가 있으면 현재 +
 *       오차 &lt; nbf면 거부. {@code iat}는 기본 선택(필수로 지정 가능)이며 있으면 오차보다 미래인 값 거부(끌 수 있음),
 *       {@link Builder#maxAge}를 주면 너무 오래된 토큰 거부. 시간 값은 기본으로 0 이상 정수 초만(소수 초 허용 옵션).</li>
 *   <li>클레임: {@code iss} 정확히 일치(지정 시), {@code aud}에 기대 대상 포함(지정 시). 대상을 지정하지 않았는데 토큰에
 *       {@code aud}가 있으면 거부한다({@link Builder#anyAudience()}로 명시해야 허용). 필수 클레임·클레임 값(문자열 정확히 일치).</li>
 * </ol>
 * <p>실패는 {@link JwtException}(사유 구분)이며 실패한 토큰의 클레임은 돌려주지 않는다. 서명·만료 검증은 토큰 폐기·일회 사용을
 * 확인하지 않는다(필요하면 {@code jti}를 공유 저장소에서 원자적으로 확인). 객체는 불변이며 여러 스레드에서 함께 써도 된다.</p>
 */
public final class JwtVerifier {
    /** 최대 허용 시각 오차. */
    public static final Duration MAX_CLOCK_SKEW = Duration.ofSeconds(300);
    private static final Set<String> FORBIDDEN_HEADERS = new HashSet<>(Arrays.asList("crit", "b64", "enc", "zip"));

    private final List<JwtKey> keys;
    private final String issuer;
    private final String audience;
    private final boolean anyAudience;
    private final Set<String> types;
    private final boolean allowMissingType;
    private final List<String> requiredClaims;
    private final Map<String, String> claimValues;
    private final boolean requireExpiration;
    private final boolean requireIssuedAt;
    private final boolean rejectFutureIssuedAt;
    private final Duration maxAge;
    private final long skewSeconds;
    private final boolean allowFractionalTimes;
    private final Clock clock;

    private JwtVerifier(Builder b) {
        this.keys = Collections.unmodifiableList(new ArrayList<>(b.keys));
        this.issuer = b.issuer;
        this.audience = b.audience;
        this.anyAudience = b.anyAudience;
        this.types = b.types == null ? Collections.singleton("jwt") : b.types;
        this.allowMissingType = b.types == null;
        this.requiredClaims = Collections.unmodifiableList(new ArrayList<>(b.requiredClaims));
        this.claimValues = Collections.unmodifiableMap(new LinkedHashMap<>(b.claimValues));
        this.requireExpiration = b.requireExpiration;
        this.requireIssuedAt = b.requireIssuedAt;
        this.rejectFutureIssuedAt = b.rejectFutureIssuedAt;
        this.maxAge = b.maxAge;
        this.skewSeconds = b.clockSkew.getSeconds();
        this.allowFractionalTimes = b.allowFractionalTimes;
        this.clock = b.clock;
    }

    /** @return 검증기 생성기 */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * 토큰을 검증한다.
     *
     * @param token compact JWS
     * @return 검증된 JWT
     * @throws JwtException 형식·알고리즘·키·서명·시간·클레임 중 하나라도 정책에 맞지 않음
     */
    public VerifiedJwt verify(String token) throws JwtException {
        String[] parts = Jose.split(token);
        Map<String, Object> header = Jose.object(Jose.decode(parts[0]));
        JwtAlgorithm algorithm = checkHeader(header);
        JwtKey key = selectKey(algorithm, header.get("kid"));
        byte[] signature = Jose.decode(parts[2]);
        if (!key.verify(Bytes.utf8(parts[0] + "." + parts[1]), signature)) {
            throw Jose.fail(JwtException.Reason.SIGNATURE, "jwt.err.signature", null);
        }
        JwtClaims claims = new JwtClaims(Jose.object(Jose.decode(parts[1])));
        checkClaims(claims, key);
        return new VerifiedJwt(algorithm, key.keyId(), new JwtClaims(header), claims);
    }

    private JwtAlgorithm checkHeader(Map<String, Object> header) throws JwtException {
        Object alg = header.get("alg");
        if (!(alg instanceof String)) throw Jose.fail(JwtException.Reason.MALFORMED, "jwt.err.alg", "alg");
        JwtAlgorithm algorithm = JwtAlgorithm.fromHeader((String) alg);
        if (algorithm == null) throw Jose.fail(JwtException.Reason.UNSUPPORTED, "jwt.err.algUnsupported", "alg");
        for (String name : FORBIDDEN_HEADERS) {
            if (header.containsKey(name)) throw Jose.fail(JwtException.Reason.UNSUPPORTED, "jwt.err.header", name);
        }
        // 등록 헤더는 "없음"과 명시적 null을 구분한다: 있으면 문자열이어야 한다(null이면 형식 오류).
        if (header.containsKey("cty")) {
            Object cty = header.get("cty");
            if (!(cty instanceof String)) throw Jose.fail(JwtException.Reason.MALFORMED, "jwt.err.headerType", "cty");
            if ("jwt".equals(Jose.normalizeType((String) cty))) throw Jose.fail(JwtException.Reason.UNSUPPORTED, "jwt.err.nested", "cty");
        }
        if (!header.containsKey("typ")) {
            if (!allowMissingType) throw Jose.fail(JwtException.Reason.TYPE, "jwt.err.type", "typ");
        } else {
            Object typ = header.get("typ");
            if (!(typ instanceof String)) throw Jose.fail(JwtException.Reason.MALFORMED, "jwt.err.headerType", "typ");
            if (!types.contains(Jose.normalizeType((String) typ))) throw Jose.fail(JwtException.Reason.TYPE, "jwt.err.type", "typ");
        }
        if (header.containsKey("kid")) {
            Object kid = header.get("kid");
            if (!(kid instanceof String) || ((String) kid).isEmpty() || ((String) kid).length() > Jose.MAX_KID_LENGTH) {
                throw Jose.fail(JwtException.Reason.MALFORMED, "jwt.err.headerType", "kid");
            }
        }
        return algorithm;
    }

    private JwtKey selectKey(JwtAlgorithm algorithm, Object kid) throws JwtException {
        List<JwtKey> candidates = new ArrayList<>();
        for (JwtKey key : keys) {
            if (key.algorithm() == algorithm) candidates.add(key);
        }
        if (candidates.isEmpty()) throw Jose.fail(JwtException.Reason.KEY_NOT_FOUND, "jwt.err.noKeyForAlg", "alg");
        if (kid != null) {
            for (JwtKey key : candidates) {
                if (kid.equals(key.keyId())) return key;
            }
            throw Jose.fail(JwtException.Reason.KEY_NOT_FOUND, "jwt.err.unknownKid", "kid");
        }
        if (candidates.size() != 1) throw Jose.fail(JwtException.Reason.KEY_NOT_FOUND, "jwt.err.ambiguousKey", "kid");
        return candidates.get(0);
    }

    private void checkClaims(JwtClaims claims, JwtKey key) throws JwtException {
        Map<String, Object> raw = claims.raw();
        for (String name : new String[] {"iss", "sub", "jti"}) {
            if (raw.containsKey(name) && !(raw.get(name) instanceof String)) throw Jose.fail(JwtException.Reason.INVALID_CLAIM, "jwt.err.claimFormat", name);
        }
        List<String> aud = audienceOf(raw);
        Instant now = clock.instant();
        Instant exp = time(raw, "exp");
        Instant nbf = time(raw, "nbf");
        Instant iat = time(raw, "iat");
        if (exp == null && requireExpiration) throw Jose.fail(JwtException.Reason.MISSING_CLAIM, "jwt.err.missing", "exp");
        if (exp != null && !now.isBefore(exp.plusSeconds(skewSeconds))) throw Jose.fail(JwtException.Reason.EXPIRED, "jwt.err.expired", "exp");
        if (nbf != null && now.isBefore(nbf.minusSeconds(skewSeconds))) throw Jose.fail(JwtException.Reason.NOT_YET_VALID, "jwt.err.notYetValid", "nbf");
        if (iat == null && (requireIssuedAt || maxAge != null)) throw Jose.fail(JwtException.Reason.MISSING_CLAIM, "jwt.err.missing", "iat");
        if (iat != null && rejectFutureIssuedAt && now.isBefore(iat.minusSeconds(skewSeconds))) {
            throw Jose.fail(JwtException.Reason.ISSUED_IN_FUTURE, "jwt.err.futureIat", "iat");
        }
        if (iat != null && maxAge != null) {
            Instant deadline;
            try {
                deadline = iat.plus(maxAge).plusSeconds(skewSeconds);
            } catch (ArithmeticException | DateTimeException e) {
                throw Jose.fail(JwtException.Reason.INVALID_CLAIM, "jwt.err.maxAgeRange", "iat");
            }
            if (now.isAfter(deadline)) throw Jose.fail(JwtException.Reason.TOO_OLD, "jwt.err.tooOld", "iat");
        }
        String tokenIssuer = (String) raw.get("iss");
        if (issuer != null && !issuer.equals(tokenIssuer)) throw Jose.fail(JwtException.Reason.ISSUER, "jwt.err.issuer", "iss");
        if (key.issuer() != null && !key.issuer().equals(tokenIssuer)) throw Jose.fail(JwtException.Reason.ISSUER, "jwt.err.keyIssuer", "iss");
        if (audience != null) {
            if (!aud.contains(audience)) throw Jose.fail(JwtException.Reason.AUDIENCE, "jwt.err.audience", "aud");
        } else if (!aud.isEmpty() && !anyAudience) {
            throw Jose.fail(JwtException.Reason.AUDIENCE, "jwt.err.audiencePolicy", "aud");
        }
        for (String name : requiredClaims) {
            if (!raw.containsKey(name)) throw Jose.fail(JwtException.Reason.MISSING_CLAIM, "jwt.err.missing", name);
            if (raw.get(name) == null) throw Jose.fail(JwtException.Reason.INVALID_CLAIM, "jwt.err.claimFormat", name);
        }
        for (Map.Entry<String, String> expected : claimValues.entrySet()) {
            if (!raw.containsKey(expected.getKey())) throw Jose.fail(JwtException.Reason.MISSING_CLAIM, "jwt.err.missing", expected.getKey());
            if (!expected.getValue().equals(raw.get(expected.getKey()))) {
                throw Jose.fail(JwtException.Reason.INVALID_CLAIM, "jwt.err.claimValue", expected.getKey());
            }
        }
    }

    /** 등록 클레임 aud: 없으면 빈 목록, 있으면 문자열 또는 비어 있지 않은 문자열 배열(명시적 null은 형식 오류). */
    private static List<String> audienceOf(Map<String, Object> raw) throws JwtException {
        if (!raw.containsKey("aud")) return Collections.emptyList();
        Object value = raw.get("aud");
        if (value instanceof String) return Collections.singletonList((String) value);
        if (value instanceof List && !((List<?>) value).isEmpty()) {
            List<String> out = new ArrayList<>();
            for (Object item : (List<?>) value) {
                if (!(item instanceof String)) throw Jose.fail(JwtException.Reason.INVALID_CLAIM, "jwt.err.claimFormat", "aud");
                out.add((String) item);
            }
            return out;
        }
        throw Jose.fail(JwtException.Reason.INVALID_CLAIM, "jwt.err.claimFormat", "aud");
    }

    /** 등록 시간 클레임(exp·nbf·iat): 없으면 null, 있으면 NumericDate여야 한다(명시적 null은 형식 오류). */
    private Instant time(Map<String, Object> raw, String name) throws JwtException {
        if (!raw.containsKey(name)) return null;
        Object value = raw.get(name);
        if (value instanceof Long && (Long) value >= 0 && (Long) value <= Times.MAX_SECONDS) return Instant.ofEpochSecond((Long) value);
        if (allowFractionalTimes && value instanceof Double && Times.validFraction((Double) value)) return Times.fractional((Double) value);
        throw Jose.fail(JwtException.Reason.INVALID_CLAIM, "jwt.err.numericDate", name);
    }

    /** 검증기 생성기(한 번 설정해 {@link #build()}하고 결과 검증기를 재사용한다). */
    public static final class Builder {
        private final List<JwtKey> keys = new ArrayList<>();
        private String issuer;
        private String audience;
        private boolean anyAudience;
        private Set<String> types;
        private final List<String> requiredClaims = new ArrayList<>();
        private final Map<String, String> claimValues = new LinkedHashMap<>();
        private boolean requireExpiration = true;
        private boolean requireIssuedAt;
        private boolean rejectFutureIssuedAt = true;
        private Duration maxAge;
        private Duration clockSkew = Duration.ZERO;
        private boolean allowFractionalTimes;
        private Clock clock = Clock.systemUTC();

        Builder() { }

        /** @param key 검증 키(HS256 비밀키 또는 공개키) @return this */
        public Builder key(JwtKey key) {
            if (key == null || !key.canVerify()) throw Jose.invalid("jwt.err.notVerifyKey");
            keys.add(key);
            return this;
        }

        /** @param keys 검증 키 목록(예: {@link Jwks#parse(String, String)} 결과) @return this */
        public Builder keys(Collection<JwtKey> keys) {
            if (keys == null) throw Jose.invalid("jwt.err.null", "keys");
            for (JwtKey key : keys) key(key);
            return this;
        }

        /** @param issuer 기대 발급자({@code iss} 정확히 일치) @return this */
        public Builder issuer(String issuer) {
            if (issuer == null || issuer.isEmpty()) throw Jose.invalid("jwt.err.issuerEmpty");
            this.issuer = issuer;
            return this;
        }

        /** @param audience 이 서비스의 식별자(토큰 {@code aud}에 포함되어야 함) @return this */
        public Builder audience(String audience) {
            if (audience == null || audience.isEmpty()) throw Jose.invalid("jwt.err.null", "aud");
            this.audience = audience;
            return this;
        }

        /** @return this(대상을 확인하지 않고 {@code aud}가 있는 토큰도 받는다는 명시적 선택) */
        public Builder anyAudience() {
            this.anyAudience = true;
            return this;
        }

        /**
         * 허용할 헤더 {@code typ} 값(지정하면 typ가 없는 토큰은 거부). 기본은 "없음 또는 JWT".
         *
         * @param allowed 값(예: {@code JWT}, {@code at+jwt}; 대소문자·{@code application/} 무시)
         * @return this
         */
        public Builder types(String... allowed) {
            if (allowed == null || allowed.length == 0) throw Jose.invalid("jwt.err.null", "typ");
            Set<String> normalized = new LinkedHashSet<>();
            for (String value : allowed) {
                if (value == null || value.isEmpty()) throw Jose.invalid("jwt.err.null", "typ");
                normalized.add(Jose.normalizeType(value));
            }
            this.types = Collections.unmodifiableSet(normalized);
            return this;
        }

        /** @param names 있어야 하는 클레임 @return this */
        public Builder requireClaims(String... names) {
            if (names == null) throw Jose.invalid("jwt.err.null", "names");
            for (String name : names) {
                if (name == null || name.isEmpty()) throw Jose.invalid("jwt.err.null", "name");
                requiredClaims.add(name);
            }
            return this;
        }

        /**
         * @param name  클레임 이름
         * @param value 기대 문자열(정확히 일치, 형식 변환 없음)
         * @return this
         */
        public Builder requireClaimValue(String name, String value) {
            if (name == null || name.isEmpty() || value == null) throw Jose.invalid("jwt.err.null", "name");
            claimValues.put(name, value);
            return this;
        }

        /** @param required {@code exp} 필수 여부(기본 true) @return this */
        public Builder requireExpiration(boolean required) {
            this.requireExpiration = required;
            return this;
        }

        /** @param required {@code iat} 필수 여부(기본 false) @return this */
        public Builder requireIssuedAt(boolean required) {
            this.requireIssuedAt = required;
            return this;
        }

        /** @param reject 허용 오차보다 미래의 {@code iat} 거부 여부(기본 true) @return this */
        public Builder rejectFutureIssuedAt(boolean reject) {
            this.rejectFutureIssuedAt = reject;
            return this;
        }

        /** @param maxAge {@code iat} 기준 최대 나이(지정하면 iat 필수) @return this */
        public Builder maxAge(Duration maxAge) {
            if (maxAge == null || maxAge.isNegative() || maxAge.isZero()) throw Jose.invalid("jwt.err.lifetime");
            this.maxAge = maxAge;
            return this;
        }

        /** @param skew 서버 간 시계 차 허용(0~300초, 기본 0) @return this */
        public Builder clockSkew(Duration skew) {
            if (skew == null || skew.isNegative() || skew.compareTo(MAX_CLOCK_SKEW) > 0 || skew.getNano() != 0) {
                throw Jose.invalid("jwt.err.skew", MAX_CLOCK_SKEW.getSeconds());
            }
            this.clockSkew = skew;
            return this;
        }

        /** @param allow 소수 초 NumericDate 허용(기본 false) @return this */
        public Builder allowFractionalTimes(boolean allow) {
            this.allowFractionalTimes = allow;
            return this;
        }

        /** @param clock 현재 시각 시계(기본 시스템 UTC) @return this */
        public Builder clock(Clock clock) {
            if (clock == null) throw Jose.invalid("jwt.err.null", "clock");
            this.clock = clock;
            return this;
        }

        /**
         * @return 검증기
         * @throws IllegalArgumentException 키가 없음, kid 중복, kid 없는 같은 알고리즘 키가 둘 이상, 기대 발급자와 다른 발급자에 묶인 키
         */
        public JwtVerifier build() {
            if (keys.isEmpty()) throw Jose.invalid("jwt.err.noKeys");
            Set<String> kids = new HashSet<>();
            Set<JwtAlgorithm> keyless = new HashSet<>();
            for (JwtKey key : keys) {
                if (key.keyId() != null && !kids.add(key.keyId())) throw Jose.invalid("jwt.err.duplicateKid");
                if (key.keyId() == null && !keyless.add(key.algorithm())) throw Jose.invalid("jwt.err.duplicateKeyless");
                if (issuer != null && key.issuer() != null && !issuer.equals(key.issuer())) throw Jose.invalid("jwt.err.mixedIssuer");
            }
            return new JwtVerifier(this);
        }
    }
}
