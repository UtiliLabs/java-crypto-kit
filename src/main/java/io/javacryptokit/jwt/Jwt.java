package io.javacryptokit.jwt;

import io.javacryptokit.json.StrictJson;
import io.javacryptokit.security.Bytes;
import io.javacryptokit.security.SecureRandoms;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>공개 API</b>: 일반 JWT(compact JWS, RFC 7515·7519)의 생성과 <b>검증하지 않는</b> 분석. 검증은 {@link JwtVerifier},
 * OAuth Access Token(RFC 9068)은 {@code io.javacryptokit.oauth.AccessTokens}·{@code AccessTokenVerifier}를 쓴다.
 *
 * <pre>{@code
 * JwtKey key = JwtKey.rs256(privateKey).withKeyId("2026-11");
 * String token = Jwt.builder()
 *         .issuer("https://auth.example.com").subject("user-1").audience("orders-api")
 *         .expiresIn(Duration.ofMinutes(10))
 *         .claim("role", "admin")
 *         .sign(key);                                    // header.payload.signature
 * UnverifiedJwt peek = Jwt.parseUnverified(token);      // 서명 미검증: 인증에 쓰지 않는다
 * }</pre>
 *
 * <p>생성: 헤더는 {@code alg}(키의 알고리즘)·{@code typ}(기본 {@code JWT})·{@code kid}(키에 있으면)만 쓴다. {@code iat}는 기본으로
 * 현재 시각(시계 주입 가능)이며, 만료({@code exp})가 필요한 인증 용도는 {@link Builder#expiresIn}을 꼭 지정한다. 표준 클레임은 전용
 * 메서드로만 넣는다({@link Builder#claim}로 iss·exp 등을 넣으면 거부, 형식 실수 방지). 토큰 크기는 64KiB까지.</p>
 *
 * <p>분석({@link #parseUnverified}): 세 구간·엄격한 Base64URL(패딩 없음)·UTF-8·JSON(중복 멤버 거부)만 확인한다. 서명·알고리즘·시간을
 * 확인하지 않으므로 결과를 인증 성공으로 쓰면 안 된다. 실패는 {@link JwtException}(MALFORMED·UNSUPPORTED).</p>
 */
public final class Jwt {
    private static final Set<String> REGISTERED = new HashSet<>(Arrays.asList("iss", "sub", "aud", "exp", "nbf", "iat", "jti"));

    private Jwt() { }

    /** @return 시스템 UTC 시계를 쓰는 생성기 */
    public static Builder builder() {
        return new Builder(Clock.systemUTC());
    }

    /**
     * @param clock 발급 시각·만료 계산에 쓸 시계
     * @return 생성기
     */
    public static Builder builder(Clock clock) {
        if (clock == null) throw Jose.invalid("jwt.err.null", "clock");
        return new Builder(clock);
    }

    /**
     * 서명을 검증하지 않고 헤더·클레임만 읽는다.
     *
     * @param token compact JWS
     * @return 미검증 분석 결과
     * @throws JwtException MALFORMED(형식), UNSUPPORTED(JWE 등)
     */
    public static UnverifiedJwt parseUnverified(String token) throws JwtException {
        String[] parts = Jose.split(token);
        Map<String, Object> header = Jose.object(Jose.decode(parts[0]));
        Map<String, Object> claims = Jose.object(Jose.decode(parts[1]));
        Jose.decode(parts[2]);
        return new UnverifiedJwt(new JwtClaims(header), new JwtClaims(claims));
    }

    /** JWT 생성기(한 번 쓰고 버린다, 스레드 안전하지 않음). */
    public static final class Builder {
        private final Clock clock;
        private final Map<String, Object> claims = new LinkedHashMap<>();
        private String type = "JWT";
        private Instant issuedAt;
        private boolean issuedAtSet;
        private Duration expiresIn;

        Builder(Clock clock) {
            this.clock = clock;
        }

        /**
         * @param type 헤더 {@code typ}(기본 {@code JWT}, 예: {@code at+jwt}). null이면 typ를 쓰지 않는다
         * @return this
         */
        public Builder type(String type) {
            if (type != null && (type.isEmpty() || type.length() > 64)) throw Jose.invalid("jwt.err.typeFormat");
            this.type = type;
            return this;
        }

        /** @param issuer {@code iss} @return this */
        public Builder issuer(String issuer) {
            return put("iss", text(issuer));
        }

        /** @param subject {@code sub} @return this */
        public Builder subject(String subject) {
            return put("sub", text(subject));
        }

        /**
         * @param audience {@code aud}(하나면 문자열, 둘 이상이면 배열)
         * @return this
         */
        public Builder audience(String... audience) {
            if (audience == null || audience.length == 0) throw Jose.invalid("jwt.err.null", "aud");
            List<String> values = new ArrayList<>();
            for (String value : audience) values.add(text(value));
            return put("aud", values.size() == 1 ? values.get(0) : Collections.unmodifiableList(values));
        }

        /** @param expiresAt {@code exp} @return this */
        public Builder expiresAt(Instant expiresAt) {
            this.expiresIn = null;
            return put("exp", seconds(expiresAt));
        }

        /**
         * @param lifetime 발급 시각부터 만료까지(1초 이상)
         * @return this
         */
        public Builder expiresIn(Duration lifetime) {
            if (lifetime == null || lifetime.getSeconds() < 1) throw Jose.invalid("jwt.err.lifetime");
            claims.remove("exp");
            this.expiresIn = lifetime;
            return this;
        }

        /** @param notBefore {@code nbf} @return this */
        public Builder notBefore(Instant notBefore) {
            return put("nbf", seconds(notBefore));
        }

        /**
         * @param issuedAt {@code iat}(기본은 현재 시각). null이면 iat를 쓰지 않는다
         * @return this
         */
        public Builder issuedAt(Instant issuedAt) {
            this.issuedAt = issuedAt;
            this.issuedAtSet = true;
            return this;
        }

        /** @param jwtId {@code jti} @return this */
        public Builder jwtId(String jwtId) {
            return put("jti", text(jwtId));
        }

        /** @return this({@code jti}에 256비트 보안 난수 Base64URL을 넣는다) */
        public Builder randomJwtId() {
            return put("jti", SecureRandoms.token());
        }

        /** @param name 업무 클레임 이름(표준 이름 불가) @param value 문자열 @return this */
        public Builder claim(String name, String value) {
            return custom(name, text(value));
        }

        /** @param name 업무 클레임 이름 @param value 정수 @return this */
        public Builder claim(String name, long value) {
            return custom(name, value);
        }

        /** @param name 업무 클레임 이름 @param value 논리 값 @return this */
        public Builder claim(String name, boolean value) {
            return custom(name, value);
        }

        /** @param name 업무 클레임 이름 @param values 문자열 배열 @return this */
        public Builder claim(String name, List<String> values) {
            if (values == null) throw Jose.invalid("jwt.err.null", name);
            List<String> copy = new ArrayList<>();
            for (String value : values) copy.add(text(value));
            return custom(name, Collections.unmodifiableList(copy));
        }

        /**
         * @param name  업무 클레임 이름
         * @param value 중첩 객체(값은 문자열·정수·논리·null·목록·객체만)
         * @return this
         */
        public Builder claim(String name, Map<String, ?> value) {
            if (value == null) throw Jose.invalid("jwt.err.null", name);
            try {
                StrictJson.write(value);
            } catch (IllegalArgumentException e) {
                throw Jose.invalid("jwt.err.claimValue", name);
            }
            return custom(name, new LinkedHashMap<>(value));
        }

        /**
         * 서명해 compact JWS를 만든다.
         *
         * @param key 서명 키(HS256 비밀키 또는 개인키)
         * @return {@code header.payload.signature}
         * @throws IllegalArgumentException 최종 헤더·클레임이 JOSE 상한을 넘거나 유효하지 않은 시간 정책
         */
        public String sign(JwtKey key) {
            if (key == null || !key.canSign()) throw Jose.invalid("jwt.err.notSigningKey");
            Instant now = clock.instant();
            Map<String, Object> payload = new LinkedHashMap<>(claims);
            Instant iat = issuedAtSet ? issuedAt : now;
            if (iat != null) payload.put("iat", seconds(iat));
            if (expiresIn != null) {
                Instant base = iat == null ? now : iat;
                long baseSeconds = seconds(base);
                if (expiresIn.getSeconds() > Times.MAX_SECONDS - baseSeconds) {
                    throw Jose.invalid("jwt.err.timeRange");
                }
                payload.put("exp", seconds(base.plus(expiresIn)));
            }
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", key.algorithm().name());
            if (type != null) header.put("typ", type);
            if (key.keyId() != null) header.put("kid", key.keyId());
            String signingInput = Jose.encodeObject(header) + "." + Jose.encodeObject(payload);
            if (signingInput.length() >= Jose.MAX_TOKEN_LENGTH) throw Jose.invalid("jwt.err.tooLarge", Jose.MAX_TOKEN_LENGTH);
            String token = signingInput + "." + Jose.encode(key.sign(Bytes.utf8(signingInput)));
            if (token.length() > Jose.MAX_TOKEN_LENGTH) throw Jose.invalid("jwt.err.tooLarge", Jose.MAX_TOKEN_LENGTH);
            return token;
        }

        private Builder put(String name, Object value) {
            claims.put(name, value);
            return this;
        }

        private Builder custom(String name, Object value) {
            if (name == null || name.isEmpty()) throw Jose.invalid("jwt.err.null", "name");
            if (REGISTERED.contains(name)) throw Jose.invalid("jwt.err.registered", name);
            return put(name, value);
        }

        private static String text(String value) {
            if (value == null) throw Jose.invalid("jwt.err.null", "value");
            return value;
        }

        private static long seconds(Instant time) {
            if (time == null) throw Jose.invalid("jwt.err.null", "time");
            long value = time.getEpochSecond();
            if (value < 0 || value > Times.MAX_SECONDS) throw Jose.invalid("jwt.err.timeRange");
            return value;
        }
    }
}
