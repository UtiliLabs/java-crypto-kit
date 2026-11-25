package io.javacryptokit.jwt;

/**
 * <b>공개 API</b>: <b>서명을 검증하지 않은</b> JWT 분석 결과. 헤더와 클레임을 들여다볼 때만 쓰며(예: 어떤 발급자의 검증기를 쓸지 고르기,
 * 문제 분석), 인증·권한 판단에 쓰면 안 된다. 인증에는 {@link JwtVerifier#verify(String)}가 돌려주는 {@link VerifiedJwt}만 쓴다.
 * 이 타입은 {@link VerifiedJwt}로 바꿀 수 없다.
 */
public final class UnverifiedJwt {
    private final JwtClaims header;
    private final JwtClaims claims;

    UnverifiedJwt(JwtClaims header, JwtClaims claims) {
        this.header = header;
        this.claims = claims;
    }

    /** @return 헤더의 {@code alg} 문자열(검증 전이므로 지원하지 않는 값일 수 있다) */
    public String algorithm() {
        return header.has("alg") && header.raw().get("alg") instanceof String ? (String) header.raw().get("alg") : null;
    }

    /** @return 헤더의 {@code kid}(없거나 문자열이 아니면 null) */
    public String keyId() {
        return header.raw().get("kid") instanceof String ? (String) header.raw().get("kid") : null;
    }

    /** @return 헤더의 {@code typ}(없거나 문자열이 아니면 null) */
    public String type() {
        return header.raw().get("typ") instanceof String ? (String) header.raw().get("typ") : null;
    }

    /** @return 헤더 전체(검증되지 않음) */
    public JwtClaims header() {
        return header;
    }

    /** @return 클레임(검증되지 않음) */
    public JwtClaims claims() {
        return claims;
    }

    @Override
    public String toString() {
        return "UnverifiedJwt[alg=" + algorithm() + ", kid=" + keyId() + ", NOT VERIFIED]";
    }
}
