package io.javacryptokit.jwt;

/**
 * <b>공개 API</b>: {@link JwtVerifier}가 서명과 정책(알고리즘·키·발급자·대상·시간·필수 클레임)을 모두 확인한 JWT. 이 객체만 검증된
 * 클레임을 담으며, 라이브러리 밖에서는 만들 수 없다. 서명 검증은 내용을 숨기지 않으므로(Payload는 누구나 읽을 수 있다) 비밀을
 * 클레임에 넣지 않는다. 사용자·권한의 업무 적합성, 토큰 폐기·재사용 여부는 호출 애플리케이션이 판단한다.
 */
public final class VerifiedJwt {
    private final JwtAlgorithm algorithm;
    private final String keyId;
    private final JwtClaims header;
    private final JwtClaims claims;

    VerifiedJwt(JwtAlgorithm algorithm, String keyId, JwtClaims header, JwtClaims claims) {
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.header = header;
        this.claims = claims;
    }

    /** @return 검증에 쓴 알고리즘 */
    public JwtAlgorithm algorithm() {
        return algorithm;
    }

    /** @return 검증에 쓴 키의 kid(없으면 null) */
    public String keyId() {
        return keyId;
    }

    /** @return 헤더 */
    public JwtClaims header() {
        return header;
    }

    /** @return 검증된 클레임 */
    public JwtClaims claims() {
        return claims;
    }

    @Override
    public String toString() {
        return "VerifiedJwt[" + algorithm + (keyId == null ? "" : ", kid=" + keyId) + "]";
    }
}
