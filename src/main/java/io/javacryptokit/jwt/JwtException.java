package io.javacryptokit.jwt;

import java.security.GeneralSecurityException;

/**
 * <b>공개 API</b>: JWT 해석·검증 실패. 실패한 토큰의 클레임은 돌려주지 않으며, 문구에는 토큰 원문·키·클레임 값을 넣지 않는다(문구는
 * 한국어 고정, 판별은 {@link #getReason()}).
 */
public final class JwtException extends GeneralSecurityException {
    private static final long serialVersionUID = 1L;

    /** 실패 사유. 이름은 공개 계약이다. */
    public enum Reason {
        /** 형식 오류: 세 구간이 아님, Base64URL·UTF-8·JSON 오류, 중복 헤더·클레임, 크기 상한 초과. */
        MALFORMED,
        /** 지원하지 않는 표현: {@code none}·모르는 알고리즘, {@code crit}·{@code b64}, JWE·중첩 JWT. */
        UNSUPPORTED,
        /** 검증 키 없음: 그 알고리즘·kid의 키가 등록되지 않았거나 kid가 없어 키를 하나로 정할 수 없음. */
        KEY_NOT_FOUND,
        /** 서명 불일치(다른 키·변조·잘못된 서명 길이). */
        SIGNATURE,
        /** 만료(exp). */
        EXPIRED,
        /** 아직 사용 시작 전(nbf). */
        NOT_YET_VALID,
        /** 발급 시각(iat)이 허용 오차보다 미래. */
        ISSUED_IN_FUTURE,
        /** 발급 시각(iat)이 허용한 최대 나이보다 오래됨. */
        TOO_OLD,
        /** 발급자(iss) 불일치. */
        ISSUER,
        /** 대상(aud) 불일치 또는 대상 정책 없음. */
        AUDIENCE,
        /** 토큰 종류(typ 헤더) 불일치. */
        TYPE,
        /** 필수 클레임 없음. */
        MISSING_CLAIM,
        /** 클레임 형식·값이 정책과 다름(금지 클레임 포함). */
        INVALID_CLAIM,
        /** 필요한 권한(scope·roles) 없음. */
        SCOPE
    }

    private final Reason reason;
    private final String claim;

    /**
     * 라이브러리 내부용(JWT·OAuth 검증기가 만든다). 문구에는 토큰·키·클레임 값을 넣지 않는다.
     *
     * @param reason  사유
     * @param message 고정 문구
     * @param claim   관련 클레임·헤더 이름(없으면 null)
     */
    public JwtException(Reason reason, String message, String claim) {
        super(message);
        this.reason = reason;
        this.claim = claim;
    }

    /** @return 실패 사유 */
    public Reason getReason() {
        return reason;
    }

    /** @return 관련 클레임·헤더 이름(예: {@code exp}), 없으면 null. 값이 아니라 이름이다 */
    public String getClaim() {
        return claim;
    }
}
