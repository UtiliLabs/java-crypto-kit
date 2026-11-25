package io.javacryptokit.oauth;

import io.javacryptokit.i18n.Messages;
import io.javacryptokit.jwt.JwtException;

/** 패키지 내부: OAuth 보조 API의 고정 문구(한국어 고정, 토큰·비밀·응답 본문을 넣지 않음). */
final class OAuthText {
    private OAuthText() { }

    static String get(String key, Object... args) {
        return Messages.get(Messages.Language.KO, key, args);
    }

    static IllegalArgumentException invalid(String key, Object... args) {
        return new IllegalArgumentException(get(key, args));
    }

    static JwtException fail(JwtException.Reason reason, String key, String claim) {
        return new JwtException(reason, get(key, claim == null ? "-" : claim), claim);
    }

    static String require(String value, String name) {
        if (value == null || value.isEmpty()) throw invalid("oauth.err.required", name);
        return value;
    }
}
