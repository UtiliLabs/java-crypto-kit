package io.javacryptokit.oauth;

import io.javacryptokit.i18n.Messages;
import io.javacryptokit.jwt.JwtClaims;
import io.javacryptokit.jwt.JwtException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

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

    /** @return scope 이름 규칙(RFC 6749 scope-token: 비어 있지 않은 출력 가능한 ASCII, 공백·큰따옴표·역슬래시 제외)에 맞으면 true */
    static boolean validScope(String scope) {
        if (scope == null || scope.isEmpty()) return false;
        for (int i = 0; i < scope.length(); i++) {
            char c = scope.charAt(i);
            if (c < 0x21 || c > 0x7e || c == '"' || c == '\\') return false;
        }
        return true;
    }

    /** 원격 scope 필드가 주어지면 RFC 6749의 단일 ASCII 공백 구분 규칙을 검사한다. */
    static Set<String> responseScopes(JwtClaims claims) {
        if (!claims.has("scope")) return Collections.emptySet();
        String scope = claims.getString("scope");
        if (scope == null) throw invalid("oauth.err.scopeFormat");
        Set<String> scopes = new LinkedHashSet<>();
        for (String part : scope.split(" ", -1)) {
            if (!validScope(part)) throw invalid("oauth.err.scopeFormat");
            scopes.add(part);
        }
        return Collections.unmodifiableSet(scopes);
    }

    /** @return 공백뿐인 값이나 제어문자를 제외한 역할·식별자면 true */
    static boolean validIdentifier(String value) {
        if (value == null) return false;
        boolean visible = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isISOControl(c)) return false;
            if (!Character.isWhitespace(c) && !Character.isSpaceChar(c)) visible = true;
        }
        return visible;
    }

    static String requireIdentifier(String value, String name) {
        if (!validIdentifier(require(value, name))) throw invalid("oauth.err.claimType", name);
        return value;
    }

    static String require(String value, String name) {
        if (value == null || value.isEmpty()) throw invalid("oauth.err.required", name);
        return value;
    }
}
