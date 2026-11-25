package io.javacryptokit.security;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.i18n.Messages;

/**
 * 패키지 내부: 범용 보안 API의 고정 오류 문구. 설정을 읽지 않으므로 직접 키 주입 API와 같게 한국어로 고정한다(번들에는 영어도
 * 있다). 문구에는 키·비밀번호·토큰·평문·입력값을 넣지 않는다.
 */
final class Text {
    private Text() { }

    static String get(String key, Object... args) {
        return Messages.get(Messages.Language.KO, key, args);
    }

    static IllegalArgumentException invalid(String key, Object... args) {
        return new IllegalArgumentException(get(key, args));
    }

    /** null이면 {@code sec.err.null}로 거부한다. */
    static <T> T require(T value, String name) {
        if (value == null) throw invalid("sec.err.null", name);
        return value;
    }

    /** 복호화·형식 실패를 기존 공개 예외({@link CredentialCryptoException}, Reason 불변)로 만든다(한국어 고정 문구). */
    static CredentialCryptoException failure(CredentialCryptoException.Reason reason, String key) {
        try (Messages.Scope ignored = Messages.use(Messages.Language.KO)) {
            return new CredentialCryptoException(reason, Messages.get(key));
        }
    }
}
