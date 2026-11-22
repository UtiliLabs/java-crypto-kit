package io.javacryptokit.core;

import io.javacryptokit.CredentialCryptoException;
import io.javacryptokit.config.CryptoSettings;
import io.javacryptokit.i18n.Messages;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: 암호문 토큰의 "바깥 표현"을 다루는 입출력 Codec이다. 암호화 자체는 하지 않는다.
 *
 * <p><b>두 가지 토큰 표현</b></p>
 * <ul>
 *   <li>{@code ENC[v1:키ID:IV:암호문]} — 기본 형식. 내부 IV·암호문 칸의 Base64URL은 암호문을 문자로 저장하기 위해
 *       반드시 필요하므로 끌 수 없다.</li>
 *   <li>{@code B64[<패딩 없는 Base64URL(UTF-8("ENC[v1:...]"))>]} — 선택 형식({@code crypto.output.encoding=base64}).
 *       위 ENC 문자열 전체를 한 번 더 Base64URL로 감싼 "추가 포장"일 뿐이다. 암호 강도를 높이지 않으며 보안 기능이 아니다.</li>
 * </ul>
 *
 * <p><b>읽기 규칙</b>: 설정과 관계없이 두 표현을 모두 받아들이고, {@code B64[...]}는 포장을 푼 뒤 항상
 * {@link CredentialCipher}의 엄격한 v1 파서와 AES-GCM 인증 검증을 그대로 거친다. 포장 해제 단계에서는
 * 최대 길이, Base64URL 문자 집합, 정규(canonical) 인코딩, 정확한 UTF-8, 중첩 포장 금지를 모두 검사한다.
 * 임의의 일반 Base64 값이나 평문을 암호문으로 추측해 받아들이지 않는다.</p>
 */
public final class TokenCodec {
    /** 기본 암호문 봉투 접두어. */
    public static final String ENC_PREFIX = "ENC[";
    /** 선택형 추가 포장 접두어. 내부 형식의 새 버전이 아니라 바깥 표현 이름이다. */
    public static final String B64_PREFIX = "B64[";
    /** ENC 봉투 최대 길이. 비정상적으로 긴 입력으로 자원을 낭비시키는 것을 막는다. */
    public static final int MAX_ENC_LENGTH = 16384;
    /** B64 토큰 최대 길이 = 접두어 + (최대 ENC 길이를 패딩 없이 Base64URL로 인코딩한 길이) + 닫는 괄호. */
    public static final int MAX_B64_LENGTH = B64_PREFIX.length() + (MAX_ENC_LENGTH * 4 + 2) / 3 + 1;
    /** 패딩 없는 Base64URL 문자 집합. '='·공백·'+'·'/'는 허용하지 않는다. */
    private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");

    /** 정적 메서드만 제공하므로 인스턴스 생성을 막는다. */
    private TokenCodec() { }

    /**
     * 값이 이 라이브러리의 암호문 토큰처럼 보이는지({@code ENC[} 또는 {@code B64[}로 시작하는지)만 확인한다.
     * 키를 읽거나 복호화하지 않는 가벼운 검사이며, 형식의 완전성은 {@link #toEnvelope}와 복호화에서 검사한다.
     *
     * @param value 검사할 값(null 허용)
     * @return 토큰 접두어로 시작하면 true
     */
    public static boolean looksLikeToken(String value) {
        return value != null && (value.startsWith(ENC_PREFIX) || value.startsWith(B64_PREFIX));
    }

    /**
     * {@code ENC[v1:...]} 봉투를 설정한 출력 표현으로 바꾼다.
     *
     * @param envelope {@link CredentialCipher}가 만든 ENC 봉투(ASCII)
     * @param format   출력 표현
     * @return ENC면 그대로, BASE64면 {@code B64[...]}
     */
    public static String format(String envelope, CryptoSettings.OutputFormat format) {
        if (format != CryptoSettings.OutputFormat.BASE64) return envelope;
        return B64_PREFIX + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(envelope.getBytes(StandardCharsets.US_ASCII)) + "]";
    }

    /**
     * 토큰을 내부 {@code ENC[v1:...]} 봉투로 되돌린다. ENC는 그대로 돌려주고(엄격한 검사는 복호화 단계),
     * B64는 포장을 엄격하게 검증하며 푼다.
     *
     * @param token {@code ENC[...]} 또는 {@code B64[...]}
     * @return 내부 ENC 봉투 문자열
     * @throws CredentialCryptoException INVALID_TOKEN: 토큰 접두어가 없거나, B64 포장이 길이·문자·정규 인코딩·UTF-8·
     *                                   내부 접두어 규칙을 어긴 경우
     */
    public static String toEnvelope(String token) throws CredentialCryptoException {
        if (token == null) throw invalid("token.err.null");
        if (token.startsWith(ENC_PREFIX)) return token;
        if (!token.startsWith(B64_PREFIX)) throw invalid("token.err.prefix");
        // [1] 길이와 닫는 괄호: 대용량 입력을 디코딩하기 전에 거부한다.
        if (token.length() > MAX_B64_LENGTH || !token.endsWith("]")) {
            throw invalid("token.err.b64Length");
        }
        String body = token.substring(B64_PREFIX.length(), token.length() - 1);
        // [2] 문자 집합과 길이 규칙: 패딩·공백·표준 Base64 문자가 섞인 값, 길이 나머지가 1인 불가능한 길이를 거부한다.
        if (body.isEmpty() || !BASE64URL.matcher(body).matches() || body.length() % 4 == 1) {
            throw invalid("token.err.b64Chars");
        }
        byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw invalid("token.err.b64Decode");
        }
        // [3] 정규 인코딩: 마지막 문자의 남는 비트만 다른 "같은 값의 다른 표기"를 거부해 표현을 하나로 고정한다.
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(body)) {
            throw invalid("token.err.b64Canonical");
        }
        // [4] 정확한 UTF-8: 잘못된 바이트를 '?'로 바꾸지 않고 거부한다.
        String inner;
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(decoded));
            inner = chars.toString();
        } catch (CharacterCodingException e) {
            throw invalid("token.err.b64Utf8");
        }
        // [5] 내부는 반드시 ENC 봉투여야 한다. B64 안의 B64(중첩 포장)나 임의 데이터는 거부한다.
        if (!inner.startsWith(ENC_PREFIX)) {
            throw invalid("token.err.b64Inner");
        }
        return inner;
    }

    /** 형식 오류 예외를 만든다(메시지 키 → 현재 언어 문구). 입력값은 메시지에 넣지 않는다. */
    private static CredentialCryptoException invalid(String messageKey) {
        return new CredentialCryptoException(CredentialCryptoException.Reason.INVALID_TOKEN, Messages.get(messageKey));
    }
}
