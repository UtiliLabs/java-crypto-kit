package io.javacryptokit.security;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * <b>공개 API</b>: 문자열 ↔ UTF-8 바이트 변환과 검증값의 안전한 비교.
 *
 * <ul>
 *   <li>UTF-8 변환은 엄격하다. 짝이 맞지 않는 서로게이트가 든 문자열, 올바르지 않은 UTF-8 바이트는 '?'로 바꾸지 않고
 *       {@link IllegalArgumentException}으로 거부한다(서명·MAC 원본이 조용히 바뀌는 것을 막는다).</li>
 *   <li>안전 비교는 토큰·MAC 같은 <b>검증값</b>을 비교할 때 쓴다. JDK {@link MessageDigest#isEqual}(내용과 무관한 시간)로
 *       비교하되, 그대로 쓰면 {@code null}끼리·빈 배열끼리도 같다고 판단하므로 이 클래스는 {@code null}이나 빈 값이 하나라도
 *       있으면 항상 {@code false}를 돌려준다("저장값 없음 + 입력 없음"이 일치로 통과하는 결함 방지). 길이가 다르면 바로
 *       {@code false}다(길이 정보는 숨기지 않는다). 시간차 공격을 완전히 없앤다고 보장하지 않으며, 값의 진위·유효기간·재사용
 *       여부는 판단하지 않는다.</li>
 * </ul>
 */
public final class Bytes {
    private Bytes() { }

    /**
     * 문자열을 UTF-8 바이트로 바꾼다.
     *
     * @param text 문자열
     * @return UTF-8 바이트
     * @throws IllegalArgumentException null이거나 UTF-8로 나타낼 수 없는 문자(짝 없는 서로게이트)가 있음
     */
    public static byte[] utf8(String text) {
        Text.require(text, "text");
        try {
            ByteBuffer buffer = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(text));
            byte[] out = new byte[buffer.remaining()];
            buffer.get(out);
            return out;
        } catch (CharacterCodingException e) {
            throw Text.invalid("sec.err.utf8Encode");
        }
    }

    /**
     * UTF-8 바이트를 문자열로 바꾼다.
     *
     * @param data UTF-8 바이트
     * @return 문자열
     * @throws IllegalArgumentException null이거나 올바른 UTF-8이 아님
     */
    public static String utf8String(byte[] data) {
        Text.require(data, "data");
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data)).toString();
        } catch (CharacterCodingException e) {
            throw Text.invalid("sec.err.utf8Decode");
        }
    }

    /**
     * 두 검증값을 내용과 무관한 시간으로 비교한다.
     *
     * @param a 값(바꾸지 않는다)
     * @param b 값(바꾸지 않는다)
     * @return 둘 다 비어 있지 않고 내용이 같으면 true. 하나라도 null·빈 값이면 false
     */
    public static boolean equalsConstantTime(byte[] a, byte[] b) {
        if (a == null || b == null || a.length == 0 || b.length == 0) return false;
        return MessageDigest.isEqual(a, b);
    }

    /**
     * 두 문자열 검증값(예: 저장된 토큰과 입력 토큰)을 UTF-8 바이트로 바꿔 내용과 무관한 시간으로 비교한다.
     *
     * @param a 값
     * @param b 값
     * @return 둘 다 비어 있지 않고 같으면 true. 하나라도 null·빈 문자열이거나 UTF-8로 나타낼 수 없으면 false
     */
    public static boolean equalsConstantTime(String a, String b) {
        if (a == null || b == null || a.isEmpty() || b.isEmpty()) return false;
        try {
            return equalsConstantTime(utf8(a), utf8(b));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
