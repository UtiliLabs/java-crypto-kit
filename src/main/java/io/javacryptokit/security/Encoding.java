package io.javacryptokit.security;

import java.util.Base64;

/**
 * <b>공개 API</b>: 바이너리 값(키·MAC·해시·서명·난수)을 문자열로 나타내는 방식. <b>인코딩은 암호화가 아니며</b> 누구나 원래
 * 바이트로 되돌릴 수 있다. 범용 보안 API의 문자열 입출력은 모두 이 열거형으로 형식을 명시한다(자동 감지·다른 형식 재시도 없음).
 *
 * <table border="1">
 *   <caption>형식별 규칙</caption>
 *   <tr><th>값</th><th>출력</th><th>입력(디코딩)</th></tr>
 *   <tr><td>{@link #HEX}</td><td>소문자 16진수</td><td>대소문자 모두, 짝수 길이</td></tr>
 *   <tr><td>{@link #BASE64}</td><td>표준 Base64(RFC 4648 §4), 패딩 포함</td><td>정확한 패딩 필수</td></tr>
 *   <tr><td>{@link #BASE64_URL}</td><td>URL·파일 이름에 안전한 Base64URL(§5), 패딩 없음</td><td>패딩 있어도 됨(있으면 정확해야 함)</td></tr>
 *   <tr><td>{@link #BASE32}</td><td>Base32(§6) 대문자, 패딩 없음(OTP 비밀키 표기)</td><td>대소문자·패딩 모두 허용</td></tr>
 * </table>
 *
 * <p>디코딩은 엄격하다: 공백·줄바꿈·형식 밖 문자, 정규형이 아닌 표현(마지막 문자의 남는 비트가 0이 아님 등)은
 * {@link IllegalArgumentException}으로 거부하고 값을 조용히 고치지 않는다. 오류 문구에는 입력값을 넣지 않는다. 빈 문자열은 빈
 * 배열이다. 상태가 없어 여러 스레드에서 함께 써도 된다.</p>
 */
public enum Encoding {
    /** 16진수. */
    HEX,
    /** 표준 Base64(패딩 포함). */
    BASE64,
    /** Base64URL(패딩 없음). */
    BASE64_URL,
    /** Base32(RFC 4648, 대문자·패딩 없음). */
    BASE32;

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /**
     * 바이트를 문자열로 나타낸다.
     *
     * @param data 원본(바꾸지 않는다)
     * @return 인코딩한 문자열
     * @throws IllegalArgumentException data가 null
     */
    public String encode(byte[] data) {
        Text.require(data, "data");
        switch (this) {
            case HEX:
                return hex(data);
            case BASE64:
                return Base64.getEncoder().encodeToString(data);
            case BASE64_URL:
                return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
            default:
                return base32(data);
        }
    }

    /**
     * 문자열을 바이트로 되돌린다.
     *
     * @param text 인코딩한 문자열
     * @return 원래 바이트
     * @throws IllegalArgumentException null이거나 이 형식이 아님
     */
    public byte[] decode(String text) {
        Text.require(text, "text");
        switch (this) {
            case HEX:
                return unhex(text);
            case BASE64:
                return base64(text, false);
            case BASE64_URL:
                return base64(text, true);
            default:
                return unbase32(text);
        }
    }

    private IllegalArgumentException malformed() {
        return Text.invalid("sec.err.encoding", name());
    }

    private static String hex(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            out[i * 2] = HEX_DIGITS[(data[i] >> 4) & 0x0f];
            out[i * 2 + 1] = HEX_DIGITS[data[i] & 0x0f];
        }
        return new String(out);
    }

    private byte[] unhex(String text) {
        if (text.length() % 2 != 0) throw malformed();
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(text.charAt(i * 2), 16);
            int low = Character.digit(text.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0 || text.charAt(i * 2) > 'f' || text.charAt(i * 2 + 1) > 'f') throw malformed();
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    private byte[] base64(String text, boolean url) {
        String alphabetPattern = url ? "[A-Za-z0-9_-]*={0,2}" : "[A-Za-z0-9+/]*={0,2}";
        if (!text.matches(alphabetPattern)) throw malformed();
        byte[] decoded;
        try {
            decoded = url ? Base64.getUrlDecoder().decode(text) : Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            throw malformed();
        }
        // 정규형만 허용: 같은 바이트를 다시 인코딩한 결과와 같아야 한다(남는 비트·잘못된 패딩 거부).
        String padded = url ? Base64.getUrlEncoder().encodeToString(decoded) : Base64.getEncoder().encodeToString(decoded);
        boolean canonical = url
                ? (text.indexOf('=') >= 0 ? padded.equals(text) : padded.replace("=", "").equals(text))
                : padded.equals(text);
        if (!canonical) throw malformed();
        return decoded;
    }

    private static String base32(byte[] data) {
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                out.append(BASE32_ALPHABET.charAt((buffer >> (bits - 5)) & 0x1f));
                bits -= 5;
            }
        }
        if (bits > 0) out.append(BASE32_ALPHABET.charAt((buffer << (5 - bits)) & 0x1f));
        return out.toString();
    }

    private byte[] unbase32(String text) {
        String body = text;
        int padding = 0;
        while (body.endsWith("=")) {
            body = body.substring(0, body.length() - 1);
            padding++;
        }
        if (padding > 0 && text.length() % 8 != 0) throw malformed();
        int remainder = body.length() % 8;
        if (remainder == 1 || remainder == 3 || remainder == 6) throw malformed();
        if (padding > 0 && padding != (8 - remainder) % 8) throw malformed();
        byte[] out = new byte[body.length() * 5 / 8];
        int buffer = 0;
        int bits = 0;
        int index = 0;
        for (int i = 0; i < body.length(); i++) {
            int value = BASE32_ALPHABET.indexOf(Character.toUpperCase(body.charAt(i)));
            if (value < 0 || body.charAt(i) > 'z') throw malformed();
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                out[index++] = (byte) (buffer >> (bits - 8));
                bits -= 8;
            }
        }
        // 정규형: 마지막 문자의 남는 비트는 0이어야 한다.
        if (bits > 0 && (buffer & ((1 << bits) - 1)) != 0) throw malformed();
        return out;
    }
}
