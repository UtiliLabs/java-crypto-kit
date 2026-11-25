package io.javacryptokit.config;

import io.javacryptokit.i18n.Messages;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * <b>내부 구현 클래스</b>: JAR 안에 저장하는 내장 키 값({@code *.embedded})과 변경 이력 본문의 <b>경량 난독화(obf1)</b>.
 *
 * <p><b>목적과 한계</b>: JAR를 풀어 텍스트 편집기·{@code unzip -p}·{@code strings}로 열었을 때 키 재료와 이력이 글자 그대로
 * 보이지 않게 하는 것(단순 열람 방지)뿐이다. 되돌리는 방법이 이 라이브러리 안에 공개되어 있으므로 JAR를 가진 사람은 누구나 원래
 * 값을 되살릴 수 있다. 암호화·접근 통제·키 추출 방지·변조 방지가 아니며, 키 기밀성이 필요하면 외부 공급원(file·env·Vault·AWS
 * KMS)을 쓴다. 키 바이트·지문·Key ID·암호문 형식은 이 표현과 무관하게 그대로다.</p>
 *
 * <p><b>형식</b>: {@code obf1:} + Base64url(패딩 없음)[ (확인값 4바이트 || 데이터) XOR 키 스트림 ].
 * 확인값은 {@code SHA-256("java-crypto-kit/obf1/check" || 0x00 || 데이터)}의 앞 4바이트(손상 탐지용, 보안 목적 아님),
 * 키 스트림은 블록 번호 i(0부터, 4바이트 big-endian)마다 {@code SHA-256("java-crypto-kit/obf1/pad" || 0x00 || i)}를 이어 붙인
 * 고정 공개 값이다. 같은 값은 항상 같은 표현이 된다. 버전 표시({@code obf<숫자>:})가 있으므로 표시가 없는 구형 평문 값과 구분하며,
 * 모르는 버전·손상된 값은 다른 값으로 대체하지 않고 오류로 처리한다(Fail Closed).</p>
 */
public final class LightObfuscation {
    /** 현재 형식의 머리말. */
    public static final String PREFIX = "obf1:";
    /** 버전이 붙은 난독화 값({@code obf<숫자>:...}). 표준 Base64에는 ':'가 없어 평문 키와 겹치지 않는다. */
    private static final Pattern MARKER = Pattern.compile("obf[0-9]{1,3}:.*", Pattern.DOTALL);
    private static final byte[] PAD_LABEL = "java-crypto-kit/obf1/pad".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CHECK_LABEL = "java-crypto-kit/obf1/check".getBytes(StandardCharsets.US_ASCII);
    private static final int CHECK_BYTES = 4;
    /**
     * 키 스트림 앞 4블록(128바이트)을 미리 계산해 둔다. 키 스트림은 비밀이 아닌 고정 공개 값이고, 내장 키(확인값 포함 36바이트)는
     * 암복호화할 때마다 되돌리므로(로컬 키는 매번 읽고 쓴 뒤 지움) 그때마다 SHA-256을 다시 계산하지 않게 한다. 형식은 같다.
     */
    private static final byte[] PAD_PREFIX = padPrefix(4);

    private LightObfuscation() { }

    /** @return 값이 버전 표시가 붙은 난독화 표현이면 true(구형 평문 값이면 false) */
    public static boolean isEncoded(String value) {
        return value != null && MARKER.matcher(value).matches();
    }

    /**
     * 데이터를 obf1 표현으로 바꾼다.
     *
     * @param data 원래 바이트(바꾸지 않는다)
     * @return {@code obf1:...} 한 줄(ASCII)
     */
    public static String encode(byte[] data) {
        byte[] body = new byte[CHECK_BYTES + data.length];
        try {
            System.arraycopy(check(data), 0, body, 0, CHECK_BYTES);
            System.arraycopy(data, 0, body, CHECK_BYTES, data.length);
            xorPad(body);
            return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(body);
        } finally {
            Arrays.fill(body, (byte) 0);
        }
    }

    /**
     * obf1 표현을 원래 바이트로 되돌린다.
     *
     * @param value {@code obf1:...}
     * @return 원래 바이트(호출자가 사용 후 지운다)
     * @throws SafeMessageException 모르는 버전이거나 형식·확인값이 맞지 않는 경우(값은 메시지에 넣지 않음)
     */
    public static byte[] decode(String value) {
        if (value == null || !value.startsWith(PREFIX)) throw damaged();
        byte[] body;
        try {
            body = Base64.getUrlDecoder().decode(value.substring(PREFIX.length()));
        } catch (IllegalArgumentException e) {
            // 디코더 메시지에는 문제 문자가 들어갈 수 있으므로 버린다.
            throw damaged();
        }
        if (body.length < CHECK_BYTES) {
            Arrays.fill(body, (byte) 0);
            throw damaged();
        }
        try {
            xorPad(body);
            byte[] data = Arrays.copyOfRange(body, CHECK_BYTES, body.length);
            byte[] expected = check(data);
            if (!MessageDigest.isEqual(expected, Arrays.copyOf(body, CHECK_BYTES))) {
                Arrays.fill(data, (byte) 0);
                throw damaged();
            }
            return data;
        } finally {
            Arrays.fill(body, (byte) 0);
        }
    }

    /**
     * 파일 전체(예: 변경 이력)를 obf1 한 줄로 바꾼다.
     *
     * @param plain 원래 파일 내용
     * @return {@code obf1:...} + 줄바꿈(ASCII)
     */
    public static byte[] encodeFile(byte[] plain) {
        return (encode(plain) + "\n").getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * 파일 내용이 obf1 표현이면 되돌리고, 버전 표시가 없으면(구형 평문 파일) 그대로 돌려준다.
     *
     * @param raw JAR 항목의 바이트
     * @return 원래 파일 내용
     * @throws SafeMessageException 버전 표시는 있으나 모르는 버전이거나 손상된 경우
     */
    public static byte[] decodeFile(byte[] raw) {
        if (!startsWithMarker(raw)) return raw;
        return decode(new String(raw, StandardCharsets.US_ASCII).trim());
    }

    private static boolean startsWithMarker(byte[] raw) {
        if (raw.length < 5 || raw[0] != 'o' || raw[1] != 'b' || raw[2] != 'f') return false;
        int i = 3;
        while (i < raw.length && i < 7 && raw[i] >= '0' && raw[i] <= '9') i++;
        return i > 3 && i < raw.length && raw[i] == ':';
    }

    private static SafeMessageException damaged() {
        return new SafeMessageException(Messages.get("config.err.obfuscated"));
    }

    private static byte[] check(byte[] data) {
        MessageDigest digest = sha256();
        digest.update(CHECK_LABEL);
        digest.update((byte) 0);
        digest.update(data);
        return Arrays.copyOf(digest.digest(), CHECK_BYTES);
    }

    /** 고정 공개 키 스트림과 XOR한다(같은 호출로 되돌아온다). 앞 128바이트는 미리 계산한 값을 쓴다. */
    private static void xorPad(byte[] body) {
        int cached = Math.min(body.length, PAD_PREFIX.length);
        for (int i = 0; i < cached; i++) body[i] ^= PAD_PREFIX[i];
        if (body.length <= PAD_PREFIX.length) return;
        // 긴 값(변경 이력 본문)은 나머지 블록을 계산한다.
        MessageDigest digest = sha256();
        for (int offset = PAD_PREFIX.length, counter = PAD_PREFIX.length / 32; offset < body.length; offset += 32, counter++) {
            byte[] pad = padBlock(digest, counter);
            for (int i = 0; i < 32 && offset + i < body.length; i++) body[offset + i] ^= pad[i];
        }
    }

    /** @return 키 스트림 블록 하나: {@code SHA-256(PAD_LABEL || 0x00 || counter(4바이트 big-endian))} */
    private static byte[] padBlock(MessageDigest digest, int counter) {
        digest.reset();
        digest.update(PAD_LABEL);
        digest.update((byte) 0);
        digest.update(new byte[] {(byte) (counter >>> 24), (byte) (counter >>> 16), (byte) (counter >>> 8), (byte) counter});
        return digest.digest();
    }

    private static byte[] padPrefix(int blocks) {
        MessageDigest digest = sha256();
        byte[] prefix = new byte[blocks * 32];
        for (int counter = 0; counter < blocks; counter++) System.arraycopy(padBlock(digest, counter), 0, prefix, counter * 32, 32);
        return prefix;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256");
        }
    }
}
