package io.javacryptokit.core;

import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.i18n.Messages;
import java.nio.CharBuffer;
import java.security.GeneralSecurityException;
import java.text.Normalizer;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: Passphrase 검증·NFC 정규화와 PBKDF2 계산을 한 곳에 둔다. 관리형 pass 키
 * ({@code key.PassKdf})와 공개 API({@code security.Pbkdf2}·{@code security.Passwords}·{@code security.AesGcm},
 * {@code CredentialCrypto.fromPassphrase})가 같은 계산을 쓴다. 이 클래스는 상태(캐시·키 저장소)를 갖지 않는다. 관리형 키의 파생
 * 결과 캐시는 {@code key.PassKdf}에만 있고 직접 주입·공개 API는 그 캐시를 거치지 않는다.
 *
 * <p>JDK 기본 {@code PBKDF2WithHmacSHA256}·{@code PBKDF2WithHmacSHA512}를 쓴다(새 의존성 없음). JDK는 문자 배열을 UTF-8 바이트로
 * 바꿔 계산하며, 이를 고정 시험 벡터로 확인한다.</p>
 */
public final class Kdf {
    private Kdf() { }

    /**
     * 입력을 검증하고 NFC로 정규화한다. 실제 입력 오류만 거부한다: 빈 값, 공백만, 제어문자(줄바꿈·탭 등), 짝이 맞지 않는
     * 서로게이트. 메시지는 현재 메시지 언어이며 입력값을 담지 않는다.
     *
     * @param input 입력(바꾸지 않는다)
     * @return 정규화한 새 배열(호출자가 지운다)
     * @throws SafeMessageException 입력 오류({@link IllegalArgumentException})
     */
    public static char[] normalize(char[] input) {
        if (input == null || input.length == 0) throw new SafeMessageException(Messages.get("pass.err.empty"));
        boolean visible = false;
        for (int i = 0; i < input.length; i++) {
            char c = input[i];
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= input.length || !Character.isLowSurrogate(input[i + 1])) {
                    throw new SafeMessageException(Messages.get("pass.err.invalid"));
                }
                i++;
                visible = true;
                continue;
            }
            if (Character.isLowSurrogate(c)) throw new SafeMessageException(Messages.get("pass.err.invalid"));
            if (Character.isISOControl(c)) throw new SafeMessageException(Messages.get("pass.err.control"));
            if (!Character.isWhitespace(c) && !Character.isSpaceChar(c)) visible = true;
        }
        if (!visible) throw new SafeMessageException(Messages.get("pass.err.blank"));
        return Normalizer.normalize(CharBuffer.wrap(input), Normalizer.Form.NFC).toCharArray();
    }

    /**
     * PBKDF2를 계산한다(입력 검증은 호출자가 한다).
     *
     * @param jcaName    {@code PBKDF2WithHmacSHA256} 또는 {@code PBKDF2WithHmacSHA512}
     * @param normalized {@link #normalize}의 결과(바꾸지 않는다)
     * @param salt       Salt
     * @param iterations 반복 횟수
     * @param keyBytes   결과 길이(바이트)
     * @return 파생 키(호출자가 지운다)
     * @throws IllegalStateException 실행 중인 Java가 해당 알고리즘을 제공하지 않음
     */
    public static byte[] pbkdf2(String jcaName, char[] normalized, byte[] salt, int iterations, int keyBytes) {
        PBEKeySpec spec = new PBEKeySpec(normalized, salt, iterations, keyBytes * 8);
        try {
            return SecretKeyFactory.getInstance(jcaName).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(jcaName);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * 문자 배열의 UTF-8 바이트 수(서로게이트 쌍은 4바이트).
     *
     * @param chars 검증된 문자 배열
     * @return UTF-8 길이
     */
    public static int utf8Length(char[] chars) {
        int length = 0;
        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];
            if (c < 0x80) {
                length += 1;
            } else if (c < 0x800) {
                length += 2;
            } else if (Character.isHighSurrogate(c) && i + 1 < chars.length && Character.isLowSurrogate(chars[i + 1])) {
                length += 4;
                i++;
            } else {
                length += 3;
            }
        }
        return length;
    }
}
