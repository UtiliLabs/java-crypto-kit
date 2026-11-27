package io.javacryptokit.key;

import io.javacryptokit.config.SafeMessageException;
import io.javacryptokit.core.Kdf;
import io.javacryptokit.i18n.Messages;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <b>내부 구현 클래스(공개 API 아님)</b>: Passphrase(pass 유형)를 AES-256 키로 파생한다. 파생한 키는 key 유형과 같은
 * AES-256-GCM 엔진에 그대로 넘기므로 암호문·파일 형식이 같다.
 *
 * <p><b>파생 규칙(pbkdf2-sha256)</b>: Passphrase를 유니코드 NFC로 정규화한 뒤 UTF-8 바이트로 PBKDF2-HMAC-SHA256(키마다 무작위
 * 16바이트 Salt, 반복 횟수는 프로필에 기록, 출력 32바이트)을 적용한다. JDK 기본 {@code PBKDF2WithHmacSHA256}를 쓰며(새 의존성
 * 없음), JDK 8·21 모두 문자를 UTF-8로 처리하는 것을 고정 시험 벡터로 확인한다. 같은 Passphrase·Salt·반복 횟수는 어느 OS·JVM에서도
 * 같은 키가 되고, Salt가 다르면 다른 키가 된다. NFC를 쓰므로 한글을 조합형(NFD)으로 입력해도 같은 키다(전각·반각처럼 NFC가
 * 바꾸지 않는 문자는 서로 다른 키).</p>
 *
 * <p><b>입력 검증</b>: 실제 입력 오류만 거부한다(빈 값, 공백만, 제어문자, 짝이 맞지 않는 서로게이트). 길이 같은 정책성 제한은 두지
 * 않는다. Passphrase는 로그·예외·이력에 넣지 않는다. Java 문자열 정규화 결과는 지울 수 없는 String이다(Java 한계).</p>
 *
 * <p><b>반복 파생 방지</b>: 파생은 한 번에 수백 ms가 걸리므로, 같은 입력(Key ID·Salt·반복 횟수·Passphrase의 해시)의 결과는 JVM 안에
 * 한 번만 계산해 둔다. Passphrase가 바뀌면 해시가 달라 새로 파생하고, 지문 고정 검사로 걸러진다.</p>
 */
public final class PassKdf {
    /** 공개 기본 Passphrase의 Key ID. */
    public static final String PUBLIC_KEY_ID = "pass-default";
    /** 파생 방식 이름(프로필 kdf 값). */
    public static final String NAME = "pbkdf2-sha256";
    /** Salt 길이(바이트). */
    public static final int SALT_BYTES = 16;
    /** Passphrase 파일 최대 크기(바이트). */
    public static final int MAX_FILE_BYTES = 1024;
    /** 자동 생성 Passphrase 길이(영문·숫자 62종, 약 190비트). */
    static final int GENERATED_LENGTH = 32;
    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();
    /** 파생 결과 캐시(입력 해시 → 파생 키). 프로필이 많지 않으므로 상한을 넘으면 비운다. */
    private static final Map<String, byte[]> CACHE = new ConcurrentHashMap<>();
    private static final int CACHE_LIMIT = 64;

    private PassKdf() { }

    /** @return 새 무작위 Salt(16바이트) */
    public static byte[] newSalt() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /** @return 새 무작위 Passphrase(영문·숫자 32자). 호출자가 사용 후 지운다. */
    public static char[] generate() {
        char[] value = new char[GENERATED_LENGTH];
        for (int i = 0; i < value.length; i++) value[i] = ALPHABET[RANDOM.nextInt(ALPHABET.length)];
        return value;
    }

    /**
     * 입력을 검증하고 NFC로 정규화한다.
     *
     * @param input 입력(바꾸지 않는다)
     * @return 정규화한 새 배열(호출자가 지운다)
     * @throws IllegalArgumentException 빈 값·공백만·제어문자·깨진 문자({@link SafeMessageException})
     */
    public static char[] normalize(char[] input) {
        return Kdf.normalize(input);
    }

    /**
     * UTF-8 바이트(파일·환경변수·Vault에서 받은 Passphrase)를 엄격하게 문자로 바꾼다. 파일은 편집기가 붙이는 앞의 UTF-8 BOM
     * 하나와 끝의 줄바꿈 하나만 뗀다(예: Windows PowerShell 5.1 {@code Set-Content -Encoding UTF8}은 BOM을 붙인다. 떼지 않으면 BOM이
     * Passphrase의 일부가 되어 같은 값을 입력·환경변수로 줄 때 다른 키가 된다). 그 밖의 공백·문자는 그대로 둔다.
     *
     * @param material      UTF-8 바이트(바꾸지 않는다)
     * @param stripLineEnd  파일 재료면 true: 앞의 BOM 하나와 끝의 줄바꿈(\n 또는 \r\n) 하나를 뗀다
     * @return 문자 배열(호출자가 지운다)
     */
    public static char[] decodeUtf8(byte[] material, boolean stripLineEnd) {
        int start = 0;
        int length = material.length;
        if (stripLineEnd && length >= 3 && (material[0] & 0xff) == 0xEF && (material[1] & 0xff) == 0xBB
                && (material[2] & 0xff) == 0xBF) {
            start = 3;
        }
        if (stripLineEnd && length > start && material[length - 1] == '\n') {
            length--;
            if (length > start && material[length - 1] == '\r') length--;
        }
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(material, start, length - start));
            char[] result = new char[chars.remaining()];
            chars.get(result);
            Arrays.fill(chars.array(), '\0');
            return result;
        } catch (CharacterCodingException e) {
            throw new SafeMessageException(Messages.get("pass.err.invalid"));
        }
    }

    /**
     * 정규화한 Passphrase에서 32바이트 키를 파생한다.
     *
     * @param normalized {@link #normalize}의 결과(바꾸지 않는다)
     * @param salt       Salt
     * @param iterations 반복 횟수
     * @return 32바이트 키(호출자가 지운다)
     */
    public static byte[] derive(char[] normalized, byte[] salt, int iterations) {
        return Kdf.pbkdf2("PBKDF2WithHmacSHA256", normalized, salt, iterations, 32);
    }

    /**
     * {@link #derive}와 같지만 같은 입력의 결과를 JVM 안에 한 번만 계산한다(Tomcat Resource마다·호출마다 다시 파생하지 않음).
     *
     * @return 32바이트 키 복사본(호출자가 지운다)
     */
    static byte[] deriveCached(String keyId, char[] normalized, byte[] salt, int iterations) {
        String cacheKey = cacheKey(keyId, normalized, salt, iterations);
        byte[] cached = CACHE.get(cacheKey);
        if (cached != null) return cached.clone();
        byte[] key = derive(normalized, salt, iterations);
        if (CACHE.size() >= CACHE_LIMIT) CACHE.clear();
        CACHE.put(cacheKey, key.clone());
        return key;
    }

    /** @return 정규화한 입력이 공개 기본 Passphrase와 같으면 true(사용자 키로 등록하지 않는다) */
    public static boolean isPublicPassphrase(char[] normalized) {
        ByteBuffer bytes = StandardCharsets.UTF_8.encode(CharBuffer.wrap(normalized));
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(bytes);
            return MessageDigest.isEqual(digest.digest(), java.util.Base64.getDecoder().decode("RwWxbCnF9DWxQzI2QvYemmwuvUYG631gKZ6KH0hhalI="));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256");
        } finally {
            if (bytes.hasArray()) Arrays.fill(bytes.array(), (byte) 0);
        }
    }

    /** 캐시 키: 원문 대신 해시만 보관한다(Key ID·Salt·반복 횟수·원문이 모두 같아야 같은 키). */
    private static String cacheKey(String keyId, char[] normalized, byte[] salt, int iterations) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("java-crypto-kit/pass-cache/v1\0".getBytes(StandardCharsets.US_ASCII));
            digest.update(keyId.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(salt);
            digest.update(Integer.toString(iterations).getBytes(StandardCharsets.US_ASCII));
            digest.update((byte) 0);
            ByteBuffer utf8 = StandardCharsets.UTF_8.encode(CharBuffer.wrap(normalized));
            byte[] bytes = new byte[utf8.remaining()];
            utf8.get(bytes);
            digest.update(bytes);
            Arrays.fill(bytes, (byte) 0);
            if (utf8.hasArray()) Arrays.fill(utf8.array(), (byte) 0);
            StringBuilder hex = new StringBuilder();
            for (byte b : digest.digest()) hex.append(String.format("%02x", b & 0xff));
            return hex.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256");
        }
    }

}
