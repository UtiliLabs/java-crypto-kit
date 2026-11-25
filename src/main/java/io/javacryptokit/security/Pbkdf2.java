package io.javacryptokit.security;

import io.javacryptokit.core.Kdf;
import io.javacryptokit.i18n.Messages;
import java.util.Arrays;

/**
 * <b>공개 API</b>: Passphrase에서 암호화 키를 파생한다(PBKDF2, RFC 8018). 같은 Passphrase·Salt·알고리즘·반복 횟수·키 길이는
 * 어느 OS·JVM에서도 같은 키가 된다. 대부분은 {@link AesGcm#fromPassphrase}처럼 파생까지 해 주는 API를 쓰고, 이 클래스는 다른
 * 시스템과 같은 키를 직접 맞춰야 할 때 쓴다.
 *
 * <ul>
 *   <li>Passphrase: 유니코드 NFC 정규화 뒤 UTF-8(관리형 pass 키와 같은 규칙). 빈 값·공백만·제어문자·깨진 문자는 거부하고,
 *       UTF-8 1,024바이트까지. 호출자 배열은 바꾸지 않는다(다 쓰면 호출자가 지운다).</li>
 *   <li>Salt: 16~64바이트. 처음 한 번 {@link #newSalt()}로 만들어 Key ID·알고리즘·반복 횟수와 함께 보관한다(비밀은 아니지만
 *       복호화에 꼭 필요하다).</li>
 *   <li>반복 횟수: 100,000~5,000,000(권장 {@link Pbkdf2Algorithm#recommendedIterations()}). 범위 밖 값을 조용히 고치지 않는다.</li>
 *   <li>키 길이: 16~64바이트(AES-128은 16, AES-256은 32).</li>
 * </ul>
 * <p>상태·캐시가 없다(관리형 키의 파생 캐시와 무관). 파생은 수백 ms가 걸리므로 결과 객체를 재사용한다.</p>
 */
public final class Pbkdf2 {
    /** {@link #newSalt()}가 만드는 Salt 길이(바이트). */
    public static final int SALT_BYTES = 16;
    /** Salt 최소 길이(바이트). */
    public static final int MIN_SALT_BYTES = 16;
    /** Salt 최대 길이(바이트). */
    public static final int MAX_SALT_BYTES = 64;
    /** 최소 반복 횟수. */
    public static final int MIN_ITERATIONS = 100_000;
    /** 최대 반복 횟수(지나친 연산으로 인한 서비스 거부 방지). */
    public static final int MAX_ITERATIONS = 5_000_000;
    /** Passphrase 최대 길이(UTF-8 바이트). */
    public static final int MAX_PASSPHRASE_BYTES = 1024;

    private Pbkdf2() { }

    /** @return 새 16바이트 보안 난수 Salt */
    public static byte[] newSalt() {
        return SecureRandoms.fill(SALT_BYTES);
    }

    /**
     * Passphrase에서 키를 파생한다.
     *
     * @param algorithm  알고리즘
     * @param passphrase Passphrase(바꾸지 않는다)
     * @param salt       Salt(16~64바이트, 바꾸지 않는다)
     * @param iterations 반복 횟수(100,000~5,000,000)
     * @param keyBytes   키 길이(16~64바이트)
     * @return 파생 키(호출자가 다 쓰면 지운다)
     * @throws IllegalArgumentException 입력이 규칙에 맞지 않음
     */
    public static byte[] deriveKey(Pbkdf2Algorithm algorithm, char[] passphrase, byte[] salt, int iterations, int keyBytes) {
        Text.require(algorithm, "algorithm");
        if (keyBytes < 16 || keyBytes > 64) throw Text.invalid("sec.err.keyLength", 16, 64);
        checkSaltAndIterations(salt, iterations, MIN_ITERATIONS);
        char[] normalized = normalize(passphrase);
        try {
            return Kdf.pbkdf2(algorithm.jcaName(), normalized, salt.clone(), iterations, keyBytes);
        } finally {
            Arrays.fill(normalized, '\0');
        }
    }

    /** 패키지 내부: Salt 길이와 반복 횟수 범위 검사(최소 반복 횟수는 호출자가 정한다). */
    static void checkSaltAndIterations(byte[] salt, int iterations, int minIterations) {
        Text.require(salt, "salt");
        if (salt.length < MIN_SALT_BYTES || salt.length > MAX_SALT_BYTES) {
            throw Text.invalid("sec.err.saltLength", MIN_SALT_BYTES, MAX_SALT_BYTES);
        }
        if (iterations < minIterations || iterations > MAX_ITERATIONS) {
            throw Text.invalid("sec.err.iterations", minIterations, MAX_ITERATIONS);
        }
    }

    /**
     * 패키지 내부: Passphrase·비밀번호 검증과 NFC 정규화(한국어 고정 문구), UTF-8 길이 상한.
     *
     * @return 정규화한 새 배열(호출자가 지운다)
     */
    static char[] normalize(char[] passphrase) {
        Text.require(passphrase, "passphrase");
        char[] normalized;
        try (Messages.Scope ignored = Messages.use(Messages.Language.KO)) {
            normalized = Kdf.normalize(passphrase);
        }
        if (Kdf.utf8Length(normalized) > MAX_PASSPHRASE_BYTES) {
            Arrays.fill(normalized, '\0');
            throw Text.invalid("sec.err.passphraseLong", MAX_PASSPHRASE_BYTES);
        }
        return normalized;
    }
}
